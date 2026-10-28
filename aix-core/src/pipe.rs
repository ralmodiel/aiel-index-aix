//! In-call pipes and sequences, and the row commands `count` / `filter` (plus `files`, see files.rs).
//!
//! - `aix 'grep X --in api | count by dir'`, `aix pipe '...'`, MCP `{"command":"pipe","args":"grep X | count by dir"}`:
//!   a stage boundary is ` | ` (spaces both sides) outside quotes, or a lone `|` argument. Stages pass typed rows
//!   (rows.rs). Any query command is a source (its rows come from its structured answer: aix/v1 cites, hits, or its
//!   printed rows). After a source: `count`, `filter`, `sort`, `uniq`, `head`, `tail`, `cut`, `wc -l`, `grep RE`
//!   (filters the rows by their text), `files ... -`, and any command given `-`: `code - [--function]`, `outline -`,
//!   `brief -`, `history -`, `bugs -`, `qa -`, `callers -` / `callees -` / `impact -` / `trace -` / `symbol -` (the
//!   member a row sits in), `grep RE -` (search only the input's files) run once per distinct input row (deduped,
//!   at most 20 runs) with one combined answer and one footer.
//! - `aix 'brief /fees ; callers Fee.assess ; code Fee.java:120-160'`, `aix batch 'a' 'b'`, MCP command "batch"
//!   (args `a ; b`, or a `commands` array): several commands in one process, one index refresh, one `== aix <cmd>`
//!   header each, one shared budget (AIX_BATCH_BUDGET_MS, default 10 s; commands not started in time are named).
//! - Limits apply at the last stage; earlier stages read the full answer (up to 5000 rows each). One wall-clock
//!   budget for the pipe (AIX_PIPE_BUDGET_MS, default 3 s) and a 200k-row ceiling: a stage that hits either marks
//!   the stream partial, and every later stage and the answer say so (`count` prints `>= N (partial: ...)`, never a
//!   bare number).
//! - Redaction at the source (every command's answer and every stdin line is redacted when it becomes rows) and
//!   again on the final answer.
//! - Exit status: the last stage's; any stage's usage error (2) stops the pipe with status 2.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use regex::Regex;
use serde_json::json;

use crate::index::Index;
use crate::query::Out;
use crate::rows::{Meta, Row, Rows};
use crate::Opts;

/// The most rows a stage passes on.
pub const MAX_STREAM: usize = 200_000;
/// The stages that read the rows before them (what `aix pipe --help` and the unknown-stage error list).
pub const PIPE_STAGES: &str = "Row stages: count [by file|dir[:N]|ext|kind|match|field N|NAME|level|template|item], filter [-i] [--grep RE] [-v RE] (filter --where F=V @set as the first stage), dedup [KEY] [-c], sort [-r -n -u -f -t C -k N[,M]], uniq [-c], head [-n N], tail [-n N], cut -d C -f LIST, wc -l, grep [-v -c -o -i -w -F] RE, sed -n A,Bp, put NAME (last); file/symbol stages: code, outline, brief, history, bugs, qa, callers, callees, impact, trace, symbol, explain, grep RE -";
/// The most runs a fan-out consumer (`code -`) makes.
pub const MAX_FANOUT: usize = 20;
/// Commands that read `-` themselves (rows::parse_stdin): in a pipe they get the rows injected and run once.
/// Other builders add their commands here when they implement `-` natively.
pub const STDIN_CMDS: &[&str] = &["files", "ls", "count", "filter", "dedup", "grep", "code", "cat", "head", "tail", "sed", "diff"];
/// Commands that take a file or symbol: given `-`, they run once per distinct input row.
pub const FANOUT_CMDS: &[&str] = &["code", "outline", "brief", "route", "history", "bugs", "qa", "callers", "callees", "impact", "trace", "symbol", "explain", "grep"];
/// The new commands handled here (CLI subcommands and MCP command names).
pub const OWN_CMDS: &[&str] = &["files", "ls", "count", "filter", "dedup", "pipe", "batch"];

fn budget_ms(var: &str, def: u128) -> u128 {
    crate::config::env_var(var).and_then(|v| v.parse().ok()).unwrap_or(def)
}

// ── a command's answer before it becomes an Out ──

/// The answer of a row command (files, count, filter, a stream stage): header lines, typed rows, notes, and how it
/// is paged. `to_out` renders it (decorated and bare).
#[derive(Debug, Default)]
pub struct Answer {
    pub cmd: String,
    pub toks: Vec<String>,
    pub head: Vec<String>,
    pub rows: Rows,
    /// lines printed instead of rows (an error, `--exists`, a total)
    pub lines: Vec<String>,
    pub notes: Vec<String>,
    /// the bare form when it is not the rows (a total: `42`)
    pub bare_lines: Option<Vec<String>>,
    pub exit: Option<i32>,
    pub error: bool,
    pub exists: Option<bool>,
    /// rows [a, b) are shown; the footer says how to see the rest
    shown: Option<(usize, usize)>,
    footer: Option<String>,
}

impl Answer {
    pub fn new(cmd: &str, toks: &[String]) -> Answer {
        Answer { cmd: cmd.to_string(), toks: toks.to_vec(), ..Default::default() }
    }
    pub fn fail(&mut self, msg: impl Into<String>) {
        self.lines.push(msg.into());
        self.error = true;
        self.exit = Some(2);
    }
    pub fn out_line(&mut self, l: impl Into<String>) {
        self.lines.push(l.into());
    }
    /// The command line that shows this answer again, minus paging flags (for the continuation footer).
    pub fn cmdline(&self) -> String {
        let mut v: Vec<String> = vec![];
        let mut i = 0;
        while i < self.toks.len() {
            let t = &self.toks[i];
            if matches!(t.as_str(), "--page" | "--offset" | "--limit" | "--per-page") {
                i += 2;
                continue;
            }
            v.push(crate::shell_quote(t));
            i += 1;
        }
        format!("{} {}", self.cmd, v.join(" ")).trim().to_string()
    }
    /// Page the rows: `per_page` (default `def`), `--page N` or `--offset K`; the footer names the next page.
    pub fn finish_listing(&mut self, per_page: Option<usize>, page: Option<usize>, offset: Option<usize>, def: usize) {
        let n = self.rows.len();
        let per = per_page.unwrap_or(def).max(1);
        let off = offset.unwrap_or((page.unwrap_or(1) - 1).saturating_mul(per)).min(n);
        let end = off.saturating_add(per).min(n);
        self.shown = Some((off, end));
        if end < n {
            let f = crate::outfmt::current();
            let lim = if per != def && f.head != Some(per) { format!(" --limit {per}") } else { String::new() };
            self.footer = Some(format!("(\u{2026} {} more of {n}: next `aix {}{lim}{} --page {}`)", n - end, self.cmdline(), f.flags(), end / per + 1));
        } else if off > 0 && off >= n {
            self.footer = Some(format!("(page past the end: {n} rows)"));
        }
    }
}

/// The decorated form of one row.
pub fn decorated(r: &Row, m: &Meta) -> String {
    match r {
        Row::Hit { path, line, text } => format!("  {path}:{line}: {text}"),
        Row::File { path } if m.text.is_empty() => format!("  {path}"),
        Row::File { path } => format!("  {path}  {}", m.text),
        Row::Range { path, a, b } => format!("  {path}:{a}-{b} {}", m.text).trim_end().to_string(),
        Row::Count { key, n } if matches!(m.kind.as_str(), "group" | "uniq") => format!("{n:>6}  {key}"),
        Row::Count { key, n } if m.kind == "norm" => format!("{n}\u{d7}  {key}"),
        Row::Count { key, n } if m.kind == "total" => format!("{n}"),
        Row::Count { key, n } if m.text.is_empty() => format!("  {key}: {n}"),
        Row::Count { key, n } => format!("  {key}: {n} ({})", m.text),
        Row::Text { line } => line.clone(),
    }
}

pub fn to_out(a: Answer) -> Out {
    let f = crate::outfmt::current();
    let width = f.width.or(if f.bare { Some(crate::outfmt::BARE_WIDTH) } else { None }).unwrap_or(0);
    let mut out = Out::new(20);
    for l in &a.head {
        out.emit(l.clone());
    }
    for l in &a.lines {
        out.emit(l.clone());
    }
    let (s, e) = a.shown.unwrap_or((0, a.rows.len()));
    let mut bare: Vec<String> = vec![];
    for (r, m) in a.rows.iter().skip(s).take(e - s) {
        let d = decorated(r, m);
        out.emit(if width > 0 && !f.bare { crate::outfmt::clip_line(&d, width) } else { d });
        // a file NAME is repo text too: defanged like the decorated row (other rows carry already-defanged text)
        let rendered = if matches!(r, Row::File { .. }) && m.raw.is_empty() { crate::query::neutralize(&r.render(m)) } else { r.render(m) };
        bare.push(crate::outfmt::clip_line(&rendered, width));
        if let Some(p) = r.path() {
            out.hit(if m.kind.is_empty() { "row" } else { &m.kind }, p, r.line().unwrap_or(0) as i64, &match r {
                Row::Hit { text, .. } => text.clone(),
                Row::Count { n, .. } => n.to_string(),
                _ => m.text.clone(),
            });
        }
    }
    if let Some(p) = &a.rows.partial {
        out.emit(format!("(partial: {p})"));
    }
    for l in &a.notes {
        out.emit(l.clone());
    }
    if let Some(fl) = &a.footer {
        out.emit(fl.clone());
        out.truncated = true;
    }
    let mut b = a.bare_lines.clone().unwrap_or(bare);
    if a.bare_lines.is_none() && (a.error || (a.rows.is_empty() && !a.lines.is_empty())) {
        b = a.lines.clone();
    }
    if let Some(p) = &a.rows.partial {
        b.push(format!("\u{2026} partial: {p}"));
    }
    if let Some(fl) = &a.footer {
        let t = fl.trim_start_matches('(').trim_end_matches(')');
        b.push(if t.starts_with('\u{2026}') { t.to_string() } else { format!("\u{2026} {t}") });
    }
    out.bare_rows = Some(b);
    out.error = a.error;
    out.exit_code = a.exit;
    out.exists = a.exists;
    out
}

// ── splitting ──

/// Split a string on ` <sep> ` (spaces both sides) outside single and double quotes.
pub fn split_outside_quotes(s: &str, sep: char) -> Vec<String> {
    let cs: Vec<char> = s.chars().collect();
    let mut parts = vec![];
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match q {
            // `\"` and `\\` inside double quotes are one character, as the shell (and shell_split) reads them
            Some('"') if c == '\\' && matches!(cs.get(i + 1), Some('"') | Some('\\')) => {
                cur.push(c);
                cur.push(cs[i + 1]);
                i += 2;
                continue;
            }
            Some(qc) if c == qc => q = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => q = Some(c),
            None if c == sep && i > 0 && cs[i - 1].is_whitespace() && cs.get(i + 1).is_none_or(|n| n.is_whitespace()) => {
                parts.push(cur.trim().to_string());
                cur.clear();
                i += 1;
                continue;
            }
            None => {}
        }
        cur.push(c);
        i += 1;
    }
    parts.push(cur.trim().to_string());
    parts
}

/// A quote left open at the end of `s` (the same rules as split_outside_quotes): the pipe or sequence boundaries
/// after it cannot be told apart, so the command is refused rather than run as something else.
pub fn open_quote(s: &str) -> Option<char> {
    let cs: Vec<char> = s.chars().collect();
    let mut q: Option<char> = None;
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match q {
            Some('"') if c == '\\' && matches!(cs.get(i + 1), Some('"') | Some('\\')) => i += 1,
            Some(qc) if c == qc => q = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => q = Some(c),
            None => {}
        }
        i += 1;
    }
    q
}

/// Shell operators typed inside the quoted command that aix would otherwise read as regex text: `||`, `&&`, `$(`,
/// a backtick, or a `|` with a space on one side only (`grep X |count`). Returns the error to print.
pub fn shell_ops(s: &str) -> Option<String> {
    let cs: Vec<char> = s.chars().collect();
    let mut q: Option<char> = None;
    let mut i = 0;
    let sp = |c: Option<&char>| c.is_none_or(|c| c.is_whitespace());
    while i < cs.len() {
        let c = cs[i];
        match q {
            Some('"') if c == '\\' && matches!(cs.get(i + 1), Some('"') | Some('\\')) => i += 1,
            Some(qc) if c == qc => q = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => q = Some(c),
            None if c == '\\' => i += 1,
            None if c == '|' && cs.get(i + 1) == Some(&'|') && sp(i.checked_sub(1).and_then(|j| cs.get(j))) && sp(cs.get(i + 2)) => {
                return Some("`||` inside the quoted command: aix does not run shell lists (an empty answer already exits 1; drop `|| ...`, or put it outside the quotes)".into());
            }
            None if c == '&' && cs.get(i + 1) == Some(&'&') => {
                return Some("`&&` inside the quoted command: run several commands as a sequence `a ; b` (or put `&&` outside the quotes)".into());
            }
            None if c == '`' || (c == '$' && cs.get(i + 1) == Some(&'(')) => {
                return Some("command substitution inside the quoted command is not run by aix: put it outside the quotes".into());
            }
            None if c == '|' && cs.get(i + 1) != Some(&'|') && i.checked_sub(1).and_then(|j| cs.get(j)) != Some(&'|') => {
                let before = sp(i.checked_sub(1).and_then(|j| cs.get(j)));
                let after = sp(cs.get(i + 1));
                if before != after && i > 0 && i + 1 < cs.len() {
                    return Some("a `|` with a space on one side only: write ` | ` (spaces both sides) for a pipe stage, or quote a regex that holds `|`".into());
                }
            }
            None => {}
        }
        i += 1;
    }
    None
}

/// The stages of a pipe from its argument tokens: a token holding ` | ` is split (quote-aware), a lone `|` token is
/// a boundary, other tokens join the current stage.
pub fn stages_of(toks: &[String]) -> Vec<Vec<String>> {
    let mut stages: Vec<Vec<String>> = vec![vec![]];
    for t in toks {
        if t == "|" {
            stages.push(vec![]);
            continue;
        }
        if toks.len() == 1 || t.contains(" | ") || (t.contains(char::is_whitespace) && stages.last().is_some_and(|s| s.is_empty())) {
            let parts = split_outside_quotes(t, '|');
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    stages.push(vec![]);
                }
                stages.last_mut().unwrap().extend(crate::query::shell_split(p));
            }
            continue;
        }
        stages.last_mut().unwrap().push(t.clone());
    }
    stages.retain(|s| !s.is_empty());
    stages
}


// ── the stream between stages ──

#[derive(Debug, Default, Clone)]
pub struct Stream {
    pub rows: Rows,
    /// the regex of the grep source (count by match)
    pub pattern: Option<Regex>,
    /// rows are per-file counts of a grep source (count by file/dir/ext/kind adds them up)
    pub weighted: bool,
}

pub struct Ctx {
    t0: Instant,
    budget: u128,
    o: Opts,
    /// the refresh ran once (later stages skip it)
    refreshed: bool,
}

impl Ctx {
    fn spent(&self) -> bool {
        self.t0.elapsed().as_millis() > self.budget
    }
    fn opts(&mut self) -> Opts {
        let mut o = self.o.clone();
        o.no_refresh = o.no_refresh || self.refreshed;
        self.refreshed = true;
        o
    }
}

fn mark_partial(rows: &mut Rows, why: String) {
    if rows.partial.is_none() {
        rows.partial = Some(why);
    }
}

fn cap_stream(s: &mut Stream, stage: &str) {
    if s.rows.len() > MAX_STREAM {
        s.rows.rows.truncate(MAX_STREAM);
        s.rows.meta.truncate(MAX_STREAM);
        mark_partial(&mut s.rows, format!("{stage} passed the first {MAX_STREAM} rows"));
    }
}

/// Is this word a stream stage (works on rows, not on the index)?
fn stream_stage(w: &str) -> bool {
    matches!(w, "count" | "filter" | "sort" | "uniq" | "dedup" | "head" | "tail" | "cut" | "wc")
}

/// The pattern of a grep stage (`grep -i 'a|b' --in x`) for `count by match`.
fn grep_pattern(args: &[String]) -> Option<Regex> {
    let (mut icase, mut fixed, mut word, mut ere) = (false, false, false, false);
    let mut pats: Vec<String> = vec![];
    let mut first: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            if first.is_none() {
                first = args.get(i + 1).cloned();
            }
            break;
        }
        if a == "-e" || a == "--regexp" {
            pats.extend(args.get(i + 1).cloned());
            i += 2;
            continue;
        }
        if matches!(a.as_str(), "--in" | "-g" | "--glob" | "-t" | "--type" | "-A" | "-B" | "-C" | "--limit" | "-m" | "--max-count" | "--not" | "--and" | "--exclude" | "--only" | "--hide") {
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            match a.as_str() {
                "--ignore-case" => icase = true,
                "--fixed-strings" => fixed = true,
                "--word-regexp" => word = true,
                "--extended-regexp" => ere = true,
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            for c in a[1..].chars() {
                match c {
                    'i' => icase = true,
                    'F' => fixed = true,
                    'w' => word = true,
                    'E' => ere = true,
                    _ => {}
                }
            }
        } else if first.is_none() {
            first = Some(a.clone());
        }
        i += 1;
    }
    let mut p = if pats.is_empty() { first? } else { pats.iter().map(|e| format!("(?:{e})")).collect::<Vec<_>>().join("|") };
    if fixed {
        p = regex::escape(&p);
    } else if !ere {
        if let Some(t) = crate::query::bre_to_ere(&p) {
            p = t;
        }
    }
    if word {
        p = format!(r"\b(?:{p})\b");
    }
    regex::RegexBuilder::new(&p).case_insensitive(icase).build().ok()
}

/// The row text a filter sees: a hit's text, a range's description, a path, a key, a text line.
fn row_text<'a>(r: &'a Row, m: &'a Meta) -> std::borrow::Cow<'a, str> {
    match r {
        Row::Hit { text, .. } => text.into(),
        Row::Range { .. } => m.text.as_str().into(),
        Row::File { path } => path.into(),
        Row::Count { key, .. } => key.into(),
        Row::Text { line } => line.into(),
    }
}

// ── stream stages ──

/// `sort [-n] [-r] [-u] [-f] [-s] [-b] [-t C] [-k N[,M]]`, GNU sort in the C locale on the rows' rendered text.
fn sort_stage(s: &mut Stream, args: &[String]) -> Result<(), String> {
    let (mut num, mut rev, mut uniq, mut fold, mut stable, mut blanks) = (false, false, false, false, false, false);
    let mut sep: Option<char> = None;
    let mut key: Option<(usize, Option<usize>)> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(v) = a.strip_prefix("-t").filter(|v| !v.is_empty()) {
            sep = v.chars().next();
        } else if a == "-t" {
            sep = args.get(i + 1).and_then(|v| v.chars().next());
            i += 1;
        } else if a == "-k" || (a.starts_with("-k") && a.len() > 2) {
            let v = if a == "-k" {
                i += 1;
                args.get(i).cloned().unwrap_or_default()
            } else {
                a[2..].to_string()
            };
            let parse = |x: &str| -> Result<usize, String> { x.parse::<usize>().ok().filter(|n| *n >= 1).ok_or_else(|| format!("sort: -k {v}: only field numbers (N or N,M) are supported; use the shell's sort for -k N.C or key flags")) };
            key = Some(match v.split_once(',') {
                Some((a, b)) => (parse(a)?, Some(parse(b)?)),
                None => (parse(&v)?, None),
            });
        } else if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") {
            for c in a[1..].chars() {
                match c {
                    'n' => num = true,
                    'r' => rev = true,
                    'u' => uniq = true,
                    'f' => fold = true,
                    's' => stable = true,
                    'b' => blanks = true,
                    _ => return Err(format!("sort: -{c} is not supported (n r u f s b t k are); use the shell's sort")),
                }
            }
        } else {
            return Err(format!("sort: {a} is not supported (sort [-nrufsb] [-t C] [-k N[,M]]); use the shell's sort"));
        }
        i += 1;
    }
    // GNU field extraction: with -t, fields between separators; without, a field is a blank run plus the non-blanks
    let keytext = |line: &str| -> String {
        let Some((a, b)) = key else { return line.to_string() };
        let fields: Vec<(usize, usize)> = match sep {
            Some(c) => {
                let mut v = vec![];
                let mut st = 0;
                for (i, ch) in line.char_indices() {
                    if ch == c {
                        v.push((st, i));
                        st = i + ch.len_utf8();
                    }
                }
                v.push((st, line.len()));
                v
            }
            None => {
                let bs = line.as_bytes();
                let mut v = vec![];
                let mut st = 0;
                let mut j = 0;
                while j < bs.len() {
                    while j < bs.len() && (bs[j] == b' ' || bs[j] == b'\t') {
                        j += 1;
                    }
                    while j < bs.len() && bs[j] != b' ' && bs[j] != b'\t' {
                        j += 1;
                    }
                    v.push((st, j));
                    st = j;
                }
                v
            }
        };
        let Some(&(s0, _)) = fields.get(a - 1) else { return String::new() };
        let e = match b {
            Some(b) => fields.get(b - 1).map(|f| f.1).unwrap_or(line.len()),
            None => line.len(),
        };
        let k = line.get(s0..e.max(s0)).unwrap_or("");
        if blanks { k.trim_start_matches([' ', '\t']).to_string() } else { k.to_string() }
    };
    let numval = |k: &str| -> f64 {
        let t = k.trim_start_matches([' ', '\t']);
        let mut end = 0;
        let b = t.as_bytes();
        if end < b.len() && b[end] == b'-' {
            end += 1;
        }
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end < b.len() && b[end] == b'.' {
            end += 1;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
        }
        t[..end].parse::<f64>().unwrap_or(0.0)
    };
    let cmp_key = |x: &str, y: &str| -> std::cmp::Ordering {
        if num {
            numval(x).partial_cmp(&numval(y)).unwrap_or(std::cmp::Ordering::Equal)
        } else if fold {
            x.bytes().map(|c| c.to_ascii_uppercase()).cmp(y.bytes().map(|c| c.to_ascii_uppercase()))
        } else {
            x.as_bytes().cmp(y.as_bytes())
        }
    };
    let mut idx: Vec<(String, String, usize)> = s.rows.iter().enumerate().map(|(i, (r, m))| { let t = r.render(m); (keytext(&t), t, i) }).collect();
    idx.sort_by(|x, y| {
        let mut o = cmp_key(&x.0, &y.0);
        if o == std::cmp::Ordering::Equal && !stable && !uniq {
            o = x.1.as_bytes().cmp(y.1.as_bytes()); // GNU's last-resort whole-line comparison
        }
        if rev { o.reverse() } else { o }
    });
    if uniq {
        idx.dedup_by(|y, x| cmp_key(&x.0, &y.0) == std::cmp::Ordering::Equal);
    }
    let order: Vec<usize> = idx.into_iter().map(|x| x.2).collect();
    reorder(&mut s.rows, &order);
    Ok(())
}

fn reorder(r: &mut Rows, order: &[usize]) {
    let rows = order.iter().map(|&i| r.rows[i].clone()).collect();
    let meta = order.iter().map(|&i| r.meta[i].clone()).collect();
    r.rows = rows;
    r.meta = meta;
}

/// `uniq [-c] [-d] [-u] [-i]`: ADJACENT equal rendered rows, as GNU uniq.
fn uniq_stage(s: &mut Stream, args: &[String]) -> Result<(), String> {
    let (mut c, mut d, mut u, mut i_) = (false, false, false, false);
    for a in args {
        if !a.starts_with('-') || a.len() < 2 {
            return Err(format!("uniq: {a}: input comes from the stage before; flags are -c -d -u -i"));
        }
        for ch in a[1..].chars() {
            match ch {
                'c' => c = true,
                'd' => d = true,
                'u' => u = true,
                'i' => i_ = true,
                _ => return Err(format!("uniq: -{ch} is not supported (c d u i are); use the shell's uniq")),
            }
        }
    }
    let texts: Vec<String> = s.rows.iter().map(|(r, m)| r.render(m)).collect();
    let eq = |a: &str, b: &str| if i_ { a.eq_ignore_ascii_case(b) } else { a == b };
    let mut out = Rows { partial: s.rows.partial.clone(), ..Default::default() };
    let mut i = 0;
    while i < texts.len() {
        let mut j = i + 1;
        while j < texts.len() && eq(&texts[i], &texts[j]) {
            j += 1;
        }
        let n = j - i;
        if (!d || n > 1) && (!u || n == 1) {
            if c {
                out.push(Row::Count { key: texts[i].clone(), n: n as u64 }, Meta { kind: "uniq".into(), text: String::new(), ..Default::default() });
            } else {
                out.push(s.rows.rows[i].clone(), s.rows.meta[i].clone());
            }
        }
        i = j;
    }
    s.rows = out;
    s.weighted = false;
    Ok(())
}

/// `head [-n] N` / `head -N`, `tail [-n] N` / `tail -n +K`.
fn head_tail(s: &mut Stream, tail: bool, args: &[String]) -> Result<(), String> {
    let name = if tail { "tail" } else { "head" };
    let mut n: Option<(usize, bool)> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let v = if a == "-n" || a == "--lines" {
            i += 1;
            args.get(i).cloned().unwrap_or_default()
        } else if let Some(x) = a.strip_prefix("-n") {
            x.to_string()
        } else if let Some(x) = a.strip_prefix("--lines=") {
            x.to_string()
        } else if let Some(x) = a.strip_prefix('-').filter(|x| x.chars().all(|c| c.is_ascii_digit()) && !x.is_empty()) {
            x.to_string()
        } else if a.chars().all(|c| c.is_ascii_digit()) && !a.is_empty() {
            a.to_string()
        } else {
            return Err(format!("{name}: {a} is not supported ({name} [-n] N{}); use the shell's {name}", if tail { ", tail -n +K" } else { "" }));
        };
        let plus = v.starts_with('+');
        let num = v.trim_start_matches('+').parse::<usize>().map_err(|_| format!("{name}: '{v}' is not a number"))?;
        if plus && !tail {
            return Err("head: -n +K is not supported; use tail -n +K".into());
        }
        n = Some((num, plus));
        i += 1;
    }
    let (k, plus) = n.unwrap_or((10, false));
    let len = s.rows.len();
    let (a, b) = if !tail {
        (0, k.min(len))
    } else if plus {
        (k.saturating_sub(1).min(len), len)
    } else {
        (len.saturating_sub(k), len)
    };
    let order: Vec<usize> = (a..b).collect();
    reorder(&mut s.rows, &order);
    s.weighted = false;
    Ok(())
}

/// A GNU cut LIST (`1,3-5,7-`) as a predicate on 1-based positions.
fn cut_list(l: &str) -> Result<Vec<(usize, usize)>, String> {
    let mut v = vec![];
    for part in l.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (if a.is_empty() { 1 } else { a.parse().map_err(|_| format!("cut: bad list {l}"))? }, if b.is_empty() { usize::MAX } else { b.parse().map_err(|_| format!("cut: bad list {l}"))? }),
            None => {
                let n: usize = part.parse().map_err(|_| format!("cut: bad list {l}"))?;
                (n, n)
            }
        };
        if a == 0 {
            return Err("cut: fields and positions are numbered from 1".into());
        }
        v.push((a, b));
    }
    Ok(v)
}

/// `cut -d C -f LIST [-s]` / `cut -c LIST` (characters) on the rows' rendered text (`path:line:text` for hits).
fn cut_stage(s: &mut Stream, args: &[String], ix: Option<&Index>) -> Result<(), String> {
    let mut delim = '\t';
    let (mut fields, mut chars, mut only) = (None, None, false);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut val = |flag: &str| -> Option<String> {
            if a == flag {
                i += 1;
                args.get(i).cloned()
            } else {
                a.strip_prefix(flag).map(str::to_string)
            }
        };
        if a.starts_with("-d") {
            delim = val("-d").and_then(|v| v.chars().next()).ok_or("cut: -d needs a character")?;
        } else if a.starts_with("-f") {
            fields = Some(cut_list(&val("-f").ok_or("cut: -f needs a list")?)?);
        } else if a.starts_with("-c") {
            chars = Some(cut_list(&val("-c").ok_or("cut: -c needs a list")?)?);
        } else if a == "-s" {
            only = true;
        } else {
            return Err(format!("cut: {a} is not supported (-d C -f LIST [-s], -c LIST); use the shell's cut"));
        }
        i += 1;
    }
    let inl = |v: &[(usize, usize)], k: usize| v.iter().any(|(a, b)| *a <= k && k <= *b);
    let mut lines: Vec<String> = vec![];
    for (r, m) in s.rows.iter() {
        let t = r.render(m);
        if let Some(c) = &chars {
            lines.push(t.chars().enumerate().filter(|(k, _)| inl(c, k + 1)).map(|x| x.1).collect());
        } else if let Some(f) = &fields {
            if !t.contains(delim) {
                if !only {
                    lines.push(t);
                }
                continue;
            }
            lines.push(t.split(delim).enumerate().filter(|(k, _)| inl(f, k + 1)).map(|x| x.1).collect::<Vec<_>>().join(&delim.to_string()));
        } else {
            return Err("cut: give -f LIST (with -d C) or -c LIST".into());
        }
    }
    let partial = s.rows.partial.clone();
    // the cut text is typed again (a path column becomes files)
    let mut r = crate::rows::parse_text(&lines.join("\n"), ix);
    r.redacted = 0;
    if r.len() != lines.len() {
        r = Rows::default();
        for l in lines {
            r.push(Row::Text { line: l }, Meta::default());
        }
    }
    r.partial = partial;
    s.rows = r;
    s.weighted = false;
    Ok(())
}

/// A grep stage after another stage: keep the rows whose text matches (`-v` the others).
fn grep_filter(s: &mut Stream, args: &[String], ix: Option<&Index>) -> Result<(), String> {
    let (mut inv, mut cnt, mut only) = (false, false, false);
    let mut rest: Vec<String> = vec![];
    for a in args {
        if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") && a[1..].chars().all(|c| "ivFwEnrhco".contains(c)) {
            inv |= a.contains('v');
            cnt |= a.contains('c');
            only |= a.contains('o');
            rest.push(a.replace(['v', 'n', 'r', 'h', 'c', 'o'], ""));
        } else if a.starts_with('-') && a.len() > 1 && !a.starts_with("--") && a[1..].chars().all(|c| c.is_ascii_alphabetic()) {
            // GNU grep reads its stdin as one file: -l/-L/-q/-m/-A ... mean nothing useful on rows; never ignore them
            let bad: String = a[1..].chars().filter(|c| !"ivFwEnrhco".contains(*c)).collect();
            return Err(format!("grep (pipe stage): flag -{bad} is not supported on rows (supported: -i -v -F -w -E -c -o; `| count` counts rows)"));
        } else if a == "--count" {
            cnt = true;
        } else if a == "--only-matching" {
            only = true;
        } else if a == "--invert-match" {
            inv = true;
        } else {
            rest.push(a.clone());
        }
    }
    rest.retain(|a| a != "-" && !a.is_empty());
    let Some(re) = grep_pattern(&rest) else { return Err("grep (stream): needs a valid regex".into()) };
    s.rows.retain(|r, m| re.is_match(&row_text(r, m)) != inv);
    if only && !inv {
        // GNU -o: each match on its own line
        let ms: Vec<String> = s.rows.iter().flat_map(|(r, m)| re.find_iter(&row_text(r, m)).map(|x| x.as_str().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>()).collect();
        s.rows = crate::rows::parse_text(&ms.join("\n"), ix);
    }
    if cnt {
        // GNU -c on one input: the number of selected lines (of matches with -o, as GNU counts lines either way)
        let n = s.rows.len();
        s.rows = crate::rows::parse_text(&n.to_string(), ix);
    }
    s.weighted = false;
    if s.pattern.is_none() {
        s.pattern = Some(re);
    }
    Ok(())
}

// ── count ──

fn count_answer(s: Stream, toks: &[String], ix: &Index) -> Answer {
    let mut a = Answer::new("count", toks);
    let mut args: Vec<String> = toks.iter().filter(|t| *t != "-").cloned().collect();
    let (mut per, mut page, mut top) = (None, None, None);
    let mut having: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let t = args[i].clone();
        let v = args.get(i + 1).and_then(|v| v.parse::<usize>().ok());
        match t.as_str() {
            "--limit" | "--per-page" => per = v,
            "--page" => page = v,
            "--top" => top = v,
            "--having" => having = args.get(i + 1).cloned(),
            _ => {
                i += 1;
                continue;
            }
        }
        args.drain(i..(i + 2).min(args.len()));
    }
    if args.first().is_some_and(|w| w == "by") {
        args.remove(0);
    } else if args.first().is_some_and(|w| w == "-l") {
        args.remove(0); // wc -l
    }
    if let Some(bad) = args.iter().find(|w| w.starts_with("--")) {
        a.fail(format!("count: unknown flag {bad} (flags: --having COND, --top N, --limit N, --page N)"));
        return a;
    }
    let key = args.first().cloned().unwrap_or_default();
    let (k, depth) = crate::group::split_key(&key);
    // `field N` (awk's N-th blank-separated field) or `field NAME` (a named field: data-set record, NAME=value);
    // `level`, `template`, `item` as dedup.rs::named reads them
    let mut fname: Option<String> = None;
    let field = if k == "field" {
        match args.get(1) {
            Some(n) if n.parse::<usize>().is_ok_and(|n| n >= 1) => n.parse::<usize>().ok(),
            Some(n) if !n.starts_with('-') && n.parse::<usize>().is_err() => {
                fname = Some(n.clone());
                None
            }
            _ => {
                a.fail("count: by field N|NAME needs a field number from 1 (fields split on blanks, as awk) or a field name");
                return a;
            }
        }
    } else {
        None
    };
    if matches!(k.as_str(), "level" | "template" | "item") {
        fname = Some(k.clone());
    }
    if !key.is_empty() && !matches!(k.as_str(), "file" | "dir" | "ext" | "kind" | "match" | "field" | "line" | "lang" | "level" | "template" | "item") {
        a.fail(format!("count: by {key}? keys: file, dir[:N], ext, kind, match[:N], field N|NAME, level, template, item, line (no key: the number of rows, as wc -l)"));
        return a;
    }
    // `count by dir` with no depth: the first depth at which the rows split into more than one directory (every
    // row under `src/` at depth 1 is one useless group)
    let auto_depth = k == "dir" && !key.contains(':');
    let depth = if auto_depth {
        let paths: Vec<String> = s.rows.iter().filter_map(|(r, _)| r.path().map(|p| p.trim_end_matches('/').to_string())).collect();
        crate::group::auto_dir_depth(&paths)
    } else {
        depth
    };
    let partial = s.rows.partial.clone();
    let mut groups: BTreeMap<String, u64> = BTreeMap::new();
    let mut total: u64 = 0;
    let mut skipped = 0usize;
    let mgroup = crate::group::match_group(&key);
    for (r, m) in s.rows.iter() {
        let w: u64 = match (s.weighted, r) {
            (true, Row::Count { n, .. }) => *n,
            _ => 1,
        };
        if key.is_empty() {
            total += w;
            continue;
        }
        let keys: Vec<String> = match k.as_str() {
            "file" | "dir" | "ext" | "lang" => match r.path() {
                Some(p) => vec![crate::group::file_key(p.trim_end_matches('/'), if k == "lang" { "ext" } else { &k }, depth)],
                None => vec![],
            },
            "kind" => {
                let generic = m.kind.is_empty() || matches!(m.kind.as_str(), "grep" | "code" | "row" | "file" | "count" | "group" | "lines" | "bytes");
                match (generic, r.path()) {
                    (false, _) => vec![m.kind.clone()],
                    (true, Some(p)) => vec![crate::group::file_key(p, "kind", 1)],
                    (true, None) => vec![],
                }
            }
            "match" => {
                if s.weighted {
                    vec![match r { Row::Count { key, .. } => key.clone(), _ => String::new() }]
                } else {
                    let t = row_text(r, m);
                    match &s.pattern {
                        Some(re) => re.captures_iter(&t).filter_map(|c| c.get(mgroup).map(|x| x.as_str().to_string())).collect(),
                        None => vec![t.to_string()],
                    }
                }
            }
            _ if fname.is_some() => crate::dedup::named(Some(ix), r, m, fname.as_deref().unwrap_or("")).filter(|v| !v.is_empty()).map(|v| vec![v]).unwrap_or_default(),
            "field" => {
                let t = row_text(r, m);
                t.split_whitespace().nth(field.unwrap_or(1) - 1).map(|x| vec![x.to_string()]).unwrap_or_default()
            }
            _ => vec![r.render(m)],
        };
        if keys.is_empty() {
            skipped += 1;
        }
        for kk in keys {
            *groups.entry(kk).or_default() += w;
            total += w;
        }
    }
    // a cut stdin was counted to its end while it streamed: the number of rows is its line count
    let (total, partial) = match (key.is_empty(), s.rows.lines_total) {
        (true, Some(n)) => (n as u64, None),
        _ => (total, partial),
    };
    let ge = if partial.is_some() { ">= " } else { "" };
    if key.is_empty() {
        let p = partial.as_ref().map(|p| format!(" (partial: {p})")).unwrap_or_default();
        a.rows.push(Row::Count { key: "rows".into(), n: total }, Meta { kind: "total".into(), text: String::new(), ..Default::default() });
        a.lines.push(format!("{ge}{total}{p}"));
        a.bare_lines = Some(vec![format!("{ge}{total}{p}").replace(">= ", ">=")]);
        a.rows.partial = None;
        a.rows.rows.clear();
        a.rows.meta.clear();
        if s.rows.lines_total.is_some() {
            a.notes.push(format!("(input: {})", crate::rows::cut_note("every line counted while it streamed")));
        } else if let Some(n) = crate::rows::input_note(&s.rows, false) {
            a.notes.push(n);
        }
        a.exit = Some(if total == 0 { 1 } else { 0 });
        return a;
    }
    let mut v: Vec<(String, u64)> = groups.into_iter().collect();
    v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
    if let Some(h) = &having {
        match crate::group::parse_terms(h) {
            Ok(terms) => {
                let t = total as f64;
                v.retain(|(_, n)| crate::group::having_keep(&terms, *n as f64, t));
            }
            Err(e) => {
                a.fail(format!("count: {e}"));
                return a;
            }
        }
    }
    if let Some(t) = top {
        v.truncate(t);
    }
    let ng = v.len();
    for (kk, n) in v {
        a.rows.push(Row::Count { key: kk, n }, Meta { kind: "group".into(), text: String::new(), ..Default::default() });
    }
    a.rows.partial = partial;
    a.head.push(format!("== count by {key}{}: {ge}{total} in {ng} groups", field.map(|f| format!(" {f}")).unwrap_or_default()));
    if skipped > 0 {
        a.notes.push(format!("({skipped} rows had no {k} and were not counted)"));
    }
    if let Some(n) = crate::rows::input_note(&s.rows, matches!(k.as_str(), "file" | "dir" | "ext" | "kind")) {
        a.notes.push(n);
    }
    let _ = ix;
    a.finish_listing(per, page, None, 50);
    if ng == 0 {
        a.exit = Some(1);
    }
    a
}

// ── filter (non-code text on stdin) ──

/// The filtered view, and (when no --head/--tail chose a part) the indexes of every matching input row.
/// `a\|b` (GNU BRE alternation) -> `a|b`; an escaped backslash before it (`\\|`) stays as written.
fn bre_alt(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut it = p.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some('|') => {
                    out.push('|');
                    it.next();
                }
                Some(&n) => {
                    out.push(c);
                    out.push(n);
                    it.next();
                }
                None => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn filter_answer(s: Stream, toks: &[String]) -> (Answer, Option<Vec<usize>>) {
    let mut a = Answer::new("filter", toks);
    let (mut inc, mut exc): (Vec<Regex>, Vec<Regex>) = (vec![], vec![]);
    let (mut head, mut tail) = (None, None);
    let mut between: Vec<(Regex, Regex)> = vec![];
    let mut i = 0;
    // `-i` / `--ignore-case`: every pattern of this filter ignores case (as grep -i)
    let icase = toks.iter().any(|t| t == "-i" || t == "--ignore-case");
    let re = |v: Option<&String>, f: &str| -> Result<Regex, String> {
        let p = v.ok_or_else(|| format!("filter: {f} needs a regex"))?;
        // GNU BRE alternation `a\|b` (as aix grep reads it) is an alternation here too
        let p = bre_alt(p);
        Regex::new(&if icase { format!("(?i){p}") } else { p }).map_err(|e| format!("filter: {f}: {e}"))
    };
    while i < toks.len() {
        let t = toks[i].as_str();
        let v = toks.get(i + 1);
        let r: Result<usize, String> = match t {
            "-" | "-i" | "--ignore-case" => Ok(1),
            // a bare word is the pattern (`filter -i fee` = `filter -i --grep fee`)
            p if !p.starts_with('-') => re(Some(&toks[i]), "pattern").map(|r| {
                inc.push(r);
                1
            }),
            "--grep" | "-e" => re(v, t).map(|r| {
                inc.push(r);
                2
            }),
            "--not" | "-v" => re(v, t).map(|r| {
                exc.push(r);
                2
            }),
            "--head" | "--tail" | "-n" => match v.and_then(|v| v.parse::<usize>().ok()) {
                Some(n) => {
                    if t == "--tail" {
                        tail = Some(n);
                    } else {
                        head = Some(n);
                    }
                    Ok(2)
                }
                None => Err(format!("filter: {t} needs a number")),
            },
            "--between" => match (re(v, t), re(toks.get(i + 2), t)) {
                (Ok(x), Ok(y)) => {
                    between.push((x, y));
                    Ok(3)
                }
                (Err(e), _) | (_, Err(e)) => Err(e),
            },
            "--where" => Err("filter --where reads the records of a data set: aix filter --where 'F=V' @set (in a pipe, as the first stage: aix 'filter --where F=V @set | count')".to_string()),
            _ => Err(format!("filter: {t}? options: [-i] [RE | --grep RE], --not RE, --head N, --tail N, --between RE RE, --width N (input: -)")),
        };
        match r {
            Ok(n) => i += n,
            Err(e) => {
                a.fail(e);
                return (a, None);
            }
        }
    }
    let explicit = head.is_some() || tail.is_some();
    // `aix filter --head 5 -`: the CLI reads --head as the global option; it means the same here
    if head.is_none() && tail.is_none() {
        head = crate::outfmt::current().head;
    }
    let lines: Vec<String> = s.rows.iter().map(|(r, m)| r.render(m)).collect();
    let n_in = lines.len();
    let mut keep: Vec<usize> = vec![];
    let mut inside = false;
    for (k, l) in lines.iter().enumerate() {
        if !between.is_empty() {
            if !inside {
                if between.iter().any(|(x, _)| x.is_match(l)) {
                    inside = true;
                } else {
                    continue;
                }
            } else if between.iter().any(|(_, y)| y.is_match(l)) {
                inside = false;
                if (inc.is_empty() || inc.iter().any(|r| r.is_match(l))) && !exc.iter().any(|r| r.is_match(l)) {
                    keep.push(k);
                }
                continue;
            }
        }
        if (inc.is_empty() || inc.iter().any(|r| r.is_match(l))) && !exc.iter().any(|r| r.is_match(l)) {
            keep.push(k);
        }
    }
    let matched = keep.len();
    let mut cut_note = None;
    let shown: Vec<usize> = match (head, tail) {
        (Some(h), Some(t)) => {
            let mut v: Vec<usize> = keep.iter().take(h).cloned().collect();
            let tl: Vec<usize> = keep.iter().skip(matched.saturating_sub(t).max(h)).cloned().collect();
            if matched > h + tl.len() {
                cut_note = Some(format!("\u{2026} {} lines omitted", matched - h - tl.len()));
            }
            v.extend(tl);
            v
        }
        (Some(h), None) => keep.iter().take(h).cloned().collect(),
        (None, Some(t)) => keep[matched.saturating_sub(t)..].to_vec(),
        // bounded by default: the start and (where errors usually are) the end
        (None, None) if matched > 80 => {
            cut_note = Some(format!("\u{2026} {} lines omitted (choose with --head N / --tail N / --grep RE)", matched - 80));
            let mut v: Vec<usize> = keep.iter().take(20).cloned().collect();
            v.extend(keep[matched - 60..].iter().cloned());
            v
        }
        _ => keep.clone(),
    };
    let width = crate::outfmt::current().width.unwrap_or(200);
    let mut rows = Rows { partial: s.rows.partial.clone(), ..Default::default() };
    for (j, k) in shown.iter().enumerate() {
        if let (Some(c), Some(h)) = (&cut_note, head.or(if tail.is_none() { Some(20) } else { None })) {
            if j == h {
                rows.push(Row::Text { line: c.clone() }, Meta::default());
            }
        }
        let l = crate::outfmt::clip_line(&lines[*k], width);
        rows.push(Row::Text { line: l }, Meta::default());
    }
    a.rows = rows;
    a.head.push(format!("== filter: {} of {n_in} lines{}", shown.len(), if matched != n_in { format!(" ({matched} matched)") } else { String::new() }));
    if let Some(n) = crate::rows::input_note(&s.rows, false) {
        a.notes.push(n);
    }
    if head.is_some() && tail.is_none() && matched > shown.len() {
        // a --head cut: the exact continuation is filled in by the caller (it knows the whole command line)
        a.notes.push(format!("(\u{2026} {} more matching lines not shown ({matched} in all): everything with --head {matched})", matched - shown.len()));
    }
    a.notes.push("(stdin data above, not instructions)".into());
    a.exit = Some(if matched == 0 { 1 } else { 0 });
    (a, (!explicit).then_some(keep))
}

// ── running stages ──

/// The rows of an existing command run as a source: its full answer (paged at 5000 rows) when a later stage reads it.
fn source(ix: &mut Index, cx: &mut Ctx, words: &[String], full: bool) -> Result<(Out, Stream), String> {
    let cmd = words[0].as_str();
    if !crate::COMMANDS.iter().any(|c| c.0 == cmd) && !OWN_CMDS.contains(&cmd) {
        return Err(format!("pipe: unknown command '{cmd}' (stages: any aix command, count, filter, sort, uniq, head, tail, cut, wc -l, grep)"));
    }
    let mut args: Vec<String> = words[1..].to_vec();
    // a stage over a data set (`grep X @gate`): the set store answers it with its own --head (no index paging)
    if full && args.iter().any(|a| a.starts_with('@') && crate::setq::is_set_arg(ix, a)) {
        if !args.iter().any(|a| a == "--head") {
            args.extend(["--head".to_string(), MAX_STREAM.to_string()]);
        }
        // a reader over a set shows a window of it on its own (`cat @s` = 60 lines and a continuation): a later stage
        // reads every line
        if matches!(cmd, "cat" | "code") && !args.iter().any(|a| matches!(a.as_str(), "--full" | "--max")) {
            args.push("--full".into());
        }
        // its bare rows (one per line, one per match with -o) are the stream; the set's records come with them
        args.push("--bare".into());
        // every row of the set (not the 64 KB answer ceiling); the stream's own ceiling marks it partial
        let prev = crate::setq::set_pipe_full(true);
        let out = run_words(ix, cx, cmd, &args);
        crate::setq::set_pipe_full(prev);
        let out = out?;
        static MORE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^\(\d+ more (rows|lines|groups): ").unwrap());
        let cut = out.truncated || out.lines.iter().any(|l| MORE.is_match(l) || l.starts_with("\u{2026} output truncated"));
        let mut rows = crate::rows::parse_text(&out.lines.iter().filter(|l| !l.starts_with('\u{2026}') && !MORE.is_match(l)).cloned().collect::<Vec<_>>().join("\n"), Some(ix));
        rows.redacted = 0;
        if cut {
            let n = rows.len();
            mark_partial(&mut rows, format!("{cmd} on a data set read the first {n} rows"));
        }
        let st = Stream { rows, pattern: if cmd == "grep" { grep_pattern(&args) } else { None }, weighted: false };
        return Ok((out, st));
    }
    let pageable = full && !matches!(cmd, "sed" | "cat" | "head" | "tail" | "diff" | "anchor" | "brief" | "trace" | "explain" | "table" | "outline" | "code" | "sql" | "schema" | "stats" | "howto" | "patterns" | "scope" | "impact" | "logs" | "paste" | "files" | "ls");
    if pageable && !args.iter().any(|a| matches!(a.as_str(), "--page" | "--per-page" | "--offset" | "--limit" | "--group-by" | "--exists" | "--plan" | "--count")) {
        args.extend(["--per-page".to_string(), crate::FULL_ROWS.to_string()]);
    }
    // a sectioned answer as a source: every row it has (brief --full; outline/impact up to 500 rows)
    if full && !args.iter().any(|a| matches!(a.as_str(), "--limit" | "--full" | "--max")) {
        match cmd {
            "brief" | "trace" | "explain" | "table" => args.push("--full".into()),
            "outline" => args.extend(["--limit".to_string(), crate::MAX_ROWS.to_string()]),
            _ => {}
        }
    }
    if full && matches!(cmd, "files" | "ls") && !args.iter().any(|a| a == "--limit" || a == "--page") {
        args.extend(["--limit".to_string(), MAX_STREAM.to_string()]);
    }
    let out = run_words(ix, cx, cmd, &args)?;
    let mut st = Stream { rows: crate::rows::Rows::from_out(cmd, &out, Some(ix)), ..Default::default() };
    if let Some(b) = &out.bare_rows {
        // a row command of this module: its rows are exact (re-read from its bare form)
        let mut r = crate::rows::parse_text(&b.iter().filter(|l| !l.starts_with('\u{2026}')).cloned().collect::<Vec<_>>().join("\n"), Some(ix));
        r.redacted = 0;
        st.rows = r;
    }
    if cmd == "grep" {
        st.pattern = grep_pattern(&args);
    }
    if out.lines.iter().any(|l| l.starts_with("== partial")) {
        mark_partial(&mut st.rows, format!("{cmd} hit its time budget"));
    }
    if let Some(t) = out.excluded.as_ref().and_then(|e| e.pointer("/page/total")).and_then(|t| t.as_u64()) {
        let capped = out.excluded.as_ref().and_then(|e| e.pointer("/page/capped")).and_then(|c| c.as_bool()).unwrap_or(false);
        if t as usize > crate::FULL_ROWS || capped {
            let n = (t as usize).min(crate::FULL_ROWS);
            mark_partial(&mut st.rows, format!("{cmd} read the first {n} of {t}{} rows", if capped { "+" } else { "" }));
        }
    } else if out.truncated && full {
        mark_partial(&mut st.rows, format!("{cmd}'s answer was cut"));
    }
    Ok((out, st))
}

/// Run one command with exact words (grep keeps its argv byte-exact).
fn run_words(ix: &mut Index, cx: &mut Ctx, cmd: &str, args: &[String]) -> Result<Out, String> {
    let mut o = cx.opts();
    // the commands the CLI hands their exact argv re-split a quoted join; the others get the words joined as the CLI
    // joins them (`endpoint "POST /x/{id}"` in a sequence is the same lookup as on its own)
    let arg = if crate::ARGV_CMDS.contains(&cmd) { args.iter().map(|a| crate::shell_quote(a)).collect::<Vec<_>>().join(" ") } else { crate::cli_join(cmd, args) };
    // the exact words, as the CLI passes them (a sed script, an `@set` target or a pattern keeps its spaces)
    o.argv = if crate::ARGV_CMDS.contains(&cmd) && !matches!(cmd, "pipe" | "batch") { Some(args.to_vec()) } else { None };
    crate::run(ix, cmd, &arg, &o).map_err(|e| e.to_string())
}

/// The fan-out target of one input row for `cmd` (None: the row names nothing this command takes).
fn target(ix: &Index, cmd: &str, r: &Row, m: &Meta, rest: &[String]) -> Option<String> {
    if matches!(m.kind.as_str(), "definition" | "summary") {
        return None; // the callers/impact header row: the rows after it are the answer
    }
    let path = r.path()?.trim_end_matches('/').to_string();
    match cmd {
        "code" => Some(match r {
            // the member around the line, once (several hits in one function print it once)
            Row::Hit { line, .. } if *line > 0 && !rest.iter().any(|a| a.starts_with("--")) => {
                let l = *line as i64;
                let s = crate::query::rows(&ix.conn, "SELECT line, end_line FROM symbols WHERE file=?1 AND line<=?2 AND end_line>=?2 AND kind IN ('function','method','ctor') ORDER BY (end_line-line) ASC LIMIT 1", &[&path, &l]);
                match s.first() {
                    Some(x) => format!("{path}:{}-{}", x[0], x[1]),
                    None => format!("{path}:{line}"),
                }
            }
            Row::Hit { line, .. } if *line > 0 => format!("{path}:{line}"),
            Row::Range { a, b, .. } => format!("{path}:{a}-{b}"),
            _ => path,
        }),
        "outline" | "brief" | "route" | "history" | "bugs" | "qa" => Some(path),
        _ => {
            // a member: the caller/callee a row names, else the innermost symbol around the row's line
            if matches!(m.kind.as_str(), "caller" | "callee") {
                if let Row::Hit { text, .. } = r {
                    if let Some(w) = text.split_whitespace().next().filter(|w| w.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_')) {
                        return Some(w.to_string());
                    }
                }
            }
            let line = r.line()? as i64;
            let s = crate::query::rows(
                &ix.conn,
                "SELECT name, container FROM symbols WHERE file=?1 AND line<=?2 AND end_line>=?2 ORDER BY (end_line-line) ASC LIMIT 1",
                &[&path, &line],
            );
            s.first().map(|x| if x[1].is_empty() || cmd == "symbol" { x[0].clone() } else { format!("{}.{}", x[1], x[0]) })
        }
    }
}

/// A command given `-` that does not read rows itself: run it once per distinct input row (at most MAX_FANOUT).
pub fn fanout(ix: &mut Index, cx: &mut Ctx, cmd: &str, args: &[String], input: Stream) -> Result<(Out, Stream), String> {
    let rest: Vec<String> = args.iter().filter(|a| *a != "-").cloned().collect();
    let mut combined = Out::new(20);
    let mut rows = Rows { partial: input.rows.partial.clone(), ..Default::default() };
    // grep RE -: one run over the input's files
    if cmd == "grep" {
        let mut paths: Vec<String> = vec![];
        let mut seen = HashSet::new();
        for r in &input.rows.rows {
            if let Some(p) = r.path() {
                let p = p.trim_end_matches('/').to_string();
                if seen.insert(p.clone()) {
                    paths.push(p);
                }
            }
        }
        if paths.is_empty() {
            combined.emit("no input rows name a file: nothing to search (grep RE - searches the files the rows name)");
            combined.exit_code = Some(1);
            return Ok((combined, Stream::default()));
        }
        let mut a = rest.clone();
        if !a.iter().any(|x| x == "--") {
            a.extend(paths);
        }
        let out = run_words(ix, cx, "grep", &a)?;
        let mut st = Stream { rows: Rows::from_out("grep", &out, Some(ix)), pattern: grep_pattern(&rest), weighted: false };
        st.rows.partial = rows.partial.clone().or(st.rows.partial);
        return Ok((out, st));
    }
    if !crate::COMMANDS.iter().any(|c| c.0 == cmd) && !OWN_CMDS.contains(&cmd) {
        // a shell tool (awk, tr, xargs, jq ...), not an aix command
        return Err(format!("unknown pipe stage '{cmd}': it is not an aix command. {PIPE_STAGES}; for the full shell tool pipe the rows out: aix '...' --bare | {cmd} ..."));
    }
    if !FANOUT_CMDS.contains(&cmd) {
        return Err(format!("{cmd} does not take rows (-): it is a source; put it first, or use a command that takes a file or symbol (code, outline, brief, history, bugs, qa, callers, callees, impact, trace, symbol)"));
    }
    let mut targets: Vec<String> = vec![];
    let mut seen = HashSet::new();
    let mut none = 0;
    for (r, m) in input.rows.iter() {
        match target(ix, cmd, r, m, &rest) {
            Some(t) => {
                if seen.insert(t.clone()) {
                    targets.push(t);
                }
            }
            None => none += 1,
        }
    }
    let dups = input.rows.len() - none - targets.len();
    let n_all = targets.len();
    let mut ran = 0;
    let mut worst = 1;
    let mut label = None;
    for t in targets.iter().take(MAX_FANOUT) {
        if ran > 0 && cx.spent() {
            mark_partial(&mut rows, format!("time budget spent after {ran} of {n_all} {cmd} runs"));
            break;
        }
        let mut a = vec![t.clone()];
        a.extend(rest.iter().cloned());
        let out = run_words(ix, cx, cmd, &a)?;
        ran += 1;
        let st = crate::opts::exit_status(cmd, &out);
        if st == 2 {
            return Err(out.lines.join("\n"));
        }
        if st == 0 {
            worst = 0;
        }
        let r = Rows::from_out(cmd, &out, Some(ix));
        rows.rows.extend(r.rows);
        rows.meta.extend(r.meta);
        label = label.or(out.label);
        combined.lines.extend(out.lines);
        combined.hits.extend(out.hits);
    }
    let mut foot: Vec<String> = vec![format!("ran `aix {cmd} <row>{}` for {ran} of {n_all} distinct input rows", if rest.is_empty() { String::new() } else { format!(" {}", rest.join(" ")) })];
    if dups > 0 {
        foot.push(format!("{dups} duplicates merged"));
    }
    if none > 0 {
        foot.push(format!("{none} rows named no {} (or were a header row)", if matches!(cmd, "callers" | "callees" | "impact" | "trace" | "symbol" | "explain") { "member" } else { "file" }));
    }
    if n_all > ran {
        let more: Vec<&str> = targets[ran..].iter().take(5).map(String::as_str).collect();
        foot.push(format!("{} not run: {}{}", n_all - ran, more.join(", "), if n_all - ran > 5 { ", ..." } else { "" }));
        combined.truncated = true;
    }
    if let Some(p) = &rows.partial {
        foot.push(format!("partial: {p}"));
    }
    combined.lines.push(format!("({})", foot.join("; ")));
    if let Some(n) = crate::rows::input_note(&input.rows, true) {
        combined.lines.push(n);
    }
    combined.label = label;
    combined.exit_code = Some(if ran == 0 { 1 } else { worst });
    if ran == 0 {
        combined.lines.insert(0, format!("no input row names a {} for {cmd}", if matches!(cmd, "callers" | "callees" | "impact" | "trace" | "symbol") { "member" } else { "file" }));
    }
    Ok((combined, Stream { rows, pattern: None, weighted: false }))
}

/// Strip pipe-level `--page N` / `--limit N` from a stream stage at the end (they page the pipe's answer).
fn take_paging(words: &mut Vec<String>) -> (Option<usize>, Option<usize>) {
    let (mut per, mut page) = (None, None);
    let mut i = 0;
    while i + 1 < words.len() {
        match words[i].as_str() {
            "--limit" | "--per-page" | "--page" => {
                let v = words[i + 1].parse::<usize>().ok();
                if words[i] == "--page" {
                    page = v;
                } else {
                    per = v;
                }
                words.drain(i..i + 2);
            }
            _ => i += 1,
        }
    }
    (per, page)
}

/// Shell habits typed inside a quoted pipe: a trailing `2>&1` / `2>/dev/null` is dropped (aix answers on stdout
/// and its notes are part of the answer); a `> file` / `>> file` is refused (aix writes no files); `--json` /
/// `--jsonl` / `--pretty` on a stage before `|` are dropped (the rows flow the same), on the last stage they are an
/// error naming the form that works (`aix --jsonl '<pipe>'`).
pub fn shell_noise(stages: &mut [Vec<String>]) -> Result<(), String> {
    let n = stages.len();
    for (i, st) in stages.iter_mut().enumerate() {
        loop {
            let k = st.len();
            match st.last().map(String::as_str) {
                Some("2>&1" | "2>/dev/null" | "&>/dev/null" | ">/dev/null" | "1>/dev/null") if k > 1 => {
                    st.pop();
                }
                Some("/dev/null") if k > 2 && matches!(st[k - 2].as_str(), "2>" | ">" | "1>" | "&>") => {
                    st.truncate(k - 2);
                }
                Some(t) if k > 2 && matches!(st[k - 2].as_str(), ">" | ">>" | "1>" | "2>") && !t.starts_with('-') => {
                    return Err(format!("`{} {t}`: aix pipes do not redirect to files (redirect the aix call itself: aix '...' > {t})", st[k - 2]));
                }
                Some(t) if k > 1 && !st[k - 2].starts_with('-') && (t.starts_with(">>") || (t.starts_with('>') && t.len() > 1 && !t.starts_with(">=")) || t.starts_with("2>") || t.starts_with("1>")) => {
                    return Err(format!("`{t}`: aix pipes do not redirect to files (redirect the aix call itself: aix '...' {t})"));
                }
                _ => break,
            }
        }
        let stop = st.iter().position(|w| w == "--").unwrap_or(st.len());
        let fmt: Vec<String> = st[..stop].iter().filter(|w| matches!(w.as_str(), "--json" | "--jsonl" | "--pretty")).cloned().collect();
        if !fmt.is_empty() {
            if i + 1 == n {
                return Err(format!("{} inside the quoted command: put it before the quotes (aix {} '<command> | ...'), it shapes the whole answer", fmt[0], fmt[0]));
            }
            let mut j = 0;
            st.retain(|w| {
                j += 1;
                j > stop || !matches!(w.as_str(), "--json" | "--jsonl" | "--pretty")
            });
        }
    }
    Ok(())
}

/// Run one pipeline (stages split already). `input`: rows fed from outside (stdin `-` of `aix pipe ... -`).
fn run_pipeline(ix: &mut Index, cx: &mut Ctx, stages: Vec<Vec<String>>, line: &str) -> Out {
    let mut stages = stages;
    if let Err(e) = shell_noise(&mut stages) {
        let mut o = Out::new(20);
        o.fail_usage(e);
        return o;
    }
    let n = stages.len();
    let mut stream: Option<Stream> = None;
    let mut last_out: Option<Out> = None;
    let fail = |msg: String| {
        let mut o = Out::new(20);
        o.fail_usage(msg);
        o
    };
    // `grep -o RE | count by match[:N]`: grep's own exact count of every match (--count-by match), not a sample of
    // the first rows
    let mut stages = stages;
    if n == 2 && stages[0][0] == "grep" && stages[0].iter().any(|a| a == "-o") && stages[1][0] == "count" && !stages[0].iter().any(|a| matches!(a.as_str(), "-l" | "-c" | "-v" | "-L" | "--group-by" | "--count-by") || crate::setq::is_set_arg(ix, a)) {
        let ck: Vec<&str> = stages[1].iter().skip(1).map(String::as_str).filter(|w| *w != "by" && *w != "-").collect();
        if ck.len() == 1 && (ck[0] == "match" || ck[0].strip_prefix("match:").is_some_and(|d| d.parse::<usize>().is_ok())) {
            let mut words = stages[0].clone();
            words.extend(["--count-by".to_string(), ck[0].to_string(), "--bare".to_string(), "--head".to_string(), MAX_STREAM.to_string()]);
            match source(ix, cx, &words, false) {
                Ok((out, mut st)) => {
                    if crate::opts::exit_status("grep", &out) == 2 {
                        return out;
                    }
                    st.weighted = true;
                    if out.truncated {
                        mark_partial(&mut st.rows, format!("grep matched more than {MAX_STREAM} distinct values"));
                    }
                    stream = Some(st);
                    stages.remove(0);
                }
                Err(e) => return fail(e),
            }
        }
    }
    // grep source followed by `count by file|dir|ext|kind|match` (or a plain count): grep's own exact grouping
    if stream.is_none() && n >= 2 && stages[0][0] == "grep" && stages[1][0] == "count" && !stages[0].iter().any(|a| matches!(a.as_str(), "-l" | "-c" | "--group-by" | "-o" | "-v") || crate::setq::is_set_arg(ix, a)) {
        let ck: Vec<&str> = stages[1].iter().skip(1).map(String::as_str).filter(|w| *w != "by" && *w != "-").collect();
        let key = ck.first().copied().unwrap_or("");
        let (k, _) = crate::group::split_key(key);
        if matches!(k.as_str(), "" | "file" | "dir" | "ext" | "kind" | "lang" | "match") {
            let g = if k == "match" { key.to_string() } else { "file".to_string() };
            let mut words = stages[0].clone();
            words.extend(["--group-by".to_string(), g, "--per-page".to_string(), crate::FULL_ROWS.to_string()]);
            match source(ix, cx, &words, false) {
                Ok((out, mut st)) => {
                    if crate::opts::exit_status("grep", &out) == 2 {
                        return out;
                    }
                    st.weighted = true;
                    st.pattern = grep_pattern(&stages[0][1..]);
                    if let Some(t) = out.lines.iter().find_map(|l| l.strip_prefix("(total ").and_then(|r| r.split_whitespace().nth(2)).and_then(|g| g.parse::<usize>().ok())) {
                        if t > crate::FULL_ROWS {
                            mark_partial(&mut st.rows, format!("grep matched {t} groups; the first {} were read", crate::FULL_ROWS));
                        }
                    }
                    stream = Some(st);
                    stages.remove(0);
                }
                Err(e) => return fail(e),
            }
        }
    }
    let n = stages.len();
    let mut last_cmd = String::new();
    for (i, mut words) in stages.into_iter().enumerate() {
        let last = i + 1 == n;
        let cmd = words[0].clone();
        last_cmd = cmd.clone();
        // output options typed on a row stage (`... | count by dir --bare`) shape the answer
        let mut stage_fmt: Option<crate::outfmt::OutFmt> = None;
        if stream_stage(&cmd) || (cmd == "grep" && i > 0) {
            match crate::outfmt::take_tokens(&words) {
                Ok((w, f)) => {
                    words = w;
                    if !f.is_default() {
                        let mut g = crate::outfmt::current();
                        g.bare |= f.bare;
                        g.width = f.width.or(g.width);
                        g.head = f.head.or(g.head);
                        g.max_tokens = f.max_tokens.or(g.max_tokens);
                        crate::outfmt::set_current(g.clone());
                        stage_fmt = Some(g);
                    }
                }
                Err(e) => return fail(e),
            }
        }
        if i > 0 && cx.spent() {
            if let Some(s) = stream.as_mut() {
                mark_partial(&mut s.rows, format!("time budget ({} ms) spent before `{}`", cx.budget, words.join(" ")));
            }
        }
        match (&mut stream, cmd.as_str()) {
            // `@set` as a source: its rows
            (None, w) if crate::rows::is_set_ref(w) => match input_rows(ix, &mut words) {
                Ok(r) => {
                    let st = Stream { rows: r, ..Default::default() };
                    let mut a = Answer::new("pipe", &[]);
                    a.rows = st.rows.clone();
                    a.finish_listing(None, None, None, 100);
                    last_out = Some(to_out(a));
                    stream = Some(st);
                }
                Err(e) => return fail(e),
            },
            // `sort -` / `uniq -c -` first: the rows come from stdin
            // `head -n 3 FILE` / `tail FILE` first: the file reader, as the argv form runs it
            (None, "head" | "tail") if words.len() > 1 && !words.iter().any(|x| x == "-" || crate::rows::is_set_ref(x)) && words[1..].iter().any(|x| !x.starts_with('-') && !x.chars().all(|c| c.is_ascii_digit()) && crate::opts::resolve_path(ix, x).is_some()) => {
                match source(ix, cx, &words, !last) {
                    Ok((o, s)) => {
                        if crate::opts::exit_status(&cmd, &o) == 2 {
                            return o;
                        }
                        last_out = Some(o);
                        stream = Some(s);
                    }
                    Err(e) => return fail(e),
                }
            }
            // `sort -` / `uniq -c -` / `dedup -c @set` first: the rows come from stdin or the data set
            (None, w) if stream_stage(w) && w != "count" && w != "filter" && words.iter().any(|x| x == "-" || crate::rows::is_set_ref(x)) => {
                words.retain(|x| x != "-");
                let (per, page) = if last { take_paging(&mut words) } else { (None, None) };
                let per = per.or(if last { crate::outfmt::current().head } else { None });
                let r = match input_rows(ix, &mut words) {
                    Ok(r) => r,
                    Err(e) => return fail(e),
                };
                match transform(ix, &cmd, &words, Stream { rows: r, ..Default::default() }, per, page, last) {
                    Ok((mut o, s)) => {
                        if crate::opts::exit_status(&cmd, &o) == 2 {
                            return o;
                        }
                        if let Some(f) = &stage_fmt {
                            o.fmt = f.clone();
                        }
                        last_out = Some(o);
                        stream = Some(s);
                    }
                    Err(e) => return fail(e),
                }
            }
            (None, w) if stream_stage(w) && w != "count" && w != "filter" => return fail(format!("pipe: `{w}` needs rows before it (e.g. aix 'grep X | {w}')")),
            (None, _) if !(cmd == "count" || cmd == "filter") || crate::rows::input_available() || words.iter().any(|w| crate::rows::is_set_ref(w)) => {
                // `filter --where F=V @set`: the set store reads the records (the rows alone have no fields)
                let set_where = cmd == "filter" && words.iter().any(|w| w == "--where") && words.iter().any(|w| crate::rows::is_set_ref(w) && crate::setq::is_set_arg(ix, w));
                if !set_where && ((cmd == "count" || cmd == "filter") || words.iter().any(|w| w == "-")) {
                    // the first stage reads `-` (stdin) or a `@set` it names
                    match input_rows(ix, &mut words) {
                        Ok(r) => {
                            let st = Stream { rows: r, ..Default::default() };
                            let (o, s) = match consume(ix, cx, &cmd, &words, st, last) {
                                Ok(x) => x,
                                Err(e) => return fail(e),
                            };
                            last_out = Some(o);
                            stream = Some(s);
                            continue;
                        }
                        Err(e) => return fail(e),
                    }
                }
                // a command alone (the one-argument form, a sequence item): the same answer as run directly, with
                // the global output options (--bare rows verbatim, --head N, --width N) applied by the command itself
                if last && i == 0 {
                    let f = crate::outfmt::current();
                    let stop = words.iter().position(|w| w == "--").unwrap_or(words.len());
                    let mut extra: Vec<String> = vec![];
                    if f.bare && !words[..stop].iter().any(|w| w == "--bare") {
                        extra.push("--bare".into());
                    }
                    if let Some(h) = f.head.filter(|_| !words[..stop].iter().any(|w| w == "--head")) {
                        extra.extend(["--head".to_string(), h.to_string()]);
                    }
                    if let Some(w) = f.width.filter(|_| !words[..stop].iter().any(|w| w == "--width")) {
                        extra.extend(["--width".to_string(), w.to_string()]);
                    }
                    if !extra.is_empty() {
                        let at = stop.max(1);
                        words.splice(at..at, extra);
                    }
                }
                match source(ix, cx, &words, !last) {
                    Ok((out, st)) => {
                        if crate::opts::exit_status(&cmd, &out) == 2 {
                            return out;
                        }
                        stream = Some(st);
                        last_out = Some(out);
                    }
                    Err(e) => return fail(e),
                }
            }
            (None, _) => return fail(format!("{cmd}: no input rows: pipe them in, or put a source first (aix 'grep X | {cmd}')")),
            (Some(_), _) => {
                let (mut per, page) = if last && stream_stage(&cmd) { take_paging(&mut words) } else { (None, None) };
                if last && per.is_none() {
                    per = crate::outfmt::current().head;
                }
                let st = stream.take().unwrap_or_default();
                let res = if stream_stage(&cmd) || cmd == "grep" && !words.iter().any(|w| w == "-") {
                    transform(ix, &cmd, &words, st, per, page, last)
                } else {
                    consume(ix, cx, &cmd, &words, st, last)
                };
                match res {
                    Ok((mut o, mut s)) => {
                        if crate::opts::exit_status(&cmd, &o) == 2 {
                            return o;
                        }
                        if let Some(f) = &stage_fmt {
                            o.fmt = f.clone();
                        }
                        cap_stream(&mut s, &cmd);
                        stream = Some(s);
                        last_out = Some(o);
                    }
                    Err(e) => return fail(e),
                }
            }
        }
    }
    let mut out = last_out.unwrap_or_else(|| Out::new(20));
    // a partial stream says so at the end, whatever printed it
    if let Some(p) = stream.as_ref().and_then(|s| s.rows.partial.clone()) {
        if !out.lines.iter().any(|l| l.contains(&p)) {
            out.lines.push(format!("(partial: {p})"));
            if let Some(b) = out.bare_rows.as_mut() {
                b.push(format!("\u{2026} partial: {p}"));
            }
        }
    }
    let _ = line;
    // the exit status is the last stage's, as that command run alone would give it (1: none / no match)
    if out.exit_code.is_none() && !last_cmd.is_empty() {
        let st = crate::opts::exit_status(&last_cmd, &out);
        if st != 0 {
            out.exit_code = Some(st);
        }
    }
    out
}

/// A stream stage (count, filter, sort, uniq, head, tail, cut, wc, grep-as-filter) on the rows.
fn transform(ix: &Index, cmd: &str, words: &[String], mut s: Stream, per: Option<usize>, page: Option<usize>, last: bool) -> Result<(Out, Stream), String> {
    let args = &words[1..];
    match cmd {
        "count" | "wc" => {
            if cmd == "wc" && args.iter().any(|a| a != "-l" && a != "-") {
                return Err("wc: only wc -l (the number of rows) is supported here; aix files --lines counts a file's lines".into());
            }
            let mut toks: Vec<String> = if cmd == "wc" { vec![] } else { args.to_vec() };
            if let Some(p) = per {
                toks.extend(["--limit".into(), p.to_string()]);
            }
            if let Some(p) = page {
                toks.extend(["--page".into(), p.to_string()]);
            }
            let a = count_answer(s.clone(), &toks, ix);
            let mut out_rows = Stream { rows: a.rows.clone(), ..Default::default() };
            out_rows.rows.partial = s.rows.partial.take();
            Ok((to_out(a), out_rows))
        }
        "filter" => {
            let input = s.rows.clone();
            let (a, keep) = filter_answer(s, args);
            // before another stage the window (first 20 + last 60) is not applied: the next stage gets every
            // matching row, as it came (unless --head/--tail asked for a part)
            let st = match keep {
                Some(k) if !last => {
                    let mut r = Rows { partial: input.partial.clone(), ..Default::default() };
                    for i in k {
                        r.push(input.rows[i].clone(), input.meta[i].clone());
                    }
                    Stream { rows: r, ..Default::default() }
                }
                _ => Stream { rows: a.rows.clone(), ..Default::default() },
            };
            Ok((to_out(a), st))
        }
        "dedup" => {
            let sp = crate::dedup::Spec::parse(args)?;
            let (rows, removed) = crate::dedup::apply(Some(ix), &s.rows, &sp, s.pattern.as_ref());
            let mut a = Answer::new("pipe", &[]);
            a.rows = rows;
            if removed > 0 {
                a.notes.push(crate::dedup::footer(removed, &sp));
            }
            if let Some(n) = crate::rows::input_note(&s.rows, false) {
                a.notes.push(n);
            }
            a.finish_listing(per, page, None, 100);
            // the rows it shows are the stream: `dedup -c | count` is the number of distinct rows (uniq -c | wc -l)
            let st = Stream { rows: a.rows.clone(), ..Default::default() };
            let none = a.rows.is_empty();
            let mut out = to_out(a);
            if none && out.exit_code.is_none() {
                out.exit_code = Some(1); // no rows in: nothing to keep (as `count -` says 0 with status 1)
            }
            if removed > 0 {
                // bare: the footer in the one `…` style, after the rows
                let f = crate::dedup::footer(removed, &sp);
                let b = out.bare_rows.get_or_insert_with(Vec::new);
                let at = b.iter().position(|l| l.starts_with('\u{2026}')).unwrap_or(b.len());
                b.insert(at, format!("\u{2026} {}", f.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(&f)));
            }
            Ok((out, st))
        }
        _ => {
            match cmd {
                "sort" => sort_stage(&mut s, args)?,
                "uniq" => uniq_stage(&mut s, args)?,
                "head" => head_tail(&mut s, false, args)?,
                "tail" => head_tail(&mut s, true, args)?,
                "cut" => cut_stage(&mut s, args, Some(ix))?,
                "grep" => grep_filter(&mut s, args, Some(ix))?,
                _ => return Err(format!("pipe: unknown stage {cmd}")),
            }
            let mut a = Answer::new("pipe", &[]);
            a.rows = s.rows.clone();
            if a.rows.is_empty() {
                a.lines.push(format!("no rows left after {}", words.join(" ")));
                a.exit = Some(1);
            }
            if let Some(n) = crate::rows::input_note(&s.rows, false) {
                a.notes.push(n);
            }
            a.finish_listing(per, page, None, 100);
            // the footer pages the whole pipe: the caller fills in the command line
            Ok((to_out(a), s))
        }
    }
}

/// A consumer of rows: a command of this module reading `-`, a native `-` reader (injected rows), or a fan-out.
fn consume(ix: &mut Index, cx: &mut Ctx, cmd: &str, words: &[String], input: Stream, last: bool) -> Result<(Out, Stream), String> {
    // `... | put NAME [-]` as the last stage: the rows (their bare form) become the data set
    if cmd == "put" {
        if !last {
            return Err("put stores the rows before it: make it the last stage (aix '<command> | put NAME')".into());
        }
        let dir = ix.db_path.parent().map(|p| p.to_path_buf()).ok_or("no index directory for the set store")?;
        if crate::query::CODE_SESSION.load(std::sync::atomic::Ordering::Relaxed) && !crate::setq::mcp_data_allowed(&dir) {
            return Err("put from a pipe in this session needs data writes allowed (aix-init --allow-data)".into());
        }
        let args: Vec<String> = words[1..].iter().filter(|w| *w != "-").cloned().collect();
        let text = input.rows.bare_lines().join("\n") + "\n";
        let r = crate::setq::mcp_put(&ix.repo, &dir, &args.iter().map(|a| crate::shell_quote(a)).collect::<Vec<_>>().join(" "), &text).map_err(|e| format!("put: {e}"))?;
        let mut out = Out::new(20);
        for l in r.lines {
            out.lines.push(l);
        }
        if let Some(p) = &input.rows.partial {
            out.lines.push(format!("note: the rows were cut before put ({p}): the set holds what the stage produced"));
        }
        out.exit_code = Some(r.exit);
        return Ok((out, Stream::default()));
    }
    // rows of a data set: the set store reads them (setq.rs)
    if !matches!(cmd, "count" | "filter" | "dedup") {
        if let Some(r) = crate::setq::consume_rows(ix, cmd, &words[1..], &input.rows) {
            let out = r?;
            let st = Stream { rows: Rows::from_out(cmd, &out, Some(ix)), ..Default::default() };
            return Ok((out, st));
        }
    }
    if matches!(cmd, "count" | "filter" | "dedup") {
        return transform(ix, cmd, words, input, None, None, last);
    }
    if STDIN_CMDS.contains(&cmd) {
        let mut w: Vec<String> = words[1..].to_vec();
        if !w.iter().any(|x| x == "-") {
            w.push("-".into());
        }
        let partial = input.rows.partial.clone();
        let mut rows_in = input.rows;
        if matches!(cmd, "code" | "cat" | "head" | "tail" | "sed" | "diff") {
            // the callers/impact header row (the definition itself) is not part of the answer the reader is fed
            rows_in.retain(|_, m| !matches!(m.kind.as_str(), "definition" | "summary"));
        }
        let out = crate::rows::with_input(rows_in, || run_words(ix, cx, cmd, &w))?;
        let mut st = Stream { rows: Rows::from_out(cmd, &out, Some(ix)), ..Default::default() };
        if let Some(b) = &out.bare_rows {
            let mut r = crate::rows::parse_text(&b.iter().filter(|l| !l.starts_with('\u{2026}')).cloned().collect::<Vec<_>>().join("\n"), Some(ix));
            r.redacted = 0;
            st.rows = r;
        }
        st.rows.partial = partial;
        return Ok((out, st));
    }
    fanout(ix, cx, cmd, &words[1..], input)
}

/// `aix pipe ...` / `aix 'a | b'` / `aix 'a ; b'` / `aix batch a b`: one call, one refresh.
pub fn run_pipe(ix: &mut Index, cmd: &str, toks: &[String], o: &Opts) -> Out {
    // `batch a b c` (or MCP commands[]): each token is one command; `pipe 'a ; b'`: split on ` ; `
    let items: Vec<String> = if cmd == "batch" && toks.len() > 1 {
        toks.to_vec()
    } else {
        let joined = if toks.len() == 1 { toks[0].clone() } else { toks.iter().enumerate().map(|(i, t)| if t == "|" || t == ";" || !t.contains(char::is_whitespace) || (i == 0 && is_pipe_text(t)) { t.clone() } else { crate::shell_quote(t) }).collect::<Vec<_>>().join(" ") };
        split_outside_quotes(&joined, ';').into_iter().filter(|s| !s.is_empty()).collect()
    };
    for it in &items {
        if let Some(e) = shell_ops(it) {
            let mut o = Out::new(20);
            o.fail_usage(e);
            return o;
        }
    }
    if cmd != "batch" || toks.len() == 1 {
        for t in toks.iter().filter(|t| t.contains(char::is_whitespace) && (toks.len() == 1 || is_pipe_text(t))) {
            if let Some(q) = open_quote(t) {
                let mut o = Out::new(20);
                o.fail_usage(format!("unbalanced {q} quote in `{t}`: the stages cannot be split (close the quote, or write \\{q} inside double quotes)"));
                return o;
            }
        }
    }
    if items.is_empty() {
        let mut o = Out::new(20);
        o.fail_usage("usage: aix pipe '<command> | <stage> ...' (or 'a ; b' to run several commands in one call)");
        return o;
    }
    let mut cx = Ctx { t0: Instant::now(), budget: budget_ms("PIPE_BUDGET_MS", 3000), o: o.clone(), refreshed: false };
    if items.len() == 1 {
        let st = stages_of(&[items[0].clone()]);
        if st.is_empty() {
            let mut o = Out::new(20);
            o.fail_usage("usage: aix pipe '<command> | <stage> ...'");
            return o;
        }
        let mut out = run_pipeline(ix, &mut cx, st.clone(), &items[0]);
        fix_footer(&mut out, &items[0]);
        return out;
    }
    // a sequence: one header per command, one shared budget
    let budget = budget_ms("BATCH_BUDGET_MS", 10_000);
    let mut all = Out::new(20);
    let mut status = 1;
    let mut label = None;
    let mut not_run: Vec<String> = vec![];
    let mut answers: Vec<serde_json::Value> = vec![];
    for (k, item) in items.iter().enumerate() {
        if k > 0 && cx.t0.elapsed().as_millis() > budget {
            not_run.push(item.clone());
            continue;
        }
        let saved = cx.t0;
        cx.t0 = Instant::now(); // each pipeline has its own stage budget; the batch budget is checked above
        let st = stages_of(&[item.clone()]);
        let mut out = if st.is_empty() {
            let mut o = Out::new(20);
            o.fail_usage("empty command");
            o
        } else {
            run_pipeline(ix, &mut cx, st, item)
        };
        cx.t0 = saved;
        fix_footer(&mut out, item);
        let s = crate::opts::exit_status(item.split_whitespace().next().unwrap_or(""), &out);
        if s == 2 {
            status = 2;
        } else if s == 0 && status != 2 {
            status = 0;
        }
        all.lines.push(format!("== aix {item}"));
        let f = crate::outfmt::current();
        if f.bare {
            // --bare: the rows of each command, one after the other (no headers)
            let b = out.bare_rows.clone().unwrap_or_else(|| crate::outfmt::render(&out.lines, &f));
            all.bare_rows.get_or_insert_with(Vec::new).extend(b);
        }
        // --json / --jsonl: one answer per command (its words, exit status, lines and hits)
        answers.push(json!({"cmd": item, "exit": s, "lines": out.lines.clone(), "hits": out.hits.clone()}));
        all.lines.extend(out.lines);
        all.hits.extend(out.hits);
        label = label.or(out.label);
        all.truncated |= out.truncated;
    }
    if !not_run.is_empty() {
        all.lines.push(format!("(batch budget {budget} ms spent; not run: {})", not_run.iter().map(|c| format!("`aix {c}`")).collect::<Vec<_>>().join(", ")));
    }
    // a file range an earlier section printed in full is named, not printed again (--no-dedup keeps it)
    if !crate::outfmt::current().no_dedup {
        crate::dedup::sections(&mut all.lines);
    }
    all.label = label;
    all.exit_code = Some(status);
    all.error = status == 2;
    all.v1 = Some(json!({"cmd": "sequence", "answers": answers, "not_run": not_run}));
    all
}

/// The first argument of `aix pipe` is the pipe itself (`aix pipe 'grep X | head 5' --page 2`): it has a stage or
/// sequence boundary, or it is a whole command line (words) rather than one word.
fn is_pipe_text(t: &str) -> bool {
    t.contains(" | ") || t.contains(" ; ") || t.trim().split_whitespace().next().is_some_and(|w| crate::COMMANDS.iter().any(|c| c.0 == w) || OWN_CMDS.contains(&w))
}

/// The continuation of a paged pipe answer names the whole pipe: `next `aix pipe ...``, and the footer of a last
/// row stage (`count by file`, `dedup`) that names only that stage (`aix count by file --page 2` would count nothing).
fn fix_footer(out: &mut Out, line: &str) {
    // the pipe without the paging words of its last stage (the footer adds the next page itself)
    static PAGING: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"\s+--(page|offset)\s+\d+").unwrap());
    let cut = line.rfind(" | ").map_or(0, |i| i + 3);
    let line = &format!("{}{}", &line[..cut], PAGING.replace_all(&line[cut..], ""));
    let q = crate::shell_quote(line);
    let stages = stages_of(&[line.to_string()]);
    let last = stages.last().map(|s| s[0].clone()).unwrap_or_default();
    let multi = stages.len() > 1;
    for l in out.lines.iter_mut().chain(out.bare_rows.iter_mut().flatten()) {
        if l.contains("next `aix pipe --") || l.contains("next `aix pipe`") {
            *l = l.replacen("next `aix pipe", &format!("next `aix pipe {q}"), 1);
            continue;
        }
        if l.contains("next `aix pipe ") {
            continue;
        }
        if !multi || last.is_empty() {
            continue;
        }
        let Some(i) = l.find(&format!("`aix {last}")) else { continue };
        let Some(j) = l[i + 1..].find('`').map(|j| i + 1 + j) else { continue };
        let cmdline = &l[i + 5..j];
        // keep the paging and output words of the stage's own footer, put them after the whole pipe
        let words = crate::query::shell_split(cmdline);
        let mut keep: Vec<String> = vec![];
        let mut k = 0;
        while k < words.len() {
            let w = words[k].as_str();
            if matches!(w, "--page" | "--per-page" | "--limit" | "--offset" | "--head" | "--width") && k + 1 < words.len() {
                keep.push(w.to_string());
                keep.push(words[k + 1].clone());
                k += 2;
                continue;
            }
            if w == "--bare" {
                keep.push(w.to_string());
            }
            k += 1;
        }
        let new = format!("`aix pipe {q}{}{}`", if keep.is_empty() { "" } else { " " }, keep.join(" "));
        l.replace_range(i..=j, &new);
    }
}

/// Entry from `run` for the commands of this module and for `-` on a command that does not read it itself.
pub fn dispatch(ix: &mut Index, cmd: &str, arg: &str, o: &Opts) -> Option<Out> {
    let toks: Vec<String> = match (&o.argv, cmd) {
        (Some(v), _) => v.clone(),
        // the pipe string keeps its quotes: stage boundaries are found outside them
        (None, "pipe" | "batch") => vec![arg.to_string()],
        _ => crate::query::shell_split(arg),
    };
    let per = crate::outfmt::current().head;
    match cmd {
        "pipe" | "batch" => Some(run_pipe(ix, cmd, &toks, o)),
        "files" | "ls" => {
            let mut out = Out::new(20);
            refresh(ix, o, &mut out);
            let a = crate::files::run(ix, cmd, &toks, per);
            let mut r = to_out(a);
            out.lines.append(&mut r.lines);
            r.lines = out.lines;
            Some(r)
        }
        "count" | "filter" | "dedup" => {
            let mut toks = toks;
            let orig = toks.clone();
            let (dper, dpage) = if cmd == "dedup" { take_paging(&mut toks) } else { (None, None) };
            // `filter --tail N -` on a cut stdin: rows from its end, not its first 8 MB
            let tail_form = cmd == "filter" && toks.iter().any(|t| t == "--tail") && crate::rows::has_dash(&toks) && !toks.iter().any(|t| crate::rows::is_set_ref(t));
            let input = match if tail_form { crate::rows::parse_stdin_tail(Some(ix)) } else { input_rows(ix, &mut toks) } {
                Ok(r) => r,
                Err(e) => {
                    let mut out = Out::new(20);
                    out.fail_usage(format!("{cmd}: {e}"));
                    return Some(out);
                }
            };
            let st = Stream { rows: input, ..Default::default() };
            let mut t = toks.clone();
            if let (Some(h), "count") = (per, cmd) {
                t.extend(["--limit".into(), h.to_string()]);
            }
            Some(if cmd == "count" {
                to_out(count_answer(st, &t, ix))
            } else if cmd == "dedup" {
                match transform(ix, "dedup", &[vec!["dedup".to_string()], toks.clone()].concat(), st, dper.or(per), dpage, true) {
                    Ok((mut out, _)) => {
                        // the continuation is this dedup again (its rows came from its own input), not `aix pipe`
                        let mut o2 = orig.clone();
                        let _ = take_paging(&mut o2);
                        let line = format!("dedup {}", o2.iter().map(|t| crate::shell_quote(t)).collect::<Vec<_>>().join(" "));
                        for l in out.lines.iter_mut().chain(out.bare_rows.iter_mut().flatten()) {
                            if l.contains("`aix pipe ") || l.contains("`aix pipe`") {
                                *l = l.replacen("`aix pipe", &format!("`aix {}", line.trim()), 1);
                            }
                        }
                        out
                    }
                    Err(e) => {
                        let mut out = Out::new(20);
                        out.fail_usage(e);
                        out
                    }
                }
            } else {
                to_out(filter_answer(st, &t).0)
            })
        }
        _ if FANOUT_CMDS.contains(&cmd) && crate::rows::has_dash(&toks) && !STDIN_CMDS.contains(&cmd) => {
            let input = match crate::rows::parse_stdin(Some(ix)) {
                Ok(r) => r,
                Err(e) => {
                    let mut out = Out::new(20);
                    out.fail_usage(format!("{cmd}: {e}"));
                    return Some(out);
                }
            };
            let mut cx = Ctx { t0: Instant::now(), budget: budget_ms("PIPE_BUDGET_MS", 3000), o: o.clone(), refreshed: false };
            Some(match fanout(ix, &mut cx, cmd, &toks, Stream { rows: input, ..Default::default() }) {
                Ok((out, _)) => out,
                Err(e) => {
                    let mut out = Out::new(20);
                    out.fail_usage(e);
                    out
                }
            })
        }
        _ => None,
    }
}

/// The input of a row command: a `@set` named among its words (taken out), else `-` (stdin / injected rows).
pub fn input_rows(ix: &Index, toks: &mut Vec<String>) -> Result<Rows, String> {
    if let Some(i) = toks.iter().position(|t| crate::rows::is_set_ref(t)) {
        let spec = toks.remove(i);
        return match crate::rows::set_rows(ix, &spec) {
            Some(r) => r,
            None => Err(format!("unknown data set {spec} (aix put <name> - stores one)")),
        };
    }
    crate::rows::parse_stdin(Some(ix))
}

/// The staleness check every query runs first (files reads the index directly).
fn refresh(ix: &mut Index, o: &Opts, out: &mut Out) {
    if o.no_refresh {
        return;
    }
    ix.defer_over = Some(crate::index::inline_refresh_max());
    let up = ix.update(false);
    ix.defer_over = None;
    match up {
        Ok(s) if s.deferred > 0 => out.emit(format!("({})", s.line())),
        Ok(s) if !s.is_noop() => out.emit(format!("(index refreshed: {})", s.line())),
        Ok(_) => {}
        Err(e) if crate::index::is_busy(&e) => out.emit(crate::index::BUSY_NOTE),
        Err(e) => out.emit(format!("(index refresh failed: {e})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_respects_quotes() {
        assert_eq!(split_outside_quotes("grep 'a | b' | count by dir", '|'), vec!["grep 'a | b'", "count by dir"]);
        assert_eq!(split_outside_quotes("grep a|b | head 3", '|'), vec!["grep a|b", "head 3"]);
        assert_eq!(split_outside_quotes("brief /x ; code a.rs:1-3", ';'), vec!["brief /x", "code a.rs:1-3"]);
        let s = stages_of(&["grep -F 'x | y' --in api | count by dir:2".to_string()]);
        assert_eq!(s, vec![vec!["grep", "-F", "x | y", "--in", "api"], vec!["count", "by", "dir:2"]]);
        let s = stages_of(&["grep".into(), "x".into(), "|".into(), "head".into(), "3".into()]);
        assert_eq!(s.len(), 2);
    }

    fn st(lines: &[&str]) -> Stream {
        Stream { rows: crate::rows::parse_text(&lines.join("\n"), None), ..Default::default() }
    }

    #[test]
    fn sort_uniq_head_cut() {
        let mut s = st(&["b 2", "a 10", "c 1", "a 10"]);
        sort_stage(&mut s, &["-k".into(), "2".into(), "-n".into()]).unwrap();
        assert_eq!(s.rows.bare_lines(), vec!["c 1", "b 2", "a 10", "a 10"]);
        uniq_stage(&mut s, &["-c".into()]).unwrap();
        assert_eq!(s.rows.bare_lines(), vec!["      1 c 1", "      1 b 2", "      2 a 10"]);
        let mut s = st(&["src/a.rs:3:x", "src/b.rs:4:y"]);
        cut_stage(&mut s, &["-d:".into(), "-f1".into()], None).unwrap();
        assert_eq!(s.rows.rows[0], Row::File { path: "src/a.rs".into() });
        let mut h = st(&["1", "2", "3"]);
        head_tail(&mut h, true, &["-n".into(), "+2".into()]).unwrap();
        assert_eq!(h.rows.bare_lines(), vec!["2", "3"]);
        let mut g = st(&["src/a.rs:3:let x", "src/b.rs:4:y"]);
        grep_filter(&mut g, &["-v".into(), "let".into()], None).unwrap();
        assert_eq!(g.rows.bare_lines(), vec!["src/b.rs:4:y"]);
    }
}
