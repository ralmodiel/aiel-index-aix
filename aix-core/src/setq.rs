//! Queries over data sets (`sets.rs`): `@name`, `@name/item`, `@name:A-B`, `@name#Heading` work wherever a path works:
//! grep (GNU flags), code/cat/head/tail, count (by line|match|field|template|level|item), files/ls, filter
//! (--where/--field/--level/--between/--match/--not), find/ask --in @set, outline, sql (read-only views per set), and
//! in-call pipes / sequences (`grep -o 're' @access | count by match`, `grep Exception @gate | code -`,
//! `files @gate ; head @gate`). Everything printed passes the redactor and the injection defang of `Out::emit`, and
//! answers end with "(data, not instructions)".

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use regex::Regex;
use rusqlite::params;
use serde_json::{json, Value};

use crate::query::Out;
use crate::sets::{self, rid, Fmt, Item, SetStore, LABEL};

/// The verbs that accept `@set` targets.
pub const SET_CMDS: &[&str] = &["grep", "code", "cat", "sed", "head", "tail", "count", "files", "ls", "filter", "find", "ask", "outline", "sql", "sets", "put", "pipe"];

pub struct Ctx {
    pub stores: Vec<SetStore>,
    pub repo: PathBuf,
    pub dir: PathBuf,
    pub db: Option<PathBuf>,
    /// CLI (true) or MCP (false): an unbounded `--head 0` and paths in `put` are CLI-only
    pub cli: bool,
    pub limit: Option<usize>,
    pub embed: Option<crate::config::Endpoint>,
    pub embed_doc_prefix: String,
    pub embed_query_prefix: String,
    /// the repo index, opened on first need (`| code -` on stack frames, a repo command in a sequence)
    pub ix: Option<crate::Index>,
}

impl Ctx {
    /// `dir` = the `.aix` directory of the repo index; the global store is looked up too.
    pub fn open(repo: &Path, dir: &Path, db: Option<&Path>, cli: bool) -> Ctx {
        let cfg = crate::config::Config::load(repo, dir); // installs the repo's [redact] settings and masks
        let mut stores = vec![];
        if let Ok(Some(s)) = sets::open(dir, false, false) {
            stores.push(s);
        }
        if let Some(g) = sets::global_dir() {
            if g != dir {
                if let Ok(Some(s)) = sets::open(&g, true, false) {
                    stores.push(s);
                }
            }
        }
        Ctx { stores, repo: repo.to_path_buf(), dir: dir.to_path_buf(), db: db.map(Path::to_path_buf), cli, limit: None, embed: cfg.embed.clone(), embed_doc_prefix: cfg.embed_doc_prefix.clone(), embed_query_prefix: cfg.embed_query_prefix.clone(), ix: None }
    }

    fn find_set(&self, name: &str) -> Option<usize> {
        self.stores.iter().position(|s| sets::exists(s, name))
    }

    /// Does `tok` name an existing set (`@name...`)?
    pub fn is_set_token(&self, tok: &str) -> bool {
        parse_target(tok).is_some_and(|t| self.find_set(&t.set).is_some())
    }

    fn index(&mut self) -> Result<&mut crate::Index> {
        if self.ix.is_none() {
            let mut ix = crate::Index::open(&self.repo, self.db.as_deref())?;
            let _ = ix.update(false); // as any query does: the frames resolve against current files
            self.ix = Some(ix);
        }
        Ok(self.ix.as_mut().unwrap())
    }
}

/// Is there any set store at all (cheap: two stat calls)? No store, no interception.
pub fn any_store(dir: &Path) -> bool {
    sets::db_path(dir).exists() || sets::global_dir().is_some_and(|g| sets::db_path(&g).exists())
}

// ---- targets -----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TargetSpec {
    pub set: String,
    pub item: Option<String>,
    pub range: Option<(i64, Option<i64>)>,
    pub heading: Option<String>,
}

/// `@name[/item][:A[-B]]` or `@name[/item]#Heading`.
pub fn parse_target(tok: &str) -> Option<TargetSpec> {
    let t = tok.strip_prefix('@')?;
    if !t.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let (t, heading) = match t.split_once('#') {
        Some((a, h)) => (a, Some(h.to_string())),
        None => (t, None),
    };
    let mut range = None;
    let mut body = t;
    if let Some((a, r)) = t.rsplit_once(':') {
        let ok = !r.is_empty() && r.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ',');
        if ok {
            body = a;
            let r = r.split(',').next().unwrap_or(r);
            range = match r.split_once('-') {
                Some((x, "")) => x.parse().ok().map(|x| (x, None)),
                Some((x, y)) => match (x.parse().ok(), y.parse().ok()) {
                    (Some(x), Some(y)) => Some((x, Some(y))),
                    _ => None,
                },
                None => r.parse().ok().map(|x| (x, Some(x))),
            };
            range?;
        }
    }
    let (set, item) = match body.split_once('/') {
        Some((s, i)) if !i.is_empty() => (s, Some(i.to_string())),
        Some((s, _)) => (s, None),
        None => (body, None),
    };
    if !sets::valid_name(set) {
        return None;
    }
    Some(TargetSpec { set: set.to_string(), item, range, heading })
}

#[derive(Debug, Clone)]
pub struct Target {
    pub store: usize,
    pub items: Vec<Item>,
    pub single: bool,
    pub range: Option<(i64, Option<i64>)>,
    pub heading: Option<String>,
}

fn resolve(ctx: &Ctx, tok: &str) -> Result<Target> {
    let spec = parse_target(tok).ok_or_else(|| anyhow!("{tok}: not a data set reference (@name, @name/item, @name:A-B)"))?;
    let Some(si) = ctx.find_set(&spec.set) else {
        let known: Vec<String> = ctx.stores.iter().flat_map(|s| sets::list_sets(s).unwrap_or_default()).map(|s| format!("@{}", s.name)).take(12).collect();
        bail!("no data set @{} (known: {}; aix put {} - stores one)", spec.set, if known.is_empty() { "none".into() } else { known.join(" ") }, spec.set);
    };
    let st = &ctx.stores[si];
    let all = sets::items_of(st, &spec.set)?;
    let single = all.len() == 1;
    let items: Vec<Item> = match &spec.item {
        None => all.clone(),
        Some(p) => all.iter().filter(|i| if p.contains(['*', '?', '[']) { sets::glob1(p, &i.item) } else { i.item == *p }).cloned().collect(),
    };
    if items.is_empty() {
        bail!("@{} has no item {:?} (items: {})", spec.set, spec.item.unwrap_or_default(), all.iter().map(|i| i.item.as_str()).take(20).collect::<Vec<_>>().join(", "));
    }
    sets::touch_used(st, &spec.set);
    // `@set:120-180` on a set with several items: the first item
    let items = if spec.range.is_some() && spec.item.is_none() && items.len() > 1 { vec![items[0].clone()] } else { items };
    Ok(Target { store: si, items, single, range: spec.range, heading: spec.heading })
}

// ---- line access -------------------------------------------------------------------------------------------------------------

/// Visit lines `from..=to` of an item in order; `f` returns false to stop.
fn scan(st: &SetStore, item: i64, from: i64, to: i64, f: &mut dyn FnMut(i64, &str) -> bool) -> Result<()> {
    let mut q = st.conn.prepare_cached("SELECT id, t FROM lines WHERE id>=?1 AND id<=?2 ORDER BY id")?;
    let mut rows = q.query(params![rid(item, from.max(1)), rid(item, to.clamp(0, u32::MAX as i64))])?;
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let t = r.get_ref(1)?.as_str().unwrap_or("");
        if !f(id & 0xffff_ffff, t) {
            break;
        }
    }
    Ok(())
}

fn line_range(t: &Target, it: &Item, st: &SetStore) -> Result<(i64, i64)> {
    if let Some(h) = &t.heading {
        let hs: Vec<(i64, i64, String)> = st
            .conn
            .prepare_cached("SELECT id, lvl, title FROM heads WHERE id>=?1 AND id<?2 ORDER BY id")?
            .query_map(params![rid(it.id, 0), rid(it.id + 1, 0)], |r| Ok((r.get::<_, i64>(0)? & 0xffff_ffff, r.get(1)?, r.get(2)?)))?
            .flatten()
            .collect();
        let hl = h.to_lowercase();
        let k = hs.iter().position(|x| x.2.to_lowercase() == hl).or_else(|| hs.iter().position(|x| x.2.to_lowercase().contains(&hl))).ok_or_else(|| anyhow!("no heading {h:?} in {} (outline {} lists them)", it.cite(t.single), it.cite(t.single)))?;
        let end = hs[k + 1..].iter().find(|x| x.1 <= hs[k].1).map(|x| x.0 - 1).unwrap_or(it.lines);
        return Ok((hs[k].0, end));
    }
    match t.range {
        Some((a, b)) => Ok((a.max(1), b.unwrap_or(it.lines).min(it.lines))),
        None => Ok((1, it.lines)),
    }
}

// ---- results and rendering -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SRow {
    pub cite: String,
    pub n: i64,
    /// ':' a hit, '-' a context line, '=' a "--" group separator, ' ' a plain numbered line (code/head/tail)
    pub sep: char,
    pub text: String,
    pub src: Option<(usize, i64)>,
    /// the matched text (`grep -o`, `--re`): what `count by match` counts
    pub m: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Body {
    Rows(Vec<SRow>),
    /// (count, key, extra)
    Groups(Vec<(i64, String, String)>),
    Lines(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Res {
    pub title: String,
    pub body: Body,
    pub notes: Vec<String>,
    /// rows before the output cap was applied (for the footer)
    pub cut_style: CapKind,
    pub exit: i32,
    /// the default row cap of this command
    pub default_cap: usize,
    /// rows in all when the scan kept only the first `cap` (the footer counts the rest)
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapKind {
    Rows,
    Lines,
    Groups,
}

impl Res {
    fn rows(title: String, rows: Vec<SRow>, cap: usize) -> Res {
        let exit = if rows.iter().any(is_row) { 0 } else { 1 };
        Res { title, body: Body::Rows(rows), notes: vec![], cut_style: CapKind::Rows, exit, default_cap: cap, total: None }
    }
    fn lines(title: String, lines: Vec<String>) -> Res {
        let exit = if lines.is_empty() { 1 } else { 0 };
        Res { title, body: Body::Lines(lines), notes: vec![], cut_style: CapKind::Lines, exit, default_cap: usize::MAX, total: None }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutOpts {
    pub bare: bool,
    pub head: Option<usize>,
    pub offset: usize,
    pub width: Option<usize>,
}

/// Pull the shared output options out of an argument list.
fn take_out_opts(args: &mut Vec<String>) -> Result<OutOpts> {
    let mut o = OutOpts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        if a == "--" {
            break;
        }
        let (k, v) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let want = |args: &mut Vec<String>, i: usize, v: Option<String>| -> Result<usize> {
            let s = match v {
                Some(s) => s,
                None => {
                    if i + 1 >= args.len() {
                        bail!("{k} needs a number");
                    }
                    args.remove(i + 1)
                }
            };
            s.parse::<usize>().map_err(|_| anyhow!("{k} needs a number, got {s:?}"))
        };
        match k.as_str() {
            "--bare" => {
                o.bare = true;
                args.remove(i);
            }
            "--head" => {
                o.head = Some(want(args, i, v)?);
                args.remove(i);
            }
            "--offset" => {
                o.offset = want(args, i, v)?;
                args.remove(i);
            }
            "--width" => {
                o.width = Some(want(args, i, v)?);
                args.remove(i);
            }
            _ => i += 1,
        }
    }
    Ok(o)
}

fn clip(s: &str, w: usize) -> String {
    if w == 0 || s.len() <= w || s.chars().count() <= w {
        return s.to_string();
    }
    let mut o: String = s.chars().take(w.saturating_sub(1)).collect();
    o.push('…');
    o
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "@/:._-,+=#".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command that shows the next page.
fn next_cmd(argv: &[String], next_off: usize) -> String {
    let mut v: Vec<String> = vec![];
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == "--offset" {
            i += 2;
            continue;
        }
        if argv[i].starts_with("--offset=") {
            i += 1;
            continue;
        }
        v.push(shell_quote(&argv[i]));
        i += 1;
    }
    format!("aix {} --offset {next_off}", v.join(" "))
}

thread_local! {
    static PIPE_FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A pipe stage reads this set answer (`grep . @big | count`): its rows are not cut at the 64 KB output ceiling (the
/// pipe caps the stream at its own row ceiling and says so). Returns the previous value.
pub fn set_pipe_full(on: bool) -> bool {
    PIPE_FULL.with(|c| c.replace(on))
}

fn pipe_full() -> bool {
    PIPE_FULL.with(|c| c.get())
}

/// Render a result into `Out` (each line redacted and defanged by `emit`).
pub fn render(res: Res, oo: &OutOpts, argv: &[String], cli: bool, json_hits: bool) -> Out {
    let mut out = Out::new(crate::FULL_ROWS);
    let cap = match oo.head {
        Some(0) if cli => usize::MAX,
        Some(0) => crate::FULL_ROWS,
        Some(n) => n,
        None => res.default_cap,
    };
    let width = oo.width.unwrap_or(if oo.bare { 0 } else { 200 });
    let width = if width == 0 { 0 } else { width.max(8) };
    let more;
    if !oo.bare && !res.title.is_empty() {
        out.emit(format!("== {}", res.title));
    }
    match res.body {
        Body::Rows(rows) => {
            let real: usize = rows.iter().filter(|r| is_row(r) && r.sep != '~').count();
            let mut shown = 0usize;
            let mut skipped = 0usize;
            let mut last_sep = true;
            for r in rows {
                if r.sep == '~' {
                    if !oo.bare && shown > 0 && !last_sep && shown < cap {
                        out.emit("  --");
                        last_sep = true;
                    }
                    continue;
                }
                if r.sep == '=' {
                    if shown > 0 && !last_sep && shown < cap {
                        out.emit(if oo.bare { "--".to_string() } else { "  --".to_string() });
                        last_sep = true;
                    }
                    continue;
                }
                if skipped < oo.offset {
                    skipped += 1;
                    continue;
                }
                if shown >= cap {
                    continue;
                }
                shown += 1;
                last_sep = false;
                let text = clip(&r.text, width);
                let line = if r.sep == ' ' {
                    if oo.bare {
                        format!("{}:{}:{}", r.cite, r.n, text)
                    } else {
                        format!("{} {}", r.n, text)
                    }
                } else if r.n == 0 && r.sep == ':' && r.text.is_empty() {
                    r.cite.clone() // -l
                } else if r.n < 0 {
                    format!("{}:{}", r.cite, r.text) // -c
                } else if r.cite.is_empty() {
                    // grep -h: no name; bare rows are the text alone (GNU), so a later stage or a put sees the text
                    if oo.bare {
                        text.to_string()
                    } else {
                        format!("  {}{} {}", r.n, r.sep, text)
                    }
                } else if oo.bare {
                    format!("{}{}{}{}{}", r.cite, r.sep, r.n, r.sep, text)
                } else {
                    format!("  {}{}{}{} {}", r.cite, r.sep, r.n, r.sep, text)
                };
                if json_hits && r.sep != '-' {
                    out.hit("set", &r.cite, r.n.max(0), &text);
                }
                out.emit(line);
            }
            let real = res.total.map_or(real, |t| t.max(real));
            more = real.saturating_sub(oo.offset + shown);
            if more > 0 {
                out.truncated = true;
                out.emit(format!("({more} more {}: {})", if res.cut_style == CapKind::Lines { "lines" } else { "rows" }, next_cmd(argv, oo.offset + shown)));
            }
        }
        Body::Groups(gs) => {
            let total = gs.len();
            for (i, (n, k, extra)) in gs.iter().enumerate().skip(oo.offset) {
                if i - oo.offset >= cap {
                    break;
                }
                let k = clip(k, width);
                if json_hits {
                    out.hits.push(json!({"kind": "group", "key": crate::query::oneline(&aix_extract::redact::redact_line(&k)), "n": n}));
                }
                out.emit(if oo.bare { format!("{n}\t{k}") } else { format!("  {n:>8}  {k}{extra}") });
            }
            more = total.saturating_sub(oo.offset + cap.min(total));
            if more > 0 {
                out.truncated = true;
                out.emit(format!("({more} more groups: {})", next_cmd(argv, oo.offset + cap)));
            }
        }
        Body::Lines(ls) => {
            let total = ls.len();
            for l in ls.iter().skip(oo.offset).take(cap) {
                out.emit(clip(l, if width == 0 { 0 } else { width.max(200) }));
            }
            more = total.saturating_sub(oo.offset + cap.min(total));
            if more > 0 {
                out.truncated = true;
                out.emit(format!("({more} more lines: {})", next_cmd(argv, oo.offset + cap)));
            }
        }
    }
    if !oo.bare {
        for n in &res.notes {
            out.emit(format!("note: {n}"));
        }
        out.label = Some(LABEL);
    } else {
        // --bare: a cut answer still ends with one `…` line naming the exact continuation
        for n in res.notes.iter().filter_map(|n| n.strip_prefix("next: ")) {
            out.emit(format!("\u{2026} {n}"));
        }
    }
    if res.exit != 0 {
        out.exit_code = Some(res.exit);
    }
    if !(cli && oo.head == Some(0)) && !pipe_full() {
        out.cap(crate::FULL_ROWS, crate::MAX_BYTES);
        // the generic cut note names --page, which set commands do not take: name what continues a set answer
        let shown = out.lines.iter().filter(|l| !l.starts_with('\u{2026}') && !l.starts_with('(') && !l.starts_with("==") && !l.starts_with("note:")).count();
        if let Some(l) = out.lines.last_mut().filter(|l| l.starts_with("\u{2026} output truncated")) {
            *l = format!("\u{2026} output truncated at {} KB: narrow it (a stricter pattern, @set/item, :A-B), or continue with {} (a pipe stage reads every row: aix '... @set | count')", crate::MAX_BYTES / 1024, next_cmd(argv, oo.offset + shown));
        }
    }
    out
}

// ---- matching ----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct GrepOpts {
    pats: Vec<String>,
    i: bool,
    w: bool,
    x: bool,
    fixed: bool,
    v: bool,
    o: bool,
    c: bool,
    l: bool,
    big_l: bool,
    h: bool,
    a: usize,
    b: usize,
    m: Option<usize>,
    targets: Vec<String>,
    stdin_rows: bool,
    /// `--field F`: match within that named field of each record
    field: Option<String>,
    /// `-f @set` / `-f FILE`: one pattern per line of it
    pat_files: Vec<String>,
}

struct Matcher {
    re: Regex,
    w: bool,
    v: bool,
}

impl Matcher {
    fn new(pats: &[String], i: bool, w: bool, x: bool, fixed: bool, v: bool) -> Result<Matcher> {
        let parts: Vec<String> = pats.iter().map(|p| if fixed { regex::escape(p) } else { p.clone() }).collect();
        let mut body = if parts.len() == 1 { parts[0].clone() } else { parts.iter().map(|p| format!("(?:{p})")).collect::<Vec<_>>().join("|") };
        if x {
            body = format!("^(?:{body})$");
        }
        let re = regex::RegexBuilder::new(&body).case_insensitive(i).size_limit(1 << 24).build().map_err(|e| anyhow!("bad regex {:?}: {}", pats.join(" | "), e.to_string().lines().last().unwrap_or("")))?;
        Ok(Matcher { re, w: w && !x, v })
    }
    fn word_ok(l: &str, s: usize, e: usize) -> bool {
        let wc = |c: char| c.is_alphanumeric() || c == '_';
        let before = l[..s].chars().next_back().is_none_or(|c| !wc(c));
        let after = l[e..].chars().next().is_none_or(|c| !wc(c));
        before && after
    }
    /// Matches in the line (GNU -w: retried after a failed boundary check).
    fn find_all(&self, l: &str) -> Vec<(usize, usize)> {
        let mut v = vec![];
        let mut at = 0;
        while at <= l.len() {
            let Some(m) = self.re.find_at(l, at) else { break };
            let (s, e) = (m.start(), m.end());
            if !self.w || Self::word_ok(l, s, e) {
                if e > s || !self.w {
                    v.push((s, e));
                }
                at = if e > s { e } else { next_char(l, e) };
            } else {
                // a shorter match at the same start that ends on a boundary (GNU tries those too)
                let mut found = false;
                let mut ends: Vec<usize> = (s + 1..e).filter(|k| l.is_char_boundary(*k)).collect();
                ends.reverse();
                for k in ends {
                    if Self::word_ok(l, s, k) && self.re.find_at(&l[..k], s).is_some_and(|m2| m2.start() == s && m2.end() == k) {
                        v.push((s, k));
                        at = k;
                        found = true;
                        break;
                    }
                }
                if !found {
                    at = next_char(l, s);
                }
            }
            if at > l.len() {
                break;
            }
        }
        v
    }
    fn hit(&self, l: &str) -> bool {
        let m = if self.w { !self.find_all(l).is_empty() } else { self.re.is_match(l) };
        m != self.v
    }
}

fn next_char(l: &str, i: usize) -> usize {
    let mut k = i + 1;
    while k < l.len() && !l.is_char_boundary(k) {
        k += 1;
    }
    k
}

fn num_arg(flag: &str, v: Option<&String>) -> Result<usize> {
    v.and_then(|s| s.parse::<usize>().ok()).ok_or_else(|| anyhow!("{flag} needs a number"))
}

fn parse_grep(args: &[String]) -> Result<GrepOpts> {
    let mut g = GrepOpts::default();
    let mut pos: Vec<String> = vec![];
    let mut i = 0;
    let mut dashdash = false;
    while i < args.len() {
        let a = &args[i];
        if dashdash || a == "-" || !a.starts_with('-') || a.len() == 1 {
            if a == "-" {
                g.stdin_rows = true;
            } else {
                pos.push(a.clone());
            }
            i += 1;
            continue;
        }
        if a == "--" {
            dashdash = true;
            i += 1;
            continue;
        }
        let (name, val) = match a.split_once('=') {
            Some((k, v)) if a.starts_with("--") => (k.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let take = |i: &mut usize| -> Result<String> {
            if let Some(v) = &val {
                return Ok(v.clone());
            }
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| anyhow!("{name} needs a value"))
        };
        match name.as_str() {
            "-e" | "--regexp" => g.pats.push(take(&mut i)?),
            "-f" | "--file" => g.pat_files.push(take(&mut i)?),
            "-i" | "--ignore-case" => g.i = true,
            "-w" | "--word-regexp" => g.w = true,
            "-x" | "--line-regexp" => g.x = true,
            "-F" | "--fixed-strings" => g.fixed = true,
            "-v" | "--invert-match" => g.v = true,
            "-o" | "--only-matching" => g.o = true,
            "-c" | "--count" => g.c = true,
            "-l" | "--files-with-matches" => g.l = true,
            "-L" | "--files-without-match" => g.big_l = true,
            "-h" | "--no-filename" => g.h = true,
            "-n" | "-H" | "-E" | "-r" | "-R" | "-s" | "--line-number" | "--with-filename" | "--extended-regexp" | "--recursive" | "-P" | "--perl-regexp" => {}
            "-A" | "--after-context" => g.a = num_arg(&name, Some(&take(&mut i)?))?,
            "-B" | "--before-context" => g.b = num_arg(&name, Some(&take(&mut i)?))?,
            "-C" | "--context" => {
                let n = num_arg(&name, Some(&take(&mut i)?))?;
                g.a = n;
                g.b = n;
            }
            "-m" | "--max-count" => g.m = Some(num_arg(&name, Some(&take(&mut i)?))?),
            "--in" => g.targets.push(take(&mut i)?),
            "--field" => g.field = Some(sets::norm_field(&take(&mut i)?)),
            s if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 && s[1..].chars().all(|c| "iwxFvoclLhnHErRsP".contains(c)) => {
                // bundled short flags: -in, -ic, -oE
                for c in s[1..].chars() {
                    match c {
                        'i' => g.i = true,
                        'w' => g.w = true,
                        'x' => g.x = true,
                        'F' => g.fixed = true,
                        'v' => g.v = true,
                        'o' => g.o = true,
                        'c' => g.c = true,
                        'l' => g.l = true,
                        'L' => g.big_l = true,
                        'h' => g.h = true,
                        _ => {}
                    }
                }
            }
            s if s.len() > 2 && (s.starts_with("-A") || s.starts_with("-B") || s.starts_with("-C") || s.starts_with("-m")) && s[2..].chars().all(|c| c.is_ascii_digit()) => {
                let n: usize = s[2..].parse().unwrap_or(0);
                match &s[..2] {
                    "-A" => g.a = n,
                    "-B" => g.b = n,
                    "-C" => {
                        g.a = n;
                        g.b = n
                    }
                    _ => g.m = Some(n),
                }
            }
            other => bail!("grep on a data set: flag {other} is not supported (supported: -e -f -i -w -x -F -v -o -c -l -L -h -A -B -C -m; count matches: `aix 'grep -o RE @set | count by match'` or `--count-by match`; GNU grep on the raw text: `aix code @set --full --bare --width 0 | cut -d: -f3- | grep ...`)"),
        }
        i += 1;
    }
    if g.pats.is_empty() && g.pat_files.is_empty() {
        if pos.is_empty() {
            bail!("usage: aix grep <regex> [flags] @set[/item] ...");
        }
        g.pats.push(pos.remove(0));
    }
    g.targets.extend(pos);
    if g.o && (g.a > 0 || g.b > 0) {
        bail!("grep -o with context (-A/-B/-C) is not supported on data sets: drop one of them");
    }
    Ok(g)
}

fn cite_of(t: &Target, it: &Item) -> String {
    it.cite(t.single)
}

fn grep_targets(ctx: &Ctx, g: &GrepOpts, cap: usize) -> Result<(Vec<SRow>, usize, usize, usize)> {
    // rows that would be printed (hits, -o matches, context lines), stored or not: the footer counts the cut
    let emitted = std::cell::Cell::new(0usize);
    // `-f @set`: the patterns are the lines of a set (or of a repo file); an empty list matches nothing (as GNU)
    let mut pats = g.pats.clone();
    for src in &g.pat_files {
        let lines: Vec<String> = if src.starts_with('@') {
            let t = resolve(ctx, src)?;
            let st = &ctx.stores[t.store];
            let mut v = vec![];
            for it in &t.items {
                let (from, to) = line_range(&t, it, st)?;
                scan(st, it.id, from, to, &mut |_, l| {
                    v.push(l.to_string());
                    true
                })?;
            }
            v
        } else {
            bail!("grep -f on a data set takes the patterns from another set (-f @name); store the file first: aix put NAME {src}");
        };
        pats.extend(lines.into_iter().filter(|l| !l.is_empty()));
    }
    let none = pats.is_empty();
    if none {
        pats.push("\u{0}aix: no pattern\u{0}".to_string());
    }
    let mt = Matcher::new(&pats, g.i, g.w, g.x, g.fixed || none, g.v)?;
    if let Some(fname) = &g.field {
        // within one field of each record: the row shows the record's first line (its citation stays valid)
        if g.a > 0 || g.b > 0 || g.o {
            bail!("grep --field: -o and context are not supported (use filter --field {fname} --match RE)");
        }
        let (mut rows, mut n, mut scanned) = (vec![], 0usize, 0usize);
        for tok in &g.targets {
            let t = resolve(ctx, tok)?;
            let st = &ctx.stores[t.store];
            for it in &t.items {
                let cite = cite_of(&t, it);
                let (a, b) = line_range(&t, it, st)?;
                let mut count = 0usize;
                records(st, it, a, b, &mut |ln, raw, kv| {
                    scanned += 1;
                    let vals = field_values(kv, fname);
                    let hit = if g.v { !vals.iter().any(|v| mt.re.is_match(v)) } else { vals.iter().any(|v| mt.hit(v)) };
                    if hit {
                        count += 1;
                        if !(g.c || g.l) && rows.len() < cap {
                            let first = raw.split('\n').next().unwrap_or("");
                            let text = first.to_string();
                            rows.push(SRow { cite: cite.clone(), n: ln, sep: ':', text, src: Some((t.store, it.id)), m: None });
                        }
                    }
                    !g.m.is_some_and(|m| count >= m)
                })?;
                n += count;
                if g.c {
                    rows.push(SRow { cite: cite.clone(), n: -1, sep: ':', text: count.to_string(), src: Some((t.store, it.id)), m: None });
                } else if g.l && count > 0 {
                    rows.push(SRow { cite: cite.clone(), n: 0, sep: ':', text: String::new(), src: Some((t.store, it.id)), m: None });
                }
            }
        }
        return Ok((rows, n, scanned, n));
    }
    let mut rows: Vec<SRow> = vec![];
    let (mut nmatch, mut scanned) = (0usize, 0usize);
    let ctxmode = g.a > 0 || g.b > 0;
    let mut any_printed = false;
    for tok in &g.targets {
        let t = resolve(ctx, tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let cite = if g.h { String::new() } else { cite_of(&t, it) };
            let (from, to) = line_range(&t, it, st)?;
            let mut count = 0usize;
            let mut before: std::collections::VecDeque<(i64, String)> = Default::default();
            let mut after_left = 0usize;
            let mut last_printed: i64 = -1;
            let mut stop_after = false;
            let push = |rows: &mut Vec<SRow>, n: i64, sep: char, text: &str, m: Option<String>, last_printed: &mut i64, any: &mut bool| {
                if ctxmode && *any && *last_printed >= 0 && n > *last_printed + 1 || ctxmode && *any && *last_printed < 0 {
                    rows.push(SRow { cite: String::new(), n: 0, sep: '=', text: String::new(), src: None, m: None });
                }
                emitted.set(emitted.get() + 1);
                if emitted.get() <= cap {
                    rows.push(SRow { cite: cite.clone(), n, sep, text: text.to_string(), src: Some((t.store, it.id)), m });
                }
                *last_printed = n;
                *any = true;
            };
            scan(st, it.id, from, to, &mut |n, l| {
                scanned += 1;
                if stop_after {
                    if after_left > 0 && !mt.hit(l) {
                        push(&mut rows, n, '-', l, None, &mut last_printed, &mut any_printed);
                        after_left -= 1;
                        return after_left > 0;
                    }
                    return false;
                }
                if mt.hit(l) {
                    count += 1;
                    if !(g.c || g.l || g.big_l) {
                        for (bn, bl) in before.drain(..) {
                            if bn > last_printed {
                                push(&mut rows, bn, '-', &bl, None, &mut last_printed, &mut any_printed);
                            }
                        }
                        if g.o {
                            if !g.v {
                                for (s, e) in mt.find_all(l) {
                                    if e > s {
                                        push(&mut rows, n, ':', &l[s..e], Some(l[s..e].to_string()), &mut last_printed, &mut any_printed);
                                    }
                                }
                            }
                        } else {
                            push(&mut rows, n, ':', l, None, &mut last_printed, &mut any_printed);
                        }
                        after_left = g.a;
                    }
                    if g.m.is_some_and(|m| count >= m) {
                        if g.c || g.l || g.big_l || after_left == 0 {
                            return false;
                        }
                        stop_after = true;
                    }
                    if g.l && !g.c {
                        return false;
                    }
                } else if !(g.c || g.l || g.big_l) {
                    if after_left > 0 {
                        push(&mut rows, n, '-', l, None, &mut last_printed, &mut any_printed);
                        after_left -= 1;
                    } else if g.b > 0 {
                        before.push_back((n, l.to_string()));
                        if before.len() > g.b {
                            before.pop_front();
                        }
                    }
                }
                true
            })?;
            nmatch += count;
            let c2 = cite_of(&t, it);
            if g.c {
                rows.push(SRow { cite: c2, n: -1, sep: ':', text: count.to_string(), src: Some((t.store, it.id)), m: None });
            } else if g.l && count > 0 || g.big_l && count == 0 {
                rows.push(SRow { cite: c2, n: 0, sep: ':', text: String::new(), src: Some((t.store, it.id)), m: None });
            }
        }
    }
    Ok((rows, nmatch, scanned, emitted.get()))
}

// ---- records (JSON / CSV fields) ---------------------------------------------------------------------------------------------

/// Visit the records of an item: (first line, [(field path, value)]). JSONL and JSON-looking lines of any item, CSV/TSV
/// rows (quoted fields may span lines), JSON document elements.
fn records(st: &SetStore, it: &Item, from: i64, to: i64, f: &mut dyn FnMut(i64, &str, &[(String, String)]) -> bool) -> Result<()> {
    let fmt = Fmt::from_name(&it.fmt);
    let from_recs = fmt == Fmt::Json || !it.shape.is_empty();
    match fmt {
        _ if from_recs => {
            // named-field rows show their stored first line; JSON document elements their JSON
            let sql = if it.shape.is_empty() { "SELECT r.id, r.j, r.j FROM recs r WHERE r.id>=?1 AND r.id<=?2 ORDER BY r.id" } else { "SELECT r.id, r.j, COALESCE(l.t, r.j) FROM recs r LEFT JOIN lines l ON l.id=r.id WHERE r.id>=?1 AND r.id<=?2 ORDER BY r.id" };
            let mut q = st.conn.prepare_cached(sql)?;
            let mut rows = q.query(params![rid(it.id, from), rid(it.id, to)])?;
            while let Some(r) = rows.next()? {
                let id: i64 = r.get(0)?;
                let j: String = r.get(1)?;
                let raw: String = r.get(2)?;
                if let Ok(v) = serde_json::from_str::<Value>(&j) {
                    let mut kv = vec![];
                    sets::flatten(&v, "", &mut kv);
                    if !f(id & 0xffff_ffff, &raw, &kv) {
                        break;
                    }
                }
            }
            Ok(())
        }
        Fmt::Csv | Fmt::Tsv => {
            let _ = from_recs;
            let sep = if fmt == Fmt::Csv { ',' } else { '\t' };
            let mut pend: Option<(i64, String)> = None;
            let mut header_seen = false;
            scan(st, it.id, 1, to, &mut |n, l| {
                if !header_seen {
                    if l.trim().is_empty() {
                        return true;
                    }
                    header_seen = true;
                    return true;
                }
                let (start, text) = match pend.take() {
                    Some((s, mut p)) => {
                        p.push('\n');
                        p.push_str(l);
                        (s, p)
                    }
                    None => (n, l.to_string()),
                };
                let parts = if sep == '\t' { Some(text.split('\t').map(str::to_string).collect()) } else { sets::csv_split(&text, ',') };
                match parts {
                    None => {
                        pend = Some((start, text));
                        true
                    }
                    Some(p) => {
                        if start < from || text.trim().is_empty() {
                            return true;
                        }
                        let kv: Vec<(String, String)> = it.header.iter().cloned().zip(p).collect();
                        f(start, &text, &kv)
                    }
                }
            })
        }
        _ => scan(st, it.id, from, to, &mut |n, l| {
            let t = l.trim();
            if t.starts_with('{') && t.ends_with('}') || t.starts_with('[') && t.ends_with(']') {
                if let Ok(v) = serde_json::from_str::<Value>(t) {
                    let mut kv = vec![];
                    sets::flatten(&v, "", &mut kv);
                    return f(n, l, &kv);
                }
            }
            true
        }),
    }
}

#[derive(Debug, Clone)]
pub struct Cond {
    field: String,
    op: String,
    val: String,
    re: Option<Regex>,
    tval: Option<f64>,
}

pub fn parse_where(s: &str) -> Result<Cond> {
    static W: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^\s*([^=!<>~\s]+)\s*(>=|<=|!=|==|=|<|>|!~|~)\s*(.*?)\s*$").unwrap());
    let c = W.captures(s).ok_or_else(|| anyhow!("--where {s:?}: use FIELD OP VALUE with OP one of = != < > <= >= ~ (regex) !~"))?;
    let mut val = c[3].to_string();
    if val.len() >= 2 && (val.starts_with('"') && val.ends_with('"') || val.starts_with('\'') && val.ends_with('\'')) {
        val = val[1..val.len() - 1].to_string();
    }
    let op = if &c[2] == "==" { "=".to_string() } else { c[2].to_string() };
    let re = if op.contains('~') { Some(Regex::new(&val).map_err(|e| anyhow!("--where {s:?}: bad regex: {e}"))?) } else { None };
    let tval = crate::setpat::parse_time(&val);
    // `ms>>5`, `a=>3`: a doubled operator is a typo, not a value
    if val.starts_with(['<', '>', '=', '!', '~']) {
        bail!("--where {s:?}: the value starts with an operator ({val:?}); write FIELD OP VALUE with one of = != < > <= >= ~ !~");
    }
    Ok(Cond { field: sets::norm_field(&c[1]), op, val, re, tval })
}

fn num(s: &str) -> Option<f64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<f64>().ok().filter(|x| x.is_finite())
}

impl Cond {
    fn test1(&self, v: &str) -> bool {
        if let Some(re) = &self.re {
            return re.is_match(v) == (self.op == "~");
        }
        let ord = match (num(v), num(&self.val)) {
            (Some(a), Some(b)) => a.partial_cmp(&b),
            // a number to compare with and a value that is not one: only = and != (as text) can hold
            (None, Some(_)) if self.op != "=" && self.op != "!=" => return false,
            // two timestamps compare as times (`ts>=2026-10-24T10:00` against `2026-10-24 10:00:01.123`)
            _ => match (crate::setpat::parse_time(v), self.tval) {
                (Some(a), Some(b)) => a.partial_cmp(&b),
                _ => Some(v.cmp(self.val.as_str())),
            },
        };
        let Some(o) = ord else { return false };
        use std::cmp::Ordering::*;
        match self.op.as_str() {
            "=" => o == Equal,
            "!=" => o != Equal,
            "<" => o == Less,
            ">" => o == Greater,
            "<=" => o != Greater,
            ">=" => o != Less,
            _ => false,
        }
    }
    /// any value of the field satisfies it (a record without the field never matches)
    fn test(&self, kv: &[(String, String)]) -> bool {
        kv.iter().any(|(k, v)| sets::norm_field(k) == self.field && self.test1(v))
    }
}

fn field_values<'a>(kv: &'a [(String, String)], f: &str) -> Vec<&'a str> {
    kv.iter().filter(|(k, _)| sets::norm_field(k) == f).map(|(_, v)| v.as_str()).collect()
}

// ---- levels and templates ----------------------------------------------------------------------------------------------------

struct LevelTrack {
    cur: Option<u8>,
}

impl LevelTrack {
    /// (level of this line, is an entry start)
    fn feed(&mut self, l: &str) -> (Option<u8>, bool) {
        use aix_extract::logparse::{is_entry_start, parse_entry, Format};
        if is_entry_start(l, Format::Auto) {
            self.cur = parse_entry(l, &[], Format::Auto).level;
            (self.cur, true)
        } else {
            (self.cur, false)
        }
    }
}

fn parse_level(s: &str) -> Result<u8> {
    aix_extract::logparse::level_from(s).ok_or_else(|| anyhow!("--level {s:?}: trace|debug|info|warn|error|fatal"))
}

fn template_of(l: &str) -> String {
    use aix_extract::logparse::{parse_entry, template, Format};
    let p = parse_entry(l, &[], Format::Auto);
    let msg = if p.message.trim().is_empty() { l } else { p.message.as_str() };
    let lv = p.level.map(|x| format!("{} ", aix_extract::logparse::level_name(x))).unwrap_or_default();
    format!("{lv}{}", template(msg))
}

// ---- commands -------------------------------------------------------------------------------------------------------------------

fn split_targets(ctx: &Ctx, args: &[String]) -> (Vec<String>, Vec<String>, bool) {
    let mut t = vec![];
    let mut rest = vec![];
    let mut dash = false;
    for a in args {
        if a == "-" {
            dash = true;
        } else if a.starts_with('@') && ctx.is_set_token(a) {
            t.push(a.clone());
        } else {
            rest.push(a.clone());
        }
    }
    (t, rest, dash)
}

fn code_cmd(ctx: &Ctx, cmd: &str, args: &[String], input: Option<&[SRow]>) -> Result<Res> {
    let (targets, rest, _) = split_targets(ctx, args);
    let mut n: Option<i64> = None;
    let mut from_start: Option<i64> = None;
    let mut full = false;
    let mut maxl: Option<usize> = None;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "-n" | "--lines" => {
                let v = rest.get(i + 1).ok_or_else(|| anyhow!("{a} needs a number"))?;
                if let Some(k) = v.strip_prefix('+') {
                    from_start = Some(k.parse().map_err(|_| anyhow!("{a} {v}: not a number"))?);
                } else {
                    n = Some(v.parse().map_err(|_| anyhow!("{a} {v}: not a number"))?);
                }
                i += 1;
            }
            "--full" => full = true,
            "--max" => {
                maxl = Some(num_arg("--max", rest.get(i + 1))?);
                i += 1;
            }
            s if s.starts_with('-') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_digit()) => n = Some(s[1..].parse().unwrap_or(10)),
            s if s.starts_with("-n") && s[2..].chars().all(|c| c.is_ascii_digit()) && s.len() > 2 => n = Some(s[2..].parse().unwrap_or(10)),
            s if s.starts_with("--lines=") => n = Some(s[8..].parse().map_err(|_| anyhow!("{s}: not a number"))?),
            other => bail!("{cmd} on a data set: argument {other} is not supported ({cmd} [-n N] @set[/item][:A-B])"),
        }
        i += 1;
    }
    if let Some(rows) = input {
        // over piped rows: head/tail slice them, code shows each cited line in context
        let real: Vec<SRow> = rows.iter().filter(|r| is_row(r)).cloned().collect();
        let k = n.unwrap_or(10).max(0) as usize;
        return Ok(match cmd {
            "head" => Res::rows(format!("head -n {k} of {} rows", real.len()), real.into_iter().take(k).collect(), usize::MAX),
            "tail" => {
                let s = real.len().saturating_sub(k);
                Res::rows(format!("tail -n {k} of {} rows", real.len()), real.into_iter().skip(s).collect(), usize::MAX)
            }
            _ => bail!("internal: code over rows"),
        });
    }
    if targets.is_empty() {
        bail!("usage: aix {cmd} @set[/item][:A-B]");
    }
    let mut rows = vec![];
    let mut titles = vec![];
    let mut notes = vec![];
    let cap_code = if full { usize::MAX } else { maxl.unwrap_or(60) };
    for tok in &targets {
        let t = resolve(ctx, tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let (a0, b0) = line_range(&t, it, st)?;
            let (a, b) = (a0, b0);
            let cite = cite_of(&t, it);
            let (a, b) = match cmd {
                "head" => {
                    let k = n.unwrap_or(10);
                    if k < 0 {
                        (a, (b + k).max(a - 1))
                    } else {
                        (a, (a + k - 1).min(b))
                    }
                }
                "tail" => match from_start {
                    Some(s) => ((a + s - 1).max(a), b),
                    None => ((b - n.unwrap_or(10) + 1).max(a), b),
                },
                _ => (a, b),
            };
            if b < a {
                titles.push(format!("{cite}: no lines"));
                continue;
            }
            let mut k = 0usize;
            let lim = if cmd == "code" || cmd == "cat" { cap_code } else { usize::MAX };
            let mut last = a - 1;
            scan(st, it.id, a, b, &mut |ln, l| {
                if k >= lim {
                    return false;
                }
                k += 1;
                last = ln;
                rows.push(SRow { cite: cite.clone(), n: ln, sep: ' ', text: l.to_string(), src: Some((t.store, it.id)), m: None });
                true
            })?;
            titles.push(format!("lines {cite}:{a}-{last} ({} of {} lines{})", k, it.lines, if it.fmt != "text" { format!(", {}", it.fmt) } else { String::new() }));
            if last < b {
                let step = cap_code.max(1) as i64;
                notes.push(format!("next: aix code {cite}:{}-{} (lines {}-{} remain; --full shows them all)", last + 1, (last + step).min(b), last + 1, b));
            } else if cmd == "head" && last < b0 {
                // `head -n N` cut the item: the same continuation as `code` ("more:", not "next:", so --bare stays byte-identical to GNU head)
                let step = cap_code.min(60).max(1) as i64;
                notes.push(format!("more: aix code {cite}:{}-{} (lines {}-{} remain)", last + 1, (last + step).min(b0), last + 1, b0));
            } else if cmd == "tail" && a > a0 {
                let step = cap_code.min(60).max(1) as i64;
                notes.push(format!("earlier: aix code {cite}:{}-{} (lines {}-{} come before)", (a - step).max(a0), a - 1, a0, a - 1));
            }
        }
    }
    let mut r = Res::rows(titles.join("; "), rows, usize::MAX);
    r.cut_style = CapKind::Lines;
    r.notes = notes;
    Ok(r)
}

fn files_cmd(ctx: &Ctx, args: &[String], input: Option<&[SRow]>) -> Result<Res> {
    let (targets, rest, _) = split_targets(ctx, args);
    if let Some(x) = rest.first() {
        bail!("files on a data set: argument {x} is not supported (files @set ...)");
    }
    let mut lines = vec![];
    let mut want: Option<HashSet<(usize, i64)>> = None;
    let mut tlist = targets.clone();
    if let Some(rows) = input {
        want = Some(rows.iter().filter_map(|r| r.src).collect());
        let mut seen = HashSet::new();
        for r in rows {
            if let Some((s, id)) = r.src {
                if seen.insert((s, id)) {
                    if let Ok(Some(set)) = ctx.stores[s].conn.query_row("SELECT set_name FROM items WHERE id=?", [id], |r| r.get::<_, String>(0)).map(Some) {
                        let tok = format!("@{set}");
                        if !tlist.contains(&tok) {
                            tlist.push(tok);
                        }
                    }
                }
            }
        }
    }
    for tok in &tlist {
        let t = resolve(ctx, tok)?;
        for it in &t.items {
            if want.as_ref().is_some_and(|w| !w.contains(&(t.store, it.id))) {
                continue;
            }
            let fields = if it.fields.is_empty() { String::new() } else { format!("  fields: {}", it.fields.iter().take(12).map(|f| f.0.clone()).collect::<Vec<_>>().join(", ")) };
            let note = if it.note.is_empty() { String::new() } else { format!("  ({})", it.note) };
            let recs = if it.recs > 0 { format!(", {} records", it.recs) } else { String::new() };
            lines.push(format!("{}  {}  {} lines{recs}, {}  src {}{fields}{note}", cite_of(&t, it), it.fmt, it.lines, crate::logs::human(it.bytes), if it.src.is_empty() { "-" } else { &it.src }));
        }
    }
    let n = lines.len();
    Ok(Res::lines(format!("{n} item(s)"), lines))
}

fn outline_cmd(ctx: &Ctx, args: &[String]) -> Result<Res> {
    let (targets, _, _) = split_targets(ctx, args);
    let mut lines = vec![];
    for tok in &targets {
        let t = resolve(ctx, tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let cite = cite_of(&t, it);
            let hs: Vec<(i64, i64, String)> = st
                .conn
                .prepare_cached("SELECT id, lvl, title FROM heads WHERE id>=?1 AND id<?2 ORDER BY id")?
                .query_map(params![rid(it.id, 0), rid(it.id + 1, 0)], |r| Ok((r.get::<_, i64>(0)? & 0xffff_ffff, r.get(1)?, r.get(2)?)))?
                .flatten()
                .collect();
            if !hs.is_empty() {
                for (k, (n, lv, title)) in hs.iter().enumerate() {
                    let end = hs[k + 1..].iter().find(|x| x.1 <= *lv).map(|x| x.0 - 1).unwrap_or(it.lines);
                    lines.push(format!("{}{cite}:{n}-{end}  {} {title}", "  ".repeat((*lv as usize).saturating_sub(1)), "#".repeat(*lv as usize)));
                }
            } else if !it.fields.is_empty() {
                lines.push(format!("{cite}: {} {} records; fields (records having it):", it.recs, it.fmt));
                for (f, n) in it.fields.iter().take(60) {
                    lines.push(format!("  {f}  {n}"));
                }
            } else {
                lines.push(format!("{cite}: {} lines of {} (no headings or fields; count by template {cite} shows its shape)", it.lines, it.fmt));
            }
        }
    }
    Ok(Res::lines(String::new(), lines))
}

#[derive(Default)]
struct FilterOpts {
    wheres: Vec<Cond>,
    fields: Vec<String>,
    level: Option<u8>,
    between: Option<(Regex, Regex)>,
    matches: Vec<Regex>,
    nots: Vec<Regex>,
}

fn parse_filter(args: &[String], icase: bool) -> Result<(FilterOpts, Vec<String>)> {
    let mut f = FilterOpts::default();
    let mut rest = vec![];
    let mut i = 0;
    let rx = |s: &str| regex::RegexBuilder::new(s).case_insensitive(icase).build().map_err(|e| anyhow!("bad regex {s:?}: {e}"));
    while i < args.len() {
        let a = args[i].as_str();
        let (k, v) = match a.split_once('=') {
            Some((k, v)) if a.starts_with("--") && !a.starts_with("--where") => (k, Some(v.to_string())),
            _ => (a, None),
        };
        let val = |i: &mut usize| -> Result<String> {
            if let Some(v) = &v {
                return Ok(v.clone());
            }
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| anyhow!("{k} needs a value"))
        };
        match k {
            "--where" => f.wheres.push(parse_where(&val(&mut i)?)?),
            w if w.starts_with("--where=") => f.wheres.push(parse_where(&w[8..])?),
            "--field" | "--fields" => f.fields.extend(val(&mut i)?.split(',').map(|s| sets::norm_field(s.trim())).filter(|s| !s.is_empty())),
            "--level" => f.level = Some(parse_level(&val(&mut i)?)?),
            "--match" | "--grep" => f.matches.push(rx(&val(&mut i)?)?),
            "--not" => f.nots.push(rx(&val(&mut i)?)?),
            "--between" => {
                let a1 = val(&mut i)?;
                i += 1;
                let b1 = args.get(i).cloned().ok_or_else(|| anyhow!("--between needs two regexes: --between 'START' 'END'"))?;
                f.between = Some((rx(&a1)?, rx(&b1)?));
            }
            "-i" => {}
            _ => rest.push(a.to_string()),
        }
        i += 1;
    }
    Ok((f, rest))
}

fn filter_cmd(ctx: &Ctx, args: &[String], input: Option<&[SRow]>, cap: usize) -> Result<Res> {
    let icase = args.iter().any(|a| a == "-i");
    let (targets, rest, _) = split_targets(ctx, args);
    let (f, rest) = parse_filter(&rest, icase)?;
    if let Some(x) = rest.first() {
        bail!("filter: argument {x} is not supported (filter [--where 'F OP V'] [--field F] [--level L] [--between A B] [--match RE] [--not RE] [-i] @set)");
    }
    let text_ok = |l: &str| f.matches.iter().all(|r| r.is_match(l)) && !f.nots.iter().any(|r| r.is_match(l));
    let mut rows = vec![];
    let mut total = 0usize;
    let mut no_field = 0usize;
    let record_mode = !f.wheres.is_empty() || !f.fields.is_empty();
    let fmt_row = |kv: &[(String, String)], raw: &str| -> String {
        if f.fields.is_empty() {
            raw.to_string()
        } else {
            f.fields.iter().map(|x| field_values(kv, x).join(",")).collect::<Vec<_>>().join("\t")
        }
    };
    if let Some(inp) = input {
        for r in inp.iter().filter(|r| is_row(r)) {
            if !text_ok(&r.text) {
                continue;
            }
            if record_mode {
                let kv = row_record(ctx, r);
                if !f.wheres.iter().all(|c| c.test(&kv)) {
                    continue;
                }
                let mut r2 = r.clone();
                r2.text = fmt_row(&kv, &r.text);
                rows.push(r2);
            } else {
                rows.push(r.clone());
            }
        }
        return Ok(Res::rows(format!("{} of {} rows", rows.len(), inp.len()), rows, cap));
    }
    if targets.is_empty() {
        bail!("usage: aix filter [--where 'F OP V'] [--field F] [--level L] [--between A B] [--match RE] [--not RE] @set");
    }
    let mut first_range = true;
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for tok in &targets {
        let t = resolve(ctx, tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let cite = cite_of(&t, it);
            let (a, b) = line_range(&t, it, st)?;
            if record_mode {
                records(st, it, a, b, &mut |n, raw, kv| {
                    if seen.len() < 512 {
                        for (k, _) in kv {
                            seen.insert(sets::norm_field(k));
                        }
                    }
                    if !f.wheres.iter().all(|c| c.test(kv)) || !text_ok(raw) {
                        return true;
                    }
                    if !f.fields.is_empty() && f.fields.iter().all(|x| field_values(kv, x).is_empty()) {
                        no_field += 1;
                    }
                    total += 1;
                    if rows.len() < cap {
                        rows.push(SRow { cite: cite.clone(), n, sep: ':', text: fmt_row(kv, raw), src: Some((t.store, it.id)), m: None });
                    }
                    true
                })?;
            } else {
                let mut lt = LevelTrack { cur: None };
                let mut inside = false;
                scan(st, it.id, a, b, &mut |n, l| {
                    let (lv, _) = if f.level.is_some() { lt.feed(l) } else { (None, false) };
                    let mut keep = true;
                    if let Some((s, e)) = &f.between {
                        if inside {
                            if e.is_match(l) {
                                inside = false;
                            }
                        } else if s.is_match(l) {
                            inside = true;
                            if !first_range {
                                // shown as `--` in the decorated form only (bare equals `sed -n '/A/,/B/p'`)
                                rows.push(SRow { cite: String::new(), n: 0, sep: '~', text: String::new(), src: None, m: None });
                            }
                            first_range = false;
                        } else {
                            keep = false;
                        }
                    }
                    if let Some(min) = f.level {
                        keep &= lv.is_some_and(|x| x >= min);
                    }
                    keep &= text_ok(l);
                    if keep {
                        total += 1;
                        if rows.len() < cap {
                            rows.push(SRow { cite: cite.clone(), n, sep: ':', text: l.to_string(), src: Some((t.store, it.id)), m: None });
                        }
                    }
                    true
                })?;
            }
        }
    }
    // a field no record has (a typo): say which, and the fields there are (not a silent "0 records")
    if total == 0 && !seen.is_empty() {
        if let Some(c) = f.wheres.iter().find(|c| !seen.contains(&c.field)) {
            let list: Vec<&String> = seen.iter().take(30).collect();
            bail!("filter --where: no record has a field {:?} (fields: {})", c.field, list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
    }
    let mut r = Res::rows(format!("{total} {} in {}", if record_mode { "records" } else { "lines" }, targets.join(" ")), rows, 50);
    if no_field > 0 {
        r.notes.push(format!("{no_field} matching records have none of the fields {}", f.fields.join(", ")));
    }
    r.exit = if total == 0 { 1 } else { 0 };
    pad_total(&mut r, total);
    Ok(r)
}

/// rows were capped while scanning: the footer counts the real total
fn pad_total(r: &mut Res, total: usize) {
    r.total = Some(total);
}

/// The record behind a piped row: JSON text parsed, CSV split with its item's header.
fn row_record(ctx: &Ctx, r: &SRow) -> Vec<(String, String)> {
    let mut kv = vec![];
    if let Some((s, id)) = r.src {
        if let Ok((fmt, header, shape)) = ctx.stores[s].conn.query_row("SELECT fmt, header, shape FROM items WHERE id=?", [id], |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?, x.get::<_, String>(2)?))) {
            let fm = Fmt::from_name(&fmt);
            if matches!(fm, Fmt::Csv | Fmt::Tsv) && shape.is_empty() {
                let h: Vec<String> = serde_json::from_str(&header).unwrap_or_default();
                let p = if fm == Fmt::Tsv { Some(r.text.split('\t').map(str::to_string).collect()) } else { sets::csv_split(&r.text, ',') };
                return h.into_iter().zip(p.unwrap_or_default()).collect();
            }
            if fm == Fmt::Json || !shape.is_empty() {
                if let Ok(j) = ctx.stores[s].conn.query_row("SELECT j FROM recs WHERE id=?", [rid(id, r.n)], |x| x.get::<_, String>(0)) {
                    if let Ok(v) = serde_json::from_str::<Value>(&j) {
                        sets::flatten(&v, "", &mut kv);
                        return kv;
                    }
                }
            }
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(r.text.trim()) {
        sets::flatten(&v, "", &mut kv);
    }
    kv
}

fn count_cmd(ctx: &Ctx, args: &[String], input: Option<&[SRow]>) -> Result<Res> {
    let icase = args.iter().any(|a| a == "-i");
    let (targets, rest, _) = split_targets(ctx, args);
    let (f, rest) = parse_filter(&rest, icase)?;
    let mut key = "lines".to_string();
    let mut field = String::new();
    let mut re: Option<Regex> = None;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "by" => {
                key = rest.get(i + 1).cloned().ok_or_else(|| anyhow!("count by what? line|match|field F|template|level|item"))?;
                i += 1;
                if key == "field" {
                    field = sets::norm_field(rest.get(i + 1).ok_or_else(|| anyhow!("count by field <path> (e.g. user.role, items[].sku, a CSV column)"))?);
                    i += 1;
                }
            }
            "--re" | "-e" => {
                let s = rest.get(i + 1).ok_or_else(|| anyhow!("--re needs a regex"))?;
                re = Some(regex::RegexBuilder::new(s).case_insensitive(icase).build().map_err(|e| anyhow!("bad regex {s:?}: {e}"))?);
                i += 1;
            }
            "-i" => {}
            other => bail!("count: argument {other} is not supported (count [by line|match|field F|template|level|item] [--re RE] [--where 'F OP V'] [--level L] @set)"),
        }
        i += 1;
    }
    // `count by <name>`: a field of the targets (named at ingest, JSON, CSV) wins over the built-in keys of the same name
    if key != "field" && !targets.is_empty() {
        let nk = sets::norm_field(&key);
        let mut has = false;
        for tok in &targets {
            if let Ok(t) = resolve(ctx, tok) {
                has |= t.items.iter().any(|it| it.fields.iter().any(|(f, _)| sets::norm_field(f) == nk));
            }
        }
        if has {
            field = nk;
            key = "field".into();
        }
    }
    let key = match key.as_str() {
        "line" | "lines" => "line",
        "match" | "matches" => "match",
        "field" => "field",
        "template" | "templates" | "tpl" => "template",
        "level" | "levels" => "level",
        "item" | "items" | "file" => "item",
        other => bail!("count by {other}: no such field in {} (aix sets show <name> --fields lists them), and not one of line, match, field <path>, template, level, item", if targets.is_empty() { "the rows".to_string() } else { targets.join(" ") }),
    };
    let plain_total = rest.iter().all(|a| a != "by");
    if key == "match" && re.is_none() && input.is_none() {
        bail!("count by match needs --re 'REGEX' (a capture group counts its text), or rows from grep -o in a pipe: aix 'grep -o \"status=[0-9]+\" @set | count by match'");
    }
    let mut groups: HashMap<String, (i64, String)> = HashMap::new();
    let mut units = 0i64;
    let mut missing = 0i64;
    let text_ok = |l: &str| f.matches.iter().all(|r| r.is_match(l)) && !f.nots.iter().any(|r| r.is_match(l));
    let add = |groups: &mut HashMap<String, (i64, String)>, k: String, cite: &dyn Fn() -> String| {
        let e = groups.entry(k).or_insert_with(|| (0, cite()));
        e.0 += 1;
    };
    let match_keys = |re: &Regex, l: &str| -> Vec<String> {
        re.captures_iter(l).map(|c| c.get(1).or_else(|| c.get(0)).map(|m| m.as_str().to_string()).unwrap_or_default()).collect()
    };
    if let Some(inp) = input {
        let mut lt = LevelTrack { cur: None };
        for r in inp.iter().filter(|r| is_row(r)) {
            if !text_ok(&r.text) {
                continue;
            }
            let cite = || format!("{}:{}", r.cite, r.n);
            if !f.wheres.is_empty() && !f.wheres.iter().all(|c| c.test(&row_record(ctx, r))) {
                continue;
            }
            units += 1;
            match key {
                "line" => add(&mut groups, r.text.clone(), &cite),
                "match" => match &re {
                    Some(re) => match_keys(re, &r.text).into_iter().for_each(|k| add(&mut groups, k, &cite)),
                    None => add(&mut groups, r.m.clone().unwrap_or_else(|| r.text.clone()), &cite),
                },
                "field" => {
                    let kv = row_record(ctx, r);
                    let vs = field_values(&kv, &field);
                    if vs.is_empty() {
                        missing += 1;
                    }
                    vs.into_iter().for_each(|v| add(&mut groups, v.to_string(), &cite));
                }
                "template" => add(&mut groups, template_of(&r.text), &cite),
                "level" => {
                    if let (Some(l), true) = lt.feed(&r.text) {
                        add(&mut groups, aix_extract::logparse::level_name(l).to_string(), &cite)
                    }
                }
                _ => add(&mut groups, r.cite.clone(), &cite),
            }
        }
    } else {
        if targets.is_empty() {
            bail!("usage: aix count [by line|match|field F|template|level|item] @set");
        }
        for tok in &targets {
            let t = resolve(ctx, tok)?;
            let st = &ctx.stores[t.store];
            for it in &t.items {
                let c0 = cite_of(&t, it);
                let (a, b) = line_range(&t, it, st)?;
                if key == "field" || (!f.wheres.is_empty() && key != "item") {
                    records(st, it, a, b, &mut |n, raw, kv| {
                        if !f.wheres.iter().all(|c| c.test(kv)) || !text_ok(raw) {
                            return true;
                        }
                        units += 1;
                        let cite = || format!("{c0}:{n}");
                        match key {
                            "field" => {
                                let vs = field_values(kv, &field);
                                if vs.is_empty() {
                                    missing += 1;
                                }
                                vs.into_iter().for_each(|v| add(&mut groups, v.to_string(), &cite));
                            }
                            "line" => add(&mut groups, raw.to_string(), &cite),
                            "match" => {
                                if let Some(re) = &re {
                                    match_keys(re, raw).into_iter().for_each(|k| add(&mut groups, k, &cite));
                                }
                            }
                            "template" => add(&mut groups, template_of(raw), &cite),
                            _ => add(&mut groups, c0.clone(), &cite),
                        }
                        true
                    })?;
                    continue;
                }
                if key == "template" {
                    // templating is the slow part: batches of lines in parallel, counted in order
                    use rayon::prelude::*;
                    let mut lt = LevelTrack { cur: None };
                    let mut buf: Vec<(i64, String)> = Vec::with_capacity(65536);
                    let flush = |buf: &mut Vec<(i64, String)>, groups: &mut HashMap<String, (i64, String)>, units: &mut i64| {
                        let ts: Vec<Option<String>> = buf.par_iter().map(|(_, l)| (aix_extract::logparse::is_entry_start(l, aix_extract::logparse::Format::Auto) && text_ok(l)).then(|| template_of(l))).collect();
                        for ((n, _), t) in buf.iter().zip(ts) {
                            if let Some(t) = t {
                                *units += 1;
                                add(groups, t, &|| format!("{c0}:{n}"));
                            }
                        }
                        buf.clear();
                    };
                    scan(st, it.id, a, b, &mut |n, l| {
                        if let Some(min) = f.level {
                            if !lt.feed(l).0.is_some_and(|x| x >= min) {
                                return true;
                            }
                        }
                        buf.push((n, l.to_string()));
                        if buf.len() >= 65536 {
                            flush(&mut buf, &mut groups, &mut units);
                        }
                        true
                    })?;
                    flush(&mut buf, &mut groups, &mut units);
                    continue;
                }
                let mut lt = LevelTrack { cur: None };
                scan(st, it.id, a, b, &mut |n, l| {
                    let need_lv = f.level.is_some() || key == "level";
                    let (lv, start) = if need_lv { lt.feed(l) } else { (None, false) };
                    if let Some(min) = f.level {
                        if !lv.is_some_and(|x| x >= min) {
                            return true;
                        }
                    }
                    if !text_ok(l) {
                        return true;
                    }
                    let cite = || format!("{c0}:{n}");
                    match key {
                        "line" => {
                            units += 1;
                            if !plain_total {
                                add(&mut groups, l.to_string(), &cite);
                            } else {
                                add(&mut groups, c0.clone(), &|| c0.clone());
                            }
                        }
                        "match" => {
                            units += 1;
                            if let Some(re) = &re {
                                match_keys(re, l).into_iter().for_each(|k| add(&mut groups, k, &cite));
                            }
                        }
                        "template" => {
                            if aix_extract::logparse::is_entry_start(l, aix_extract::logparse::Format::Auto) {
                                units += 1;
                                add(&mut groups, template_of(l), &cite);
                            }
                        }
                        "level" => {
                            if start {
                                units += 1;
                                if let Some(x) = lv {
                                    add(&mut groups, aix_extract::logparse::level_name(x).to_string(), &cite);
                                }
                            }
                        }
                        _ => {
                            units += 1;
                            add(&mut groups, c0.clone(), &|| c0.clone());
                        }
                    }
                    true
                })?;
            }
        }
    }
    let mut gs: Vec<(i64, String, String)> = groups.into_iter().map(|(k, (n, c))| (n, k, c)).collect();
    gs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.as_bytes().cmp(b.1.as_bytes())));
    let show_first = matches!(key, "template" | "match" | "field" | "line") && !plain_total;
    let gs: Vec<(i64, String, String)> = gs.into_iter().map(|(n, k, c)| (n, k, if show_first { format!("  (first {c})") } else { String::new() })).collect();
    let what = if plain_total { "lines per item".to_string() } else if key == "field" { format!("field {field}") } else { key.to_string() };
    let unit = if key == "field" || !f.wheres.is_empty() { "records" } else if matches!(key, "template" | "level") { "entries" } else if input.is_some() { "rows" } else { "lines" };
    let mut r = Res { title: format!("count by {what}: {} groups over {units} {unit}{}", gs.len(), if targets.is_empty() { String::new() } else { format!(" of {}", targets.join(" ")) }), exit: if gs.is_empty() { 1 } else { 0 }, body: Body::Groups(gs), notes: vec![], cut_style: CapKind::Groups, default_cap: if plain_total { usize::MAX } else { 20 }, total: None };
    if missing > 0 {
        r.notes.push(format!("{missing} {unit} without {field}"));
    }
    Ok(r)
}

// ---- find / ask over units -------------------------------------------------------------------------------------------------

struct Unit {
    store: usize,
    cite: String,
    a: i64,
    b: i64,
    tf: Vec<f64>,
    dl: f64,
    best: String,
    text: Option<String>,
}

/// Visit the search units of the targets: markdown sections, records (JSONL/CSV rows, JSON elements), log entries
/// (a line and its stack frames), paragraphs of plain text; at most 40 lines each.
fn for_units(ctx: &Ctx, targets: &[String], f: &mut dyn FnMut(usize, &str, i64, i64, &str)) -> Result<()> {
    for tok in targets {
        let t = resolve(ctx, tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let cite = cite_of(&t, it);
            let (a, b) = line_range(&t, it, st)?;
            let fmt = Fmt::from_name(&it.fmt);
            let table = match fmt {
                Fmt::Md => Some("heads"),
                Fmt::Json => Some("recs"),
                _ => None,
            };
            let starts: Vec<i64> = match table {
                Some(tb) => st.conn.prepare_cached(&format!("SELECT id FROM {tb} WHERE id>=?1 AND id<?2 ORDER BY id"))?.query_map(params![rid(it.id, 0), rid(it.id + 1, 0)], |r| Ok(r.get::<_, i64>(0)? & 0xffff_ffff))?.flatten().collect(),
                None => vec![],
            };
            let mut cur: Option<(i64, i64, String)> = None;
            let mut hi = 0usize;
            let per_line = matches!(fmt, Fmt::Jsonl | Fmt::Csv | Fmt::Tsv);
            scan(st, it.id, a, b, &mut |n, l| {
                let mut boundary = cur.is_none();
                if table.is_some() {
                    while hi < starts.len() && starts[hi] < n {
                        hi += 1;
                    }
                    if hi < starts.len() && starts[hi] == n {
                        boundary = true;
                    }
                } else if per_line {
                    boundary = true;
                } else if fmt == Fmt::Log {
                    boundary |= aix_extract::logparse::is_entry_start(l, aix_extract::logparse::Format::Auto);
                } else if l.trim().is_empty() {
                    if let Some((ua, ub, ut)) = cur.take() {
                        f(t.store, &cite, ua, ub, &ut);
                    }
                    return true;
                }
                if let Some((ua, ub, _)) = &cur {
                    if ub - ua >= 39 {
                        boundary = true;
                    }
                }
                if boundary {
                    if let Some((ua, ub, ut)) = cur.take() {
                        f(t.store, &cite, ua, ub, &ut);
                    }
                    cur = Some((n, n, l.to_string()));
                } else if let Some((_, ub, ut)) = &mut cur {
                    *ub = n;
                    ut.push('\n');
                    ut.push_str(l);
                }
                true
            })?;
            if let Some((ua, ub, ut)) = cur.take() {
                f(t.store, &cite, ua, ub, &ut);
            }
        }
    }
    Ok(())
}

fn toks(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_').filter(|w| w.len() >= 2).map(|w| w.to_lowercase()).collect()
}

const SEM_MAX_UNITS: usize = 3000;

fn find_cmd(ctx: &mut Ctx, cmd: &str, args: &[String]) -> Result<Res> {
    let mut targets = vec![];
    let mut words = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--in" {
            if let Some(t) = args.get(i + 1) {
                targets.push(t.clone());
            }
            i += 2;
            continue;
        }
        if a.starts_with('@') && ctx.is_set_token(a) {
            targets.push(a.clone());
        } else if a == "--kind" {
            i += 1;
        } else if a != "--answer" {
            words.push(a.clone());
        }
        i += 1;
    }
    let q = words.join(" ");
    let qt: Vec<String> = {
        let mut v = toks(&q);
        v.sort();
        v.dedup();
        v
    };
    if qt.is_empty() || targets.is_empty() {
        bail!("usage: aix {cmd} <words> --in @set");
    }
    let mut units: Vec<Unit> = vec![];
    let (mut n, mut dl_sum) = (0f64, 0f64);
    let mut df = vec![0f64; qt.len()];
    let keep_all = cmd == "ask" && ctx.embed.is_some();
    for_units(ctx, &targets, &mut |store, cite, a, b, text| {
        n += 1.0;
        let mut tf = vec![0f64; qt.len()];
        let mut dl = 0f64;
        for w in toks(text) {
            dl += 1.0;
            if let Ok(k) = qt.binary_search(&w) {
                tf[k] += 1.0;
            }
        }
        dl_sum += dl;
        let hit = tf.iter().any(|x| *x > 0.0);
        for (k, x) in tf.iter().enumerate() {
            if *x > 0.0 {
                df[k] += 1.0;
            }
        }
        if hit || keep_all && units.len() < SEM_MAX_UNITS + 1 {
            let best = text
                .lines()
                .max_by_key(|l| {
                    let lt = toks(l);
                    qt.iter().filter(|w| lt.contains(w)).count()
                })
                .unwrap_or("")
                .trim()
                .to_string();
            units.push(Unit { store, cite: cite.to_string(), a, b, tf, dl, best, text: keep_all.then(|| text.to_string()) });
        }
    })?;
    let avgdl = dl_sum / n.max(1.0);
    let mut scored: Vec<(f64, usize)> = units
        .iter()
        .enumerate()
        .filter_map(|(k, u)| {
            let s: f64 = u
                .tf
                .iter()
                .enumerate()
                .map(|(w, tf)| {
                    if *tf == 0.0 {
                        return 0.0;
                    }
                    let idf = ((n - df[w] + 0.5) / (df[w] + 0.5) + 1.0).ln();
                    idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * u.dl / avgdl.max(1.0)))
                })
                .sum();
            (s > 0.0).then_some((s, k))
        })
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
    let mut notes = vec![];
    if cmd == "ask" {
        let r = if n as usize > SEM_MAX_UNITS { Err(format!("{n} units: embeddings are built for sets of up to {SEM_MAX_UNITS} units")) } else { semantic_rank(ctx, &q, &units) };
        match r {
            Ok(sem) => {
                // reciprocal rank fusion of keyword and embedding ranks
                let mut f: HashMap<usize, f64> = HashMap::new();
                for (r, (_, k)) in scored.iter().enumerate() {
                    *f.entry(*k).or_default() += 1.0 / (60.0 + r as f64);
                }
                for (r, k) in sem.iter().take(200).enumerate() {
                    *f.entry(*k).or_default() += 1.0 / (60.0 + r as f64);
                }
                let mut v: Vec<(f64, usize)> = f.into_iter().map(|(k, s)| (s, k)).collect();
                v.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
                scored = v;
                notes.push("ranked by keywords + embeddings (RRF)".to_string());
            }
            Err(e) => notes.push(format!("keyword ranking only ({e})")),
        }
    }
    let lines: Vec<String> = scored
        .iter()
        .map(|(s, k)| {
            let u = &units[*k];
            let range = if u.a == u.b { format!("{}", u.a) } else { format!("{}-{}", u.a, u.b) };
            format!("{}:{range}  {}  {}", u.cite, fmt_score(*s), u.best)
        })
        .collect();
    let mut r = Res::lines(format!("{cmd} {q:?} in {}: {} of {} units match", targets.join(" "), lines.len(), n), lines);
    r.default_cap = 10;
    r.notes = notes;
    Ok(r)
}

fn fmt_score(s: f64) -> String {
    if s >= 0.1 {
        format!("{s:.2}")
    } else {
        format!("{s:.1e}")
    }
}

/// Embedding rank of the units (cached per unit text in the store), or why not.
fn semantic_rank(ctx: &Ctx, q: &str, units: &[Unit]) -> std::result::Result<Vec<usize>, String> {
    let ep = ctx.embed.clone().ok_or("no embedder configured")?;
    let t0 = std::time::Instant::now();
    let mut vecs: Vec<Option<Vec<f32>>> = vec![None; units.len()];
    let texts: Vec<&str> = units.iter().map(|u| u.text.as_deref().unwrap_or(&u.best)).collect();
    let keys: Vec<String> = texts.iter().map(|t| blake3::hash(format!("{}\u{1}{}\u{1}{}", ep.model, ctx.embed_doc_prefix, t).as_bytes()).to_hex()[..32].to_string()).collect();
    for s in &ctx.stores {
        let _ = s.conn.execute_batch("CREATE TABLE IF NOT EXISTS vecs(k TEXT PRIMARY KEY, v BLOB)");
    }
    for (i, u) in units.iter().enumerate() {
        if let Ok(b) = ctx.stores[u.store].conn.query_row("SELECT v FROM vecs WHERE k=?", [&keys[i]], |r| r.get::<_, Vec<u8>>(0)) {
            vecs[i] = Some(crate::llm::from_blob(&b));
        }
    }
    let todo: Vec<usize> = (0..units.len()).filter(|i| vecs[*i].is_none()).collect();
    for chunk in todo.chunks(32) {
        if t0.elapsed().as_secs() > 30 {
            return Err("embedding the set took over 30 s (run the ask again to continue)".into());
        }
        let batch: Vec<String> = chunk.iter().map(|i| format!("{}{}", ctx.embed_doc_prefix, texts[*i].chars().take(2000).collect::<String>())).collect();
        let vs = crate::llm::embed(&ep, &batch, std::time::Duration::from_secs(20)).map_err(|e| format!("embedder unavailable: {}", e.to_string().chars().take(80).collect::<String>()))?;
        for (i, v) in chunk.iter().zip(vs) {
            let _ = ctx.stores[units[*i].store].conn.execute("INSERT OR REPLACE INTO vecs(k, v) VALUES(?,?)", params![keys[*i], crate::llm::to_blob(&v)]);
            vecs[*i] = Some(v);
        }
    }
    let qv = crate::llm::embed(&ep, &[format!("{}{q}", ctx.embed_query_prefix)], std::time::Duration::from_secs(8)).map_err(|e| format!("embedder unavailable: {}", e.to_string().chars().take(80).collect::<String>()))?;
    let qv = qv.into_iter().next().unwrap_or_default();
    let mut s: Vec<(f32, usize)> = vecs.iter().enumerate().filter_map(|(i, v)| v.as_ref().map(|v| (crate::llm::dot(&qv, v), i))).collect();
    s.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(s.into_iter().map(|x| x.1).collect())
}

// ---- sql ------------------------------------------------------------------------------------------------------------------------

fn view_name(set: &str) -> String {
    // `@a.b` and `@a-b` are two sets: their views must not share a name
    let tag: String = set.chars().filter(|c| matches!(c, '-' | '.')).map(|c| if c == '-' { 'd' } else { 'p' }).collect();
    let base = format!("set_{}", set.replace(['-', '.'], "_"));
    if tag.is_empty() {
        base
    } else {
        format!("{base}__{tag}")
    }
}

fn sql_cmd(ctx: &Ctx, args: &[String], cap: usize) -> Result<Res> {
    let q = args.join(" ");
    static AT: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"@([A-Za-z0-9][A-Za-z0-9_.-]*)").unwrap());
    let mut sets_used: Vec<(usize, String)> = vec![];
    for c in AT.captures_iter(&q) {
        let n = c[1].trim_end_matches('.').to_string();
        if let Some(s) = ctx.find_set(&n) {
            if !sets_used.iter().any(|x| x.1 == n) {
                sets_used.push((s, n));
            }
        }
    }
    if sets_used.is_empty() {
        bail!("sql over data sets: name one with @name (SELECT ... FROM @data)");
    }
    let si = sets_used[0].0;
    if sets_used.iter().any(|x| x.0 != si) {
        bail!("sql: the sets named live in different stores (repo and --global); query them one at a time");
    }
    let path = ctx.stores[si].path.clone();
    let c = rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.create_scalar_function("csv_field", 3, rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC | rusqlite::functions::FunctionFlags::SQLITE_UTF8, |cx| {
        let t: String = cx.get(0)?;
        let i: i64 = cx.get(1)?;
        let sep: String = cx.get(2)?;
        let parts = if sep == "\t" { Some(t.split('\t').map(str::to_string).collect::<Vec<_>>()) } else { sets::csv_split(&t, ',') };
        Ok(parts.and_then(|p| p.get(i as usize).cloned()))
    })?;
    c.create_scalar_function("regexp", 2, rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC | rusqlite::functions::FunctionFlags::SQLITE_UTF8, |cx| {
        let re: String = cx.get(0)?;
        let t: Option<String> = cx.get(1)?;
        let r = Regex::new(&re).map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
        Ok(t.is_some_and(|t| r.is_match(&t)))
    })?;
    let mut q2 = q.clone();
    let mut described = vec![];
    for (s, n) in &sets_used {
        let items = sets::items_of(&ctx.stores[*s], n)?;
        // columns: item, line, text + the set's scalar fields (top 64, no arrays)
        let mut cols: Vec<String> = vec![];
        for it in &items {
            for (f, _) in &it.fields {
                if !f.contains("[]") && !cols.contains(f) && cols.len() < 64 && !matches!(f.as_str(), "item" | "line" | "text") {
                    cols.push(f.clone());
                }
            }
        }
        let mut selects = vec![];
        for (k, it) in items.iter().enumerate() {
            let fm = Fmt::from_name(&it.fmt);
            // CSV / TSV: one row per record, read by the record parser count and filter use (a quoted field may span lines)
            if matches!(fm, Fmt::Csv | Fmt::Tsv) && it.shape.is_empty() {
                let tn = format!("aixrec_{}_{k}", described.len());
                c.execute_batch(&format!("CREATE TEMP TABLE \"{tn}\" (line INTEGER, t TEXT)"))?;
                {
                    let mut ins = c.prepare(&format!("INSERT INTO temp.\"{tn}\" VALUES (?1, ?2)"))?;
                    let mut err = None;
                    records(&ctx.stores[*s], it, 1, i64::from(u32::MAX), &mut |n, text, _| {
                        if let Err(e) = ins.execute(params![n, text]) {
                            err = Some(e);
                            return false;
                        }
                        true
                    })?;
                    if let Some(e) = err {
                        return Err(e.into());
                    }
                }
                let sepq = if fm == Fmt::Tsv { "\t" } else { "," };
                let colexpr: Vec<String> = cols
                    .iter()
                    .map(|f| {
                        let e = match it.header.iter().position(|h| h == f) {
                            Some(i) => format!("csv_field(t, {i}, '{sepq}')"),
                            None => "NULL".into(),
                        };
                        format!("{e} AS \"{}\"", f.replace('"', "\"\""))
                    })
                    .collect();
                let extra = if colexpr.is_empty() { String::new() } else { format!(", {}", colexpr.join(", ")) };
                selects.push(format!("SELECT '{}' AS item, line, t AS text{extra} FROM temp.\"{tn}\"", it.item.replace('\'', "''")));
                continue;
            }
            let colexpr: Vec<String> = cols
                .iter()
                .map(|f| {
                    let qf = f.replace('"', "\"\"");
                    let e = match fm {
                        Fmt::Csv | Fmt::Tsv if it.shape.is_empty() => match it.header.iter().position(|h| h == f) {
                            Some(k) => format!("csv_field(t, {k}, '{}')", if fm == Fmt::Tsv { "\t" } else { "," }),
                            None => "NULL".into(),
                        },
                        _ => {
                            let path = f.split('.').map(|p| format!("\"{}\"", p.replace('"', "\\\""))).collect::<Vec<_>>().join(".");
                            format!("CASE WHEN json_valid(t) THEN json_extract(t, '$.{}') END", path.replace('\'', "''"))
                        }
                    };
                    format!("{e} AS \"{qf}\"")
                })
                .collect();
            let extra = if colexpr.is_empty() { String::new() } else { format!(", {}", colexpr.join(", ")) };
            let (table, cond) = match fm {
                _ if !it.shape.is_empty() => ("recs", String::new()),
                Fmt::Json => ("recs", String::new()),
                Fmt::Jsonl => ("lines", " AND json_valid(t)".to_string()),
                Fmt::Csv | Fmt::Tsv => ("lines", format!(" AND id>{}", rid(it.id, 1))),
                _ => ("lines", String::new()),
            };
            let tcol = if table == "recs" { "j" } else { "t" };
            let extra = extra.replace("(t,", &format!("({tcol},")).replace("json_valid(t)", &format!("json_valid({tcol})"));
            selects.push(format!(
                "SELECT '{}' AS item, (id & 4294967295) AS line, {tcol} AS text{extra} FROM {table} WHERE id>{} AND id<{}{cond}",
                it.item.replace('\'', "''"),
                rid(it.id, 0),
                rid(it.id + 1, 0)
            ));
        }
        let vn = view_name(n);
        c.execute_batch(&format!("CREATE TEMP VIEW \"{vn}\" AS {}", selects.join(" UNION ALL ")))?;
        described.push(format!("@{n} = {vn}(item, line, text{})", cols.iter().map(|c| format!(", \"{c}\"")).collect::<String>()));
        q2 = Regex::new(&format!(r"@{}\b", regex::escape(n))).unwrap().replace_all(&q2, format!("\"{vn}\"").as_str()).into_owned();
    }
    c.execute_batch("PRAGMA query_only=1")?;
    let mut st = c.prepare(&q2).map_err(|e| anyhow!("sql: {e} (views: {})", described.join("; ")))?;
    if !st.readonly() {
        bail!("sql: read-only queries only");
    }
    let names: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = st.query([])?;
    let mut lines = vec![names.join("\t")];
    let mut n = 0usize;
    while let Some(r) = rows.next()? {
        n += 1;
        if n > cap.max(1) * 50 && n > 100_000 {
            break;
        }
        let vals: Vec<String> = (0..names.len())
            .map(|i| match r.get_ref(i) {
                Ok(rusqlite::types::ValueRef::Null) => String::new(),
                Ok(rusqlite::types::ValueRef::Integer(x)) => x.to_string(),
                Ok(rusqlite::types::ValueRef::Real(x)) => x.to_string(),
                Ok(rusqlite::types::ValueRef::Text(t)) => String::from_utf8_lossy(t).replace(['\n', '\t'], " "),
                Ok(rusqlite::types::ValueRef::Blob(b)) => format!("<{} bytes>", b.len()),
                Err(_) => String::new(),
            })
            .collect();
        lines.push(vals.join("\t"));
    }
    let mut r = Res::lines(format!("sql over {}: {n} rows", sets_used.iter().map(|x| format!("@{}", x.1)).collect::<Vec<_>>().join(" ")), lines);
    r.default_cap = 51;
    r.exit = if n == 0 { 1 } else { 0 };
    r.notes.push(described.join("; "));
    Ok(r)
}

// ---- sets / put ------------------------------------------------------------------------------------------------------------------

fn ago(t: i64) -> String {
    crate::logs::ago(sets::now() - t)
}

fn sets_cmd(ctx: &mut Ctx, args: &[String], allow_write: bool) -> Result<Res> {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let global = args.iter().any(|a| a == "--global");
    match sub {
        "list" | "ls" | "--global" => {
            for s in &ctx.stores {
                let _ = sets::prune(s);
            }
            let mut lines = vec![];
            for s in &ctx.stores {
                for i in sets::list_sets(s)? {
                    if global && !i.global {
                        continue;
                    }
                    let ttl = if i.ttl == 0 { "never".to_string() } else { let left = i.updated + i.ttl - sets::now(); format!("expires in {}", if left >= 172_800 { format!("{}d", (left + 43_200) / 86_400) } else { crate::logs::ago(left.max(0)) }) };
                    let rec = if i.recs > 0 { format!(", {} records", i.recs) } else { String::new() };
                    let note = if i.note.is_empty() { String::new() } else { format!("  note: {}", i.note) };
                    let items = sets::items_of(s, &i.name).unwrap_or_default();
                    let mut fl: Vec<String> = vec![];
                    let mut shapes: Vec<String> = vec![];
                    for it in &items {
                        let sp: Option<crate::setpat::ShapeSpec> = serde_json::from_str(&it.shape).ok();
                        for (f, _) in &it.fields {
                            if f.starts_with('_') || fl.contains(f) {
                                continue;
                            }
                            let ty = sp.as_ref().and_then(|x| x.compile().ok()).and_then(|x| x.types.get(f).copied()).filter(|t| *t != crate::setpat::Ty::Text);
                            fl.push(match ty { Some(t) => format!("{f}({})", t.name()), None => f.clone() });
                        }
                        if let Some(sp) = sp {
                            let d = sp.describe();
                            if !shapes.contains(&d) {
                                shapes.push(d);
                            }
                        }
                    }
                    let more = fl.len().saturating_sub(16);
                    fl.truncate(16);
                    let mut extra: Vec<String> = vec![];
                    if !fl.is_empty() {
                        extra.push(format!("    fields: {}{}", fl.join(" "), if more > 0 { format!(" (+{more})") } else { String::new() }));
                    }
                    if !shapes.is_empty() {
                        extra.push(format!("    {}", shapes.join(" | ")));
                    }
                    lines.push(format!(
                        "@{}{}  {} item(s), {} lines{rec}, {}  made {} ago, used {} ago ({}x), {ttl}{note}",
                        i.name,
                        if i.global { " (global)" } else { "" },
                        i.items,
                        i.lines,
                        crate::logs::human(i.bytes),
                        ago(i.created),
                        ago(i.used),
                        i.uses
                    ));
                    lines.extend(extra);
                }
            }
            let nsets = lines.iter().filter(|l| l.starts_with('@')).count();
            let mut r = Res::lines(format!("{nsets} data set(s)"), lines);
            if r.exit == 1 {
                r.notes.push("no data sets: `cmd 2>&1 | aix put <name> -` or `aix put <name> <file>...` stores one".into());
            }
            r.default_cap = 200;
            Ok(r)
        }
        "rm" | "prune" if !allow_write => bail!("sets {sub} changes stored data: not enabled for MCP in this repo (run it in a terminal, or opt in with aix-init --allow-data)"),
        "rm" => {
            // strict flags: an unknown one (`--dry-run` typed from habit, a typo) removes nothing
            let dry = args[1..].iter().any(|a| a == "--dry-run" || a == "-n");
            if let Some(bad) = args[1..].iter().find(|a| a.starts_with('-') && !matches!(a.as_str(), "--global" | "--dry-run" | "-n")) {
                bail!("sets rm: unknown flag {bad} (nothing removed; flags: --global, --dry-run)");
            }
            let names: Vec<&String> = args[1..].iter().filter(|a| !a.starts_with('-')).collect();
            if names.is_empty() {
                bail!("usage: aix sets rm <name>... [--global] [--dry-run]");
            }
            let mut lines = vec![];
            let mut missing = 0;
            let total = names.len();
            for n in names {
                let n = n.trim_start_matches('@');
                let mut done = false;
                for s in &ctx.stores {
                    if global && !s.global {
                        continue;
                    }
                    if dry {
                        if sets::exists(s, n) {
                            lines.push(format!("would remove @{n}{} (--dry-run: nothing removed)", if s.global { " (global)" } else { "" }));
                            done = true;
                            break;
                        }
                        continue;
                    }
                    if let Some((items, bytes)) = sets::remove(s, n)? {
                        lines.push(format!("removed @{n}{}: {items} item(s), {}", if s.global { " (global)" } else { "" }, crate::logs::human(bytes)));
                        done = true;
                        break;
                    }
                }
                if !done {
                    lines.push(format!("no data set @{n}"));
                    missing += 1;
                }
            }
            let mut r = Res::lines(String::new(), lines);
            r.exit = if missing == total { 1 } else { 0 };
            Ok(r)
        }
        "prune" => {
            let mut lines = vec![];
            for s in &ctx.stores {
                for n in sets::prune(s)? {
                    lines.push(format!("pruned @{n} (ttl ran out)"));
                }
            }
            if lines.is_empty() {
                lines.push("nothing to prune".into());
            }
            let mut r = Res::lines(String::new(), lines);
            r.exit = 0;
            Ok(r)
        }
        "show" if args.iter().any(|a| a == "--fields") => fields_cmd(ctx, &args[1..]),
        "show" | "files" if args[1..].iter().any(|a| !a.starts_with('-') && ctx.find_set(a.trim_start_matches('@').split(['/', ':']).next().unwrap_or("")).is_none()) => {
            let a = args[1..].iter().find(|a| !a.starts_with('-') && ctx.find_set(a.trim_start_matches('@').split(['/', ':']).next().unwrap_or("")).is_none()).unwrap();
            bail!("unknown data set @{} (aix sets lists them)", a.trim_start_matches('@'))
        }
        "show" | "files" => files_cmd(ctx, &args[1..].iter().map(|a| if a.starts_with('@') || a.starts_with('-') { a.clone() } else { format!("@{a}") }).collect::<Vec<_>>(), None),
        other => bail!("sets {other}: use `aix sets` (list), `aix sets rm <name>`, `aix sets prune`, `aix sets show <@name>`"),
    }
}

/// `sets show NAME --fields`: every field with its type, non-null count and 3 sample values.
fn fields_cmd(ctx: &Ctx, args: &[String]) -> Result<Res> {
    let mut lines = vec![];
    for a in args.iter().filter(|a| !a.starts_with("--")) {
        let tok = if a.starts_with('@') { a.clone() } else { format!("@{a}") };
        let t = resolve(ctx, &tok)?;
        let st = &ctx.stores[t.store];
        for it in &t.items {
            let types = serde_json::from_str::<crate::setpat::ShapeSpec>(&it.shape).ok().and_then(|x| x.compile().ok()).map(|x| x.types).unwrap_or_default();
            let mut stats: BTreeMap<String, (i64, Vec<String>, bool)> = BTreeMap::new();
            let mut n = 0i64;
            records(st, it, 1, it.lines.max(1), &mut |_, _, kv| {
                n += 1;
                let mut seen = HashSet::new();
                for (k, v) in kv {
                    let e = stats.entry(k.clone()).or_insert((0, vec![], true));
                    if seen.insert(k.clone()) && v != "null" && !v.is_empty() {
                        e.0 += 1;
                    }
                    e.2 &= num(v).is_some();
                    if e.1.len() < 3 && !e.1.contains(v) {
                        e.1.push(v.chars().take(60).collect());
                    }
                }
                true
            })?;
            lines.push(format!("{}: {n} records, {} fields", cite_of(&t, it), stats.len()));
            let mut v: Vec<_> = stats.into_iter().collect();
            v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
            for (f, (k, samples, numeric)) in v {
                let ty = types.get(&sets::norm_field(&f)).map(|t| t.name()).unwrap_or(if numeric { "num?" } else { "text" });
                lines.push(format!("  {f}  {ty}  {k} non-null  e.g. {}", samples.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")));
            }
        }
    }
    let mut r = Res::lines(String::new(), lines);
    r.default_cap = 400;
    Ok(r)
}

/// Is writing data sets from MCP enabled for this repo (`allow_data = true` in .aix/config.toml, set by
/// `aix-init --allow-data`)?
pub fn mcp_data_allowed(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join("config.toml")).ok().and_then(|t| t.parse::<toml::Table>().ok()).and_then(|t| t.get("allow_data").and_then(|v| v.as_bool())).unwrap_or(false)
}

pub struct PutArgs {
    pub name: String,
    pub paths: Vec<String>,
    pub stdin: bool,
    pub global: bool,
    pub allow_dot: bool,
    pub guess: bool,
    pub help: bool,
    pub o: sets::PutOpts,
}

pub const PUT_HELP: &str = "usage: aix put <name> [PATH... | GLOB | - | @set[/item]] [options]   (data, kept local and redacted; query it as @name)
  --format auto|text|log|json|jsonl|csv|tsv|md|clf|syslog   (log, clf, syslog also name fields: ts level thread logger msg / ip ts method path status size / ts host app pid msg)
  --pattern P (repeatable; the first that matches a line wins, recorded in _pat; unmatched lines keep their text in _raw)
      template:  --pattern '{ts:time} [{level}] {logger}: {msg}'   ({name} lazy, the last one takes the rest; {ms:int} {n:num} {ts:time}
                 {ip:ip} {id:word} {x:quoted} {_} skips, {name:/regex/} custom)
      regex:     --pattern '(?P<ts>\\S+ \\S+) (?P<level>[A-Z]+) (?P<msg>.*)'   (unnamed groups become f1..fN)
      auto:      --pattern auto   (proposes a template from the first 200 lines; below 80% it stops with exit 2 and the command to rerun)
  --multiline START_RE   a line not matching START_RE continues the record before it (stack traces); applied before --pattern
  --fields a,b,c [--sep S]   split on a literal separator (default whitespace; /regex/ for a regex); the last field takes the rest
  --kv   also every key=value / key=\"v v\" pair as a field
  --type ts=time,ms=int,size=int   typed fields: --where 'ms>500', --where 'ts>=2026-10-24T10:00'
  --append | --replace (default for an existing name) | --keep   --item NAME   --ttl 7d|never   --note T   --global   --max-mb N   --keep-ips
  aix put --guess FILE|-   prints the proposed template and its match rate, stores nothing";

pub fn parse_put(args: &[String]) -> Result<PutArgs> {
    let mut p = PutArgs { name: String::new(), paths: vec![], stdin: false, global: false, allow_dot: false, guess: false, help: false, o: sets::PutOpts::default() };
    let mut shape = crate::setpat::ShapeSpec::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let (k, v) = match a.split_once('=') {
            Some((k, v)) if a.starts_with("--") => (k, Some(v.to_string())),
            _ => (a, None),
        };
        let val = |i: &mut usize| -> Result<String> {
            if let Some(v) = &v {
                return Ok(v.clone());
            }
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| anyhow!("{k} needs a value"))
        };
        match k {
            "-" => p.stdin = true,
            "-h" | "--help" => p.help = true,
            "--guess" => p.guess = true,
            "--format" | "-f" => {
                let f = val(&mut i)?;
                match f.as_str() {
                    "clf" | "syslog" | "access" | "nginx" | "apache" => {
                        shape.preset = Some(if f == "syslog" { "syslog".into() } else { "clf".into() });
                        p.o.fmt = Some(Fmt::Log);
                    }
                    "log" => {
                        shape.preset = Some("log".into());
                        p.o.fmt = Some(Fmt::Log);
                    }
                    _ => p.o.fmt = Fmt::parse(&f).ok_or_else(|| anyhow!("--format {f}: auto|text|log|json|jsonl|csv|tsv|md|clf|syslog"))?,
                }
            }
            "--pattern" | "-p" => {
                let pt = val(&mut i)?;
                if pt == "auto" {
                    p.o.auto = true;
                } else {
                    shape.pats.push(pt);
                }
            }
            "--multiline" => shape.multiline = Some(val(&mut i)?),
            "--fields" => shape.fields = val(&mut i)?.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
            "--sep" => shape.sep = Some(val(&mut i)?),
            "--kv" => shape.kv = true,
            "--type" | "--types" => {
                for kv in val(&mut i)?.split(',') {
                    let (f, t) = kv.split_once('=').ok_or_else(|| anyhow!("--type {kv}: write field=int|num|time|text"))?;
                    crate::setpat::Ty::parse(t.trim()).ok_or_else(|| anyhow!("--type {f}={t}: int, num, time or text"))?;
                    shape.types.insert(f.trim().to_string(), t.trim().to_string());
                }
            }
            "--append" | "-a" => p.o.append = true,
            "--replace" => p.o.replace = true,
            "--keep" | "--no-clobber" => p.o.keep = true,
            "--ttl" => {
                let t = val(&mut i)?;
                p.o.ttl = Some(sets::parse_ttl(&t).ok_or_else(|| anyhow!("--ttl {t}: a positive duration like 30m, 12h, 7d, or never (no expiry)"))?);
            }
            "--note" => p.o.note = Some(val(&mut i)?),
            "--item" | "--as" => p.o.item = Some(sets::item_name(&val(&mut i)?)),
            "--global" => p.global = true,
            "--keep-ips" => p.o.keep_ips = true,
            "--allow-dotfile" => p.allow_dot = true,
            "--max-mb" => {
                let m = val(&mut i)?;
                p.o.max_bytes = Some(m.parse::<u64>().ok().filter(|m| *m > 0).ok_or_else(|| anyhow!("--max-mb {m}: a number of MB from 1"))? << 20);
            }
            s if s.starts_with('-') && s.len() > 1 => bail!("put: unknown flag {s} (aix put --help lists them)"),
            _ => {
                if p.name.is_empty() && !p.guess {
                    p.name = a.trim_start_matches('@').to_string();
                } else {
                    p.paths.push(a.to_string());
                }
            }
        }
        i += 1;
    }
    if p.help {
        return Ok(p);
    }
    if p.guess {
        // `put --guess FILE` and `put NAME --guess FILE` alike: a name is not needed
        if !p.name.is_empty() && p.paths.is_empty() && !p.stdin {
            p.paths.push(std::mem::take(&mut p.name));
        }
    } else if p.name.is_empty() {
        bail!("usage: aix put <name> [PATH... | -] [--format F] [--pattern P] [--append] [--ttl 7d] (aix put --help)");
    }
    if p.o.append && p.o.replace {
        bail!("put: --append and --replace contradict each other");
    }
    if p.o.auto && !shape.pats.is_empty() {
        bail!("put: --pattern auto and an explicit --pattern contradict each other");
    }
    // compile now: a bad regex or template is a usage error before anything is read
    if !shape.is_empty() || !shape.types.is_empty() || shape.multiline.is_some() {
        shape.compile()?;
        p.o.shape = Some(shape);
    }
    Ok(p)
}

/// The answer of a `put`: its lines and the process status (2: `--pattern auto` was not confident).
pub struct PutOut {
    pub lines: Vec<String>,
    pub exit: i32,
}

pub fn put_report(name: &str, global: bool, r: &sets::PutReport) -> Vec<String> {
    let mut v = vec![];
    let lines: i64 = r.items.iter().map(|x| x.2).sum();
    let bytes: i64 = r.items.iter().map(|x| x.3).sum();
    let recs: i64 = r.items.iter().map(|x| x.4).sum();
    let fmts: Vec<String> = {
        let mut f: Vec<String> = r.items.iter().map(|x| x.1.clone()).collect();
        f.sort();
        f.dedup();
        f
    };
    v.push(format!(
        "stored @{name}{}: {} item(s), {lines} lines{}, {} stored ({}) from {} read in {:.2} s; store {}{}",
        if global { " (global)" } else { "" },
        r.items.len(),
        if recs > 0 { format!(", {recs} records") } else { String::new() },
        crate::logs::human(bytes),
        fmts.join(","),
        crate::logs::human(r.raw_bytes as i64),
        r.secs,
        if r.db_growth >= 0 { format!("+{}", crate::logs::human(r.db_growth)) } else { format!("-{}", crate::logs::human(-r.db_growth)) },
        r.replaced.map(|(i, b)| format!("; replaced the previous @{name} ({i} item(s), {})", crate::logs::human(b))).unwrap_or_default()
    ));
    if r.items.len() > 1 {
        for (it, f, l, b, _) in r.items.iter().take(20) {
            v.push(format!("  @{name}/{it}  {f}  {l} lines, {}", crate::logs::human(*b)));
        }
    }
    let single = r.items.len() == 1;
    for sm in r.summaries.iter().take(40) {
        // `@set/item fields: ...` -> `@set fields: ...` for a one-item set
        let sm = if single { sm.replacen(&format!("@{name}/{} ", r.items[0].0), &format!("@{name} "), 1) } else { sm.clone() };
        v.push(sm);
    }
    for n in &r.notes {
        v.push(format!("note: {n}"));
    }
    if let Some(m) = &r.low_conf {
        v.push(format!("needs you: {m}"));
    }
    let any = if single { format!("@{name}") } else { format!("@{name}/<item>") };
    let rec = r.items.iter().any(|x| x.4 > 0);
    v.push(format!(
        // '@name' quoted: PowerShell reads a bare @name as a splat of $name and passes nothing
        "query it: aix grep '<re>' '@{name}' -C 3 | aix code {any}:1-60 | aix count by {} '@{name}' | aix files '@{name}'{}",
        if rec { "<field>" } else { "template" },
        if rec { format!(" | aix filter --where '<field>>=N' '@{name}' | aix sets show {name} --fields") } else { String::new() }
    ));
    v
}

/// `put --guess`: the proposal for each input, nothing stored.
fn guess_report(inputs: Vec<sets::Input>, keep_ips: bool) -> Result<PutOut> {
    let mut lines = vec![];
    let mut exit = 0;
    for mut inp in inputs {
        let mut first = vec![];
        let mut buf = String::new();
        while first.len() < 200 {
            buf.clear();
            if inp.reader.read_line(&mut buf)? == 0 {
                break;
            }
            first.push(crate::logs::redact_text(buf.trim_end_matches(['\n', '\r']), keep_ips));
        }
        // drain the rest (a producer piping into us must not die of SIGPIPE)
        let _ = std::io::copy(&mut inp.reader, &mut std::io::sink());
        let g = crate::setpat::guess(&first, &inp.name);
        let pct = (g.rate * 100.0).round();
        lines.push(format!("{}: {} -> {} (matches {} of {} sampled records, {pct}%)", inp.name, g.what, if g.shown.is_empty() { "no pattern" } else { &g.shown }, g.matched, g.sample));
        if let Some(sp) = &g.spec {
            if let Ok(sh) = sp.compile() {
                if let Some(l) = first.iter().find(|l| !l.trim().is_empty()) {
                    let (m, w, _) = crate::setpat::extract(&sh, l);
                    if w > 0 {
                        lines.push(format!("  example: {}", m.iter().map(|(k, v)| format!("{k}={}", match v { Value::String(s) => s.clone(), o => o.to_string() })).collect::<Vec<_>>().join(" ")));
                    }
                }
            }
        }
        if g.fmt.is_none() && (g.spec.is_none() || g.rate < 0.8) {
            exit = 2;
            lines.push(format!("  below 80%: check the template, edit it, then: aix put <name> {} {}", if inp.src == "stdin" { "-" } else { "<file>" }, if g.shown.is_empty() { "--pattern '<template>'" } else { &g.shown }));
        } else {
            lines.push(format!("  use it: aix put <name> {} {}", if inp.src == "stdin" { "-" } else { "<file>" }, if g.shown.is_empty() { "--pattern auto" } else { &g.shown }));
        }
    }
    Ok(PutOut { lines, exit })
}

/// A set (`@name[/item]`) as the input of a put: its stored (already redacted) lines, read before the put replaces it.
fn set_input(ctx: &Ctx, tok: &str) -> Result<Vec<sets::Input>> {
    let t = resolve(ctx, tok)?;
    let st = &ctx.stores[t.store];
    let mut v = vec![];
    for it in &t.items {
        let text = sets::read_all(&st.conn, it.id)?;
        v.push(sets::Input { name: it.item.clone(), src: format!("@{}/{}", it.set, it.item), reader: Box::new(std::io::Cursor::new(text.into_bytes())) });
    }
    Ok(v)
}

/// `put` from MCP: the content arrives as `text` (bounded); paths are CLI-only.
pub fn mcp_put(repo: &Path, dir: &Path, args: &str, text: &str) -> Result<PutOut> {
    let toks = crate::query::shell_split(args);
    let p = parse_put(&toks)?;
    if p.help {
        return Ok(PutOut { lines: PUT_HELP.lines().map(str::to_string).collect(), exit: 0 });
    }
    let ctx = Ctx::open(repo, dir, None, false);
    let mut inputs = vec![];
    for x in &p.paths {
        if x.starts_with('@') && ctx.is_set_token(x) {
            inputs.extend(set_input(&ctx, x)?);
        } else {
            bail!("put from MCP takes the content in `text` (paths are read by the CLI only: aix put {} <path>)", p.name);
        }
    }
    if text.len() > sets::MCP_TEXT_MAX {
        bail!("put: text is {} (MCP limit {}): pipe it from a shell instead (cmd | aix put {} -)", crate::logs::human(text.len() as i64), crate::logs::human(sets::MCP_TEXT_MAX as i64), p.name);
    }
    if inputs.is_empty() || !text.is_empty() {
        inputs.push(sets::Input { name: p.o.item.clone().unwrap_or_else(|| "text".into()), src: "mcp".into(), reader: Box::new(std::io::Cursor::new(text.as_bytes().to_vec())) });
    }
    if p.guess {
        return guess_report(inputs, p.o.keep_ips);
    }
    let d = if p.global { sets::global_dir().ok_or_else(|| anyhow!("no user data dir (HOME unset)"))? } else { dir.to_path_buf() };
    let st = sets::open(&d, p.global, true)?.ok_or_else(|| anyhow!("cannot open the set store"))?;
    let r = sets::put(&st, &p.name, inputs, &p.o)?;
    Ok(PutOut { lines: put_report(&p.name, p.global, &r), exit: if r.low_conf.is_some() { 2 } else { 0 } })
}

// ---- dispatch --------------------------------------------------------------------------------------------------------------

/// Should `cmd args` be answered from data sets? (a set verb, or an argument naming an existing set)
pub fn wants(ctx: &Ctx, cmd: &str, args: &[String]) -> bool {
    if matches!(cmd, "sets" | "put") {
        return true;
    }
    if cmd == "pipe" || cmd == "batch" {
        return false; // pipe.rs runs pipes and sequences; each stage naming a set comes back here
    }
    if !SET_CMDS.contains(&cmd) {
        return false;
    }
    if cmd == "sql" {
        return args.iter().any(|a| Regex::new(r"@([A-Za-z0-9][A-Za-z0-9_.-]*)").unwrap().captures_iter(a).any(|c| ctx.find_set(c[1].trim_end_matches('.')).is_some()));
    }
    // grep: the pattern position is not a target (`aix grep @Transactional`)
    let skip_first = cmd == "grep" && !args.iter().any(|a| a == "-e" || a.starts_with("--regexp"));
    let mut first_pos = true;
    let mut prev = "";
    for a in args {
        let is_val = matches!(prev, "-e" | "-A" | "-B" | "-C" | "-m" | "--where" | "--match" | "--not" | "--re");
        if !a.starts_with('-') && !is_val {
            if skip_first && first_pos {
                first_pos = false;
                prev = a;
                continue;
            }
            first_pos = false;
        }
        if a.starts_with('@') && ctx.is_set_token(a) {
            return true;
        }
        prev = a;
    }
    false
}


fn alias(cmd: &str) -> &str {
    match cmd {
        "ls" => "files",
        "cat" => "code",
        c => c,
    }
}

/// One stage over the sets: `input` = rows from the previous stage (None for a source).
fn stage(ctx: &mut Ctx, cmd: &str, args: &[String], input: Option<&[SRow]>, cap: usize, allow_write: bool) -> Result<Res> {
    let cmd = alias(cmd);
    match cmd {
        "grep" => {
            let g = parse_grep(args)?;
            if let Some(inp) = input {
                let mt = Matcher::new(&g.pats, g.i, g.w, g.x, g.fixed, g.v)?;
                let mut rows = vec![];
                for r in inp.iter().filter(|r| is_row(r)) {
                    let hay = r.m.as_deref().unwrap_or(&r.text);
                    if mt.hit(hay) {
                        if g.o && !g.v {
                            for (s, e) in mt.find_all(hay) {
                                if e > s {
                                    rows.push(SRow { m: Some(hay[s..e].to_string()), text: hay[s..e].to_string(), ..r.clone() });
                                }
                            }
                        } else {
                            rows.push(r.clone());
                        }
                    }
                }
                if g.c {
                    let n = rows.len();
                    return Ok(Res::lines(String::new(), vec![n.to_string()]));
                }
                return Ok(Res::rows(format!("{} of {} rows match", rows.len(), inp.len()), rows, cap));
            }
            if g.targets.is_empty() {
                bail!("grep on data sets: name one (@set) after the regex");
            }
            let (rows, nmatch, scanned, emitted) = grep_targets(ctx, &g, if g.c || g.l || g.big_l { usize::MAX } else { cap })?;
            let title = format!("{nmatch} matching lines in {} ({scanned} lines searched)", g.targets.join(" "));
            let mut r = Res::rows(title, rows, 50);
            if g.c || g.l || g.big_l {
                r.exit = if nmatch > 0 || g.big_l && matches!(&r.body, Body::Rows(v) if !v.is_empty()) { 0 } else { 1 };
            } else {
                r.exit = if nmatch > 0 { 0 } else { 1 };
                if g.o || g.a > 0 || g.b > 0 {
                    // the cap was applied while scanning; the footer counts what was cut
                    r.total = Some(emitted);
                } else {
                    pad_total(&mut r, nmatch);
                }
            }
            Ok(r)
        }
        "code" if input.is_some() => code_rows(ctx, input.unwrap_or(&[])),
        "sed" => {
            // `sed -n 'A,Bp' @set` / `sed -n Np @set`: the line range of the set (as `code @set:A-B`)
            let re = Regex::new(r"^(\d+)(?:,(\d+))?p$").unwrap();
            let (mut range, mut tgt, mut quiet) = (None, None, false);
            for a in args {
                if a == "-n" {
                    quiet = true;
                } else if let Some(c) = re.captures(a) {
                    range = Some(format!("{}-{}", &c[1], c.get(2).map_or(&c[1], |m| m.as_str())));
                } else if a.starts_with('@') {
                    tgt = Some(a.clone());
                } else {
                    bail!("sed on a data set: only sed -n 'Np' / -n 'A,Bp' @set is supported (aix code @set:A-B; aix grep RE @set)");
                }
            }
            match (quiet, range, tgt) {
                (true, Some(r), Some(t)) => code_cmd(ctx, "code", &[format!("{t}:{r}")], None),
                _ => bail!("sed on a data set: only sed -n 'Np' / -n 'A,Bp' @set is supported (aix code @set:A-B; aix grep RE @set)"),
            }
        }
        "code" | "head" | "tail" => code_cmd(ctx, cmd, args, input),
        "files" => files_cmd(ctx, args, input),
        "filter" => filter_cmd(ctx, args, input, cap),
        "count" => count_cmd(ctx, args, input),
        "outline" => outline_cmd(ctx, args),
        "find" | "ask" => find_cmd(ctx, cmd, args),
        "sql" => sql_cmd(ctx, args, cap),
        "sets" => sets_cmd(ctx, args, allow_write),
        "put" => bail!("put inside a pipe or sequence is not supported: run `cmd | aix put <name> -` on its own"),
        other => bail!("{other} cannot read data-set rows (stages over @set rows: grep, count, head, tail, code, files, filter)"),
    }
}

/// `code -` over set rows: a stack frame in the row that resolves to a repo file shows that repo code; any other row
/// shows its cited lines with 3 lines of context.
fn code_rows(ctx: &mut Ctx, rows: &[SRow]) -> Result<Res> {
    let mut lines = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut shown = 0;
    let mut cut = 0;
    for r in rows.iter().filter(|r| r.sep == ':' || r.sep == ' ') {
        let frames = aix_extract::logparse::frames(&r.text, 3);
        let mut done = false;
        for f in frames {
            let file = {
                let ix = match ctx.index() {
                    Ok(ix) => ix,
                    Err(_) => break,
                };
                crate::logq::resolve_frame_file(ix, &f)
            };
            if let Some(file) = file {
                let key = format!("{file}:{}", f.line);
                done = true;
                if !seen.insert(key.clone()) {
                    break;
                }
                if shown >= 10 {
                    cut += 1;
                    break;
                }
                shown += 1;
                let ix = ctx.index()?;
                let o = crate::Opts { limit: 20, no_refresh: true, ..Default::default() };
                let out = crate::run(ix, "code", &format!("{file}:{}-{}", (f.line - 8).max(1), f.line + 8), &o)?;
                lines.push(format!("{}:{} -> {key} ({})", r.cite, r.n, f.func));
                for l in out.lines {
                    lines.push(format!("  {l}"));
                }
                break;
            }
        }
        if done {
            continue;
        }
        let Some((s, id)) = r.src else { continue };
        let key = format!("{}:{}", r.cite, r.n);
        if !seen.insert(key) {
            continue;
        }
        if shown >= 10 {
            cut += 1;
            continue;
        }
        shown += 1;
        lines.push(format!("== {}:{}-{}", r.cite, (r.n - 3).max(1), r.n + 3));
        scan(&ctx.stores[s], id, (r.n - 3).max(1), r.n + 3, &mut |n, l| {
            lines.push(format!("{n}{}{l}", if n == r.n { ": " } else { "  " }));
            true
        })?;
    }
    let mut res = Res::lines(format!("code for {shown} row(s)"), lines);
    res.default_cap = usize::MAX;
    if cut > 0 {
        res.notes.push(format!("{cut} more rows not shown (10 per call): narrow the grep"));
    }
    Ok(res)
}

/// Run one command line (possibly a pipeline / sequence) against the sets. `argv` is the command and its arguments as
/// typed; `cli` allows unbounded output and paths in `put`.
pub fn run(ctx: &mut Ctx, cmd: &str, argv: &[String], json_hits: bool, allow_write: bool) -> Out {
    match run_inner(ctx, cmd, argv, json_hits, allow_write) {
        Ok(o) => o,
        Err(e) => {
            let mut out = Out::new(20);
            out.fail_usage(format!("aix: {e:#}"));
            out
        }
    }
}

fn run_inner(ctx: &mut Ctx, cmd: &str, argv: &[String], json_hits: bool, allow_write: bool) -> Result<Out> {
    let mut args = argv.to_vec();
    let mut oo = take_out_opts(&mut args)?;
    if oo.head.is_none() {
        oo.head = ctx.limit;
    }
    let mut full: Vec<String> = vec![cmd.to_string()];
    full.extend(argv.iter().cloned());
    let cap_for = |oo: &OutOpts, def: usize| -> usize {
        let c = match oo.head {
            Some(0) => usize::MAX,
            Some(n) => n,
            None => def,
        };
        c.saturating_add(oo.offset)
    };
    let cap = cap_for(&oo, 50);
    let res = stage(ctx, cmd, &args, None, cap, allow_write)?;
    let mut out = render(res, &oo, &full, ctx.cli, json_hits);
    if json_hits {
        out.v1 = None;
    }
    Ok(out)
}


/// `put` from the CLI: paths, globs, sets (`@name`), or stdin (`-`, or no path with piped stdin).
pub fn cli_put(ctx: &Ctx, args: &[String], stdin_is_tty: bool) -> Result<PutOut> {
    let p = parse_put(args)?;
    if p.help {
        return Ok(PutOut { lines: PUT_HELP.lines().map(str::to_string).collect(), exit: 0 });
    }
    let mut inputs: Vec<sets::Input> = vec![];
    let mut errs = vec![];
    for raw in &p.paths {
        if raw.starts_with('@') && ctx.is_set_token(raw) {
            inputs.extend(set_input(ctx, raw)?);
            continue;
        }
        let list = sets::expand_glob(raw);
        if list.is_empty() {
            errs.push(format!("{raw}: no file matches"));
        }
        for path in list {
            match sets::open_input(&path, &ctx.repo, p.allow_dot) {
                Ok(i) => inputs.push(i),
                Err(e) => errs.push(e.to_string()),
            }
        }
    }
    if p.stdin || (p.paths.is_empty() && !stdin_is_tty) {
        let mut r = std::io::BufReader::with_capacity(1 << 20, std::io::stdin());
        crate::sys::skip_stdin_bom(&mut r);
        inputs.push(sets::Input { name: p.o.item.clone().unwrap_or_else(|| "stdin".into()), src: "stdin".into(), reader: Box::new(r) });
    }
    if inputs.is_empty() {
        if !errs.is_empty() {
            bail!("{}", errs.join("; "));
        }
        bail!("put {}: nothing to read (give files, or pipe data in: cmd 2>&1 | aix put {} -)", p.name, p.name);
    }
    if p.guess {
        let mut g = guess_report(inputs, p.o.keep_ips)?;
        for e in errs {
            g.lines.insert(0, format!("skipped: {e}"));
        }
        return Ok(g);
    }
    let d = if p.global { sets::global_dir().ok_or_else(|| anyhow!("no user data dir (HOME unset)"))? } else { ctx.dir.clone() };
    if !p.global {
        ensure_aix_dir(&ctx.repo, &d)?;
    }
    let st = sets::open(&d, p.global, true)?.ok_or_else(|| anyhow!("cannot open the set store"))?;
    let r = sets::put(&st, &p.name, inputs, &p.o)?;
    let mut v = put_report(&p.name, p.global, &r);
    for e in errs {
        v.insert(1, format!("skipped: {e}"));
    }
    Ok(PutOut { lines: v, exit: if r.low_conf.is_some() { 2 } else { 0 } })
}

/// `<repo>/.aix` with its `*` .gitignore (as `Index::open` makes it), so a set is never committed.
fn ensure_aix_dir(repo: &Path, dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    if dir == repo.join(".aix") {
        crate::sys::private_dir(&mut std::fs::DirBuilder::new()).create(dir)?;
        std::fs::write(dir.join(".gitignore"), "# aix index (local cache)\n*\n")?;
        Ok(())
    } else {
        bail!("{}: directory does not exist", dir.display())
    }
}

/// Exit status for a sets answer.
pub fn status(out: &Out) -> i32 {
    if out.error {
        2
    } else {
        out.exit_code.unwrap_or(0)
    }
}

#[allow(dead_code)]
fn _unused(_: BTreeMap<i32, i32>) {}

/// A data row (not a `--` separator).
fn is_row(r: &SRow) -> bool {
    matches!(r.sep, ':' | '-' | ' ')
}

// ---- the shared row layer (rows.rs / pipe.rs) -------------------------------------------------------------------------

/// The data-set store as a row source for rows.rs: `@name[/item][:A-B]` read as `Hit` rows (`@cite:N:text`) whose
/// named fields (the item's records) travel in Meta.fields, so count / dedup / filter stages in pipe.rs key on them.
pub struct StoreSource;

fn ctx_for(ix: &crate::Index) -> Option<Ctx> {
    let dir = ix.db_path.parent()?.to_path_buf();
    if !any_store(&dir) {
        return None;
    }
    Some(Ctx::open(&ix.repo, &dir, Some(&ix.db_path), false))
}

fn rec_fields(st: &SetStore, item: i64, n: i64) -> Vec<(String, String)> {
    let j: Option<String> = st.conn.query_row("SELECT j FROM recs WHERE id=?1", params![rid(item, n)], |r| r.get(0)).ok();
    let mut out = vec![];
    if let Some(v) = j.and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok()) {
        sets::flatten(&v, "", &mut out);
    }
    out
}

impl crate::rows::SetSource for StoreSource {
    fn rows(&self, ix: &crate::Index, spec: &str) -> Option<Result<crate::rows::Rows, String>> {
        let ctx = ctx_for(ix)?;
        if !ctx.is_set_token(spec) {
            return None;
        }
        let t = match resolve(&ctx, spec) {
            Ok(t) => t,
            Err(e) => return Some(Err(e.to_string())),
        };
        let st = &ctx.stores[t.store];
        let mut rows = crate::rows::Rows::default();
        let mut bytes = 0usize;
        for it in &t.items {
            let (a, b) = match t.range {
                Some((a, b)) => (a, b.unwrap_or(it.lines)),
                None => (1, it.lines),
            };
            let cite = it.cite(t.single);
            let mut lines: Vec<(i64, String)> = vec![];
            let _ = scan(st, it.id, a, b, &mut |n, text| {
                bytes += text.len() + 1;
                lines.push((n, text.to_string()));
                bytes <= crate::rows::MAX_INPUT
            });
            for (n, text) in lines {
                let fields = if it.recs > 0 { rec_fields(st, it.id, n) } else { vec![] };
                rows.push(
                    crate::rows::Row::Hit { path: cite.clone(), line: n as usize, text },
                    crate::rows::Meta { kind: "set".into(), fields, ..Default::default() },
                );
            }
            if bytes > crate::rows::MAX_INPUT {
                rows.truncated = true;
                break;
            }
        }
        rows.bytes = bytes;
        Some(Ok(rows))
    }
    fn fields(&self, ix: &crate::Index, cite: &str, line: usize) -> Option<Vec<(String, String)>> {
        let ctx = ctx_for(ix)?;
        let t = resolve(&ctx, cite).ok()?;
        let it = t.items.first()?;
        (it.recs > 0).then(|| rec_fields(&ctx.stores[t.store], it.id, line as i64))
    }
}

/// Register the store with rows.rs (once per process).
pub fn register() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| crate::rows::register_source(Box::new(StoreSource)));
}

/// Does `tok` name an existing data set of this index's store (`@gate`, `@gate/item:1-9`)?
/// `grep X @name` naming no stored set and no repo path: the `@name` it would search (the caller refuses it, as
/// count and files do, instead of searching the repo).
pub fn unknown_grep_set(ix: &crate::Index, args: &[String]) -> Option<String> {
    let skip_first = !args.iter().any(|a| a == "-e" || a.starts_with("--regexp") || a == "-f");
    let mut first_pos = true;
    let mut prev = "";
    let ctx = ctx_for(ix);
    for a in args {
        // `-x` is grep's whole-line flag here (`grep -x ab @set`): the word after it is the pattern, not a value
        let is_val = matches!(prev, "-e" | "-A" | "-B" | "-C" | "-m" | "-f" | "--in" | "--exclude" | "--glob" | "--include" | "--group-by" | "--head" | "--width" | "--per-page" | "--page" | "--offset" | "--max-count" | "--not" | "--where" | "--match" | "--re");
        let pos = !a.starts_with('-') && !is_val;
        if pos && skip_first && first_pos {
            first_pos = false;
            prev = a;
            continue;
        }
        if pos {
            first_pos = false;
            if crate::rows::is_set_ref(a) && !a.contains('/') && !ix.repo.join(a).exists() && !ctx.as_ref().is_some_and(|c| c.is_set_token(a)) {
                return Some(a.clone());
            }
        }
        prev = a;
    }
    None
}

pub fn is_set_arg(ix: &crate::Index, tok: &str) -> bool {
    ctx_for(ix).is_some_and(|c| c.is_set_token(tok))
}

/// A pipe.rs consumer stage fed rows that come from a data set (`grep X @gate | code -`): the set store reads them
/// (code: the repo frames they name, else their lines; files: the items). None when no input row is a set row, so the
/// usual consumer runs; Err for a command that cannot read set rows.
pub fn consume_rows(ix: &crate::Index, cmd: &str, args: &[String], rows: &crate::rows::Rows) -> Option<std::result::Result<Out, String>> {
    let set_row = |r: &crate::rows::Row| r.path().is_some_and(crate::rows::is_set_ref);
    if !rows.rows.iter().any(set_row) {
        return None;
    }
    let mut ctx = ctx_for(ix)?;
    let cmd = alias(cmd);
    if !matches!(cmd, "code" | "files") {
        return Some(Err(format!("{cmd} cannot read data-set rows (stages over @set rows: grep, count, dedup, filter, head, tail, sort, uniq, cut, code, files)")));
    }
    let mut srows: Vec<SRow> = vec![];
    for (r, _) in rows.iter() {
        if let crate::rows::Row::Hit { path, line, text } = r {
            if let Ok(t) = resolve(&ctx, path) {
                if let Some(it) = t.items.first() {
                    srows.push(SRow { cite: path.clone(), n: *line as i64, sep: ':', text: text.clone(), src: Some((t.store, it.id)), m: None });
                }
            }
        }
    }
    let mut a: Vec<String> = args.iter().filter(|a| *a != "-").cloned().collect();
    let oo = match take_out_opts(&mut a) {
        Ok(o) => o,
        Err(e) => return Some(Err(e.to_string())),
    };
    let res = match stage(&mut ctx, cmd, &a, Some(&srows), 50, false) {
        Ok(r) => r,
        Err(e) => return Some(Err(e.to_string())),
    };
    let mut full = vec![cmd.to_string()];
    full.extend(a);
    Some(Ok(render(res, &oo, &full, ctx.cli, false)))
}
