//! Shell steering for the PreToolUse hook: a small shell lexer (POSIX, plus PowerShell and cmd.exe dialects after
//! `powershell -Command` / `pwsh -c` / `cmd /c` unwrapping), and ONE translation table from what an agent typed to the
//! aix line that answers it. Every pipeline of a compound command is evaluated; the hook turns the results into one
//! combined hint (or, for proven-identical reads, an answer; see `hookans`). `aix hook classify` uses the same code,
//! so the missed-opportunity metric and the steering cannot drift apart.
//!
//! Rules: suggest only when every flag is understood and every target is an indexed repo path; anything else is
//! silent with a reason (outside the repo, not indexed, a `$var`, stdin data, an unknown flag, a write).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;

// ------------------------------------------------------------------------------------------------ the table

/// Shell intent -> aix line. `{X}` is a scalar, `{XS}` a list that may expand to nothing; ` | ` separates in-call
/// stages. Keep this the single place to adjust a suggestion's shape.
pub const TABLE: &[(&str, &str)] = &[
    ("grep", "grep {FLAGS} {PAT} {PATHS} {MODS}"),
    ("grep|wc-l", "grep {FLAGS} -c --total {PAT} {PATHS}"),
    ("grep-l|wc-l", "grep {FLAGS} {PAT} {PATHS} | count"),
    ("grep|grep-v", "grep {FLAGS} {PAT} {PATHS} --not {PAT2} {MODS}"),
    ("grep|grep", "grep {FLAGS} {PAT} {PATHS} --and {PAT2} {MODS}"),
    ("grep-o|sort|uniq-c", "grep {FLAGS} {PAT} {PATHS} --count-by match {MODS}"),
    ("grep|cut-f1|sort-u", "grep -l {FLAGS} {PAT} {PATHS} {MODS}"),
    ("grep|cut-f1|uniq-c", "grep -c {FLAGS} {PAT} {PATHS} {MODS}"),
    // repeated rows: first-seen dedupe (awk '!seen[$0]++' exactly; sort -u as a set), counts per distinct row
    ("grep|dedup", "grep {FLAGS} {PAT} {PATHS} --dedup {MODS}"),
    ("grep|sort|uniq-c", "grep {FLAGS} {PAT} {PATHS} | count by line"),
    ("grep-l|xargs", "grep {FLAGS} {PAT} {PATHS} | {XCMD} -"),
    ("grep-q", "grep {FLAGS} {PAT} {PATHS} --exists"),
    ("find", "files {ROOTS} {PREDS} {MODS}"),
    ("find|wc-l", "files {ROOTS} {PREDS} | count"),
    ("find|xargs", "files {ROOTS} {PREDS} | {XCMD} -"),
    ("find|xargs-grep", "grep {FLAGS} {PAT} {ROOTS} {INCL} {MODS}"),
    ("ls", "ls {PATHS} {MODS}"),
    ("ls-R", "files {PATHS} {MODS}"),
    ("ls|wc-l", "ls {PATHS} | count"),
    ("sed-range", "code {TARGETS} {MODS}"),
    ("head", "code {TARGETS} {MODS}"),
    ("tail", "code {TARGETS} {MODS}"),
    ("tail-n", "tail -n {N} {FILES} {MODS}"),
    ("cat", "cat {FILES} {MODS}"),
    ("wc-l", "files {FILES}"),
    ("test-f", "files {FILES} --exists"),
    ("stat", "files {FILES}"),
    ("diff", "diff {A} {B}"),
    // a cap or a clip on any of the above
    ("mod:head", "--head {N}"),
    ("mod:width", "--width {N}"),
];

fn template(intent: &str) -> &'static str {
    TABLE.iter().find(|r| r.0 == intent).map(|r| r.1).unwrap_or("")
}

// ------------------------------------------------------------------------------------------------ results

/// One argument of a suggested aix call. `raw` = a shell glob the shell must expand (emitted unquoted).
#[derive(Debug, Clone, PartialEq)]
pub struct Arg {
    pub s: String,
    pub raw: bool,
}
fn a(s: impl Into<String>) -> Arg {
    Arg { s: s.into(), raw: false }
}

/// A translation: aix in-call stages (argv after `aix`), a shell tail left as typed, and an optional short note.
#[derive(Debug, Clone, Default)]
pub struct Tr {
    pub stages: Vec<Vec<Arg>>,
    pub tail: Option<String>,
    pub note: Option<String>,
    /// a whole line that is not an aix argv (`cmd 2>&1 | aix put NAME -`)
    pub literal: Option<String>,
}

/// A read whose exact output the hook can produce itself (deny-with-answer candidates).
#[derive(Debug, Clone, PartialEq)]
pub enum ReadOp {
    /// `sed -n` print commands: inclusive line ranges, `usize::MAX` = `$`
    Sed { file: String, ranges: Vec<(usize, usize)> },
    Head { file: String, n: usize },
    Tail { file: String, n: usize },
    TailFrom { file: String, k: usize },
    Cat { files: Vec<String> },
    Echo(String),
    /// `grep [-nEFivc] RE F...` over indexed files (no -r): (repo path, the name as typed, printed when several)
    Grep { files: Vec<(String, String)>, filt: Filt },
    /// an exact read piped through pure text filters (`| grep -n RE | tail -1`, `| head -n N`, `| wc -l`)
    Piped { src: Box<ReadOp>, filters: Vec<Filt> },
}

/// A pure text filter the hook reproduces exactly (anything it cannot is never turned into one).
#[derive(Debug, Clone, PartialEq)]
pub enum Filt {
    /// `re` is regex-crate syntax already checked to read the same as GNU grep on ASCII text
    Grep { re: String, n: bool, v: bool, c: bool, i: bool },
    Head(usize),
    Tail(usize),
    TailFrom(usize),
    WcL,
}

impl ReadOp {
    /// Can this read exit non-zero with indexed, unchanged files (a final grep with no match)?
    pub fn may_fail(&self) -> bool {
        match self {
            ReadOp::Grep { .. } => true,
            ReadOp::Piped { filters, .. } => matches!(filters.last(), Some(Filt::Grep { .. })),
            _ => false,
        }
    }
}

/// The verdict on one pipeline.
#[derive(Debug, Clone, Default)]
pub struct Seg {
    /// normalised intent, e.g. `bash:grep-r|wc-l`, `ps:sls`, `cmd:findstr`
    pub intent: String,
    pub tr: Option<Tr>,
    /// why there is no translation (when `tr` is None): outside-repo, not-indexed, var, stdin, flag:<x>, no-counterpart, ...
    pub reason: String,
    pub read: Option<ReadOp>,
    /// an `aix` call itself
    pub is_aix: bool,
    /// a large data file outside the index read by a text tool: (absolute path, data-set name, the `@name` query)
    pub data: Option<(String, String, String)>,
    /// a recursive grep for one plain pattern (the symbol-lookup upgrade looks at it)
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub segs: Vec<Seg>,
    /// the whole command consists only of exact reads (ReadOps) without side effects
    pub reads: Option<Vec<ReadOp>>,
    pub bypass: bool,
    pub cwd_outside: bool,
    /// a `cd DIR` into an existing repo directory is part of the exact reads (it prints nothing; when the command is
    /// answered instead of run, the shell's directory does not change)
    pub cd: Option<String>,
    /// some pipeline is not a lookup the hook understands (a side effect, an unknown program): never denied
    pub other: bool,
}

// ------------------------------------------------------------------------------------------------ index probe

#[derive(Debug, Clone, Copy, Default)]
pub struct FileRow {
    pub lines: i64,
    pub bytes: i64,
    pub mtime_ns: i64,
}

/// What the translation needs from the index (a trait so tests and `classify` can stub it).
pub trait Probe {
    fn file(&self, rel: &str) -> Option<FileRow>;
    /// any indexed file under `rel/` ("" = the whole repo)
    fn dir_has(&self, rel: &str) -> bool;
    /// indexed paths under `rel/` (bounded)
    fn under(&self, rel: &str, max: usize) -> Vec<String>;
    /// a function/method of this name that something calls
    fn has_callers(&self, _name: &str) -> bool {
        false
    }
    /// `aix callers SYM` and the endpoints that reach it (`aix impact SYM`), as text; None when the index has no
    /// call site for it or the budget runs out
    fn callers_answer(&self, _sym: &str, _budget_ms: u128) -> Option<String> {
        None
    }
}

pub struct IxProbe<'a>(pub &'a aix_core::Index);

/// A probe over the files on disk, for a repo with no index yet: "would this be a lookup aix answers once it is
/// indexed?" (the hook then names the one-time index command, never a query that cannot answer yet).
pub struct DiskProbe(pub PathBuf);

impl Probe for DiskProbe {
    fn file(&self, rel: &str) -> Option<FileRow> {
        let m = std::fs::metadata(self.0.join(rel)).ok().filter(|m| m.is_file() && !rel.is_empty())?;
        // lines counted for an ordinary source file; a big one is estimated at ~40 bytes a line (a hook stays fast)
        let lines = if m.len() <= 1 << 20 {
            std::fs::read(self.0.join(rel)).map(|b| b.iter().filter(|c| **c == b'\n').count() as i64).unwrap_or(0)
        } else {
            m.len() as i64 / 40
        };
        Some(FileRow { lines, bytes: m.len() as i64, mtime_ns: 0 })
    }
    fn dir_has(&self, rel: &str) -> bool {
        !rel.starts_with(".git") && self.0.join(rel).is_dir()
    }
    fn under(&self, _rel: &str, _max: usize) -> Vec<String> {
        vec![]
    }
}

impl Probe for IxProbe<'_> {
    fn file(&self, rel: &str) -> Option<FileRow> {
        self.0
            .conn
            .query_row("SELECT lines, bytes, mtime_ns FROM files WHERE path=?", [rel], |r| {
                Ok(FileRow { lines: r.get::<_, Option<i64>>(0)?.unwrap_or(0), bytes: r.get::<_, Option<i64>>(1)?.unwrap_or(0), mtime_ns: r.get::<_, Option<i64>>(2)?.unwrap_or(0) })
            })
            .ok()
    }
    fn dir_has(&self, rel: &str) -> bool {
        if rel.is_empty() {
            return self.0.conn.query_row("SELECT EXISTS(SELECT 1 FROM files)", [], |r| r.get::<_, i64>(0)).unwrap_or(0) == 1;
        }
        let (lo, hi) = (format!("{rel}/"), format!("{rel}0"));
        self.0.conn.query_row("SELECT EXISTS(SELECT 1 FROM files WHERE path > ?1 AND path < ?2)", [&lo, &hi], |r| r.get::<_, i64>(0)).unwrap_or(0) == 1
    }
    fn under(&self, rel: &str, max: usize) -> Vec<String> {
        let (lo, hi) = if rel.is_empty() { (String::new(), "\u{10FFFF}".to_string()) } else { (format!("{rel}/"), format!("{rel}0")) };
        let Ok(mut st) = self.0.conn.prepare_cached("SELECT path FROM files WHERE path > ?1 AND path < ?2 ORDER BY path LIMIT ?3") else { return vec![] };
        st.query_map(aix_core::rusqlite::params![lo, hi, max as i64], |r| r.get::<_, String>(0)).map(|it| it.flatten().collect()).unwrap_or_default()
    }
    fn has_callers(&self, name: &str) -> bool {
        self.0
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM members m WHERE m.name=?1 AND m.kind IN ('method','function','ctor','component') AND EXISTS (SELECT 1 FROM call_edges e WHERE e.cname=?1 AND e.kind<>'field'))",
                [name],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            == 1
    }
    fn callers_answer(&self, sym: &str, budget_ms: u128) -> Option<String> {
        let t0 = std::time::Instant::now();
        let name = sym.rsplit('.').next().unwrap_or(sym);
        if !self.has_callers(name) {
            return None;
        }
        let mut out = aix_core::query::Out::new(20);
        aix_core::expert::callers(self.0, sym, &mut out);
        let text = out.text();
        // a usable answer: at least one call site row, nothing that reads as a miss
        let head = text.lines().next().unwrap_or("");
        if !head.starts_with("== callers of") || !head.contains("call site") || head.contains(": 0 call") || head.contains(": none") {
            return None;
        }
        let mut lines: Vec<String> = text.lines().filter(|l| !l.starts_with("(repo data")).map(str::to_string).collect();
        if t0.elapsed().as_millis() < budget_ms / 2 {
            let mut imp = aix_core::query::Out::new(20);
            aix_core::expert::impact(self.0, sym, &mut imp);
            let it = imp.text();
            let mut take = false;
            let mut eps = vec![];
            for l in it.lines() {
                if l.starts_with("endpoints reached") {
                    take = true;
                } else if take && !l.starts_with("  ") {
                    break;
                }
                if take {
                    eps.push(l.to_string());
                }
            }
            if eps.len() > 1 && eps.len() <= 31 {
                lines.push(format!("== endpoints that reach {sym} through any call chain (aix impact {sym}, depth<=3):"));
                lines.extend(eps.into_iter().skip(1));
            }
        }
        (t0.elapsed().as_millis() <= budget_ms).then(|| lines.join("\n") + "\n")
    }
}

// ------------------------------------------------------------------------------------------------ lexer

/// A shell word: its text after quote removal, whether it holds an expansion (`$x`, `$(..)`, backticks), and
/// whether an unquoted glob character is in it (the shell would expand it).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct W {
    pub s: String,
    pub var: bool,
    pub glob: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Stage {
    pub w: Vec<W>,
    /// output redirected to a file (a write)
    pub writes: bool,
    /// stdin from a file (`< F`), or "-" for a here-doc / here-string
    pub stdin: Option<W>,
    /// leading `VAR=value` assignments
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Pipeline {
    pub stages: Vec<Stage>,
    /// the operator after this pipeline (`;`, `&&`, `||`, `&`, newline, parenthesis, or "" at the end)
    pub sep: String,
}

#[derive(Debug)]
enum Tok {
    W(W),
    Op(String),
    Redir(String, W),
}

/// Drop here-document bodies (`<<EOF ... EOF`): their lines are data for a program, not commands.
pub fn strip_heredocs(cmd: &str) -> String {
    static HEREDOC: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?"#).unwrap());
    let mut out = String::with_capacity(cmd.len());
    let mut end: Option<String> = None;
    for line in cmd.lines() {
        if let Some(tag) = &end {
            if line.trim() == tag {
                end = None;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
        end = HEREDOC.captures(line).map(|c| c[1].to_string());
    }
    out
}

#[allow(unused_assignments)]
fn lex(cmd: &str) -> Vec<Tok> {
    let mut toks = vec![];
    let mut w = W::default();
    let mut in_word = false;
    let mut redir: Option<String> = None;
    let c: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    macro_rules! flush {
        () => {
            if in_word {
                let word = std::mem::take(&mut w);
                match redir.take() {
                    Some(op) => toks.push(Tok::Redir(op, word)),
                    None => toks.push(Tok::W(word)),
                }
                in_word = false;
            }
        };
    }
    // read a $( ... ) / ` ... ` body (balanced, quotes skipped roughly) and return the index after it
    fn skip_subst(c: &[char], mut i: usize, open: char, close: char) -> usize {
        let mut depth = 1;
        while i < c.len() {
            match c[i] {
                '\'' => {
                    i += 1;
                    while i < c.len() && c[i] != '\'' {
                        i += 1;
                    }
                }
                '\\' => i += 1,
                x if x == close && open != close => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                x if x == close => return i + 1,
                x if x == open => depth += 1,
                _ => {}
            }
            i += 1;
        }
        c.len()
    }
    while i < c.len() {
        let ch = c[i];
        match ch {
            '\n' => {
                flush!();
                toks.push(Tok::Op("\n".into()));
                i += 1;
            }
            x if x.is_whitespace() => {
                flush!();
                i += 1;
            }
            '#' if !in_word => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '\'' => {
                in_word = true;
                i += 1;
                while i < c.len() && c[i] != '\'' {
                    w.s.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                in_word = true;
                i += 1;
                while i < c.len() && c[i] != '"' {
                    match c[i] {
                        '\\' if i + 1 < c.len() && matches!(c[i + 1], '"' | '\\' | '$' | '`') => {
                            w.s.push(c[i + 1]);
                            i += 2;
                            continue;
                        }
                        '$' if i + 1 < c.len() && (c[i + 1].is_alphanumeric() || matches!(c[i + 1], '_' | '{' | '(' | '@' | '*' | '#' | '?')) => {
                            w.var = true;
                            if c[i + 1] == '(' {
                                let e = skip_subst(&c, i + 2, '(', ')');
                                w.s.extend(&c[i..e]);
                                i = e;
                                continue;
                            }
                        }
                        '`' => {
                            w.var = true;
                            let e = skip_subst(&c, i + 1, '`', '`');
                            w.s.extend(&c[i..e]);
                            i = e;
                            continue;
                        }
                        _ => {}
                    }
                    w.s.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '\\' => {
                in_word = true;
                if i + 1 < c.len() && c[i + 1] != '\n' {
                    w.s.push(c[i + 1]);
                }
                i += 2;
            }
            '$' if i + 1 < c.len() && (c[i + 1].is_alphanumeric() || matches!(c[i + 1], '_' | '{' | '(' | '@' | '*' | '#' | '?' | '!')) => {
                in_word = true;
                w.var = true;
                let e = match c[i + 1] {
                    '(' => skip_subst(&c, i + 2, '(', ')'),
                    '{' => skip_subst(&c, i + 2, '{', '}'),
                    _ => {
                        let mut e = i + 2;
                        while e < c.len() && (c[e].is_alphanumeric() || c[e] == '_') && !matches!(c[i + 1], '@' | '*' | '#' | '?' | '!') {
                            e += 1;
                        }
                        e
                    }
                };
                w.s.extend(&c[i..e]);
                i = e;
            }
            '`' => {
                in_word = true;
                w.var = true;
                let e = skip_subst(&c, i + 1, '`', '`');
                w.s.extend(&c[i..e]);
                i = e;
            }
            ';' => {
                flush!();
                toks.push(Tok::Op(";".into()));
                i += if c.get(i + 1) == Some(&';') { 2 } else { 1 };
            }
            '&' if c.get(i + 1) == Some(&'&') => {
                flush!();
                toks.push(Tok::Op("&&".into()));
                i += 2;
            }
            '&' if c.get(i + 1) == Some(&'>') => {
                flush!();
                redir = Some("&>".into());
                i += 2;
                if c.get(i) == Some(&'>') {
                    i += 1;
                }
            }
            '&' => {
                flush!();
                toks.push(Tok::Op("&".into()));
                i += 1;
            }
            '|' if c.get(i + 1) == Some(&'|') => {
                flush!();
                toks.push(Tok::Op("||".into()));
                i += 2;
            }
            '|' => {
                flush!();
                toks.push(Tok::Op("|".into()));
                i += if c.get(i + 1) == Some(&'&') { 2 } else { 1 };
            }
            '(' | ')' => {
                flush!();
                toks.push(Tok::Op(ch.to_string()));
                i += 1;
            }
            '<' if c.get(i + 1) == Some(&'(') => {
                // process substitution: an opaque word
                in_word = true;
                w.var = true;
                let e = skip_subst(&c, i + 2, '(', ')');
                w.s.extend(&c[i..e]);
                i = e;
            }
            '>' | '<' => {
                // `2>` / `1>`: the digits are the fd, not a word
                if in_word && !w.s.is_empty() && w.s.chars().all(|d| d.is_ascii_digit()) && !w.var {
                    w = W::default();
                    in_word = false;
                } else {
                    flush!();
                }
                let mut op = String::new();
                while i < c.len() && matches!(c[i], '>' | '<' | '&' | '|') && op.len() < 3 {
                    op.push(c[i]);
                    i += 1;
                }
                if op.ends_with('&') {
                    let mut t = String::new();
                    while i < c.len() && (c[i].is_ascii_digit() || c[i] == '-') {
                        t.push(c[i]);
                        i += 1;
                    }
                    toks.push(Tok::Redir(op, W { s: format!("&{t}"), ..Default::default() }));
                } else {
                    redir = Some(op);
                }
            }
            _ => {
                in_word = true;
                if matches!(ch, '*' | '?' | '[') {
                    w.glob = true;
                }
                // brace expansion `{a,b}`
                if ch == '{' && c[i..].iter().take_while(|x| **x != '}' && !x.is_whitespace()).any(|x| *x == ',') {
                    w.glob = true;
                }
                w.s.push(ch);
                i += 1;
            }
        }
    }
    flush!();
    if let Some(op) = redir {
        toks.push(Tok::Redir(op, W::default()));
    }
    toks
}

/// Words that start or end a shell construct; the command after them is what runs.
const KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "fi", "done", "esac", "time"];

/// POSIX command line -> pipelines.
pub fn parse_posix(cmd: &str) -> Vec<Pipeline> {
    let mut out = vec![];
    let mut pl = Pipeline::default();
    let mut st = Stage::default();
    let finish_stage = |st: &mut Stage, pl: &mut Pipeline| {
        // keywords and assignments ahead of the program
        loop {
            match st.w.first() {
                Some(x) if KEYWORDS.contains(&x.s.as_str()) => {
                    st.w.remove(0);
                }
                Some(x) if !x.s.starts_with('-') && x.s.contains('=') && x.s.split('=').next().is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_')) => {
                    st.env.push(st.w.remove(0).s);
                }
                _ => break,
            }
        }
        while st.w.last().is_some_and(|x| matches!(x.s.as_str(), "}" | "fi" | "done")) {
            st.w.pop();
        }
        if !st.w.is_empty() || !st.env.is_empty() {
            pl.stages.push(std::mem::take(st));
        } else {
            *st = Stage::default();
        }
    };
    for t in lex(&strip_heredocs(cmd)) {
        match t {
            Tok::W(w) => st.w.push(w),
            Tok::Redir(op, target) => {
                if op.starts_with('<') {
                    st.stdin = Some(if op == "<" { target } else { W { s: "-".into(), ..Default::default() } });
                } else if !(target.s == "/dev/null" || target.s.starts_with('&') || target.s.is_empty()) {
                    st.writes = true;
                }
            }
            Tok::Op(op) if op == "|" => finish_stage(&mut st, &mut pl),
            Tok::Op(op) => {
                finish_stage(&mut st, &mut pl);
                if !pl.stages.is_empty() {
                    pl.sep = op;
                    out.push(std::mem::take(&mut pl));
                }
            }
        }
    }
    finish_stage(&mut st, &mut pl);
    if !pl.stages.is_empty() {
        out.push(pl);
    }
    out
}

/// PowerShell: `;` and `|` outside quotes; `'...'` (with `''`), `"..."` (backtick escapes, `$x` expands).
pub fn parse_ps(cmd: &str) -> Vec<Pipeline> {
    let mut out = vec![];
    let mut pl = Pipeline::default();
    let mut st = Stage::default();
    let mut w = W::default();
    let mut in_word = false;
    let c: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    let mut depth = 0; // ( ) groups stay inside one word: `(gc a)`
    while i < c.len() {
        let ch = c[i];
        if depth > 0 {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
            }
            w.s.push(ch);
            i += 1;
            continue;
        }
        match ch {
            '\'' => {
                in_word = true;
                i += 1;
                while i < c.len() {
                    if c[i] == '\'' {
                        if c.get(i + 1) == Some(&'\'') {
                            w.s.push('\'');
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    w.s.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                in_word = true;
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '`' && i + 1 < c.len() {
                        w.s.push(c[i + 1]);
                        i += 2;
                        continue;
                    }
                    if c[i] == '$' {
                        w.var = true;
                    }
                    w.s.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '(' => {
                in_word = true;
                depth = 1;
                w.s.push(ch);
                w.var = true;
                i += 1;
            }
            '$' => {
                in_word = true;
                w.var = true;
                w.s.push(ch);
                i += 1;
            }
            '{' | '}' => {
                in_word = true;
                w.var = true; // script blocks: opaque
                w.s.push(ch);
                i += 1;
            }
            ';' | '|' | '\n' => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                if !st.w.is_empty() {
                    pl.stages.push(std::mem::take(&mut st));
                }
                if ch != '|' && !pl.stages.is_empty() {
                    pl.sep = ";".into();
                    out.push(std::mem::take(&mut pl));
                }
                i += 1;
            }
            '>' => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                // `> $null` / `2>&1` are harmless, any other target is a write
                let mut j = i;
                while j < c.len() && matches!(c[j], '>' | '&' | '1' | '2') {
                    j += 1;
                }
                while j < c.len() && c[j] == ' ' {
                    j += 1;
                }
                let rest: String = c[j..].iter().take(5).collect();
                if !(c[i..j].iter().collect::<String>().contains('&') || rest.to_ascii_lowercase().starts_with("$null")) {
                    st.writes = true;
                }
                i = j;
                if rest.to_ascii_lowercase().starts_with("$null") {
                    i += 5;
                }
            }
            x if x.is_whitespace() => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                i += 1;
            }
            _ => {
                in_word = true;
                if matches!(ch, '*' | '?') {
                    w.glob = true;
                }
                w.s.push(ch);
                i += 1;
            }
        }
    }
    if in_word {
        st.w.push(w);
    }
    if !st.w.is_empty() {
        pl.stages.push(st);
    }
    if !pl.stages.is_empty() {
        out.push(pl);
    }
    out
}

/// cmd.exe: `&`, `&&`, `||` and `|` outside double quotes, `^` escapes.
pub fn parse_cmd(cmd: &str) -> Vec<Pipeline> {
    let mut out = vec![];
    let mut pl = Pipeline::default();
    let mut st = Stage::default();
    let mut w = W::default();
    let mut in_word = false;
    let c: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        match ch {
            '"' => {
                in_word = true;
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '%' {
                        w.var = true;
                    }
                    w.s.push(c[i]);
                    i += 1;
                }
                i += 1;
            }
            '^' => {
                in_word = true;
                if i + 1 < c.len() {
                    w.s.push(c[i + 1]);
                }
                i += 2;
            }
            '%' | '!' => {
                in_word = true;
                w.var = true;
                w.s.push(ch);
                i += 1;
            }
            '&' | '|' | '\n' => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                if !st.w.is_empty() {
                    pl.stages.push(std::mem::take(&mut st));
                }
                let dbl = c.get(i + 1) == Some(&ch);
                if (ch != '|' || dbl) && !pl.stages.is_empty() {
                    pl.sep = if dbl { format!("{ch}{ch}") } else { ch.to_string() };
                    out.push(std::mem::take(&mut pl));
                }
                i += if dbl { 2 } else { 1 };
            }
            '>' => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                let mut j = i;
                while j < c.len() && matches!(c[j], '>' | '&' | '1' | '2') {
                    j += 1;
                }
                while j < c.len() && c[j] == ' ' {
                    j += 1;
                }
                let rest: String = c[j..].iter().take(3).collect::<String>().to_ascii_lowercase();
                if !(c[i..j].iter().any(|x| *x == '&') || rest == "nul") {
                    st.writes = true;
                }
                i = if rest == "nul" { j + 3 } else { j };
            }
            x if x.is_whitespace() => {
                if in_word {
                    st.w.push(std::mem::take(&mut w));
                    in_word = false;
                }
                i += 1;
            }
            _ => {
                in_word = true;
                if matches!(ch, '*' | '?') {
                    w.glob = true;
                }
                w.s.push(ch);
                i += 1;
            }
        }
    }
    if in_word {
        st.w.push(w);
    }
    if !st.w.is_empty() {
        pl.stages.push(st);
    }
    if !pl.stages.is_empty() {
        out.push(pl);
    }
    out
}

// ------------------------------------------------------------------------------------------------ context

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Dialect {
    Posix,
    Ps,
    Cmd,
}

pub struct Cx<'a> {
    /// the repo root as given and canonical
    pub repo: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub probe: &'a dyn Probe,
    pub home: Option<String>,
}

impl Cx<'_> {
    pub fn new<'a>(repo: &Path, cwd: Option<&Path>, probe: &'a dyn Probe) -> Cx<'a> {
        let mut roots = vec![native(&repo.display().to_string())];
        let canon = aix_core::sys::canonicalize(&repo);
        if let Ok(c) = &canon {
            let c = native(&c.display().to_string());
            if !roots.contains(&c) {
                roots.push(c);
            }
        }
        let mut cx = Cx { repo: roots, cwd: Some(cwd.map(Path::to_path_buf).unwrap_or_else(|| repo.to_path_buf())), probe, home: aix_core::sys::home().and_then(|h| h.into_os_string().into_string().ok()) };
        // Windows: the project opened through another name for its folder (a subst drive, a junction, an 8.3 name);
        // the cwd's spelling of the root is one more root
        if let (true, Some(c), Ok(canon)) = (cfg!(windows), cwd, &canon) {
            let typed = lexical(&native(&c.display().to_string()));
            if cx.strip_repo(&typed).is_none() {
                if let Some(rel) = aix_core::sys::canonicalize(os_path(&typed)).ok().and_then(|r| cx.strip_repo(&native(&r.display().to_string()))) {
                    let segs: Vec<&str> = typed.split('/').collect();
                    let k = rel.split('/').filter(|s| !s.is_empty()).count();
                    let alias = segs[..segs.len().saturating_sub(k)].join("/");
                    if segs.len() > k + 1 && aix_core::sys::canonicalize(os_path(&alias)).is_ok_and(|a| aix_core::sys::same_path(&a, canon)) {
                        cx.repo.push(alias);
                    }
                }
            }
        }
        cx
    }

    /// The cwd relative to the repo ("" = the root), None when outside it or unknown.
    fn cwd_rel(&self) -> Option<String> {
        let c = native(&self.cwd.as_ref()?.display().to_string());
        self.strip_repo(&c)
    }

    fn strip_repo(&self, p: &str) -> Option<String> {
        for r in &self.repo {
            let r = r.trim_end_matches('/');
            if p == r || (cfg!(windows) && p.eq_ignore_ascii_case(r)) {
                return Some(String::new());
            }
            if let Some(rest) = p.strip_prefix(r).and_then(|x| x.strip_prefix('/')) {
                return Some(rest.trim_end_matches('/').to_string());
            }
            // Windows: case-insensitive drive paths
            if r.len() > 2 && p.len() > r.len() && p.is_char_boundary(r.len()) && p[..r.len()].eq_ignore_ascii_case(r) && p.as_bytes()[r.len()] == b'/' {
                return Some(p[r.len() + 1..].trim_end_matches('/').to_string());
            }
        }
        None
    }

    /// A path word -> repo-relative path, or the silent reason.
    pub fn rel(&self, w: &W, dialect: Dialect) -> Result<String, String> {
        if w.var {
            return Err("var".into());
        }
        let mut s = w.s.clone();
        // PowerShell and cmd spell C:\x; on Windows so do Claude Code's own tools (Read, Grep, Glob paths)
        if dialect != Dialect::Posix || cfg!(windows) {
            s = drive_slash(&s);
        }
        if let Some(h) = s.strip_prefix("~/") {
            s = format!("{}/{h}", native(self.home.as_deref().ok_or("var")?));
        } else if s == "~" {
            return Err("outside-repo".into());
        }
        let abs = if s.starts_with('/') {
            s
        } else {
            let Some(c) = &self.cwd else { return Err("cwd-unknown".into()) };
            format!("{}/{s}", native(&c.display().to_string()))
        };
        let norm = lexical(&abs);
        self.strip_repo(&norm).ok_or_else(|| "outside-repo".into())
    }

    /// A path in a suggestion: as typed when relative to a cwd inside the repo, else repo-relative.
    fn shown(&self, w: &W, rel: &str) -> Arg {
        let typed_ok = !native(&w.s).starts_with('/') && !w.s.starts_with('~') && !w.s.contains('\\') && self.cwd_rel().is_some();
        let s = if typed_ok { w.s.clone() } else if rel.is_empty() { ".".into() } else { rel.to_string() };
        Arg { s, raw: w.glob }
    }

    fn file_ok(&self, rel: &str) -> bool {
        self.probe.file(rel).is_some()
    }

    /// Is the target answerable: an indexed file, a directory with indexed files, or a glob over indexed files?
    fn target(&self, w: &W, dialect: Dialect) -> Result<(String, Arg), String> {
        let rel = self.rel(w, dialect)?;
        if is_log_path(&rel) {
            return Err("log".into());
        }
        if w.glob {
            let (dir, re) = glob_split(&rel).ok_or("glob")?;
            if self.probe.under(&dir, 20000).iter().any(|p| re.is_match(p)) {
                return Ok((rel.clone(), self.shown(w, &rel)));
            }
            return Err("not-indexed".into());
        }
        if self.file_ok(&rel) || self.probe.dir_has(&rel) {
            Ok((rel.clone(), self.shown(w, &rel)))
        } else {
            Err("not-indexed".into())
        }
    }
}

fn is_log_path(rel: &str) -> bool {
    rel.ends_with(".log") || rel.contains(".log.") || rel.starts_with(".aix/") || rel.starts_with(".git/") || rel == ".git"
}

/// `/a/./b/../c` -> `/a/c` without touching the filesystem.
/// A Windows path in the one spelling the hook compares: `C:\x`, `C:/x` and `\\?\C:\x` all become Git Bash's `/c/x`.
fn drive_slash(p: &str) -> String {
    let s = p.replace('\\', "/");
    let s = s.strip_prefix("//?/UNC/").map(|r| format!("//{r}")).unwrap_or(s);
    let s = s.strip_prefix("//?/").map(str::to_string).unwrap_or(s);
    match s.as_bytes() {
        [d, b':'] | [d, b':', b'/', ..] if d.is_ascii_alphabetic() => format!("/{}{}", (*d as char).to_ascii_lowercase(), &s[2..]),
        _ => s,
    }
}

/// `drive_slash` on Windows (roots, cwds and words then compare); other platforms: unchanged.
pub fn native(p: &str) -> String {
    if cfg!(windows) { drive_slash(p) } else { p.to_string() }
}

/// A path in any spelling (`/c/x`, `C:\x`, `C:/x`) as one the OS opens (`C:/x`); other platforms: unchanged.
pub fn os_path(p: &str) -> String {
    let p = native(p);
    match p.as_bytes() {
        [b'/', d] | [b'/', d, b'/', ..] if cfg!(windows) && d.is_ascii_alphabetic() => format!("{}:{}", (*d as char).to_ascii_uppercase(), if p.len() == 2 { "/" } else { &p[2..] }),
        _ => p.to_string(),
    }
}

/// An absolute path in any spelling, relative to `repo` ("" = the root, `/`-separated); None outside it. Windows paths
/// compare case-insensitively, and one through another name for the folder (a subst drive, a junction, an 8.3 name)
/// as what it resolves to.
pub fn repo_rel(repo: &Path, p: &str) -> Option<String> {
    let r = lexical(&native(&repo.display().to_string()));
    let r = r.trim_end_matches('/');
    let rel = |p: &str| -> Option<String> {
        let p = lexical(&native(p));
        if p == r || (cfg!(windows) && p.eq_ignore_ascii_case(r)) {
            return Some(String::new());
        }
        if let Some(rest) = p.strip_prefix(r).and_then(|x| x.strip_prefix('/')) {
            return Some(rest.to_string());
        }
        (cfg!(windows) && p.len() > r.len() && p.is_char_boundary(r.len()) && p[..r.len()].eq_ignore_ascii_case(r) && p.as_bytes()[r.len()] == b'/')
            .then(|| p[r.len() + 1..].to_string())
    };
    rel(p).or_else(|| if cfg!(windows) { rel(&aix_core::sys::canonicalize(os_path(p)).ok()?.display().to_string()) } else { None })
}

pub fn lexical(p: &str) -> String {
    let mut parts: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    // Windows: a UNC path keeps its `//host/share` head
    let head = if cfg!(windows) && p.starts_with("//") && !p.starts_with("///") { "//" } else { "/" };
    format!("{head}{}", parts.join("/"))
}

/// A glob (shell or ripgrep style) -> anchored regex over `/` paths. `**/` = any directories, `*` and `?` stay
/// inside one segment, `{a,b}` alternation, `[..]` classes.
pub fn glob_re(g: &str) -> Option<Regex> {
    let mut re = String::from("^");
    let c: Vec<char> = g.chars().collect();
    let mut i = 0;
    let mut brace = 0;
    while i < c.len() {
        match c[i] {
            '*' if c.get(i + 1) == Some(&'*') => {
                if c.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            '[' => {
                let end = c[i + 1..].iter().position(|x| *x == ']')? + i + 1;
                let mut body: String = c[i + 1..end].iter().collect();
                if let Some(b) = body.strip_prefix('!') {
                    body = format!("^{b}");
                }
                re.push('[');
                re.push_str(&body.replace('\\', "\\\\"));
                re.push(']');
                i = end + 1;
                continue;
            }
            '{' => {
                brace += 1;
                re.push_str("(?:");
            }
            '}' if brace > 0 => {
                brace -= 1;
                re.push(')');
            }
            ',' if brace > 0 => re.push('|'),
            ch => re.push_str(&regex::escape(&ch.to_string())),
        }
        i += 1;
    }
    if brace != 0 {
        return None;
    }
    re.push('$');
    Regex::new(&re).ok()
}

/// A repo-relative glob path -> (its literal directory prefix, a regex over full repo paths).
fn glob_split(rel: &str) -> Option<(String, Regex)> {
    let first = rel.find(['*', '?', '[', '{'])?;
    let dir = rel[..first].rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default();
    Some((dir, glob_re(rel)?))
}

// ------------------------------------------------------------------------------------------------ entry

/// Evaluate a whole Bash (or PowerShell-tool) command.
pub fn evaluate(cx: &mut Cx, cmd: &str, tool_dialect: Dialect) -> Verdict {
    let mut v = Verdict::default();
    let expanded = if tool_dialect == Dialect::Posix { expand_for(cmd) } else { None };
    let cmd = expanded.as_deref().unwrap_or(cmd);
    let pls = match tool_dialect {
        Dialect::Posix => parse_posix(cmd),
        Dialect::Ps => parse_ps(cmd),
        Dialect::Cmd => parse_cmd(cmd),
    };
    let mut reads: Option<Vec<ReadOp>> = Some(vec![]);
    walk(cx, &pls, tool_dialect, &mut v, &mut reads, 0);
    if v.segs.iter().any(|s| s.read.is_none()) || v.segs.is_empty() {
        reads = None;
    }
    v.reads = reads.filter(|r| !r.is_empty());
    v.cwd_outside = cx.cwd_rel().is_none();
    v
}

fn walk(cx: &mut Cx, pls: &[Pipeline], dialect: Dialect, v: &mut Verdict, reads: &mut Option<Vec<ReadOp>>, depth: usize) {
    for pl in pls {
        if pl.stages.iter().any(|s| s.env.iter().any(|e| e == "AIX_HOOK=off")) {
            v.bypass = true;
        }
        // anything but `;`/`&&`/end between exact reads makes the output depend on exit codes or job control
        if !matches!(pl.sep.as_str(), ";" | "&&" | "\n" | "") {
            *reads = None;
        }
        let st0 = &pl.stages[0];
        let prog = st0.w.first().map(|w| base(&w.s)).unwrap_or_default();
        // cd / pushd
        if dialect == Dialect::Posix && pl.stages.len() == 1 && matches!(prog.as_str(), "cd" | "pushd") {
            cx.cwd = match st0.w.get(1) {
                Some(w) if !w.var && w.s != "-" => {
                    let s = native(&w.s.replace("~", cx.home.as_deref().unwrap_or("~")));
                    let p = if s.starts_with('/') { s } else { format!("{}/{s}", cx.cwd.as_ref().map(|c| native(&c.display().to_string())).unwrap_or_default()) };
                    cx.cwd.as_ref().map(|_| PathBuf::from(lexical(&p))).or_else(|| p.starts_with('/').then(|| PathBuf::from(lexical(&p))))
                }
                _ => None,
            };
            // `cd DIR` into an existing directory inside the repo prints nothing and succeeds: the reads after it stay
            // exact (pushd prints the stack; CDPATH can make cd print the directory; `-` / a $var are unknown)
            let quiet_cd = prog == "cd"
                && st0.w.len() == 2
                && !st0.writes
                && st0.env.is_empty()
                && st0.stdin.is_none()
                && std::env::var("CDPATH").map_or(true, |c| c.is_empty())
                && cx.cwd_rel().is_some()
                && cx.cwd.as_ref().is_some_and(|c| Path::new(&os_path(&c.display().to_string())).is_dir());
            if quiet_cd {
                v.cd = cx.cwd_rel();
            } else {
                *reads = None;
            }
            continue;
        }
        if dialect != Dialect::Posix && pl.stages.len() == 1 && matches!(prog.to_ascii_lowercase().as_str(), "cd" | "set-location" | "sl" | "chdir" | "pushd") {
            *reads = None;
            cx.cwd = st0.w.iter().skip(1).find(|w| !w.s.starts_with('-') && !w.s.starts_with('/')).and_then(|w| cx.rel(w, dialect).ok()).map(|r| PathBuf::from(format!("{}/{r}", cx.repo[0])));
            continue;
        }
        // wrappers that carry another dialect or a nested shell
        if depth < 3 {
            if let Some((inner, d)) = unwrap_shell(st0, dialect) {
                if pl.stages.len() > 1 {
                    *reads = None;
                }
                let sub = match d {
                    Dialect::Posix => parse_posix(&inner),
                    Dialect::Ps => parse_ps(&inner),
                    Dialect::Cmd => parse_cmd(&inner),
                };
                walk(cx, &sub, d, v, reads, depth + 1);
                continue;
            }
        }
        let seg = match dialect {
            Dialect::Posix => posix(cx, pl),
            Dialect::Ps => ps(cx, pl),
            Dialect::Cmd => cmdexe(cx, pl),
        };
        let seg = seg.map(|mut s| {
            if s.tr.is_none() && !s.is_aix && matches!(s.reason.as_str(), "outside-repo" | "not-indexed" | "log" | "not-a-file") && dialect == Dialect::Posix {
                s.data = data_hint(cx, pl);
            }
            s
        });
        match seg {
            Some(s) => {
                // a piped read covers every stage of its pipeline; a grep that may find nothing ends a `&&` chain
                let covers = pl.stages.len() == 1 || matches!(s.read, Some(ReadOp::Piped { .. }));
                if s.read.is_none() || !covers || pl.stages.iter().any(|st| st.writes || !st.env.is_empty()) || (pl.sep == "&&" && s.read.as_ref().is_some_and(ReadOp::may_fail)) {
                    *reads = None;
                }
                if let (Some(r), Some(rd)) = (reads.as_mut(), s.read.clone()) {
                    r.push(rd);
                }
                v.segs.push(s);
            }
            None => {
                // a side-effecting or unrelated command: no exact answer for the whole command
                *reads = None;
                v.other = true;
            }
        }
    }
}

fn base(p: &str) -> String {
    let b = p.rsplit(['/', '\\']).next().unwrap_or(p);
    b.strip_suffix(".exe").unwrap_or(b).to_string()
}

/// `bash -c S`, `powershell -Command S`, `pwsh -c S`, `cmd /c S` -> (S, dialect).
fn unwrap_shell(st: &Stage, dialect: Dialect) -> Option<(String, Dialect)> {
    let w = &st.w;
    let p = base(&w.first()?.s).to_ascii_lowercase();
    match p.as_str() {
        "bash" | "sh" | "zsh" | "dash" if dialect == Dialect::Posix => {
            let i = w.iter().position(|x| x.s.starts_with('-') && !x.s.starts_with("--") && x.s.contains('c'))?;
            let s = w.get(i + 1)?;
            (!s.var).then(|| (s.s.clone(), Dialect::Posix))
        }
        "powershell" | "pwsh" => {
            let mut i = 1;
            while i < w.len() {
                let f = w[i].s.to_ascii_lowercase();
                if matches!(f.as_str(), "-command" | "-c" | "/c" | "-com") {
                    let rest: Vec<String> = w[i + 1..].iter().map(|x| x.s.clone()).collect();
                    return (!rest.is_empty()).then(|| (rest.join(" "), Dialect::Ps));
                }
                if matches!(f.as_str(), "-executionpolicy" | "-ep" | "-file" | "-f" | "-encodedcommand" | "-e" | "-ec") {
                    if f.starts_with("-e") && f != "-executionpolicy" && f != "-ep" {
                        return None; // encoded: opaque
                    }
                    i += 1;
                }
                i += 1;
            }
            None
        }
        "cmd" => {
            let i = w.iter().position(|x| matches!(x.s.to_ascii_lowercase().as_str(), "/c" | "/k" | "/s/c" | "/d/c"))?;
            let rest: Vec<String> = w[i + 1..].iter().map(|x| if x.s.contains([' ', '^', '&', '|', '<', '>']) { format!("\"{}\"", x.s) } else { x.s.clone() }).collect();
            // `cmd /c "type a b"`: one word is the whole command line
            if w.len() == i + 2 {
                return Some((w[i + 1].s.clone(), Dialect::Cmd));
            }
            (!rest.is_empty()).then(|| (rest.join(" "), Dialect::Cmd))
        }
        _ => None,
    }
}

fn silent(intent: &str, reason: impl Into<String>) -> Option<Seg> {
    Some(Seg { intent: intent.into(), reason: reason.into(), ..Default::default() })
}

/// The program word of a stage after transparent wrappers (`env`, `command`, `nice`, `timeout N`, `stdbuf`, `nohup`).
fn prog_at(st: &Stage) -> (String, usize) {
    let mut i = 0;
    while i < st.w.len() {
        let p = base(&st.w[i].s);
        match p.as_str() {
            "env" | "command" | "nohup" | "builtin" | "exec" => {
                i += 1;
                while i < st.w.len() && (st.w[i].s.contains('=') || st.w[i].s.starts_with('-')) {
                    i += 1;
                }
            }
            "nice" | "stdbuf" | "ionice" => {
                i += 1;
                while i < st.w.len() && st.w[i].s.starts_with('-') {
                    i += if st.w[i].s == "-n" { 2 } else { 1 };
                }
            }
            "time" => {
                i += 1;
                while i < st.w.len() && st.w[i].s.starts_with('-') {
                    i += if matches!(st.w[i].s.as_str(), "-f" | "-o" | "--format" | "--output") { 2 } else { 1 };
                }
            }
            "timeout" => {
                i += 1;
                while i < st.w.len() && st.w[i].s.starts_with('-') {
                    i += if matches!(st.w[i].s.as_str(), "-s" | "-k") { 2 } else { 1 };
                }
                i += 1; // the duration
            }
            _ => return (p, i),
        }
    }
    (String::new(), i)
}

const AIX_SUBS: &[&str] = &[
    "brief", "impact", "callers", "callees", "trace", "explain", "outline", "scope", "bugs", "qa", "feature", "text", "endpoint", "symbol", "script", "tasks", "history",
    "find", "ask", "route", "hints", "table", "code", "grep", "sql", "schema", "patterns", "howto", "files", "ls", "count", "filter", "cat", "head", "tail", "sed", "diff",
    "anchor", "stats", "card", "logs",
];

fn is_aix(st: &Stage) -> bool {
    let (p, i) = prog_at(st);
    // aix itself and its shipped scripts (aix-init, aix-refresh, aix-watch, with or without .sh)
    if p == "aix" || matches!(p.trim_end_matches(".sh"), "aix-init" | "aix-refresh" | "aix-watch") {
        return true;
    }
    // `$A grep ...`, `$AIX --repo . code ...`
    let w0 = st.w.get(i).map(|w| base(&w.s)).unwrap_or_default();
    if w0.starts_with('$') && w0.len() <= 12 {
        let mut j = i + 1;
        while j < st.w.len() && st.w[j].s.starts_with("--") {
            let flag_only = matches!(st.w[j].s.as_str(), "--json" | "--jsonl" | "--pretty" | "--no-refresh") || st.w[j].s.contains('=');
            j += if flag_only { 1 } else { 2 };
        }
        return st.w.get(j).is_some_and(|w| AIX_SUBS.contains(&w.s.as_str()));
    }
    false
}

/// Words of a stage from the program on.
fn words(st: &Stage) -> &[W] {
    let (_, i) = prog_at(st);
    &st.w[i.min(st.w.len())..]
}

/// Is this stage a pure text filter (safe to keep as a shell tail after an aix call)?
fn pure_filter(st: &Stage) -> bool {
    if st.writes {
        return false;
    }
    let (p, _) = prog_at(st);
    match p.as_str() {
        "grep" | "egrep" | "fgrep" | "head" | "tail" | "sort" | "uniq" | "cut" | "wc" | "tr" | "column" | "nl" | "cat" | "less" | "more" | "rg" | "jq" => true,
        "awk" | "gawk" | "mawk" => true,
        "sed" => !words(st).iter().any(|w| w.s.starts_with("-i") || w.s == "--in-place"),
        _ => false,
    }
}

fn stage_text(st: &Stage) -> String {
    words(st).iter().map(|w| if w.s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:,=+@%".contains(c)) && !w.s.is_empty() { w.s.clone() } else { sh_quote(&w.s) }).collect::<Vec<_>>().join(" ")
}

pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ------------------------------------------------------------------------------------------------ POSIX tools

fn posix(cx: &Cx, pl: &Pipeline) -> Option<Seg> {
    let st0 = &pl.stages[0];
    if is_aix(st0) {
        return Some(Seg { intent: "aix".into(), is_aix: true, ..Default::default() });
    }
    let (prog, _) = prog_at(st0);
    let w = words(st0);
    let rest = &pl.stages[1..];
    // output saved to a file: not a lookup to steer (and never answered)
    if pl.stages.iter().any(|s| s.writes) {
        return None;
    }
    match prog.as_str() {
        "grep" | "egrep" | "fgrep" | "rg" | "ag" | "ack" => grep_pl(cx, &prog, &w[1..], st0, rest, Dialect::Posix, "bash"),
        "git" if w.get(1).is_some_and(|x| x.s == "grep") => grep_pl(cx, "git-grep", &w[2..], st0, rest, Dialect::Posix, "bash"),
        "git" if w.get(1).is_some_and(|x| x.s == "ls-files") => {
            let mut paths = vec![];
            for x in &w[2..] {
                if x.s == "--" {
                    continue;
                }
                if x.s.starts_with('-') {
                    return silent("bash:git-ls-files", format!("flag:{}", x.s));
                }
                paths.push(x.clone());
            }
            list_pl(cx, "bash:git-ls-files", "ls-R", &paths, &[], rest, Dialect::Posix)
        }
        "find" => find_pl(cx, &w[1..], rest),
        "ls" => {
            let mut rec = false;
            let mut paths = vec![];
            for x in &w[1..] {
                if x.s.starts_with('-') && x.s.len() > 1 {
                    if x.s[1..].chars().any(|c| !"laRh1tSrdAF".contains(c)) && !x.s.starts_with("--color") {
                        return silent("bash:ls", format!("flag:{}", x.s));
                    }
                    rec |= x.s.contains('R');
                } else {
                    paths.push(x.clone());
                }
            }
            list_pl(cx, "bash:ls", if rec { "ls-R" } else { "ls" }, &paths, &[], rest, Dialect::Posix)
        }
        "sed" => sed_pl(cx, &w[1..], st0, rest),
        "head" | "tail" => headtail_pl(cx, &prog, &w[1..], st0, rest),
        "cat" | "bat" | "nl" | "less" | "more" => cat_pl(cx, &prog, &w[1..], st0, rest),
        "wc" => {
            let files: Vec<W> = w[1..].iter().filter(|x| !x.s.starts_with('-')).cloned().chain(st0.stdin.clone()).collect();
            if w[1..].iter().any(|x| x.s.starts_with('-') && x.s != "-l") || files.is_empty() {
                return silent("bash:wc", "no-counterpart");
            }
            files_only(cx, "bash:wc-l", "wc-l", &files, rest, Dialect::Posix, Some("line counts"))
        }
        "test" | "[" | "[[" => {
            let f = w.iter().position(|x| matches!(x.s.as_str(), "-f" | "-e" | "-s" | "-r"))?;
            let file = w.get(f + 1)?;
            files_only(cx, "bash:test-f", "test-f", std::slice::from_ref(file), rest, Dialect::Posix, None)
        }
        "stat" => {
            let fmt_ok = w.windows(2).any(|p| (p[0].s == "-c" && p[1].s.replace("%s", "").replace("%n", "").trim().is_empty()) || (p[0].s == "-f" && p[1].s.replace("%z", "").replace("%N", "").trim().is_empty()));
            if !fmt_ok {
                return silent("bash:stat", "no-counterpart");
            }
            let files: Vec<W> = w[1..].windows(1).enumerate().filter(|(i, x)| !x[0].s.starts_with('-') && !(*i > 0 && matches!(w[*i].s.as_str(), "-c" | "-f"))).map(|(_, x)| x[0].clone()).collect();
            files_only(cx, "bash:stat", "stat", &files, rest, Dialect::Posix, Some("size and lines"))
        }
        "diff" => {
            let f: Vec<&W> = w[1..].iter().filter(|x| !x.s.starts_with('-')).collect();
            if f.len() != 2 || w[1..].iter().any(|x| x.s.starts_with('-') && !matches!(x.s.as_str(), "-u")) {
                return silent("bash:diff", "no-counterpart");
            }
            let (Ok((_, x)), Ok((_, y))) = (cx.target(f[0], Dialect::Posix), cx.target(f[1], Dialect::Posix)) else { return silent("bash:diff", "not-indexed") };
            let tr = build("diff", &HashMap::from([("A", vec![x]), ("B", vec![y])]));
            Some(Seg { intent: "bash:diff".into(), tr: Some(tr), ..Default::default() })
        }
        "echo" | "printf" => {
            // only as a separator between exact reads: `sed -n 1,5p a; echo ---; sed -n 1,5p b`
            if prog == "echo" && pl.stages.len() == 1 && !st0.writes && w[1..].iter().all(|x| !x.var && !x.glob && !(x.s.len() > 1 && x.s.starts_with('-') && x.s[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E'))) && !x.s.contains('\\')) {
                let text = w[1..].iter().map(|x| x.s.as_str()).collect::<Vec<_>>().join(" ") + "\n";
                return Some(Seg { intent: "echo".into(), reason: "separator".into(), read: Some(ReadOp::Echo(text)), ..Default::default() });
            }
            None
        }
        "awk" | "gawk" | "mawk" | "python" | "python3" | "perl" | "jq" | "cut" | "sort" | "uniq" => {
            // a repo file read by a tool aix has no counterpart for: count it as a lookup, but stay silent
            let hits_repo = w[1..].iter().any(|x| !x.s.starts_with('-') && cx.rel(x, Dialect::Posix).is_ok_and(|r| cx.file_ok(&r)));
            hits_repo.then(|| Seg { intent: format!("bash:{prog}"), reason: "no-counterpart".into(), ..Default::default() })
        }
        _ => long_output(st0, rest),
    }
}

/// Programs whose output is long and slow to reproduce (builds, test runs, containers): piping it into head/tail/grep
/// throws most of it away, and the next look re-runs it.
const LONG_RUNNING: &[&str] = &[
    "cargo", "npm", "npx", "yarn", "pnpm", "gradle", "gradlew", "mvn", "mvnw", "pytest", "make", "go", "docker", "kubectl", "playwright", "jest", "vitest", "tsc", "java", "dotnet",
];

/// `slow-cmd 2>&1 | tail -50` / `| grep -E 'FAIL|ERROR'` -> save it once as a data set, then query it.
fn long_output(st0: &Stage, rest: &[Stage]) -> Option<Seg> {
    let (prog, _) = prog_at(st0);
    if rest.is_empty() || !LONG_RUNNING.contains(&prog.as_str()) || st0.writes {
        return None;
    }
    if !rest.iter().all(|s| ["head", "tail", "grep", "egrep", "rg", "cut", "sort", "uniq", "wc"].contains(&prog_at(s).0.as_str()) && !s.writes) {
        return None;
    }
    let w = words(st0);
    let name: String = w.iter().take(3).filter(|x| !x.s.starts_with('-') && !x.var).map(|x| base(&x.s)).collect::<Vec<_>>().join("-");
    let name = data_name(&name);
    let q = rest
        .iter()
        .find(|s| matches!(prog_at(s).0.as_str(), "grep" | "egrep" | "rg"))
        .and_then(|s| parse_grep(&prog_at(s).0, &words(s)[1..]).ok())
        .and_then(|g| aix_pattern(&g).ok().map(|p| format!("aix grep {} @{name}", sh_quote(&p))))
        .unwrap_or_else(|| format!("aix tail -n 50 @{name}"));
    let line = format!("{} 2>&1 | aix put {name} -", stage_text(st0));
    Some(Seg {
        intent: format!("data:{prog}|filter"),
        tr: Some(Tr { literal: Some(line), note: Some(format!("then query the saved output instead of re-running it: {q}")), ..Default::default() }),
        ..Default::default()
    })
}

/// Source and doc files are code even outside the index (another worktree, a scratch copy): not data sets.
fn code_ext(p: &str) -> bool {
    let e = p.rsplit('/').next().unwrap_or(p).rsplit_once('.').map(|x| x.1).unwrap_or("");
    matches!(e, "rs" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "java" | "kt" | "py" | "go" | "rb" | "sh" | "md" | "toml" | "yaml" | "yml" | "sql" | "html" | "css" | "c" | "h" | "cpp" | "cs" | "php" | "swift" | "scala" | "vue" | "svelte")
}

fn data_name(s: &str) -> String {
    let n: String = s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let n = n.trim_matches('-').chars().take(24).collect::<String>();
    if n.is_empty() {
        "data".into()
    } else {
        n
    }
}

/// A large non-code file (log, saved output, JSON/CSV, transcript) read by a text tool: its absolute path, a data-set
/// name and the `@name` query that replaces the read.
fn data_hint(cx: &Cx, pl: &Pipeline) -> Option<(String, String, String)> {
    let st0 = &pl.stages[0];
    let (prog, _) = prog_at(st0);
    // a followed file is live: not a data set to save
    if words(st0).iter().any(|w| matches!(w.s.as_str(), "-f" | "-F" | "--follow")) {
        return None;
    }
    if !["grep", "egrep", "rg", "head", "tail", "cat", "jq", "python", "python3", "cut", "awk", "sed", "wc", "less", "sort"].contains(&prog.as_str()) {
        return None;
    }
    let w = words(st0);
    let g = matches!(prog.as_str(), "grep" | "egrep" | "rg").then(|| parse_grep(&prog, &w[1..]).ok()).flatten();
    let cands: Vec<&W> = match &g {
        Some(g) => g.paths.iter().collect(),
        None => w[1..].iter().filter(|x| !x.s.starts_with('-')).collect(),
    };
    for c in cands {
        if c.var || c.glob {
            continue;
        }
        let s = native(&c.s.replace('~', cx.home.as_deref().unwrap_or("~")));
        let abs = if s.starts_with('/') { s } else { format!("{}/{s}", native(&cx.cwd.as_ref()?.display().to_string())) };
        let abs = os_path(&lexical(&abs));
        let md = std::fs::metadata(&abs).ok()?;
        let low = abs.to_ascii_lowercase();
        let datalike = [".log", ".out", ".txt", ".json", ".jsonl", ".csv", ".tsv", ".ndjson", ".xml"].iter().any(|e| low.ends_with(e))
            || ((low.contains("/.scratch/") || low.contains("/logs/") || low.starts_with("/tmp/")) && !code_ext(&low));
        if !md.is_file() || md.len() < 4 * 1024 || !datalike {
            continue;
        }
        let stem = Path::new(&abs).file_stem().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
        let name = data_name(&stem);
        let q = match (&g, prog.as_str()) {
            (Some(g), _) => aix_pattern(g).ok().map(|p| format!("aix grep {}{} @{name}", if g.i { "-i " } else { "" }, sh_quote(&p))),
            (None, "head") => n_of(st0).map(|n| format!("aix code @{name}:1-{n}")),
            (None, "jq") | (None, "python") | (None, "python3") => Some(format!("aix count by field <field> @{name}")),
            _ => None,
        }
        .unwrap_or_else(|| format!("aix grep '<re>' @{name}"));
        return Some((abs, name, q));
    }
    None
}

/// Flags of a grep-family command, normalised.
#[derive(Debug, Default, Clone)]
struct G {
    pats: Vec<String>,
    fixed: bool,
    ere: bool,
    flags: Vec<Arg>,
    l: bool,
    c: bool,
    o: bool,
    q: bool,
    v: bool,
    i: bool,
    recursive: bool,
    paths: Vec<W>,
    includes: Vec<String>,
}

fn parse_grep(prog: &str, args: &[W]) -> Result<G, String> {
    let mut g = G { ere: matches!(prog, "egrep" | "rg" | "ag" | "ack"), fixed: prog == "fgrep", recursive: matches!(prog, "rg" | "ag" | "ack" | "git-grep"), ..Default::default() };
    let rg = prog == "rg";
    let mut i = 0;
    let mut done = false;
    let mut pos: Vec<W> = vec![];
    let num = |v: Option<&W>| -> Result<String, String> { v.filter(|x| x.s.parse::<u32>().is_ok()).map(|x| x.s.clone()).ok_or_else(|| "flag:num".to_string()) };
    while i < args.len() {
        let x = &args[i];
        i += 1;
        if done || !x.s.starts_with('-') || x.s == "-" {
            if x.s == "-" {
                return Err("stdin".into());
            }
            pos.push(x.clone());
            continue;
        }
        if x.s == "--" {
            done = true;
            continue;
        }
        if let Some(long) = x.s.strip_prefix("--") {
            let (name, val) = match long.split_once('=') {
                Some((n, v)) => (n, Some(W { s: v.to_string(), ..x.clone() })),
                None => (long, None),
            };
            let mut take = |val: Option<W>| -> Result<W, String> {
                match val {
                    Some(v) => Ok(v),
                    None => {
                        i += 1;
                        args.get(i - 1).cloned().ok_or_else(|| format!("flag:--{name}"))
                    }
                }
            };
            match name {
                "recursive" | "dereference-recursive" => g.recursive = true,
                "line-number" | "with-filename" | "no-messages" | "color" | "colour" | "no-heading" | "heading" | "binary-files" | "line-buffered" | "sort" | "no-ignore-messages" => {
                    if matches!(name, "binary-files") && val.is_none() {
                        i += 1;
                    }
                }
                "ignore-case" => {
                    g.i = true;
                    g.flags.push(a("-i"));
                }
                "word-regexp" => g.flags.push(a("-w")),
                "line-regexp" => g.flags.push(a("-x")),
                "fixed-strings" => g.fixed = true,
                "extended-regexp" => g.ere = true,
                "basic-regexp" => g.ere = false,
                "invert-match" => {
                    g.v = true;
                    g.flags.push(a("-v"));
                }
                "only-matching" => {
                    g.o = true;
                    g.flags.push(a("-o"));
                }
                "files-with-matches" => g.l = true,
                "files-without-match" => g.flags.push(a("-L")),
                "count" => g.c = true,
                "quiet" | "silent" => g.q = true,
                "no-filename" => g.flags.push(a("-h")),
                "regexp" => g.pats.push(take(val)?.s),
                "include" | "glob" | "iglob" => {
                    let v = take(val)?;
                    if v.s.starts_with('!') {
                        g.flags.extend([a("--exclude"), a(&v.s[1..])]);
                    } else {
                        g.includes.push(v.s);
                    }
                }
                "exclude" => {
                    let v = take(val)?;
                    g.flags.extend([a("--exclude"), a(v.s)]);
                }
                "exclude-dir" => {
                    let v = take(val)?;
                    let d = v.s.trim_matches(['{', '}']);
                    if !d.split(',').all(|x| matches!(x, "node_modules" | ".git" | "target" | "dist" | "build" | "vendor" | "__pycache__" | ".venv" | ".aix" | ".claude" | "coverage" | ".next")) {
                        g.flags.extend([a("--exclude-dir"), a(v.s)]);
                    }
                }
                "max-count" => {
                    let v = take(val)?;
                    g.flags.extend([a("-m"), a(num(Some(&v))?)]);
                }
                "context" | "after-context" | "before-context" => {
                    let v = take(val)?;
                    let n = num(Some(&v))?;
                    if n.parse::<u32>().unwrap_or(99) > 30 {
                        return Err("flag:context>30".into());
                    }
                    g.flags.extend([a(match name {
                        "context" => "-C",
                        "after-context" => "-A",
                        _ => "-B",
                    }), a(n)]);
                }
                "type" if rg => {
                    let v = take(val)?;
                    g.flags.extend([a("-t"), a(v.s)]);
                }
                "case-sensitive" if rg => {}
                _ => return Err(format!("flag:--{name}")),
            }
            continue;
        }
        // short flag cluster
        let fl: Vec<char> = x.s[1..].chars().collect();
        // `-5` (GNU context shorthand)
        if fl.iter().all(|c| c.is_ascii_digit()) {
            if x.s[1..].parse::<u32>().unwrap_or(99) > 30 {
                return Err("flag:context>30".into());
            }
            g.flags.extend([a("-C"), a(&x.s[1..])]);
            continue;
        }
        let mut k = 0;
        while k < fl.len() {
            let ch = fl[k];
            k += 1;
            let arg_val = |k: usize, i: &mut usize| -> Option<W> {
                let rest: String = fl[k..].iter().collect();
                if rest.is_empty() {
                    *i += 1;
                    args.get(*i - 1).cloned()
                } else {
                    Some(W { s: rest, ..Default::default() })
                }
            };
            match ch {
                'r' | 'R' if !rg => g.recursive = true,
                'n' | 'H' | 's' | 'I' | 'N' if !(rg && ch == 's') => {}
                's' if rg => {}
                'i' => {
                    g.i = true;
                    g.flags.push(a("-i"));
                }
                'w' => g.flags.push(a("-w")),
                'x' => g.flags.push(a("-x")),
                'F' => g.fixed = true,
                'E' => g.ere = true,
                'G' if !rg => g.ere = false,
                'v' => {
                    g.v = true;
                    g.flags.push(a("-v"));
                }
                'o' => {
                    g.o = true;
                    g.flags.push(a("-o"));
                }
                'l' => g.l = true,
                'L' => g.flags.push(a("-L")),
                'c' => g.c = true,
                'q' => g.q = true,
                'h' => g.flags.push(a("-h")),
                'e' => {
                    g.pats.push(arg_val(k, &mut i).ok_or("flag:-e")?.s);
                    break;
                }
                'm' => {
                    let v = arg_val(k, &mut i);
                    g.flags.extend([a("-m"), a(num(v.as_ref())?)]);
                    break;
                }
                'A' | 'B' | 'C' => {
                    let v = arg_val(k, &mut i);
                    let n = num(v.as_ref())?;
                    if n.parse::<u32>().unwrap_or(99) > 30 {
                        return Err("flag:context>30".into());
                    }
                    g.flags.extend([a(format!("-{ch}")), a(n)]);
                    break;
                }
                'g' if rg => {
                    let v = arg_val(k, &mut i).ok_or("flag:-g")?;
                    if let Some(neg) = v.s.strip_prefix('!') {
                        g.flags.extend([a("--exclude"), a(neg)]);
                    } else {
                        g.includes.push(v.s);
                    }
                    break;
                }
                't' if rg => {
                    let v = arg_val(k, &mut i).ok_or("flag:-t")?;
                    g.flags.extend([a("-t"), a(v.s)]);
                    break;
                }
                'Q' if matches!(prog, "ag" | "ack") => g.fixed = true,
                _ => return Err(format!("flag:-{ch}")),
            }
        }
    }
    if g.pats.is_empty() {
        if pos.is_empty() {
            return Err("no-pattern".into());
        }
        let p = pos.remove(0);
        if p.var {
            return Err("var".into());
        }
        g.pats.push(p.s);
    }
    g.paths = pos;
    Ok(g)
}

/// The aix pattern for a grep pattern list: BRE translated, several `-e` joined into one alternation.
fn aix_pattern(g: &G) -> Result<String, String> {
    let mut out = vec![];
    for p in &g.pats {
        if p.is_empty() || p.contains('\n') || p.len() > 300 {
            return Err("pattern".into());
        }
        let q = if g.fixed {
            if g.pats.len() == 1 {
                p.clone()
            } else {
                regex::escape(p)
            }
        } else if g.ere {
            p.clone()
        } else {
            bre2ere(p)
        };
        out.push(q);
    }
    let pat = if out.len() == 1 { out.remove(0) } else { out.iter().map(|p| format!("(?:{p})")).collect::<Vec<_>>().join("|") };
    if !(g.fixed && g.pats.len() == 1) && Regex::new(&pat.replace("\\<", "\\b").replace("\\>", "\\b")).is_err() {
        return Err("regex".into());
    }
    Ok(pat)
}

/// GNU BRE -> ERE (the regex crate's syntax): `\| \( \) \{ \} \+ \?` become operators, the bare ones literals
/// (`[|]`).
pub fn bre2ere(p: &str) -> String {
    let c: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut in_class = false;
    while i < c.len() {
        let ch = c[i];
        if in_class {
            out.push(ch);
            if ch == ']' && !(out.ends_with("[]") || out.ends_with("[^]")) {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match ch {
            '[' => {
                in_class = true;
                out.push(ch);
            }
            '\\' if i + 1 < c.len() => {
                let n = c[i + 1];
                if matches!(n, '|' | '(' | ')' | '{' | '}' | '+' | '?') {
                    out.push(n);
                } else {
                    out.push('\\');
                    out.push(n);
                }
                i += 1;
            }
            // a literal operator as a one-character class: the same in ERE and in `aix grep`'s GNU BRE reading
            // (where `\|` would be an alternation again)
            '|' | '(' | ')' | '{' | '}' | '+' | '?' => {
                out.push('[');
                out.push(ch);
                out.push(']');
            }
            // a leading `*` is a literal in BRE
            '*' if out.is_empty() || out.ends_with("\\(") || out == "^" => out.push_str("\\*"),
            _ => out.push(ch),
        }
        i += 1;
    }
    out
}

fn pat_args(g: &G, pat: &str) -> Vec<Arg> {
    let mut v = vec![];
    if g.fixed && g.pats.len() == 1 {
        v.push(a("-F"));
    }
    if pat.starts_with('-') {
        v.push(a("-e"));
    }
    v.push(a(pat));
    v
}

/// Resolve a list of path words; an empty list means the cwd.
fn targets(cx: &Cx, paths: &[W], dialect: Dialect) -> Result<Vec<Arg>, String> {
    if paths.is_empty() {
        let r = cx.cwd_rel().ok_or("outside-repo")?;
        if !cx.probe.dir_has(&r) {
            return Err("not-indexed".into());
        }
        return Ok(vec![]);
    }
    let mut out = vec![];
    for p in paths {
        let (rel, shown) = cx.target(p, dialect)?;
        // the cwd itself (`.`) is aix's default scope only at the repo root
        if (p.s == "." || p.s == "./") && cx.cwd_rel().as_deref() == Some("") {
            continue;
        }
        let _ = rel;
        out.push(shown);
    }
    Ok(out)
}

fn n_of(st: &Stage) -> Option<usize> {
    // `head -n N`, `head -N`, `head -nN`, `head` (10)
    let w = words(st);
    match w.len() {
        1 => Some(10),
        2 => w[1].s.strip_prefix("-n").filter(|x| !x.is_empty()).or_else(|| w[1].s.strip_prefix('-')).and_then(|x| x.parse().ok()),
        3 if w[1].s == "-n" => w[2].s.parse().ok(),
        _ => None,
    }
}

fn is_prog(st: &Stage, p: &str) -> bool {
    prog_at(st).0 == p
}

fn cut_width(st: &Stage) -> Option<usize> {
    let w = words(st);
    if !is_prog(st, "cut") {
        return None;
    }
    let spec = match w.len() {
        2 => w[1].s.strip_prefix("-c")?.to_string(),
        3 if w[1].s == "-c" => w[2].s.clone(),
        _ => return None,
    };
    let spec = spec.strip_prefix("1-").or_else(|| spec.strip_prefix('-'))?;
    spec.parse().ok()
}

/// Shared modifiers on the remaining stages: `| head N` -> --head, `| cut -c1-N` -> --width; anything else that is a
/// pure filter stays as a shell tail. Err when a stage is not a pure filter.
fn mods(rest: &[Stage]) -> Result<(Vec<Arg>, Option<String>), String> {
    let mut m = vec![];
    let mut k = 0;
    while k < rest.len() {
        let st = &rest[k];
        if is_prog(st, "head") && st.stdin.is_none() {
            if let Some(n) = n_of(st) {
                m.extend([a("--head"), a(n.to_string())]);
                k += 1;
                continue;
            }
        }
        if let Some(n) = cut_width(st) {
            m.extend([a("--width"), a(n.to_string())]);
            k += 1;
            continue;
        }
        break;
    }
    let tail = &rest[k..];
    if tail.iter().any(|s| !pure_filter(s)) {
        return Err("pipe".into());
    }
    let t = (!tail.is_empty()).then(|| tail.iter().map(stage_text).collect::<Vec<_>>().join(" | "));
    Ok((m, t))
}

/// `xargs [-0] [-r] [-n N] CMD ARGS` after a file list -> the aix stage that does CMD per file (reads `-`).
fn xargs_stage(st: &Stage) -> Option<(Vec<Arg>, &'static str)> {
    let w = words(st);
    if !is_prog(st, "xargs") {
        return None;
    }
    let mut i = 1;
    while i < w.len() && w[i].s.starts_with('-') {
        match w[i].s.as_str() {
            "-0" | "-r" | "--no-run-if-empty" | "--null" => i += 1,
            "-n" | "-P" => i += 2,
            _ => return None,
        }
    }
    let cmd = &w.get(i..)?;
    let p = base(&cmd.first()?.s);
    let args = &cmd[1..];
    if args.iter().any(|x| x.var) {
        return None;
    }
    match p.as_str() {
        "grep" | "egrep" | "rg" => {
            let g = parse_grep(&p, args).ok()?;
            if !g.paths.is_empty() {
                return None;
            }
            let pat = aix_pattern(&g).ok()?;
            let mut v = vec![a("grep")];
            v.extend(g.flags.clone());
            if g.l {
                v.push(a("-l"));
            }
            if g.c {
                v.push(a("-c"));
            }
            v.extend(pat_args(&g, &pat));
            Some((v, "grep"))
        }
        "sed" => {
            let (ranges, files) = sed_ranges(args)?;
            if !files.is_empty() {
                return None;
            }
            let spec = ranges.iter().map(|(x, y)| if *y == usize::MAX { format!("{x},$p") } else { format!("{x},{y}p") }).collect::<Vec<_>>().join(";");
            Some((vec![a("sed"), a("-n"), a(spec)], "sed"))
        }
        "head" | "tail" => {
            let n = match args {
                [] => 10,
                [x] => x.s.strip_prefix('-')?.parse().ok()?,
                [f, x] if f.s == "-n" => x.s.parse().ok()?,
                _ => return None,
            };
            Some((vec![a(p.clone()), a("-n"), a(n.to_string())], if p == "head" { "head" } else { "tail" }))
        }
        "cat" if args.is_empty() => Some((vec![a("cat")], "cat")),
        "wc" if args.len() == 1 && args[0].s == "-l" => Some((vec![a("files")], "wc")),
        _ => None,
    }
}

fn grep_pl(cx: &Cx, prog: &str, args: &[W], st0: &Stage, rest: &[Stage], dialect: Dialect, dl: &str) -> Option<Seg> {
    let label = if prog == "git-grep" { "git-grep".to_string() } else { "grep".to_string() };
    let mut intent = format!("{dl}:{label}");
    if prog == "rg" && args.iter().any(|x| x.s == "--files") {
        let paths: Vec<W> = args.iter().filter(|x| !x.s.starts_with('-')).cloned().collect();
        if args.iter().any(|x| x.s.starts_with('-') && x.s != "--files") {
            return silent("bash:rg-files", "flag");
        }
        return list_pl(cx, "bash:rg-files", "ls-R", &paths, &[], rest, dialect);
    }
    let g = match parse_grep(prog, args) {
        Ok(g) => g,
        Err(e) => return silent(&intent, e),
    };
    if g.paths.is_empty() && !g.recursive {
        // reads stdin: data, not the index
        return match &st0.stdin {
            Some(f) if f.s != "-" => grep_with_paths(cx, g, vec![f.clone()], rest, dialect, intent),
            _ => None,
        };
    }
    if g.recursive {
        intent.push_str("-r");
    }
    let paths = g.paths.clone();
    let read = if dialect == Dialect::Posix && !g.recursive { grep_read(cx, prog, args, st0, rest) } else { None };
    let mut seg = grep_with_paths(cx, g, paths, rest, dialect, intent)?;
    if seg.tr.is_some() {
        seg.read = read;
    }
    Some(seg)
}

fn grep_with_paths(cx: &Cx, g: G, paths: Vec<W>, rest: &[Stage], dialect: Dialect, mut intent: String) -> Option<Seg> {
    let pat = match aix_pattern(&g) {
        Ok(p) => p,
        Err(e) => return silent(&intent, e),
    };
    let tpaths = match targets(cx, &paths, dialect) {
        Ok(t) => t,
        Err(e) => return silent(&intent, e),
    };
    let mut flags = g.flags.clone();
    if g.l {
        flags.push(a("-l"));
    }
    if g.c {
        flags.push(a("-c"));
    }
    for inc in &g.includes {
        flags.extend([a("--include"), a(inc)]);
    }
    let mut m: HashMap<&str, Vec<Arg>> = HashMap::from([("FLAGS", flags.clone()), ("PAT", pat_args(&g, &pat)), ("PATHS", tpaths.clone())]);
    let mut row = "grep";
    let mut note = None;
    let mut rest = rest;
    if g.q {
        row = "grep-q";
        intent.push_str("-q");
    } else if !rest.is_empty() {
        let p1 = prog_at(&rest[0]).0;
        let w1 = words(&rest[0]);
        // `| wc -l`
        if p1 == "wc" && w1.len() == 2 && w1[1].s == "-l" && rest.len() == 1 {
            if g.l {
                row = "grep-l|wc-l";
            } else if !g.c && !g.o {
                row = "grep|wc-l";
            } else {
                return silent(&format!("{intent}|wc-l"), "no-counterpart");
            }
            intent.push_str("|wc-l");
            rest = &[];
        } else if matches!(p1.as_str(), "grep" | "egrep") && !g.l && !g.c && !g.o {
            // `| grep -v Y` / `| grep Y` on the hit lines
            if let Ok(g2) = parse_grep(&p1, &w1[1..]) {
                let only_v_i = g2.flags.iter().all(|f| f.s == "-v" || f.s == "-i") && g2.paths.is_empty() && !g2.l && !g2.c && !g2.o && !g2.q && g2.includes.is_empty();
                if only_v_i && g2.i == g.i {
                    if let Ok(p2) = aix_pattern(&g2) {
                        row = if g2.v { "grep|grep-v" } else { "grep|grep" };
                        intent.push_str(if g2.v { "|grep-v" } else { "|grep" });
                        let p2 = if g2.fixed { regex::escape(&g2.pats[0]) } else { p2 };
                        m.insert("PAT2", vec![a(p2)]);
                        rest = &rest[1..];
                    }
                }
            }
        } else if !g.l && !g.c && ((p1 == "awk" && w1.len() == 2 && w1[1].s.replace(' ', "") == "!seen[$0]++") || (p1 == "sort" && w1.len() == 2 && w1[1].s == "-u" && rest.len() == 1) || (p1 == "sort" && w1.len() == 1 && rest.len() == 2 && is_prog(&rest[1], "uniq") && words(&rest[1]).len() == 1)) {
            // (sort -u only as the last stage: a `| head` after it picks the first rows in sorted order)
            // `| awk '!seen[$0]++'` (first seen, order kept: exact), `| sort -u` / `| sort | uniq` (the same set)
            row = "grep|dedup";
            if p1 == "awk" {
                intent.push_str("|awk-seen");
                rest = &rest[1..];
            } else {
                intent.push_str("|sort-u");
                note = Some("first-seen order (sort -u sorts the same rows)".into());
                rest = if w1.len() == 1 { &rest[2..] } else { &rest[1..] };
            }
        } else if !g.o && !g.l && !g.c && p1 == "sort" && w1.len() == 1 && rest.len() >= 2 && is_prog(&rest[1], "uniq") && words(&rest[1]).iter().any(|x| x.s == "-c") {
            // `| sort | uniq -c [| sort -rn]`: one row per distinct line with its count, most first
            row = "grep|sort|uniq-c";
            intent.push_str("|sort|uniq-c");
            rest = &rest[2..];
            if rest.first().is_some_and(|s| is_prog(s, "sort")) {
                rest = &rest[1..];
            }
        } else if g.o && p1 == "sort" && rest.len() >= 2 && is_prog(&rest[1], "uniq") && words(&rest[1]).iter().any(|x| x.s == "-c") {
            row = "grep-o|sort|uniq-c";
            intent.push_str("|sort|uniq-c");
            rest = &rest[2..];
            if rest.first().is_some_and(|s| is_prog(s, "sort")) {
                rest = &rest[1..];
            }
            m.get_mut("FLAGS").unwrap().retain(|f| f.s != "-o");
        } else if p1 == "cut" && w1.iter().any(|x| x.s == "-d:" || x.s == "-d" ) && w1.iter().any(|x| x.s == "-f1" || x.s == "-f" ) && !g.l && !g.c {
            if rest.len() >= 2 && is_prog(&rest[1], "sort") && words(&rest[1]).iter().any(|x| x.s == "-u") {
                row = "grep|cut-f1|sort-u";
                intent.push_str("|cut-f1|sort-u");
                rest = &rest[2..];
            } else if rest.len() >= 3 && is_prog(&rest[1], "sort") && is_prog(&rest[2], "uniq") && words(&rest[2]).iter().any(|x| x.s == "-c") {
                row = "grep|cut-f1|uniq-c";
                intent.push_str("|cut-f1|uniq-c");
                rest = &rest[3..];
                if rest.first().is_some_and(|s| is_prog(s, "sort")) {
                    rest = &rest[1..];
                }
                note = Some("count per file".to_string());
            }
        } else if g.l && p1 == "xargs" {
            if let Some((stage, kind)) = xargs_stage(&rest[0]) {
                row = "grep-l|xargs";
                intent.push_str(&format!("|xargs-{kind}"));
                m.get_mut("FLAGS").unwrap().retain(|f| f.s != "-l");
                m.get_mut("FLAGS").unwrap().push(a("-l"));
                m.insert("XCMD", stage);
                if kind == "sed" {
                    note = Some("per file (xargs sed joins the files into one stream)".into());
                }
                rest = &rest[1..];
            } else {
                return silent(&format!("{intent}|xargs"), "no-counterpart");
            }
        }
    }
    let (md, tail) = match mods(rest) {
        Ok(x) => x,
        Err(e) => return silent(&intent, e),
    };
    if !md.is_empty() {
        intent.push_str(if md[0].s == "--head" { "|head" } else { "|cut-c" });
    }
    if g.i && dialect == Dialect::Ps {
        note = Some("Select-String ignores case by default: -i keeps that".into());
    }
    if note.is_none() && !g.l && !g.c && !g.o && !g.v && g.pats.len() == 1 {
        note = semantic_alt(&g.pats[0], cx.probe);
    }
    m.insert("MODS", md.clone());
    let mut tr = build(row, &m);
    if template(row).contains(" | ") && !md.is_empty() {
        tr.stages.last_mut().unwrap().extend(md);
    }
    tr.tail = tail;
    tr.note = note;
    let pattern = (g.recursive && g.pats.len() == 1 && !g.v && !g.c && !g.o && !g.i && !g.q && !g.l).then(|| g.pats[0].clone());
    Some(Seg { intent, tr: Some(tr), pattern, ..Default::default() })
}

/// A question the pattern looks like, answered better than by text matching: a UI phrase, an API path, a route,
/// a type name.
pub fn semantic_alt(p: &str, probe: &dyn Probe) -> Option<String> {
    if p.contains(['^', '$', '|', '[', '(', '*', '+', '?', '{', '\\', '"']) || p.len() > 80 {
        return None;
    }
    if p.starts_with("/api") || p.contains("/api/") {
        return Some(format!("aix endpoint {p} gives the handler, roles and callers"));
    }
    if p.starts_with('/') && !p.contains(' ') {
        return Some(format!("aix brief {p} gives the page, roles and endpoints"));
    }
    if p.contains(' ') && p.chars().next().is_some_and(|c| c.is_uppercase()) {
        return Some(format!("aix text \"{p}\" finds the component that renders this UI text"));
    }
    let ident = !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$');
    if ident && probe.has_callers(p) {
        return Some(format!("aix callers {p} answers who calls it (callers|callees|impact <symbol> for the call graph)"));
    }
    if !p.contains(' ') && p.len() > 2 && p.chars().next().is_some_and(|c| c.is_uppercase()) && p.chars().all(|c| c.is_alphanumeric() || c == '_') && p.chars().any(|c| c.is_lowercase()) {
        return Some(format!("aix symbol {p} / aix callers {p} for the definition and its callers"));
    }
    None
}

/// `find ROOTS PREDS [| xargs grep ...] [| wc -l]`
fn find_pl(cx: &Cx, args: &[W], rest: &[Stage]) -> Option<Seg> {
    let mut intent = "bash:find".to_string();
    let mut i = 0;
    let mut roots = vec![];
    while i < args.len() && matches!(args[i].s.as_str(), "-L" | "-H" | "-P" | "-E" | "-x") {
        i += 1;
    }
    while i < args.len() && !args[i].s.starts_with('-') && !matches!(args[i].s.as_str(), "!" | "(" | "\\(") {
        roots.push(args[i].clone());
        i += 1;
    }
    let mut preds: Vec<Arg> = vec![];
    let mut names = vec![];
    let mut exec: Option<Vec<W>> = None;
    let mut neg = false;
    while i < args.len() {
        let x = args[i].s.as_str();
        i += 1;
        match x {
            "!" | "-not" => neg = true,
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" => {
                let v = args.get(i)?;
                i += 1;
                if v.var {
                    return silent(&intent, "var");
                }
                if neg {
                    preds.extend([a("-not"), a(x), a(&v.s)]);
                } else {
                    preds.extend([a(x), a(&v.s)]);
                    if x == "-name" {
                        names.push(v.s.clone());
                    }
                }
                neg = false;
            }
            "-type" => {
                let v = args.get(i)?;
                i += 1;
                if v.s != "f" {
                    return silent(&intent, "flag:-type");
                }
                preds.extend([a("-type"), a("f")]);
            }
            "-maxdepth" | "-mindepth" => {
                let v = args.get(i)?;
                i += 1;
                preds.extend([a(x), a(&v.s)]);
            }
            "-print" | "-print0" => {}
            "-exec" => {
                let end = args[i..].iter().position(|w| w.s == ";" || w.s == "+" || w.s == "\\;")? + i;
                exec = Some(args[i..end].iter().filter(|w| w.s != "{}").cloned().collect());
                i = end + 1;
            }
            _ => return silent(&intent, format!("flag:{x}")),
        }
    }
    let troots = match targets(cx, &roots, Dialect::Posix) {
        Ok(t) => t,
        Err(e) => return silent(&intent, e),
    };
    // `-exec grep ... {} +` is `| xargs grep`
    let rest_owned: Vec<Stage>;
    let mut rest = rest;
    if let Some(e) = exec {
        let mut xs = Stage::default();
        xs.w.push(W { s: "xargs".into(), ..Default::default() });
        xs.w.extend(e);
        rest_owned = std::iter::once(xs).chain(rest.iter().cloned()).collect();
        rest = &rest_owned[..];
    }
    let mut m: HashMap<&str, Vec<Arg>> = HashMap::from([("ROOTS", troots), ("PREDS", preds.clone())]);
    let mut row = "find";
    if let Some(st) = rest.first() {
        let w1 = words(st);
        if is_prog(st, "wc") && w1.len() == 2 && w1[1].s == "-l" {
            row = "find|wc-l";
            intent.push_str("|wc-l");
            rest = &rest[1..];
        } else if is_prog(st, "xargs") {
            let Some((stage, kind)) = xargs_stage(st) else { return silent(&format!("{intent}|xargs"), "no-counterpart") };
            intent.push_str(&format!("|xargs-{kind}"));
            rest = &rest[1..];
            // a grep over files picked by name only: one aix grep with --include
            let simple_names = preds.iter().all(|p| p.s == "-name" || p.s == "-type" || p.s == "f" || names.contains(&p.s));
            if kind == "grep" && simple_names && names.len() <= 1 {
                row = "find|xargs-grep";
                let mut flags = vec![];
                let mut pat = vec![];
                // stage = ["grep", flags..., pattern]
                let body = &stage[1..];
                let (last, init) = body.split_last()?;
                flags.extend(init.iter().filter(|f| f.s != "-F" && f.s != "-e").cloned());
                if init.iter().any(|f| f.s == "-F") {
                    pat.push(a("-F"));
                }
                if last.s.starts_with('-') {
                    pat.push(a("-e"));
                }
                pat.push(last.clone());
                m.insert("FLAGS", flags);
                m.insert("PAT", pat);
                m.insert("INCL", names.iter().flat_map(|n| [a("--include"), a(n)]).collect());
            } else {
                row = "find|xargs";
                m.insert("XCMD", stage);
            }
        }
    }
    let (md, tail) = match mods(rest) {
        Ok(x) => x,
        Err(e) => return silent(&intent, e),
    };
    m.insert("MODS", md);
    let mut tr = build(row, &m);
    tr.tail = tail;
    Some(Seg { intent, tr: Some(tr), ..Default::default() })
}

/// ls / ls -R / git ls-files / rg --files
fn list_pl(cx: &Cx, intent: &str, row: &str, paths: &[W], preds: &[Arg], rest: &[Stage], dialect: Dialect) -> Option<Seg> {
    let mut intent = intent.to_string();
    let tpaths = match targets(cx, paths, dialect) {
        Ok(t) => t,
        Err(e) => return silent(&intent, e),
    };
    let mut row = row;
    let mut rest = rest;
    if let Some(st) = rest.first() {
        let w1 = words(st);
        if is_prog(st, "wc") && w1.len() == 2 && w1[1].s == "-l" && row == "ls" {
            row = "ls|wc-l";
            intent.push_str("|wc-l");
            rest = &rest[1..];
        }
    }
    let (md, tail) = match mods(rest) {
        Ok(x) => x,
        Err(e) => return silent(&intent, e),
    };
    if tail.is_some() {
        intent.push_str("|filter");
    }
    let mut paths = tpaths;
    paths.extend(preds.iter().cloned());
    let mut tr = build(row, &HashMap::from([("PATHS", paths), ("MODS", md)]));
    tr.tail = tail;
    Some(Seg { intent, tr: Some(tr), ..Default::default() })
}

/// wc -l / test -f / stat on named files.
fn files_only(cx: &Cx, intent: &str, row: &str, files: &[W], rest: &[Stage], dialect: Dialect, note: Option<&str>) -> Option<Seg> {
    let mut shown = vec![];
    for f in files {
        match cx.target(f, dialect) {
            Ok((rel, s)) if cx.file_ok(&rel) || f.glob => shown.push(s),
            Ok(_) => return silent(intent, "not-a-file"),
            Err(e) => return silent(intent, e),
        }
    }
    if shown.is_empty() || !rest.iter().all(pure_filter) {
        return silent(intent, "pipe");
    }
    let mut tr = build(row, &HashMap::from([("FILES", shown)]));
    tr.tail = (!rest.is_empty()).then(|| rest.iter().map(stage_text).collect::<Vec<_>>().join(" | "));
    tr.note = note.map(str::to_string);
    Some(Seg { intent: intent.into(), tr: Some(tr), ..Default::default() })
}

/// A search pattern that is plainly a symbol lookup -> (the symbol as `aix callers` takes it, its last name part):
/// `camelCase`, `snake_case`, `Class.method` / `Class\.method` / `Class::method` / `Class#method`, `name(` / `name\(`,
/// `\bname\b`, `new Name(`, `.name(`. A plain lowercase word or a bare `PascalCase` type name is not (text and type
/// searches have better answers than call sites).
pub fn symbol_of(pat: &str) -> Option<(String, String)> {
    static ID: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*$").unwrap());
    let mut p = pat.trim();
    let mut call = false;
    let mut ctor = false;
    let mut bounded = false;
    if let Some(x) = p.strip_prefix(r"\b") {
        p = x;
        bounded = true;
    }
    if let Some(x) = p.strip_suffix(r"\b") {
        p = x;
        bounded = true;
    }
    for suf in [r"\s*\(", r"\(", "("] {
        if let Some(x) = p.strip_suffix(suf) {
            p = x;
            call = true;
            break;
        }
    }
    for pre in [r"new\s+", "new "] {
        if let Some(x) = p.strip_prefix(pre) {
            p = x;
            ctor = call;
            break;
        }
    }
    if let Some(x) = p.strip_prefix(r"\.").or_else(|| p.strip_prefix('.')) {
        p = x;
    }
    let parts: Vec<String> = p.replace(r"\.", ".").replace("::", ".").replace('#', ".").split('.').map(str::to_string).collect();
    if parts.len() > 2 || parts.iter().any(|x| !ID.is_match(x)) {
        return None;
    }
    let name = parts.last()?.clone();
    if name.len() < 3 {
        return None;
    }
    let lower0 = name.chars().next().is_some_and(|c| c.is_ascii_lowercase());
    let camel = lower0 && name.chars().any(|c| c.is_ascii_uppercase());
    let snake = lower0 && name.contains('_') && !name.ends_with('_');
    let ok = parts.len() == 2 || camel || snake || ctor || ((call || bounded) && lower0);
    ok.then(|| (parts.join("."), name))
}

// ------------------------------------------------------------------------------------------------ exact filters

/// `for V in a b c; do BODY; done` over literal words -> BODY once per word (the same commands in the same order, so
/// the same output). None unless every part is plain: literal words, `$V` / `${V}` only outside single quotes, no
/// nested loop, no break/continue/exit, nothing piped or redirected from the loop as a whole.
pub fn expand_for(cmd: &str) -> Option<String> {
    static FOR: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?s)^(?P<pre>[^'\x22`]*?)\bfor\s+(?P<v>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+(?P<ws>[^;\n]*?)\s*[;\n]\s*do\s+(?P<body>.*?)[;\n\s]*\bdone\b(?P<post>.*)$").unwrap()
    });
    let c = FOR.captures(cmd)?;
    let (pre, var, body, post) = (&c["pre"], &c["v"], &c["body"], c["post"].trim());
    let kw = Regex::new(r"\b(for|while|until|do|done|break|continue|exit|return|select|case)\b").ok()?;
    if kw.is_match(pre) || kw.is_match(body) || kw.is_match(post) || !(post.is_empty() || post.starts_with(';') || post.starts_with("&&") || post.starts_with('\n')) {
        return None;
    }
    let words: Vec<&str> = c["ws"].split_whitespace().collect();
    if words.is_empty() || words.len() > 40 || !words.iter().all(|w| w.chars().all(|ch| ch.is_ascii_alphanumeric() || "_./:+@%,=-".contains(ch))) {
        return None;
    }
    // where $V is used (outside single quotes only), and nothing else touches V
    let b: Vec<char> = body.chars().collect();
    let vn: Vec<char> = var.chars().collect();
    let mut uses: Vec<(usize, usize)> = vec![];
    let (mut sq, mut i) = (false, 0);
    while i < b.len() {
        match b[i] {
            '\'' => sq = !sq,
            '\\' => i += 1,
            '$' => {
                let braced = b.get(i + 1) == Some(&'{');
                let s = i + 1 + usize::from(braced);
                let is_v = b.len() >= s + vn.len() && b[s..s + vn.len()] == vn[..];
                let after = b.get(s + vn.len()).copied();
                if is_v && !braced && after.is_some_and(|ch| ch.is_alphanumeric() || ch == '_') {
                    // another variable ($Vx): unknown value
                    return None;
                }
                if is_v {
                    if sq || (braced && after != Some('}')) {
                        return None;
                    }
                    uses.push((i, s + vn.len() + usize::from(braced)));
                } else if !sq {
                    return None; // any other expansion: not a literal command
                }
            }
            _ => {}
        }
        i += 1;
    }
    if uses.is_empty() || Regex::new(&format!(r"\b{var}=")).ok()?.is_match(body) {
        return None;
    }
    let mut out = String::from(pre);
    for (k, w) in words.iter().enumerate() {
        if k > 0 {
            out.push('\n');
        }
        let mut last = 0;
        for (s, e) in &uses {
            out.extend(&b[last..*s]);
            out.push_str(w);
            last = *e;
        }
        out.extend(&b[last..]);
    }
    out.push_str(&c["post"]);
    Some(out)
}

/// A GNU grep pattern (already in ERE / regex-crate form) that the regex crate reads the same way on ASCII text, or
/// None: no backslash or nested `[` in a bracket expression, no back-references or GNU-only escapes, `{` only as a
/// counted repetition.
fn same_as_grep(p: &str) -> Option<String> {
    let c: Vec<char> = p.chars().collect();
    let mut i = 0;
    let mut class = false;
    while i < c.len() {
        let ch = c[i];
        if class {
            match ch {
                '\\' => return None,
                '[' if c.get(i + 1) == Some(&':') => {
                    let end = c[i..].iter().collect::<String>().find(":]")?;
                    i += end + 2;
                    continue;
                }
                '[' => return None,
                '&' | '-' | '~' if c.get(i + 1) == Some(&ch) => return None,
                ']' if !(c[i - 1] == '[' || (c[i - 1] == '^' && c[i - 2] == '[')) => class = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match ch {
            '[' => class = true,
            '\\' => {
                let n = *c.get(i + 1)?;
                if !(n.is_ascii_punctuation() || matches!(n, 'b' | 'B' | 'w' | 'W' | 's' | 'S')) || matches!(n, '<' | '>' | '`' | '\'') {
                    return None;
                }
                i += 1;
            }
            '{' => {
                let rest: String = c[i..].iter().collect();
                if !Regex::new(r"^\{[0-9]+(,[0-9]*)?\}").unwrap().is_match(&rest) || i == 0 {
                    return None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if class || p.contains("(?") {
        return None;
    }
    Regex::new(p).ok()?;
    Some(p.to_string())
}

/// `grep` flags the hook reproduces: -n -E -F -i -v -c (and -e RE). Returns the filter and the file words.
fn filt_grep(prog: &str, args: &[W]) -> Option<(Filt, Vec<W>)> {
    let (mut n, mut v, mut c, mut i, mut ere, mut fixed) = (false, false, false, false, prog == "egrep", prog == "fgrep");
    let mut pats: Vec<String> = vec![];
    let mut files: Vec<W> = vec![];
    let mut k = 0;
    let mut done = false;
    while k < args.len() {
        let x = &args[k];
        k += 1;
        if x.var || x.glob {
            return None;
        }
        if done || !x.s.starts_with('-') || x.s == "-" {
            if x.s == "-" {
                return None;
            }
            files.push(x.clone());
            continue;
        }
        match x.s.as_str() {
            "--" => done = true,
            "--line-number" => n = true,
            "--invert-match" => v = true,
            "--count" => c = true,
            "--ignore-case" => i = true,
            "--extended-regexp" => ere = true,
            "--fixed-strings" => fixed = true,
            s if s.starts_with("--") => return None,
            s => {
                let fl: Vec<char> = s[1..].chars().collect();
                let mut j = 0;
                while j < fl.len() {
                    match fl[j] {
                        'n' => n = true,
                        'v' => v = true,
                        'c' => c = true,
                        'i' => i = true,
                        'E' => ere = true,
                        'F' => fixed = true,
                        's' => {}
                        'e' => {
                            let rest: String = fl[j + 1..].iter().collect();
                            if rest.is_empty() {
                                let w = args.get(k)?;
                                if w.var {
                                    return None;
                                }
                                pats.push(w.s.clone());
                                k += 1;
                            } else {
                                pats.push(rest);
                            }
                            j = fl.len();
                            continue;
                        }
                        _ => return None,
                    }
                    j += 1;
                }
            }
        }
    }
    if pats.is_empty() {
        if files.is_empty() {
            return None;
        }
        pats.push(files.remove(0).s);
    }
    let mut res = vec![];
    for p in &pats {
        if p.contains('\n') || p.len() > 300 {
            return None;
        }
        res.push(if fixed { regex::escape(p) } else { same_as_grep(&if ere { p.clone() } else { bre_exact(p)? })? });
    }
    let re = if res.len() == 1 { res.remove(0) } else { res.iter().map(|p| format!("(?:{p})")).collect::<Vec<_>>().join("|") };
    Some((Filt::Grep { re, n, v, c, i }, files))
}

/// GNU BRE -> regex-crate syntax for the exact path: `bre2ere`, refusing the shapes it reads loosely (a `*` right
/// after `\(` or `\|`, `\{`).
fn bre_exact(p: &str) -> Option<String> {
    if p.contains("\\(*") || p.contains("\\|*") || p.contains("\\{") || p.contains("\\}") {
        return None;
    }
    Some(bre2ere(p))
}

/// One pipeline stage as an exact filter (grep / head / tail / wc -l over stdin), or None.
fn filt_of(st: &Stage) -> Option<Filt> {
    if st.writes || st.stdin.is_some() || !st.env.is_empty() {
        return None;
    }
    let w = words(st);
    let p = base(&w.first()?.s);
    let args = &w[1..];
    if args.iter().any(|x| x.var || x.glob) {
        return None;
    }
    match p.as_str() {
        "grep" | "egrep" | "fgrep" => match filt_grep(&p, args)? {
            (f, files) if files.is_empty() => Some(f),
            _ => None,
        },
        "head" | "tail" => {
            let v: Option<String> = match args.iter().map(|x| x.s.as_str()).collect::<Vec<_>>().as_slice() {
                [] => Some("10".into()),
                ["-n", v] | ["--lines", v] => Some(v.to_string()),
                [x] if x.starts_with("-n") => Some(x[2..].to_string()),
                [x] if x.starts_with("--lines=") => Some(x[8..].to_string()),
                [x] if x.len() > 1 && x.starts_with('-') && x[1..].chars().all(|c| c.is_ascii_digit()) => Some(x[1..].to_string()),
                _ => None,
            };
            let v = v?;
            if let Some(k) = v.strip_prefix('+') {
                return (p == "tail").then(|| k.parse().ok().map(Filt::TailFrom)).flatten();
            }
            let n: usize = v.parse().ok()?;
            Some(if p == "head" { Filt::Head(n) } else { Filt::Tail(n) })
        }
        "wc" if args.len() == 1 && args[0].s == "-l" => Some(Filt::WcL),
        _ => None,
    }
}

/// Every stage after the read as an exact filter, or None.
fn filters(rest: &[Stage]) -> Option<Vec<Filt>> {
    rest.iter().map(filt_of).collect()
}

/// The read with its pipe filters (the read alone when nothing follows), or None.
fn piped(src: ReadOp, rest: &[Stage]) -> Option<ReadOp> {
    if rest.is_empty() {
        return Some(src);
    }
    Some(ReadOp::Piped { src: Box::new(src), filters: filters(rest)? })
}

/// `grep RE F...` over indexed files (no recursion, no glob), possibly piped through exact filters.
fn grep_read(cx: &Cx, prog: &str, args: &[W], st0: &Stage, rest: &[Stage]) -> Option<ReadOp> {
    if !matches!(prog, "grep" | "egrep" | "fgrep") || st0.writes || st0.stdin.is_some() {
        return None;
    }
    let (filt, files) = filt_grep(prog, args)?;
    if files.is_empty() {
        return None;
    }
    let mut fs = vec![];
    for f in &files {
        let rel = cx.rel(f, Dialect::Posix).ok()?;
        cx.probe.file(&rel)?;
        fs.push((rel, f.s.clone()));
    }
    piped(ReadOp::Grep { files: fs, filt }, rest)
}

/// `sed -n` print scripts: ranges and the file words (None when any command is not a plain print).
fn sed_ranges(args: &[W]) -> Option<(Vec<(usize, usize)>, Vec<W>)> {
    let mut quiet = false;
    let mut scripts: Vec<String> = vec![];
    let mut files = vec![];
    let mut i = 0;
    while i < args.len() {
        let x = &args[i];
        i += 1;
        match x.s.as_str() {
            "-n" | "--quiet" | "--silent" => quiet = true,
            "-E" | "-r" | "--regexp-extended" | "-u" => {}
            "-e" => {
                scripts.push(args.get(i)?.s.clone());
                i += 1;
            }
            "-ne" | "-En" | "-nE" | "-rn" | "-nr" => {
                quiet = true;
                if x.s == "-ne" {
                    scripts.push(args.get(i)?.s.clone());
                    i += 1;
                }
            }
            s if s.starts_with('-') && s.len() > 1 => return None,
            _ => {
                if scripts.is_empty() && !args[..i - 1].iter().any(|w| w.s == "-e" || w.s == "-ne") {
                    scripts.push(x.s.clone());
                } else {
                    files.push(x.clone());
                }
            }
        }
    }
    if !quiet || scripts.is_empty() {
        return None;
    }
    let mut ranges = vec![];
    let mut quit: Option<usize> = None;
    static CMD: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^\s*(\d+|\$)(?:\s*,\s*(\d+|\$|\+\d+))?\s*([pq])\s*$").unwrap());
    for s in &scripts {
        for part in s.split([';', '\n']).filter(|p| !p.trim().is_empty()) {
            let c = CMD.captures(part)?;
            let num = |t: &str| -> Option<usize> { if t == "$" { Some(usize::MAX) } else { t.parse().ok() } };
            let a0 = num(&c[1])?;
            let b0 = match c.get(2).map(|m| m.as_str()) {
                None => a0,
                Some(t) if t.starts_with('+') => a0.checked_add(t[1..].parse().ok()?)?,
                Some(t) => num(t)?,
            };
            if &c[3] == "q" {
                if c.get(2).is_some() {
                    return None;
                }
                quit = Some(a0);
                continue;
            }
            if a0 == 0 {
                return None;
            }
            ranges.push((a0, if b0 < a0 { a0 } else { b0 }));
        }
    }
    // `q` after the last printed line changes nothing; earlier it would cut output
    if let Some(q) = quit {
        if ranges.iter().any(|r| r.1 > q) {
            return None;
        }
    }
    (!ranges.is_empty()).then_some((ranges, files))
}

fn sed_pl(cx: &Cx, args: &[W], st0: &Stage, rest: &[Stage]) -> Option<Seg> {
    let intent = "bash:sed-range";
    if args.iter().any(|x| x.s.starts_with("-i") || x.s == "--in-place") {
        return None; // a write
    }
    let Some((ranges, mut files)) = sed_ranges(args) else {
        return if args.iter().any(|x| x.s.contains('/')) { silent("bash:sed-pattern", "no-counterpart") } else { silent(intent, "sed-script") };
    };
    if files.is_empty() {
        match &st0.stdin {
            Some(f) if f.s != "-" => files.push(f.clone()),
            _ => return None, // a filter over piped data
        }
    }
    if files.len() != 1 {
        return silent(intent, "several-files");
    }
    let (rel, shown) = match cx.target(&files[0], Dialect::Posix) {
        Ok(x) => x,
        Err(e) => return silent(intent, e),
    };
    let Some(fr) = cx.probe.file(&rel) else { return silent(intent, "not-a-file") };
    let lines = fr.lines.max(0) as usize;
    // ranges past the end print nothing
    if ranges.iter().all(|r| r.0 != usize::MAX && r.0 > lines) {
        return silent(intent, "empty-range");
    }
    let tg: Vec<Arg> = ranges.iter().filter(|r| r.0 == usize::MAX || r.0 <= lines).map(|(x, y)| a(format!("{}:{}-{}", shown.s, x, if *y == usize::MAX { lines } else { (*y).min(lines.max(*x)) }))).collect();
    range_seg(intent, tg, rest, (st0.stdin.is_none() && !st0.writes).then(|| piped(ReadOp::Sed { file: rel, ranges }, rest)).flatten())
}

fn range_seg(intent: &str, targets: Vec<Arg>, rest: &[Stage], read: Option<ReadOp>) -> Option<Seg> {
    let (md, tail) = match mods(rest) {
        Ok(x) => x,
        Err(e) => return silent(intent, e),
    };
    let row = intent.rsplit(':').next().unwrap_or("sed-range");
    let row = if TABLE.iter().any(|r| r.0 == row) { row } else { "sed-range" };
    let mut tr = build(row, &HashMap::from([("TARGETS", targets), ("MODS", md)]));
    tr.tail = tail;
    Some(Seg { intent: intent.into(), tr: Some(tr), read, ..Default::default() })
}

fn headtail_pl(cx: &Cx, prog: &str, args: &[W], st0: &Stage, rest: &[Stage]) -> Option<Seg> {
    let intent = format!("bash:{prog}");
    let mut n: usize = 10;
    let mut from: Option<usize> = None;
    let mut all_but = false;
    let mut files = vec![];
    let mut i = 0;
    while i < args.len() {
        let x = &args[i].s;
        i += 1;
        let val = if x == "-n" || x == "--lines" {
            i += 1;
            Some(args.get(i - 1)?.s.clone())
        } else if let Some(v) = x.strip_prefix("--lines=") {
            Some(v.to_string())
        } else if let Some(v) = x.strip_prefix("-n") {
            Some(v.to_string())
        } else if x.starts_with('-') && x.len() > 1 && x[1..].chars().all(|c| c.is_ascii_digit()) {
            Some(x[1..].to_string())
        } else if x == "-q" || x == "--quiet" {
            None
        } else if x.starts_with('-') && x.len() > 1 {
            return if matches!(x.as_str(), "-f" | "-F" | "--follow") { silent("bash:tail-f", "log") } else { silent(&intent, format!("flag:{x}")) };
        } else {
            files.push(args[i - 1].clone());
            None
        };
        if let Some(v) = val {
            if let Some(k) = v.strip_prefix('+') {
                if prog != "tail" {
                    return silent(&intent, "flag");
                }
                from = Some(k.parse().ok()?);
            } else if let Some(k) = v.strip_prefix('-') {
                if prog != "head" {
                    return silent(&intent, "flag");
                }
                all_but = true;
                n = k.parse().ok()?;
            } else {
                n = v.parse().ok()?;
            }
        }
    }
    if files.is_empty() {
        match &st0.stdin {
            Some(f) if f.s != "-" => files.push(f.clone()),
            _ => return None, // a filter over piped data
        }
    }
    let mut tg = vec![];
    let mut read = None;
    for f in &files {
        let (rel, shown) = match cx.target(f, Dialect::Posix) {
            Ok(x) => x,
            Err(e) => return silent(&intent, e),
        };
        let Some(fr) = cx.probe.file(&rel) else { return silent(&intent, "not-a-file") };
        let l = fr.lines.max(0) as usize;
        let (x, y) = match (prog, from) {
            ("tail", Some(k)) => (k.max(1), l),
            ("tail", None) => (l.saturating_sub(n) + 1, l),
            (_, _) if all_but => (1, l.saturating_sub(n)),
            _ => (1, n.min(l.max(1))),
        };
        if y < x || l == 0 {
            return silent(&intent, "empty-range");
        }
        tg.push(a(format!("{}:{x}-{y}", shown.s)));
        if files.len() == 1 && st0.stdin.is_none() && !all_but {
            read = piped(
                match (prog, from) {
                    ("tail", Some(k)) => ReadOp::TailFrom { file: rel.clone(), k },
                    ("tail", None) => ReadOp::Tail { file: rel.clone(), n },
                    _ => ReadOp::Head { file: rel.clone(), n },
                },
                rest,
            );
        }
    }
    if files.len() > 1 {
        return silent(&intent, "several-files");
    }
    range_seg(&intent, tg, rest, read)
}

fn cat_pl(cx: &Cx, prog: &str, args: &[W], st0: &Stage, rest: &[Stage]) -> Option<Seg> {
    let intent = format!("bash:{prog}");
    if args.iter().any(|x| x.s.starts_with('-') && x.s != "-n") {
        return silent(&intent, "flag");
    }
    let mut files: Vec<W> = args.iter().filter(|x| !x.s.starts_with('-')).cloned().collect();
    if files.is_empty() {
        match &st0.stdin {
            Some(f) if f.s != "-" => files.push(f.clone()),
            _ => return None,
        }
    }
    // `cat F | grep X` / `cat F | head` / `cat F | sed -n` / `cat F | wc -l`: the same as the tool on F
    if files.len() == 1 && !rest.is_empty() {
        let mut st = rest[0].clone();
        st.stdin = Some(files[0].clone());
        let (p, _) = prog_at(&st);
        let r = &rest[1..];
        let seg = match p.as_str() {
            "grep" | "egrep" | "fgrep" => grep_pl(cx, &p, &words(&st)[1..], &st, r, Dialect::Posix, "bash"),
            "head" | "tail" => headtail_pl(cx, &p, &words(&st)[1..], &st, r),
            "sed" => sed_pl(cx, &words(&st)[1..], &st, r),
            "wc" if words(&st).len() == 2 && words(&st)[1].s == "-l" => files_only(cx, "bash:wc-l", "wc-l", &files, r, Dialect::Posix, Some("line counts")),
            _ => None,
        };
        if let Some(mut s) = seg {
            s.intent = format!("bash:cat|{}", s.intent.trim_start_matches("bash:"));
            // `cat F | <exact filters>`: the filters over F's bytes
            s.read = match cx.target(&files[0], Dialect::Posix) {
                Ok((rel, _)) if prog == "cat" && args.len() == 1 && st0.stdin.is_none() && cx.file_ok(&rel) => piped(ReadOp::Cat { files: vec![rel] }, rest),
                _ => None,
            };
            return Some(s);
        }
    }
    let mut shown = vec![];
    let mut rels = vec![];
    for f in &files {
        match cx.target(f, Dialect::Posix) {
            Ok((rel, s)) if cx.file_ok(&rel) => {
                shown.push(s);
                rels.push(rel);
            }
            Ok(_) => return silent(&intent, "not-a-file"),
            Err(e) => return silent(&intent, e),
        }
    }
    let (md, tail) = match mods(rest) {
        Ok(x) => x,
        Err(e) => return silent(&intent, e),
    };
    let mut tr = build("cat", &HashMap::from([("FILES", shown), ("MODS", md)]));
    tr.tail = tail;
    let exact = prog == "cat" && rest.is_empty() && !args.iter().any(|x| x.s == "-n" || x.glob) && st0.stdin.is_none();
    Some(Seg { intent, tr: Some(tr), read: exact.then_some(ReadOp::Cat { files: rels }), ..Default::default() })
}

// ------------------------------------------------------------------------------------------------ PowerShell

fn ps(cx: &Cx, pl: &Pipeline) -> Option<Seg> {
    let st0 = &pl.stages[0];
    let w = &st0.w;
    let cmd0 = w.first()?.s.to_ascii_lowercase();
    if matches!(cmd0.as_str(), "aix" | "aix.exe") || cmd0.ends_with("\\aix.exe") || cmd0.ends_with("/aix") {
        return Some(Seg { intent: "aix".into(), is_aix: true, ..Default::default() });
    }
    // (Get-Content F)[A..B] and (Get-Content F).Count: the reads `Get-Content F | Select-Object -Skip A -First N` and
    // `| Measure-Object -Line`
    if w.len() == 1 && pl.stages.len() == 1 && cmd0.starts_with('(') {
        let close = cmd0.rfind(')')?;
        let (inner, suf) = (&w[0].s[1..close], &cmd0[close + 1..]);
        let mut sub = parse_ps(inner);
        let gc = sub.first().and_then(|p| p.stages.first()).and_then(|s| s.w.first()).is_some_and(|x| matches!(x.s.to_ascii_lowercase().as_str(), "get-content" | "gc" | "cat" | "type"));
        if sub.len() != 1 || sub[0].stages.len() != 1 || !gc {
            return None;
        }
        let stage = |v: &[&str]| Stage { w: v.iter().map(|x| W { s: x.to_string(), ..Default::default() }).collect(), ..Default::default() };
        let tail = match suf.strip_prefix('[').and_then(|x| x.strip_suffix(']')).and_then(|x| x.split_once("..")) {
            Some((a, b)) => {
                let (a, b) = (a.trim().parse::<usize>().ok()?, b.trim().parse::<usize>().ok()?);
                stage(&["Select-Object", "-Skip", &a.to_string(), "-First", &(b.checked_sub(a)? + 1).to_string()])
            }
            None if matches!(suf, ".count" | ".length") => stage(&["Measure-Object", "-Line"]),
            None => return None,
        };
        sub[0].stages.push(tail);
        return ps(cx, &sub[0]);
    }
    let rest = &pl.stages[1..];
    // output saved to a file (`> out.txt`, `| Out-File x`, `| Set-Content x`): a write, not a lookup to steer
    if pl.stages.iter().any(|s| s.writes)
        || rest.iter().any(|s| s.w.first().is_some_and(|x| matches!(x.s.to_ascii_lowercase().as_str(), "out-file" | "set-content" | "add-content" | "tee-object" | "export-csv" | "tee")))
    {
        return None;
    }
    // named + positional parameters (PowerShell accepts unambiguous prefixes, case-insensitive)
    let params = |names: &[&str], switches: &[&str]| -> Result<(HashMap<String, W>, Vec<W>), String> {
        let mut named = HashMap::new();
        let mut pos = vec![];
        let mut i = 1;
        while i < w.len() {
            let x = &w[i];
            i += 1;
            if let Some(n) = x.s.strip_prefix('-').filter(|n| !n.is_empty() && n.chars().next().is_some_and(|c| c.is_alphabetic())) {
                let n = n.trim_end_matches(':').to_ascii_lowercase();
                if let Some(full) = switches.iter().find(|s| s.starts_with(&n)) {
                    named.insert(full.to_string(), W { s: "1".into(), ..Default::default() });
                } else if let Some(full) = names.iter().find(|s| s.starts_with(&n)) {
                    named.insert(full.to_string(), w.get(i).cloned().ok_or_else(|| format!("flag:-{n}"))?);
                    i += 1;
                } else {
                    return Err(format!("flag:-{n}"));
                }
            } else {
                pos.push(x.clone());
            }
        }
        Ok((named, pos))
    };
    let ps_rest = |rest: &[Stage]| -> Result<(Vec<Arg>, bool), String> {
        // Select-Object -First N -> --head N; Measure-Object -Line -> count
        let mut m = vec![];
        let mut count = false;
        for st in rest {
            let c = st.w[0].s.to_ascii_lowercase();
            let args: Vec<String> = st.w[1..].iter().map(|x| x.s.to_ascii_lowercase()).collect();
            match c.as_str() {
                "select-object" | "select" if args.len() == 2 && "-first".starts_with(&args[0]) && args[0].len() >= 2 => m.extend([a("--head"), a(&args[1])]),
                "measure-object" | "measure" if args.iter().all(|x| "-line".starts_with(x.as_str()) && x.len() >= 2) => count = true,
                "out-string" | "format-table" | "ft" | "out-host" => {}
                _ => return Err("pipe".into()),
            }
        }
        Ok((m, count))
    };
    match cmd0.as_str() {
        "select-string" | "sls" => {
            let intent = "ps:sls";
            let (named, pos) = match params(&["pattern", "path", "literalpath", "context", "include", "exclude", "encoding"], &["simplematch", "casesensitive", "notmatch", "list", "quiet", "allmatches", "raw"]) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            if named.contains_key("encoding") || named.contains_key("allmatches") || named.contains_key("raw") {
                return silent(intent, "flag");
            }
            let mut pos = pos.into_iter();
            let pat = named.get("pattern").cloned().or_else(|| pos.next())?;
            if pat.var || pat.s.contains(',') {
                return silent(intent, "pattern");
            }
            let path = named.get("path").or(named.get("literalpath")).cloned().or_else(|| pos.next());
            let Some(path) = path else { return None }; // pipeline input: data
            sls_to_grep(cx, intent, &named, pat, vec![path], false, rest, ps_rest)
        }
        "get-content" | "gc" | "cat" | "type" => {
            let intent = "ps:gc";
            let (named, pos) = match params(&["path", "totalcount", "head", "first", "tail", "last", "encoding", "readcount", "literalpath"], &["raw", "wait"]) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            if named.contains_key("wait") {
                return silent(intent, "log");
            }
            let f = named.get("path").or(named.get("literalpath")).cloned().or_else(|| pos.first().cloned())?;
            let (rel, shown) = match cx.target(&f, Dialect::Ps) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            let Some(fr) = cx.probe.file(&rel) else { return silent(intent, "not-a-file") };
            let l = fr.lines.max(0) as usize;
            let num = |k: &str| named.get(k).and_then(|x| x.s.parse::<usize>().ok());
            let mut range = if let Some(n) = num("totalcount").or(num("head")).or(num("first")) {
                Some((1, n.min(l)))
            } else {
                num("tail").or(num("last")).map(|n| (l.saturating_sub(n) + 1, l))
            };
            let mut rest = rest;
            // gc F | Select-Object -Skip K -First N / -First N / -Last N
            if let Some(st) = rest.first() {
                let c = st.w[0].s.to_ascii_lowercase();
                if matches!(c.as_str(), "select-object" | "select") {
                    let args: Vec<String> = st.w[1..].iter().map(|x| x.s.to_ascii_lowercase()).collect();
                    let get = |n: &str| args.iter().position(|x| x.len() >= 2 && n.starts_with(x.as_str())).and_then(|p| args.get(p + 1)).and_then(|v| v.parse::<usize>().ok());
                    let (skip, first, last) = (get("-skip").unwrap_or(0), get("-first"), get("-last"));
                    if args.iter().any(|x| x.starts_with('-') && !["-skip", "-first", "-last"].iter().any(|n| n.starts_with(x.as_str()))) {
                        return silent(intent, "flag");
                    }
                    range = match (first, last) {
                        (Some(n), _) => Some((skip + 1, (skip + n).min(l))),
                        (None, Some(n)) => Some((l.saturating_sub(n) + 1, l)),
                        _ => Some((skip + 1, l)),
                    };
                    rest = &rest[1..];
                } else if matches!(c.as_str(), "select-string" | "sls") {
                    // gc F | sls X == sls X F (line numbers aside)
                    let st2 = Stage { w: st.w.clone(), ..Default::default() };
                    let sub = Pipeline { stages: std::iter::once(st2).chain(rest[1..].iter().cloned()).collect(), sep: String::new() };
                    let mut s = ps(cx, &sub);
                    if let Some(s) = &mut s {
                        s.intent = "ps:gc|sls".into();
                    }
                    if s.as_ref().is_some_and(|s| s.tr.is_some()) {
                        return s;
                    }
                    let mut sub2 = sub.clone();
                    sub2.stages[0].w.push(f.clone());
                    return ps(cx, &sub2).map(|mut s| {
                        s.intent = "ps:gc|sls".into();
                        s
                    });
                } else if matches!(c.as_str(), "measure-object" | "measure") {
                    let mut tr = build("wc-l", &HashMap::from([("FILES", vec![shown])]));
                    tr.note = Some("Measure-Object -Line skips blank lines; aix counts every line like wc -l".into());
                    return Some(Seg { intent: "ps:gc|measure".into(), tr: Some(tr), ..Default::default() });
                }
            }
            let (md, _) = match ps_rest(rest) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            let tr = match range {
                Some((x, y)) if y >= x => build("sed-range", &HashMap::from([("TARGETS", vec![a(format!("{}:{x}-{y}", shown.s))]), ("MODS", md)])),
                Some(_) => return silent(intent, "empty-range"),
                None => build("cat", &HashMap::from([("FILES", vec![shown]), ("MODS", md)])),
            };
            Some(Seg { intent: intent.into(), tr: Some(tr), ..Default::default() })
        }
        "get-childitem" | "gci" | "ls" | "dir" => {
            let intent = "ps:gci";
            let (named, pos) = match params(&["path", "filter", "include", "exclude", "depth"], &["recurse", "file", "name", "force", "hidden", "directory", "attributes"]) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            if named.contains_key("force") || named.contains_key("hidden") || named.contains_key("directory") || named.contains_key("attributes") {
                return silent(intent, "flag");
            }
            let path = named.get("path").cloned().or_else(|| pos.first().cloned());
            let rec = named.contains_key("recurse");
            let mut preds = vec![];
            let mut names = vec![];
            for k in ["filter", "include"] {
                if let Some(v) = named.get(k) {
                    for n in v.s.split(',') {
                        preds.extend([a("-name"), a(n.trim())]);
                        names.push(n.trim().to_string());
                    }
                }
            }
            // gci -Recurse -Filter *.ts | Select-String X  ->  aix grep -i X --include '*.ts'
            if let Some(st) = rest.first().filter(|s| matches!(s.w[0].s.to_ascii_lowercase().as_str(), "select-string" | "sls")) {
                let sub = Pipeline { stages: std::iter::once(st.clone()).chain(rest[1..].iter().cloned()).collect(), sep: String::new() };
                let w2 = &sub.stages[0].w;
                let mut named2 = HashMap::new();
                let mut pat = None;
                let mut k = 1;
                while k < w2.len() {
                    let x = w2[k].s.to_ascii_lowercase();
                    if x.starts_with('-') {
                        let full = ["-pattern", "-simplematch", "-casesensitive", "-notmatch", "-list", "-context"].iter().find(|n| n.starts_with(&x) && x.len() >= 2).copied();
                        match full {
                            Some("-pattern") => {
                                pat = w2.get(k + 1).cloned();
                                k += 1;
                            }
                            Some("-context") => {
                                named2.insert("context".to_string(), w2.get(k + 1)?.clone());
                                k += 1;
                            }
                            Some(f) => {
                                named2.insert(f[1..].to_string(), W { s: "1".into(), ..Default::default() });
                            }
                            None => return silent("ps:gci|sls", "flag"),
                        }
                    } else if pat.is_none() {
                        pat = Some(w2[k].clone());
                    }
                    k += 1;
                }
                let pat = pat?;
                if !rec {
                    return silent("ps:gci|sls", "no-counterpart");
                }
                let paths = path.clone().map(|p| vec![p]).unwrap_or_default();
                let mut s = sls_to_grep(cx, "ps:gci|sls", &named2, pat, paths, true, &rest[1..], ps_rest)?;
                if let Some(tr) = &mut s.tr {
                    for n in names {
                        tr.stages[0].extend([a("--include"), a(n)]);
                    }
                }
                return Some(s);
            }
            let tp = match targets(cx, &path.into_iter().collect::<Vec<_>>(), Dialect::Ps) {
                Ok(t) => t,
                Err(e) => return silent(intent, e),
            };
            let (md, count) = match ps_rest(rest) {
                Ok(x) => x,
                Err(e) => return silent(intent, e),
            };
            let row = match (rec || !preds.is_empty(), count) {
                (_, true) => "find|wc-l",
                (true, false) => "find",
                (false, false) => "ls",
            };
            let tr = build(row, &HashMap::from([("ROOTS", tp.clone()), ("PATHS", tp), ("PREDS", preds), ("MODS", md)]));
            Some(Seg { intent: if rec { "ps:gci-r".into() } else { intent.into() }, tr: Some(tr), ..Default::default() })
        }
        "compare-object" | "diff" => {
            // Compare-Object (gc A) (gc B)
            let ws: Vec<&W> = w[1..].iter().filter(|x| !x.s.starts_with('-')).collect();
            if ws.len() != 2 {
                return silent("ps:compare-object", "no-counterpart");
            }
            let strip = |x: &W| -> Option<W> {
                let s = x.s.trim_start_matches('(').trim_end_matches(')');
                let mut it = s.split_whitespace();
                let c = it.next()?.to_ascii_lowercase();
                let f = it.next()?;
                (matches!(c.as_str(), "gc" | "get-content" | "cat" | "type") && it.next().is_none()).then(|| W { s: f.trim_matches(['\'', '"']).to_string(), ..Default::default() })
            };
            let (Some(x), Some(y)) = (strip(ws[0]), strip(ws[1])) else { return silent("ps:compare-object", "no-counterpart") };
            let (Ok((_, x)), Ok((_, y))) = (cx.target(&x, Dialect::Ps), cx.target(&y, Dialect::Ps)) else { return silent("ps:compare-object", "not-indexed") };
            let mut tr = build("diff", &HashMap::from([("A", vec![x]), ("B", vec![y])]));
            tr.note = Some("unified diff, not the <= / => SideIndicator shape".into());
            Some(Seg { intent: "ps:compare-object".into(), tr: Some(tr), ..Default::default() })
        }
        "convertfrom-json" | "group-object" | "sort-object" | "where-object" | "foreach-object" | "measure-object" => silent(&format!("ps:{cmd0}"), "no-counterpart"),
        // native tools from PowerShell read like cmd ones
        "findstr" | "find" | "fc" | "where" | "more" => cmdexe(cx, pl).map(|mut s| {
            s.intent = s.intent.replacen("cmd:", "ps:", 1);
            s
        }),
        // POSIX tools from PowerShell (git always; grep, sed, head ... when Git for Windows' usr\bin is on PATH) read
        // like Bash ones; only Bash gets deny answers (from_verdict), so these are steered, never answered
        "git" | "rg" | "grep" | "egrep" | "fgrep" | "sed" | "head" | "tail" | "wc" => posix(cx, pl).map(|mut s| {
            s.intent = s.intent.replacen("bash:", "ps:", 1);
            s
        }),
        _ => None,
    }
}

/// Select-String parameters -> aix grep. Case-insensitive by default: `-i` unless -CaseSensitive.
#[allow(clippy::too_many_arguments)]
fn sls_to_grep(
    cx: &Cx,
    intent: &str,
    named: &HashMap<String, W>,
    pat: W,
    paths: Vec<W>,
    recursive: bool,
    rest: &[Stage],
    ps_rest: impl Fn(&[Stage]) -> Result<(Vec<Arg>, bool), String>,
) -> Option<Seg> {
    let mut flags = vec![];
    if !named.contains_key("casesensitive") {
        flags.push(a("-i"));
    }
    if named.contains_key("notmatch") {
        flags.push(a("-v"));
    }
    if named.contains_key("list") {
        flags.extend([a("-m"), a("1")]);
    }
    if named.contains_key("quiet") {
        flags.push(a("-q"));
    }
    if let Some(c) = named.get("context") {
        let mut it = c.s.split(',');
        let b = it.next()?.trim().to_string();
        let af = it.next().map(|x| x.trim().to_string()).unwrap_or_else(|| b.clone());
        if b.parse::<u32>().ok()? > 30 || af.parse::<u32>().ok()? > 30 {
            return silent(intent, "flag:context>30");
        }
        flags.extend([a("-B"), a(b), a("-A"), a(af)]);
    }
    let fixed = named.contains_key("simplematch");
    // .NET regex: refuse constructs the Rust engine reads differently
    if !fixed && (pat.s.contains("(?<") || pat.s.contains("\\p{") && pat.s.contains("Is") || Regex::new(&pat.s).is_err()) {
        return silent(intent, "regex");
    }
    let mut tpaths = vec![];
    let mut includes = vec![];
    for p in &paths {
        // Select-String -Path *.ts (no recursion): a glob in the cwd
        if p.glob && !p.s.contains(['/', '\\']) {
            includes.push(p.s.clone());
            continue;
        }
        match cx.target(p, Dialect::Ps) {
            Ok((_, s)) => tpaths.push(Arg { s: s.s, raw: false }),
            Err(e) => return silent(intent, e),
        }
    }
    if paths.is_empty() || !includes.is_empty() {
        let r = cx.cwd_rel().ok_or("outside-repo").ok();
        if r.is_none_or(|r| !cx.probe.dir_has(&r)) {
            return silent(intent, "not-indexed");
        }
        if !recursive && !includes.is_empty() {
            flags.extend([a("--maxdepth"), a("1")]);
            return silent(intent, "no-counterpart"); // a non-recursive glob in one folder: aix grep recurses
        }
    }
    for inc in includes {
        flags.extend([a("--include"), a(inc)]);
    }
    let (md, count) = match ps_rest(rest) {
        Ok(x) => x,
        Err(e) => return silent(intent, e),
    };
    let mut pa = vec![];
    // Windows PowerShell 5.1 drops a `"` inside a native program's argument: the regex spells it \x22
    let quoted = pat.s.contains('"');
    if fixed && !quoted {
        pa.push(a("-F"));
    }
    if pat.s.starts_with('-') {
        pa.push(a("-e"));
    }
    pa.push(a(if !quoted { pat.s.clone() } else if fixed { regex::escape(&pat.s).replace('"', r"\x22") } else { pat.s.replace('"', r"\x22") }));
    let row = if count { "grep|wc-l" } else { "grep" };
    let mut tr = build(row, &HashMap::from([("FLAGS", flags), ("PAT", pa), ("PATHS", tpaths), ("MODS", md)]));
    tr.note = (!named.contains_key("casesensitive")).then(|| "Select-String ignores case by default; -i keeps that".to_string());
    Some(Seg { intent: if count { format!("{intent}|measure") } else { intent.to_string() }, tr: Some(tr), ..Default::default() })
}

// ------------------------------------------------------------------------------------------------ cmd.exe

fn cmdexe(cx: &Cx, pl: &Pipeline) -> Option<Seg> {
    let st0 = &pl.stages[0];
    let w = &st0.w;
    let c0 = base(&w.first()?.s).to_ascii_lowercase();
    if c0 == "aix" {
        return Some(Seg { intent: "aix".into(), is_aix: true, ..Default::default() });
    }
    let rest = &pl.stages[1..];
    if !rest.is_empty() {
        return silent(&format!("cmd:{c0}"), "pipe");
    }
    let sw = |x: &W| x.s.starts_with('/') && x.s.len() >= 2 && x.s.len() <= 4 && !x.s[1..].contains('/');
    match c0.as_str() {
        "findstr" => {
            let intent = "cmd:findstr";
            let mut flags = vec![];
            let (mut rec, mut lit, mut re, mut phrase) = (false, false, false, None::<String>);
            let mut pos = vec![];
            for x in &w[1..] {
                let l = x.s.to_ascii_lowercase();
                if let Some(p) = l.strip_prefix("/c:") {
                    let _ = p;
                    phrase = Some(x.s[3..].to_string());
                    continue;
                }
                if sw(x) || (x.s.starts_with('/') && x.s[1..].chars().all(|c| c.is_ascii_alphabetic()) && x.s.len() <= 6) {
                    for ch in l[1..].chars() {
                        match ch {
                            's' => rec = true,
                            'i' => flags.push(a("-i")),
                            'n' | 'p' | 'o' => {}
                            'r' => re = true,
                            'l' => lit = true,
                            'v' => flags.push(a("-v")),
                            'm' => flags.push(a("-l")),
                            'x' => flags.push(a("-x")),
                            'b' | 'e' => return silent(intent, format!("flag:/{ch}")),
                            _ => return silent(intent, format!("flag:/{ch}")),
                        }
                    }
                    continue;
                }
                if x.s.starts_with('/') && x.s.contains(':') {
                    return silent(intent, "flag");
                }
                pos.push(x.clone());
            }
            let pats: Vec<String> = match phrase {
                Some(p) => vec![p],
                None => {
                    if pos.is_empty() {
                        return None;
                    }
                    pos.remove(0).s.split(' ').filter(|s| !s.is_empty()).map(str::to_string).collect()
                }
            };
            // findstr's regex is a subset (`.` `*` `^` `$` `[]`); without /r or /l a metachar is ambiguous
            let meta = |p: &str| p.contains(['.', '*', '^', '$', '[', '\\']);
            let fixed = lit || (!re && !pats.iter().any(|p| meta(p)));
            if !fixed && !re {
                return silent(intent, "ambiguous");
            }
            if re && pats.iter().any(|p| p.contains(['|', '+', '?', '(', '{'])) {
                return silent(intent, "regex");
            }
            let pat = if pats.len() == 1 && fixed {
                pats[0].clone()
            } else {
                pats.iter().map(|p| if fixed { regex::escape(p) } else { p.clone() }).collect::<Vec<_>>().join("|")
            };
            let mut pa = vec![];
            if fixed && pats.len() == 1 {
                pa.push(a("-F"));
            }
            pa.push(a(pat));
            // file specs: a glob with /s -> --include; named files -> paths
            let mut tpaths = vec![];
            for f in &pos {
                if f.glob && !f.s.contains(['\\', '/']) {
                    if !rec {
                        return silent(intent, "no-counterpart");
                    }
                    flags.extend([a("--include"), a(&f.s)]);
                    continue;
                }
                match cx.target(f, Dialect::Cmd) {
                    Ok((_, s)) => tpaths.push(Arg { s: s.s, raw: false }),
                    Err(e) => return silent(intent, e),
                }
            }
            if pos.is_empty() {
                return None; // reads stdin
            }
            if tpaths.is_empty() {
                let r = cx.cwd_rel();
                if r.is_none_or(|r| !cx.probe.dir_has(&r)) {
                    return silent(intent, "not-indexed");
                }
            }
            let tr = build("grep", &HashMap::from([("FLAGS", flags), ("PAT", pa), ("PATHS", tpaths)]));
            Some(Seg { intent: intent.into(), tr: Some(tr), ..Default::default() })
        }
        "type" | "more" => {
            let files: Vec<&W> = w[1..].iter().filter(|x| !sw(x) && !x.s.starts_with('+')).collect();
            if files.len() != w.len() - 1 || files.is_empty() {
                return silent(&format!("cmd:{c0}"), "flag");
            }
            let mut shown = vec![];
            for f in files {
                match cx.target(f, Dialect::Cmd) {
                    Ok((rel, s)) if cx.file_ok(&rel) => shown.push(Arg { s: s.s, raw: false }),
                    Ok(_) => return silent(&format!("cmd:{c0}"), "not-a-file"),
                    Err(e) => return silent(&format!("cmd:{c0}"), e),
                }
            }
            Some(Seg { intent: format!("cmd:{c0}"), tr: Some(build("cat", &HashMap::from([("FILES", shown)]))), ..Default::default() })
        }
        "dir" => {
            let intent = "cmd:dir";
            let mut rec = false;
            let mut bare = false;
            let mut pos = vec![];
            for x in &w[1..] {
                match x.s.to_ascii_lowercase().as_str() {
                    "/s" => rec = true,
                    "/b" => bare = true,
                    s if s.starts_with('/') => return silent(intent, format!("flag:{s}")),
                    _ => pos.push(x.clone()),
                }
            }
            if !bare {
                return silent(intent, "no-counterpart");
            }
            let mut roots = vec![];
            let mut preds = vec![];
            for p in pos {
                if p.glob {
                    let s = p.s.replace('\\', "/");
                    let (d, n) = s.rsplit_once('/').map(|(d, n)| (Some(d.to_string()), n.to_string())).unwrap_or((None, s.clone()));
                    preds.extend([a("-name"), a(n)]);
                    if let Some(d) = d {
                        roots.push(W { s: d, ..Default::default() });
                    }
                } else {
                    roots.push(p);
                }
            }
            let tr_roots = match targets(cx, &roots, Dialect::Cmd) {
                Ok(t) => t,
                Err(e) => return silent(intent, e),
            };
            let row = if rec { "find" } else { "ls" };
            let tr = build(row, &HashMap::from([("ROOTS", tr_roots.clone()), ("PATHS", tr_roots), ("PREDS", preds)]));
            Some(Seg { intent: if rec { "cmd:dir-s".into() } else { intent.into() }, tr: Some(tr), ..Default::default() })
        }
        "find" => {
            // cmd find: a fixed-string line filter (`find /c "x" F`); never aix find
            let intent = "cmd:find";
            let mut flags = vec![];
            let mut pos = vec![];
            for x in &w[1..] {
                match x.s.to_ascii_lowercase().as_str() {
                    "/c" => flags.push(a("-c")),
                    "/v" => flags.push(a("-v")),
                    "/i" => flags.push(a("-i")),
                    "/n" => {}
                    s if s.starts_with('/') && s.len() <= 3 => return silent(intent, format!("flag:{s}")),
                    _ => pos.push(x.clone()),
                }
            }
            if pos.len() < 2 {
                return None;
            }
            let pat = pos.remove(0);
            let mut tp = vec![];
            for f in &pos {
                match cx.target(f, Dialect::Cmd) {
                    Ok((rel, s)) if cx.file_ok(&rel) => tp.push(Arg { s: s.s, raw: false }),
                    Ok(_) => return silent(intent, "not-a-file"),
                    Err(e) => return silent(intent, e),
                }
            }
            let tr = build("grep", &HashMap::from([("FLAGS", flags), ("PAT", vec![a("-F"), a(pat.s)]), ("PATHS", tp)]));
            Some(Seg { intent: intent.into(), tr: Some(tr), ..Default::default() })
        }
        "fc" => {
            let f: Vec<&W> = w[1..].iter().filter(|x| !sw(x)).collect();
            if f.len() != 2 || w[1..].iter().any(|x| sw(x) && !matches!(x.s.to_ascii_lowercase().as_str(), "/n")) {
                return silent("cmd:fc", "flag");
            }
            let (Ok((_, x)), Ok((_, y))) = (cx.target(f[0], Dialect::Cmd), cx.target(f[1], Dialect::Cmd)) else { return silent("cmd:fc", "not-indexed") };
            let mut tr = build("diff", &HashMap::from([("A", vec![Arg { s: x.s, raw: false }]), ("B", vec![Arg { s: y.s, raw: false }])]));
            tr.note = Some("unified diff, not fc's ***** blocks".into());
            Some(Seg { intent: "cmd:fc".into(), tr: Some(tr), ..Default::default() })
        }
        "where" => {
            // `where /r DIR pattern`; a PATH lookup (`where git`) is not a repo question
            let r = w.iter().position(|x| x.s.eq_ignore_ascii_case("/r"))?;
            let dir = w.get(r + 1)?;
            let pat = w.get(r + 2)?;
            let tr_roots = match targets(cx, std::slice::from_ref(dir), Dialect::Cmd) {
                Ok(t) => t,
                Err(e) => return silent("cmd:where", e),
            };
            let tr = build("find", &HashMap::from([("ROOTS", tr_roots), ("PREDS", vec![a("-name"), a(&pat.s)])]));
            Some(Seg { intent: "cmd:where".into(), tr: Some(tr), ..Default::default() })
        }
        _ => None,
    }
}

// ------------------------------------------------------------------------------------------------ rendering

/// Expand a table row.
fn build(row: &str, m: &HashMap<&str, Vec<Arg>>) -> Tr {
    let t = template(row);
    let mut stages: Vec<Vec<Arg>> = vec![vec![]];
    for tok in t.split(' ').filter(|s| !s.is_empty()) {
        if tok == "|" {
            stages.push(vec![]);
            continue;
        }
        let cur = stages.last_mut().unwrap();
        if let Some(name) = tok.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            if let Some(v) = m.get(name) {
                cur.extend(v.iter().cloned());
            }
            continue;
        }
        // scalars inside a token (`{F}:{A}-{B}`)
        let mut s = tok.to_string();
        for (k, v) in m {
            let key = format!("{{{k}}}");
            if s.contains(&key) {
                s = s.replace(&key, &v.iter().map(|x| x.s.clone()).collect::<Vec<_>>().join(" "));
            }
        }
        if !s.is_empty() {
            cur.push(a(s));
        }
    }
    Tr { stages, ..Default::default() }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Quote {
    Posix,
    Ps,
}

fn plain(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:,=+@%".contains(c))
}

fn q(arg: &Arg, qt: Quote) -> String {
    if arg.raw || plain(&arg.s) {
        return arg.s.clone();
    }
    match qt {
        Quote::Posix => sh_quote(&arg.s),
        Quote::Ps => format!("'{}'", arg.s.replace('\'', "''")),
    }
}

/// A word inside an in-call pipe string (`aix '...'`): plain, or double-quoted; None when it cannot be written
/// there (a single quote, a backslash-escape, an expansion, a shell glob).
fn inner(arg: &Arg) -> Option<String> {
    if arg.raw {
        return None;
    }
    if plain(&arg.s) {
        return Some(arg.s.clone());
    }
    (!arg.s.contains(['\'', '"', '\\', '$', '`', '!', '\n'])).then(|| format!("\"{}\"", arg.s))
}

fn stage_inner(st: &[Arg]) -> Option<String> {
    st.iter().map(inner).collect::<Option<Vec<_>>>().map(|v| v.join(" "))
}

/// One translation as a runnable line.
pub fn render(tr: &Tr, qt: Quote, prefix: &str) -> String {
    if let Some(l) = &tr.literal {
        return l.clone();
    }
    let line = if tr.stages.len() == 1 {
        format!("{prefix} {}", tr.stages[0].iter().map(|x| q(x, qt)).collect::<Vec<_>>().join(" "))
    } else if let Some(v) = tr.stages.iter().map(|s| stage_inner(s)).collect::<Option<Vec<_>>>() {
        format!("{prefix} {}", q(&a(v.join(" | ")), qt))
    } else {
        // separate processes: rows flow through `--bare` and `-`
        tr.stages
            .iter()
            .enumerate()
            .map(|(k, s)| {
                let mut s: Vec<String> = s.iter().map(|x| q(x, qt)).collect();
                if k + 1 < tr.stages.len() {
                    s.push("--bare".into());
                }
                format!("{prefix} {}", s.join(" "))
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    match &tr.tail {
        Some(t) if tr.stages.len() == 1 => format!("{line} --bare | {t}"),
        Some(t) => format!("{line} | {t}"),
        None => line,
    }
}

/// Several translations as ONE line: `aix 'a ; b | c'` when every word fits the in-call string, else the separate
/// lines joined with `; `.
pub fn render_all(trs: &[&Tr], qt: Quote, prefix: &str) -> String {
    if trs.len() == 1 {
        return render(trs[0], qt, prefix);
    }
    if trs.iter().all(|t| t.tail.is_none() && t.literal.is_none()) {
        let parts: Option<Vec<String>> = trs.iter().map(|t| t.stages.iter().map(|s| stage_inner(s)).collect::<Option<Vec<_>>>().map(|v| v.join(" | "))).collect();
        if let Some(p) = parts {
            return format!("{prefix} {}", q(&a(p.join(" ; ")), qt));
        }
    }
    trs.iter().map(|t| render(t, qt, prefix)).collect::<Vec<_>>().join("; ")
}

/// The aix argv of a translation's first stage (for tests and the event log).
#[cfg(test)]
pub fn first_argv(tr: &Tr) -> Vec<String> {
    tr.stages[0].iter().map(|x| x.s.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    struct P;
    impl Probe for P {
        fn file(&self, rel: &str) -> Option<FileRow> {
            ["src/a.ts", "src/b.ts", "src/big.java", "README.md", "docs/x.md"].contains(&rel).then_some(FileRow { lines: if rel.ends_with("big.java") { 900 } else { 50 }, bytes: 1, mtime_ns: 1 })
        }
        fn dir_has(&self, rel: &str) -> bool {
            rel.is_empty() || rel == "src" || rel == "docs"
        }
        fn under(&self, rel: &str, _: usize) -> Vec<String> {
            ["src/a.ts", "src/b.ts", "src/big.java", "README.md", "docs/x.md"].iter().filter(|p| rel.is_empty() || p.starts_with(&format!("{rel}/"))).map(|s| s.to_string()).collect()
        }
    }
    fn line(cmd: &str) -> String {
        let p = P;
        let mut cx = Cx::new(Path::new("/r"), Some(Path::new("/r")), &p);
        let v = evaluate(&mut cx, cmd, Dialect::Posix);
        let trs: Vec<&Tr> = v.segs.iter().filter_map(|s| s.tr.as_ref()).collect();
        if trs.is_empty() {
            return format!("silent:{}", v.segs.iter().map(|s| s.reason.clone()).collect::<Vec<_>>().join(","));
        }
        render_all(&trs, Quote::Posix, "aix")
    }
    #[test]
    fn basics() {
        assert_eq!(line("tail -n 20 src/big.java"), "aix code src/big.java:881-900");
        assert_eq!(line("sed -n '10,40p' src/a.ts"), "aix code src/a.ts:10-40");
        assert_eq!(line("grep -rn foo src | wc -l"), "aix grep -c --total foo src");
        assert_eq!(line("grep -n foo /etc/passwd"), "silent:outside-repo");
        assert_eq!(line("grep -n X src/a.ts; sed -n 10,40p src/a.ts"), "aix 'grep X src/a.ts ; code src/a.ts:10-40'");
        assert!(glob_re("src/**/*.ts").unwrap().is_match("src/a/b.ts"));
        assert!(glob_re("src/**/*.ts").unwrap().is_match("src/b.ts"));
        assert!(!glob_re("*.ts").unwrap().is_match("src/b.ts"));
    }
}
