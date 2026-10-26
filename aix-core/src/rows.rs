//! Typed rows: the one shape every command that reads `-` (stdin) or runs as a pipe stage works on.
//!
//! # Stable API (other modules rely on exactly this)
//!
//! ```text
//! enum Row { Hit{path,line,text}, File{path}, Range{path,a,b}, Count{key,n}, Text{line} }
//! struct Meta { kind, text, ..Default::default() }                 one per row (parallel vector): answer kind and a range's description
//! struct Rows { rows, meta, unknown, redacted, truncated, partial, bytes }
//!
//! parse_text(text, ix) -> Rows               pure parser of any accepted input (below)
//! parse_stdin(ix) -> Result<Rows, String>    the `-` input: rows injected by an in-call pipe, else the process stdin
//!                                            (CLI only, 8 MB cap); Err = no input (a TTY, MCP) -> exit status 2
//! has_dash(args) / is_dash(tok)              does an argument list name `-` (before any `--`)
//! with_input(rows, f)                        run f with `rows` as the `-` input (pipes use it for the next stage)
//! allow_process_stdin()                      the CLI calls it once; MCP never does (its stdin is the protocol)
//! Rows::from_out(cmd, &Out)                  rows of an existing command's answer: aix/v1 cites, else hits, else lines
//! Row::bare(&Meta) / Rows::bare_lines()      the `--bare` rendering: `path:line:text`, `path`, `path:A-B[:text]`,
//!                                            `path:N` (per-file count), `N<TAB>key` (group), plain text
//! Row::path() / Row::render()                the file a row names; the GNU-shaped text that cut/sort/uniq/filter see
//! ```
//!
//! Data sets (`@name`, `@name/item`): a row's path may be a set reference (`@gate/1:120:text` is line 120 of item 1
//! of set `gate`); the parser keeps it as written (never resolved against the index). The set store plugs in as a
//! row source without touching this module's internals:
//!
//! ```text
//! trait SetSource { fn rows(&self, ix: &Index, spec: &str) -> Option<Result<Rows, String>>; }
//! register_source(Box<dyn SetSource>)        once at startup (or lazily) by the store
//! set_rows(ix, "@gate/1") -> Option<..>      None: no source knows the name; `files`, `count`, `filter` and pipe
//!                                            stages (`aix '@gate | count by field 3'`) read sets through it
//! is_set_ref(word)                           `@name[/item]`
//! ```
//!
//! Accepted input, line by line (CRLF ok, at most [`MAX_INPUT`] bytes, every line redacted on read):
//! - aix decorated output: `== ...` headers (a header naming `path[:A-B]` gives the path of the `N text` rows of
//!   `aix code` and the `L12-30 ...` rows of `aix outline` below it), two-space indented rows `path:line: text`,
//!   `path: N` counts, `   N  key` groups, `[kind] path:line text` (find), `path:line name (conf)` (callers);
//!   `(...)` notes and labels, `…` footers, `--` separators and `path-12- ` context lines are decoration (skipped).
//! - aix `--jsonl` / `--json` lines: `{"file","line","kind","text"}` hits, `{"answers":[{cites:[{file,line,end}]}]}`
//!   envelopes, `{"summary":...}` (skipped).
//! - GNU grep / rg / git grep: `path:line:text`, `path:line:col:text` (rg --column), `path:N` (grep -c / rg -c),
//!   `path-line-text` context (skipped); `path:A-B`; bare paths (rg --files, git diff --name-only, ls -1);
//!   Windows `C:\repo\a.rs:12:text` (the drive colon is not a separator; `\` becomes `/`).
//! - anything else is a `Text` row (what `filter` works on) and is counted in `unknown` for consumers that need a
//!   location.
//!
//! Paths are normalised with `opts::resolve_path` when an index is given (`./x`, `x\y`, the repo's absolute prefix,
//! a path below the working subdirectory); a path that is not indexed is kept as written (cleaned).

use std::cell::RefCell;
use std::io::{IsTerminal, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, OnceLock};

use regex::Regex;
use serde_json::Value;

use crate::index::Index;
use crate::query::Out;

/// The most bytes read from stdin (the rest is dropped and the answer says so).
pub const MAX_INPUT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    /// a location with its line text (`text` may be empty)
    Hit { path: String, line: usize, text: String },
    /// a file (a directory ends with `/`)
    File { path: String },
    /// a line range of a file (a member, a hunk)
    Range { path: String, a: usize, b: usize },
    /// a count: per file (`grep -c`, key = path) or per group (meta.kind = "group")
    Count { key: String, n: u64 },
    /// a line that names no location (logs, build output, prose)
    Text { line: String },
}

/// What a row carries besides its shape: the answer kind (`caller`, `member`, `endpoint`, `grep`, `group`, ...) and,
/// for a range, its description (`fn save(...)`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub kind: String,
    pub text: String,
    /// the input line as it came (stdin in GNU shape): `render` gives it back byte for byte (sort, uniq, filter)
    pub raw: String,
    /// named fields of a data-set row (`field NAME` in dedup / count / --where read them first)
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Rows {
    pub rows: Vec<Row>,
    /// parallel to `rows`
    pub meta: Vec<Meta>,
    /// lines that were not a location (they are `Text` rows)
    pub unknown: usize,
    /// lines the redactor changed (they show `***` and must never be used as edit anchors)
    pub redacted: usize,
    /// the input was longer than MAX_INPUT and was cut
    pub truncated: bool,
    /// a budget or row ceiling cut the stream short somewhere upstream: why (carried to the end of a pipe)
    pub partial: Option<String>,
    /// input bytes read
    pub bytes: usize,
    /// lines in the whole input when only part of it became rows (a cut stdin): `count -` reports this total
    pub lines_total: Option<usize>,
}

impl Row {
    pub fn path(&self) -> Option<&str> {
        match self {
            Row::Hit { path, .. } | Row::File { path } | Row::Range { path, .. } => Some(path),
            Row::Count { key, .. } => Some(key).filter(|k| looks_path(k) || spaced_path_key(k)).map(|s| s.as_str()),
            Row::Text { .. } => None,
        }
    }
    /// The line number (a range: its first line).
    pub fn line(&self) -> Option<usize> {
        match self {
            Row::Hit { line, .. } => Some(*line),
            Row::Range { a, .. } => Some(*a),
            _ => None,
        }
    }
    /// GNU-shaped text: what `cut`, `sort`, `uniq`, `filter --grep` and `count by field` see.
    pub fn render(&self, m: &Meta) -> String {
        if !m.raw.is_empty() {
            return m.raw.clone();
        }
        self.bare(m)
    }
    /// `--bare` form of one row.
    pub fn bare(&self, m: &Meta) -> String {
        match self {
            Row::Hit { path, line, text } => format!("{path}:{line}:{text}"),
            Row::File { path } => path.clone(),
            Row::Range { path, a, b } if m.text.is_empty() => format!("{path}:{a}-{b}"),
            Row::Range { path, a, b } => format!("{path}:{a}-{b}:{}", m.text),
            Row::Count { key, n } if matches!(m.kind.as_str(), "group" | "norm") => format!("{n}\t{key}"),
            // `uniq -c` prints exactly as GNU uniq
            Row::Count { key, n } if m.kind == "uniq" => format!("{n:>7} {key}"),
            Row::Count { key, n } => format!("{key}:{n}"),
            Row::Text { line } => line.clone(),
        }
    }
}

impl Rows {
    pub fn push(&mut self, r: Row, m: Meta) {
        self.rows.push(r);
        self.meta.push(m);
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Row, &Meta)> {
        self.rows.iter().zip(self.meta.iter())
    }
    pub fn bare_lines(&self) -> Vec<String> {
        self.iter().map(|(r, m)| r.bare(m)).collect()
    }
    /// Rows that name a file (hits, files, ranges, per-file counts).
    pub fn located(&self) -> usize {
        self.rows.iter().filter(|r| r.path().is_some()).count()
    }
    /// Keep the rows for which `f` holds.
    pub fn retain(&mut self, mut f: impl FnMut(&Row, &Meta) -> bool) {
        let (rows, meta): (Vec<Row>, Vec<Meta>) = std::mem::take(&mut self.rows).into_iter().zip(std::mem::take(&mut self.meta)).filter(|(r, m)| f(r, m)).unzip();
        self.rows = rows;
        self.meta = meta;
    }
    /// The rows of an existing command's answer, from its structured data: the aix/v1 envelope's cited answers,
    /// else the JSON hits when they are per-row (grep, symbol, find), else the printed lines (code, outline, counts).
    pub fn from_out(cmd: &str, out: &Out, ix: Option<&Index>) -> Rows {
        let mut r = Rows::default();
        if let Some(v1) = &out.v1 {
            if let Some(ans) = v1.get("answers").and_then(|a| a.as_array()) {
                for a in ans {
                    push_answer(&mut r, a);
                }
                if !r.is_empty() {
                    return r;
                }
            }
        }
        // `code` has one hit for the whole block, `grep -c` / `-l` hits are the lines: the printed rows are exact there
        let per_row_hits = matches!(cmd, "symbol" | "find" | "ask" | "text" | "endpoint" | "script" | "feature" | "bugs" | "qa" | "history" | "tasks" | "hints")
            || (cmd == "grep" && !out.lines.iter().any(|l| COUNT_LINE.is_match(l)) && out.hits.len() >= out.lines.iter().filter(|l| crate::plan::is_row(l)).count());
        if per_row_hits && !out.hits.is_empty() {
            for h in &out.hits {
                push_hit_json(&mut r, h);
            }
            return r;
        }
        let mut p = parse_answer(&out.lines.join("\n"), ix);
        p.rows.iter().zip(p.meta.iter_mut()).for_each(|(_, m)| {
            if m.kind.is_empty() {
                m.kind = cmd.to_string();
            }
        });
        p.redacted = 0; // already redacted output
        p
    }
}

fn push_answer(r: &mut Rows, a: &Value) {
    let kind = a.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
    let text = a.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let Some(cites) = a.get("cites").and_then(|c| c.as_array()).filter(|c| !c.is_empty()) else { return };
    for c in cites {
        let Some(f) = c.get("file").and_then(|f| f.as_str()).filter(|f| !f.is_empty()) else { continue };
        let line = c.get("line").and_then(|l| l.as_u64()).unwrap_or(0) as usize;
        let end = c.get("end").and_then(|l| l.as_u64()).unwrap_or(line as u64) as usize;
        let desc = strip_loc(&text, f);
        if line == 0 {
            r.push(Row::File { path: f.to_string() }, Meta { kind: kind.clone(), text: desc, ..Default::default() });
        } else if end > line {
            r.push(Row::Range { path: f.to_string(), a: line, b: end }, Meta { kind: kind.clone(), text: desc, ..Default::default() });
        } else {
            r.push(Row::Hit { path: f.to_string(), line, text: desc }, Meta { kind: kind.clone(), text: String::new(), ..Default::default() });
        }
    }
}

fn push_hit_json(r: &mut Rows, h: &Value) {
    let Some(f) = h.get("file").and_then(|f| f.as_str()).filter(|f| !f.is_empty()) else { return };
    let line = h.get("line").and_then(|l| l.as_u64()).unwrap_or(0) as usize;
    let kind = h.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string();
    let mut text = h.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
    if kind == "endpoint" {
        // an endpoint row in a pipe keeps what its card says: `GET /api/x roles=a,b scripts=s.py`
        let list = |k: &str| h.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",")).unwrap_or_default();
        let roles = list("roles");
        text.push_str(&format!(" roles={}", if roles.is_empty() { "(none declared)" } else { roles.as_str() }));
        for k in ["clients", "scripts"] {
            let v = list(k);
            if !v.is_empty() {
                text.push_str(&format!(" {k}={v}"));
            }
        }
    }
    if line == 0 {
        r.push(Row::File { path: f.to_string() }, Meta { kind, text, ..Default::default() });
    } else {
        r.push(Row::Hit { path: f.to_string(), line, text }, Meta { kind, text: String::new(), ..Default::default() });
    }
}

/// `path:12-30 defined: fn x` -> `defined: fn x`; `L12-30 fn x` -> `fn x` (the location is in the row already).
fn strip_loc(text: &str, file: &str) -> String {
    static LEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:L\d+(?:-\d+)?\s+|\[\w+\]\s+)").unwrap());
    let t = text.trim();
    let t = match t.strip_prefix(file) {
        Some(rest) => {
            let rest = rest.trim_start_matches(|c: char| c == ':' || c == '-' || c.is_ascii_digit());
            rest.trim_start()
        }
        None => t,
    };
    LEAD.replace(t, "").trim().to_string()
}

/// `@name` or `@name/item` (a data set reference).
pub fn is_set_ref(s: &str) -> bool {
    static SET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^@[A-Za-z0-9_][\w.-]*(?:/[^\s:]*)?$").unwrap());
    SET.is_match(s)
}

/// A plug-in row source for `@name[/item]` references (the data-set store registers one).
pub trait SetSource: Send + Sync {
    /// The rows of `spec` (`@name` or `@name/item`); None when this source does not know the name.
    fn rows(&self, ix: &Index, spec: &str) -> Option<Result<Rows, String>>;
    /// The named fields of one row of a set (`@name[/item]`, line N), when the source keeps records.
    fn fields(&self, _ix: &Index, _cite: &str, _line: usize) -> Option<Vec<(String, String)>> {
        None
    }
}

static SOURCES: std::sync::RwLock<Vec<Box<dyn SetSource>>> = std::sync::RwLock::new(Vec::new());

/// Register a set source (asked in registration order).
pub fn register_source(s: Box<dyn SetSource>) {
    if let Ok(mut v) = SOURCES.write() {
        v.push(s);
    }
}

/// The named fields of row `line` of set `cite` (a row that came from a set, e.g. through another command's answer).
pub fn set_fields(ix: &Index, cite: &str, line: usize) -> Option<Vec<(String, String)>> {
    let v = SOURCES.read().ok()?;
    v.iter().find_map(|s| s.fields(ix, cite, line))
}

/// The rows of a set reference, from the first source that knows it (None: unknown everywhere).
pub fn set_rows(ix: &Index, spec: &str) -> Option<Result<Rows, String>> {
    let v = SOURCES.read().ok()?;
    v.iter().find_map(|s| s.rows(ix, spec))
}

/// A group key that is a path with spaces (`docs/my notes.md` from a grep grouped by file): a directory part
/// without blanks, a file name with an extension.
fn spaced_path_key(k: &str) -> bool {
    static K: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s:/][^\s:]*/[^:\t]*[^\s:]\.[A-Za-z0-9_]{1,10}$").unwrap());
    !k.contains("  ") && K.is_match(k)
}

fn looks_path(s: &str) -> bool {
    is_set_ref(s) || !s.is_empty() && !s.contains(char::is_whitespace) && (s.contains('/') || s.contains('\\') || EXT.is_match(s))
}

static EXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^\s:]*\.[A-Za-z0-9_]{1,10}$").unwrap());
/// a path: no colon except a Windows drive prefix, no whitespace (at least one `.`, `/` or `\` checked by looks_path)
const PATH: &str = r"(?:[A-Za-z]:[\\/])?[^\s:]+";
/// `path:line[:col]:text` (GNU / rg / git grep, aix decorated with `: `), `path:line text` (callers), `path:A-B rest`
static HIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^(?P<p>{PATH}):(?P<l>\d{{1,9}})(?:-(?P<b>\d{{1,9}}))?(?:(?::(?P<c>\d{{1,6}}))?:(?P<t>.*)|(?P<s>\s.*))?$")).unwrap());
/// `path: N` (aix -c) / `path:N` is matched by HIT without text: a count when the source says so
static COUNT_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^\s*(?P<p>{PATH}): (?P<n>\d+)$")).unwrap());
/// `   12  key` (aix --group-by / count) or `     12 key` (uniq -c)
static GROUP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:\s+(?P<n>\d+)  |(?P<m>\d+)\t)(?P<k>\S.*)$").unwrap());
/// `path-12-text` GNU context line; `  path-12- text` aix context line
static CTX: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!(r"^(?:{PATH})-\d+-")).unwrap());
/// `== ... path:A-B ...` / `== outline path (...)`
static HEAD_LOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?P<p>[\w@.+\-/\\]+\.[A-Za-z0-9_]{1,10})(?::(?P<a>\d+)(?:-(?P<b>\d+))?)?").unwrap());
/// `40 text` (aix code) and `L12-30 text` (aix outline) under a header
static NUMBERED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?P<n>\d{1,9})(?: (?P<t>.*))?$").unwrap());
static OUTLINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^L(?P<a>\d+)-(?P<b>\d+) (?P<t>.*)$").unwrap());
/// `[kind] path:line rest` (aix find)
static KINDED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[(?P<k>[\w-]+)\] (?P<rest>.*)$").unwrap());

thread_local! {
    static MEMO: RefCell<(std::path::PathBuf, std::collections::HashMap<String, String>)> = RefCell::new(Default::default());
}

/// Forget the path lookups of `norm` (each top-level call starts fresh: the index may have changed in between).
pub fn clear_memo() {
    MEMO.with(|m| m.borrow_mut().1.clear());
}

/// Normalise one path spelling: `\` -> `/`, the repo's absolute prefix (also a Windows one) dropped, `./` dropped,
/// then the indexed path it means when an index is given.
pub fn norm(p: &str, ix: Option<&Index>) -> String {
    if is_set_ref(p) {
        return p.to_string();
    }
    let mut s = p.replace('\\', "/");
    if let Some(ix) = ix {
        let root = ix.repo.to_string_lossy().replace('\\', "/");
        let root = root.trim_end_matches('/');
        if !root.is_empty() {
            if let Some(r) = s.strip_prefix(&format!("{root}/")) {
                s = r.to_string();
            } else if s.len() > 2 && s.as_bytes()[1] == b':' {
                // `C:/work/repo/a.rs` on a Windows-shaped path: drop the drive, then the repo prefix by its name
                let name = root.rsplit('/').next().unwrap_or("");
                if let Some(i) = s.find(&format!("/{name}/")).filter(|_| !name.is_empty()) {
                    s = s[i + name.len() + 2..].to_string();
                }
            }
        }
        // one lookup per distinct path (8 MB of rows name the same files again and again)
        if let Some(hit) = MEMO.with(|m| {
            let m = m.borrow();
            (m.0 == ix.db_path).then(|| m.1.get(&s).cloned()).flatten()
        }) {
            return hit;
        }
        let v = crate::opts::resolve_path(ix, &s).unwrap_or_else(|| crate::opts::clean_path(&s));
        MEMO.with(|m| {
            let mut m = m.borrow_mut();
            if m.0 != ix.db_path || m.1.len() > 100_000 {
                m.0 = ix.db_path.clone();
                m.1.clear();
            }
            m.1.insert(s.clone(), v.clone());
        });
        return v;
    }
    crate::opts::clean_path(&s)
}

/// Parse one block of text into rows (see the module doc for the accepted forms).
pub fn parse_text(text: &str, ix: Option<&Index>) -> Rows {
    parse_with(text, ix, false)
}

/// `parse_text` for aix's own answers: a `section (N):` line names the kind of the rows below it, and a line that
/// only quotes a location inside its text (`POST /api/x [roles] api/X.java:90 X.save`) or an indexed path
/// (`/orders -> OrderList web/src/pages/OrderList.tsx`) is a row of that location.
pub fn parse_answer(text: &str, ix: Option<&Index>) -> Rows {
    parse_with(text, ix, true)
}

fn parse_with(text: &str, ix: Option<&Index>, answer: bool) -> Rows {
    let mut r = Rows { bytes: text.len(), ..Default::default() };
    // the path a `== header` names, for the `N text` / `L12-30 text` rows below it
    let mut head: Option<(String, bool)> = None;
    let mut section = String::new();
    static SECTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z][\w/ -]*?)(?: reached| hitting [\w ]+)?(?: \([^)]*\))?:\s*$").unwrap());
    static LOC_IN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[\s(\[])((?:[\w@.+\-]+/)*[\w@.+\-]+\.[A-Za-z0-9]{1,8}):(\d{1,7})\b").unwrap());
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.trim().is_empty() {
            continue;
        }
        let red = crate::query::redact_keep_locations(raw);
        if red != raw {
            r.redacted += 1;
        }
        let l = red.as_str();
        if answer && !l.starts_with(' ') {
            if let Some(c) = SECTION.captures(l) {
                let w = c[1].trim().to_ascii_lowercase();
                section = w.strip_suffix('s').filter(|_| !w.contains('/')).unwrap_or(&w).to_string();
                continue;
            }
            if l.starts_with("==") {
                section.clear();
            }
            // `endpoints reached: none`: an empty section, not a row
            if l.trim_end().ends_with(": none") && !l.contains(char::is_numeric) {
                continue;
            }
        }
        let before = r.len();
        let unknown = r.unknown;
        let plain = !answer && head.is_none() && !l.starts_with(' ') && !l.starts_with('{') && !l.starts_with("==");
        parse_line(&mut r, l, ix, &mut head);
        if plain && r.len() == before + 1 {
            r.meta.last_mut().unwrap().raw = l.to_string();
        }
        if answer && r.len() > before {
            if let (Some(Row::Text { .. }), true) = (r.rows.last(), r.unknown > unknown) {
                // a location or an indexed path quoted inside the line
                let t = l.trim();
                let hit = LOC_IN.captures(t).map(|c| (norm(&c[1], ix), c[2].parse::<usize>().unwrap_or(0))).filter(|(p, _)| looks_path(p));
                let file = || t.split_whitespace().map(|w| w.trim_matches(|c: char| matches!(c, ',' | ';' | '(' | ')' | '[' | ']'))).find(|w| looks_path(w) && w.contains('/') && ix.is_some_and(|ix| crate::opts::resolve_path(ix, w).is_some())).map(|w| norm(w, ix));
                let row = match hit {
                    Some((p, n)) => Some(Row::Hit { path: p, line: n, text: t.to_string() }),
                    None => file().map(|p| Row::File { path: p }),
                };
                if let Some(row) = row {
                    let is_file = matches!(row, Row::File { .. });
                    *r.rows.last_mut().unwrap() = row;
                    r.unknown -= 1;
                    if is_file {
                        r.meta.last_mut().unwrap().text = t.to_string();
                    }
                }
            }
            if !section.is_empty() && r.meta.last().is_some_and(|m| m.kind.is_empty()) {
                r.meta.last_mut().unwrap().kind = section.clone();
            }
        }
    }
    r
}

/// A stand-in path (no whitespace, no colon) for a row whose real path has spaces or was C-quoted by git.
const SENT: &str = "aix\u{e000}path.x";

/// git's C-style quoted path (`"src/\303\274n.py"`, core.quotePath): the bytes it names.
fn unquote_git(q: &str) -> Option<String> {
    let inner = q.strip_prefix('"')?.strip_suffix('"')?;
    let mut out: Vec<u8> = vec![];
    let b = inner.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let c = b[i + 1];
            if (b'0'..=b'7').contains(&c) && i + 4 <= b.len() && b[i + 1..i + 4].iter().all(|d| (b'0'..=b'7').contains(d)) {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).ok()?, 8).ok()?);
                i += 4;
                continue;
            }
            out.push(match c {
                b'n' => b'\n',
                b't' => b'\t',
                b'"' => b'"',
                b'\\' => b'\\',
                b'a' => 7,
                b'b' => 8,
                b'f' => 12,
                b'v' => 11,
                b'r' => b'\r',
                o => o,
            });
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// A row whose path the plain row shapes cannot read: a path with whitespace (`docs/my notes.md:2: x`, the longest
/// prefix before `:N` that is an indexed file) or a git C-quoted path. Returns (real path, the line with SENT in its place).
fn odd_path(body: &str, ix: Option<&Index>) -> Option<(String, String)> {
    static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^("(?:[^"\\]|\\.)+")(:.*)?$"#).unwrap());
    if body.starts_with('"') {
        let c = QUOTED.captures(body)?;
        let p = unquote_git(&c[1])?;
        let p = match ix {
            Some(ix) => crate::opts::resolve_path(ix, &p).unwrap_or(p),
            None => p,
        };
        return Some((p, format!("{SENT}{}", c.get(2).map_or("", |m| m.as_str()))));
    }
    let ix = ix?;
    if !body.contains(char::is_whitespace) {
        return None;
    }
    // `path:N...` with spaces in the path: every `:N` boundary, the first one that names an indexed file
    for m in body.match_indices(':') {
        let p = &body[..m.0];
        if !p.contains(char::is_whitespace) || p.contains('\t') || p.starts_with(' ') {
            if !p.contains(char::is_whitespace) {
                return None; // the plain path shape reads it
            }
            continue;
        }
        if !body[m.0 + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let c = crate::opts::clean_path(p);
        if crate::opts::resolve_path(ix, &c).is_some_and(|r| r == c) && crate::opts::path_is_file(ix, &c) {
            return Some((c, format!("{SENT}{}", &body[m.0..])));
        }
    }
    // a bare path with spaces (grep -l, files, cut -d: -f1)
    let c = crate::opts::clean_path(body.trim_end());
    if crate::opts::resolve_path(ix, &c).is_some_and(|r| r == c) && crate::opts::path_is_file(ix, &c) {
        return Some((c, SENT.to_string()));
    }
    None
}

fn parse_line(r: &mut Rows, l: &str, ix: Option<&Index>, head: &mut Option<(String, bool)>) {
    let t0 = l.trim_start();
    if !t0.starts_with("==") && !t0.starts_with('(') && !t0.starts_with('{') && !t0.starts_with('[') {
        if let Some((p, fake)) = odd_path(t0, ix) {
            let lead = &l[..l.len() - t0.len()];
            let before = r.len();
            parse_line_plain(r, &format!("{lead}{fake}"), None, head);
            for i in before..r.len() {
                match &mut r.rows[i] {
                    Row::Hit { path, .. } | Row::File { path } | Row::Range { path, .. } if path == SENT => *path = p.clone(),
                    Row::Count { key, .. } if key == SENT => *key = p.clone(),
                    _ => {}
                }
            }
            if r.len() > before {
                return;
            }
        }
    }
    parse_line_plain(r, l, ix, head)
}

fn parse_line_plain(r: &mut Rows, l: &str, ix: Option<&Index>, head: &mut Option<(String, bool)>) {
    let t = l.trim_start();
    let indented = l.starts_with("  ");
    // JSON (--jsonl / --json)
    if t.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            if v.get("summary").is_some() {
                return;
            }
            let before = r.len();
            if let Some(ans) = v.get("answers").and_then(|a| a.as_array()) {
                for a in ans {
                    push_answer(r, a);
                }
            } else if let Some(hits) = v.get("hits").and_then(|h| h.as_array()) {
                for h in hits {
                    push_hit_json(r, h);
                }
            } else {
                push_hit_json(r, &v);
            }
            for i in before..r.len() {
                if let Some(p) = path_of_mut(&mut r.rows[i]) {
                    *p = norm(p, ix);
                }
            }
            if r.len() > before {
                return;
            }
        }
    }
    // decoration
    if t.starts_with("==") {
        // a header naming `path:A-B` opens numbered code lines; `== outline path` opens `L12-30` member rows
        *head = HEAD_LOC.captures(t).map(|c| (norm(&c["p"], ix), c.name("b").is_some())).filter(|(p, _)| looks_path(p));
        return;
    }
    if t.starts_with('(') || t.starts_with('\u{2026}') || t == "--" || (indented && CTX.is_match(t)) {
        return;
    }
    // `N text` (aix code) / `L12-30 text` (aix outline) below a header that named a file
    if let Some((h, code)) = head.as_ref() {
        if let Some(c) = OUTLINE.captures(t).filter(|_| !indented) {
            let (a, b) = (c["a"].parse().unwrap_or(0), c["b"].parse().unwrap_or(0));
            r.push(Row::Range { path: h.clone(), a, b }, Meta { kind: "member".into(), text: c["t"].trim().to_string(), ..Default::default() });
            return;
        }
        if let Some(c) = NUMBERED.captures(l).filter(|_| *code) {
            let n = c["n"].parse().unwrap_or(0);
            r.push(Row::Hit { path: h.clone(), line: n, text: c.name("t").map(|m| m.as_str().to_string()).unwrap_or_default() }, Meta::default());
            return;
        }
    }
    let (kind, body) = match KINDED.captures(t) {
        Some(c) => (c["k"].to_string(), c.name("rest").map(|m| m.as_str()).unwrap_or("").to_string()),
        None => (String::new(), t.to_string()),
    };
    let body = body.as_str();
    // `path: N` (aix grep -c)
    if let Some(c) = COUNT_LINE.captures(body).filter(|c| looks_path(&c["p"])) {
        r.push(Row::Count { key: norm(&c["p"], ix), n: c["n"].parse().unwrap_or(0) }, Meta { kind: "count".into(), text: String::new(), ..Default::default() });
        return;
    }
    if let Some(c) = HIT.captures(body).filter(|c| looks_path(&c["p"])) {
        let p = norm(&c["p"], ix);
        let n: usize = c["l"].parse().unwrap_or(0);
        let text = match (c.name("t"), c.name("s")) {
            // aix decorated rows print `path:line: text`; GNU prints `path:line:text`
            (Some(t), _) if indented || !kind.is_empty() => t.as_str().strip_prefix(' ').unwrap_or(t.as_str()).to_string(),
            (Some(t), _) => t.as_str().to_string(),
            (None, Some(s)) => s.as_str().trim().to_string(),
            (None, None) => String::new(),
        };
        let has_col = c.name("c").is_some();
        let _ = has_col;
        match (c.name("b"), c.name("t"), c.name("s")) {
            (Some(b), _, _) => {
                let b: usize = b.as_str().parse().unwrap_or(n);
                r.push(Row::Range { path: p, a: n, b }, Meta { kind, text, ..Default::default() });
            }
            // `path:N` with nothing after it: grep -c / rg -c
            (None, None, None) => r.push(Row::Count { key: p, n: n as u64 }, Meta { kind: "count".into(), text: String::new(), ..Default::default() }),
            _ => r.push(Row::Hit { path: p, line: n, text }, Meta { kind, text: String::new(), ..Default::default() }),
        }
        return;
    }
    if !indented && CTX.is_match(t) && t.split('-').next().is_some_and(|p| looks_path(p) && ix.is_none_or(|ix| crate::opts::resolve_path(ix, p).is_some())) {
        return; // GNU context line of a known file
    }
    if let Some(c) = GROUP.captures(l) {
        let n = c.name("n").or(c.name("m")).map(|m| m.as_str()).unwrap_or("0");
        r.push(Row::Count { key: c["k"].trim_end().to_string(), n: n.parse().unwrap_or(0) }, Meta { kind: "group".into(), ..Default::default() });
        return;
    }
    // a bare path (rg --files, git diff --name-only, ls -1, aix -l)
    let cand = body.trim();
    if looks_path(cand) || ix.is_some_and(|ix| !cand.contains(char::is_whitespace) && crate::opts::resolve_path(ix, cand).is_some()) {
        let dir = cand.ends_with('/') || cand.ends_with('\\');
        let mut p = norm(cand, ix);
        if dir && !p.ends_with('/') {
            p.push('/');
        }
        r.push(Row::File { path: p }, Meta { kind, text: String::new(), ..Default::default() });
        return;
    }
    r.unknown += 1;
    r.push(Row::Text { line: l.to_string() }, Meta::default());
}

fn path_of_mut(r: &mut Row) -> Option<&mut String> {
    match r {
        Row::Hit { path, .. } | Row::File { path } | Row::Range { path, .. } => Some(path),
        _ => None,
    }
}

// ── the `-` input ──

static PROCESS_STDIN: AtomicBool = AtomicBool::new(false);
static STDIN: OnceLock<Result<(String, bool), String>> = OnceLock::new();
thread_local! {
    static INJECTED: RefCell<Vec<Rows>> = const { RefCell::new(Vec::new()) };
}

/// The CLI allows reading the process stdin for `-` (MCP never: its stdin is the protocol).
pub fn allow_process_stdin() {
    PROCESS_STDIN.store(true, Ordering::Relaxed);
}

/// Run `f` with `rows` as the `-` input (an in-call pipe feeding the next stage).
pub fn with_input<T>(rows: Rows, f: impl FnOnce() -> T) -> T {
    INJECTED.with(|s| s.borrow_mut().push(rows));
    let out = f();
    INJECTED.with(|s| s.borrow_mut().pop());
    out
}

/// Is a `-` input available (injected rows, or the CLI's piped stdin)?
pub fn input_available() -> bool {
    INJECTED.with(|s| !s.borrow().is_empty()) || (PROCESS_STDIN.load(Ordering::Relaxed) && !std::io::stdin().is_terminal())
}

/// What lay past the first MAX_INPUT bytes of a long stdin: its last MAX_INPUT bytes (whole lines) and the size of
/// the whole input, counted while it streamed by (tail forms answer from the end; counts say the real total).
#[derive(Debug, Clone)]
pub struct StdinRest {
    /// the last lines of the input (at most MAX_INPUT bytes)
    pub tail: String,
    /// 1-based line number of the first line of `tail` in the whole input
    pub tail_first: usize,
    /// lines in the whole input (a last line without a newline counts)
    pub lines: usize,
    pub bytes: usize,
}

static STDIN_REST: OnceLock<StdinRest> = OnceLock::new();

/// The process stdin, read once: (its first MAX_INPUT bytes, truncated). A longer input is streamed to its end in
/// bounded memory (2 x MAX_INPUT): its last MAX_INPUT bytes and its line count go to [`stdin_rest`].
fn process_stdin() -> Result<(String, bool), String> {
    STDIN
        .get_or_init(|| {
            if !PROCESS_STDIN.load(Ordering::Relaxed) {
                return Err("'-' reads rows from a pipe; the MCP tool has no stdin: use an in-call pipe, command \"pipe\" with args \"<source> | <this command> -\"".into());
            }
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                return Err("'-' reads rows from stdin, but stdin is a terminal: pipe something in (cmd | aix ... -) or use aix '<source> | <this command> -'".into());
            }
            let mut lock = stdin.lock();
            let mut buf = Vec::new();
            let _ = (&mut lock).take(MAX_INPUT as u64 + 1).read_to_end(&mut buf);
            crate::sys::strip_stdin_bom_bytes(&mut buf);
            let cut = buf.len() > MAX_INPUT;
            if cut {
                // stream the rest: keep a window of the last MAX_INPUT bytes, count every line
                let mut nl = buf.iter().filter(|b| **b == b'\n').count();
                let mut bytes = buf.len();
                let mut tail: Vec<u8> = buf[buf.len().saturating_sub(MAX_INPUT)..].to_vec();
                let mut chunk = vec![0u8; 1 << 20];
                loop {
                    match lock.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            nl += chunk[..n].iter().filter(|b| **b == b'\n').count();
                            bytes += n;
                            tail.extend_from_slice(&chunk[..n]);
                            if tail.len() > 2 * MAX_INPUT {
                                tail.drain(..tail.len() - MAX_INPUT);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                if tail.len() > MAX_INPUT {
                    tail.drain(..tail.len() - MAX_INPUT);
                }
                let ends_nl = tail.last() == Some(&b'\n');
                // the window starts inside a line: drop that partial first line
                let skip = tail.iter().position(|b| *b == b'\n').map_or(0, |i| i + 1);
                tail.drain(..skip);
                let lines = nl + usize::from(!ends_nl);
                let tail_lines = tail.iter().filter(|b| **b == b'\n').count() + usize::from(!ends_nl && !tail.is_empty());
                let rest = StdinRest { tail: String::from_utf8_lossy(&tail).into_owned(), tail_first: lines + 1 - tail_lines.min(lines), lines, bytes };
                let _ = STDIN_REST.set(rest);
            }
            buf.truncate(MAX_INPUT);
            if cut {
                // the cut lands inside a row: drop that partial last row (it would name a wrong line or file)
                let keep = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                buf.truncate(keep);
            }
            Ok((String::from_utf8_lossy(&buf).into_owned(), cut))
        })
        .clone()
}

/// The end and the size of a process stdin longer than MAX_INPUT (None: it was not cut, or `-` is injected rows).
pub fn stdin_rest() -> Option<StdinRest> {
    if INJECTED.with(|s| !s.borrow().is_empty()) {
        return None;
    }
    process_stdin().ok().filter(|(_, cut)| *cut)?;
    STDIN_REST.get().cloned()
}

/// The note on an answer read from a cut stdin: how much there was and which part was read.
pub fn cut_note(part: &str) -> String {
    match STDIN_REST.get() {
        Some(r) => format!("stdin is {:.1} MB / {} lines, over the {} MB kept: {part}", r.bytes as f64 / 1048576.0, r.lines, MAX_INPUT / (1024 * 1024)),
        None => format!("stdin cut at {} MB: {part}", MAX_INPUT / (1024 * 1024)),
    }
}

/// The `-` input as rows from the END of a cut stdin (tail forms: `filter --tail N -`); else [`parse_stdin`].
pub fn parse_stdin_tail(ix: Option<&Index>) -> Result<Rows, String> {
    match stdin_rest() {
        Some(rest) => {
            let mut r = parse_text(&rest.tail, ix);
            r.truncated = true;
            r.partial = Some(cut_note(&format!("rows read from its last {} lines", rest.lines + 1 - rest.tail_first)));
            Ok(r)
        }
        None => parse_stdin(ix),
    }
}

/// The `-` input as text (a reader that takes content, not rows: `cat -`, `diff -` with a patch): the injected rows
/// in their GNU shape, else the process stdin (CLI).
pub fn input_text() -> Result<(String, bool), String> {
    if let Some(r) = INJECTED.with(|s| s.borrow().last().cloned()) {
        return Ok((r.iter().map(|(row, m)| row.render(m)).collect::<Vec<_>>().join("\n"), r.truncated));
    }
    process_stdin()
}

/// The `-` input as rows: what an in-call pipe injected, else the process stdin parsed (CLI).
pub fn parse_stdin(ix: Option<&Index>) -> Result<Rows, String> {
    if let Some(r) = INJECTED.with(|s| s.borrow().last().cloned()) {
        return Ok(r);
    }
    let (text, cut) = process_stdin()?;
    let mut r = parse_text(&text, ix);
    r.truncated = cut;
    if cut {
        r.partial = Some(cut_note(&format!("rows read from its first {} MB only", MAX_INPUT / (1024 * 1024))));
        r.lines_total = STDIN_REST.get().map(|x| x.lines);
    }
    Ok(r)
}

pub fn is_dash(t: &str) -> bool {
    t == "-"
}

/// Does an argument list name `-` (before a `--`)?
pub fn has_dash(args: &[String]) -> bool {
    args.iter().take_while(|a| *a != "--").any(|a| is_dash(a))
}

/// One footer line about the input, when there is something to say (unknown lines, redactions, a cut).
pub fn input_note(r: &Rows, need_location: bool) -> Option<String> {
    let mut parts: Vec<String> = vec![];
    if r.truncated {
        parts.push(r.partial.clone().unwrap_or_else(|| format!("stdin cut at {} MB", MAX_INPUT / (1024 * 1024))));
    }
    if need_location && r.unknown > 0 {
        parts.push(format!("{} input line{} named no file and {} ignored", r.unknown, if r.unknown == 1 { "" } else { "s" }, if r.unknown == 1 { "was" } else { "were" }));
    }
    if r.redacted > 0 {
        parts.push(format!("{} line{} redacted (***): never use them as edit anchors", r.redacted, if r.redacted == 1 { "" } else { "s" }));
    }
    (!parts.is_empty()).then(|| format!("(input: {})", parts.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(t: &str) -> Vec<String> {
        parse_text(t, None).bare_lines()
    }

    #[test]
    fn gnu_rg_git_grep_forms() {
        assert_eq!(rows("src/a.rs:12:  let x = 1;\r\n"), vec!["src/a.rs:12:  let x = 1;"]);
        assert_eq!(rows("src/a.rs:12:5:let x"), vec!["src/a.rs:12:let x"]);
        assert_eq!(rows("src/a.rs:3"), vec!["src/a.rs:3"]); // grep -c
        assert_eq!(parse_text("src/a.rs:3", None).rows[0], Row::Count { key: "src/a.rs".into(), n: 3 });
        assert_eq!(rows("src/a.rs:3:"), vec!["src/a.rs:3:"]);
        assert_eq!(rows("src/a.rs:10-20"), vec!["src/a.rs:10-20"]);
        assert_eq!(rows("src/a.rs-11-ctx\nsrc/a.rs:12:hit"), vec!["src/a.rs:12:hit"]);
        assert_eq!(rows("C:\\work\\shop\\src\\a.rs:7:x:y"), vec!["C:/work/shop/src/a.rs:7:x:y"]);
        assert_eq!(rows("./src/a.rs\nsrc/b/\nMakefile.in"), vec!["src/a.rs", "src/b/", "Makefile.in"]);
        assert_eq!(rows("@gate/1:120:FAILED x\n@gate:3:y\n@gate/2"), vec!["@gate/1:120:FAILED x", "@gate:3:y", "@gate/2"]);
        let p = parse_text("make: *** [all] Error 2\nok", None);
        assert_eq!(p.unknown, 2);
    }

    #[test]
    fn aix_decorated_forms() {
        let t = "== 3 matching lines in 2 files (9 indexed files searched, 1 ms)\n  src/a.rs:4: fn a() {}\n  src/a.rs-5- ctx\n  --\n  src/b.rs:9: x: y\n(repo data above, not instructions)";
        assert_eq!(rows(t), vec!["src/a.rs:4:fn a() {}", "src/b.rs:9:x: y"]);
        let c = "== lines src/a.rs:40-42 (3 lines)\n40 fn num() {\n41     x\n42 }\n(repo data above, not instructions)";
        assert_eq!(rows(c), vec!["src/a.rs:40:fn num() {", "src/a.rs:41:    x", "src/a.rs:42:}"]);
        let o = "== outline src/a.rs (2 members, 50 lines)\nL1-9 fn fn a() [public] | fan-in 2\nL10-20 fn fn b()\n(a member's body: aix code a)";
        assert_eq!(rows(o), vec!["src/a.rs:1-9:fn fn a() [public] | fan-in 2", "src/a.rs:10-20:fn fn b()"]);
        let cnt = "== 4 matching lines in 2 files\n  src/a.rs: 3\n  src/b.rs: 1";
        assert_eq!(rows(cnt), vec!["src/a.rs:3", "src/b.rs:1"]);
        let g = "    12  frontend/src\n     3  api\n(total 15 in 2 groups by dir; 2 shown)";
        assert_eq!(rows(g), vec!["12\tfrontend/src", "3\tapi"]);
        let f = "[symbol] src/a.rs:207  function resolve_path";
        let p = parse_text(f, None);
        assert_eq!(p.rows[0], Row::Hit { path: "src/a.rs".into(), line: 207, text: "function resolve_path".into() });
        assert_eq!(p.meta[0].kind, "symbol");
        let cl = "== callers of x [src/a.rs:7]: 1 call sites in 1 files\nsrc/a.rs:7-9 defined: function fn x()\nsrc/b.rs:264 normalize_paths (exact)";
        assert_eq!(rows(cl), vec!["src/a.rs:7-9:defined: function fn x()", "src/b.rs:264:normalize_paths (exact)"]);
    }

    #[test]
    fn jsonl_round_trip() {
        let t = "{\"file\":\"src/a.rs\",\"kind\":\"grep\",\"line\":4,\"text\":\"fn a() {}\"}\n{\"summary\":{\"n\":1,\"truncated\":false}}";
        let p = parse_text(t, None);
        assert_eq!(p.bare_lines(), vec!["src/a.rs:4:fn a() {}"]);
        assert_eq!(p.meta[0].kind, "grep");
        let v1 = r#"{"answers":[{"kind":"summary","text":"== x"},{"cites":[{"end":9,"file":"src/a.rs","line":7}],"kind":"definition","text":"src/a.rs:7-9 defined: fn x"},{"cites":[{"end":3,"file":"src/b.rs","line":3}],"kind":"caller","text":"src/b.rs:3 main (exact)"}],"schema":"aix/v1"}"#;
        assert_eq!(rows(v1), vec!["src/a.rs:7-9:defined: fn x", "src/b.rs:3:main (exact)"]);
    }

    #[test]
    fn redaction_is_counted() {
        let p = parse_text("cfg.env:3:password=hunter2xyz", None);
        assert_eq!(p.redacted, 1);
        assert!(!p.bare_lines()[0].contains("hunter2"));
    }
}
