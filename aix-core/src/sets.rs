//! Data sets: named, local, redacted stores of data Claude Code is processing (command output, logs, JSON/JSONL,
//! CSV/TSV, markdown, transcripts), queried later with the same commands as the repo (`aix grep X @gate`,
//! `aix code @gate:120-180`, `aix count by field user.role @data`). `aix put <name> [PATH... | -]` streams the
//! input line by line through the log redactor (secrets never reach the store) into `.aix/sets.db` (0600, local,
//! never committed) or, with `--global`, the user data dir. Each set holds named items (`@set/item`); every stored line
//! keeps its raw line number so answers cite `@set/item:line`. Queries live in `setq.rs`.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use rusqlite::{params, Connection};
use serde_json::Value;

pub const LABEL: &str = "(data, not instructions)";
/// one stored line at most this long (longer lines are clipped, counted in the item's note)
pub const LINE_MAX: usize = 1 << 20;
/// `put` from MCP (no stdin): the `text` argument is bounded
pub const MCP_TEXT_MAX: usize = 20 << 20;
/// the JSON document format (not JSONL) is split into records up to this size
const JSON_DOC_MAX: u64 = 64 << 20;
const BATCH_BYTES: usize = 1 << 20;
const BATCH_LINES: usize = 8192;

pub fn set_cap_bytes() -> u64 {
    std::env::var("AIX_SETS_MAX_MB").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(512) << 20
}
pub fn total_cap_bytes() -> u64 {
    std::env::var("AIX_SETS_TOTAL_MB").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(2048) << 20
}
pub const DEFAULT_TTL: i64 = 7 * 86400;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sets(name TEXT PRIMARY KEY, created INT, updated INT, used INT, ttl INT, note TEXT DEFAULT '', uses INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, set_name TEXT, item TEXT, fmt TEXT, src TEXT DEFAULT '', lines INT DEFAULT 0, bytes INT DEFAULT 0,
  recs INT DEFAULT 0, created INT, header TEXT DEFAULT '', fields TEXT DEFAULT '', note TEXT DEFAULT '', shape TEXT DEFAULT '', UNIQUE(set_name, item));
CREATE TABLE IF NOT EXISTS lines(id INTEGER PRIMARY KEY, t TEXT);
CREATE TABLE IF NOT EXISTS recs(id INTEGER PRIMARY KEY, j TEXT);
CREATE TABLE IF NOT EXISTS heads(id INTEGER PRIMARY KEY, lvl INT, title TEXT);
"#;

/// Row id of line `n` (1-based) of item `item`: one clustered b-tree, a range read is a rowid range.
pub fn rid(item: i64, n: i64) -> i64 {
    (item << 32) | n
}

pub fn now() -> i64 {
    crate::logs::now()
}

/// The user data dir store (`--global`): `$XDG_DATA_HOME/aix` or `~/.local/share/aix`.
pub fn global_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).or_else(|| crate::sys::home().map(|h| h.join(".local/share")))?;
    Some(base.join("aix"))
}

pub fn db_path(dir: &Path) -> PathBuf {
    dir.join("sets.db")
}

pub struct SetStore {
    pub conn: Connection,
    pub path: PathBuf,
    pub global: bool,
}

/// Open (creating with mode 0600) a set store. Same hardening as the log store: no symlink, `secure_delete`, incremental
/// auto-vacuum so `rm`/`prune` really shrink the file.
pub fn open(dir: &Path, global: bool, create: bool) -> Result<Option<SetStore>> {
    let path = db_path(dir);
    let fresh = !path.exists();
    if fresh && !create {
        return Ok(None);
    }
    if fresh {
        if !dir.exists() {
            crate::sys::private_dir(std::fs::DirBuilder::new().recursive(true)).create(dir)?;
        }
        let _ = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(&path)?;
    } else if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
        bail!("{} is a symlink: refused", path.display());
    }
    let conn = Connection::open(&path)?;
    conn.busy_timeout(std::time::Duration::from_millis(10_000))?;
    if fresh {
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
    }
    conn.execute_batch("PRAGMA secure_delete=ON; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-65536;")?;
    conn.execute_batch(SCHEMA)?;
    let has_shape = conn.prepare("PRAGMA table_info(items)").and_then(|mut q| q.query_map([], |r| r.get::<_, String>(1)).map(|i| i.flatten().any(|n| n == "shape"))).unwrap_or(true);
    if !has_shape {
        let _ = conn.execute_batch("ALTER TABLE items ADD COLUMN shape TEXT DEFAULT ''");
    }
    let _ = crate::sys::chmod(&path, 0o600);
    Ok(Some(SetStore { conn, path, global }))
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// An item name from a file name: `[A-Za-z0-9_.+-]`, other characters become `_`.
pub fn item_name(raw: &str) -> String {
    let s: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-') { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        "item".into()
    } else {
        s.chars().take(80).collect()
    }
}

#[derive(Debug, Clone)]
pub struct SetInfo {
    pub name: String,
    pub created: i64,
    pub updated: i64,
    pub used: i64,
    pub ttl: i64,
    pub note: String,
    pub uses: i64,
    pub items: i64,
    pub lines: i64,
    pub bytes: i64,
    pub recs: i64,
    pub global: bool,
}

#[derive(Debug, Clone)]
pub struct Item {
    pub id: i64,
    pub set: String,
    pub item: String,
    pub fmt: String,
    pub src: String,
    pub lines: i64,
    pub bytes: i64,
    pub recs: i64,
    pub header: Vec<String>,
    pub fields: Vec<(String, i64)>,
    pub note: String,
    pub global: bool,
    /// the named-field spec (`--pattern` ...), JSON; "" = none
    pub shape: String,
}

impl Item {
    /// What answers cite: `@set` when the set has one item, else `@set/item`.
    pub fn cite(&self, single: bool) -> String {
        if single {
            format!("@{}", self.set)
        } else {
            format!("@{}/{}", self.set, self.item)
        }
    }
}

pub fn list_sets(st: &SetStore) -> Result<Vec<SetInfo>> {
    let mut q = st.conn.prepare(
        "SELECT s.name, s.created, s.updated, s.used, s.ttl, s.note, s.uses, count(i.id), COALESCE(sum(i.lines),0), COALESCE(sum(i.bytes),0), COALESCE(sum(i.recs),0)
         FROM sets s LEFT JOIN items i ON i.set_name=s.name GROUP BY s.name ORDER BY s.used DESC, s.name",
    )?;
    let v = q
        .query_map([], |r| {
            Ok(SetInfo {
                name: r.get(0)?,
                created: r.get(1)?,
                updated: r.get(2)?,
                used: r.get(3)?,
                ttl: r.get(4)?,
                note: r.get(5)?,
                uses: r.get(6)?,
                items: r.get(7)?,
                lines: r.get(8)?,
                bytes: r.get(9)?,
                recs: r.get(10)?,
                global: st.global,
            })
        })?
        .flatten()
        .collect();
    Ok(v)
}

pub fn items_of(st: &SetStore, set: &str) -> Result<Vec<Item>> {
    let mut q = st.conn.prepare("SELECT id, set_name, item, fmt, src, lines, bytes, recs, header, fields, note, shape FROM items WHERE set_name=? ORDER BY id")?;
    let v = q
        .query_map([set], |r| {
            let header: String = r.get(8)?;
            let fields: String = r.get(9)?;
            Ok(Item {
                id: r.get(0)?,
                set: r.get(1)?,
                item: r.get(2)?,
                fmt: r.get(3)?,
                src: r.get(4)?,
                lines: r.get(5)?,
                bytes: r.get(6)?,
                recs: r.get(7)?,
                header: serde_json::from_str(&header).unwrap_or_default(),
                fields: serde_json::from_str(&fields).unwrap_or_default(),
                note: r.get(10)?,
                global: st.global,
                shape: r.get(11)?,
            })
        })?
        .flatten()
        .collect();
    Ok(v)
}

pub fn exists(st: &SetStore, name: &str) -> bool {
    st.conn.query_row("SELECT 1 FROM sets WHERE name=?", [name], |_| Ok(())).is_ok()
}

pub fn touch_used(st: &SetStore, name: &str) {
    let _ = st.conn.execute("UPDATE sets SET used=?, uses=uses+1 WHERE name=?", params![now(), name]);
}

pub fn total_bytes(st: &SetStore) -> i64 {
    st.conn.query_row("SELECT COALESCE(sum(bytes),0) FROM items", [], |r| r.get(0)).unwrap_or(0)
}

/// Delete a set's rows (inside the caller's transaction).
fn delete_set_rows(c: &Connection, name: &str) -> Result<(i64, i64)> {
    let ids: Vec<(i64, i64)> = c.prepare("SELECT id, bytes FROM items WHERE set_name=?")?.query_map([name], |r| Ok((r.get(0)?, r.get(1)?)))?.flatten().collect();
    let mut bytes = 0;
    for (id, b) in &ids {
        for t in ["lines", "recs", "heads"] {
            c.execute(&format!("DELETE FROM {t} WHERE id>=?1 AND id<?2"), params![rid(*id, 0), rid(*id + 1, 0)])?;
        }
        bytes += b;
    }
    c.execute("DELETE FROM items WHERE set_name=?", [name])?;
    c.execute("DELETE FROM sets WHERE name=?", [name])?;
    Ok((ids.len() as i64, bytes))
}

/// Give the freed pages back to the file system (each step of the pragma frees pages: run it to the end).
fn shrink(c: &Connection) {
    if let Ok(mut st) = c.prepare("PRAGMA incremental_vacuum") {
        if let Ok(mut rows) = st.query([]) {
            while let Ok(Some(_)) = rows.next() {}
        }
    }
}

pub fn remove(st: &SetStore, name: &str) -> Result<Option<(i64, i64)>> {
    if !exists(st, name) {
        return Ok(None);
    }
    let r = crate::logs::with_tx(&st.conn, |c| delete_set_rows(c, name))?;
    shrink(&st.conn);
    Ok(Some(r))
}

/// Remove sets whose TTL ran out (`updated + ttl`, ttl 0 = never).
pub fn prune(st: &SetStore) -> Result<Vec<String>> {
    let t = now();
    let names: Vec<String> = st.conn.prepare("SELECT name FROM sets WHERE ttl>0 AND updated+ttl<?")?.query_map([t], |r| r.get(0))?.flatten().collect();
    if names.is_empty() {
        return Ok(names);
    }
    crate::logs::with_tx(&st.conn, |c| {
        for n in &names {
            delete_set_rows(c, n)?;
        }
        Ok(())
    })?;
    shrink(&st.conn);
    Ok(names)
}

// ---- formats -------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
    Text,
    Log,
    Json,
    Jsonl,
    Csv,
    Tsv,
    Md,
}

impl Fmt {
    pub fn parse(s: &str) -> Option<Option<Fmt>> {
        Some(Some(match s {
            "auto" => return Some(None),
            "text" | "txt" => Fmt::Text,
            "log" => Fmt::Log,
            "json" => Fmt::Json,
            "jsonl" | "ndjson" => Fmt::Jsonl,
            "csv" => Fmt::Csv,
            "tsv" => Fmt::Tsv,
            "md" | "markdown" => Fmt::Md,
            _ => return None,
        }))
    }
    pub fn name(self) -> &'static str {
        match self {
            Fmt::Text => "text",
            Fmt::Log => "log",
            Fmt::Json => "json",
            Fmt::Jsonl => "jsonl",
            Fmt::Csv => "csv",
            Fmt::Tsv => "tsv",
            Fmt::Md => "md",
        }
    }
    pub fn from_name(s: &str) -> Fmt {
        Fmt::parse(s).flatten().unwrap_or(Fmt::Text)
    }
    pub fn records(self) -> bool {
        matches!(self, Fmt::Json | Fmt::Jsonl | Fmt::Csv | Fmt::Tsv)
    }
}

fn by_extension(name: &str) -> Option<Fmt> {
    let l = name.to_ascii_lowercase();
    let ext = l.rsplit('.').next().unwrap_or("");
    Some(match ext {
        "jsonl" | "ndjson" => Fmt::Jsonl,
        "csv" => Fmt::Csv,
        "tsv" | "tab" => Fmt::Tsv,
        "md" | "markdown" => Fmt::Md,
        "log" => Fmt::Log,
        "json" => Fmt::Json,
        // code and config whose `#` comments read like markdown headings: plain text lines
        "sh" | "bash" | "zsh" | "py" | "rb" | "pl" | "ps1" | "yaml" | "yml" | "toml" | "ini" | "conf" | "cfg" | "properties" | "env" | "sql" | "r" | "mk" => Fmt::Text,
        _ => return None,
    })
}

/// Split one CSV line into fields (RFC 4180 quoting); `None` when a quoted field is still open at the end of the line.
pub fn csv_split(line: &str, sep: char) -> Option<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut q = false;
    let mut chars = line.chars().peekable();
    let mut at_start = true;
    while let Some(c) = chars.next() {
        if q {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    q = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' && at_start {
            q = true;
            at_start = false;
        } else if c == sep {
            out.push(std::mem::take(&mut cur));
            at_start = true;
        } else {
            cur.push(c);
            at_start = false;
        }
    }
    if q {
        return None;
    }
    out.push(cur);
    Some(out)
}

/// Guess the format of the first lines (and the file name).
pub fn detect(first: &[String], name: &str) -> Fmt {
    let ext = by_extension(name);
    let nb: Vec<&str> = first.iter().map(String::as_str).filter(|l| !l.trim().is_empty()).take(200).collect();
    if nb.is_empty() {
        return ext.unwrap_or(Fmt::Text);
    }
    let objline = |l: &str| {
        let t = l.trim();
        (t.starts_with('{') && t.ends_with('}') || t.starts_with('[') && t.ends_with(']')) && serde_json::from_str::<Value>(t).is_ok()
    };
    let jsonl = nb.iter().filter(|l| objline(l)).count();
    if jsonl == nb.len() && (nb.len() >= 2 || ext == Some(Fmt::Jsonl)) {
        return Fmt::Jsonl;
    }
    if ext == Some(Fmt::Json) || nb[0].trim_start().starts_with('[') || nb[0].trim() == "{" {
        return Fmt::Json;
    }
    if let Some(e) = ext {
        return e;
    }
    for (sep, f) in [(',', Fmt::Csv), ('\t', Fmt::Tsv)] {
        if nb.len() >= 2 {
            let counts: Vec<Option<usize>> = nb.iter().take(30).map(|l| if sep == '\t' { Some(l.split('\t').count()) } else { csv_split(l, sep).map(|v| v.len()) }).collect();
            let n0 = counts[0].unwrap_or(0);
            // a header of short names, the same field count on every sampled line
            let head_ok = csv_split(nb[0], sep).is_some_and(|h| h.iter().all(|c| c.len() <= 64 && !c.trim().is_empty()));
            if n0 >= 2 && head_ok && counts.iter().all(|c| *c == Some(n0)) {
                return f;
            }
        }
    }
    let heads = nb.iter().filter(|l| md_heading(l).is_some()).count();
    if heads >= 2 && heads * 40 >= nb.len().min(200) {
        return Fmt::Md;
    }
    let sample = nb.iter().take(200).copied().collect::<Vec<_>>().join("\n");
    match crate::logs::detect_kind(&sample) {
        "log lines" | "java stack traces" | "python traceback" | "js stack trace" => Fmt::Log,
        _ => Fmt::Text,
    }
}

pub fn md_heading(l: &str) -> Option<(i64, &str)> {
    let t = l.trim_end();
    let n = t.bytes().take_while(|b| *b == b'#').count();
    if (1..=6).contains(&n) && t.len() > n && t.as_bytes()[n] == b' ' {
        Some((n as i64, t[n + 1..].trim()))
    } else {
        None
    }
}

// ---- JSON flattening -------------------------------------------------------------------------------------------------------

/// `{"user":{"role":"a"},"items":[{"sku":1}]}` -> [("user.role","a"), ("items[].sku","1")]: every scalar with its path.
pub fn flatten(v: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(x, &p, out);
            }
        }
        Value::Array(a) => {
            let p = format!("{prefix}[]");
            for x in a {
                flatten(x, &p, out);
            }
        }
        _ => out.push((prefix.to_string(), scalar(v))),
    }
}

pub fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// Field paths compare without the `[]` markers (`items.sku` finds `items[].sku`).
pub fn norm_field(p: &str) -> String {
    p.replace("[]", "")
}

// ---- ingest ----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PutOpts {
    pub fmt: Option<Fmt>,
    pub append: bool,
    pub replace: bool,
    pub keep: bool,
    pub ttl: Option<i64>,
    pub note: Option<String>,
    pub item: Option<String>,
    pub keep_ips: bool,
    pub max_bytes: Option<u64>,
    /// named fields at ingest (`--pattern`, `--fields`, `--kv`, presets)
    pub shape: Option<crate::setpat::ShapeSpec>,
    /// `--pattern auto`: guess the shape from the first lines
    pub auto: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PutReport {
    pub items: Vec<(String, String, i64, i64, i64)>, // (item, fmt, lines, bytes, records)
    pub notes: Vec<String>,
    pub replaced: Option<(i64, i64)>,
    pub secs: f64,
    pub raw_bytes: u64,
    pub db_growth: i64,
    /// per item: the fields line and one example row
    pub summaries: Vec<String>,
    /// `--pattern auto` was not confident: the message with the exact command to rerun
    pub low_conf: Option<String>,
}

pub struct ItemDone {
    pub name: String,
    pub fmt: Fmt,
    pub lines: i64,
    pub bytes: i64,
    pub recs: i64,
    pub note: String,
    pub raw: u64,
    pub summary: Vec<String>,
    pub low_conf: Option<String>,
}

#[derive(Default)]
struct ShapeStats {
    rows: i64,
    unmatched: i64,
    bad: std::collections::BTreeMap<String, i64>,
    example: Option<(i64, String)>,
}

struct Batch {
    start: i64,
    lines: Vec<String>,
}

struct Done {
    lines: Vec<String>,
    fields: Vec<Vec<String>>, // per JSONL/CSV record line: its field paths (stats)
}

/// Strip what never belongs in a stored line: CR, control characters (tab kept), ANSI colour codes.
fn clean_line(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let s = s.strip_suffix('\r').unwrap_or(&s);
    let needs = s.bytes().any(|c| c < 0x20 && c != b'\t' || c == 0x7f);
    if !needs {
        return s.to_string();
    }
    let s = if s.contains('\u{1b}') { aix_extract::logparse::strip_ansi(s) } else { s.to_string() };
    s.chars().filter(|c| !c.is_control() || *c == '\t').collect()
}

/// A batch ends on a line that starts a new top-level construct, never inside a PEM block (multi-line secrets are
/// redacted as a whole).
fn may_cut(lines: &[String], in_pem: bool) -> bool {
    if in_pem {
        return false;
    }
    match lines.last() {
        Some(l) => !l.starts_with([' ', '\t']) || l.trim().is_empty(),
        None => true,
    }
}

fn process(b: &Batch, fmt: Fmt, keep_ips: bool, header: &[String]) -> Done {
    let joined = b.lines.join("\n");
    let red = crate::logs::redact_text(&joined, keep_ips);
    let mut lines: Vec<String> = red.split('\n').map(str::to_string).collect();
    if lines.len() != b.lines.len() {
        // the redactor keeps the line count; if it ever did not, redact line by line (never store unredacted text)
        lines = b.lines.iter().map(|l| crate::logs::redact_text(l, keep_ips)).collect();
    }
    let mut fields = vec![];
    match fmt {
        Fmt::Jsonl => {
            for l in &lines {
                let mut f = vec![];
                if let Ok(v) = serde_json::from_str::<Value>(l.trim()) {
                    let mut kv = vec![];
                    flatten(&v, "", &mut kv);
                    f = kv.into_iter().map(|(k, _)| k).collect();
                    f.dedup();
                }
                fields.push(f);
            }
        }
        Fmt::Csv | Fmt::Tsv if !header.is_empty() => {
            // the header's names are the fields; nothing per line
        }
        _ => {}
    }
    Done { lines, fields }
}

/// Where one ingest goes: a new or existing item of a set.
struct Sink<'a> {
    c: &'a Connection,
    item: i64,
    next: i64,
    bytes: i64,
    fmt: Fmt,
    field_n: HashMap<String, i64>,
    recs: i64,
    in_fence: bool,
    shape: Option<&'a crate::setpat::Shape>,
    pending: Option<(i64, String)>,
    pst: ShapeStats,
}

impl Sink<'_> {
    fn write(&mut self, d: Done) -> Result<()> {
        let mut st = self.c.prepare_cached("INSERT INTO lines(id, t) VALUES(?, ?)")?;
        let mut hs = self.c.prepare_cached("INSERT OR REPLACE INTO heads(id, lvl, title) VALUES(?, ?, ?)")?;
        for (i, l) in d.lines.iter().enumerate() {
            let n = self.next;
            self.next += 1;
            st.execute(params![rid(self.item, n), l])?;
            self.bytes += l.len() as i64 + 1;
            if self.fmt == Fmt::Md {
                if l.trim_start().starts_with("```") || l.trim_start().starts_with("~~~") {
                    self.in_fence = !self.in_fence;
                } else if !self.in_fence {
                    if let Some((lv, t)) = md_heading(l) {
                        hs.execute(params![rid(self.item, n), lv, t])?;
                    }
                }
            }
            if let Some(f) = d.fields.get(i) {
                if !f.is_empty() {
                    self.recs += 1;
                }
                for k in f {
                    *self.field_n.entry(k.clone()).or_default() += 1;
                }
            }
        }
        if let Some(sh) = self.shape {
            // records: a line that does not start one (--multiline / log entries) continues the one before it
            let first_n = self.next - d.lines.len() as i64;
            let mut done: Vec<(i64, String)> = vec![];
            for (i, l) in d.lines.into_iter().enumerate() {
                let n = first_n + i as i64;
                let starts = if sh.entry_start && sh.multiline.is_none() {
                    aix_extract::logparse::is_entry_start(&l, aix_extract::logparse::Format::Auto)
                } else if let Some(m) = &sh.multiline {
                    m.is_match(&l)
                } else {
                    true
                };
                match &mut self.pending {
                    Some((_, t)) if !starts && t.len() < (1 << 20) => {
                        t.push('\n');
                        t.push_str(&l);
                    }
                    _ => {
                        if let Some(p) = self.pending.take() {
                            done.push(p);
                        }
                        self.pending = Some((n, l));
                    }
                }
            }
            self.emit_recs(sh, done)?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if let (Some(sh), Some(p)) = (self.shape, self.pending.take()) {
            self.emit_recs(sh, vec![p])?;
        }
        Ok(())
    }

    /// Extract the fields of finished records (in parallel) and store them as rows of `recs`.
    fn emit_recs(&mut self, sh: &crate::setpat::Shape, recs: Vec<(i64, String)>) -> Result<()> {
        use rayon::prelude::*;
        if recs.is_empty() {
            return Ok(());
        }
        let out: Vec<_> = recs.par_iter().map(|(_, t)| crate::setpat::extract(sh, t)).collect();
        let mut ins = self.c.prepare_cached("INSERT OR REPLACE INTO recs(id, j) VALUES(?, ?)")?;
        let user_pats = sh.pats.len() + usize::from(sh.entry_start);
        for ((n, t), (mut m, which, bad)) in recs.iter().zip(out) {
            if t.trim().is_empty() {
                continue;
            }
            self.pst.rows += 1;
            if which == 0 {
                self.pst.unmatched += 1;
                m.insert("_raw".into(), Value::String(t.clone()));
            } else if user_pats > 1 && which <= user_pats {
                m.insert("_pat".into(), Value::from(which as i64));
            }
            for b in bad {
                *self.pst.bad.entry(b).or_default() += 1;
            }
            for k in m.keys() {
                *self.field_n.entry(k.clone()).or_default() += 1;
            }
            if self.pst.example.is_none() && which > 0 {
                let ex: Vec<String> = m.iter().map(|(k, v)| format!("{k}={}", match v { Value::String(s) => s.replace('\n', "\u{23ce}"), o => o.to_string() })).collect();
                self.pst.example = Some((*n, ex.join(" ")));
            }
            ins.execute(params![rid(self.item, *n), Value::Object(m).to_string()])?;
        }
        Ok(())
    }
}

/// Record boundaries of a JSON document: the elements of a top-level array (their first line), or the document itself.
fn json_doc_records(text: &str) -> Vec<(i64, Value)> {
    let b = text.as_bytes();
    let mut i = 0;
    let mut line = 1i64;
    while i < b.len() && b[i].is_ascii_whitespace() {
        if b[i] == b'\n' {
            line += 1;
        }
        i += 1;
    }
    if i >= b.len() {
        return vec![];
    }
    if b[i] != b'[' {
        return serde_json::from_str::<Value>(text).ok().map(|v| vec![(line, v)]).unwrap_or_default();
    }
    let mut out = vec![];
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    let mut start: Option<(usize, i64)> = None;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line += 1;
        }
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_str = true;
                if depth == 1 && start.is_none() {
                    start = Some((i, line));
                }
            }
            b'[' | b'{' => {
                if depth == 1 && start.is_none() {
                    start = Some((i, line));
                }
                depth += 1;
            }
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some((s, l)) = start.take() {
                        if let Ok(v) = serde_json::from_str::<Value>(text[s..i].trim()) {
                            out.push((l, v));
                        }
                    }
                    break;
                }
            }
            b',' if depth == 1 => {
                if let Some((s, l)) = start.take() {
                    if let Ok(v) = serde_json::from_str::<Value>(text[s..i].trim()) {
                        out.push((l, v));
                    }
                }
            }
            c if depth == 1 && start.is_none() && !c.is_ascii_whitespace() => start = Some((i, line)),
            _ => {}
        }
        i += 1;
    }
    out
}

/// One input of a `put`: a display name (file name or `stdin`), its source note, and a reader.
pub struct Input {
    pub name: String,
    pub src: String,
    pub reader: Box<dyn BufRead + Send>,
}

/// Stream one input into a set item: reader thread -> redaction pool -> writer (this thread), batches in order.
/// Never holds more than a few batches in memory. Returns (item name, fmt, lines, bytes, records, note).
fn ingest_one(c: &Connection, set: &str, item_nm: &str, append_to: Option<(i64, i64, Fmt, Vec<String>)>, input: Input, o: &PutOpts, budget: u64) -> Result<ItemDone> {
    use std::sync::mpsc::sync_channel;
    use std::sync::Mutex;
    let Input { name, src, mut reader } = input;
    // the first batch decides the format (and the CSV header)
    let mut first: Vec<String> = vec![];
    let mut raw_total: u64 = 0;
    let mut buf = Vec::with_capacity(4096);
    let mut eof = false;
    let mut fb = 0usize;
    while first.len() < 2000 && fb < 256 * 1024 {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            eof = true;
            break;
        }
        raw_total += n as u64;
        let b = buf.strip_suffix(b"\n").unwrap_or(&buf);
        let l = clean_line(b);
        fb += l.len();
        first.push(l);
    }
    // named fields: the item's own spec when lines are appended, else --pattern/--fields/--kv/preset, or a guess
    let mut spec: Option<crate::setpat::ShapeSpec> = o.shape.clone();
    let mut fmt_over: Option<Fmt> = None;
    let mut low_conf: Option<String> = None;
    let mut guess_note: Option<String> = None;
    if let Some((id, ..)) = &append_to {
        let s: String = c.query_row("SELECT shape FROM items WHERE id=?", [id], |r| r.get(0)).unwrap_or_default();
        spec = serde_json::from_str(&s).ok();
    } else if o.auto {
        let red: Vec<String> = first.iter().take(200).map(|l| crate::logs::redact_text(l, o.keep_ips)).collect();
        let g = crate::setpat::guess(&red, &name);
        let pct = (g.rate * 100.0).round();
        let msg = format!("auto: {} -> {} (matches {} of {} sampled records, {pct}%)", g.what, if g.shown.is_empty() { "no pattern".to_string() } else { g.shown.clone() }, g.matched, g.sample);
        if g.fmt.is_some() {
            fmt_over = g.fmt;
            guess_note = Some(msg);
        } else if g.spec.is_some() && g.rate >= 0.8 {
            let mut sp = g.spec.clone().unwrap();
            for (k, v) in o.shape.as_ref().map(|x| x.types.clone()).unwrap_or_default() {
                sp.types.insert(k, v);
            }
            spec = Some(sp);
            guess_note = Some(msg);
        } else {
            spec = None;
            low_conf = Some(format!("{msg}: below 80%, so no fields were named (the lines are stored as plain text). Check the template, edit it if needed, and rerun: aix put {set} {} --replace {}", if src == "stdin" || src == "mcp" { format!("@{set}") } else { src.clone() }, if g.shown.is_empty() { "--pattern '<template>'".to_string() } else { g.shown.clone() }));
        }
    }
    let spec = spec.filter(|s| !s.is_empty());
    let shape = match &spec {
        Some(sp) => Some(sp.compile()?),
        None => None,
    };
    let (item_id, start_n, fmt, header) = match append_to {
        Some((id, last, f, h)) => (id, last + 1, f, h),
        None => {
            let fmt = fmt_over.or(o.fmt).unwrap_or_else(|| detect(&first, &name));
            let header: Vec<String> = match fmt {
                Fmt::Csv => first.iter().find(|l| !l.trim().is_empty()).and_then(|h| csv_split(&crate::logs::redact_text(h, o.keep_ips), ',')).unwrap_or_default(),
                Fmt::Tsv => first.iter().find(|l| !l.trim().is_empty()).map(|h| crate::logs::redact_text(h, o.keep_ips).split('\t').map(str::to_string).collect()).unwrap_or_default(),
                _ => vec![],
            };
            let header = dedup_header(header);
            c.execute(
                "INSERT INTO items(set_name, item, fmt, src, created, header, shape) VALUES(?,?,?,?,?,?,?)",
                params![set, item_nm, fmt.name(), crate::logs::redact_text(&src, true), now(), serde_json::to_string(&header)?, spec.as_ref().map(|s| serde_json::to_string(s).unwrap_or_default()).unwrap_or_default()],
            )?;
            (c.last_insert_rowid(), 1, fmt, header)
        }
    };
    let workers = crate::logs::pipeline_workers().max(1);
    let mut sink = Sink { c, item: item_id, next: start_n, bytes: 0, fmt, field_n: HashMap::new(), recs: 0, in_fence: false, shape: shape.as_ref(), pending: None, pst: ShapeStats::default() };
    let keep_ips = o.keep_ips;
    let mut stopped: Option<String> = None;
    let mut dropped_lines: u64 = 0;
    let raw_counter = std::sync::atomic::AtomicU64::new(raw_total);
    let clipped = std::sync::atomic::AtomicI64::new(0);
    let budget_hit = std::sync::atomic::AtomicBool::new(false);
    let mut err: Option<anyhow::Error> = None;
    let (tx_in, rx_in) = sync_channel::<(usize, Batch)>(workers * 2);
    let rx_in = Mutex::new(rx_in);
    let (tx_out, rx_out) = sync_channel::<(usize, Done)>(workers * 2);
    std::thread::scope(|sc| {
        let raw_counter = &raw_counter;
        let clipped = &clipped;
        let budget_hit = &budget_hit;
        // reader
        let reader_h = sc.spawn(move || -> (u64, Option<String>) {
            let mut idx = 0usize;
            let mut n = start_n;
            let mut cur: Vec<String> = Vec::with_capacity(BATCH_LINES);
            let mut cur_bytes = 0usize;
            let mut in_pem = false;
            let mut sent_bytes: u64 = 0;
            let mut dropped: u64 = 0;
            let mut err: Option<String> = None;
            let push = |l: String, cur: &mut Vec<String>, cur_bytes: &mut usize, in_pem: &mut bool| {
                let l = if l.len() > LINE_MAX {
                    clipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut e = LINE_MAX;
                    while !l.is_char_boundary(e) {
                        e -= 1;
                    }
                    l[..e].to_string()
                } else {
                    l
                };
                if l.contains("-----BEGIN") && l.contains("PRIVATE KEY") {
                    *in_pem = true;
                }
                if l.contains("-----END") {
                    *in_pem = false;
                }
                *cur_bytes += l.len() + 1;
                cur.push(l);
            };
            let mut over = false;
            for l in std::mem::take(&mut first) {
                push(l, &mut cur, &mut cur_bytes, &mut in_pem);
            }
            let mut b = Vec::with_capacity(4096);
            let mut eof = eof;
            loop {
                let full = cur.len() >= BATCH_LINES * 2 || cur_bytes >= BATCH_BYTES * 4;
                if !cur.is_empty() && (eof || ((cur.len() >= BATCH_LINES || cur_bytes >= BATCH_BYTES) && may_cut(&cur, in_pem)) || full) {
                    let k = cur.len() as i64;
                    sent_bytes += cur_bytes as u64;
                    if !over && sent_bytes > budget {
                        over = true;
                        budget_hit.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    if over {
                        dropped += k as u64;
                        cur.clear();
                    } else {
                        let batch = Batch { start: n, lines: std::mem::take(&mut cur) };
                        n += k;
                        if tx_in.send((idx, batch)).is_err() {
                            break;
                        }
                        idx += 1;
                    }
                    cur_bytes = 0;
                    cur.reserve(BATCH_LINES);
                }
                if eof {
                    break;
                }
                b.clear();
                match reader.read_until(b'\n', &mut b) {
                    Ok(0) => eof = true,
                    Ok(k) => {
                        raw_counter.fetch_add(k as u64, std::sync::atomic::Ordering::Relaxed);
                        if over {
                            // keep draining (a producer piping into us must not die of SIGPIPE), count, store nothing
                            dropped += 1;
                            continue;
                        }
                        let s = b.strip_suffix(b"\n").unwrap_or(&b);
                        push(clean_line(s), &mut cur, &mut cur_bytes, &mut in_pem);
                    }
                    Err(e) => {
                        err = Some(e.to_string());
                        eof = true;
                    }
                }
            }
            drop(tx_in);
            (dropped, err)
        });
        for _ in 0..workers {
            let tx = tx_out.clone();
            let rx = &rx_in;
            let header = &header;
            sc.spawn(move || loop {
                let m = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                let Ok((i, b)) = m else { break };
                let _ = b.start;
                let d = process(&b, fmt, keep_ips, header);
                if tx.send((i, d)).is_err() {
                    break;
                }
            });
        }
        drop(tx_out);
        let mut pending: std::collections::BTreeMap<usize, Done> = Default::default();
        let mut next = 0;
        for (i, d) in rx_out {
            pending.insert(i, d);
            while let Some(d) = pending.remove(&next) {
                if err.is_none() {
                    if let Err(e) = sink.write(d) {
                        err = Some(e);
                    }
                }
                next += 1;
            }
        }
        match reader_h.join() {
            Ok((d, e)) => {
                dropped_lines = d;
                if let Some(e) = e {
                    stopped = Some(format!("read error: {e}"));
                }
            }
            Err(_) => stopped = Some("reader failed".into()),
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    sink.finish()?;
    let raw_total = raw_counter.load(std::sync::atomic::Ordering::Relaxed);
    let mut notes: Vec<String> = vec![];
    let lines_added = sink.next - start_n;
    if budget_hit.load(std::sync::atomic::Ordering::Relaxed) {
        notes.push(format!("truncated: size cap reached, kept {} lines, dropped the last {} lines", lines_added, dropped_lines));
    }
    let cl = clipped.load(std::sync::atomic::Ordering::Relaxed);
    if cl > 0 {
        notes.push(format!("{cl} line(s) longer than {} MB clipped", LINE_MAX >> 20));
    }
    if let Some(s) = stopped {
        notes.push(s);
    }
    // structure that needs the whole item
    let pst = std::mem::take(&mut sink.pst);
    let mut recs = if shape.is_some() { pst.rows } else { sink.recs };
    let mut fields: Vec<(String, i64)> = sink.field_n.into_iter().collect();
    let total_lines = sink.next - 1;
    let total_bytes_item = sink.bytes;
    match fmt {
        Fmt::Csv | Fmt::Tsv => {
            recs = (total_lines - 1).max(0);
            fields = header.iter().map(|h| (h.clone(), recs)).collect();
        }
        Fmt::Json if append_to_is_none(start_n) => {
            let (prev_bytes,): (i64,) = c.query_row("SELECT bytes FROM items WHERE id=?", [item_id], |r| Ok((r.get(0)?,)))?;
            if (prev_bytes + total_bytes_item) as u64 <= JSON_DOC_MAX {
                let text = read_all(c, item_id)?;
                let rs = json_doc_records(&text);
                let mut fnum: HashMap<String, i64> = HashMap::new();
                let mut ins = c.prepare_cached("INSERT OR REPLACE INTO recs(id, j) VALUES(?, ?)")?;
                for (l, v) in &rs {
                    let mut kv = vec![];
                    flatten(v, "", &mut kv);
                    let mut ks: Vec<String> = kv.into_iter().map(|x| x.0).collect();
                    ks.dedup();
                    for k in ks {
                        *fnum.entry(k).or_default() += 1;
                    }
                    ins.execute(params![rid(item_id, *l), v.to_string()])?;
                }
                recs = rs.len() as i64;
                fields = fnum.into_iter().collect();
            } else {
                notes.push(format!("JSON document over {} MB: kept as lines (records not split; use JSONL for field queries)", JSON_DOC_MAX >> 20));
            }
        }
        _ => {}
    }
    if let Some(g) = guess_note {
        notes.insert(0, g);
    }
    if shape.is_some() && !append_to_is_none(start_n) {
        // appended lines: merge the field counts with what the item had
        let old: String = c.query_row("SELECT fields FROM items WHERE id=?", [item_id], |r| r.get(0)).unwrap_or_default();
        let old: Vec<(String, i64)> = serde_json::from_str(&old).unwrap_or_default();
        let mut m: HashMap<String, i64> = fields.into_iter().collect();
        for (k, n) in old {
            *m.entry(k).or_default() += n;
        }
        fields = m.into_iter().collect();
    }
    fields.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    fields.truncate(400);
    // the summary: fields (with types) and one example row, so the caller can query at once
    let mut summary = vec![];
    if let Some(sh) = &shape {
        let fl: Vec<String> = fields.iter().filter(|f| !f.0.starts_with('_')).take(24).map(|(f, _)| match sh.types.get(f) { Some(t) if *t != crate::setpat::Ty::Text => format!("{f}({})", t.name()), _ => f.clone() }).collect();
        summary.push(format!("fields: {} \u{b7} {} rows, {} unmatched{}", if fl.is_empty() { "(none)".to_string() } else { fl.join(" ") }, pst.rows, pst.unmatched, if pst.unmatched > 0 { " (field _raw)" } else { "" }));
        for (f, k) in &pst.bad {
            notes.push(format!("{f}: {k} value(s) did not parse as {} (kept as text)", sh.types.get(f).map(|t| t.name()).unwrap_or("its type")));
        }
        if let Some((n, ex)) = &pst.example {
            summary.push(format!("example :{n}: {}", clip_ex(ex)));
        }
    } else if !fields.is_empty() {
        let fl: Vec<String> = fields.iter().take(24).map(|f| f.0.clone()).collect();
        summary.push(format!("fields: {} \u{b7} {} records", fl.join(" "), recs));
    }
    let note = notes.join("; ");
    if shape.is_some() && !append_to_is_none(start_n) {
        c.execute("UPDATE items SET recs=0 WHERE id=?", [item_id])?;
        recs = c.query_row("SELECT count(*) FROM recs WHERE id>=?1 AND id<?2", params![rid(item_id, 0), rid(item_id + 1, 0)], |r| r.get::<_, i64>(0))?;
    }
    c.execute(
        "UPDATE items SET lines=?, bytes=bytes+?, recs=recs+?, fields=CASE WHEN ?4='' THEN fields ELSE ?4 END, note=CASE WHEN ?5='' THEN note ELSE ?5 END WHERE id=?6",
        params![total_lines, total_bytes_item, recs, if fields.is_empty() { String::new() } else { serde_json::to_string(&fields)? }, note, item_id],
    )?;
    if matches!(fmt, Fmt::Csv | Fmt::Tsv) {
        c.execute("UPDATE items SET recs=? WHERE id=?", params![recs, item_id])?;
    }
    Ok(ItemDone { name: item_nm.to_string(), fmt, lines: lines_added, bytes: total_bytes_item, recs, note, raw: raw_total, summary, low_conf })
}

fn clip_ex(s: &str) -> String {
    if s.chars().count() <= 220 {
        s.to_string()
    } else {
        s.chars().take(219).collect::<String>() + "\u{2026}"
    }
}

fn append_to_is_none(start_n: i64) -> bool {
    start_n == 1
}

fn dedup_header(h: Vec<String>) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    h.into_iter()
        .enumerate()
        .map(|(i, x)| {
            let x = x.trim().to_string();
            let x = if x.is_empty() { format!("col{}", i + 1) } else { x };
            let k = seen.entry(x.clone()).or_default();
            *k += 1;
            if *k > 1 {
                format!("{x}_{k}")
            } else {
                x
            }
        })
        .collect()
}

pub fn read_all(c: &Connection, item: i64) -> Result<String> {
    let mut q = c.prepare_cached("SELECT t FROM lines WHERE id>=?1 AND id<?2 ORDER BY id")?;
    let mut s = String::new();
    let mut rows = q.query(params![rid(item, 0), rid(item + 1, 0)])?;
    while let Some(r) = rows.next()? {
        let t: String = r.get(0)?;
        s.push_str(&t);
        s.push('\n');
    }
    Ok(s)
}

/// `put`: store the inputs as items of `set`. Default for an existing name: replace it (and say so); `--append` adds
/// items (or lines, to `--item NAME`), `--keep` refuses.
/// Stdin inputs copied to an unlinked spool file (see `put`); file inputs are left as they are.
/// At most `cap` + 1 bytes are kept (the item's own size cap then reports the cut); the rest is drained.
fn spool_stdin(inputs: Vec<Input>, dir: &Path, cap: u64) -> Result<Vec<Input>> {
    let mut v = Vec::with_capacity(inputs.len());
    for mut i in inputs {
        if i.src != "stdin" {
            v.push(i);
            continue;
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let sp = dir.join(format!(".put-spool-{}-{nanos}", std::process::id()));
        let mut f = crate::sys::private_file(std::fs::OpenOptions::new().read(true).write(true).create_new(true)).open(&sp)?;
        let _ = std::fs::remove_file(&sp); // unlinked: readable through `f` only, gone with it
        {
            use std::io::Read;
            std::io::copy(&mut (&mut i.reader).take(cap.saturating_add(1)), &mut f)?;
        }
        let _ = std::io::copy(&mut i.reader, &mut std::io::sink());
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(0))?;
        i.reader = Box::new(std::io::BufReader::with_capacity(1 << 20, f));
        v.push(i);
    }
    Ok(v)
}

/// A write transaction that waits for another writer (up to 60 s, `AIX_STORE_BUSY_MS` per try) instead of failing
/// with "database is locked" when several agents store data at once.
fn with_tx_patient<T>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    let t0 = std::time::Instant::now();
    loop {
        match conn.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => break,
            Err(e) if t0.elapsed() < std::time::Duration::from_secs(60) && matches!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(e.into()),
        }
    }
    match f(conn) {
        Ok(v) => {
            conn.execute_batch("COMMIT")?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

pub fn put(st: &SetStore, set: &str, inputs: Vec<Input>, o: &PutOpts) -> Result<PutReport> {
    if !valid_name(set) {
        bail!("bad set name {set:?}: letters, digits, '_', '-', '.' (start with a letter or digit, at most 64)");
    }
    let t0 = std::time::Instant::now();
    let size0 = std::fs::metadata(&st.path).map(|m| m.len() as i64).unwrap_or(0);
    let _ = prune(st);
    let mut rep = PutReport::default();
    let had = exists(st, set);
    if had && o.keep && !o.append {
        // drain nothing: the caller decided before reading; say what to do
        bail!("set {set} exists: add --append to add items, --replace to start over (aix sets lists them)");
    }
    let set_cap = o.max_bytes.unwrap_or_else(set_cap_bytes);
    let total_cap = total_cap_bytes();
    // piped input (`cmd 2>&1 | aix put t -`) is read to its end BEFORE the write transaction: a long test run must not
    // hold the store's write lock for its whole duration (another `aix put` would fail with "database is locked").
    // The spool is an unlinked 0600 file next to the store (nothing to clean up; gone when this process ends).
    let inputs = spool_stdin(inputs, st.path.parent().unwrap_or(Path::new(".")), set_cap.min(total_cap) as u64)?;
    let res = with_tx_patient(&st.conn, |c| {
        if had && !o.append {
            rep.replaced = Some(delete_set_rows(c, set)?);
        }
        let ttl = o.ttl.unwrap_or(DEFAULT_TTL);
        if had && o.append {
            c.execute("UPDATE sets SET updated=?, ttl=COALESCE(?, ttl), note=COALESCE(?, note) WHERE name=?", params![now(), o.ttl, o.note.as_deref().map(|n| crate::logs::redact_text(n, true)), set])?;
        } else {
            c.execute("INSERT INTO sets(name, created, updated, used, ttl, note) VALUES(?,?,?,?,?,?)", params![set, now(), now(), now(), ttl, o.note.as_deref().map(|n| crate::logs::redact_text(n, true)).unwrap_or_default()])?;
        }
        let mut used_set: i64 = c.query_row("SELECT COALESCE(sum(bytes),0) FROM items WHERE set_name=?", [set], |r| r.get(0))?;
        let mut used_total: i64 = c.query_row("SELECT COALESCE(sum(bytes),0) FROM items", [], |r| r.get(0))?;
        for inp in inputs {
            let budget = (set_cap as i64 - used_set).min(total_cap as i64 - used_total).max(0) as u64;
            // --item NAME of an existing item: append its lines
            let target = o.item.clone().unwrap_or_else(|| item_name(&inp.name));
            let existing: Option<(i64, i64, String, String)> = c.query_row("SELECT id, lines, fmt, header FROM items WHERE set_name=? AND item=?", params![set, target], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).ok();
            let (nm, append_to) = match existing {
                Some((id, lines, f, h)) if o.item.is_some() => (target.clone(), Some((id, lines, Fmt::from_name(&f), serde_json::from_str(&h).unwrap_or_default()))),
                Some(_) => {
                    let mut k = 2;
                    loop {
                        let cand = format!("{target}-{k}");
                        if c.query_row("SELECT 1 FROM items WHERE set_name=? AND item=?", params![set, cand], |_| Ok(())).is_err() {
                            break (cand, None);
                        }
                        k += 1;
                    }
                }
                None => (target.clone(), None),
            };
            if budget == 0 {
                rep.notes.push(format!("{nm}: not stored: size cap reached (set cap {} MB via --max-mb / AIX_SETS_MAX_MB, all sets {} MB via AIX_SETS_TOTAL_MB; aix sets rm <name> frees space)", set_cap >> 20, total_cap >> 20));
                let mut r = inp.reader;
                let mut sink = std::io::sink();
                let _ = std::io::copy(&mut r, &mut sink);
                continue;
            }
            let d = ingest_one(c, set, &nm, append_to, inp, o, budget)?;
            let ItemDone { name: nm, fmt, lines, bytes, recs, note, raw, summary, low_conf } = d;
            for l in summary {
                rep.summaries.push(format!("@{set}/{nm} {l}"));
            }
            if low_conf.is_some() {
                rep.low_conf = low_conf;
            }
            rep.raw_bytes += raw;
            used_set += bytes;
            used_total += bytes;
            if !note.is_empty() {
                let capmsg = if note.contains("size cap") { format!(" (set cap {} MB: --max-mb N or AIX_SETS_MAX_MB; all sets {} MB: AIX_SETS_TOTAL_MB)", set_cap >> 20, total_cap >> 20) } else { String::new() };
                rep.notes.push(format!("{nm}: {note}{capmsg}"));
            }
            rep.items.push((nm, fmt.name().to_string(), lines, bytes, recs));
        }
        Ok(())
    });
    res?;
    shrink(&st.conn);
    rep.secs = t0.elapsed().as_secs_f64();
    rep.db_growth = std::fs::metadata(&st.path).map(|m| m.len() as i64).unwrap_or(0) - size0;
    Ok(rep)
}

/// Re-apply the user's masks to stored set data (`aix mask add --purge`).
pub fn remask(dir: &Path) -> usize {
    let mut n = 0;
    for (d, g) in [(Some(dir.to_path_buf()), false), (global_dir(), true)] {
        let Some(d) = d else { continue };
        let Ok(Some(st)) = open(&d, g, false) else { continue };
        for (table, col) in [("lines", "t"), ("recs", "j")] {
            let rows: Vec<(i64, String)> = st.conn.prepare(&format!("SELECT id, {col} FROM {table}")).and_then(|mut q| q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map(|i| i.flatten().collect())).unwrap_or_default();
            let _ = crate::logs::with_tx(&st.conn, |c| {
                for (id, t) in &rows {
                    if let Some(new) = aix_extract::masks::apply(t) {
                        c.execute(&format!("UPDATE {table} SET {col}=? WHERE id=?"), params![new, id])?;
                        n += 1;
                    }
                }
                Ok(())
            });
        }
    }
    n
}

/// A path for `put`, checked like `aix attach` (credential stores, home dot-folders, foreign owners are refused).
pub fn open_input(p: &Path, repo: &Path, allow_dot: bool) -> Result<Input> {
    let canon = crate::logs::check_path_with(p, repo, allow_dot)?;
    // git's own files (config with remotes and credentials helpers, hooks, objects) are never data
    if canon.components().any(|c| c.as_os_str() == ".git") {
        bail!("{}: refused (inside a .git directory)", crate::logs::display_path(&p.to_string_lossy()));
    }
    let md = std::fs::metadata(&canon)?;
    if !md.is_file() {
        bail!("{}: not a regular file", crate::logs::display_path(&p.to_string_lossy()));
    }
    let f = crate::sys::open_nofollow(&canon, false).map_err(|e| anyhow!("{}: {e}", crate::logs::display_path(&p.to_string_lossy())))?;
    let name = canon.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".into());
    let rel = canon.strip_prefix(crate::sys::canonicalize(&repo).unwrap_or(repo.to_path_buf())).map(crate::sys::slash).unwrap_or_else(|_| crate::logs::display_path(&canon.to_string_lossy()));
    Ok(Input { name, src: rel, reader: Box::new(std::io::BufReader::with_capacity(1 << 20, f)) })
}

/// Expand a glob (`logs/*.log`, `~/Downloads/*.csv`, `data/**/*.jsonl`); plain paths pass through.
pub fn expand_glob(pat: &str) -> Vec<PathBuf> {
    let pat = if let Some(rest) = pat.strip_prefix("~/") { crate::sys::home().map(|h| h.join(rest).to_string_lossy().to_string()).unwrap_or_else(|| pat.to_string()) } else { pat.to_string() };
    if !pat.contains(['*', '?', '[']) {
        return vec![PathBuf::from(pat)];
    }
    let comps: Vec<&str> = pat.split('/').collect();
    let k = comps.iter().position(|c| c.contains(['*', '?', '['])).unwrap_or(comps.len());
    let base = if k == 0 { ".".to_string() } else if comps[..k].join("/").is_empty() { "/".into() } else { comps[..k].join("/") };
    let rest: Vec<&str> = comps[k..].to_vec();
    let mut out = vec![];
    fn walk(dir: &Path, rest: &[&str], out: &mut Vec<PathBuf>, depth: usize) {
        if rest.is_empty() || depth > 32 || out.len() > 10_000 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let mut ents: Vec<_> = rd.flatten().collect();
        ents.sort_by_key(|e| e.file_name());
        for e in ents {
            let n = e.file_name().to_string_lossy().to_string();
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            if rest[0] == "**" {
                // zero directories, or descend
                walk(dir, &rest[1..], out, depth + 1);
                if is_dir && !n.starts_with('.') {
                    walk(&e.path(), rest, out, depth + 1);
                }
                return;
            }
            if n.starts_with('.') && !rest[0].starts_with('.') {
                continue;
            }
            if glob1(rest[0], &n) {
                if rest.len() == 1 {
                    if !is_dir {
                        out.push(e.path());
                    }
                } else if is_dir {
                    walk(&e.path(), &rest[1..], out, depth + 1);
                }
            }
        }
    }
    walk(Path::new(&base), &rest, &mut out, 0);
    out.sort();
    out.dedup();
    out
}

/// One path component against `*`, `?`, `[abc]`.
pub fn glob1(p: &str, s: &str) -> bool {
    let p: Vec<char> = p.chars().collect();
    let s: Vec<char> = s.chars().collect();
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => (0..=s.len()).any(|i| go(&p[1..], &s[i..])),
            Some('?') => !s.is_empty() && go(&p[1..], &s[1..]),
            Some('[') => {
                let Some(end) = p.iter().position(|c| *c == ']') else { return !s.is_empty() && s[0] == '[' && go(&p[1..], &s[1..]) };
                let set = &p[1..end];
                let (neg, set) = if set.first() == Some(&'!') || set.first() == Some(&'^') { (true, &set[1..]) } else { (false, set) };
                let Some(c) = s.first() else { return false };
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        hit |= set[i] <= *c && *c <= set[i + 2];
                        i += 3;
                    } else {
                        hit |= set[i] == *c;
                        i += 1;
                    }
                }
                hit != neg && go(&p[end + 1..], &s[1..])
            }
            Some(c) => !s.is_empty() && s[0] == *c && go(&p[1..], &s[1..]),
        }
    }
    go(&p, &s)
}

/// `7d`, `12h`, `never` (0 = no expiry). A negative or zero duration is refused (`never` says it).
pub fn parse_ttl(s: &str) -> Option<i64> {
    match s {
        "never" | "none" | "off" => Some(0),
        _ => crate::logs::parse_duration(s).filter(|d| *d > 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_and_flatten() {
        assert_eq!(csv_split(r#"a,"b,c","d""e",f"#, ',').unwrap(), vec!["a", "b,c", "d\"e", "f"]);
        assert!(csv_split(r#"a,"b"#, ',').is_none());
        let v: Value = serde_json::from_str(r#"{"user":{"role":"a"},"items":[{"sku":1},{"sku":"x"}],"n":null}"#).unwrap();
        let mut kv = vec![];
        flatten(&v, "", &mut kv);
        assert!(kv.contains(&("user.role".into(), "a".into())) && kv.contains(&("items[].sku".into(), "1".into())) && kv.contains(&("n".into(), "null".into())));
        assert!(glob1("*.log", "a.log") && !glob1("*.log", "a.txt") && glob1("a[0-9].csv", "a7.csv"));
    }
    #[test]
    fn json_doc() {
        let t = "[\n  {\"a\": 1},\n  {\"a\": [2, 3],\n   \"b\": \"x,]\"}\n]\n";
        let r = json_doc_records(t);
        assert_eq!(r.iter().map(|x| x.0).collect::<Vec<_>>(), vec![2, 3]);
    }
}
