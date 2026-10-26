//! Code graph storage and resolution: `members` and `refs` are per-file facts (replaced when a file changes);
//! `call_edges` (ref -> member, with confidence) and `sym_fanin` are derived and rebuilt only for dirty keys:
//! the refs of changed files plus the refs whose callee name is defined (or was defined) in a changed file.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rusqlite::{params, Transaction};
use aix_extract::Rows;

use crate::index::{resolve_import, Index};

mod overload;
mod xq;

/// Indexes added after the schema version (created by every update when missing): the refs a dirty type or function
/// result reaches, the members by return type, the type hierarchy (read whole by a partial graph), and the snapshot of
/// changed files' members by file (read once per changed file: without it 10,000 changed files scanned it 10,000 times).
pub const LATE_DDL: &str = "CREATE INDEX IF NOT EXISTS refs_rt ON refs(recv_type) WHERE recv_type<>'';
CREATE INDEX IF NOT EXISTS members_ret ON members(ret) WHERE ret<>'';
CREATE INDEX IF NOT EXISTS members_sup ON members(file, line) WHERE supers<>'';
CREATE INDEX IF NOT EXISTS cg_oldm_file ON cg_oldm(file, line);";

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS members(file TEXT, line INT, end_line INT, name TEXT, container TEXT, qname TEXT, kind TEXT,
  sig TEXT, vis TEXT, annos TEXT, is_static INT, supers TEXT, ret TEXT);
CREATE INDEX IF NOT EXISTS members_file ON members(file, line);
CREATE INDEX IF NOT EXISTS members_name ON members(name);
CREATE INDEX IF NOT EXISTS members_cn ON members(container, name);
CREATE TABLE IF NOT EXISTS refs(fid INT, line INT, caller_line INT, callee TEXT, recv TEXT, recv_type TEXT, kind TEXT, conf TEXT, argc INT);
CREATE INDEX IF NOT EXISTS refs_file ON refs(fid, caller_line);
CREATE INDEX IF NOT EXISTS refs_callee ON refs(callee, kind);
CREATE TABLE IF NOT EXISTS call_edges(fid INT, line INT, caller_line INT, cfid INT, callee_line INT, callee TEXT, cname TEXT, kind TEXT, conf TEXT);
CREATE INDEX IF NOT EXISTS ce_callee ON call_edges(cfid, callee_line);
CREATE INDEX IF NOT EXISTS ce_caller ON call_edges(fid, caller_line);
CREATE INDEX IF NOT EXISTS ce_cname ON call_edges(cname);
-- path-named views (the tables hold files.rowid instead of the path: half the size)
CREATE VIEW IF NOT EXISTS refs_v AS SELECT f.path AS file, r.line AS line,
  COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=r.caller_line LIMIT 1), '') AS caller,
  r.caller_line AS caller_line, r.callee AS callee, r.recv AS recv, r.recv_type AS recv_type, r.kind AS kind, r.conf AS conf, r.argc AS argc
  FROM refs r JOIN files f ON f.rowid=r.fid;
CREATE VIEW IF NOT EXISTS call_edges_v AS SELECT f.path AS file, e.line AS line,
  COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=e.caller_line LIMIT 1), '') AS caller,
  e.caller_line AS caller_line, g.path AS callee_file, e.callee_line AS callee_line, e.callee AS callee, e.cname AS cname,
  e.kind AS kind, e.conf AS conf
  FROM call_edges e JOIN files f ON f.rowid=e.fid JOIN files g ON g.rowid=e.cfid;
CREATE TABLE IF NOT EXISTS sym_fanin(file TEXT, line INT, qname TEXT, n INT, files INT, PRIMARY KEY(file, line));
CREATE TABLE IF NOT EXISTS cg_dirty(kind TEXT, key TEXT, PRIMARY KEY(kind, key));
-- targets whose fan-in must be recounted
CREATE TABLE IF NOT EXISTS cg_touch(cfid INT, line INT, PRIMARY KEY(cfid, line));
-- edges into / re-resolved by a changed file as they were before the update (compared afterwards: callers whose edges moved are dirty for the trace layer)
-- a changed file's members and the edges into it from other files, as they were before the update: names whose
-- definitions kept their shape (only lines moved) are not re-resolved, their edges come back with the new lines
CREATE TABLE IF NOT EXISTS cg_oldm(file TEXT, line INT, name TEXT, shape TEXT, is_type INT);
CREATE TABLE IF NOT EXISTS cg_keep(fid INT, line INT, caller_line INT, cfid INT, callee_line INT, callee TEXT, cname TEXT, kind TEXT, conf TEXT);
CREATE TABLE IF NOT EXISTS cg_old(fid INT, line INT, caller_line INT, cfid INT, callee_line INT, PRIMARY KEY(fid, line, caller_line, cfid, callee_line)) WITHOUT ROWID;
"#;

/// Per-file tables owned by the code graph (added to the engine's FILE_TABLES).
pub const FILE_TABLES: &[&str] = &["members"];
/// Everything about a member the resolver reads, except where it sits: equal shapes resolve the same refs.
const SHAPE: &str = "json_array(name, COALESCE(container,''), qname, kind, COALESCE(sig,''), COALESCE(supers,''), COALESCE(annos,''), COALESCE(ret,''), COALESCE(vis,''), COALESCE(is_static,0))";
/// Member kinds that carry a hierarchy (`supers`): when one changes, every name in its file re-resolves.
const TYPE_KINDS: &str = "'class','interface','enum','record','struct','trait','type','object','annotation','protocol','module','impl'";

/// Everything wiped by a full rebuild.
pub const WIPE_TABLES: &[&str] = &["members", "refs"];

/// Before a file's rows are dropped: its member names and the file itself become dirty.
pub fn mark_dirty_file(tx: &Transaction, path: &str) -> Result<()> {
    tx.prepare_cached("INSERT OR IGNORE INTO cg_dirty SELECT 'n', name FROM members WHERE file=?")?.execute([path])?;
    // first change of this file in the update only (a file is not snapshotted twice)
    tx.prepare_cached(&format!(
        "INSERT INTO cg_oldm SELECT file, line, name, {SHAPE}, kind IN ({TYPE_KINDS}) FROM members WHERE file=?1 AND NOT EXISTS (SELECT 1 FROM cg_dirty WHERE kind='f' AND key=?1)"
    ))?
    .execute([path])?;
    tx.prepare_cached(
        "INSERT INTO cg_keep SELECT fid, line, caller_line, cfid, callee_line, callee, cname, kind, conf FROM call_edges
         WHERE cfid IN (SELECT rowid FROM files WHERE path=?1) AND fid NOT IN (SELECT rowid FROM files WHERE path=?1)
           AND NOT EXISTS (SELECT 1 FROM cg_dirty WHERE kind='f' AND key=?1)",
    )?
    .execute([path])?;
    tx.prepare_cached("INSERT OR IGNORE INTO cg_dirty VALUES('f', ?)")?.execute([path])?;
    tx.prepare_cached("DELETE FROM refs WHERE fid IN (SELECT rowid FROM files WHERE path=?)")?.execute([path])?;
    tx.prepare_cached("INSERT OR IGNORE INTO cg_touch SELECT cfid, callee_line FROM call_edges WHERE fid IN (SELECT rowid FROM files WHERE path=?)")?.execute([path])?;
    tx.prepare_cached("INSERT OR IGNORE INTO cg_old SELECT fid, line, caller_line, cfid, callee_line FROM call_edges WHERE cfid IN (SELECT rowid FROM files WHERE path=?1) AND fid NOT IN (SELECT rowid FROM files WHERE path=?1)")?.execute([path])?;
    // edges from the file go (the resolver rebuilds them); edges into it stay until their callee names re-resolve
    tx.prepare_cached("DELETE FROM call_edges WHERE fid IN (SELECT rowid FROM files WHERE path=?) OR cfid IN (SELECT rowid FROM files WHERE path=?)")?.execute([path, path])?;
    Ok(())
}

pub fn insert(tx: &Transaction, rows: &Rows) -> Result<()> {
    let rd = |s: &str| crate::par::rd(s);
    {
        let mut st = tx.prepare_cached("INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
        let mut dn = tx.prepare_cached("INSERT OR IGNORE INTO cg_dirty VALUES('n', ?)")?;
        for m in &rows.members {
            st.execute(params![
                m.file,
                m.line,
                m.end_line,
                m.name,
                m.container,
                m.qname,
                m.kind,
                rd(&m.sig),
                m.vis,
                rd(&m.annos.join(", ")),
                m.is_static,
                m.supers.join(","),
                m.ret
            ])?;
            dn.execute([&m.name])?;
        }
    }
    {
        let mut st = tx.prepare_cached("INSERT INTO refs VALUES(?,?,?,?,?,?,?,?,?)")?;
        let mut fids: HashMap<&str, i64> = HashMap::new();
        for r in &rows.refs {
            let fid = match fids.get(r.file.as_str()) {
                Some(f) => *f,
                None => {
                    let f: i64 = tx.query_row("SELECT rowid FROM files WHERE path=?", [&r.file], |x| x.get(0))?;
                    fids.insert(r.file.as_str(), f);
                    f
                }
            };
            st.execute(params![fid, r.line, r.caller_line, r.callee, rd(&r.recv), r.recv_type, r.kind, r.conf, r.argc])?;
        }
    }
    let mut files: HashSet<&str> = rows.members.iter().map(|m| m.file.as_str()).collect();
    files.extend(rows.refs.iter().map(|r| r.file.as_str()));
    for f in files {
        tx.prepare_cached("INSERT OR IGNORE INTO cg_dirty VALUES('f', ?)")?.execute([f])?;
    }
    Ok(())
}

/// Shared, immutable text: a kernel-size graph holds millions of members, and most of their strings repeat (the file,
/// the kind, the container, an empty annotation), so one allocation is shared through the interner in `fill`.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Str(Arc<str>);
impl Str {
    fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::ops::Deref for Str {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}
impl std::borrow::Borrow<str> for Str {
    fn borrow(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Display for Str {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl From<String> for Str {
    fn from(s: String) -> Str {
        Str(s.into())
    }
}
impl PartialEq<str> for Str {
    fn eq(&self, o: &str) -> bool {
        *self.0 == *o
    }
}
impl PartialEq<&str> for Str {
    fn eq(&self, o: &&str) -> bool {
        *self.0 == **o
    }
}
impl PartialEq<String> for Str {
    fn eq(&self, o: &String) -> bool {
        *self.0 == **o
    }
}
impl PartialEq<Str> for &str {
    fn eq(&self, o: &Str) -> bool {
        **self == *o.0
    }
}
impl PartialEq<Str> for String {
    fn eq(&self, o: &Str) -> bool {
        **self == *o.0
    }
}

struct M {
    file: Str,
    line: i64,
    name: Str,
    container: Str,
    qname: Str,
    kind: Str,
    supers: Vec<String>,
    annos: Str,
    ret: Str,
    /// (min, max) argument count from the signature; max -1 = unbounded
    arity: Option<(i32, i32)>,
    /// parameter types (JVM / C# only: same-arity overloads are told apart by them)
    params: Vec<String>,
    /// Go interface: its method names (`a; b`), from the signature
    iface: Str,
    /// JVM: the element type of a one-argument collection result (`List<Visit> getVisits()` -> `Visit`)
    elem: String,
}

/// `List<Visit> getVisits()` -> `Visit`: the element type of a JVM method's collection result.
fn sig_elem(sig: &str, name: &str) -> String {
    let Some(head) = sig.split_once(&format!(" {name}(")).map(|x| x.0) else { return String::new() };
    let ret = head.rsplit(|c: char| c.is_whitespace() && !head.contains('<')).next().unwrap_or(head);
    let Some((outer, inner)) = ret.split_once('<') else { return String::new() };
    let outer = outer.rsplit([' ', '.']).next().unwrap_or(outer);
    const C: &[&str] = &["List", "Set", "Collection", "Iterable", "Stream", "Optional", "ArrayList", "LinkedList", "HashSet", "LinkedHashSet", "TreeSet", "SortedSet", "Deque", "Queue"];
    let inner = inner.trim_end_matches('>').trim();
    if !C.contains(&outer) || inner.contains([',', '<', '?']) {
        return String::new();
    }
    inner.rsplit('.').next().unwrap_or(inner).to_string()
}

/// Parameter-count range of a signature (`name(a, b = 1, *rest)`): None when it has no parameter list.
pub fn sig_arity(sig: &str, lang_py: bool) -> Option<(i32, i32)> {
    // Go method: `func (r *T) name(a, b)`: the first group is the receiver
    let from = if sig.starts_with("func (") { sig.find(')').map(|i| i + 1)? } else { 0 };
    let open = from + sig[from..].find('(')?;
    let mut depth = 0i32;
    let (mut params, mut cur): (Vec<String>, String) = (vec![], String::new());
    let mut closed = false;
    for c in sig[open..].chars() {
        match c {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                if depth > 1 {
                    cur.push(c);
                }
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                if depth == 0 {
                    closed = true;
                    break;
                }
                cur.push(c);
            }
            ',' if depth == 1 => params.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if !closed {
        return None; // truncated signature
    }
    if !cur.trim().is_empty() {
        params.push(cur);
    }
    let (mut min, mut max) = (0i32, 0i32);
    for (i, p) in params.iter().enumerate() {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if lang_py && i == 0 && (p == "self" || p == "cls" || p.starts_with("self:") || p.starts_with("self,")) {
            continue;
        }
        if p.starts_with('*') || p.starts_with("...") || p.contains("...") {
            // *args / **kwargs / varargs: unbounded, the keyword-only `*` marker adds nothing
            if p != "*" {
                max = -2;
            }
            continue;
        }
        if p == "/" {
            continue;
        }
        let optional = p.contains('=') || p.split(':').next().is_some_and(|n| n.trim().ends_with('?'));
        if !optional {
            min += 1;
        }
        if max != -2 {
            max += 1;
        }
    }
    Some((min, if max == -2 { -1 } else { max }))
}

fn callable(kind: &str) -> bool {
    matches!(kind, "method" | "ctor" | "function" | "component")
}
fn is_type(kind: &str) -> bool {
    matches!(kind, "class" | "interface" | "enum" | "record")
}

/// Very common library method names: a name-only match on these would be noise.
const NOISE: &[&str] = &[
    "get",
    "set",
    "add",
    "put",
    "remove",
    "size",
    "length",
    "toString",
    "equals",
    "hashCode",
    "stream",
    "collect",
    "of",
    "then",
    "catch",
    "join",
    "split",
    "trim",
    "includes",
    "map",
    "filter",
    "forEach",
    "push",
    "pop",
    "slice",
    "keys",
    "values",
    "entries",
    "has",
    "delete",
    "clear",
    "find",
    "reduce",
    "some",
    "every",
    "sort",
    "concat",
    "indexOf",
    "toLowerCase",
    "toUpperCase",
    "startsWith",
    "endsWith",
    "replace",
    "isEmpty",
    "contains",
    "format",
    "valueOf",
    "name",
    "close",
    "run",
    "apply",
    "accept",
    "test",
    "build",
    "parse",
    "stringify",
    "log",
    "error",
    "warn",
    "info",
    "debug",
    "append",
    "write",
    "read",
    "open",
    "send",
    "next",
    "items",
    "update",
    "count",
    "list",
    "save",
    "load",
    "init",
    "main",
    "call",
    "start",
    "stop",
    "create",
    "getMessage",
    "orElse",
    "isPresent",
    "ifPresent",
    "limit",
    "mapToInt",
    "toList",
    "equalsIgnoreCase",
];


/// Std / collection / string / Option / Result / iterator methods of Rust: a name match would pin them on some project type.
const RS_NOISE: &[&str] = &[
    "len",
    "exists",
    "iter",
    "iter_mut",
    "into_iter",
    "clone",
    "unwrap",
    "expect",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "to_string",
    "to_owned",
    "to_vec",
    "as_str",
    "as_ref",
    "as_mut",
    "as_bytes",
    "as_slice",
    "is_some",
    "is_none",
    "is_ok",
    "is_err",
    "ok",
    "err",
    "ok_or",
    "ok_or_else",
    "map_err",
    "and_then",
    "or_else",
    "cloned",
    "copied",
    "take",
    "skip",
    "enumerate",
    "zip",
    "rev",
    "chain",
    "flatten",
    "filter_map",
    "flat_map",
    "fold",
    "sum",
    "min",
    "max",
    "any",
    "all",
    "position",
    "first",
    "last",
    "lines",
    "chars",
    "bytes",
    "trim_start",
    "trim_end",
    "strip_prefix",
    "strip_suffix",
    "contains_key",
    "get_mut",
    "insert",
    "extend",
    "drain",
    "retain",
    "entry",
    "or_insert",
    "or_insert_with",
    "or_default",
    "push_str",
    "borrow",
    "borrow_mut",
    "lock",
    "into",
    "try_into",
    "is_match",
    "is_dir",
    "is_file",
    "parent",
    "file_name",
    "to_str",
    "to_path_buf",
    "display",
    "elapsed",
    "flush",
    "matches",
    "replace_all",
];

/// Receivers that are language/runtime globals, never project code.
const GLOBALS: &[&str] = &[
    "Math",
    "JSON",
    "Object",
    "Array",
    "Promise",
    "console",
    "window",
    "document",
    "Number",
    "String",
    "Date",
    "localStorage",
    "sessionStorage",
    "navigator",
    "URL",
    "Intl",
    "Reflect",
    "Set",
    "Map",
    "Symbol",
    "BigInt",
    "Boolean",
    "RegExp",
    "Error",
    "process",
    "os",
    "sys",
    "re",
    "json",
    "time",
    "logging",
    "System",
    "Arrays",
    "Collections",
    "Objects",
    "Files",
    "Paths",
    "Instant",
    "Duration",
    "LocalDate",
    "Optional",
    "Stream",
    "Collectors",
    "Logger",
    "log",
    "Thread",
    "UUID",
];

struct Graph {
    ms: Vec<M>,
    // keyed by member name (complete only for the names in `part`, when partial): use the accessors below
    by_name_: HashMap<Str, Vec<usize>>,
    // (container, name) -> members, keyed by a hash of the pair (no copy of both strings per member); a pair whose
    // hash collides with another pair's lives in `by_cn_x`, so a lookup is exact
    by_cn_: HashMap<u64, Vec<usize>>,
    by_cn_x: HashMap<(String, String), Vec<usize>>,
    cn_hash: std::collections::hash_map::RandomState,
    types_: HashMap<Str, Vec<usize>>,
    subs: HashMap<String, Vec<String>>,
    files: HashSet<String>,
    fids: HashMap<String, i64>,
    py_mods: HashMap<String, Vec<String>>,
    /// per file: import and re-export bindings (callee in the source module, specifier, local / exported name, kind)
    imps_: HashMap<String, Vec<Imp>>,
    ts: Vec<TsCfg>,
    ts_sig: String,
    /// go.mod: (directory, module path)
    go_mods: Vec<(String, String)>,
    repo: std::path::PathBuf,
    /// Rust module files by stem (`a.rs`, `a/mod.rs` -> `a`), the crate roots (lib.rs / main.rs), the callable member at a line
    rs_stems: HashMap<String, Vec<String>>,
    rs_roots: Vec<String>,
    rs_at_: HashMap<(String, i64), usize>,
    /// Rust sources read on demand (inline `mod` blocks, path qualifiers)
    rs_src: Mutex<HashMap<String, Option<Arc<RsText>>>>,
    /// other sources read on demand (overloaded calls: the argument text)
    src_: Mutex<HashMap<String, Option<Arc<Vec<String>>>>>,
    /// directory -> its build module root (nearest ancestor with a build file), cached
    mod_root_: Mutex<HashMap<String, String>>,
    /// C family: file name -> paths (to resolve `#include "x.h"` / `<a/x.h>`), and the resolved includes of each header
    c_names: HashMap<String, Vec<String>>,
    c_inc: Mutex<HashMap<String, Arc<Vec<String>>>>,
    /// None: every member is loaded. Some: only the keys listed (see [`Keys`]); a lookup outside them is recorded
    part: Option<Part>,
}

/// What a partial graph holds: every member named one of `names` (so by name, by (container, name) and the types of
/// that name are complete), the import bindings of the files in `imps`, and every member of the files in `rs_at`.
#[derive(Default, Clone)]
struct Keys {
    names: HashSet<String>,
    imps: HashSet<String>,
    rs_at: HashSet<String>,
}

impl Keys {
    fn len(&self) -> usize {
        self.names.len() + self.imps.len() + self.rs_at.len()
    }
}

/// A partial graph's keys and the lookups it could not answer (filled while resolving, read after).
struct Part {
    keys: Keys,
    miss: Mutex<Keys>,
}

/// A Rust file as the resolver reads it: its lines and the inline `mod x { }` blocks (first line, last line, path).
pub struct RsText {
    lines: Vec<String>,
    mods: Vec<(i64, i64, Vec<String>)>,
}

impl RsText {
    /// The inline module path (outermost first) that holds `line`.
    fn stack_at(&self, line: i64) -> Vec<String> {
        self.mods.iter().filter(|m| m.0 <= line && line <= m.1).max_by_key(|m| m.2.len()).map(|m| m.2.clone()).unwrap_or_default()
    }
}

/// Find the inline `mod name { ... }` blocks of a Rust source (comments and strings skipped, braces counted).
fn scan_rs(text: &str) -> RsText {
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut mods: Vec<(i64, i64, Vec<String>)> = vec![];
    let mut open: Vec<(String, i64, i64)> = vec![]; // name, brace depth at the `{`, first line
    let (mut depth, mut block, mut in_str) = (0i64, 0u32, false);
    let mut pending: Option<String> = None;
    let mut prev = String::new();
    let has_mod = text.contains("mod ");
    for (n, l) in lines.iter().enumerate() {
        let ln = n as i64 + 1;
        if !has_mod {
            break;
        }
        let cs: Vec<char> = l.chars().collect();
        let (mut i, mut word) = (0usize, String::new());
        let end_word = |word: &mut String, prev: &mut String, pending: &mut Option<String>| {
            if !word.is_empty() {
                if prev == "mod" {
                    *pending = Some(word.clone());
                }
                *prev = std::mem::take(word);
            }
        };
        while i < cs.len() {
            let c = cs[i];
            if block > 0 {
                if c == '*' && cs.get(i + 1) == Some(&'/') {
                    block -= 1;
                    i += 2;
                } else if c == '/' && cs.get(i + 1) == Some(&'*') {
                    block += 1;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_str {
                if c == '\\' {
                    i += 2;
                } else {
                    if c == '"' {
                        in_str = false;
                    }
                    i += 1;
                }
                continue;
            }
            if c.is_alphanumeric() || c == '_' {
                word.push(c);
                i += 1;
                continue;
            }
            end_word(&mut word, &mut prev, &mut pending);
            if c.is_whitespace() {
                i += 1;
                continue;
            }
            if c != '{' && prev == "mod" {
                prev.clear();
            }
            match c {
                '/' if cs.get(i + 1) == Some(&'/') => break,
                '/' if cs.get(i + 1) == Some(&'*') => {
                    block += 1;
                    i += 1;
                }
                '"' => in_str = true,
                '\'' => {
                    if cs.get(i + 1) == Some(&'\\') {
                        i += 2;
                        while i < cs.len() && cs[i] != '\'' {
                            i += 1;
                        }
                    } else if cs.get(i + 2) == Some(&'\'') {
                        i += 2;
                    }
                }
                '{' => {
                    if let Some(n) = pending.take() {
                        open.push((n, depth, ln));
                    }
                    depth += 1;
                    prev.clear();
                }
                '}' => {
                    depth -= 1;
                    if open.last().is_some_and(|o| o.1 == depth) {
                        let (name, _, start) = open.pop().unwrap();
                        let mut path: Vec<String> = open.iter().map(|o| o.0.clone()).collect();
                        path.push(name);
                        mods.push((start, ln, path));
                    }
                    prev.clear();
                }
                ';' => {
                    pending = None;
                    prev.clear();
                }
                _ => {}
            }
            i += 1;
        }
        end_word(&mut word, &mut prev, &mut pending);
    }
    RsText { lines, mods }
}

/// Does this Rust source declare an inline module (`mod x { ... }`)?
fn rs_has_inline_mods(repo: &std::path::Path, file: &str) -> bool {
    std::fs::read_to_string(repo.join(file)).is_ok_and(|t| t.contains("mod ") && !scan_rs(&t).mods.is_empty())
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The path qualifiers of each call to free function `callee` on one source line (`a::b::run(` -> ["a", "b"]).
fn rs_quals(line: &str, callee: &str) -> Vec<Vec<String>> {
    let b = line.as_bytes();
    let (mut out, mut from) = (vec![], 0usize);
    while let Some(p) = line[from..].find(callee) {
        let s = from + p;
        let e = s + callee.len();
        from = e;
        if (s > 0 && is_ident_byte(b[s - 1])) || b.get(e).is_some_and(|&x| is_ident_byte(x)) {
            continue;
        }
        let after = line[e..].trim_start();
        if !(after.starts_with('(') || after.starts_with("::<")) {
            continue;
        }
        let pre = line[..s].trim_end();
        if pre.ends_with('.') || pre.ends_with("fn") && !pre[..pre.len() - 2].ends_with(|c: char| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let mut segs: Vec<String> = vec![];
        let mut cur = &line[..s];
        while let Some(r) = cur.strip_suffix("::") {
            let st = r.rfind(|c: char| !(c.is_alphanumeric() || c == '_')).map(|x| x + 1).unwrap_or(0);
            if st == r.len() {
                break;
            }
            segs.insert(0, r[st..].to_string());
            cur = &r[..st];
        }
        out.push(segs);
    }
    out
}

/// One ref's position, for the resolvers that read the source (Rust path qualifiers, inline modules, generic bounds).
struct Rc {
    line: i64,
    caller_line: i64,
    qual: Vec<String>,
}

struct Imp {
    callee: String,
    source: String,
    local: String,
    reexport: bool,
}

/// One tsconfig.json / jsconfig.json: the directory it lives in, the base for `paths` and the path patterns.
pub struct TsCfg {
    dir: String,
    base: String,
    paths: Vec<(String, Vec<String>)>,
}

/// JSON with comments and trailing commas (tsconfig) -> parsed value.
fn parse_jsonc(t: &str) -> Option<serde_json::Value> {
    let cs: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(t.len());
    let (mut i, mut instr) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if instr {
            out.push(c);
            if c == '\\' && i + 1 < cs.len() {
                out.push(cs[i + 1]);
                i += 1;
            } else if c == '"' {
                instr = false;
            }
        } else if c == '"' {
            instr = true;
            out.push(c);
        } else if c == '/' && cs.get(i + 1) == Some(&'/') {
            while i < cs.len() && cs[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '/' && cs.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < cs.len() && !(cs[i] == '*' && cs[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else {
            out.push(c);
        }
        i += 1;
    }
    // trailing commas
    let b: Vec<char> = out.chars().collect();
    let mut clean = String::with_capacity(b.len());
    let mut instr = false;
    for (i, &c) in b.iter().enumerate() {
        if instr {
            clean.push(c);
            if c == '"' && b.get(i.wrapping_sub(1)) != Some(&'\\') {
                instr = false;
            }
            continue;
        }
        if c == '"' {
            instr = true;
        }
        if c == ',' {
            let nx = b[i + 1..].iter().find(|x| !x.is_whitespace());
            if matches!(nx, Some('}') | Some(']')) {
                continue;
            }
        }
        clean.push(c);
    }
    serde_json::from_str(&clean).ok()
}

fn norm_path(p: &str) -> String {
    let mut out: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// Read every tsconfig.json / jsconfig.json in the index (following one `extends` chain) and return the parsed
/// path mappings plus a signature of their content (a change forces a full re-resolve).
fn load_ts_configs(repo: &std::path::Path, files: &HashSet<String>) -> (Vec<TsCfg>, String) {
    let mut names: Vec<&String> =
        files.iter().filter(|p| matches!(p.rsplit('/').next(), Some("tsconfig.json") | Some("jsconfig.json"))).collect();
    names.sort();
    let mut sig = String::new();
    let mut cfgs = vec![];
    let read = |p: &str| -> Option<serde_json::Value> {
        let t = std::fs::read_to_string(repo.join(p)).ok()?;
        parse_jsonc(&t)
    };
    for p in names {
        let Some(mut v) = read(p) else { continue };
        let dir = p.rsplit_once('/').map(|x| x.0).unwrap_or("").to_string();
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        v.to_string().hash(&mut h);
        sig.push_str(&format!("{p}:{:x};", h.finish()));
        // compilerOptions of this file, falling back to what an `extends` chain provides
        let mut opts = v.get("compilerOptions").cloned().unwrap_or(serde_json::Value::Null);
        let mut cur_dir = dir.clone();
        for _ in 0..3 {
            if opts.get("paths").is_some() && opts.get("baseUrl").is_some() {
                break;
            }
            let Some(ext) = v.get("extends").and_then(|e| e.as_str()).map(str::to_string) else { break };
            if !ext.starts_with('.') {
                break;
            }
            let mut tp = norm_path(&format!("{cur_dir}/{ext}"));
            if !tp.ends_with(".json") {
                tp.push_str(".json");
            }
            let Some(pv) = read(&tp) else { break };
            if let Some(po) = pv.get("compilerOptions") {
                if !opts.is_object() {
                    opts = serde_json::json!({});
                }
                for k in ["paths", "baseUrl"] {
                    if opts.get(k).is_none() {
                        if let (Some(x), Some(o)) = (po.get(k), opts.as_object_mut()) {
                            // baseUrl inherited from a parent is relative to the parent's directory: store it repo-relative
                            let x = if k == "baseUrl" {
                                let pd = tp.rsplit_once('/').map(|y| y.0).unwrap_or("");
                                serde_json::Value::String(format!("/{}", norm_path(&format!("{pd}/{}", x.as_str().unwrap_or(".")))))
                            } else {
                                x.clone()
                            };
                            o.insert(k.to_string(), x);
                        }
                    }
                }
            }
            cur_dir = tp.rsplit_once('/').map(|y| y.0).unwrap_or("").to_string();
            v = pv;
        }
        let base = match opts.get("baseUrl").and_then(|b| b.as_str()) {
            Some(b) if b.starts_with('/') => b[1..].to_string(), // already repo-relative (inherited)
            Some(b) => norm_path(&format!("{dir}/{b}")),
            None => dir.clone(),
        };
        let mut paths = vec![];
        if let Some(m) = opts.get("paths").and_then(|x| x.as_object()) {
            for (k, v) in m {
                let t: Vec<String> = v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                paths.push((k.clone(), t));
            }
        }
        let has_base = opts.get("baseUrl").is_some();
        if paths.is_empty() && !has_base {
            continue;
        }
        cfgs.push(TsCfg { dir, base, paths });
    }
    (cfgs, sig)
}

impl Graph {
    /// Everything read from the file list and the config files (always complete); no members yet.
    fn base(conn: &rusqlite::Connection, repo: &std::path::Path) -> Result<Graph> {
        let mut g = Graph {
            ms: vec![],
            by_name_: HashMap::new(),
            by_cn_: HashMap::new(),
            by_cn_x: HashMap::new(),
            cn_hash: Default::default(),
            types_: HashMap::new(),
            subs: HashMap::new(),
            files: HashSet::new(),
            fids: HashMap::new(),
            py_mods: HashMap::new(),
            imps_: HashMap::new(),
            ts: vec![],
            ts_sig: String::new(),
            go_mods: vec![],
            repo: repo.to_path_buf(),
            rs_stems: HashMap::new(),
            rs_roots: vec![],
            rs_at_: HashMap::new(),
            rs_src: Mutex::new(HashMap::new()),
            src_: Mutex::new(HashMap::new()),
            mod_root_: Mutex::new(HashMap::new()),
            part: None,
            c_names: HashMap::new(),
            c_inc: Mutex::new(HashMap::new()),
        };
        let mut st = conn.prepare("SELECT path, rowid FROM files")?;
        for p in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (p, rid) = p?;
            g.fids.insert(p.clone(), rid);
            if p.ends_with(".rs") {
                let (dirs, f) = p.rsplit_once('/').unwrap_or(("", &p));
                if f == "lib.rs" || f == "main.rs" {
                    g.rs_roots.push(p.clone());
                }
                let stem = if f == "mod.rs" { dirs.rsplit('/').next().unwrap_or("").to_string() } else { f.trim_end_matches(".rs").to_string() };
                if !stem.is_empty() {
                    g.rs_stems.entry(stem).or_default().push(p.clone());
                }
            }
            if let Some(stem) = p.strip_suffix(".py") {
                let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
                let parts: Vec<&str> = stem.split('/').collect();
                for i in 0..parts.len() {
                    g.py_mods.entry(parts[i..].join(".")).or_default().push(p.clone());
                }
            }
            if lang_family(&p) == Some("c") {
                let base = p.rsplit('/').next().unwrap_or(&p).to_string();
                g.c_names.entry(base).or_default().push(p.clone());
            }
            g.files.insert(p);
        }
        (g.ts, g.ts_sig) = load_ts_configs(repo, &g.files);
        // go.mod is not an indexed file: look for one in every directory that holds Go source (and its parents)
        let mut dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for p in g.files.iter().filter(|p| p.ends_with(".go")) {
            let mut d = p.rsplit_once('/').map(|x| x.0).unwrap_or("");
            loop {
                if !dirs.insert(d.to_string()) {
                    break;
                }
                match d.rsplit_once('/') {
                    Some((up, _)) => d = up,
                    None if !d.is_empty() => d = "",
                    None => break,
                }
            }
        }
        for dir in dirs {
            let gm = if dir.is_empty() { "go.mod".to_string() } else { format!("{dir}/go.mod") };
            if let Some(m) = std::fs::read_to_string(repo.join(&gm))
                .ok()
                .and_then(|t| t.lines().find_map(|l| l.trim().strip_prefix("module ").map(|x| x.trim().trim_matches('"').to_string())))
            {
                g.ts_sig.push_str(&format!("{gm}:{m};"));
                g.go_mods.push((dir, m));
            }
        }
        Ok(g)
    }

    /// Load the members and import bindings: all of them (`keys` None), or only those `keys` names (replacing what a
    /// previous fill loaded). Members keep the full graph's order (file, line, rowid), so every lookup a partial graph
    /// answers lists the same members in the same relative order as the full graph.
    fn fill(&mut self, conn: &rusqlite::Connection, keys: Option<&Keys>) -> Result<()> {
        self.ms.clear();
        self.by_name_.clear();
        self.by_cn_.clear();
        self.by_cn_x.clear();
        // resolved #includes are read through `imps` (partial in a partial graph): never kept across fills
        if let Ok(mut m) = self.c_inc.lock() {
            m.clear();
        }
        self.types_.clear();
        self.subs.clear();
        self.imps_.clear();
        self.rs_at_.clear();
        self.part = keys.map(|k| Part { keys: k.clone(), miss: Mutex::new(Keys::default()) });
        const COLS: &str = "m.file, m.line, m.name, COALESCE(m.container,''), m.qname, m.kind, m.supers, m.annos, m.ret, m.sig, m.rowid";
        // one shared copy of each repeated string (file, kind, container, return type, annotations)
        let pool: std::cell::RefCell<HashSet<Str>> = Default::default();
        let intern = |v: String| -> Str {
            let mut p = pool.borrow_mut();
            if let Some(x) = p.get(v.as_str()) {
                return x.clone();
            }
            let x = Str::from(v);
            p.insert(x.clone());
            x
        };
        let row = |r: &rusqlite::Row| -> rusqlite::Result<(M, i64)> {
            let file: String = r.get(0)?;
            let sig: String = r.get(9)?;
            let py = file.ends_with(".py");
            let kind: String = r.get(5)?;
            Ok((
                M {
                    arity: sig_arity(&sig, py),
                    params: if matches!(lang_family(&file), Some("jvm" | "cs")) { overload::param_types(&sig) } else { vec![] },
                    iface: if kind == "interface" && file.ends_with(".go") {
                        sig.split_once(" interface {").and_then(|x| x.1.rsplit_once('}')).map(|x| x.0.trim().to_string()).unwrap_or_default().into()
                    } else {
                        intern(String::new())
                    },
                    ret: intern(r.get::<_, Option<String>>(8)?.unwrap_or_default()),
                    elem: if matches!(lang_family(&file), Some("jvm")) && kind == "method" { sig_elem(&sig, &r.get::<_, String>(2)?) } else { String::new() },
                    file: intern(file),
                    line: r.get(1)?,
                    name: r.get::<_, String>(2)?.into(),
                    container: intern(r.get(3)?),
                    qname: r.get::<_, String>(4)?.into(),
                    kind: intern(kind),
                    supers: r.get::<_, String>(6)?.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
                    annos: intern(r.get(7)?),
                },
                r.get(10)?,
            ))
        };
        let add = |g: &mut Graph, m: M| {
            let i = g.ms.len();
            let named = keys.is_none_or(|k| k.names.contains(&*m.name));
            if named {
                g.by_name_.entry(m.name.clone()).or_default().push(i);
                let h = g.cn_hash.hash_one((&*m.container, &*m.name));
                match g.by_cn_.get_mut(&h) {
                    None => {
                        g.by_cn_.insert(h, vec![i]);
                    }
                    Some(v) if g.ms[v[0]].container == m.container && g.ms[v[0]].name == m.name => v.push(i),
                    Some(_) => g.by_cn_x.entry((m.container.to_string(), m.name.to_string())).or_default().push(i),
                }
            }
            if m.file.ends_with(".rs") && callable(&m.kind) && keys.is_none_or(|k| k.rs_at.contains(&*m.file)) {
                g.rs_at_.entry((m.file.to_string(), m.line)).or_insert(i);
            }
            if is_type(&m.kind) {
                if named {
                    g.types_.entry(m.name.clone()).or_default().push(i);
                }
                if keys.is_none() {
                    for s in &m.supers {
                        g.subs.entry(s.clone()).or_default().push(m.name.to_string());
                    }
                }
            }
            g.ms.push(m);
        };
        match keys {
            None => {
                // the whole graph: streamed straight into `ms` (no second copy of every member while it is built)
                let n: i64 = conn.query_row("SELECT count(*) FROM members", [], |r| r.get(0)).unwrap_or(0);
                self.ms.reserve_exact(n.max(0) as usize);
                let mut st = conn.prepare(&format!("SELECT {COLS} FROM members m ORDER BY m.file, m.line, m.rowid"))?;
                for m in st.query_map([], row)? {
                    add(self, m?.0);
                }
            }
            Some(k) => {
                let mut ms: Vec<(M, i64)> = vec![];
                let mut seen: HashSet<i64> = HashSet::new();
                let mut by_name = conn.prepare_cached(&format!("SELECT {COLS} FROM members m WHERE m.name=?"))?;
                for n in &k.names {
                    for m in by_name.query_map([n], row)? {
                        let m = m?;
                        if seen.insert(m.1) {
                            ms.push(m);
                        }
                    }
                }
                let mut by_file = conn.prepare_cached(&format!("SELECT {COLS} FROM members m WHERE m.file=?"))?;
                for f in &k.rs_at {
                    for m in by_file.query_map([f], row)? {
                        let m = m?;
                        if seen.insert(m.1) {
                            ms.push(m);
                        }
                    }
                }
                // the same order as the full load (SQLite's BINARY collation compares bytes, as `str` does)
                ms.sort_by(|a, b| (&*a.0.file, a.0.line, a.1).cmp(&(&*b.0.file, b.0.line, b.1)));
                for (m, _) in ms {
                    add(self, m);
                }
            }
        }
        if keys.is_some() {
            // subclasses are read by the super's name: load the whole (small) hierarchy, in member order
            let mut st = conn.prepare_cached(&format!("SELECT m.name, m.kind, m.supers FROM members m WHERE m.supers<>'' ORDER BY m.file, m.line, m.rowid"))?;
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                let (name, kind, supers): (String, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?);
                if is_type(&kind) {
                    for s in supers.split(',').filter(|s| !s.is_empty()) {
                        self.subs.entry(s.to_string()).or_default().push(name.clone());
                    }
                }
            }
        }
        let imp = |r: &rusqlite::Row| -> rusqlite::Result<(String, Imp)> {
            Ok((r.get::<_, String>(0)?, Imp { callee: r.get(1)?, source: r.get(2)?, local: r.get(3)?, reexport: matches!(r.get::<_, String>(4)?.as_str(), "reexport" | "defaultexport") }))
        };
        match keys {
            None => {
                let mut st = conn.prepare(
                    "SELECT f.path, r.callee, r.recv, r.recv_type, r.kind FROM refs r JOIN files f ON f.rowid=r.fid WHERE r.kind IN ('import','reexport','defaultexport') ORDER BY r.rowid",
                )?;
                for r in st.query_map([], imp)? {
                    let (f, i) = r?;
                    self.imps_.entry(f).or_default().push(i);
                }
            }
            Some(k) => {
                let mut st = conn.prepare_cached(
                    "SELECT f.path, r.callee, r.recv, r.recv_type, r.kind FROM files f JOIN refs r ON r.fid=f.rowid WHERE f.path=? AND r.kind IN ('import','reexport','defaultexport') ORDER BY r.rowid",
                )?;
                for f in &k.imps {
                    for r in st.query_map([f], imp)? {
                        let (f, i) = r?;
                        self.imps_.entry(f).or_default().push(i);
                    }
                }
            }
        }
        Ok(())
    }

    /// Is `key` loaded? (always, for a full graph); a partial graph records the miss.
    fn has(&self, key: &str, set: fn(&Keys) -> &HashSet<String>, add: fn(&mut Keys, String)) -> bool {
        let Some(p) = &self.part else { return true };
        if set(&p.keys).contains(key) {
            return true;
        }
        if let Ok(mut m) = p.miss.lock() {
            add(&mut m, key.to_string());
        }
        false
    }
    fn has_name(&self, n: &str) -> bool {
        self.has(n, |k| &k.names, |k, s| { k.names.insert(s); })
    }
    fn by_name(&self, n: &str) -> Option<&Vec<usize>> {
        if self.has_name(n) { self.by_name_.get(n) } else { None }
    }
    fn by_cn(&self, k: &(String, String)) -> Option<&Vec<usize>> {
        if !self.has_name(&k.1) {
            return None;
        }
        match self.by_cn_.get(&self.cn_hash.hash_one((k.0.as_str(), k.1.as_str()))) {
            Some(v) if *self.ms[v[0]].container == *k.0 && *self.ms[v[0]].name == *k.1 => Some(v),
            _ => self.by_cn_x.get(k),
        }
    }
    fn types(&self, n: &str) -> Option<&Vec<usize>> {
        if self.has_name(n) { self.types_.get(n) } else { None }
    }
    fn has_type(&self, n: &str) -> bool {
        self.types(n).is_some()
    }
    fn imps(&self, f: &str) -> Option<&Vec<Imp>> {
        if self.has(f, |k| &k.imps, |k, s| { k.imps.insert(s); }) { self.imps_.get(f) } else { None }
    }
    fn rs_at(&self, k: &(String, i64)) -> Option<&usize> {
        if self.has(&k.0, |k| &k.rs_at, |k, s| { k.rs_at.insert(s); }) { self.rs_at_.get(k) } else { None }
    }
    /// C family: the files `file` #includes, resolved to indexed paths (relative to its directory first, else every
    /// indexed file whose path ends with the include spec, as an include path would find it).
    fn c_includes(&self, file: &str) -> Arc<Vec<String>> {
        if let Some(v) = self.c_inc.lock().ok().and_then(|m| m.get(file).cloned()) {
            return v;
        }
        let mut out: Vec<String> = vec![];
        for imp in self.imps(file).into_iter().flatten() {
            let spec = imp.source.as_str();
            let base = spec.rsplit('/').next().unwrap_or(spec);
            if base.is_empty() || imp.callee != "*" {
                continue;
            }
            let dir = file.rsplit_once('/').map(|x| x.0).unwrap_or("");
            let rel = norm_path(&if dir.is_empty() { spec.to_string() } else { format!("{dir}/{spec}") });
            if self.files.contains(&rel) {
                out.push(rel);
                continue;
            }
            let tail = format!("/{spec}");
            for p in self.c_names.get(base).into_iter().flatten() {
                if p == spec || p.ends_with(&tail) {
                    out.push(p.clone());
                }
            }
        }
        let v = Arc::new(out);
        if let Ok(mut m) = self.c_inc.lock() {
            m.insert(file.to_string(), v.clone());
        }
        v
    }

    /// C family: of the definitions `cands`, the ones `file` can see: in a header it includes, or one those include.
    fn c_visible(&self, file: &str, cands: &[usize]) -> Vec<usize> {
        let want: HashSet<&str> = cands.iter().map(|&i| &*self.ms[i].file).collect();
        let mut seen: HashSet<String> = HashSet::new();
        let direct = self.c_includes(file);
        for h in direct.iter() {
            if want.contains(h.as_str()) {
                seen.insert(h.clone());
            }
        }
        if seen.is_empty() {
            for h in direct.iter() {
                for h2 in self.c_includes(h).iter() {
                    if want.contains(h2.as_str()) {
                        seen.insert(h2.clone());
                    }
                }
            }
        }
        cands.iter().copied().filter(|&i| seen.contains(&*self.ms[i].file)).collect()
    }

    /// The lookups a partial graph could not answer since it was filled (empty for a full graph).
    fn misses(&self) -> Keys {
        self.part.as_ref().and_then(|p| p.miss.lock().ok().map(|m| m.clone())).unwrap_or_default()
    }

    /// `@/client` / `~/x` / a baseUrl-relative specifier through the nearest tsconfig `paths`.
    fn ts_alias(&self, from: &str, source: &str) -> Option<String> {
        if source.starts_with('.') {
            return None;
        }
        let mut cfgs: Vec<&TsCfg> = self.ts.iter().filter(|c| c.dir.is_empty() || from.starts_with(&format!("{}/", c.dir))).collect();
        cfgs.sort_by_key(|c| std::cmp::Reverse(c.dir.len()));
        for c in cfgs {
            for (pat, targets) in &c.paths {
                let rest = match pat.split_once('*') {
                    Some((pre, post)) => match source.strip_prefix(pre).and_then(|x| x.strip_suffix(post)) {
                        Some(r) => r.to_string(),
                        None => continue,
                    },
                    None if pat == source => String::new(),
                    None => continue,
                };
                for t in targets {
                    let p = norm_path(&format!("{}/{}", c.base, t.replace('*', &rest)));
                    let r = resolve_import("x", &format!("./{p}"), &self.files);
                    if !r.is_empty() {
                        return Some(r);
                    }
                }
            }
            // baseUrl-relative bare specifier (`import x from 'app/foo'` with baseUrl `src`)
            let p = norm_path(&format!("{}/{}", c.base, source));
            let r = resolve_import("x", &format!("./{p}"), &self.files);
            if !r.is_empty() {
                return Some(r);
            }
        }
        None
    }

    fn module_file(&self, from: &str, source: &str) -> Option<String> {
        // MarkLogic: `require("/lib/x.sjs")` / an XQuery location is absolute against a modules root
        if (from.ends_with(".sjs") || xq::is_xq(from)) && source.starts_with('/') {
            return xq::abs_file(&self.files, from, source);
        }
        if from.ends_with(".py") {
            if let Some(rest) = source.strip_prefix('.') {
                let dots = 1 + rest.chars().take_while(|c| *c == '.').count();
                let rest = rest.trim_start_matches('.');
                let mut dir: Vec<&str> = from.split('/').collect();
                dir.pop();
                for _ in 1..dots {
                    dir.pop();
                }
                let base = if rest.is_empty() {
                    dir.join("/")
                } else {
                    format!(
                        "{}{}",
                        if dir.is_empty() { String::new() } else { format!("{}/", dir.join("/")) },
                        rest.replace('.', "/")
                    )
                };
                for c in [format!("{base}.py"), format!("{base}/__init__.py")] {
                    if self.files.contains(&c) {
                        return Some(c);
                    }
                }
                return None;
            }
            let c = self.py_mods.get(source)?;
            // prefer the candidate sharing the longest directory prefix with the importer
            return c
                .iter()
                .max_by_key(|p| p.split('/').zip(from.split('/')).take_while(|(a, b)| a == b).count())
                .cloned();
        }
        if from.ends_with(".go") {
            // an import path inside this module -> its package directory (a trailing `/` marks a directory)
            for (dir, m) in &self.go_mods {
                if let Some(rest) = source.strip_prefix(m.as_str()).filter(|r| r.is_empty() || r.starts_with('/')) {
                    let d = norm_path(&format!("{dir}/{rest}"));
                    let d = if d.is_empty() { "/".to_string() } else { format!("{d}/") };
                    if self.files.iter().any(|f| f.ends_with(".go") && Self::in_file(f, &d)) {
                        return Some(d);
                    }
                }
            }
            return None;
        }
        if let Some(r) = self.ts_alias(from, source) {
            return Some(r);
        }
        let r = resolve_import(from, source, &self.files);
        if r.is_empty() {
            None
        } else {
            Some(r)
        }
    }

    /// Is member file `mfile` the module `f` (a file, or for Go a package directory ending in `/`)?
    fn in_file(mfile: &str, f: &str) -> bool {
        if f.ends_with('/') {
            let pre = if f == "/" { "" } else { f };
            mfile.strip_prefix(pre).is_some_and(|r| !r.contains('/'))
        } else {
            mfile == f
        }
    }

    /// The file that really defines top-level `name` of module file `t`, following re-exports (`export * from`,
    /// `export { x } from`, `index.ts` barrels, Python `from .mod import x` in `__init__.py`): (file, name there).
    fn defining(&self, t: &str, name: &str, depth: u32) -> Option<(String, String)> {
        if depth > 5 {
            return None;
        }
        let top = |f: &str, n: &str| -> bool {
            self.by_name(n).is_some_and(|v| v.iter().any(|&i| Self::in_file(&self.ms[i].file, f) && self.ms[i].container.is_empty()))
        };
        if top(t, name) {
            return Some((t.to_string(), name.to_string()));
        }
        let py = t.ends_with(".py");
        for im in self.imps(t).into_iter().flatten() {
            if im.reexport || py {
                let (hit, orig) = if im.callee == "*" && im.local == "*" {
                    (true, name.to_string()) // export * / from x import *
                } else if im.local == name {
                    (true, if im.callee == "*" { name.to_string() } else { im.callee.clone() })
                } else {
                    (false, String::new())
                };
                if !hit {
                    continue;
                }
                // `export default mul` in `t` itself
                if im.source.is_empty() {
                    if top(t, &orig) {
                        return Some((t.to_string(), orig));
                    }
                    continue;
                }
                let Some(sf) = self.module_file(t, &im.source) else { continue };
                if sf == t {
                    continue;
                }
                if let Some(r) = self.defining(&sf, &orig, depth + 1) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Members named `name` reachable from class `cls`: (idx, via_super).
    fn in_class(&self, cls: &str, name: &str, depth: u32, seen: &mut HashSet<String>) -> Vec<(usize, bool)> {
        if depth > 5 || !seen.insert(cls.to_string()) {
            return vec![];
        }
        if let Some(v) = self.by_cn(&(cls.to_string(), name.to_string())) {
            if !v.is_empty() {
                return v.iter().map(|i| (*i, depth > 0)).collect();
            }
        }
        let mut out = vec![];
        if let Some(defs) = self.types(cls) {
            for &d in defs {
                for s in &self.ms[d].supers {
                    out.extend(self.in_class(s, name, depth + 1, seen).into_iter().map(|(i, _)| (i, true)));
                }
                if out.is_empty() && !self.ms[d].container.is_empty() {
                    // inner class: the enclosing class's members are in scope
                    out.extend(
                        self.in_class(&self.ms[d].container, name, depth + 1, seen).into_iter().map(|(i, _)| (i, true)),
                    );
                }
            }
        }
        out
    }

    fn subs_with(&self, cls: &str, name: &str, depth: u32, out: &mut Vec<usize>, cap: usize) {
        if depth > 3 || out.len() > cap {
            return;
        }
        for s in self.subs.get(cls).into_iter().flatten() {
            if let Some(v) = self.by_cn(&(s.clone(), name.to_string())) {
                out.extend(v.iter().copied().filter(|i| callable(&self.ms[*i].kind)));
            }
            self.subs_with(s, name, depth + 1, out, cap);
        }
    }

    fn panache(&self, cls: &str) -> Option<usize> {
        self.types(cls)?.iter().copied().find(|&d| {
            let m = &self.ms[d];
            m.annos.contains("Entity")
                || m.supers
                    .iter()
                    .any(|s| s.starts_with("Panache") || s.ends_with("Repository") || s.ends_with("Entity"))
        })
    }


    // ---- Rust: module paths, `use` imports, inline modules, generic bounds ----

    fn rs_text(&self, file: &str) -> Option<Arc<RsText>> {
        if let Some(t) = self.rs_src.lock().ok()?.get(file) {
            return t.clone();
        }
        let t = std::fs::read_to_string(self.repo.join(file)).ok().map(|s| Arc::new(scan_rs(&s)));
        self.rs_src.lock().ok()?.insert(file.to_string(), t.clone());
        t
    }

    fn rs_stack(&self, file: &str, line: i64) -> Vec<String> {
        self.rs_text(file).map(|t| t.stack_at(line)).unwrap_or_default()
    }

    fn rs_has_mod(&self, file: &str, path: &[String]) -> bool {
        self.rs_text(file).is_some_and(|t| t.mods.iter().any(|m| m.2 == path))
    }

    /// Among `files`, the ones sharing the longest directory prefix with `from`.
    fn rs_nearest(from: &str, files: &[String]) -> Vec<String> {
        let score = |p: &String| p.split('/').zip(from.split('/')).take_while(|(a, b)| a == b).count();
        let best = files.iter().map(score).max().unwrap_or(0);
        files.iter().filter(|p| score(p) == best).cloned().collect()
    }

    fn rs_parent_files(&self, f: &str) -> Vec<String> {
        let dir = f.rsplit_once('/').map(|x| x.0).unwrap_or("");
        let base = f.rsplit('/').next().unwrap_or("");
        // dir/x.rs -> dir/mod.rs | dir.rs | dir/lib.rs | dir/main.rs; dir/mod.rs -> the same one level up
        let d = if base == "mod.rs" { dir.rsplit_once('/').map(|x| x.0).unwrap_or("") } else { dir };
        let join = |a: &str, b: &str| if a.is_empty() { b.to_string() } else { format!("{a}/{b}") };
        let mut c = vec![join(d, "mod.rs"), join(d, "lib.rs"), join(d, "main.rs")];
        if !d.is_empty() {
            c.push(format!("{d}.rs"));
        }
        c.into_iter().filter(|x| x != f && self.files.contains(x)).collect()
    }

    /// Callable top-level (no container) members named `name` in module `file` / inline module path `stack`.
    fn rs_top_in(&self, file: &str, stack: &[String], name: &str) -> Vec<usize> {
        self.by_name(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|&i| {
                let m = &self.ms[i];
                m.file == file && m.container.is_empty() && callable(&m.kind) && self.rs_stack(file, m.line) == stack
            })
            .collect()
    }

    /// `name` in the module reached by the path `segs` from `from` (inline module stack `cstack`). None: the path
    /// leaves the project (std, another crate); Some(empty): a project module without it (a re-export, maybe).
    fn rs_lookup(&self, from: &str, cstack: &[String], segs: &[String], name: &str) -> Option<Vec<usize>> {
        let mut locs: Vec<(String, Vec<String>)> = vec![];
        let mut i = 0;
        match segs.first().map(String::as_str) {
            None => locs.push((from.to_string(), cstack.to_vec())),
            Some("crate") => {
                locs.extend(Self::rs_nearest(from, &self.rs_roots).into_iter().map(|r| (r, vec![])));
                i = 1;
            }
            Some("self") => {
                locs.push((from.to_string(), cstack.to_vec()));
                i = 1;
            }
            Some("super") => {
                let mut stack = cstack.to_vec();
                let mut files = vec![from.to_string()];
                while segs.get(i).is_some_and(|x| x == "super") {
                    if stack.pop().is_none() {
                        files = files.iter().flat_map(|f| self.rs_parent_files(f)).collect();
                    }
                    i += 1;
                }
                locs.extend(files.into_iter().map(|f| (f, stack.clone())));
            }
            Some(first) => {
                let mut child = cstack.to_vec();
                child.push(first.to_string());
                if self.rs_has_mod(from, &child) {
                    locs.push((from.to_string(), child));
                } else if self.rs_has_mod(from, &[first.to_string()]) {
                    locs.push((from.to_string(), vec![first.to_string()]));
                } else if let Some(fs) = self.rs_stems.get(first) {
                    locs.extend(Self::rs_nearest(from, fs).into_iter().map(|f| (f, vec![])));
                } else {
                    // a workspace crate named by its root directory (`aix_extract` -> aix-extract/src/lib.rs)
                    let dashed = first.replace('_', "-");
                    let roots: Vec<String> =
                        self.rs_roots.iter().filter(|r| r.split('/').any(|c| c == first || c == dashed)).cloned().collect();
                    if roots.is_empty() {
                        return None;
                    }
                    locs.extend(roots.into_iter().map(|r| (r, vec![])));
                }
                i = 1;
            }
        }
        while i < segs.len() {
            let y = &segs[i];
            let mut next: Vec<(String, Vec<String>)> = vec![];
            for (f, st) in &locs {
                let mut p = st.clone();
                p.push(y.clone());
                if self.rs_has_mod(f, &p) {
                    next.push((f.clone(), p));
                } else if st.is_empty() {
                    if let Some(fs) = self.rs_stems.get(y) {
                        next.extend(Self::rs_nearest(f, fs).into_iter().map(|c| (c, vec![])));
                    }
                }
            }
            if next.is_empty() {
                return Some(vec![]);
            }
            locs = next;
            i += 1;
        }
        let mut out: Vec<usize> = vec![];
        for (f, st) in &locs {
            out.extend(self.rs_top_in(f, st, name));
        }
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    /// Resolution of a Rust free-function call from its path qualifier, `use` imports and inline modules.
    fn rs_call(&self, file: &str, callee: &str, rc: &Rc) -> Option<Vec<(usize, &'static str)>> {
        let cstack = self.rs_stack(file, rc.line);
        let imps = self.imps(file);
        let conf = |v: &[usize]| if v.len() == 1 { "exact" } else { "resolved" };
        let pack = |v: Vec<usize>| -> Vec<(usize, &'static str)> {
            let c = conf(&v);
            v.into_iter().take(4).map(|i| (i, c)).collect()
        };
        if let Some(first) = rc.qual.first() {
            let mut q: Vec<String> = rc.qual.clone();
            // the first segment may be an imported module (`use crate::a;` / `use x::y as z;`)
            if let Some(im) = imps.into_iter().flatten().find(|im| im.local == *first && im.callee != "*") {
                let mut p: Vec<String> = im.source.split("::").map(str::to_string).collect();
                p.push(im.callee.clone());
                q.splice(0..1, p);
            }
            let last = q.last().cloned().unwrap_or_default();
            if last == "Self" || last.chars().next().is_some_and(|c| c.is_uppercase()) {
                let cont = if last == "Self" {
                    self.rs_at(&(file.to_string(), rc.caller_line)).map(|&i| self.ms[i].container.to_string()).unwrap_or_default()
                } else {
                    last
                };
                let v: Vec<usize> = self
                    .by_cn(&(cont, callee.to_string()))
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|&i| callable(&self.ms[i].kind))
                    .collect();
                return if v.is_empty() { None } else { Some(pack(v)) };
            }
            return match self.rs_lookup(file, &cstack, &q, callee) {
                Some(v) if !v.is_empty() => Some(pack(v)),
                Some(_) => None,
                None => Some(vec![]),
            };
        }
        // `use path::name;` / `use path::name as local;`
        for im in imps.into_iter().flatten() {
            if im.local == callee && im.callee != "*" {
                let segs: Vec<String> = im.source.split("::").map(str::to_string).collect();
                return match self.rs_lookup(file, &cstack, &segs, &im.callee) {
                    Some(v) if !v.is_empty() => Some(pack(v)),
                    Some(_) => None,
                    None => Some(vec![]),
                };
            }
        }
        // this module
        let same = self.rs_top_in(file, &cstack, callee);
        if !same.is_empty() {
            return Some(pack(same));
        }
        // `use path::*;`
        let mut out: Vec<usize> = vec![];
        for im in imps.into_iter().flatten() {
            if im.callee == "*" && im.local == "*" {
                let segs: Vec<String> = im.source.split("::").map(str::to_string).collect();
                out.extend(self.rs_lookup(file, &cstack, &segs, callee).unwrap_or_default());
            }
        }
        out.sort_unstable();
        out.dedup();
        if out.is_empty() {
            None
        } else {
            Some(out.into_iter().take(4).map(|i| (i, "resolved")).collect())
        }
    }

    /// The trait a generic receiver type `T` is bounded by in the caller's signature (`fn f<T: Extractor + Send>(e: T)`).
    fn rs_bound(&self, file: &str, caller_line: i64, t: &str) -> Option<String> {
        // the extracted signature drops the generics: read the header from the source
        let text = self.rs_text(file)?;
        let mut sig = String::new();
        for l in text.lines.iter().skip((caller_line - 1).max(0) as usize).take(8) {
            sig.push_str(l);
            sig.push(' ');
            if l.contains('{') {
                break;
            }
        }
        let sig = sig.as_str();
        let b = sig.as_bytes();
        let mut from = 0;
        while let Some(p) = sig[from..].find(t) {
            let s = from + p;
            let e = s + t.len();
            from = e;
            if (s > 0 && is_ident_byte(b[s - 1])) || b.get(e).is_some_and(|&x| is_ident_byte(x)) {
                continue;
            }
            let rest = sig[e..].trim_start();
            let Some(rest) = rest.strip_prefix(':').filter(|r| !r.starts_with(':')) else { continue };
            let (mut depth, mut cur, mut bounds) = (0i32, String::new(), vec![]);
            for c in rest.chars() {
                match c {
                    '<' => depth += 1,
                    '>' if depth == 0 => break,
                    '>' => depth -= 1,
                    ',' | '{' | '(' | '=' if depth == 0 => break,
                    '+' if depth == 0 => {
                        bounds.push(std::mem::take(&mut cur));
                        continue;
                    }
                    _ => {}
                }
                if depth == 0 || c == '<' {
                    if c != '<' {
                        cur.push(c);
                    }
                }
            }
            bounds.push(cur);
            for bd in bounds {
                let name = bd.trim().trim_start_matches('?').rsplit("::").next().unwrap_or("").trim().to_string();
                if self.has_type(&name) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// (target member idx, conf) for one ref: the name resolution, then the overload / arity check.
    fn targets(&self, file: &str, callee: &str, recv: &str, rt: &str, kind: &str, argc: i32, rc: &Rc) -> Vec<(usize, &'static str)> {
        if xq::is_xq(file) {
            return self.xq_targets(file, callee, rt, kind, argc);
        }
        let mut v = self.targets0(file, callee, recv, rt, kind, rc);
        self.prefer_own_module(file, &mut v);
        if argc < 0 || !matches!(kind, "call" | "new") || v.is_empty() {
            return v;
        }
        let fits = |i: usize| match self.ms[i].arity {
            None => true,
            Some((lo, hi)) => argc >= lo && (hi < 0 || argc <= hi),
        };
        // overloads: among the targets sharing (file, container, name) keep the ones that take this many arguments
        let mut groups: HashMap<(&str, &str, &str), usize> = HashMap::new();
        for (i, _) in &v {
            let m = &self.ms[*i];
            *groups.entry((m.file.as_str(), m.container.as_str(), m.name.as_str())).or_default() += 1;
        }
        let any_fit: HashSet<(&str, &str, &str)> = v
            .iter()
            .filter(|(i, _)| fits(*i))
            .map(|(i, _)| (self.ms[*i].file.as_str(), self.ms[*i].container.as_str(), self.ms[*i].name.as_str()))
            .collect();
        v.retain(|(i, _)| {
            let m = &self.ms[*i];
            let k = (m.file.as_str(), m.container.as_str(), m.name.as_str());
            groups[&k] < 2 || !any_fit.contains(&k) || fits(*i)
        });
        // same-arity overloads: told apart by the argument types, or labelled a guess
        if matches!(lang_family(file), Some("jvm" | "cs")) {
            self.pick_overloads(file, callee, rc, &mut v);
        }
        // a target that cannot take this many arguments (a signature edited since the call was written) is not exact
        for (i, c) in v.iter_mut() {
            if !fits(*i) && *c != "name" {
                *c = "name";
            }
        }
        v
    }

    /// The build module (nearest ancestor directory with a build file) a file belongs to; "" = the repo root.
    fn module_root(&self, file: &str) -> String {
        const BUILD: &[&str] = &["build.gradle", "build.gradle.kts", "pom.xml", "package.json", "Cargo.toml", "go.mod", "pyproject.toml", "setup.py", "composer.json", "Gemfile", "build.sbt"];
        let dir = file.rsplit_once('/').map(|x| x.0).unwrap_or("");
        if let Some(r) = self.mod_root_.lock().ok().and_then(|m| m.get(dir).cloned()) {
            return r;
        }
        let mut d = dir;
        let root = loop {
            let base = if d.is_empty() { self.repo.clone() } else { self.repo.join(d) };
            if BUILD.iter().any(|b| base.join(b).is_file()) {
                break d.to_string();
            }
            if d.is_empty() {
                // no build file: the directory above a `src/` source root (`alpha/src/main/kotlin/...` -> `alpha`)
                break dir.find("/src/").map(|i| dir[..i].to_string()).or_else(|| dir.strip_suffix("/src").map(str::to_string)).unwrap_or_default();
            }
            d = d.rsplit_once('/').map(|x| x.0).unwrap_or("");
        };
        if let Ok(mut m) = self.mod_root_.lock() {
            m.insert(dir.to_string(), root.clone());
        }
        root
    }

    /// The same qualified name defined in several build modules (two Gradle modules each with
    /// `com.example.service.Store`): a call binds to the copy in the caller's own module when there is one.
    fn prefer_own_module(&self, file: &str, v: &mut Vec<(usize, &'static str)>) {
        if v.len() < 2 {
            return;
        }
        let mut by_q: HashMap<&str, Vec<usize>> = HashMap::new();
        for (k, (i, _)) in v.iter().enumerate() {
            by_q.entry(self.ms[*i].qname.as_str()).or_default().push(k);
        }
        let mut drop: HashSet<usize> = HashSet::new();
        for ks in by_q.values().filter(|ks| ks.len() > 1) {
            let files: HashSet<&str> = ks.iter().map(|&k| self.ms[v[k].0].file.as_str()).collect();
            if files.len() < 2 {
                continue;
            }
            let own = self.module_root(file);
            let mine: Vec<usize> = ks.iter().copied().filter(|&k| self.module_root(&self.ms[v[k].0].file) == own).collect();
            if !mine.is_empty() && mine.len() < ks.len() {
                drop.extend(ks.iter().copied().filter(|k| !mine.contains(k)));
            }
        }
        if !drop.is_empty() {
            let mut k = 0;
            v.retain(|_| {
                k += 1;
                !drop.contains(&(k - 1))
            });
        }
    }

    /// Go: methods named `callee` on types that have every method the interface `iface` lists (implicit implementation).
    fn go_impls(&self, iface: &str, callee: &str) -> Vec<usize> {
        let Some(sig) = self.types(iface).into_iter().flatten().map(|&d| &self.ms[d]).find(|m| m.kind == "interface" && m.file.ends_with(".go")).map(|m| m.iface.clone()) else {
            return vec![];
        };
        let names: Vec<&str> = sig.split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
        if !names.contains(&callee) {
            return vec![];
        }
        let mut out = vec![];
        for &i in self.by_name(callee).into_iter().flatten() {
            let m = &self.ms[i];
            if !m.file.ends_with(".go") || m.container.is_empty() || m.container == iface || !callable(&m.kind) {
                continue;
            }
            if self.types(&m.container).is_some_and(|d| d.iter().any(|&x| self.ms[x].kind == "interface")) {
                continue;
            }
            if names.iter().all(|n| self.by_cn(&(m.container.to_string(), n.to_string())).is_some_and(|v| !v.is_empty())) {
                out.push(i);
            }
        }
        out.truncate(12);
        out
    }

    fn targets0(&self, file: &str, callee: &str, recv: &str, rt: &str, kind: &str, rc: &Rc) -> Vec<(usize, &'static str)> {
        let mut out: Vec<(usize, &'static str)> = vec![];
        let want = |i: usize| -> bool {
            let k = self.ms[i].kind.as_str();
            match kind {
                "new" | "jsx" => is_type(k) || k == "ctor" || k == "component" || k == "function",
                "field" => k == "field" || k == "const" || k == "enum",
                "ref" => callable(k),
                _ => callable(k) || k == "field",
            }
        };
        // `x := NewT()` records the call's result type as `ret:NewT`: the declared return type of that function
        let ret_ty: String;
        let rt = match rt.strip_prefix("ret:") {
            Some(f) => {
                let defs: Vec<&M> = self.by_name(f).into_iter().flatten().map(|&i| &self.ms[i]).filter(|m| callable(&m.kind) && !m.ret.is_empty()).collect();
                // a plain function first; else methods of that name when they all return the same type
                // (`x, err := f.NewHour()`: the receiver is not recorded, the result type is)
                ret_ty = match defs.iter().find(|m| m.container.is_empty()) {
                    Some(m) => m.ret.to_string(),
                    None if !defs.is_empty() && defs.iter().all(|m| m.ret == defs[0].ret) => defs[0].ret.to_string(),
                    None => String::new(),
                };
                ret_ty.as_str()
            }
            None => rt,
        };
        // `xs.forEach(x -> x.m())` with `xs = obj.getXs()`: `elem:T.getXs` is the element type of T.getXs's result
        let elem_ty: String;
        let rt = match rt.strip_prefix("elem:") {
            Some(spec) => {
                let Some((t, m)) = spec.rsplit_once('.') else { return out };
                let mut seen = HashSet::new();
                elem_ty = self.in_class(t, m, 0, &mut seen).into_iter().map(|(i, _)| self.ms[i].elem.clone()).find(|e| !e.is_empty()).unwrap_or_default();
                if elem_ty.is_empty() {
                    return out;
                }
                elem_ty.as_str()
            }
            None => rt,
        };
        // `super.m()` / `super().m()` in class C: `m` as C's parents define it (never C's own override)
        if let Some(cls) = rt.strip_prefix("super:") {
            let mut seen = HashSet::new();
            seen.insert(cls.to_string());
            let mut found: Vec<(usize, bool)> = vec![];
            for &d in self.types(cls).into_iter().flatten() {
                for s in &self.ms[d].supers {
                    found.extend(self.in_class(s, callee, 0, &mut seen));
                }
            }
            return found.into_iter().filter(|(i, _)| want(*i)).take(8).map(|(i, via)| (i, if via { "resolved" } else { "exact" })).collect();
        }
        // a generic receiver (`e: T` with `T: Extractor`): the trait it is bounded by
        let bound: String;
        let rt = if !rt.is_empty() && file.ends_with(".rs") && !rt.starts_with("mod:") && !self.has_type(rt) {
            match self.rs_bound(file, rc.caller_line, rt) {
                Some(b) => {
                    bound = b;
                    bound.as_str()
                }
                None => rt,
            }
        } else {
            rt
        };
        if let Some(spec) = rt.strip_prefix("mod:") {
            let (src, orig) = spec.rsplit_once('#').unwrap_or((spec, ""));
            let Some(mut t) = self.module_file(file, src) else { return out };
            let mut orig = orig.to_string();
            // Python `from pkg import sub` binds a submodule when `pkg` itself does not define `sub`
            if file.ends_with(".py") && !orig.is_empty() && orig != "*" && self.defining(&t, &orig, 0).is_none() {
                let sub = if src.chars().all(|c| c == '.') { format!("{src}{orig}") } else { format!("{src}.{orig}") };
                if let Some(sf) = self.module_file(file, &sub) {
                    t = sf;
                    orig = "*".into();
                }
            }
            let in_f = |f: &str, name: &str, cont: Option<&str>| -> Vec<usize> {
                self.by_name(name)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|&i| Self::in_file(&self.ms[i].file, f) && cont.is_none_or(|c| self.ms[i].container == c) && want(i))
                    .collect()
            };
            // the file and name that really define the imported binding (through barrels / re-exports)
            let (tf, on) = match orig.as_str() {
                "default" => self.defining(&t, "default", 0).unwrap_or((t.clone(), String::new())),
                "*" | "" => (t.clone(), String::new()),
                o => self.defining(&t, o, 0).unwrap_or((t.clone(), o.to_string())),
            };
            if recv.is_empty() {
                let name = if on.is_empty() { callee } else { on.as_str() };
                let v = in_f(&tf, name, Some(""));
                if !v.is_empty() {
                    return v.into_iter().map(|i| (i, "exact")).collect();
                }
                let v = in_f(&tf, name, None);
                return v.into_iter().take(3).map(|i| (i, "resolved")).collect();
            }
            // obj.member where obj is an import binding
            let (tf, cont) = match orig.as_str() {
                "*" => match self.defining(&t, callee, 0) {
                    Some((f2, n2)) if n2 == callee => (f2, ""),
                    _ => (tf, ""),
                },
                "default" => (tf, recv),
                _ => (tf, on.as_str()),
            };
            let v = in_f(&tf, callee, Some(cont));
            if !v.is_empty() {
                let mut out: Vec<(usize, &'static str)> = v.into_iter().map(|i| (i, "exact")).collect();
                if file.ends_with(".go") && !cont.is_empty() {
                    out.extend(self.go_impls(cont, callee).into_iter().map(|i| (i, "resolved")));
                }
                return out;
            }
            let v = in_f(&tf, callee, None);
            return v.into_iter().take(3).map(|i| (i, "resolved")).collect();
        }
        if !rt.is_empty() {
            let types_known = self.has_type(rt)
                || self.by_name(rt)
                    .is_some_and(|v| v.iter().any(|&i| self.ms[i].container.is_empty() || is_type(&self.ms[i].kind)));
            if kind == "new" || kind == "jsx" {
                if let Some(v) = self.by_name(callee) {
                    let c: Vec<usize> = v
                        .iter()
                        .copied()
                        .filter(|&i| want(i) && (is_type(&self.ms[i].kind) || self.ms[i].container.is_empty()))
                        .collect();
                    let same: Vec<usize> = c.iter().copied().filter(|&i| self.ms[i].file == file).collect();
                    let c = if same.is_empty() { c } else { same };
                    let conf = if c.len() == 1 { "exact" } else { "resolved" };
                    return c.into_iter().take(4).map(|i| (i, conf)).collect();
                }
                return out;
            }
            if !types_known {
                return out; // receiver is a library type: no edge
            }
            let found = self.in_class(rt, callee, 0, &mut HashSet::new());
            let found: Vec<(usize, bool)> = found.into_iter().filter(|(i, _)| want(*i)).collect();
            if !found.is_empty() {
                for (i, via) in &found {
                    out.push((*i, if *via { "resolved" } else { "exact" }));
                }
                // calls through an interface also reach its implementations
                if self.types(rt).is_some_and(|d| d.iter().any(|&x| self.ms[x].kind == "interface")) {
                    let cap = if file.ends_with(".rs") { 48 } else { 6 };
                    let mut impls = vec![];
                    self.subs_with(rt, callee, 0, &mut impls, cap);
                    for i in impls.into_iter().take(cap) {
                        out.push((i, "resolved"));
                    }
                    if file.ends_with(".go") {
                        out.extend(self.go_impls(rt, callee).into_iter().map(|i| (i, "resolved")));
                    }
                }
                out.truncate(if file.ends_with(".rs") { 56 } else { 8 });
                return out;
            }
            // Panache: Entity.find/persist/update/delete are inherited from a library class
            if let Some(d) = self.panache(rt) {
                return vec![(d, "resolved")];
            }
            return out;
        }
        // no receiver type: same-file top-level / unique name / few candidates
        let head = recv.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("");
        if (NOISE.contains(&callee) || (file.ends_with(".rs") && RS_NOISE.contains(&callee)) || GLOBALS.contains(&head)) && !recv.is_empty() {
            return out;
        }
        let rust = file.ends_with(".rs");
        if rust && recv.is_empty() && kind == "call" {
            if let Some(v) = self.rs_call(file, callee, rc) {
                return v;
            }
        }
        let Some(v) = self.by_name(callee) else { return out };
        let c: Vec<usize> =
            v.iter().copied().filter(|&i| want(i) && !(is_type(&self.ms[i].kind) && kind == "call")).collect();
        let go = file.ends_with(".go");
        let dir_of = |p: &str| p.rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default();
        if kind == "ref" {
            // a function used as a value: only a plain function of this file (Go: this package), never a name match elsewhere
            if !recv.is_empty() {
                return out;
            }
            let d = dir_of(file);
            let same: Vec<usize> = c
                .iter()
                .copied()
                .filter(|&i| self.ms[i].container.is_empty() && if go { dir_of(&self.ms[i].file) == d } else { self.ms[i].file == file })
                .collect();
            return same.into_iter().take(3).map(|i| (i, if go { "resolved" } else { "exact" })).collect();
        }
        if go && recv.is_empty() {
            // Go: a bare call names a package-level function of the same package, never a method; same-package name
            // matches are `resolved`, not `exact` (a name is not a declaration)
            let d = dir_of(file);
            let same: Vec<usize> = c
                .iter()
                .copied()
                .filter(|&i| self.ms[i].container.is_empty() && dir_of(&self.ms[i].file) == d)
                .collect();
            if !same.is_empty() {
                return same.into_iter().take(4).map(|i| (i, "resolved")).collect();
            }
            return out;
        }
        if recv.is_empty() {
            let same: Vec<usize> = c.iter().copied().filter(|&i| self.ms[i].file == file).collect();
            if !same.is_empty() {
                return same.into_iter().take(4).map(|i| (i, "exact")).collect();
            }
            // C / C++: a name defined in several places (kernel helpers copied under tools/, per-arch versions) is the
            // one the caller's #includes bring in (directly, or through one header)
            if c.len() > 1 && lang_family(file) == Some("c") {
                let vis = self.c_visible(file, &c);
                match vis.len() {
                    1 => return vec![(vis[0], "resolved")],
                    2..=5 => return vis.into_iter().map(|i| (i, "name")).collect(),
                    _ => {}
                }
            }
            return match c.len() {
                0 => out,
                1 => vec![(c[0], "resolved")],
                2..=5 => c.into_iter().map(|i| (i, "name")).collect(),
                _ => out,
            };
        }
        if c.len() <= 4 {
            return c.into_iter().map(|i| (i, "name")).collect();
        }
        if rust {
            // a method of a trait with many implementations, receiver unknown: the trait's declaration
            let tr: Vec<usize> = c
                .iter()
                .copied()
                .filter(|&i| self.types(&self.ms[i].container).is_some_and(|d| d.iter().any(|&x| self.ms[x].kind == "interface")))
                .collect();
            return tr.into_iter().take(3).map(|i| (i, "name")).collect();
        }
        out
    }
}

/// Rebuild call edges for dirty keys (everything when `full`), then the fan-in table.
const CHUNK: usize = 20_000;
/// An update resolves against a partial graph (see [`Keys`]) unless it re-resolves more refs than this, loads more keys,
/// or still misses keys after this many passes: then the whole graph is loaded (the same edges, more slowly).
const PARTIAL_REFS: usize = 200_000;
const PARTIAL_KEYS: usize = 200_000;
const PARTIAL_ROUNDS: usize = 16;
/// Refs per batch when a full build resolves in batches (memory budget), and the graph memory one member costs
/// (measured: about 380 bytes with its name / container indexes on a kernel-size C graph).
const BATCH_REFS: usize = 50_000;
const GRAPH_BYTES_PER_MEMBER: u64 = 400;

/// Names defined in changed files whose definitions only moved (same shapes, same count, same order in every changed
/// file, and no type in that file changed) leave `cg_dirty`: their refs elsewhere resolve exactly as before, so the
/// edges into those files from unchanged files are restored from `cg_keep` with the new lines instead of re-resolving
/// every ref of a common name repo-wide. Anything else stays dirty and re-resolves as before.
/// Moves of clean names: file -> old line -> new line, and the old lines that did not move cleanly.
type Moves = (HashMap<String, HashMap<i64, i64>>, HashMap<String, HashSet<i64>>);

fn keep_stable_names(tx: &Transaction, repo: &std::path::Path) -> Result<Moves> {
    type Shapes = HashMap<String, Vec<(i64, String)>>; // name -> [(line, shape)] in line order
    let load = |sql: &str, file: &str| -> Result<(Shapes, Vec<String>)> {
        let mut st = tx.prepare_cached(sql)?;
        let mut out: Shapes = HashMap::new();
        let mut types: Vec<String> = vec![];
        let mut rows = st.query([file])?;
        while let Some(r) = rows.next()? {
            let (line, name, shape, is_type): (i64, String, String, i64) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
            if is_type != 0 {
                types.push(shape.clone());
            }
            out.entry(name).or_default().push((line, shape));
        }
        types.sort();
        Ok((out, types))
    };
    let files: Vec<String> = tx.prepare("SELECT key FROM cg_dirty WHERE kind='f'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let snap: HashSet<String> = tx.prepare("SELECT DISTINCT file FROM cg_oldm")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut unstable: HashSet<String> = HashSet::new();
    let mut stable: HashSet<String> = HashSet::new();
    let mut moves: HashMap<String, HashMap<i64, i64>> = HashMap::new(); // file -> old line -> new line
    let mut bad_lines: HashMap<String, HashSet<i64>> = HashMap::new(); // old lines of members that did not keep their shape
    for f in &files {
        let (new, new_types) = load(&format!("SELECT line, name, {SHAPE}, kind IN ({TYPE_KINDS}) FROM members WHERE file=? ORDER BY line, qname, kind, sig"), f)?;
        if !snap.contains(f) {
            unstable.extend(new.into_keys()); // a new file: everything it defines is new
            continue;
        }
        let (old, old_types) = load("SELECT line, name, shape, is_type FROM cg_oldm WHERE file=? ORDER BY line, shape", f)?;
        let types_same = old_types == new_types;
        let names: HashSet<&String> = old.keys().chain(new.keys()).collect();
        let mv = moves.entry(f.clone()).or_default();
        let bad = bad_lines.entry(f.clone()).or_default();
        if f.ends_with(".rs") && rs_has_inline_mods(repo, f) {
            // which inline module a definition sits in decides how it is reached: nothing here is a clean move
            unstable.extend(names.iter().map(|n| (*n).clone()));
            bad.extend(old.values().flatten().map(|x| x.0));
            continue;
        }
        for n in names {
            let (o, w) = (old.get(n), new.get(n));
            let same = types_same
                && matches!((o, w), (Some(o), Some(w)) if o.len() == w.len() && o.iter().zip(w.iter()).all(|(a, b)| a.1 == b.1));
            if same {
                for (a, b) in o.unwrap().iter().zip(w.unwrap().iter()) {
                    if mv.insert(a.0, b.0).is_some_and(|prev| prev != b.0) {
                        bad.insert(a.0); // two members on one line moved apart: not a clean move
                    }
                }
                stable.insert(n.clone());
            } else {
                unstable.insert(n.clone());
                bad.extend(o.into_iter().flatten().map(|x| x.0));
            }
        }
        // members sharing a line (`class P { function a(){} function b(){} }`) are one unit for the line map: a name
        // with a member on a line that did not move cleanly re-resolves too (and so do the names beside it, in turn)
        loop {
            let mut grew = false;
            for (n, o) in &old {
                if !unstable.contains(n) && o.iter().any(|x| bad.contains(&x.0)) {
                    unstable.insert(n.clone());
                    bad.extend(o.iter().map(|x| x.0));
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
    }
    stable.retain(|n| !unstable.contains(n));
    {
        let mut del = tx.prepare_cached("DELETE FROM cg_dirty WHERE kind='n' AND key=?")?;
        for n in &stable {
            del.execute([n])?;
        }
    }
    Ok((moves, bad_lines))
}

/// A call on a receiver of type T resolves through T's supers and enclosing types, transitively: when one of those is
/// dirty, so is T. Adds to the dirty names every type that reaches a dirty name through `supers` or `container`
/// (`GrandChild extends Child`: Child's super changed, so `grandChild.helper()` re-resolves too).
fn dirty_subtypes(tx: &Transaction) -> Result<()> {
    let mut dirty: HashSet<String> = tx.prepare("SELECT key FROM cg_dirty WHERE kind='n'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut subs: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut st = tx.prepare(&format!("SELECT name, supers FROM members WHERE supers<>'' AND kind IN ({TYPE_KINDS})"))?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let (name, supers): (String, String) = (r.get(0)?, r.get(1)?);
            for sup in supers.split(',').filter(|x| !x.is_empty()) {
                subs.entry(sup.to_string()).or_default().push(name.clone());
            }
        }
    }
    let mut nested = tx.prepare_cached(&format!("SELECT name FROM members WHERE container=? AND kind IN ({TYPE_KINDS})"))?;
    let mut add = tx.prepare_cached("INSERT OR IGNORE INTO cg_dirty VALUES('n', ?)")?;
    let mut todo: Vec<String> = dirty.iter().cloned().collect();
    while let Some(n) = todo.pop() {
        let mut next: Vec<String> = subs.get(&n).cloned().unwrap_or_default();
        next.extend(nested.query_map([&n], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?);
        for t in next {
            if dirty.insert(t.clone()) {
                add.execute([&t])?;
                todo.push(t);
            }
        }
    }
    Ok(())
}

/// After the changed files' edges are cleared: restore the edges into them from unchanged files whose name stayed
/// clean and whose target only moved.
fn restore_moved_edges(tx: &Transaction, (moves, bad_lines): &Moves) -> Result<()> {
    let dirty_fids: HashSet<i64> = tx
        .prepare("SELECT f.rowid FROM files f JOIN cg_dirty d ON d.kind='f' AND d.key=f.path")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let mut st = tx.prepare(&format!(
        "SELECT k.fid, k.line, k.caller_line, k.cfid, g.path, k.callee_line, k.callee, k.cname, k.kind, k.conf FROM cg_keep k JOIN files g ON g.rowid=k.cfid
          WHERE k.cname NOT IN (SELECT key FROM cg_dirty WHERE kind='n')
            AND (k.fid, k.line, k.caller_line, k.cname) NOT IN {DEP}"
    ))?;
    let mut ins = tx.prepare_cached("INSERT INTO call_edges(fid,line,caller_line,cfid,callee_line,callee,cname,kind,conf) VALUES(?,?,?,?,?,?,?,?,?)")?;
    let mut touch = tx.prepare_cached("INSERT OR IGNORE INTO cg_touch VALUES(?,?)")?;
    let mut rows = st.query([])?;
    while let Some(r) = rows.next()? {
        let (fid, line, cl, cfid, path, cline): (i64, i64, i64, i64, String, i64) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
        if dirty_fids.contains(&fid) || bad_lines.get(&path).is_some_and(|b| b.contains(&cline)) {
            continue;
        }
        let Some(&nl) = moves.get(&path).and_then(|m| m.get(&cline)) else { continue };
        let (callee, cname, kind, conf): (String, String, String, String) = (r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?);
        ins.execute(params![fid, line, cl, cfid, nl, callee, cname, kind, conf])?;
        touch.execute(params![cfid, nl])?;
    }
    Ok(())
}

/// Refs whose resolution reads a type or a function that is dirty even though the ref's own callee is not: the receiver's
/// type (its members and supers), or `ret:F` (the result of F: F's declared return type, and that type).
/// (`ret:F` is only ever written in lower case; a member with an empty return type gives no result type.)
const DIRTY_REF: &str = "r.recv_type<>'' AND (r.recv_type IN (SELECT key FROM cg_dirty WHERE kind='n'
    UNION SELECT 'ret:' || key FROM cg_dirty WHERE kind='n'
    UNION SELECT 'super:' || key FROM cg_dirty WHERE kind='n'
    UNION SELECT 'ret:' || m.name FROM members m WHERE m.ret<>'' AND m.ret IN (SELECT key FROM cg_dirty WHERE kind='n'))
    OR (r.recv_type GLOB 'elem:*' AND (substr(r.recv_type, 6, instr(r.recv_type, '.') - 6) IN (SELECT key FROM cg_dirty WHERE kind='n')
        OR substr(r.recv_type, instr(r.recv_type, '.') + 1) IN (SELECT key FROM cg_dirty WHERE kind='n'))))";
/// The refs picked by [`DIRTY_REF`], gathered once per update (`temp.cg_dep`).
const DEP: &str = "(SELECT fid, line, caller_line, callee FROM temp.cg_dep)";

/// The language family of a source path (None: unknown, never filtered).
fn lang_family(p: &str) -> Option<&'static str> {
    let ext = p.rsplit_once('.').map(|x| x.1)?;
    Some(match ext {
        "java" | "kt" | "kts" | "scala" | "groovy" => "jvm",
        "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" | "sjs" | "vue" | "svelte" => "js",
        "py" | "pyi" => "py",
        "rs" => "rs",
        "go" => "go",
        "xq" | "xqm" | "xql" | "xquery" | "xqy" => "xq",
        "rb" | "rake" | "erb" => "rb",
        "php" => "php",
        "cs" | "cshtml" | "razor" => "cs",
        "swift" => "swift",
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "m" | "mm" => "c",
        "dart" => "dart",
        "lua" => "lua",
        "ex" | "exs" => "ex",
        _ => return None,
    })
}

fn same_lang(a: &str, b: &str) -> bool {
    match (lang_family(a), lang_family(b)) {
        // Kotlin Multiplatform: Swift calls into the shared Kotlin module
        (Some("swift"), Some("jvm")) => true,
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

pub fn resolve(ix: &mut Index, full: bool) -> Result<()> {
    let built = ix.meta("cg_built").is_some();
    let mut all = full || !built;
    // the write lock first, then the graph is read under it: nothing can change between the two
    let tx = ix.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // the file list and config files first: they decide whether everything re-resolves
    let mut g = { let _s = crate::par::span("cg:load"); Graph::base(&tx, &ix.repo)? };
    // a changed tsconfig (paths / baseUrl) moves edges anywhere: re-resolve everything
    let prev_ts: String = tx.query_row("SELECT value FROM meta WHERE key='cg_tscfg'", [], |r| r.get(0)).unwrap_or_default();
    if prev_ts != g.ts_sig {
        all = true;
    }
    // a changed barrel / package init re-routes names for importers whose own refs did not change
    if !all {
        let barrel: i64 = tx
            .query_row(
                "SELECT count(*) FROM cg_dirty d WHERE d.kind='f' AND (d.key LIKE '%/__init__.py' OR d.key LIKE '%/index.ts' OR d.key LIKE '%/index.tsx' OR d.key LIKE '%/index.js'
                   OR EXISTS (SELECT 1 FROM refs r JOIN files f ON f.rowid=r.fid WHERE f.path=d.key AND r.kind='reexport'))",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if barrel > 0 {
            all = true;
        }
    }
    // a whole graph that would not fit in half the memory budget: resolve in batches, each against only the members
    // its refs can reach (read from the index, the same exact partial passes as an update)
    // (AIX_CG_BATCH=1 forces it: tests, hosts that would rather trade time for memory)
    let batched = all && (std::env::var("AIX_CG_BATCH").is_ok_and(|v| v == "1") || {
        let n: i64 = tx.query_row("SELECT count(*) FROM members", [], |r| r.get(0)).unwrap_or(0);
        (n.max(0) as u64) * GRAPH_BYTES_PER_MEMBER > crate::par::mem_budget_mb() * 1024 * 1024 / 2
    });
    if all && !batched {
        let _s = crate::par::span("cg:load");
        g.fill(&tx, None)?;
    }
    let dirty_f = "(SELECT f.rowid FROM files f JOIN cg_dirty d ON d.kind='f' AND d.key=f.path)";
    let moves = if all {
        None
    } else {
        let _s = crate::par::span("cg:stable");
        let m = keep_stable_names(&tx, &ix.repo)?;
        dirty_subtypes(&tx)?;
        Some(m)
    };
    let filter = if all {
        tx.execute("DELETE FROM call_edges", [])?;
        String::new()
    } else {
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS cg_dep(fid INT, line INT, caller_line INT, callee TEXT); DELETE FROM temp.cg_dep;")?;
        tx.execute(&format!("INSERT INTO temp.cg_dep SELECT r.fid, r.line, r.caller_line, r.callee FROM refs r WHERE {DIRTY_REF}"), [])?;
        // a changed module's default export re-routes `import x from './m'; x()` in files that did not change: their
        // `mod:<source>#default` refs re-resolve when <source> is a changed file (the local name is not dirty)
        {
            let changed: HashSet<String> = tx.prepare("SELECT key FROM cg_dirty WHERE kind='f'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
            let js = |f: &str| [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"].iter().any(|e| f.ends_with(e));
            if changed.iter().any(|f| js(f)) {
                let mut st = tx.prepare("SELECT r.fid, r.line, r.caller_line, r.callee, f.path, r.recv_type FROM refs r JOIN files f ON f.rowid=r.fid WHERE r.recv_type LIKE 'mod:%#default'")?;
                let mut ins = tx.prepare_cached("INSERT INTO temp.cg_dep VALUES(?,?,?,?)")?;
                let mut rows = st.query([])?;
                while let Some(r) = rows.next()? {
                    let (path, rt): (String, String) = (r.get(4)?, r.get(5)?);
                    let src = rt.trim_start_matches("mod:").trim_end_matches("#default");
                    if g.module_file(&path, src).is_some_and(|m| changed.contains(&m)) {
                        ins.execute(params![r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?])?;
                    }
                }
            }
        }
        let hit = format!("cname IN (SELECT key FROM cg_dirty WHERE kind='n') OR (fid, line, caller_line, cname) IN {DEP}");
        tx.execute(&format!("INSERT OR IGNORE INTO cg_touch SELECT cfid, callee_line FROM call_edges WHERE {hit}"), [])?;
        tx.execute(&format!("INSERT OR IGNORE INTO cg_old SELECT fid, line, caller_line, cfid, callee_line FROM call_edges WHERE {hit}"), [])?;
        tx.execute(&format!("DELETE FROM call_edges WHERE fid IN {dirty_f} OR cfid IN {dirty_f} OR {hit}"), [])?;
        if let Some(m) = &moves {
            restore_moved_edges(&tx, m)?;
        }
        format!(" AND (r.fid IN {dirty_f} OR r.callee IN (SELECT key FROM cg_dirty WHERE kind='n') OR (r.fid, r.line, r.caller_line, r.callee) IN {DEP})")
    };
    let sql = format!("SELECT f.path, r.fid, r.line, r.caller_line, r.callee, r.recv, r.recv_type, r.kind, COALESCE(r.argc, -1), r.conf FROM refs r JOIN files f ON f.rowid=r.fid WHERE r.kind IN ('call','new','jsx','field','ref'){filter}");
    {
        let mut st = tx.prepare(&sql)?;
        let mut ins = tx.prepare(
            "INSERT INTO call_edges(fid,line,caller_line,cfid,callee_line,callee,cname,kind,conf) VALUES(?,?,?,?,?,?,?,?,?)",
        )?;
        let mut touch = tx.prepare("INSERT OR IGNORE INTO cg_touch VALUES(?,?)")?;
        let mut rows = st.query([])?;
        // one edge per (ref, target): a 128-bit digest of the key instead of the key itself (16 bytes, not a copy of
        // every label; kernel-size graphs have millions of edges). Two independent 64-bit keyed hashes: a false
        // duplicate needs both to collide at once.
        let mut seen: HashSet<u128> = HashSet::new();
        let (h1, h2) = (std::collections::hash_map::RandomState::new(), std::collections::hash_map::RandomState::new());
        type RefRow = (String, i64, i64, i64, String, String, String, String, i64, String);
        // resolution is pure on the loaded graph: chunks are resolved in parallel, then inserted in query order
        // (same edges, same order, same rowids as a serial pass)
        let resolve_chunk = |g: &Graph, chunk: &[RefRow]| -> Vec<Vec<(i64, i64, String, &'static str)>> {
            use rayon::prelude::*;
            // Rust: the path qualifier of each bare call (`a::run()`), read from the source line
            let mut ord: HashMap<(&str, i64, &str), usize> = HashMap::new();
            let rcs: Vec<Rc> = chunk
                .iter()
                .map(|(file, _fid, line, cl, callee, recv, rt, kind, _argc, _rconf)| {
                    let mut qual = vec![];
                    if file.ends_with(".rs") && recv.is_empty() && rt.is_empty() && kind == "call" {
                        if let Some(t) = g.rs_text(file) {
                            if let Some(l) = t.lines.get((*line - 1).max(0) as usize) {
                                let qs = rs_quals(l, callee);
                                let k = ord.entry((file.as_str(), *line, callee.as_str())).or_default();
                                if !qs.is_empty() {
                                    qual = qs[*k % qs.len()].clone();
                                }
                                *k += 1;
                            }
                        }
                    }
                    Rc { line: *line, caller_line: *cl, qual }
                })
                .collect();
            let work = || {
                chunk
                    .par_iter()
                    .zip(rcs.par_iter())
                    .map(|((file, _fid, _line, _cl, callee, recv, rt, kind, argc, rconf), rc)| {
                        let mut out = vec![];
                        for (i, conf) in g.targets(file, callee, recv, rt, kind, *argc as i32, rc) {
                            // the receiver type was inferred from a mock wrapper (`verify(x).m()`): a labelled guess, never `exact`
                            let conf = if rconf == "heuristic" && conf != "name" { "heuristic" } else { conf };
                            let m = &g.ms[i];
                            // a call never lands in another language (`new X()` in Java is not a TS interface X)
                            if !same_lang(file, &m.file) {
                                continue;
                            }
                            let Some(&cfid) = g.fids.get(m.file.as_str()) else { continue };
                            let label = if is_type(&m.kind) && kind == "call" && callee != &m.name {
                                format!("{}.{callee}", m.qname)
                            } else {
                                m.qname.to_string()
                            };
                            out.push((cfid, m.line, label, conf));
                        }
                        out
                    })
                    .collect()
            };
            if chunk.len() < 512 { work() } else { crate::par::pool().install(work) }
        };
        let mut flush = |chunk: &mut Vec<RefRow>, res: Vec<Vec<(i64, i64, String, &'static str)>>| -> Result<()> {
            let _si = crate::par::span("cg:insert");
            for ((_file, fid, line, cl, callee, _recv, _rt, kind, _argc, _rconf), tg) in chunk.iter().zip(res) {
                for (cfid, mline, label, conf) in tg {
                    // fields declared on one line share a (file, line) key: keep one edge per target label
                    let k = (*fid, *line, *cl, cfid, mline, label.as_str());
                    if !seen.insert(((h1.hash_one(k) as u128) << 64) | h2.hash_one(k) as u128) {
                        continue;
                    }
                    ins.execute(params![fid, line, cl, cfid, mline, label, callee, kind, conf])?;
                    if !all {
                        touch.execute(params![cfid, mline])?;
                    }
                }
            }
            chunk.clear();
            Ok(())
        };
        let get = |r: &rusqlite::Row| -> rusqlite::Result<RefRow> {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?))
        };
        // only the members the refs of `list` can reach are loaded. Resolve against that partial graph, add every key
        // it could not answer, and repeat until a pass needed nothing it lacked: that pass answered each lookup exactly
        // as the whole graph would (same members, same order), so its edges are the full graph's.
        let partial_pass = |g: &mut Graph, list: &[RefRow]| -> Result<Vec<Vec<(i64, i64, String, &'static str)>>> {
            let mut keys = Keys::default();
            for (file, _fid, _line, _cl, callee, _recv, rt, _kind, _argc, _rconf) in list {
                keys.names.insert(callee.clone());
                match rt.strip_prefix("ret:").or_else(|| rt.strip_prefix("super:")) {
                    Some(f) => keys.names.insert(f.to_string()),
                    None if rt.starts_with("elem:") => {
                        let (t, m) = rt["elem:".len()..].rsplit_once('.').unwrap_or(("", ""));
                        keys.names.insert(m.to_string());
                        keys.names.insert(t.to_string())
                    }
                    None if !rt.is_empty() && !rt.starts_with("mod:") => keys.names.insert(rt.clone()),
                    None => false,
                };
                keys.imps.insert(file.clone());
                if file.ends_with(".rs") {
                    keys.rs_at.insert(file.clone());
                }
            }
            let mut round = 0;
            loop {
                let partial = list.len() <= PARTIAL_REFS && keys.len() <= PARTIAL_KEYS && round < PARTIAL_ROUNDS;
                {
                    let _s = crate::par::span("cg:load");
                    g.fill(&tx, if partial { Some(&keys) } else { None })?;
                }
                let res: Vec<_> = {
                    let _s = crate::par::span("cg:resolve");
                    list.chunks(CHUNK).flat_map(|c| resolve_chunk(g, c)).collect()
                };
                let miss = g.misses();
                if miss.len() == 0 {
                    if crate::par::verbose() {
                        eprintln!("  .. cg: {} refs, {} graph pass(es), {}", list.len(), round + 1, if partial { format!("{} names loaded", keys.names.len()) } else { "whole graph".into() });
                    }
                    return Ok(res);
                }
                keys.names.extend(miss.names);
                keys.imps.extend(miss.imps);
                keys.rs_at.extend(miss.rs_at);
                round += 1;
            }
        };
        if all && !batched {
            let mut chunk: Vec<RefRow> = Vec::with_capacity(CHUNK);
            while let Some(r) = rows.next()? {
                chunk.push(get(r)?);
                if chunk.len() >= CHUNK {
                    let res = { let _s = crate::par::span("cg:resolve"); resolve_chunk(&g, &chunk) };
                    flush(&mut chunk, res)?;
                }
            }
            let res = { let _s = crate::par::span("cg:resolve"); resolve_chunk(&g, &chunk) };
            flush(&mut chunk, res)?;
        } else if all {
            let mut chunk: Vec<RefRow> = Vec::with_capacity(BATCH_REFS);
            loop {
                let more = match rows.next()? {
                    Some(r) => {
                        chunk.push(get(r)?);
                        true
                    }
                    None => false,
                };
                if chunk.len() >= BATCH_REFS || (!more && !chunk.is_empty()) {
                    let res = partial_pass(&mut g, &chunk)?;
                    flush(&mut chunk, res)?;
                }
                if !more {
                    break;
                }
            }
        } else {
            let mut list: Vec<RefRow> = vec![];
            while let Some(r) = rows.next()? {
                list.push(get(r)?);
            }
            let res = partial_pass(&mut g, &list)?;
            flush(&mut list, res)?;
        }
    }
    let _sf = crate::par::span("cg:fanin+rest");
    if all {
        tx.execute("DELETE FROM sym_fanin", [])?;
        tx.execute(
            "INSERT INTO sym_fanin SELECT g.path, e.callee_line, MIN(e.callee), count(*), count(DISTINCT e.fid) FROM call_edges e JOIN files g ON g.rowid=e.cfid GROUP BY e.cfid, e.callee_line",
            [],
        )?;
    } else {
        // recount only the targets that gained or lost an edge, and drop rows of changed files
        tx.execute("DELETE FROM sym_fanin WHERE file IN (SELECT key FROM cg_dirty WHERE kind='f')", [])?;
        tx.execute("DELETE FROM sym_fanin WHERE (file, line) IN (SELECT g.path, t.line FROM cg_touch t JOIN files g ON g.rowid=t.cfid)", [])?;
        tx.execute(
            "INSERT OR REPLACE INTO sym_fanin SELECT g.path, t.line, MIN(e.callee), count(*), count(DISTINCT e.fid) FROM cg_touch t
             JOIN call_edges e ON e.cfid=t.cfid AND e.callee_line=t.line JOIN files g ON g.rowid=t.cfid GROUP BY t.cfid, t.line",
            [],
        )?;
    }
    tx.execute("DELETE FROM cg_touch", [])?;
    if !all {
        // callers whose edges moved or appeared (a method added, renamed or shifted in a changed file): their derived
        // traces refresh too (data-model layer, see trace.rs). Unchanged edges leave the caller alone.
        const SAME: &str = "o.fid=e.fid AND o.line=e.line AND o.caller_line=e.caller_line AND o.cfid=e.cfid AND o.callee_line=e.callee_line";
        tx.execute(
            &format!(
                "INSERT OR IGNORE INTO dm_dirty(file, had, fid) SELECT f.path, 0, f.rowid FROM files f WHERE f.rowid IN (
                   SELECT o.fid FROM cg_old o WHERE NOT EXISTS (SELECT 1 FROM call_edges e WHERE {SAME})
                   UNION SELECT e.fid FROM call_edges e WHERE (e.cname IN (SELECT key FROM cg_dirty WHERE kind='n') OR (e.fid, e.line, e.caller_line, e.cname) IN {DEP})
                     AND NOT EXISTS (SELECT 1 FROM cg_old o WHERE {SAME}))"
            ),
            [],
        )?;
    }
    tx.execute("DELETE FROM cg_old", [])?;
    tx.execute("DELETE FROM cg_oldm", [])?;
    tx.execute("DELETE FROM cg_keep", [])?;
    tx.execute("DELETE FROM cg_dirty", [])?;
    tx.execute("INSERT OR REPLACE INTO meta VALUES('cg_built', ?)", [crate::index::chrono_now()])?;
    // remembered so the next update re-resolves everything only when tsconfig paths or go.mod modules really changed
    tx.execute("INSERT OR REPLACE INTO meta VALUES('cg_tscfg', ?)", [&g.ts_sig])?;
    tx.commit()?;
    Ok(())
}
