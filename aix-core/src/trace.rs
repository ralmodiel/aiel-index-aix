//! Cross-layer edges and materialized trace paths.
//!
//! `layer_edges` joins the layers of a stack with one row per link: route -> page, page -> component, component -> client
//! function, client function -> endpoint, endpoint -> handler, handler -> service (the call graph), service -> table
//! (`data_access`). `trace_paths` stores, for every endpoint, the shortest call chains from its handler to each table it
//! touches (depth <= 6, capped, writes and non-shared code first) and, for every route, the chains from the page to each
//! endpoint it can reach. Both are rebuilt only for the keys whose files changed (`trace_deps`), everything else is kept.
//! Queries (`trace`, `explain`, `table`) read these rows; nothing is computed from source at query time.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::Result;
use rusqlite::{params, Connection};

use crate::index::Index;

/// Tables added after schema version 8 (created on the next update of an older index).
macro_rules! late_ddl {
    () => {
        r#"
-- per endpoint: the lifecycle-state literals its call graph sets or tests (state_refs rows of the members it reaches)
CREATE TABLE IF NOT EXISTS state_flow(tid INT, op TEXT, tbl TEXT, col TEXT, val TEXT, from_vals TEXT, fid INT, line INT, sline INT, depth INT, shared INT);
CREATE INDEX IF NOT EXISTS state_flow_tid ON state_flow(tid);
CREATE INDEX IF NOT EXISTS state_flow_val ON state_flow(tbl, col, val);
"#
    };
}
pub const LATE_DDL: &str = late_ddl!();

pub const SCHEMA: &str = concat!(r#"
CREATE TABLE IF NOT EXISTS layer_edges(kind TEXT, sfid INT, sline INT, sname TEXT, dfid INT, dline INT, dname TEXT, cfid INT, cline INT, conf TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS le_src ON layer_edges(kind, sfid, sline);
CREATE INDEX IF NOT EXISTS le_dst ON layer_edges(kind, dfid, dline);
CREATE INDEX IF NOT EXISTS le_sfid ON layer_edges(sfid);
CREATE INDEX IF NOT EXISTS le_dfid ON layer_edges(dfid);
CREATE VIEW IF NOT EXISTS layer_edges_v AS SELECT e.kind AS kind, s.path AS sfile, e.sline AS sline, e.sname AS sname, d.path AS dfile, e.dline AS dline,
  e.dname AS dname, c.path AS cfile, e.cline AS cline, e.conf AS conf, e.note AS note
  FROM layer_edges e LEFT JOIN files s ON s.rowid=e.sfid LEFT JOIN files d ON d.rowid=e.dfid LEFT JOIN files c ON c.rowid=e.cfid;
CREATE TABLE IF NOT EXISTS trace_keys(id INTEGER PRIMARY KEY, kind TEXT, key TEXT, fid INT, line INT, reach INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS trace_keys_key ON trace_keys(kind, key);
CREATE INDEX IF NOT EXISTS trace_keys_node ON trace_keys(fid, line);
CREATE TABLE IF NOT EXISTS trace_paths(tid INT, pid INT, hop INT, layer TEXT, fid INT, line INT, cfid INT, cline INT, conf TEXT, tbl TEXT, rw TEXT, via TEXT);
CREATE INDEX IF NOT EXISTS trace_paths_tid ON trace_paths(tid, pid, hop);
CREATE INDEX IF NOT EXISTS trace_paths_node ON trace_paths(fid, line);
CREATE INDEX IF NOT EXISTS trace_paths_tbl ON trace_paths(tbl, rw) WHERE layer='table';
CREATE TABLE IF NOT EXISTS trace_deps(tid INT, fid INT, PRIMARY KEY(fid, tid)) WITHOUT ROWID;
"#, late_ddl!());

const MAX_DEPTH: usize = 6;
const MAX_NODES: usize = 900;
const MAX_LEAVES: usize = 24;
const MAX_CHAINS: usize = 60;
/// A TypeScript module called from more files than this is shared infrastructure, not part of one page.
const SHARED_CALLERS: usize = 8;
/// A backend method called from more files than this is shared infrastructure (auth checks, year policy): ranked last.
const SHARED_BACKEND: i64 = 25;

type Node = (i64, i64); // (files.rowid, member declaration line)

#[derive(Clone, Copy)]
struct Edge {
    to: Node,
    site: i64,
    conf: u8,
}

fn conf_rank(c: &str) -> u8 {
    match c {
        "exact" => 0,
        "resolved" => 1,
        _ => 2,
    }
}
pub fn conf_name(r: u8) -> &'static str {
    ["exact", "resolved", "name"][r.min(2) as usize]
}

struct Adj<'a> {
    conn: &'a Connection,
    cache: HashMap<Node, Vec<Edge>>,
    all: bool,
}

impl<'a> Adj<'a> {
    fn load(conn: &'a Connection, all: bool) -> Result<Adj<'a>> {
        let mut a = Adj { conn, cache: HashMap::new(), all };
        if all {
            let mut st = conn.prepare("SELECT fid, caller_line, cfid, callee_line, line, conf FROM call_edges WHERE kind IN ('call','new','jsx') AND caller_line>0 AND conf<>'name' ORDER BY fid, caller_line, line")?;
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                let (fid, cl, cfid, cll, line, conf): (i64, i64, i64, i64, i64, String) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?);
                let v = a.cache.entry((fid, cl)).or_default();
                if !v.iter().any(|e| e.to == (cfid, cll)) {
                    v.push(Edge { to: (cfid, cll), site: line, conf: conf_rank(&conf) });
                }
            }
        }
        Ok(a)
    }
    fn edges(&mut self, n: Node) -> &Vec<Edge> {
        if !self.all && !self.cache.contains_key(&n) {
            let mut v: Vec<Edge> = vec![];
            if let Ok(mut st) = self.conn.prepare_cached("SELECT cfid, callee_line, line, conf FROM call_edges WHERE fid=? AND caller_line=? AND kind IN ('call','new','jsx') AND conf<>'name' ORDER BY line") {
                if let Ok(it) = st.query_map(params![n.0, n.1], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))) {
                    for (cfid, cll, line, conf) in it.flatten() {
                        if !v.iter().any(|e| e.to == (cfid, cll)) {
                            v.push(Edge { to: (cfid, cll), site: line, conf: conf_rank(&conf) });
                        }
                    }
                }
            }
            self.cache.insert(n, v);
        }
        static EMPTY: Vec<Edge> = Vec::new();
        self.cache.get(&n).unwrap_or(&EMPTY)
    }
}

struct Da {
    tbl: String,
    rw: String,
    via: String,
    conf: u8,
    line: i64,
    entity: String,
}

#[derive(Clone)]
struct Member {
    line: i64,
    end: i64,
    qname: String,
    kind: String,
}

struct Ctx<'a> {
    conn: &'a Connection,
    path: HashMap<i64, String>,
    fid: HashMap<String, i64>,
    members: HashMap<i64, Vec<Member>>,
    ent_loc: HashMap<String, (i64, i64)>, // table -> entity (fid, line)
}

impl<'a> Ctx<'a> {
    fn new(conn: &'a Connection) -> Result<Ctx<'a>> {
        let mut c = Ctx { conn, path: HashMap::new(), fid: HashMap::new(), members: HashMap::new(), ent_loc: HashMap::new() };
        let mut st = conn.prepare("SELECT rowid, path FROM files")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
            let (i, p) = r?;
            c.fid.insert(p.clone(), i);
            c.path.insert(i, p);
        }
        let mut st = conn.prepare("SELECT file, line, tbl FROM entities WHERE kind='entity' AND tbl<>'' ORDER BY file")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)))? {
            let (f, l, t) = r?;
            if let Some(&i) = c.fid.get(&f) {
                c.ent_loc.entry(t).or_insert((i, l));
            }
        }
        Ok(c)
    }
    fn members_of(&mut self, fid: i64) -> &Vec<Member> {
        if !self.members.contains_key(&fid) {
            let p = self.path.get(&fid).cloned().unwrap_or_default();
            let mut v: Vec<Member> = vec![];
            if let Ok(mut st) = self.conn.prepare_cached("SELECT line, end_line, qname, kind FROM members WHERE file=? ORDER BY line") {
                if let Ok(it) = st.query_map([&p], |r| Ok(Member { line: r.get(0)?, end: r.get(1)?, qname: r.get(2)?, kind: r.get(3)? })) {
                    v = it.flatten().collect();
                }
            }
            self.members.insert(fid, v);
        }
        &self.members[&fid]
    }
    fn qname(&mut self, n: Node) -> String {
        let ms = self.members_of(n.0);
        ms.iter().find(|m| m.line == n.1 && m.kind != "field").or_else(|| ms.iter().find(|m| m.line == n.1)).map(|m| m.qname.clone()).unwrap_or_default()
    }
    /// Innermost callable member containing `line`.
    fn enclosing(&mut self, fid: i64, line: i64) -> Option<Member> {
        self.members_of(fid)
            .iter()
            .filter(|m| m.line <= line && line <= m.end && matches!(m.kind.as_str(), "method" | "function" | "component" | "ctor" | "const" | "field"))
            .min_by_key(|m| m.end - m.line)
            .cloned()
    }
}

type ServiceRow = (i64, i64, String, i64, i64, String, i64, i64, String, String);

fn service_rows(tx: &Connection) -> Result<HashSet<ServiceRow>> {
    let mut st = tx.prepare("SELECT sfid, sline, sname, dfid, dline, dname, cfid, cline, conf, note FROM layer_edges WHERE kind='service_table'")?;
    let v = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)))?
        .collect::<Result<HashSet<_>, _>>()?;
    Ok(v)
}

struct Endpoint {
    fid: i64,
    line: i64,
    method: String,
    norm: String,
    key: String,
    handler: Option<Node>,
}

struct Client {
    node: Node,
    qname: String,
    method: String,
    norm: String,
    aline: i64,
}

fn load_endpoints(cx: &mut Ctx) -> Result<Vec<Endpoint>> {
    let mut v = vec![];
    let mut st = cx.conn.prepare("SELECT file, line, method, norm, class, handler FROM endpoints ORDER BY file, line")?;
    let rows: Vec<(String, i64, String, String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect::<Result<_, _>>()?;
    for (f, line, method, norm, class, handler) in rows {
        let Some(&fid) = cx.fid.get(&f) else { continue };
        let ms = cx.members_of(fid);
        let h = ms
            .iter()
            .find(|m| m.line == line && (matches!(m.kind.as_str(), "method" | "function") || (m.kind == "component" && m.qname == handler)))
            .or_else(|| ms.iter().find(|m| m.qname.ends_with(&format!("{class}.{handler}")) && m.line >= line - 2 && m.line <= line + 6))
            .map(|m| (fid, m.line))
            .or_else(|| {
                let (hf, hl) = crate::compose::handler_member(cx.conn, &f, &class, &handler)?;
                cx.fid.get(&hf).map(|i| (*i, hl))
            });
        v.push(Endpoint { fid, line, key: format!("{method} {norm}"), method, norm, handler: h });
    }
    Ok(v)
}

fn load_clients(cx: &mut Ctx) -> Result<Vec<Client>> {
    let mut out: Vec<Client> = vec![];
    let mut st = cx.conn.prepare("SELECT file, line, COALESCE(method,''), norm FROM api_calls ORDER BY file, line")?;
    let rows: Vec<(String, i64, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?;
    let mut seen: HashSet<(Node, String, String)> = HashSet::new();
    for (f, aline, method, norm) in rows {
        let Some(&fid) = cx.fid.get(&f) else { continue };
        let Some(m) = cx.enclosing(fid, aline) else { continue };
        let node = (fid, m.line);
        if seen.insert((node, method.clone(), norm.clone())) {
            out.push(Client { node, qname: m.qname, method, norm, aline });
        }
    }
    Ok(out)
}

/// Endpoint index for a client call (exact, with the `/api` base, or segment-wise with `{}` wildcards).
fn match_endpoint<'e>(eps: &'e [Endpoint], by_key: &HashMap<(String, String), usize>, method: &str, norm: &str) -> Option<(&'e Endpoint, &'static str)> {
    let alt = format!("/api{norm}");
    for n in [norm, alt.as_str()] {
        if method.is_empty() {
            if let Some(e) = eps.iter().find(|e| e.norm == n) {
                return Some((e, "exact"));
            }
        } else if let Some(&i) = by_key.get(&(method.to_string(), n.to_string())) {
            return Some((&eps[i], "exact"));
        }
        if norm.starts_with("/api/") {
            break;
        }
    }
    let want: Vec<&str> = if norm.starts_with("/api/") { norm.split('/').collect() } else { alt.split('/').collect() };
    eps.iter()
        .filter(|e| (method.is_empty() || e.method == method || e.method == "ANY") && e.norm.split('/').count() == want.len())
        .filter(|e| e.norm.split('/').zip(want.iter()).all(|(a, b)| a == *b || a == "{}" || *b == "{}"))
        .max_by_key(|e| e.norm.len())
        .map(|e| (e, "resolved"))
}

struct Le {
    kind: &'static str,
    s: Node,
    sname: String,
    d: Node,
    dname: String,
    c: Node,
    conf: &'static str,
    note: String,
}

fn is_ts(p: &str) -> bool {
    matches!(p.rsplit('.').next().unwrap_or(""), "ts" | "tsx" | "js" | "jsx" | "mjs" | "mts")
}

/// Rebuild what changed. `dm_dirty` (files whose rows were dropped or added) drives it; nothing else is read from disk.
pub fn build(ix: &mut Index, full: bool) -> Result<()> {
    let dirty_rows: Vec<(String, i64)> = {
        let mut st = ix.conn.prepare("SELECT file, fid FROM dm_dirty")?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        r
    };
    let dirty: Vec<String> = dirty_rows.iter().map(|d| d.0.clone()).collect();
    let built = ix.meta("trace_built").is_some();
    let full = full || !built;
    if dirty.is_empty() && !full {
        return Ok(());
    }
    let tx = ix.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(LATE_DDL)?;
    {
        let s_ctx = crate::par::span("trace:load");
        let mut cx = Ctx::new(&tx)?;
        let mut dirty_fids: HashSet<i64> = dirty.iter().filter_map(|f| cx.fid.get(f).copied()).collect();
        dirty_fids.extend(dirty_rows.iter().map(|d| d.1).filter(|f| *f != 0));
        let eps = load_endpoints(&mut cx)?;
        let clients = load_clients(&mut cx)?;
        let by_key: HashMap<(String, String), usize> = eps.iter().enumerate().map(|(i, e)| ((e.method.clone(), e.norm.clone()), i)).collect();

        drop(s_ctx);
        // ───── layer_edges ─────
        let s_edges = crate::par::span("trace:edges");
        let mut les: Vec<Le> = vec![];
        // route -> page
        {
            let mut st = tx.prepare("SELECT file, line, path, component, page_file FROM routes WHERE page_file<>'' AND redirect=''")?;
            let rows: Vec<(String, i64, String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect::<Result<_, _>>()?;
            for (f, line, path, comp, page) in rows {
                let (Some(&sf), Some(&pf)) = (cx.fid.get(&f), cx.fid.get(&page)) else { continue };
                let pl = cx.members_of(pf).iter().find(|m| m.qname == comp || m.qname.ends_with(&format!(".{comp}"))).map(|m| m.line).unwrap_or(1);
                les.push(Le { kind: "route_page", s: (sf, line), sname: path, d: (pf, pl), dname: comp, c: (sf, line), conf: "exact", note: String::new() });
            }
        }
        // client function -> endpoint, endpoint -> handler
        for e in &eps {
            if let Some(h) = e.handler {
                let hn = cx.qname(h);
                les.push(Le { kind: "endpoint_handler", s: (e.fid, e.line), sname: e.key.clone(), d: h, dname: hn, c: (e.fid, e.line), conf: "exact", note: String::new() });
            }
        }
        let client_nodes: HashSet<Node> = clients.iter().map(|c| c.node).collect();
        for c in &clients {
            if let Some((e, conf)) = match_endpoint(&eps, &by_key, &c.method, &c.norm) {
                les.push(Le { kind: "client_endpoint", s: c.node, sname: c.qname.clone(), d: (e.fid, e.line), dname: e.key.clone(), c: (c.node.0, c.aline), conf, note: String::new() });
            }
        }
        // call-graph derived: component -> client fn, page -> component (TypeScript), handler -> service
        let handlers: HashSet<Node> = eps.iter().filter_map(|e| e.handler).collect();
        {
            // a few changed files: only the edges from or into them are read (all 500,000 edges of a big repo took
            // 200 ms per edit), and the caller count of a target is asked for when it decides an edge
            const EDGE_COLS: &str = "fid, caller_line, cfid, callee_line, line, conf, kind FROM call_edges WHERE kind IN ('call','new','jsx') AND caller_line>0";
            let partial = !full && !dirty_fids.is_empty() && dirty_fids.len() <= 2000;
            let mut raw: Vec<(i64, i64, i64, i64, i64, String, String)> = vec![];
            {
                let ids = dirty_fids.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(",");
                let sql = if partial {
                    format!("SELECT {EDGE_COLS} AND fid IN ({ids}) UNION ALL SELECT {EDGE_COLS} AND cfid IN ({ids}) AND fid NOT IN ({ids})")
                } else {
                    format!("SELECT {EDGE_COLS}")
                };
                let mut st = tx.prepare(&sql)?;
                let mut rows = st.query([])?;
                while let Some(r) = rows.next()? {
                    raw.push((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?));
                }
            }
            let mut fan: HashMap<Node, usize> = HashMap::new();
            if partial {
                let mut st = tx.prepare_cached("SELECT count(DISTINCT fid) FROM call_edges WHERE cfid=? AND callee_line=? AND kind IN ('call','new','jsx') AND caller_line>0")?;
                for t in &raw {
                    if let std::collections::hash_map::Entry::Vacant(v) = fan.entry((t.2, t.3)) {
                        v.insert(st.query_row([t.2, t.3], |r| r.get::<_, i64>(0))? as usize);
                    }
                }
            } else {
                let mut by: HashMap<Node, HashSet<i64>> = HashMap::new();
                for t in &raw {
                    by.entry((t.2, t.3)).or_default().insert(t.0);
                }
                fan = by.into_iter().map(|(k, v)| (k, v.len())).collect();
            }
            for (fid, cl, cfid, cll, line, conf, kind) in raw {
                let src = (fid, cl);
                let dst = (cfid, cll);
                if !dirty_fids.is_empty() && !full && !dirty_fids.contains(&fid) && !dirty_fids.contains(&cfid) {
                    continue;
                }
                let sp = cx.path.get(&fid).cloned().unwrap_or_default();
                let dp = cx.path.get(&cfid).cloned().unwrap_or_default();
                let cname: &'static str = conf_name(conf_rank(&conf));
                if is_ts(&sp) && is_ts(&dp) {
                    if client_nodes.contains(&dst) {
                        let (sn, dn) = (cx.qname(src), cx.qname(dst));
                        les.push(Le { kind: "component_client", s: src, sname: sn, d: dst, dname: dn, c: (fid, line), conf: cname, note: String::new() });
                    } else if fid != cfid && fan.get(&dst).copied().unwrap_or(0) <= SHARED_CALLERS {
                        let (sn, dn) = (cx.qname(src), cx.qname(dst));
                        les.push(Le { kind: "page_component", s: src, sname: sn, d: dst, dname: dn, c: (fid, line), conf: cname, note: if kind == "jsx" { "jsx".into() } else { String::new() } });
                    }
                } else if handlers.contains(&src) && kind != "jsx" && conf != "name" {
                    let (sn, dn) = (cx.qname(src), cx.qname(dst));
                    les.push(Le { kind: "handler_service", s: src, sname: sn, d: dst, dname: dn, c: (fid, line), conf: cname, note: String::new() });
                }
            }
        }
        drop(s_edges);
        // write layer_edges
        let s_write = crate::par::span("trace:write");
        let mut old_service: HashSet<ServiceRow> = HashSet::new();
        if full {
            tx.execute_batch("DELETE FROM layer_edges; DELETE FROM trace_paths; DELETE FROM trace_keys; DELETE FROM trace_deps; DELETE FROM state_flow;")?;
        } else {
            old_service = service_rows(&tx)?;
            tx.execute("DELETE FROM layer_edges WHERE kind='service_table'", [])?;
            let mut d = tx.prepare("DELETE FROM layer_edges WHERE kind<>'service_table' AND (sfid=? OR dfid=?)")?;
            for f in &dirty_fids {
                d.execute([f, f])?;
            }
        }
        {
            let mut ins = tx.prepare("INSERT INTO layer_edges VALUES(?,?,?,?,?,?,?,?,?,?,?)")?;
            for e in &les {
                if !full && !dirty_fids.contains(&e.s.0) && !dirty_fids.contains(&e.d.0) {
                    continue;
                }
                ins.execute(params![e.kind, e.s.0, e.s.1, e.sname, e.d.0, e.d.1, e.dname, e.c.0, e.c.1, e.conf, e.note])?;
            }
        }
        // service -> table (one row per member, table, read/write)
        tx.execute(
            "INSERT INTO layer_edges SELECT 'service_table', f.rowid, d.sline, d.symbol, COALESCE((SELECT e.rowid FROM files e JOIN entities n ON n.file=e.path WHERE n.tbl=d.tbl AND n.kind='entity' LIMIT 1), 0),
               COALESCE((SELECT n.line FROM entities n WHERE n.tbl=d.tbl AND n.kind='entity' LIMIT 1), 0), d.tbl, f.rowid, MIN(d.line), d.conf, d.rw || ' ' || d.via
             FROM data_access d JOIN files f ON f.path=d.file GROUP BY f.rowid, d.sline, d.tbl, d.rw, d.via",
            [],
        )?;

        drop(s_write);
        let _s_rest = crate::par::span("trace:paths");
        // files whose service -> table edges changed (a table appeared, an entity mapping moved, a member gained or lost
        // data access): the traces through them are stale even though the file itself was not edited
        if !full {
            let new_service = service_rows(&tx)?;
            for x in old_service.symmetric_difference(&new_service) {
                dirty_fids.extend([x.0, x.3, x.6].into_iter().filter(|f| *f != 0));
            }
            // callers of a changed file: their call edges may have been added or dropped
            if !dirty_fids.is_empty() {
                let ids = dirty_fids.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(",");
                let mut st = tx.prepare(&format!("SELECT DISTINCT fid FROM call_edges WHERE cfid IN ({ids})"))?;
                let callers: Vec<i64> = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
                dirty_fids.extend(callers);
            }
        }

        // ───── trace_paths ─────
        // desired keys
        struct Want {
            kind: &'static str,
            key: String,
            fid: i64,
            line: i64,
            ep: Option<usize>,
            route: Option<(String, String, String)>, // path, component, page file
        }
        let mut want: Vec<Want> = vec![];
        for (i, e) in eps.iter().enumerate() {
            want.push(Want { kind: "endpoint", key: e.key.clone(), fid: e.fid, line: e.line, ep: Some(i), route: None });
        }
        {
            let mut st = tx.prepare("SELECT file, line, path, component, page_file FROM routes WHERE page_file<>'' AND redirect='' ORDER BY file, line")?;
            let rows: Vec<(String, i64, String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect::<Result<_, _>>()?;
            for (f, line, path, comp, page) in rows {
                if let Some(&fid) = cx.fid.get(&f) {
                    want.push(Want { kind: "route", key: path.clone(), fid, line, ep: None, route: Some((path, comp, page)) });
                }
            }
        }
        // existing keys
        let mut have: HashMap<(String, String, i64, i64), i64> = HashMap::new();
        {
            let mut st = tx.prepare("SELECT id, kind, key, fid, line FROM trace_keys")?;
            for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)))? {
                let (id, k, key, f, l) = r?;
                have.insert((k, key, f, l), id);
            }
        }
        let want_set: HashSet<(String, String, i64, i64)> = want.iter().map(|w| (w.kind.to_string(), w.key.clone(), w.fid, w.line)).collect();
        let mut drop_ids: HashSet<i64> = have.iter().filter(|(k, _)| !want_set.contains(*k)).map(|(_, id)| *id).collect();
        let mut rebuild: HashSet<(String, String, i64, i64)> = HashSet::new();
        for w in &want {
            let k = (w.kind.to_string(), w.key.clone(), w.fid, w.line);
            if full || !have.contains_key(&k) {
                rebuild.insert(k);
            }
        }
        if !full && !dirty_fids.is_empty() {
            let mut st = tx.prepare("SELECT DISTINCT tid FROM trace_deps WHERE fid=?")?;
            let mut affected: HashSet<i64> = HashSet::new();
            for f in &dirty_fids {
                for t in st.query_map([f], |r| r.get::<_, i64>(0))? {
                    affected.insert(t?);
                }
            }
            for (k, id) in &have {
                if affected.contains(id) || dirty_fids.contains(&k.2) {
                    if want_set.contains(k) {
                        rebuild.insert(k.clone());
                    }
                }
            }
            // route traces point at endpoint keys: when an endpoint key disappeared, the routes reaching it refresh
            let key_gone = have.keys().any(|k| k.0 == "endpoint" && !want_set.contains(k));
            if key_gone {
                let stale: Vec<i64> = {
                    let mut st = tx.prepare(
                        "SELECT DISTINCT p.tid FROM trace_paths p WHERE p.layer='endpoint' AND p.tbl<>'' AND p.tid IN (SELECT id FROM trace_keys WHERE kind='route')
                         AND NOT EXISTS (SELECT 1 FROM trace_keys k WHERE k.kind='endpoint' AND k.key=p.tbl)",
                    )?;
                    let r = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
                    r
                };
                for (k, id) in &have {
                    if k.0 == "route" && stale.contains(id) && want_set.contains(k) {
                        rebuild.insert(k.clone());
                    }
                }
            }
        }
        for k in &rebuild {
            if let Some(id) = have.get(k) {
                drop_ids.insert(*id);
            }
        }
        {
            let mut d1 = tx.prepare("DELETE FROM trace_paths WHERE tid=?")?;
            let mut d2 = tx.prepare("DELETE FROM trace_deps WHERE tid=?")?;
            let mut d3 = tx.prepare("DELETE FROM trace_keys WHERE id=?")?;
            let mut d4 = tx.prepare("DELETE FROM state_flow WHERE tid=?")?;
            for id in &drop_ids {
                d4.execute([id])?;
                d1.execute([id])?;
                d2.execute([id])?;
                d3.execute([id])?;
            }
        }
        // data access per node, fan-in per node
        let mut da: HashMap<Node, Vec<Da>> = HashMap::new();
        // no trace to rebuild (an edit that reaches no endpoint or route): the repo-wide tables below are not read
        if !rebuild.is_empty() {
            let mut st = tx.prepare("SELECT f.rowid, d.sline, d.tbl, d.rw, d.via, d.conf, d.line, d.entity FROM data_access d JOIN files f ON f.path=d.file ORDER BY d.rw DESC, d.tbl")?;
            for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?)))? {
                let (fid, sl, tbl, rw, via, conf, line, entity) = r?;
                da.entry((fid, sl)).or_default().push(Da { tbl, rw, via, conf: conf_rank(&conf), line, entity });
            }
        }
        let mut fanin: HashMap<Node, i64> = HashMap::new();
        if !rebuild.is_empty() {
            let mut st = tx.prepare("SELECT f.rowid, s.line, s.files FROM sym_fanin s JOIN files f ON f.path=s.file")?;
            for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))? {
                let (f, l, n) = r?;
                fanin.insert((f, l), n);
            }
        }
        let mut adj = Adj::load(&tx, full || rebuild.len() > 200)?;
        // endpoint traces first (route traces point at their keys)
        let mut next_id: i64 = tx.query_row("SELECT COALESCE(MAX(id),0)+1 FROM trace_keys", [], |r| r.get(0))?;
        let mut ins_key = tx.prepare("INSERT INTO trace_keys VALUES(?,?,?,?,?,?)")?;
        let mut ins_path = tx.prepare("INSERT INTO trace_paths VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")?;
        let mut ins_dep = tx.prepare("INSERT OR IGNORE INTO trace_deps VALUES(?,?)")?;
        let mut ins_sf = tx.prepare("INSERT INTO state_flow VALUES(?,?,?,?,?,?,?,?,?,?,?)")?;
        // lifecycle-state literals per member: (fid, member line) -> (op, tbl, col, val, from, literal line)
        let mut states: HashMap<Node, Vec<(String, String, String, String, String, i64)>> = HashMap::new();
        {
            let mut st = tx.prepare("SELECT f.rowid, s.sline, s.op, s.tbl, s.col, s.val, s.from_vals, s.line FROM state_refs s JOIN files f ON f.path=s.file")?;
            for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, String>(6)?, r.get::<_, i64>(7)?)))? {
                let (f, sl, op, tbl, col, val, from, line) = r?;
                states.entry((f, sl)).or_default().push((op, tbl, col, val, from, line));
            }
        }
        for w in want.iter().filter(|w| w.kind == "endpoint") {
            let k = (w.kind.to_string(), w.key.clone(), w.fid, w.line);
            if !rebuild.contains(&k) {
                continue;
            }
            let e = &eps[w.ep.unwrap_or(0)];
            let tid = next_id;
            next_id += 1;
            let mut deps: HashSet<i64> = HashSet::from([e.fid]);
            let mut reach = 0usize;
            let mut paths: Vec<Vec<(String, Node, Node, u8, Option<(String, String, String)>)>> = vec![];
            if let Some(h) = e.handler {
                // BFS from the handler
                let mut nodes: Vec<(Node, Option<usize>, usize, i64, u8)> = vec![(h, None, 0, h.1, 0)];
                let mut seen: HashSet<Node> = HashSet::from([h]);
                let mut q: VecDeque<usize> = VecDeque::from([0]);
                while let Some(i) = q.pop_front() {
                    let (n, _, depth, _, cr) = nodes[i];
                    if depth >= MAX_DEPTH {
                        continue;
                    }
                    let es: Vec<Edge> = adj.edges(n).clone();
                    for ed in es {
                        if nodes.len() >= MAX_NODES {
                            break;
                        }
                        if ed.conf > 1 || !seen.insert(ed.to) {
                            continue;
                        }
                        nodes.push((ed.to, Some(i), depth + 1, ed.site, cr.max(ed.conf)));
                        q.push_back(nodes.len() - 1);
                    }
                }
                reach = nodes.len();
                // the lifecycle-state literals (`status = 'x'` set / tested) of every member reached
                {
                    let mut seen_sf: HashSet<(String, String, String, String, i64, i64)> = HashSet::new();
                    for nd in &nodes {
                        let shared = fanin.get(&nd.0).copied().unwrap_or(0) > SHARED_BACKEND && nd.0 != h;
                        for (op, tbl, col, val, from, line) in states.get(&nd.0).into_iter().flatten() {
                            if seen_sf.insert((op.clone(), tbl.clone(), col.clone(), val.clone(), nd.0 .0, *line)) {
                                ins_sf.execute(params![tid, op, tbl, col, val, from, nd.0 .0, line, nd.0 .1, nd.2 as i64, shared as i64])?;
                            }
                        }
                    }
                }
                // every file the search walked through: a data access appearing in any of them changes the trace
                deps.extend(nodes.iter().map(|n| n.0 .0));
                // leaves: (shared, write first, depth, node idx, data access)
                let mut leaves: Vec<(bool, bool, usize, usize, &Da)> = vec![];
                for (i, nd) in nodes.iter().enumerate() {
                    if let Some(v) = da.get(&nd.0) {
                        let shared = fanin.get(&nd.0).copied().unwrap_or(0) > SHARED_BACKEND && i != 0;
                        for d in v {
                            leaves.push((shared, d.rw != "w", nd.2, i, d));
                        }
                    }
                }
                leaves.sort_by(|a, b| (a.0, a.1, a.2, &a.4.tbl, a.3).cmp(&(b.0, b.1, b.2, &b.4.tbl, b.3)));
                let mut shared_n = 0;
                let mut kept = 0;
                for (shared, _, _, i, d) in leaves {
                    if kept >= MAX_LEAVES {
                        break;
                    }
                    if shared {
                        shared_n += 1;
                        if shared_n > 6 {
                            continue;
                        }
                    }
                    kept += 1;
                    // chain root..i
                    let mut chain = vec![];
                    let mut cur = Some(i);
                    while let Some(c) = cur {
                        chain.push(c);
                        cur = nodes[c].1;
                    }
                    chain.reverse();
                    let mut hops: Vec<(String, Node, Node, u8, Option<(String, String, String)>)> = vec![];
                    hops.push(("endpoint".into(), (e.fid, e.line), (e.fid, e.line), 0, None));
                    for (k2, &c) in chain.iter().enumerate() {
                        let (n, _, _, site, cr) = nodes[c];
                        let parent = nodes[c].1.map(|p| nodes[p].0);
                        let callsite = parent.map(|p| (p.0, site)).unwrap_or((n.0, n.1));
                        hops.push((if k2 == 0 { "handler" } else { "call" }.into(), n, callsite, cr, None));
                        deps.insert(n.0);
                    }
                    let entity = cx.ent_loc.get(&d.tbl).copied().unwrap_or((nodes[i].0 .0, d.line));
                    deps.insert(entity.0);
                    hops.push(("table".into(), entity, (nodes[i].0 .0, d.line), d.conf, Some((d.tbl.clone(), d.rw.clone(), d.via.clone()))));
                    let _ = &d.entity;
                    paths.push(hops);
                }
                if paths.is_empty() {
                    paths.push(vec![("endpoint".into(), (e.fid, e.line), (e.fid, e.line), 0, None), ("handler".into(), h, h, 0, None)]);
                }
            } else {
                paths.push(vec![("endpoint".into(), (e.fid, e.line), (e.fid, e.line), 0, None)]);
            }
            ins_key.execute(params![tid, "endpoint", e.key, e.fid, e.line, reach as i64])?;
            for (pid, hops) in paths.iter().enumerate() {
                for (hop, (layer, n, c, cr, t)) in hops.iter().enumerate() {
                    let (tbl, rw, via) = t.clone().unwrap_or_default();
                    ins_path.execute(params![tid, pid as i64, hop as i64, layer, n.0, n.1, c.0, c.1, conf_name(*cr), tbl, rw, via])?;
                }
            }
            for f in deps {
                ins_dep.execute(params![tid, f])?;
            }
        }
        // route traces: BFS over the TypeScript side of layer_edges
        let mut ui_adj: HashMap<Node, Vec<(Node, Node, u8)>> = HashMap::new(); // from -> (to, call site, conf)
        let mut client_ep: HashMap<Node, Vec<(String, Node)>> = HashMap::new();
        {
            let mut st = tx.prepare("SELECT kind, sfid, sline, dfid, dline, dname, cfid, cline, conf FROM layer_edges WHERE kind IN ('page_component','component_client','client_endpoint')")?;
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                let (k, sf, sl, df, dl, dn, cf, cl, conf): (String, i64, i64, i64, i64, String, i64, i64, String) =
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?);
                if k == "client_endpoint" {
                    client_ep.entry((sf, sl)).or_default().push((dn, (df, dl)));
                } else {
                    ui_adj.entry((sf, sl)).or_default().push(((df, dl), (cf, cl), conf_rank(&conf)));
                }
            }
        }
        for w in want.iter().filter(|w| w.kind == "route") {
            let k = (w.kind.to_string(), w.key.clone(), w.fid, w.line);
            if !rebuild.contains(&k) {
                continue;
            }
            let Some((path, comp, page)) = &w.route else { continue };
            let Some(&pf) = cx.fid.get(page) else { continue };
            let tid = next_id;
            next_id += 1;
            let page_line = cx.members_of(pf).iter().find(|m| m.qname == *comp || m.qname.ends_with(&format!(".{comp}"))).map(|m| m.line).unwrap_or(1);
            // roots: every member of the page file; BFS through the UI edges
            let roots: Vec<Node> = cx.members_of(pf).iter().filter(|m| matches!(m.kind.as_str(), "method" | "function" | "component" | "const")).map(|m| (pf, m.line)).collect();
            let mut nodes: Vec<(Node, Option<usize>, usize, Node, u8)> = vec![]; // node, parent, depth, call site, conf
            let mut seen: HashSet<Node> = HashSet::new();
            let mut q: VecDeque<usize> = VecDeque::new();
            for r in roots {
                if seen.insert(r) {
                    nodes.push((r, None, 0, (0, 0), 0));
                    q.push_back(nodes.len() - 1);
                }
            }
            while let Some(i) = q.pop_front() {
                let (n, _, depth, _, cr) = nodes[i];
                if depth >= 4 || nodes.len() > 1500 {
                    continue;
                }
                for (to, site, c) in ui_adj.get(&n).cloned().unwrap_or_default() {
                    if c > 1 || !seen.insert(to) {
                        continue;
                    }
                    nodes.push((to, Some(i), depth + 1, site, cr.max(c)));
                    q.push_back(nodes.len() - 1);
                }
            }
            let mut deps: HashSet<i64> = HashSet::from([w.fid, pf]);
            deps.extend(nodes.iter().map(|n| n.0 .0));
            let mut chains: Vec<Vec<(String, Node, Node, u8, String)>> = vec![];
            let mut seen_ep: HashSet<String> = HashSet::new();
            for (i, nd) in nodes.iter().enumerate() {
                let Some(eps_) = client_ep.get(&nd.0) else { continue };
                for (ekey, enode) in eps_ {
                    if chains.len() >= MAX_CHAINS || !seen_ep.insert(ekey.clone()) {
                        continue;
                    }
                    let mut chain = vec![];
                    let mut cur = Some(i);
                    while let Some(c) = cur {
                        chain.push(c);
                        cur = nodes[c].1;
                    }
                    chain.reverse();
                    let mut hops: Vec<(String, Node, Node, u8, String)> = vec![("route".into(), (w.fid, w.line), (w.fid, w.line), 0, path.clone())];
                    hops.push(("page".into(), (pf, page_line), (pf, page_line), 0, String::new()));
                    for (k2, &c) in chain.iter().enumerate() {
                        let (n, _, _, site, cr) = nodes[c];
                        let last = k2 == chain.len() - 1;
                        let layer = if last { "client" } else if k2 == 0 { "member" } else { "component" };
                        if k2 == 0 && n == (pf, page_line) {
                            continue;
                        }
                        hops.push((layer.into(), n, site, cr, String::new()));
                        deps.insert(n.0);
                    }
                    hops.push(("endpoint".into(), *enode, *enode, 0, ekey.clone()));
                    deps.insert(enode.0);
                    chains.push(hops);
                }
            }
            ins_key.execute(params![tid, "route", path, w.fid, w.line, chains.len() as i64])?;
            for (pid, hops) in chains.iter().enumerate() {
                for (hop, (layer, n, c, cr, key)) in hops.iter().enumerate() {
                    let tbl = if layer == "endpoint" || layer == "route" { key.clone() } else { String::new() };
                    ins_path.execute(params![tid, pid as i64, hop as i64, layer, n.0, n.1, c.0, c.1, conf_name(*cr), tbl, "", ""])?;
                }
            }
            for f in deps {
                ins_dep.execute(params![tid, f])?;
            }
        }
        let _ = (&dirty_fids, MAX_CHAINS);
        // keep the layer_edges for the client side of fresh routes consistent
        drop(ins_key);
        drop(ins_path);
        drop(ins_dep);
    }
    tx.execute("DELETE FROM dm_dirty", [])?;
    tx.execute("INSERT OR REPLACE INTO meta VALUES('trace_built', ?)", [crate::index::chrono_now()])?;
    tx.commit()?;
    Ok(())
}
