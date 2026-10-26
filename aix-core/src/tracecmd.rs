//! `trace`, `explain` and `table`: answers read from `layer_edges`, `trace_paths`, `data_access`, `entity_columns`,
//! `migrations`, `fks` and the older fact tables. Nothing is computed from source and no model is called.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use rusqlite::{params, Connection};

use crate::expert::{Cite, Resp};
use crate::index::Index;
use crate::query::{self, base, oneline, one, rows, Out};

// ───────────────────────────── shared helpers ─────────────────────────────

fn cite(file: &str, line: i64) -> Cite {
    Cite { file: file.to_string(), line, end: line }
}

fn conf_static(c: &str) -> &'static str {
    match c {
        "exact" => "exact",
        "resolved" => "resolved",
        "heuristic" => "heuristic",
        _ => "name",
    }
}

/// The declaration of a member as a cite range (`line..end_line`), falling back to the single line.
fn decl_cite(c: &Connection, file: &str, line: i64) -> Cite {
    let end: i64 = c
        .prepare_cached("SELECT end_line FROM members WHERE file=? AND line=? ORDER BY (kind='field') LIMIT 1")
        .and_then(|mut st| st.query_row(params![file, line], |r| r.get(0)))
        .unwrap_or(line);
    Cite { file: file.to_string(), line, end: end.max(line) }
}

fn entity_cite(c: &Connection, tbl: &str) -> Option<Cite> {
    c.prepare_cached("SELECT file, line, end_line FROM entities WHERE tbl=? AND kind='entity' ORDER BY file LIMIT 1")
        .and_then(|mut st| st.query_row([tbl], |r| Ok(Cite { file: r.get(0)?, line: r.get(1)?, end: r.get(2)? })))
        .ok()
}

impl Resp {
    fn ans_cites(&mut self, kind: &'static str, text: String, cites: Vec<Cite>, conf: &'static str) {
        self.answers.push(crate::expert::Answer { kind, text: oneline(&text), cites, conf });
    }
}

fn path_of(c: &Connection, fid: i64) -> String {
    c.query_row("SELECT path FROM files WHERE rowid=?", [fid], |r| r.get(0)).unwrap_or_default()
}

fn member_name(c: &Connection, file: &str, line: i64) -> String {
    c.prepare_cached("SELECT qname FROM members WHERE file=? AND line=? ORDER BY (kind='field') LIMIT 1")
        .and_then(|mut st| st.query_row(params![file, line], |r| r.get::<_, String>(0)))
        .unwrap_or_default()
}

fn endpoint_roles(c: &Connection, file: &str, line: i64) -> String {
    c.prepare_cached("SELECT roles FROM endpoints WHERE file=? AND line=? LIMIT 1")
        .and_then(|mut st| st.query_row(params![file, line], |r| r.get::<_, String>(0)))
        .unwrap_or_default()
}

/// Endpoint roles: empty means no auth was declared on the handler, NOT "any signed-in user".
fn roles_txt(r: &str) -> String {
    query::ep_roles_label(r)
}

/// Route / menu roles: empty means no role restriction is declared there.
fn rroles_txt(r: &str) -> String {
    if r.is_empty() {
        "no role restriction declared".to_string()
    } else {
        query::short_roles(r)
    }
}

#[derive(Clone, Debug, Default)]
struct Hop {
    layer: String,
    file: String,
    line: i64,
    cfile: String,
    cline: i64,
    conf: String,
    tbl: String,
    rw: String,
    via: String,
    name: String,
}

fn load_paths(c: &Connection, tid: i64) -> BTreeMap<i64, Vec<Hop>> {
    let mut out: BTreeMap<i64, Vec<Hop>> = BTreeMap::new();
    let Ok(mut st) = c.prepare_cached(
        "SELECT p.pid, p.layer, f.path, p.line, COALESCE(cf.path,''), p.cline, p.conf, p.tbl, p.rw, p.via,
           COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=p.line ORDER BY (m.kind='field') LIMIT 1), '')
         FROM trace_paths p JOIN files f ON f.rowid=p.fid LEFT JOIN files cf ON cf.rowid=p.cfid WHERE p.tid=? AND aix_drop(f.path)=0 AND aix_conf(p.conf)=1 ORDER BY p.pid, p.hop",
    ) else {
        return out;
    };
    let it = st.query_map([tid], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            Hop { layer: r.get(1)?, file: r.get(2)?, line: r.get(3)?, cfile: r.get(4)?, cline: r.get(5)?, conf: r.get(6)?, tbl: r.get(7)?, rw: r.get(8)?, via: r.get(9)?, name: r.get(10)? },
        ))
    });
    if let Ok(it) = it {
        for (pid, h) in it.flatten() {
            out.entry(pid).or_default().push(h);
        }
    }
    out
}

/// (tid, key, file, line, reach) of trace keys of a kind.
fn find_keys(c: &Connection, kind: &str, key: &str) -> Vec<(i64, String, String, i64, i64)> {
    let mut v = vec![];
    if let Ok(mut st) = c.prepare_cached("SELECT k.id, k.key, f.path, k.line, k.reach FROM trace_keys k JOIN files f ON f.rowid=k.fid WHERE k.kind=? AND k.key=? ORDER BY f.path") {
        if let Ok(it) = st.query_map(params![kind, key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))) {
            v.extend(it.flatten());
        }
    }
    v
}

fn entity_of_table(c: &Connection, tbl: &str) -> Option<(String, String, i64, String)> {
    c.prepare_cached("SELECT name, file, line, orm FROM entities WHERE tbl=? AND kind='entity' ORDER BY file LIMIT 1")
        .and_then(|mut st| st.query_row([tbl], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))))
        .ok()
}

// ───────────────────────────── trace ─────────────────────────────

#[allow(dead_code)]
struct TraceOpts {
    up: bool,
    sites: bool,
    body: bool,
    depth: usize,
    words: Vec<String>,
    target: String,
    all: bool,
    /// explain: print one path per written table, at most this many (0 = the first `limit` paths)
    tables: usize,
}

fn parse_trace(arg: &str) -> TraceOpts {
    let mut up = false;
    let mut sites = false;
    let mut body = false;
    let mut all = false;
    let mut depth = 6usize;
    let mut rest: Vec<String> = vec![];
    let toks = crate::query::shell_split(arg);
    let mut i = 0;
    while i < toks.len() {
        match toks[i].as_str() {
            "--up" | "-u" | "up" if i == 0 && toks.len() > 1 && toks[i] == "up" => up = true,
            "--up" | "-u" => up = true,
            "--body" => body = true,
            "--all" => all = true,
            "--sites" => {
                up = true;
                sites = true;
            }
            "--depth" | "-d" => {
                if let Some(n) = toks.get(i + 1).and_then(|x| x.parse::<usize>().ok()) {
                    depth = n.clamp(1, 6);
                }
                i += 1;
            }
            t => rest.push(t.to_string()),
        }
        i += 1;
    }
    TraceOpts { up, sites, body, depth, words: vec![], target: rest.join(" "), all, tables: 0 }
}

static METHOD_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)$").unwrap());

enum Target {
    Table(String),
    Endpoint(Vec<(i64, String, String, i64, i64)>),
    Route(String),
    Symbol(Vec<(String, i64, i64, String, String, String)>),
    None,
}

fn resolve_target(ix: &Index, t: &str) -> Target {
    let c = &ix.conn;
    let a = t.trim().trim_matches('"');
    if let Some(tb) = a.strip_prefix("table:").or_else(|| a.strip_prefix("tbl:")) {
        return Target::Table(tb.trim().to_lowercase());
    }
    if let Some(m) = METHOD_RE.captures(a) {
        let method = m[1].to_uppercase();
        let norm = aix_extract::norm_path(&m[2]);
        if let Some(e) = ep_lookup(ix, &method, &norm) {
            return Target::Endpoint(e);
        }
        return Target::None;
    }
    if a.starts_with('/') {
        let p = format!("/{}", a.trim_matches('/').split('?').next().unwrap_or(""));
        let p = if p == "/" { "/".to_string() } else { p };
        if !rows(c, "SELECT 1 FROM routes WHERE path=? LIMIT 1", &[&p]).is_empty() {
            return Target::Route(p);
        }
        let norm = aix_extract::norm_path(a);
        if let Some(e) = ep_lookup(ix, "", &norm) {
            return Target::Endpoint(e);
        }
        let r = query::resolve_route(ix, a);
        if let Some(r) = r.first() {
            return Target::Route(r["path"].clone());
        }
        return Target::None;
    }
    let defs = crate::expert::find_defs_pub(c, a);
    let r = query::resolve_route(ix, a);
    let exact_route = r.first().is_some_and(|x| route_exact(c, a, &x["path"]));
    if exact_route {
        return Target::Route(r[0]["path"].clone());
    }
    // a bare lowercase word that is only a field name somewhere is not what `trace users` means when a table has that name
    let fields_only = defs.iter().all(|d| d.5 == "field");
    if !defs.is_empty() && !(fields_only && !a.contains(['.', ' ']) && resolve_table(ix, a).is_ok()) {
        return Target::Symbol(defs);
    }
    // a table of that name beats a fuzzy menu-label match (`trace users` is the users table, not /directory)
    if !a.contains(' ') && resolve_table(ix, a).is_ok() {
        return Target::Table(a.to_lowercase());
    }
    if let Some(r) = r.first() {
        return Target::Route(r["path"].clone());
    }
    Target::None
}

/// Does `arg` name the route `path` itself (its path, menu label, component or page file), as opposed to a fuzzy match?
fn route_exact(c: &Connection, arg: &str, path: &str) -> bool {
    let a = arg.trim().trim_matches('"');
    if a.starts_with('/') {
        return format!("/{}", a.trim_matches('/').split('?').next().unwrap_or("")) == path;
    }
    let bare = path.trim_matches('/');
    a.eq_ignore_ascii_case(bare)
        || !rows(c, "SELECT 1 FROM routes WHERE path=? AND (component=? OR page_file=? OR page_file LIKE ? ESCAPE '\\') LIMIT 1", &[&path, &a, &a, &format!("%/{}", a.replace('%', "\\%").replace('_', "\\_"))]).is_empty()
        || !rows(c, "SELECT 1 FROM menu WHERE (href=?1 OR href LIKE ?1||'?%') AND label=?2 COLLATE NOCASE LIMIT 1", &[&path, &a]).is_empty()
}

/// Note for a route reached by a fuzzy match.
fn fuzzy_route_note(c: &Connection, arg: &str, path: &str) -> Option<String> {
    let a = arg.trim().trim_matches('"');
    if route_exact(c, a, path) {
        return None;
    }
    Some(format!("resolved '{a}' as route {path} (fuzzy match on a menu label, path prefix or keyword; pass the exact route or name to be sure)"))
}

/// Endpoint trace keys for (method?, norm): exact, with the /api base, or a wildcard segment match.
fn ep_lookup(ix: &Index, method: &str, norm: &str) -> Option<Vec<(i64, String, String, i64, i64)>> {
    let c = &ix.conn;
    let mut keys: Vec<String> = vec![];
    for n in [norm.to_string(), format!("/api{norm}")] {
        if method.is_empty() {
            for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
                keys.push(format!("{m} {n}"));
            }
        } else {
            keys.push(format!("{method} {n}"));
        }
    }
    let mut out = vec![];
    for k in &keys {
        out.extend(find_keys(c, "endpoint", k));
    }
    if out.is_empty() {
        if let Some(e) = query::match_endpoint(ix, method, norm) {
            let line: i64 = e[1].parse().unwrap_or(0);
            let r = rows(c, "SELECT k.id, k.key, f.path, k.line, k.reach FROM trace_keys k JOIN files f ON f.rowid=k.fid WHERE k.kind='endpoint' AND f.path=? AND k.line=?", &[&e[0], &line]);
            for x in r {
                out.push((x[0].parse().unwrap_or(0), x[1].clone(), x[2].clone(), x[3].parse().unwrap_or(0), x[4].parse().unwrap_or(0)));
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Request body of an endpoint: the handler's parameter types that are classes/records of the project, with their fields.
fn trace_body(ix: &Index, eps: &[(i64, String, String, i64, i64)], r: &mut Resp) {
    let c = &ix.conn;
    for (_, key, file, line, _) in eps.iter().take(2) {
        let sig = rows(c, "SELECT sig FROM members WHERE file=? AND line=? AND kind='method' LIMIT 1", &[file, line]).first().map(|x| x[0].clone()).unwrap_or_default();
        let params = sig.split_once('(').map(|x| x.1.trim_end_matches(')').to_string()).unwrap_or_default();
        r.head.push(format!("== request body of {key} [{file}:{line}]: handler params ({params})"));
        let mut found = false;
        for p in params.split(',') {
            let ty = p.split_whitespace().next().unwrap_or("").split('<').next().unwrap_or("").to_string();
            if ty.is_empty() {
                continue;
            }
            let defs = rows(c, "SELECT file, line, end_line, qname FROM members WHERE name=? AND kind IN ('class','record','interface') ORDER BY (file=?) DESC LIMIT 1", &[&ty, file]);
            let Some(d) = defs.first() else { continue };
            let fields: Vec<String> = rows(c, "SELECT name, ret FROM members WHERE file=? AND kind='field' AND line>=? AND line<=? ORDER BY line", &[&d[0], &d[1], &d[2]])
                .into_iter().map(|f| format!("{} {}", f[0], f[1])).collect();
            found = true;
            r.ans_cites("body", format!("body {} {{{}}}  {}:{}", d[3], fields.join(", "), d[0], d[1]), vec![Cite { file: d[0].clone(), line: d[1].parse().unwrap_or(0), end: d[2].parse().unwrap_or(0) }], "exact");
        }
        if !found {
            r.foot.push("no project-defined body type among the handler parameters (path/query parameters only, or a library type)".into());
        }
    }
}

fn did_you_mean_trace(ix: &Index, arg: &str, r: &mut Resp) {
    r.head.push(format!("== trace {}: none (no route, endpoint, table or symbol of that name in the index)", arg.trim()));
    let sug = query::did_you_mean(ix, arg, 5);
    if !sug.is_empty() {
        r.foot.push("did you mean:".to_string());
        for (_, name, d) in sug {
            r.foot.push(format!("  {name}  {d}"));
        }
    }
    let t: Vec<Vec<String>> = rows(&ix.conn, "SELECT method, path, file, line FROM endpoints WHERE path LIKE ? ORDER BY length(path) LIMIT 3", &[&format!("%{}%", arg.trim().trim_matches('"'))]);
    for e in t {
        r.foot.push(format!("  endpoint {} {}  {}:{}", e[0], e[1], e[2], e[3]));
    }
}

pub fn trace(ix: &Index, arg: &str, out: &mut Out) {
    let o = parse_trace(arg);
    let mut r = Resp::new("trace", arg);
    match resolve_target(ix, &o.target) {
        Target::Table(t) => {
            if !o.target.trim().to_lowercase().starts_with("table:") && !o.target.trim().to_lowercase().starts_with("tbl:") {
                if let Ok(real) = resolve_table(ix, &t) {
                    if real != o.target.trim().trim_matches('"').to_lowercase() {
                        r.head.push(format!("resolved '{}' as table {real}", o.target.trim()));
                    }
                }
            }
            trace_table(ix, &t, &o, &mut r)
        }
        Target::Endpoint(e) if o.body => trace_body(ix, &e, &mut r),
        Target::Endpoint(e) => {
            if o.up {
                trace_endpoint_up(ix, &e, out.limit, o.sites, &mut r)
            } else {
                trace_endpoint_down(ix, &e, &o, out.limit, &mut r)
            }
        }
        Target::Route(p) => {
            if let Some(n) = fuzzy_route_note(&ix.conn, &o.target, &p) {
                r.head.push(n);
            }
            if o.up {
                r.head.push(format!("== trace {p}: --up starts from an endpoint, table or symbol (a route is the top of the chain); use `trace {p}` for what it reaches"));
            } else {
                trace_route(ix, &p, &[], out.limit, false, 0, false, &mut r);
            }
        }
        Target::Symbol(defs) => {
            if defs.len() > 1 && !o.target.contains('.') {
                r.head.push(format!(
                    "'{}' has {} definitions; tracing {}. Pass Class.method to pick one: {}",
                    o.target.trim(),
                    defs.len(),
                    defs.iter().find(|d| d.5 != "field").unwrap_or(&defs[0]).4,
                    defs.iter().take(8).map(|d| d.4.clone()).collect::<Vec<_>>().join(", ")
                ));
            }
            if o.up {
                trace_symbol_up(ix, &defs, out.limit, &mut r)
            } else {
                trace_symbol_down(ix, &defs, &o, out.limit, &mut r)
            }
        }
        Target::None => did_you_mean_trace(ix, &o.target, &mut r),
    }
    r.finish(out);
}

/// One printed hop line + its cites.
fn hop_text(h: &Hop, key: &str) -> String {
    let at = |f: &str, l: i64| if l > 0 { format!("{f}:{l}") } else { f.to_string() };
    match h.layer.as_str() {
        "route" => format!("route    {}  {}", if key.is_empty() { &h.tbl } else { key }, at(&h.file, h.line)),
        "endpoint" => format!("endpoint {}  {}", if h.tbl.is_empty() { key } else { &h.tbl }, at(&h.file, h.line)),
        "table" => format!("table    {} ({}) {}", h.tbl, if h.rw == "w" { "write" } else { "read" }, at(&h.file, h.line)),
        l => format!("{:<8} {}  {}", l, h.name, at(&h.file, h.line)),
    }
}

/// Paths minus the ones that only reach a table through shared auth/tenant infrastructure (the same lookups on every
/// endpoint) and minus exact repeats. The hidden auth paths come back as one summary line: the call chain they share and
/// the tables they touch.
fn clean_paths(c: &Connection, paths: BTreeMap<i64, Vec<Hop>>, all: bool) -> (BTreeMap<i64, Vec<Hop>>, Option<String>) {
    let mut kept: BTreeMap<i64, Vec<Hop>> = BTreeMap::new();
    let mut auth: Vec<Vec<Hop>> = vec![];
    let mut seen: HashSet<Vec<(String, i64, String, String)>> = HashSet::new();
    for (pid, p) in paths {
        let sig: Vec<(String, i64, String, String)> = p.iter().map(|h| (h.file.clone(), h.line, format!("{}{}", h.tbl, h.rw), h.layer.clone())).collect();
        if !seen.insert(sig) {
            continue;
        }
        let is_auth = p.last().is_some_and(|h| h.layer == "table" && infra_access(c, &h.tbl, &h.rw, &h.cfile, h.cline));
        if is_auth && !all {
            auth.push(p);
        } else {
            kept.insert(pid, p);
        }
    }
    if auth.is_empty() {
        return (kept, None);
    }
    let names = |p: &Vec<Hop>| -> Vec<String> { p.iter().filter(|h| h.layer == "call").map(|h| h.name.clone()).collect() };
    let first = names(&auth[0]);
    let mut common = first.len();
    for p in &auth[1..] {
        let n = names(p);
        common = common.min(first.iter().zip(n.iter()).take_while(|(a, b)| a == b).count());
    }
    let tabs: BTreeSet<String> = auth.iter().filter_map(|p| p.last().map(|h| format!("{} {}", h.tbl, if h.rw == "w" { "w" } else { "r" }))).collect();
    let chain = if common == 0 { first.first().cloned().unwrap_or_default() } else { first[..common].join(" -> ") };
    (kept, Some(format!("auth: {chain} ({}; hidden, {} path(s); --all)", tabs.into_iter().collect::<Vec<_>>().join(", "), auth.len())))
}

fn print_paths(ix: &Index, paths: &BTreeMap<i64, Vec<Hop>>, key: &str, base_indent: usize, max_paths: usize, depth_cap: usize, r: &mut Resp) -> usize {
    // the best `max_paths` chains (stored order: writes and non-shared code first), printed as one tree: siblings keep the
    // order of their best chain, and every hop is printed once, directly under the hop that really called it
    let group: Vec<&Vec<Hop>> = paths.values().take(max_paths).collect();
    print_tree(ix, &group, 0, key, base_indent, depth_cap, r);
    group.len()
}

/// The paths to print when the reader wants "what does it write": the best path to each distinct written table (stored order:
/// writes and non-shared code first), skipping accesses that are shared infrastructure (the auth lookups every endpoint makes),
/// at most `cap` tables; reads only fill up when fewer than two tables are written.
fn pick_table_paths(c: &Connection, paths: &[Vec<Hop>], cap: usize) -> Vec<usize> {
    let mut picked: Vec<usize> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    for pass in ["w", "r"] {
        for (i, p) in paths.iter().enumerate() {
            let Some(h) = p.last().filter(|h| h.layer == "table" && h.rw == pass) else { continue };
            if picked.len() >= cap || (pass == "r" && picked.len() >= 2) {
                break;
            }
            if infra_access(c, &h.tbl, &h.rw, &h.cfile, h.cline) || !seen.insert(h.tbl.clone()) {
                continue;
            }
            picked.push(i);
        }
    }
    picked.sort();
    if picked.is_empty() && !paths.is_empty() {
        picked.push(0);
    }
    picked
}

fn print_tree(ix: &Index, group: &[&Vec<Hop>], i: usize, key: &str, base_indent: usize, depth_cap: usize, r: &mut Resp) {
    let c = &ix.conn;
    let hop_key = |h: &Hop| (h.file.clone(), h.line, format!("{}{}", h.tbl, h.rw), h.layer.clone());
    let mut order: Vec<((String, i64, String, String), Vec<&Vec<Hop>>)> = vec![];
    for p in group {
        let Some(h) = p.get(i) else { continue };
        let k = hop_key(h);
        match order.iter_mut().find(|o| o.0 == k) {
            Some(o) => o.1.push(p),
            None => order.push((k, vec![p])),
        }
    }
    for (_, sub) in order {
        let h = &sub[0][i];
        if !(i > depth_cap + 2 && h.layer != "table") {
            let indent = " ".repeat(base_indent + 2 * i.min(10));
            let mut text = format!("{indent}{}", hop_text(h, key));
            let conf = if h.conf.is_empty() { "exact" } else { &h.conf };
            let mut cites = vec![decl_cite(c, &h.file, h.line)];
            if h.layer == "endpoint" {
                let roles = endpoint_roles(c, &h.file, h.line);
                text.push_str(&format!("  roles {}", roles_txt(&roles)));
            }
            if h.layer == "call" || h.layer == "handler" {
                if !h.cfile.is_empty() && h.layer == "call" {
                    text.push_str(&format!(" ({conf})  <- called at {}:{}", h.cfile, h.cline));
                } else {
                    text.push_str(&format!(" ({conf})"));
                }
            }
            if h.layer == "table" {
                let ent = entity_of_table(c, &h.tbl).map(|e| format!("entity {}", e.0)).unwrap_or_else(|| "no entity".into());
                text.push_str(&format!(" via {} ({conf}); {ent}; accessed at {}:{}", h.via, h.cfile, h.cline));
                if infra_access(c, &h.tbl, &h.rw, &h.cfile, h.cline) {
                    text.push_str(" (auth side effect)");
                }
                cites = vec![entity_cite(c, &h.tbl).unwrap_or_else(|| cite(&h.cfile, h.cline))];
            }
            r.ans_cites(layer_kind(&h.layer), text, cites, conf_static(conf));
        }
        print_tree(ix, &sub, i + 1, key, base_indent, depth_cap, r);
    }
}

fn layer_kind(l: &str) -> &'static str {
    match l {
        "route" => "route",
        "page" => "page",
        "member" => "member",
        "component" => "component",
        "client" => "client",
        "endpoint" => "endpoint",
        "handler" => "handler",
        "call" => "call",
        "table" => "table",
        _ => "hop",
    }
}

fn trace_endpoint_down(ix: &Index, eps: &[(i64, String, String, i64, i64)], o: &TraceOpts, limit: usize, r: &mut Resp) {
    let c = &ix.conn;
    for (tid, key, file, line, reach) in eps.iter().take(3) {
        let (paths, auth_note) = clean_paths(c, load_paths(c, *tid), o.all);
        let ntab = paths.values().filter(|p| p.last().is_some_and(|h| h.layer == "table")).count();
        let tabs: BTreeSet<String> = paths.values().filter_map(|p| p.last().filter(|h| h.layer == "table").map(|h| h.tbl.clone())).collect();
        r.head.push(format!(
            "== trace {key} [{file}:{line}]: {ntab} paths to {} tables (depth<={}, {reach} methods reached)",
            tabs.len(),
            o.depth
        ));
        if ntab == 0 {
            r.head.push("   no table access found from the handler within the index depth (the handler may delegate through an unresolved call)".to_string());
        }
        let mut hs = vec![];
        let shown = {
            let n = paths.len();
            let lim = limit.max(1);
            hs.push(n);
            if o.tables > 0 {
                let all_paths: Vec<Vec<Hop>> = paths.values().cloned().collect();
                let pick = pick_table_paths(c, &all_paths, o.tables);
                let sel: BTreeMap<i64, Vec<Hop>> = pick.iter().enumerate().map(|(k, &i)| (k as i64, all_paths[i].clone())).collect();
                print_paths(ix, &sel, key, 0, sel.len(), o.depth, r)
            } else {
                print_paths(ix, &paths, key, 0, lim, o.depth, r)
            }
        };
        if paths.len() > shown {
            r.foot.push(format!("(+{} more paths)", paths.len() - shown));
            r.truncated = true;
        }
        if let Some(a) = auth_note {
            r.ans_cites("note", a, vec![], "exact");
        }
        let pages = rows(
            c,
            "SELECT COUNT(DISTINCT e.sfid) FROM layer_edges e JOIN files f ON f.rowid=e.dfid WHERE e.kind='client_endpoint' AND f.path=? AND e.dline=?",
            &[file, line],
        );
        if let Some(p) = pages.first() {
            r.foot.push(format!("called from {} client function(s); `trace \"{key}\" --up` for the screens", p[0]));
        }
    }
}

// ───── up: endpoint -> client fns -> callers -> page -> route ─────

struct UiNode {
    file: String,
    line: i64,
    name: String,
    site: Option<(String, i64)>, // where it calls the previous (lower) node
    conf: String,
    kind: &'static str,
}

/// Reverse BFS over the UI layer edges from a client function: returns (chain bottom-up, route path) per page reached.
fn ui_up(ix: &Index, client: (String, i64), max_depth: usize) -> Vec<(Vec<UiNode>, String, String, i64)> {
    let c = &ix.conn;
    let mut out = vec![];
    let mut q: VecDeque<(Vec<UiNode>, usize)> = VecDeque::new();
    let q0 = UiNode { file: client.0.clone(), line: client.1, name: member_name(c, &client.0, client.1), site: None, conf: "exact".into(), kind: "client" };
    q.push_back((vec![q0], 0));
    let mut seen: HashSet<(String, i64)> = HashSet::from([client]);
    let mut guard = 0;
    while let Some((chain, depth)) = q.pop_front() {
        guard += 1;
        if guard > 400 {
            break;
        }
        let last = chain.last().unwrap();
        // is this node's file a routed page?
        let rt = rows(c, "SELECT sname, sfid, sline FROM layer_edges e JOIN files f ON f.rowid=e.dfid WHERE e.kind='route_page' AND f.path=? LIMIT 3", &[&last.file]);
        if depth > 0 || last.kind != "client" {
            for x in &rt {
                let route_file = path_of(c, x[1].parse().unwrap_or(0));
                out.push((chain.iter().map(|n| UiNode { file: n.file.clone(), line: n.line, name: n.name.clone(), site: n.site.clone(), conf: n.conf.clone(), kind: n.kind }).collect(), x[0].clone(), route_file, x[2].parse().unwrap_or(0)));
            }
        }
        // a routed page is the top of a chain: whatever renders it (the router, a layout) is not another screen of the feature
        if depth >= max_depth || ((depth > 0 || last.kind != "client") && !rt.is_empty()) {
            continue;
        }
        let ups = rows(
            c,
            "SELECT s.path, e.sline, e.sname, COALESCE(cf.path,''), e.cline, e.conf, e.kind FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid LEFT JOIN files cf ON cf.rowid=e.cfid
             WHERE e.kind IN ('component_client','page_component') AND e.conf<>'name' AND d.path=? AND e.dline=? ORDER BY e.conf, s.path, e.sline",
            &[&last.file, &last.line],
        );
        for u in ups {
            let line: i64 = u[1].parse().unwrap_or(0);
            if !seen.insert((u[0].clone(), line)) {
                continue;
            }
            let mut nc: Vec<UiNode> = chain.iter().map(|n| UiNode { file: n.file.clone(), line: n.line, name: n.name.clone(), site: n.site.clone(), conf: n.conf.clone(), kind: n.kind }).collect();
            nc.push(UiNode { file: u[0].clone(), line, name: u[2].clone(), site: Some((u[3].clone(), u[4].parse().unwrap_or(0))), conf: u[5].clone(), kind: if u[6] == "page_component" { "component" } else { "member" } });
            q.push_back((nc, depth + 1));
        }
        // a handler declared inside a component (`const submit = async () => ...` in a dialog) is reached through that
        // component: climb to the enclosing member too (never from the client function itself, which sits in its api object)
        if last.kind != "client" {
            let encl = rows(
                c,
                "SELECT p.line, p.qname FROM members p JOIN members m ON m.file=p.file AND m.line=?2 WHERE p.file=?1 AND p.line<?2 AND p.end_line>=m.end_line
                   AND p.kind IN ('component','function','const','method') AND m.kind IN ('function','component','const','method') ORDER BY p.end_line-p.line LIMIT 1",
                &[&last.file, &last.line],
            );
            if let Some(u) = encl.first() {
                let line: i64 = u[0].parse().unwrap_or(0);
                if (last.file.ends_with(".tsx") || last.file.ends_with(".jsx") || last.file.ends_with(".ts") || last.file.ends_with(".js")) && seen.insert((last.file.clone(), line)) {
                    let mut nc: Vec<UiNode> = chain.iter().map(|n| UiNode { file: n.file.clone(), line: n.line, name: n.name.clone(), site: n.site.clone(), conf: n.conf.clone(), kind: n.kind }).collect();
                    nc.push(UiNode { file: last.file.clone(), line, name: u[1].clone(), site: Some((last.file.clone(), line)), conf: "exact".into(), kind: "component" });
                    q.push_back((nc, depth + 1));
                }
            }
        }
    }
    out
}

/// Direct callers of a client function with the line where each calls it: (caller, caller file, caller line, site file, site line).
/// Shown when no routed page is reached within the UI hop limit.
fn client_callers(c: &Connection, client: (&str, i64)) -> Vec<(String, String, i64, String, i64)> {
    rows(
        c,
        "SELECT e.sname, s.path, e.sline, COALESCE(cf.path,''), e.cline FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid LEFT JOIN files cf ON cf.rowid=e.cfid
         WHERE e.kind='component_client' AND e.conf<>'name' AND d.path=? AND e.dline=? ORDER BY s.path, e.sline",
        &[&client.0, &client.1],
    )
    .into_iter()
    .map(|x| (x[0].clone(), x[1].clone(), x[2].parse().unwrap_or(0), x[3].clone(), x[4].parse().unwrap_or(0)))
    .collect()
}

fn menu_of(c: &Connection, route: &str) -> Option<(String, String, String, i64)> {
    let r = rows(c, "SELECT label, COALESCE(NULLIF(roles,''), grp_roles, ''), file, line FROM menu WHERE href=? OR href LIKE ? ORDER BY length(href) LIMIT 1", &[&route, &format!("{route}?%")]);
    r.into_iter().next().map(|x| (x[0].clone(), x[1].clone(), x[2].clone(), x[3].parse().unwrap_or(0)))
}

fn route_info(c: &Connection, path: &str) -> Option<(String, String, i64, String)> {
    rows(c, "SELECT component, file, line, roles FROM routes WHERE path=? LIMIT 1", &[&path]).into_iter().next().map(|x| (x[0].clone(), x[1].clone(), x[2].parse().unwrap_or(0), x[3].clone()))
}

fn trace_endpoint_up(ix: &Index, eps: &[(i64, String, String, i64, i64)], limit: usize, sites: bool, r: &mut Resp) {
    let c = &ix.conn;
    for (tid, key, file, line, _) in eps.iter().take(2) {
        let roles = endpoint_roles(c, file, *line);
        r.head.push(format!("== trace --up {key}{} [{file}:{line}] roles {}", query::rel_tag(c, file, *line), roles_txt(&roles)));
        if !sites {
            r.ans_cites("endpoint", format!("endpoint {key}  {file}:{line}  roles {}", roles_txt(&roles)), vec![decl_cite(c, file, *line)], "exact");
        }
        let clients = rows(
            c,
            "SELECT s.path, e.sline, e.sname, COALESCE(cf.path,''), e.cline, e.conf FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid LEFT JOIN files cf ON cf.rowid=e.cfid
             WHERE e.kind='client_endpoint' AND d.path=? AND e.dline=? ORDER BY s.path, e.sline",
            &[file, line],
        );
        if clients.is_empty() {
            r.foot.push("no client function in the index calls this endpoint (called by scripts/e2e only, or unused)".into());
        }
        let mut shown = 0;
        let mut n_chains = 0;
        let mut printed: HashSet<(String, i64, String)> = HashSet::new();
        for cl in &clients {
            let cline: i64 = cl[1].parse().unwrap_or(0);
            r.ans_cites("client", format!("client   {}  {}:{} ({})", cl[2], cl[0], cl[1], cl[5]), vec![decl_cite(c, &cl[0], cline)], conf_static(&cl[5]));
            let chains = ui_up(ix, (cl[0].clone(), cline), 4);
            n_chains += chains.len();
            for (chain, route, rfile, rline) in chains {
                if shown >= limit {
                    break;
                }
                shown += 1;
                if sites {
                    // compact: the call site that reaches the client, then the screen
                    let first = chain.get(1);
                    let via: Vec<String> = chain.iter().skip(2).map(|n| n.name.clone()).collect();
                    let (site_f, site_l, who) = first.map(|n| n.site.clone().map(|s| (s.0, s.1, n.name.clone())).unwrap_or((n.file.clone(), n.line, n.name.clone()))).unwrap_or((cl[0].clone(), cline, cl[2].clone()));
                    let menu = menu_of(c, &route).map(|m| format!(", menu \"{}\" roles {}", m.0, rroles_txt(&m.1))).unwrap_or_default();
                    let rr = route_info(c, &route).map(|x| x.3).unwrap_or_default();
                    r.ans_cites(
                        "caller",
                        format!("  {site_f}:{site_l}  {who}{}  -> screen {route} ({rfile}:{rline}, roles {}{menu})", if via.is_empty() { String::new() } else { format!(" via {}", via.join(" <- ")) }, rroles_txt(&rr)),
                        vec![cite(&site_f, site_l)],
                        "exact",
                    );
                    continue;
                }
                // chain[0] is the client fn; the rest are callers, bottom-up (a caller shared by several screens is printed once)
                for n in chain.iter().skip(1) {
                    if !printed.insert((n.file.clone(), n.site.as_ref().map(|s| s.1).unwrap_or(n.line), n.name.clone())) {
                        continue;
                    }
                    let site = n.site.as_ref().map(|s| format!("  <- {} calls it at {}:{}", n.name, s.0, s.1)).unwrap_or_default();
                    let mut cs = vec![];
                    if let Some(s) = &n.site {
                        cs.push(cite(&s.0, s.1));
                    }
                    if cs.is_empty() {
                        cs.push(cite(&n.file, n.line));
                    }
                    let _ = site;
                    r.ans_cites("caller", format!("  caller   {} ({})  {}:{}", n.name, conf_static(&n.conf), n.file, n.site.as_ref().map(|s| s.1).unwrap_or(n.line)), cs, conf_static(&n.conf));
                }
                if let Some((comp, _f, _l, rroles)) = route_info(c, &route) {
                    r.ans_cites("route", format!("  route    {route} -> {comp}  {rfile}:{rline}  roles {}", rroles_txt(&rroles)), vec![cite(&rfile, rline)], "exact");
                    if let Some((label, mroles, mf, ml)) = menu_of(c, &route) {
                        r.ans_cites("menu", format!("  menu     \"{label}\" roles {}  {mf}:{ml}", rroles_txt(&mroles)), vec![cite(&mf, ml)], "exact");
                    }
                }
            }
        }
        if n_chains == 0 && !clients.is_empty() {
            r.foot.push("(client functions found, but no routed page reaches them within 4 UI hops)".into());
            // say who calls them anyway
            for cl in clients.iter().take(4) {
                let cline: i64 = cl[1].parse().unwrap_or(0);
                for (who, wf, wl, sf, sl) in client_callers(c, (&cl[0], cline)).into_iter().take(limit.max(2)) {
                    let (f, l) = if sf.is_empty() { (wf.clone(), wl) } else { (sf, sl) };
                    r.ans_cites("caller", format!("  {f}:{l}  {who} calls {}  (client caller; no routed page within 4 UI hops)", cl[2]), vec![cite(&f, l)], "exact");
                }
            }
        }
        if !sites {
            state_flow(ix, *tid, key, 4, r);
        }
    }
}


// ───── state flow: who sets a lifecycle state, who acts on it, which screens call them ─────

/// The routed screens that reach an endpoint's client functions, one line each (the call site that reaches the client,
/// then the screen), or the direct client callers when no routed page is within the UI hop limit.
fn screens_of(ix: &Index, file: &str, line: i64, cap: usize, indent: &str, seen: &mut HashSet<String>, r: &mut Resp) {
    let c = &ix.conn;
    let clients = rows(
        c,
        "SELECT s.path, e.sline, e.sname FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid
         WHERE e.kind='client_endpoint' AND d.path=? AND e.dline=? ORDER BY s.path, e.sline",
        &[&file, &line],
    );
    let mut shown = 0;
    let mut direct: Vec<(String, String, i64, String)> = vec![];
    for cl in &clients {
        let cline: i64 = cl[1].parse().unwrap_or(0);
        let chains = ui_up(ix, (cl[0].clone(), cline), 4);
        if chains.is_empty() {
            for (who, wf, wl, sf, sl) in client_callers(c, (&cl[0], cline)).into_iter().take(2) {
                let (f, l) = if sf.is_empty() { (wf, wl) } else { (sf, sl) };
                direct.push((f, format!("{who} calls {}", cl[2]), l, String::new()));
            }
        }
        for (chain, route, rfile, rline) in chains {
            if shown >= cap {
                break;
            }
            let first = chain.get(1);
            let via: Vec<String> = chain.iter().skip(2).map(|n| n.name.clone()).collect();
            let (site_f, site_l, who) = first.map(|n| n.site.clone().map(|s| (s.0, s.1, n.name.clone())).unwrap_or((n.file.clone(), n.line, n.name.clone()))).unwrap_or((cl[0].clone(), cline, cl[2].clone()));
            // a call site already named in this answer is not repeated
            if !seen.insert(format!("{site_f}:{site_l}")) {
                continue;
            }
            shown += 1;
            let menu = menu_of(c, &route).map(|m| format!(", menu \"{}\"", m.0)).unwrap_or_default();
            r.ans_cites(
                "caller",
                format!("{indent}{site_f}:{site_l}  {who} calls {}{}  -> screen {route} ({rfile}:{rline}{menu})", cl[2], if via.is_empty() { String::new() } else { format!(" via {}", via.join(" <- ")) }),
                vec![cite(&site_f, site_l)],
                "exact",
            );
        }
    }
    if shown == 0 && !direct.is_empty() {
        for (f, what, l, _) in direct.into_iter().take(cap) {
            r.ans_cites("caller", format!("{indent}{f}:{l}  {what}  (client caller; no routed page within 4 UI hops)"), vec![cite(&f, l)], "exact");
        }
    }
}

/// `state flow` for an endpoint: the lifecycle-state values (`status = 'pending_approval'`) its call graph sets, the other
/// endpoints that set the same value, the endpoints that act on it (guard on it, and often move it on), and the screens that
/// call them. Reads `state_flow` (built from the `state_refs` literals of the members each endpoint reaches).
fn state_flow(ix: &Index, tid: i64, ep_key: &str, cap: usize, r: &mut Resp) {
    let c = &ix.conn;
    let mut seen_routes: HashSet<String> = HashSet::new(); // call sites already named
    let sets = rows(
        c,
        "SELECT s.tbl, s.col, s.val, s.from_vals, f.path, s.line, s.sline, COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=s.sline LIMIT 1),''), COALESCE((SELECT m.end_line FROM members m WHERE m.file=f.path AND m.line=s.sline LIMIT 1), s.sline)
         FROM state_flow s JOIN files f ON f.rowid=s.fid WHERE s.tid=? AND s.op='set' AND s.shared=0 ORDER BY s.depth, f.path, s.line LIMIT 6",
        &[&tid],
    );
    let mut done: HashSet<(String, String, String)> = HashSet::new();
    for st in sets {
        let (tbl, col, val, from) = (st[0].clone(), st[1].clone(), st[2].clone(), st[3].clone());
        if !done.insert((tbl.clone(), col.clone(), val.clone())) || done.len() > 2 {
            continue;
        }
        let (file, line, sline, member, end): (String, i64, i64, String, i64) = (st[4].clone(), st[5].parse().unwrap_or(0), st[6].parse().unwrap_or(0), st[7].clone(), st[8].parse().unwrap_or(0));
        let from_txt = if from.is_empty() { String::new() } else { format!("'{}' -> ", from.replace(',', "|")) };
        r.ans_cites(
            "state",
            format!("state flow: {tbl}.{col} {from_txt}'{val}' is set by {ep_key} in {member}  {file}:{line}"),
            vec![Cite { file: file.clone(), line: sline, end: end.max(sline) }, cite(&file, line)],
            "resolved",
        );
        // other endpoints that set the same value
        let others = rows(
            c,
            "SELECT k.key, kf.path, k.line, f.path, s.line, s.sline, COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=s.sline LIMIT 1),''), COALESCE((SELECT m.end_line FROM members m WHERE m.file=f.path AND m.line=s.sline LIMIT 1), s.sline)
             FROM state_flow s JOIN trace_keys k ON k.id=s.tid JOIN files kf ON kf.rowid=k.fid JOIN files f ON f.rowid=s.fid
             WHERE s.tid<>?1 AND s.op='set' AND s.tbl=?2 AND s.col=?3 AND s.val=?4 AND s.shared=0 GROUP BY k.key, s.line ORDER BY s.depth, k.key LIMIT 4",
            &[&tid, &tbl, &col, &val],
        );
        for o in &others {
            let (okey, ofile, oline, mfile, mline, msline, mname, mend): (String, String, i64, String, i64, i64, String, i64) =
                (o[0].clone(), o[1].clone(), o[2].parse().unwrap_or(0), o[3].clone(), o[4].parse().unwrap_or(0), o[5].parse().unwrap_or(0), o[6].clone(), o[7].parse().unwrap_or(0));
            r.ans_cites(
                "state",
                format!("  also set by {okey} in {mname}  {mfile}:{mline}"),
                vec![Cite { file: mfile.clone(), line: msline, end: mend.max(msline) }, cite(&mfile, mline)],
                "resolved",
            );
            screens_of(ix, &ofile, oline, 2, "    ", &mut seen_routes, r);
        }
        // endpoints acting on the value: moving it on (guarded by it) first, then specific readers (a guard reached by at most 4 endpoints)
        let acts = rows(
            c,
            "WITH t AS (SELECT s.tid, s.op, s.val, s.from_vals, s.fid, s.line, s.sline, s.depth FROM state_flow s WHERE s.tid<>?1 AND s.tbl=?2 AND s.col=?3 AND s.shared=0
                          AND ((s.op='test' AND s.val=?4) OR (s.op='set' AND (',' || s.from_vals || ',') LIKE '%,' || ?4 || ',%'))),
                  n AS (SELECT s.fid, s.sline, COUNT(DISTINCT s.tid) AS c FROM state_flow s WHERE s.tbl=?2 AND s.col=?3 AND s.val=?4 AND s.op='test' GROUP BY s.fid, s.sline)
             SELECT k.key, kf.path, k.line, f.path, t.line, t.sline, COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=t.sline LIMIT 1),''), t.op, t.val,
                    COALESCE((SELECT m.end_line FROM members m WHERE m.file=f.path AND m.line=t.sline LIMIT 1), t.sline),
                    COALESCE((SELECT group_concat(DISTINCT x.val) FROM state_flow x WHERE x.tid=t.tid AND x.op='set' AND x.tbl=?2 AND x.col=?3 AND x.val<>?4 AND x.shared=0), '')
             FROM t JOIN trace_keys k ON k.id=t.tid JOIN files kf ON kf.rowid=k.fid JOIN files f ON f.rowid=t.fid LEFT JOIN n ON n.fid=t.fid AND n.sline=t.sline
             WHERE t.op='set' OR COALESCE(n.c,1) <= 4
             ORDER BY (t.op='set' OR length(COALESCE((SELECT group_concat(DISTINCT x.val) FROM state_flow x WHERE x.tid=t.tid AND x.op='set' AND x.tbl=?2 AND x.col=?3 AND x.val<>?4 AND x.shared=0), ''))>0) DESC, t.depth, k.key LIMIT 80",
            &[&tid, &tbl, &col, &val],
        );
        // one line per endpoint: a transition (it sets another value while guarded by this one) wins over a plain test
        let mut seen_ep: HashSet<String> = HashSet::new();
        let mut shown = 0;
        let mut total_eps: HashSet<String> = HashSet::new();
        for a in &acts {
            total_eps.insert(a[0].clone());
        }
        for a in &acts {
            if shown >= cap || !seen_ep.insert(a[0].clone()) {
                continue;
            }
            shown += 1;
            let (akey, afile, aline, mfile, mline, _msline, mname, op, nv, _mend): (String, String, i64, String, i64, i64, String, String, String, i64) =
                (a[0].clone(), a[1].clone(), a[2].parse().unwrap_or(0), a[3].clone(), a[4].parse().unwrap_or(0), a[5].parse().unwrap_or(0), a[6].clone(), a[7].clone(), a[8].clone(), a[9].parse().unwrap_or(0));
            let mv = a[10].replace(',', "', '");
            let what = if op == "set" { format!("moves it to '{nv}'") } else if mv.is_empty() { "checks it".to_string() } else { format!("checks it and sets '{mv}'") };
            r.ans_cites(
                "state",
                format!("  acts on '{val}': {akey} {what} in {mname}  {mfile}:{mline}"),
                vec![cite(&mfile, mline)],
                "resolved",
            );
            screens_of(ix, &afile, aline, 2, "    ", &mut seen_routes, r);
        }
        if total_eps.len() > shown {
            r.foot.push(format!("(+{} more endpoints guard on {tbl}.{col} '{val}')", total_eps.len() - shown));
        }
    }
}

// ───── route down ─────

fn words_score(words: &[String], texts: &[&str]) -> (usize, usize) {
    // (exact identifier matches, word matches)
    let mut exact = 0;
    let mut part = 0;
    for w in words {
        let mut hit = false;
        for t in texts {
            let tl = t.to_lowercase();
            let segs: Vec<String> = ident_words(t);
            let last = tl.rsplit(['.', '/']).next().unwrap_or(&tl).to_string();
            if last == *w {
                exact += 1;
                hit = true;
                break;
            }
            if segs.iter().any(|s| s == w || stem(s) == stem(w)) {
                hit = true;
            }
        }
        if hit {
            part += 1;
        }
    }
    (exact, part)
}

fn stem(s: &str) -> String {
    let s = s.to_lowercase();
    for suf in ["izations", "ization", "ations", "ation", "ings", "ing", "ies", "es", "ed", "s", "e"] {
        if s.len() > suf.len() + 3 && s.ends_with(suf) {
            return s[..s.len() - suf.len()].to_string();
        }
    }
    s
}

fn ident_words(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let cs: Vec<char> = s.chars().collect();
    for (i, &ch) in cs.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(cur.to_lowercase());
                cur.clear();
            }
            continue;
        }
        if ch.is_uppercase() && i > 0 && cs[i - 1].is_lowercase() && !cur.is_empty() {
            out.push(cur.to_lowercase());
            cur.clear();
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        out.push(cur.to_lowercase());
    }
    out
}

pub(crate) fn trace_route(ix: &Index, route: &str, words: &[String], limit: usize, roles_only: bool, tables: usize, flow: bool, r: &mut Resp) {
    let c = &ix.conn;
    let keys = find_keys(c, "route", route);
    let Some((tid, _, rfile, rline, nchains)) = keys.into_iter().next() else {
        r.head.push(format!("== trace {route}: the route has no page component in the index (redirect or unresolved import)"));
        return;
    };
    let (comp, _, _, rroles) = route_info(c, route).unwrap_or_default();
    let menu = menu_of(c, route);
    let page_file = rows(c, "SELECT page_file FROM routes WHERE path=? LIMIT 1", &[&route]).first().map(|x| x[0].clone()).unwrap_or_default();
    r.head.push(format!(
        "== trace {route} -> {comp} [{page_file}]: {nchains} endpoint chains{}",
        if words.is_empty() { String::new() } else { format!(" (focus: {})", words.join(" ")) }
    ));
    r.ans_cites("route", format!("route    {route} -> {comp} ({page_file})  {rfile}:{rline}  roles {}", rroles_txt(&rroles)), vec![cite(&rfile, rline)], "exact");
    if let Some((label, mroles, mf, ml)) = &menu {
        r.ans_cites("menu", format!("menu     \"{label}\"  {mf}:{ml}  roles {}", rroles_txt(mroles)), vec![cite(mf, *ml)], "exact");
    }
    let paths = load_paths(c, tid);
    // score chains against the focus words
    let mut scored: Vec<(i64, i64, usize, usize)> = vec![]; // (-exact, -part, idx, pid)
    let mut order: Vec<(i64, &Vec<Hop>)> = vec![];
    for (pid, hops) in &paths {
        order.push((*pid, hops));
    }
    for (i, (pid, hops)) in order.iter().enumerate() {
        let names: Vec<String> = hops.iter().map(|h| if h.layer == "endpoint" { h.tbl.clone() } else { h.name.clone() }).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let (e, p) = if words.is_empty() { (0, 0) } else { words_score(words, &refs[2.min(refs.len())..]) };
        scored.push((-(e as i64), -(p as i64), i, *pid as usize));
    }
    scored.sort();
    if !words.is_empty() {
        let best = scored.first().map(|s| (s.0, s.1)).unwrap_or((0, 0));
        scored.retain(|s| (s.0, s.1) == best);
    }
    if scored.is_empty() {
        r.foot.push("no endpoint chains for this route (the page makes no API calls the index can match)".into());
        return;
    }
    let total = scored.len();
    let mut auth_notes: Vec<String> = vec![];
    for (n, s) in scored.iter().take(limit.clamp(1, 12)).enumerate() {
        let hops = &order[s.2].1;
        if !roles_only {
            r.ans_cites("chain", format!("[{}]", n + 1), vec![], "exact");
        }
        let last_ep = hops.last().map(|h| h.tbl.clone()).unwrap_or_default();
        // hops, with UI members showing the line where they call the next layer
        for (i, h) in hops.iter().enumerate() {
            if h.layer == "route" || h.layer == "page" || (roles_only && h.layer != "endpoint") {
                continue;
            }
            let next = hops.get(i + 1);
            let mut line = h.line;
            let mut decl = String::new();
            if matches!(h.layer.as_str(), "member" | "component") {
                if let Some(nx) = next {
                    if nx.cfile == h.file && nx.cline > 0 {
                        decl = format!(" (declared at line {})", h.line);
                        line = nx.cline;
                    }
                }
            }
            let nm = if h.layer == "endpoint" { h.tbl.clone() } else { h.name.clone() };
            let mut text = format!("  {:<8} {}  {}:{}{}", h.layer, nm, h.file, line, decl);
            let mut cs = vec![cite(&h.file, line)];
            match h.layer.as_str() {
                "client" => {
                    cs = vec![decl_cite(c, &h.file, h.line)];
                    text.push_str(&format!(" ({})", h.conf));
                    if !h.cfile.is_empty() && h.cline > 0 {
                        text.push_str(&format!("  <- called at {}:{}", h.cfile, h.cline));
                    }
                }
                "endpoint" => {
                    cs = vec![decl_cite(c, &h.file, h.line)];
                    let roles = endpoint_roles(c, &h.file, h.line);
                    text.push_str(&format!("  roles {}", roles_txt(&roles)));
                    if let Some(gap) = role_gap(&rroles, &roles, roles_only) {
                        text.push_str(&format!("  [{gap}]"));
                    }
                }
                _ => {}
            }
            r.ans_cites(layer_kind(&h.layer), text, cs, conf_static(&h.conf));
        }
        if roles_only {
            continue;
        }
        // the endpoint's own trace (top paths)
        let ek = find_keys(c, "endpoint", &last_ep);
        if let Some((etid, key, _, _, _)) = ek.first() {
            let (ep, auth_note) = clean_paths(c, load_paths(c, *etid), false);
            // skip the endpoint hop (already printed); print handler..table
            let mut vs: Vec<Vec<Hop>> = ep.values().map(|v| v.iter().skip(1).cloned().collect()).collect();
            if !words.is_empty() {
                // paths ending at a table whose name shares a focus word come first (stable otherwise)
                vs.sort_by_key(|v| {
                    let t = v.last().map(|h| h.tbl.clone()).unwrap_or_default();
                    let tw = ident_words(&t.replace('_', " "));
                    std::cmp::Reverse(words.iter().filter(|w| tw.iter().any(|x| stem(x) == stem(w))).count())
                });
            }
            let trimmed: BTreeMap<i64, Vec<Hop>> = vs.into_iter().enumerate().map(|(i, v)| (i as i64, v)).collect();
            let per = if words.is_empty() { 2 } else { 3 };
            let shown = if tables > 0 {
                let all_paths: Vec<Vec<Hop>> = trimmed.values().cloned().collect();
                let pick = pick_table_paths(c, &all_paths, tables);
                let sel: BTreeMap<i64, Vec<Hop>> = pick.iter().enumerate().map(|(k, &i)| (k as i64, all_paths[i].clone())).collect();
                print_paths(ix, &sel, key, 4, sel.len(), 6, r)
            } else {
                print_paths(ix, &trimmed, key, 4, per, 6, r)
            };
            if trimmed.len() > shown {
                r.ans_cites("note", format!("      (+{} more paths: aix trace \"{key}\")", trimmed.len() - shown), vec![], "exact");
            }
            if let Some(a) = auth_note {
                auth_notes.push(a);
            }
            if flow {
                state_flow(ix, *etid, key, 4, r);
            }
        }
    }
    if let Some(first) = auth_notes.first() {
        // the same lookups run on every endpoint: one line for the page, not one per chain
        let more = auth_notes.iter().filter(|a| *a != first).count();
        r.ans_cites("note", format!("  {first}{}", if more > 0 { format!(" (+{more} other hidden auth chain(s))") } else { String::new() }), vec![], "exact");
    }
    let cap = limit.clamp(1, 12);
    // every endpoint the page calls is listed: the chains beyond the cap as one line each, then the calls the chain graph
    // misses (local handlers, lazy-loaded components) from the page's own files, as `endpoint` knows its callers
    if words.is_empty() {
        let mut listed: HashSet<(String, String)> = HashSet::new();
        let ep_norm = |key: &str| -> Option<(String, String)> {
            let (m, _) = key.split_once(' ')?;
            one(c, "SELECT method, norm FROM endpoints WHERE method||' '||norm=? OR method||' '||path=?", &[&key, &key]).map(|x| (m.to_string(), x[1].clone()))
        };
        for (_, hops) in &order {
            if let Some(k) = hops.last().filter(|h| h.layer == "endpoint").and_then(|h| ep_norm(&h.tbl)) {
                listed.insert(k);
            }
        }
        if total > cap {
            r.ans_cites("note", format!("  -- {} more chains, one line each (aix trace \"<METHOD path>\" for the handler side)", total - cap), vec![], "exact");
            for s in scored.iter().skip(cap) {
                let hops = &order[s.2].1;
                let (Some(cl), Some(ep)) = (hops.iter().rev().find(|h| h.layer == "client"), hops.last().filter(|h| h.layer == "endpoint")) else { continue };
                let roles = endpoint_roles(c, &ep.file, ep.line);
                r.ans_cites(
                    "endpoint",
                    format!("  more     {}  <- {} ({}:{})  roles {}", ep.tbl, cl.name, cl.cfile, cl.cline, roles_txt(&roles)),
                    vec![decl_cite(c, &ep.file, ep.line)],
                    "exact",
                );
            }
        }
        if !page_file.is_empty() {
            let files = query::page_closure(ix, &page_file, 3);
            let mut extra: Vec<(String, String, String, String)> = vec![];
            for ch in query::api_chain(ix, &files) {
                if ch.roles.is_empty() && ch.endpoint.starts_with('(') {
                    continue;
                }
                let m = if ch.method.is_empty() { None } else { Some(ch.method.to_uppercase()) };
                if listed.iter().any(|(lm, ln)| *ln == ch.norm && m.as_ref().is_none_or(|x| x == lm)) {
                    continue;
                }
                let key = format!("{} {}", m.clone().unwrap_or_default(), ch.path).trim().to_string();
                if extra.iter().any(|e| e.0 == key) {
                    continue;
                }
                extra.push((key, ch.api, ch.via, ch.endpoint));
            }
            if !extra.is_empty() {
                r.ans_cites("note", format!("  -- {} more endpoint(s) called from the page's own files (local handlers, lazy-loaded components) that no chain above shows", extra.len()), vec![], "exact");
                for (key, api, via, ep) in extra.iter().take(30) {
                    r.ans_cites("endpoint", format!("  also     {key}  <- {api} at {via}  handler {ep}"), vec![], "exact");
                }
            }
        }
    } else if total > cap {
        r.foot.push(format!("(+{} more endpoint chains; narrow with words: aix explain \"<feature words>\")", total - cap));
        r.truncated = true;
    }
}

fn role_gap(route_roles: &str, ep_roles: &str, with_extra: bool) -> Option<String> {
    let rr: BTreeSet<&str> = route_roles.split(',').filter(|x| !x.is_empty()).collect();
    let er: BTreeSet<&str> = ep_roles.split(',').filter(|x| !x.is_empty()).collect();
    if er.is_empty() || er.contains("public") || rr.is_empty() {
        return None;
    }
    let denied: Vec<&str> = rr.difference(&er).copied().collect();
    let extra: Vec<&str> = er.difference(&rr).copied().collect();
    let mut parts = vec![];
    if !denied.is_empty() {
        parts.push(format!("role gap: the page lets {} in but the endpoint denies them", denied.join(",")));
    }
    if with_extra && !extra.is_empty() {
        parts.push(format!("the endpoint also allows {} (not in the page roles)", extra.join(",")));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

// ───── symbol ─────

fn trace_symbol_down(ix: &Index, defs: &[(String, i64, i64, String, String, String)], o: &TraceOpts, limit: usize, r: &mut Resp) {
    let c = &ix.conn;
    let Some(d) = defs.iter().find(|d| d.5 != "field" && d.5 != "class" && d.5 != "interface").or(defs.first()) else { return };
    let (file, line) = (d.0.clone(), d.1);
    // BFS over resolved call edges
    #[derive(Clone)]
    #[allow(dead_code)]
    struct N {
        file: String,
        line: i64,
        name: String,
        parent: Option<usize>,
        depth: usize,
        site: (String, i64),
        conf: String,
    }
    let mut nodes: Vec<N> = vec![N { file: file.clone(), line, name: d.4.clone(), parent: None, depth: 0, site: (file.clone(), line), conf: "exact".into() }];
    let mut seen: HashSet<(String, i64)> = HashSet::from([(file.clone(), line)]);
    let mut q: VecDeque<usize> = VecDeque::from([0]);
    let Ok(mut st) = c.prepare_cached(
        "SELECT callee_file, callee_line, cname, line, MIN(CASE conf WHEN 'exact' THEN 0 ELSE 1 END) FROM call_edges_v WHERE file=? AND caller_line=? AND kind IN ('call','new') AND conf<>'name' GROUP BY callee_file, callee_line ORDER BY line",
    ) else {
        return;
    };
    while let Some(i) = q.pop_front() {
        if nodes[i].depth >= o.depth || nodes.len() > 900 {
            continue;
        }
        let (f, l) = (nodes[i].file.clone(), nodes[i].line);
        let es: Vec<(String, i64, String, i64, i64)> = st.query_map(params![f, l], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?))).map(|it| it.flatten().collect()).unwrap_or_default();
        for (cf, cl, cn, site, cr) in es {
            if !seen.insert((cf.clone(), cl)) {
                continue;
            }
            let d2 = nodes[i].depth + 1;
            nodes.push(N { file: cf, line: cl, name: cn, parent: Some(i), depth: d2, site: (f.clone(), site), conf: if cr == 0 { "exact".into() } else { "resolved".into() } });
            q.push_back(nodes.len() - 1);
        }
    }
    // data access per reached node
    let mut leaves: Vec<(bool, usize, usize, String, String, String, String, String, i64, String)> = vec![]; // (read, depth, idx, tbl, rw, via, conf, file, line, ...)
    let mut ds = match c.prepare_cached("SELECT tbl, rw, via, conf, file, line FROM data_access WHERE file=? AND sline=? ORDER BY rw DESC, tbl") {
        Ok(s) => s,
        Err(_) => return,
    };
    for (i, n) in nodes.iter().enumerate() {
        let v: Vec<(String, String, String, String, String, i64)> = ds.query_map(params![n.file, n.line], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?))).map(|it| it.flatten().collect()).unwrap_or_default();
        for (tbl, rw, via, conf, f, l) in v {
            leaves.push((rw != "w", n.depth, i, tbl, rw, via, conf, f, l, String::new()));
        }
    }
    leaves.sort_by(|a, b| (a.0, a.1, &a.3).cmp(&(b.0, b.1, &b.3)));
    r.head.push(format!("== trace {} [{}:{}]: {} methods reached (depth<={}), {} table accesses", d.4, file, line, nodes.len(), o.depth, leaves.len()));
    if let Some(e) = endpoint_row(c, &file, line) {
        r.ans_cites("endpoint", format!("endpoint {} {}  {}:{}  roles {}", e.0, e.1, file, line, roles_txt(&e.2)), vec![cite(&file, line)], "exact");
    }
    if leaves.is_empty() {
        r.foot.push("no table access reachable through resolved calls (exact/resolved edges only)".into());
    }
    let mut printed: HashSet<usize> = HashSet::new();
    for (_, _, i, tbl, rw, via, conf, f, l, _) in leaves.iter().take(limit.max(1)) {
        let mut chain = vec![];
        let mut cur = Some(*i);
        while let Some(cu) = cur {
            chain.push(cu);
            cur = nodes[cu].parent;
        }
        chain.reverse();
        for (k, &cu) in chain.iter().enumerate() {
            if !printed.insert(cu) {
                continue;
            }
            let n = &nodes[cu];
            let indent = " ".repeat(2 * k.min(10));
            let called = if k > 0 { format!("  <- called at {}:{}", n.site.0, n.site.1) } else { String::new() };
            r.ans_cites(if k == 0 { "handler" } else { "call" }, format!("{indent}{:<8} {}  {}:{} ({}){called}", if k == 0 { "symbol" } else { "call" }, n.name, n.file, n.line, n.conf), vec![cite(&n.file, n.line)], conf_static(&n.conf));
        }
        let ent = entity_of_table(c, tbl);
        let (ef, el) = ent.as_ref().map(|e| (e.1.clone(), e.2)).unwrap_or((f.clone(), *l));
        let indent = " ".repeat(2 * chain.len().min(11));
        r.ans_cites("table", format!("{indent}table    {tbl} ({}) {ef}:{el} via {via} ({conf}); accessed at {f}:{l}", if rw == "w" { "write" } else { "read" }), vec![cite(&ef, el)], conf_static(conf));
    }
    if leaves.len() > limit.max(1) {
        r.foot.push(format!("(+{} more table accesses)", leaves.len() - limit.max(1)));
        r.truncated = true;
    }
}

fn endpoint_row(c: &Connection, file: &str, line: i64) -> Option<(String, String, String)> {
    rows(c, "SELECT method, path, roles FROM endpoints WHERE file=? AND line=? LIMIT 1", &[&file, &line]).into_iter().next().map(|x| (x[0].clone(), x[1].clone(), x[2].clone()))
}

fn trace_symbol_up(ix: &Index, defs: &[(String, i64, i64, String, String, String)], limit: usize, r: &mut Resp) {
    let c = &ix.conn;
    let Some(d) = defs.iter().find(|d| d.5 != "field").or(defs.first()) else { return };
    let (file, line) = (d.0.clone(), d.1);
    #[derive(Clone)]
    #[allow(dead_code)]
    struct N {
        file: String,
        line: i64,
        name: String,
        parent: Option<usize>,
        depth: usize,
        site: (String, i64),
        conf: String,
    }
    let mut nodes = vec![N { file: file.clone(), line, name: d.4.clone(), parent: None, depth: 0, site: (file.clone(), line), conf: "exact".into() }];
    let mut seen: HashSet<(String, i64)> = HashSet::from([(file.clone(), line)]);
    let mut q: VecDeque<usize> = VecDeque::from([0]);
    let mut found: Vec<usize> = vec![];
    let Ok(mut st) = c.prepare_cached(
        "SELECT file, caller_line, caller, MIN(line), MIN(CASE conf WHEN 'exact' THEN 0 ELSE 1 END) FROM call_edges_v WHERE callee_file=? AND callee_line=? AND conf<>'name' AND kind IN ('call','new') GROUP BY file, caller_line",
    ) else {
        return;
    };
    // test files that reach the symbol (as `impact` counts them): a call inside a test callback (`it('..', () => ..)`)
    // has no enclosing named member, so it is not a node to climb from, but it is a caller
    let mut tests: BTreeMap<String, i64> = BTreeMap::new();
    while let Some(i) = q.pop_front() {
        if endpoint_row(c, &nodes[i].file, nodes[i].line).is_some() {
            found.push(i);
            continue;
        }
        if nodes[i].depth >= 6 || nodes.len() > 500 {
            continue;
        }
        let (f, l) = (nodes[i].file.clone(), nodes[i].line);
        let es: Vec<(String, i64, String, i64, i64)> = st.query_map(params![f, l], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?))).map(|it| it.flatten().collect()).unwrap_or_default();
        for (cf, cl, cn, site, cr) in es {
            if aix_extract::is_test_path(&cf) {
                tests.entry(cf.clone()).or_insert(site);
            }
            if cl <= 0 || !seen.insert((cf.clone(), cl)) {
                continue;
            }
            let d2 = nodes[i].depth + 1;
            nodes.push(N { file: cf, line: cl, name: cn, parent: Some(i), depth: d2, site: (cf_site(&f), site), conf: if cr == 0 { "exact".into() } else { "resolved".into() } });
            q.push_back(nodes.len() - 1);
        }
    }
    fn cf_site(f: &str) -> String {
        f.to_string()
    }
    r.head.push(format!("== trace --up {} [{}:{}]: reaches {} endpoint(s) within 6 calls ({} callers visited)", d.4, file, line, found.len(), nodes.len()));
    if !tests.is_empty() {
        r.ans_cites("note", format!("tests reaching it through calls: {} file(s)", tests.len()), vec![], "exact");
        for (tf, tl) in tests.iter().take(limit.clamp(1, 5)) {
            r.ans_cites("test", format!("  test     {tf}:{tl}"), vec![cite(tf, *tl)], "exact");
        }
        if tests.len() > limit.clamp(1, 5) {
            r.foot.push(format!("(+{} more test files: aix impact {} lists them)", tests.len() - limit.clamp(1, 5), d.4));
        }
    }
    if found.is_empty() {
        if crate::compose::no_endpoint_extractor(c) {
            r.foot.push(format!("{}; so no endpoint can be reached from here", crate::compose::NO_EXTRACTOR));
        } else {
            r.foot.push("no endpoint handler calls it through resolved edges (internal helper, scheduled job or only name-level callers)".into());
        }
        return;
    }
    for &fi in found.iter().take(limit.max(1)) {
        let mut chain = vec![];
        let mut cur = Some(fi);
        while let Some(cu) = cur {
            chain.push(cu);
            cur = nodes[cu].parent;
        }
        // chain: endpoint handler .. symbol (top-down already, since parents point toward the symbol)
        for (k, &cu) in chain.iter().enumerate() {
            let n = &nodes[cu];
            let indent = " ".repeat(2 * k.min(10));
            let ep = endpoint_row(c, &n.file, n.line);
            let label = if let Some(e) = &ep { format!("endpoint {} {}", e.0, e.1) } else { format!("caller  {}", n.name) };
            let roles = ep.as_ref().map(|e| format!("  roles {}", roles_txt(&e.2))).unwrap_or_default();
            r.ans_cites(if ep.is_some() { "endpoint" } else { "caller" }, format!("{indent}{label}  {}:{} ({}){roles}", n.file, n.line, n.conf), vec![cite(&n.file, n.line)], conf_static(&n.conf));
        }
        // screens above the endpoint
        let n = &nodes[fi];
        let clients = rows(
            c,
            "SELECT s.path, e.sline FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid WHERE e.kind='client_endpoint' AND d.path=? AND e.dline=? LIMIT 3",
            &[&n.file, &n.line],
        );
        for cl in clients {
            for (chain, route, rfile, rline) in ui_up(ix, (cl[0].clone(), cl[1].parse().unwrap_or(0)), 4).into_iter().take(3) {
                let last = chain.last().unwrap();
                let site = last.site.clone().unwrap_or((last.file.clone(), last.line));
                r.ans_cites("route", format!("    screen  {route}  {rfile}:{rline}  via {} (calls at {}:{})", last.name, site.0, site.1), vec![cite(&rfile, rline), cite(&site.0, site.1)], "exact");
            }
        }
    }
}

// ───── table up ─────

fn trace_table(ix: &Index, t: &str, o: &TraceOpts, r: &mut Resp) {
    let c = &ix.conn;
    let tbl = match resolve_table(ix, t) {
        Ok(x) => x,
        Err(sug) => {
            r.head.push(format!("== trace table:{t}: none (no table of that name in migrations, entities or data access)"));
            for s in sug {
                r.foot.push(format!("  did you mean {s}"));
            }
            return;
        }
    };
    let acc = rows(c, "SELECT symbol, file, line, rw, via, conf, sline FROM data_access WHERE tbl=? ORDER BY rw DESC, file, line", &[&tbl]);
    r.head.push(format!("== trace table:{tbl} --up: {} accessing members", acc.len()));
    let mut by_ep: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for rw in ["w", "r"] {
        let mut eps = endpoints_for_table(c, &tbl, rw, 10_000, o.all);
        if rw == "w" {
            eps.extend(cascade_endpoints(ix, &tbl, o.all));
            let mut seen_ep: HashSet<(String, String, i64)> = HashSet::new();
            eps.retain(|e| seen_ep.insert((e.0.clone(), e.1.clone(), e.2)));
        }
        let main: HashSet<String> = if o.all { endpoints_for_table(c, &tbl, rw, 10_000, false).into_iter().map(|e| e.0).collect() } else { HashSet::new() };
        let hidden = if o.all { 0 } else { endpoints_for_table(c, &tbl, rw, 10_000, true).len().saturating_sub(eps.len()) };
        let shown = eps.len().min(ix_limit(ix));
        r.ans_cites("summary", format!("endpoints that {} {tbl}: {}", if rw == "w" { "write" } else { "read" }, eps.len()), vec![], "exact");
        if hidden > 0 {
            r.foot.push(format!("({hidden} more endpoints {} {tbl} only as an auth/tenant-guard side effect; --all shows them)", if rw == "w" { "write" } else { "read" }));
        }
        for (key, file, line, depth_syms) in eps.iter().take(shown) {
            let roles = endpoint_roles(c, file, *line);
            let tag = if o.all && !main.contains(key) { " (auth side effect)" } else { "" };
            r.ans_cites("endpoint", format!("  {key}  {file}:{line}  roles {}  via {}{tag}", roles_txt(&roles), depth_syms), vec![decl_cite(c, file, *line)], "exact");
            by_ep.entry(key.clone()).or_default().push((file.clone(), rw.to_string()));
        }
        if eps.len() > shown {
            r.foot.push(format!("(+{} more {} endpoints)", eps.len() - shown, if rw == "w" { "writing" } else { "reading" }));
            r.truncated = true;
        }
    }
}

fn ix_limit(ix: &Index) -> usize {
    let _ = ix;
    20
}

/// Endpoints whose materialized trace reaches `tbl` with `rw`: (key, file, line, last member before the table).
/// A table access reached from more endpoints than this is shared infrastructure (auth / tenant guard helpers that
/// touch a table as a side effect), not something those endpoints are about.
const INFRA_ENDPOINTS: i64 = 100;

/// Is the access at (file, line) to `tbl` reached by an implausible number of endpoints?
fn infra_access(c: &Connection, tbl: &str, rw: &str, file: &str, line: i64) -> bool {
    rows(
        c,
        if crate::matviews::ready(c) {
            "SELECT COALESCE(SUM(a.n), 0) FROM mv_table_access a JOIN files f ON f.rowid=a.cfid WHERE a.tbl=? AND a.rw=? AND f.path=? AND a.cline=?"
        } else {
            "SELECT COUNT(DISTINCT p.tid) FROM trace_paths p JOIN files f ON f.rowid=p.cfid WHERE p.layer='table' AND p.tbl=? AND p.rw=? AND f.path=? AND p.cline=?"
        },
        &[&tbl, &rw, &file, &line],
    )
    .first()
    .and_then(|x| x[0].parse::<i64>().ok())
    .unwrap_or(0)
        > INFRA_ENDPOINTS
}

/// Endpoints whose traces touch `tbl` with `rw`: (key, file, line, via symbol). With `all` false the endpoints that reach
/// it only through shared infrastructure accesses (see `INFRA_ENDPOINTS`) are left out.
/// The `ON DELETE` action of the foreign key declared at (file, line): read from the migration text (the statement
/// from that line to its `;`, at most 12 lines), upper-cased (`CASCADE`, `SET NULL` ...). None when not declared.
fn fk_on_delete(ix: &Index, file: &str, line: i64) -> Option<String> {
    static ON_DEL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)\bON\s+DELETE\s+(CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION)\b").unwrap());
    let text = std::fs::read_to_string(ix.repo.join(file)).ok()?;
    let mut stmt = String::new();
    for l in text.lines().skip((line.max(1) - 1) as usize).take(12) {
        stmt.push_str(l);
        stmt.push(' ');
        // the clause ends at the statement's `;` or, inside CREATE TABLE, at the column / constraint's `,`
        if l.contains(';') || l.trim_end().ends_with(',') {
            break;
        }
    }
    // the action of this table's own FOREIGN KEY clause (a CREATE TABLE line holds one per column)
    let c = ON_DEL.captures(&stmt)?;
    Some(c[1].split_whitespace().collect::<Vec<_>>().join(" ").to_uppercase())
}

/// Parent tables whose delete also writes `tbl` through a foreign key (ON DELETE CASCADE / SET NULL / SET DEFAULT):
/// (parent, action), one per parent.
fn cascade_parents(ix: &Index, tbl: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    for f in rows(&ix.conn, "SELECT file, line, to_tbl FROM fks WHERE from_tbl=? ORDER BY file, line LIMIT 40", &[&tbl]) {
        if f[2] == tbl || out.iter().any(|o| o.0 == f[2]) {
            continue;
        }
        if let Some(a) = fk_on_delete(ix, &f[0], f[1].parse().unwrap_or(0)) {
            if matches!(a.as_str(), "CASCADE" | "SET NULL" | "SET DEFAULT") {
                out.push((f[2].clone(), a));
            }
        }
    }
    out
}

/// Endpoints that delete a cascade parent of `tbl`: the member writing the parent is named like a delete. (key, file, line, "fk cascade from <parent> (<member>)").
fn cascade_endpoints(ix: &Index, tbl: &str, all: bool) -> Vec<(String, String, i64, String)> {
    static DEL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)delete|remove|purge|destroy").unwrap());
    let mut out: Vec<(String, String, i64, String)> = vec![];
    for (parent, action) in cascade_parents(ix, tbl) {
        for (key, file, line, via) in endpoints_for_table(&ix.conn, &parent, "w", 10_000, all) {
            // the writing member must delete: a DELETE route that only updates the parent (`DELETE /follow` ->
            // `user.update`) removes no parent row
            if DEL.is_match(&via) {
                let how = if action == "CASCADE" { "fk cascade" } else { "fk on delete set null" };
                let how = if action == "SET DEFAULT" { "fk on delete set default" } else { how };
                out.push((key, file, line, format!("{how} from {parent} ({via})")));
            }
        }
    }
    out
}

fn endpoints_for_table(c: &Connection, tbl: &str, rw: &str, cap: usize, all: bool) -> Vec<(String, String, i64, String)> {
    let r = rows(
        c,
        &(if crate::matviews::ready(c) {
            "WITH infra AS (SELECT cfid, cline FROM mv_table_access WHERE tbl=?1 AND rw=?2 AND n > ?4)".to_string()
        } else {
            "WITH infra AS (SELECT cfid, cline FROM trace_paths WHERE layer='table' AND tbl=?1 AND rw=?2 GROUP BY cfid, cline HAVING COUNT(DISTINCT tid) > ?4)".to_string()
        } + "
         SELECT k.key, f.path, k.line,
            COALESCE((SELECT m.qname FROM trace_paths q JOIN files qf ON qf.rowid=q.fid LEFT JOIN members m ON m.file=qf.path AND m.line=q.line
                      WHERE q.tid=p.tid AND q.pid=p.pid AND q.hop=p.hop-1 LIMIT 1), '')
         FROM trace_paths p JOIN trace_keys k ON k.id=p.tid AND k.kind='endpoint' JOIN files f ON f.rowid=k.fid
         WHERE p.layer='table' AND p.tbl=?1 AND p.rw=?2 AND (?5 OR NOT EXISTS (SELECT 1 FROM infra i WHERE i.cfid=p.cfid AND i.cline=p.cline))
         GROUP BY k.key, f.path, k.line ORDER BY k.key LIMIT ?3"),
        &[&tbl, &rw, &(cap as i64), &INFRA_ENDPOINTS, &(all as i64)],
    );
    r.into_iter().map(|x| (x[0].clone(), x[1].clone(), x[2].parse().unwrap_or(0), x[3].clone())).collect()
}

// ───────────────────────────── tables ─────────────────────────────

fn norm_name(s: &str) -> String {
    s.to_lowercase().replace(['_', '-'], "")
}

fn sing(s: &str) -> String {
    if let Some(p) = s.strip_suffix("ies") {
        return format!("{p}y");
    }
    if s.ends_with("ses") || s.ends_with("xes") {
        return s[..s.len() - 2].to_string();
    }
    s.strip_suffix('s').map(str::to_string).unwrap_or_else(|| s.to_string())
}

fn all_tables(c: &Connection) -> Vec<(String, String)> {
    // (table, entity name or "")
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for x in rows(c, "SELECT DISTINCT tbl FROM migrations WHERE obj IN ('table','column') AND tbl<>'' UNION SELECT DISTINCT tbl FROM data_access UNION SELECT tbl FROM entities WHERE tbl<>''", &[]) {
        m.entry(x[0].clone()).or_default();
    }
    for x in rows(c, "SELECT tbl, name FROM entities WHERE tbl<>'' AND kind='entity'", &[]) {
        m.insert(x[0].clone(), x[1].clone());
    }
    m.into_iter().collect()
}

/// Exact table, entity name, or the ranked suggestions.
fn resolve_table(ix: &Index, arg: &str) -> Result<String, Vec<String>> {
    let c = &ix.conn;
    let a = arg.trim().trim_matches('"').to_lowercase();
    let all = all_tables(c);
    let raw = arg.trim();
    let quoted = format!("\"{}\"", raw.trim_matches('"').replace('"', "\"\""));
    for cand in [raw, quoted.as_str()] {
        if all.iter().any(|(t, _)| t == cand) {
            return Ok(cand.to_string()); // quoted case-sensitive or spaced name, as shown
        }
    }
    if all.iter().any(|(t, _)| *t == a) {
        return Ok(a);
    }
    let na = norm_name(&a);
    if let Some((t, _)) = all.iter().find(|(_, e)| !e.is_empty() && norm_name(e) == na) {
        return Ok(t.clone());
    }
    if let Some((t, _)) = all.iter().find(|(t, _)| norm_name(t) == na) {
        return Ok(t.clone());
    }
    // suggestions: singular/plural, token overlap, substring, edit distance on the whole name
    let toks = |s: &str| -> Vec<String> { ident_words(&s.replace('_', " ")).into_iter().map(|w| sing(&w)).collect() };
    let want = toks(&a);
    let mut scored: Vec<(f64, String)> = vec![];
    for (t, e) in &all {
        let tt = toks(t);
        let et = toks(e);
        let overlap = |x: &Vec<String>| -> f64 {
            if x.is_empty() || want.is_empty() {
                return 0.0;
            }
            let inter = want.iter().filter(|w| x.contains(w)).count() as f64;
            inter / (want.len().max(x.len()) as f64)
        };
        let mut sc = overlap(&tt).max(overlap(&et) * 0.95);
        let (s1, s2) = (sing(&norm_name(&a)), sing(&norm_name(t)));
        if s2.contains(&s1) || s1.contains(&s2) {
            sc = sc.max(0.6);
        }
        let d = query::edit_distance(&s1, &s2);
        let maxlen = s1.chars().count().max(s2.chars().count()).max(1);
        sc = sc.max(1.0 - d as f64 / maxlen as f64 - 0.15);
        if sc >= 0.4 {
            scored.push((sc, if e.is_empty() { t.clone() } else { format!("{t} (entity {e})") }));
        }
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.len().cmp(&b.1.len())));
    Err(scored.into_iter().take(6).map(|x| x.1).collect())
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct DbCol {
    name: String,
    detail: String,
    file: String,
    line: i64,
    version: String,
    stream: String,
}

/// Replay one migration stream (directory) in order: the table's columns as they stand after the last migration.
fn replay(c: &Connection, tbl: &str) -> BTreeMap<String, Vec<DbCol>> {
    let mut by_stream: BTreeMap<String, Vec<DbCol>> = BTreeMap::new();
    let ms = rows(c, "SELECT file, line, version, op, obj, col, detail, ord FROM migrations WHERE tbl=? AND obj IN ('table','column') ORDER BY ord, line", &[&tbl]);
    for m in ms {
        let stream = m[0].rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default();
        let cols = by_stream.entry(stream.clone()).or_default();
        let line: i64 = m[1].parse().unwrap_or(0);
        let (op, obj, col, detail) = (m[3].as_str(), m[4].as_str(), m[5].clone(), m[6].clone());
        let mk = |name: String, d: String| DbCol { name, detail: d, file: m[0].clone(), line, version: m[2].clone(), stream: stream.clone() };
        match (op, obj) {
            ("create", "table") => cols.clear(),
            ("drop", "table") => cols.clear(),
            ("create", "column") | ("add", "column") => {
                cols.retain(|x| x.name != col);
                cols.push(mk(col, detail));
            }
            ("drop", "column") => cols.retain(|x| x.name != col),
            ("alter", "column") => {
                if let Some(to) = detail.strip_prefix("rename to ") {
                    if let Some(x) = cols.iter_mut().find(|x| x.name == col) {
                        x.name = to.trim().to_lowercase();
                        x.file = m[0].clone();
                        x.line = line;
                        x.version = m[2].clone();
                    }
                } else if let Some(x) = cols.iter_mut().find(|x| x.name == col) {
                    if let Some(ty) = detail.strip_prefix("type ") {
                        x.detail = ty.to_string();
                    } else if detail == "set not null" && !x.detail.contains("not null") {
                        x.detail.push_str(" not null");
                    } else if detail == "drop not null" {
                        x.detail = x.detail.replace(" not null", "");
                    }
                }
            }
            _ => {}
        }
    }
    by_stream
}

/// Newest migration first: sort by the version's earliest apply position, descending; rows of one version (and the same
/// change repeated in parallel streams) keep their order, so the first stream stays the one cited.
fn newest_first(v: &mut [Vec<String>], ver_col: usize, ord_col: usize) {
    let mut first: HashMap<String, i64> = HashMap::new();
    for m in v.iter() {
        let o = m[ord_col].parse::<i64>().unwrap_or(0);
        let e = first.entry(m[ver_col].clone()).or_insert(o);
        *e = (*e).min(o);
    }
    v.sort_by_key(|m| std::cmp::Reverse(first.get(&m[ver_col]).copied().unwrap_or(0)));
}

const SECTIONS: &[&str] = &["columns", "transient", "constraints", "unique", "fk", "index", "migrations", "readers", "writers", "endpoints"];

pub fn table(ix: &Index, arg: &str, out: &mut Out) {
    let mut r = Resp::new("table", arg);
    let c = &ix.conn;
    let toks = crate::query::shell_split(arg);
    let mut name = String::new();
    let mut want: Vec<&str> = vec![];
    let mut show_all = false;
    for t in &toks {
        let tl = t.to_lowercase();
        if tl == "--all" {
            show_all = true;
        } else if SECTIONS.contains(&tl.as_str()) && !name.is_empty() {
            want.push(SECTIONS.iter().find(|s| **s == tl).unwrap());
        } else if name.is_empty() {
            name = t.clone();
        } else {
            name.push(' ');
            name.push_str(t);
        }
    }
    let (tname, colq) = match name.split_once('.') {
        Some((a, b)) if !b.is_empty() && !b.contains('/') => (a.to_string(), Some(b.to_lowercase())),
        _ => (name.clone(), None),
    };
    let tbl = match resolve_table(ix, &tname) {
        Ok(t) => t,
        Err(sug) => {
            r.head.push(format!("== table {}: none (no such table in migrations, entities or data access)", tname.trim()));
            if sug.is_empty() {
                r.foot.push("no similar table names either; `aix sql \"SELECT DISTINCT tbl FROM entities\"` lists the mapped ones".to_string());
            } else {
                r.foot.push("did you mean:".to_string());
                for s in sug {
                    r.foot.push(format!("  {s}"));
                }
            }
            r.finish(out);
            return;
        }
    };
    let all = want.is_empty();
    let has = |s: &str| all || want.contains(&s);
    let ent = entity_of_table(c, &tbl);
    let cols_e: Vec<Vec<String>> = rows(c, "SELECT field, col, ty, nullable, transient, pk, rel, flags, file, line, inherited, entity FROM entity_columns WHERE tbl=? ORDER BY file, line", &[&tbl]);
    let streams = replay(c, &tbl);
    // the stream that best matches the entity columns is the table's primary schema
    let ecols: BTreeSet<String> = cols_e.iter().filter(|x| !x[1].is_empty()).map(|x| x[1].clone()).collect();
    // a schema dump (Rails db/schema.rb, db/structure.sql) is the database as it stands: it wins over replaying the
    // migrations next to it (which may skip raw SQL, data fixes, or squashed history)
    let dump = |cs: &Vec<DbCol>| !cs.is_empty() && cs.iter().all(|x| x.file.ends_with("db/schema.rb") || x.file.ends_with("db/structure.sql"));
    let mut primary = String::new();
    let mut best = (false, 0usize, 0usize);
    for (k, cs) in &streams {
        let sc = (dump(cs), cs.iter().filter(|x| ecols.contains(&x.name)).count(), cs.len());
        if primary.is_empty() || sc > best {
            primary = k.clone();
            best = sc;
        }
    }
    let dbcols: Vec<DbCol> = streams.get(&primary).cloned().unwrap_or_default();
    let created = rows(c, "SELECT file, line, version FROM migrations WHERE tbl=? AND op='create' AND obj='table' ORDER BY ord LIMIT 1", &[&tbl]).into_iter().next();
    // a table with no entity is only "unmapped" when we understood the repo's ORM: Python models whose table could
    // not be determined, or Python code with migrations but no model parsed at all
    let orm_unparsed = ent.is_none()
        && (!rows(c, "SELECT 1 FROM entities WHERE orm='sqlalchemy' AND tbl='' LIMIT 1", &[]).is_empty()
            || (rows(c, "SELECT 1 FROM entities LIMIT 1", &[]).is_empty()
                && !rows(c, "SELECT 1 FROM files WHERE lang='python' LIMIT 1", &[]).is_empty()
                && !streams.is_empty()));
    let mut head = format!("== table {tbl}");
    if let Some(e) = &ent {
        head.push_str(&format!("  (entity {} {}:{}, {})", e.0, e.1, e.2, e.3));
    } else if orm_unparsed {
        head.push_str("  (no ORM entity found; ORM model not parsed (SQLAlchemy 2.0?) so field mapping is unknown)");
    } else {
        head.push_str("  (no ORM entity maps it)");
    }
    r.head.push(head);
    let hdr = colq.is_none() && (all || has("columns"));
    if let Some(e) = &ent {
        let ec = entity_cite(c, &tbl).map(|x| vec![x]).unwrap_or_default();
        r.ans_cites("entity", format!("entity   {}  {}:{} ({})", e.0, e.1, e.2, e.3), if hdr { ec } else { vec![] }, "exact");
    }
    if let Some(cr) = &created {
        r.ans_cites("migration", format!("created  {}:{} (version {})", cr[0], cr[1], cr[2]), if hdr { vec![cite(&cr[0], cr[1].parse().unwrap_or(0))] } else { vec![] }, "exact");
    }
    if let Some(cq) = &colq {
        // one column: its migration history and its entity field
        let mut hist = rows(c, "SELECT file, line, version, op, obj, detail, ord FROM migrations WHERE tbl=? AND col=? ORDER BY ord, line", &[&tbl, cq]);
        newest_first(&mut hist, 2, 6);
        if hist.is_empty() && !cols_e.iter().any(|x| x[1] == *cq) {
            r.ans_cites("note", format!("column {tbl}.{cq}: none in migrations or entity fields"), vec![], "exact");
            let cn: Vec<String> = dbcols.iter().map(|x| x.name.clone()).chain(ecols.iter().cloned()).filter(|n| query::edit_distance(n, cq) <= 3 || n.contains(cq.as_str())).collect::<BTreeSet<_>>().into_iter().take(5).collect();
            if !cn.is_empty() {
                r.foot.push(format!("did you mean column: {}", cn.join(", ")));
            }
            r.finish(out);
            return;
        }
        let mut seen: HashSet<(String, String, String, String)> = HashSet::new();
        r.ans_cites("summary", format!("-- {tbl}.{cq} migration history ({} entries, newest first)", hist.len()), vec![], "exact");
        for h in &hist {
            let key = (h[2].clone(), h[3].clone(), h[4].clone(), h[5].clone());
            if !seen.insert(key) {
                continue;
            }
            let dup: Vec<&Vec<String>> = hist.iter().filter(|o| o[2] == h[2] && o[3] == h[3] && o[4] == h[4] && o[5] == h[5] && o[0] != h[0]).collect();
            let also = if dup.is_empty() { String::new() } else { format!("  (same change also in {})", dup.iter().map(|d| format!("{}:{}", d[0], d[1])).collect::<Vec<_>>().join(", ")) };
            r.ans_cites("migration", format!("  v{} {} {} {}  {}:{}{also}", h[2], h[3], h[4], h[5], h[0], h[1]), vec![cite(&h[0], h[1].parse().unwrap_or(0))], "exact");
        }
        for x in cols_e.iter().filter(|x| x[1] == *cq) {
            r.ans_cites("entity", format!("  entity field {}.{} ({}{}{})  {}:{}", x[11], x[0], x[2], if x[3] == "0" { ", not null" } else { "" }, if x[5] == "1" { ", pk" } else { "" }, x[8], x[9]), vec![cite(&x[8], x[9].parse().unwrap_or(0))], "exact");
        }
        for f in rows(c, "SELECT file, line, to_tbl, to_col, src FROM fks WHERE from_tbl=? AND from_col=?", &[&tbl, cq]) {
            r.ans_cites("fk", format!("  fk -> {}({})  {}:{} [{}]", f[2], f[3], f[0], f[1], f[4]), vec![cite(&f[0], f[1].parse().unwrap_or(0))], "exact");
        }
        r.finish(out);
        return;
    }
    let lim = out.limit.max(40);
    if has("columns") {
        let mapped: Vec<&Vec<String>> = cols_e.iter().filter(|x| !x[1].is_empty()).collect();
        let transient: Vec<&Vec<String>> = cols_e.iter().filter(|x| x[4] == "1").collect();
        let db_names: BTreeSet<&str> = dbcols.iter().map(|x| x.name.as_str()).collect();
        let only_db: Vec<&DbCol> = dbcols.iter().filter(|x| !ecols.contains(&x.name)).collect();
        let only_ent: Vec<&&Vec<String>> = mapped.iter().filter(|x| !db_names.contains(x[1].as_str()) && !db_names.is_empty()).collect();
        let no_ent = ent.is_none();
        let ent_note = if orm_unparsed { "ORM model not parsed (SQLAlchemy 2.0?)" } else { "no entity" };
        r.ans_cites(
            "summary",
            if no_ent {
                format!(
                    "-- columns: {} in the schema{} ({ent_note}: entity comparison skipped)",
                    dbcols.len(),
                    if streams.len() > 1 { format!(" ({} migration streams; showing {})", streams.len(), if primary.is_empty() { "-" } else { &primary }) } else { String::new() },
                )
            } else {
            format!(
                "-- columns: {} in the schema{}, {} mapped by the entity, {} transient fields (not columns){}",
                dbcols.len(),
                if streams.len() > 1 { format!(" ({} migration streams; showing {})", streams.len(), if primary.is_empty() { "-" } else { &primary }) } else { String::new() },
                mapped.len(),
                transient.len(),
                if only_db.is_empty() && only_ent.is_empty() { String::new() } else { format!("; {} schema-only, {} entity-only", only_db.len(), only_ent.len()) }
            )},
            vec![],
            "exact",
        );
        let first = mapped.first().map(|x| (x[8].clone(), x[9].parse::<i64>().unwrap_or(0)));
        let lastl = mapped.last().map(|x| x[9].parse::<i64>().unwrap_or(0)).unwrap_or(0);
        let mut first_cite = true;
        let dbmap: HashMap<&str, &DbCol> = dbcols.iter().map(|x| (x.name.as_str(), x)).collect();
        let mut names: Vec<String> = vec![];
        for x in &mapped {
            if !names.contains(&x[1]) {
                names.push(x[1].clone());
            }
        }
        for x in only_db.iter() {
            names.push(x.name.clone());
        }
        // columns that exist in only some migration streams (e.g. tenant-only): shown and flagged
        let mut extra: HashMap<String, &DbCol> = HashMap::new();
        let mut present: HashMap<String, Vec<String>> = HashMap::new();
        if streams.len() > 1 {
            for (k, cs) in &streams {
                let short = k.rsplit('/').next().unwrap_or(k).to_string();
                for x in cs {
                    present.entry(x.name.clone()).or_default().push(short.clone());
                    if *k != primary && !names.contains(&x.name) && !extra.contains_key(&x.name) {
                        extra.insert(x.name.clone(), x);
                    }
                }
            }
            let mut ex: Vec<String> = extra.keys().cloned().collect();
            ex.sort();
            names.extend(ex);
        }
        for (shown, n) in names.iter().enumerate() {
            if shown >= lim {
                r.foot.push(format!("(+{} more columns: `aix table {tbl} columns --limit {}`)", names.len() - shown, names.len()));
                r.truncated = true;
                break;
            }
            let e = mapped.iter().find(|x| x[1] == *n);
            let d = dbmap.get(n.as_str()).or_else(|| extra.get(n.as_str()));
            let ty = d.map(|d| d.detail.clone()).or_else(|| e.map(|e| format!("{}{}", e[2], if e[3] == "0" && e[5] != "1" { " not null" } else { "" }))).unwrap_or_default();
            let mut flags = vec![];
            if let Some(p) = present.get(n.as_str()) {
                if p.len() < streams.len() {
                    flags.push(format!("only in {}", p.join("+")));
                }
            }
            if let Some(e) = e {
                if e[5] == "1" {
                    flags.push("pk".to_string());
                }
                if !e[7].is_empty() {
                    flags.push(e[7].clone());
                }
                if !e[6].is_empty() {
                    flags.push(format!("-> {}", e[6]));
                }
            }
            let src = match (e, d) {
                (Some(e), Some(d)) => format!("entity {}.{} {}:{} | schema {}:{}", e[11], e[0], base(&e[8]), e[9], base(&d.file), d.line),
                (Some(e), None) => format!("entity {}.{} {}:{} | not in migrations", e[11], e[0], base(&e[8]), e[9]),
                (None, Some(d)) if no_ent => format!("schema {}:{}", base(&d.file), d.line),
                (None, Some(d)) => format!("schema only: no entity field maps it | {}:{}", base(&d.file), d.line),
                _ => String::new(),
            };
            let text = format!("  {n}  {}{}  {src}", ty, if flags.is_empty() { String::new() } else { format!("  [{}]", flags.join(", ")) });
            if first_cite {
                first_cite = false;
                let mut cs = vec![];
                if let Some((f, l)) = &first {
                    cs.push(Cite { file: f.clone(), line: *l, end: lastl.max(*l) });
                }
                r.ans_cites("column", text, cs, "exact");
            } else {
                r.ans_cites("column", text, vec![], "exact");
            }
        }
        if !transient.is_empty() {
            let names: Vec<String> = transient.iter().map(|x| format!("{} ({}:{})", x[0], base(&x[8]), x[9])).collect();
            let l0: i64 = transient.first().map(|x| x[9].parse().unwrap_or(0)).unwrap_or(0);
            let l1: i64 = transient.last().map(|x| x[9].parse().unwrap_or(0)).unwrap_or(0);
            r.ans_cites("transient", format!("-- transient entity fields (@Transient, not columns): {}", names.join(", ")), vec![Cite { file: transient[0][8].clone(), line: l0, end: l1 }], "exact");
        }
        for rel in cols_e.iter().filter(|x| x[1].is_empty() && x[4] != "1") {
            let _ = rel;
        }
    } else if has("transient") {
        let transient: Vec<&Vec<String>> = cols_e.iter().filter(|x| x[4] == "1").collect();
        for x in transient {
            r.ans_cites("transient", format!("  transient {}.{} ({})  {}:{}", x[11], x[0], x[2], x[8], x[9]), vec![cite(&x[8], x[9].parse().unwrap_or(0))], "exact");
        }
    }
    if has("constraints") || has("unique") || has("fk") || has("index") {
        // replay in apply order: a later DROP INDEX / DROP CONSTRAINT removes what an earlier migration created (an index
        // dropped by name carries no table: it matches the CREATE INDEX of that name)
        let all_cons = rows(c, "SELECT file, line, version, obj, col, detail, op FROM migrations WHERE (tbl=? OR (tbl='' AND op='drop' AND obj='index')) AND obj IN ('constraint','index') ORDER BY ord, line", &[&tbl]);
        let strip = |d: &str| d.replace(" (conditional, in DO block)", "");
        let mut cons: Vec<Vec<String>> = vec![];
        for x in all_cons {
            if x[6] == "drop" {
                let d = strip(&x[5]);
                if let Some(n) = d.strip_prefix("drop index ") {
                    let pat = format!("index {n}(");
                    cons.retain(|y| !(y[3] == "index" && y[5].contains(&pat)));
                } else if let Some(n) = d.strip_prefix("drop constraint ") {
                    let pat = format!(" constraint {n}");
                    cons.retain(|y| !strip(&y[5]).ends_with(&pat));
                } else if d == "drop primary key" {
                    cons.retain(|y| !y[5].starts_with("primary key"));
                } else if let Some(n) = d.strip_prefix("drop foreign key ") {
                    let pat = format!(" constraint {n}");
                    cons.retain(|y| !strip(&y[5]).ends_with(&pat));
                }
                continue;
            }
            cons.push(x);
        }
        // foreign keys are listed once, from the fks table (which also has the entity-declared ones)
        cons.retain(|x| {
            (has("constraints") && x[3] == "constraint" && !(has("fk") && x[5].starts_with("fk(")))
                || (has("unique") && x[5].starts_with("unique"))
                || (has("index") && x[3] == "index")
                || (all && x[3] == "index")
        });
        let mut seen: HashSet<String> = HashSet::new();
        let want_unique_only = want == ["unique"];
        let mut n = 0;
        r.ans_cites("summary", "-- constraints and indexes".to_string(), vec![], "exact");
        for x in &cons {
            if want_unique_only && !x[5].contains("unique") {
                continue;
            }
            if !seen.insert(format!("{}{}{}", x[3], x[4], x[5])) {
                continue;
            }
            if n >= lim {
                r.foot.push(format!("(+ more constraints and indexes: `aix table {tbl} constraints index --limit {}`)", cons.len()));
                r.truncated = true;
                break;
            }
            n += 1;
            r.ans_cites("constraint", format!("  {} {}  v{}  {}:{}", x[3], x[5], x[2], x[0], x[1]), vec![cite(&x[0], x[1].parse().unwrap_or(0))], "exact");
        }
        if n == 0 {
            r.ans_cites("note", "  none".to_string(), vec![], "exact");
        }
        if has("fk") || all {
            for f in rows(c, "SELECT file, line, from_col, to_tbl, to_col, src FROM fks WHERE from_tbl=? ORDER BY file, line LIMIT 40", &[&tbl]).iter().take(lim) {
                let act = fk_on_delete(ix, &f[0], f[1].parse().unwrap_or(0)).map(|a| format!(" on delete {}", a.to_lowercase())).unwrap_or_default();
                r.ans_cites("fk", format!("  fk {} -> {}{}{act}  {}:{} [{}]", f[2], f[3], if f[4].is_empty() { String::new() } else { format!("({})", f[4]) }, f[0], f[1], f[5]), if want == ["fk"] { vec![cite(&f[0], f[1].parse().unwrap_or(0))] } else { vec![] }, "exact");
            }
            let refd = rows(c, "SELECT from_tbl, from_col, file, line FROM fks WHERE to_tbl=? ORDER BY from_tbl LIMIT 40", &[&tbl]);
            if !refd.is_empty() {
                let names: BTreeSet<String> = refd.iter().map(|x| format!("{}.{}", x[0], x[1])).collect();
                r.ans_cites("fk", format!("  referenced by {} foreign keys: {}", refd.len(), names.iter().take(12).cloned().collect::<Vec<_>>().join(", ")), vec![], "exact");
            }
        }
    }
    if has("migrations") {
        let mut ms = rows(c, "SELECT file, line, version, op, obj, col, detail, ord FROM migrations WHERE tbl=? AND obj IN ('table','column','data','view','function','trigger') ORDER BY ord, line", &[&tbl]);
        // newest first: the recent changes are the ones asked about, and a long baseline is cut by the limit, not the tail
        newest_first(&mut ms, 2, 7);
        let mut seen: HashSet<(String, String, String, String, String)> = HashSet::new();
        r.ans_cites("summary", format!("-- migration history ({} changes, newest first; identical changes in parallel streams are shown once)", ms.len()), vec![], "exact");
        let mut n = 0;
        for m in &ms {
            if !seen.insert((m[2].clone(), m[3].clone(), m[4].clone(), m[5].clone(), m[6].clone())) {
                continue;
            }
            if n >= lim {
                r.foot.push(format!("(+ more migration entries: `aix table {tbl} migrations --limit {}`)", ms.len()));
                r.truncated = true;
                break;
            }
            n += 1;
            let dup: Vec<&Vec<String>> = ms.iter().filter(|o| o[2] == m[2] && o[3] == m[3] && o[4] == m[4] && o[5] == m[5] && o[6] == m[6] && o[0] != m[0]).collect();
            let also = if dup.is_empty() { String::new() } else { format!("  (also {})", dup.iter().map(|d| base(&d[0]).to_string()).collect::<Vec<_>>().join(", ")) };
            r.ans_cites("migration", format!("  v{} {} {} {}  {}:{}{}{also}", m[2], m[3], m[4], m[5], m[0], m[1], if m[6].is_empty() { String::new() } else { format!("  {}", m[6]) }), vec![cite(&m[0], m[1].parse().unwrap_or(0))], "exact");
        }
    }
    if has("readers") || has("writers") || has("endpoints") {
        for rw in ["w", "r"] {
            if (rw == "w" && !has("writers") && !has("endpoints")) || (rw == "r" && !has("readers") && !has("endpoints")) {
                continue;
            }
            let acc = rows(c, "SELECT symbol, file, line, via, conf, sline FROM data_access WHERE tbl=? AND rw=? ORDER BY file, line", &[&tbl, &rw]);
            let word = if rw == "w" { "writers" } else { "readers" };
            if has(word) {
                // no data-access rows anywhere: the stack's ORM is not extracted (JPA / Spring Data, Panache, Prisma
                // are); an empty section would read as "nobody writes this table"
                let none_at_all = acc.is_empty() && one(c, "SELECT count(*) FROM data_access", &[]).is_some_and(|x| x[0] == "0");
                if none_at_all {
                    r.ans_cites("summary", format!("-- {word}: not known (data access is extracted for JPA / Spring Data, Panache and Prisma only; this repo has none: `aix grep` the model or table name)"), vec![], "name");
                } else {
                    r.ans_cites("summary", format!("-- {word} ({} symbols)", acc.len()), vec![], "exact");
                }
                for a in acc.iter().take(lim) {
                    r.ans_cites("access", format!("  {}  {}:{} via {} ({})", a[0], a[1], a[2], a[3], a[4]), vec![cite(&a[1], a[2].parse().unwrap_or(0))], conf_static(&a[4]));
                }
                if acc.len() > lim {
                    r.foot.push(format!("(+{} more {word}: `aix table {tbl} {word} --limit {}`)", acc.len() - lim, acc.len()));
                    r.truncated = true;
                }
                // SQL functions defined in migrations whose body reads / writes the table
                let mark = format!(" {rw}:");
                let mut fns: Vec<(String, String, String)> = vec![];
                for m in rows(c, "SELECT tbl, file, line, detail FROM migrations WHERE obj='function' ORDER BY ord DESC, file DESC, line DESC", &[]) {
                    let hit = m[3].split_whitespace().any(|p| p.strip_prefix(&mark[1..]).is_some_and(|l| l.split(',').any(|x| x == tbl)));
                    if hit && !fns.iter().any(|f| f.0 == m[0]) {
                        fns.push((m[0].clone(), m[1].clone(), m[2].clone()));
                    }
                }
                for (n, f, l) in fns.iter().take(lim) {
                    r.ans_cites("access", format!("  sql function {n}  {f}:{l}"), vec![cite(f, l.parse().unwrap_or(0))], "exact");
                }
                if rw == "w" {
                    // a parent's delete removes (or nulls) these rows too: its writers write this table
                    for (parent, action) in cascade_parents(ix, &tbl) {
                        r.ans_cites("access", format!("  via fk {} from {parent}: every delete of a {parent} row (aix table {parent} writers)", if action == "CASCADE" { "cascade".to_string() } else { format!("on delete {}", action.to_lowercase()) }), vec![], "exact");
                    }
                }
            }
            if has("endpoints") {
                let mut eps = endpoints_for_table(c, &tbl, rw, 10_000, show_all);
                if rw == "w" {
                    eps.extend(cascade_endpoints(ix, &tbl, show_all));
                }
                let mut seen_ep: HashSet<(String, String, i64)> = HashSet::new();
                eps.retain(|e| seen_ep.insert((e.0.clone(), e.1.clone(), e.2)));
                let main: HashSet<String> = if show_all { endpoints_for_table(c, &tbl, rw, 10_000, false).into_iter().map(|e| e.0).collect() } else { HashSet::new() };
                let hidden = if show_all { 0 } else { endpoints_for_table(c, &tbl, rw, 10_000, true).len().saturating_sub(eps.len()) };
                r.ans_cites("summary", format!("-- endpoints that {} {tbl} ({}; via the materialized call-graph traces)", if rw == "w" { "write" } else { "read" }, eps.len()), vec![], "exact");
                if hidden > 0 {
                    r.foot.push(format!("({hidden} more endpoints {} {tbl} only as an auth/tenant-guard side effect; --all shows them)", if rw == "w" { "write" } else { "read" }));
                }
                // 30 at most beside the other sections; the endpoints section alone takes --limit
                let cap = if want == ["endpoints"] { lim } else { lim.min(30) };
                for (key, file, line, via) in eps.iter().take(cap) {
                    let roles = endpoint_roles(c, file, *line);
                    let tag = if show_all && !main.contains(key) { " (auth side effect)" } else { "" };
                    r.ans_cites("endpoint", format!("  {key}  {file}:{line}  roles {}  via {via}{tag}", roles_txt(&roles)), vec![decl_cite(c, file, *line)], "exact");
                }
                if eps.len() > cap {
                    r.foot.push(format!("(+{} more endpoints: `aix table {tbl} endpoints --limit {}`)", eps.len() - cap, eps.len()));
                    r.truncated = true;
                }
            }
        }
    }
    // migration files the index could not read: the history above may be missing changes
    if let Some(sk) = ix.meta("skipped") {
        let miss: Vec<String> = sk
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter(|(_, p)| crate::walk::is_migration_path(p))
            .map(|(why, p)| format!("{p} ({why})"))
            .collect();
        if !miss.is_empty() {
            r.foot.push(format!("note: {} migration file(s) not indexed, so this history may be incomplete: {}{}", miss.len(), miss.iter().take(3).cloned().collect::<Vec<_>>().join(", "), if miss.len() > 3 { ", ..." } else { "" }));
        }
    }
    if all {
        r.foot.push(format!("(sections: aix table {tbl} <{}> | table {tbl}.<column> for one column's history)", SECTIONS.join("|")));
    }
    r.finish(out);
}

// ───────────────────────────── explain ─────────────────────────────

const FILLER: &[&str] = &[
    "button", "buttons", "page", "pages", "screen", "screens", "feature", "flow", "how", "does", "do", "work", "works", "working", "the", "a", "an", "of", "on", "in", "to", "for", "from",
    "trace", "explain", "menu", "ui", "and", "is", "are", "what", "which", "where", "when", "with", "by", "it", "its", "this", "that", "end", "database", "db", "roles", "role", "versus", "vs", "mismatch", "label",
    "click", "clicking", "user", "handled", "happens", "happen", "go", "goes", "through",
];

/// Words that make an explain question about who may do / see something: the answer is the roles comparison, not the feature.
/// Words that ask how a record moves through states (requested, approved, rejected, pending...).
const STATE_WORDS: &[&str] = &["flow", "flows", "lifecycle", "workflow", "transition", "transitions", "state", "states", "status", "request", "requests", "approve", "approval", "approvals", "approved", "reject", "pending"];

const ROLE_WORDS: &[&str] = &["role", "roles", "permission", "permissions", "access", "allowed", "authorization", "authorisation", "authorized", "authorised", "mismatch", "visible", "forbidden", "403", "rbac"];

/// Menu / route roles of every screen that calls an endpoint against the endpoint's own roles, mismatches flagged.
fn roles_compare(ix: &Index, eps: &[(i64, String, String, i64, i64)], cap: usize, r: &mut Resp) {
    let c = &ix.conn;
    for (_, key, file, line, _) in eps.iter().take(1) {
        let roles = endpoint_roles(c, file, *line);
        r.head.push(format!("== roles for {key}: menu and route roles of the screens that call it, against the endpoint roles"));
        r.ans_cites("endpoint", format!("endpoint {key}  {file}:{line}  roles {}", roles_txt(&roles)), vec![decl_cite(c, file, *line)], "exact");
        let clients = rows(
            c,
            "SELECT s.path, e.sline FROM layer_edges e JOIN files s ON s.rowid=e.sfid JOIN files d ON d.rowid=e.dfid WHERE e.kind='client_endpoint' AND d.path=? AND e.dline=? ORDER BY s.path, e.sline",
            &[file, line],
        );
        let mut routes: Vec<(String, String, i64)> = vec![];
        for cl in &clients {
            for (_, route, rfile, rline) in ui_up(ix, (cl[0].clone(), cl[1].parse().unwrap_or(0)), 4) {
                if !routes.iter().any(|x| x.0 == route) {
                    routes.push((route, rfile, rline));
                }
            }
        }
        if routes.is_empty() {
            r.foot.push("no routed screen reaches this endpoint's client functions, so there is no menu or route roles to compare".into());
        }
        for (route, rfile, rline) in routes.iter().take(cap) {
            let Some((comp, _, _, rroles)) = route_info(c, route) else { continue };
            r.ans_cites("route", format!("route    {route} -> {comp}  {rfile}:{rline}  roles {}", rroles_txt(&rroles)), vec![cite(rfile, *rline)], "exact");
            let mut effective = rroles.clone();
            if let Some((label, mroles, mf, ml)) = menu_of(c, route) {
                r.ans_cites("menu", format!("menu     \"{label}\"  {mf}:{ml}  roles {}", rroles_txt(&mroles)), vec![cite(&mf, ml)], "exact");
                if mroles != rroles && !mroles.is_empty() {
                    r.ans_cites("roles", format!("  mismatch: menu roles ({}) differ from the route roles ({})", mroles, if rroles.is_empty() { "none declared" } else { &rroles }), vec![], "exact");
                }
                if effective.is_empty() {
                    effective = mroles;
                }
            }
            match role_gap(&effective, &roles, true) {
                Some(g) if g.contains("role gap") => r.ans_cites("roles", format!("  mismatch: {g}"), vec![], "exact"),
                Some(g) => r.ans_cites("roles", format!("  no role gap (every role the screen admits is allowed); {g}"), vec![], "exact"),
                None => r.ans_cites("roles", "  no mismatch: the screen and the endpoint admit the same roles".into(), vec![], "exact"),
            }
        }
        if routes.len() > cap {
            r.foot.push(format!("(+{} more screens; add --all)", routes.len() - cap));
            r.truncated = true;
        }
    }
}

pub fn explain(ix: &Index, arg: &str, out: &mut Out) {
    let all = arg.split_whitespace().any(|t| t == "--all");
    let arg = &arg.split_whitespace().filter(|t| *t != "--all").collect::<Vec<_>>().join(" ");
    let mut r = Resp::new("explain", arg);
    let c = &ix.conn;
    let q = arg.trim().trim_matches('"').to_string();
    // the question's shape sets the answer's size: a roles / menu question gets the roles comparison, anything else the
    // feature; `--all` is always the full feature
    let roles_q = !all && q.split(|ch: char| !ch.is_alphanumeric()).any(|w| ROLE_WORDS.contains(&w.to_lowercase().as_str()));
    let tables_cap = if all { 12 } else { 4 };
    // questions about a request / approval / lifecycle also get the state flow of the endpoint they land on
    let flow_q = q.split(|ch: char| !ch.is_alphanumeric()).any(|w| STATE_WORDS.contains(&w.to_lowercase().as_str()));
    let words: Vec<String> = ident_words(&q).into_iter().filter(|w| w.len() > 1 || w.chars().all(char::is_numeric)).collect();
    let content: Vec<String> = words.iter().filter(|w| !FILLER.contains(&w.as_str())).cloned().collect();
    if content.is_empty() && !q.contains('/') {
        r.head.push(format!("== explain {q}: give feature words (a menu label, a route, an endpoint or what the screen does)"));
        r.finish(out);
        return;
    }
    // 1. explicit route path in the question
    let mut route: Option<(String, String)> = None; // (path, how)
    let mut consumed: HashSet<String> = HashSet::new();
    for t in q.split_whitespace() {
        let t = t.trim_matches(|ch: char| ch == '"' || ch == ',' || ch == '.' || ch == '?' || ch == ')' || ch == '(');
        if t.starts_with('/') && t.len() > 1 {
            let p = format!("/{}", t.trim_matches('/'));
            if !rows(c, "SELECT 1 FROM routes WHERE path=? LIMIT 1", &[&p]).is_empty() {
                route = Some((p.clone(), format!("route path {p}")));
                consumed.extend(ident_words(&p));
                break;
            }
        }
    }
    // 2. menu label / route component by words: every candidate flow is scored by how many of the question's words it covers,
    // then by how many roles can reach it (a flow many roles use beats an admin-only designer page); a close
    // second candidate is shown too
    let mut alt: Option<String> = None;
    if route.is_none() {
        // roles reaching a flow: the roles of every route sharing its path up to the first `:param`
        let base_of = |p: &str| -> String { p.split('/').take_while(|seg| !seg.starts_with(':')).collect::<Vec<_>>().join("/") };
        let reach = |path: &str| -> (usize, String) {
            let b = base_of(path);
            let mut roles: BTreeSet<String> = BTreeSet::new();
            let mut open = false;
            for r2 in rows(c, "SELECT path, roles FROM routes WHERE redirect='' ", &[]) {
                if base_of(&r2[0]) == b {
                    if r2[1].is_empty() {
                        open = true;
                    }
                    roles.extend(r2[1].split(',').filter(|x| !x.is_empty()).map(str::to_string));
                }
            }
            (if open { 999 } else { roles.len() }, roles.into_iter().collect::<Vec<_>>().join(","))
        };
        // (score, base path, shown path, how, label words)
        let mut cands: Vec<(usize, String, String, String, usize)> = vec![];
        for m in rows(c, "SELECT label, href, keywords FROM menu WHERE href<>''", &[]) {
            let lw = ident_words(&m[0]);
            let kw = ident_words(&m[2]);
            let hits = content.iter().filter(|w| lw.iter().any(|l| l == *w || stem(l) == stem(w))).count();
            let khits = content.iter().filter(|w| kw.iter().any(|l| l == *w)).count();
            let score = hits * 3;
            let p = m[1].split('?').next().unwrap_or("").to_string();
            if hits > 0 && (hits == content.len() || content.len() > 2 && hits * 2 > content.len()) && !rows(c, "SELECT 1 FROM routes WHERE path=? LIMIT 1", &[&p]).is_empty() {
                cands.push((score, base_of(&p), p, format!("menu \"{}\"", m[0]), (khits * 100).saturating_sub(lw.len()) + 1000));
            }
        }
        for r2 in rows(c, "SELECT DISTINCT path, COALESCE(component,'') FROM routes WHERE redirect='' AND path<>'/' AND page_file<>''", &[]) {
            let mut hay = ident_words(&r2[0]);
            hay.extend(ident_words(&r2[1]));
            let hits = content.iter().filter(|w| hay.iter().any(|h| h == *w || stem(h) == stem(w))).count();
            // every word, or (3+ words, as for menu labels) most of them: a full match still scores higher
            if !content.is_empty() && (hits == content.len() || content.len() > 2 && hits * 2 > content.len()) {
                cands.push((hits * 3, base_of(&r2[0]), r2[0].clone(), format!("route/component {}", r2[1]), 1000usize.saturating_sub(hay.len())));
            }
        }
        // one entry per flow: the best score, then the shortest path
        let mut flows: Vec<(usize, usize, String, String, String, usize)> = vec![]; // score, roles, path, how, roles text, labelwords
        for (score, bp, p, how, lw) in cands {
            let (nr, rt) = reach(&p);
            match flows.iter_mut().find(|f| base_of(&f.2) == bp) {
                Some(f) => {
                    if (score, std::cmp::Reverse(p.len())) > (f.0, std::cmp::Reverse(f.2.len())) {
                        *f = (score, nr, p, how, rt, lw);
                    }
                }
                None => flows.push((score, nr, p, how, rt, lw)),
            }
        }
        flows.sort_by(|x, y| (y.0, y.1, y.5).cmp(&(x.0, x.1, x.5)));
        if let Some(best) = flows.first() {
            consumed.extend(ident_words(&best.3));
            consumed.extend(ident_words(&best.2));
            route = Some((best.2.clone(), best.3.clone()));
            if let Some(sec) = flows.get(1).filter(|s| s.0 + 1 >= best.0) {
                alt = Some(format!(
                    "   also matches (top 2): {} -> route {} (roles {}) vs chosen {} (roles {}); name the role or the page to pick the other",
                    sec.3,
                    sec.2,
                    if sec.4.is_empty() { "all".into() } else { short_roles_list(&sec.4) },
                    best.2,
                    if best.4.is_empty() { "all".into() } else { short_roles_list(&best.4) }
                ));
            }
        }
    }
    // 3. an endpoint by words
    if route.is_none() {
        let eps = rows(c, "SELECT k.key FROM trace_keys k WHERE k.kind='endpoint'", &[]);
        // (words matched, its word count, key): every word, or (3+ words) most of them; more words matched first
        let mut best: Option<(usize, usize, String)> = None;
        for e in eps {
            let ew = ident_words(&e[0]);
            let hits = content.iter().filter(|w| ew.iter().any(|x| x == *w || stem(x) == stem(w))).count();
            let enough = hits == content.len() || content.len() > 2 && hits * 2 > content.len();
            if content.len() >= 2 && hits > 0 && enough && best.as_ref().is_none_or(|b| (hits, std::cmp::Reverse(ew.len())) > (b.0, std::cmp::Reverse(b.1))) {
                best = Some((hits, ew.len(), e[0].clone()));
            }
        }
        if let Some((_, _, key)) = best {
            r.head.push(format!("== explain \"{q}\": resolved to endpoint {key}"));
            let mut sub = Resp::new("explain", arg);
            sub.head = vec![];
            if let Some(eps) = ep_lookup_key(ix, &key) {
                if roles_q {
                    roles_compare(ix, &eps, 6, &mut r);
                    r.finish(out);
                    return;
                }
                trace_endpoint_up(ix, &eps, 2, false, &mut r);
                trace_endpoint_down(ix, &eps, &TraceOpts { up: false, sites: false, body: false, depth: 6, words: vec![], target: key.clone(), all: false, tables: tables_cap }, 3, &mut r);
            }
            // the state flow already carries the answer: fewer doc hits unless --all
            explain_docs(ix, &q, &[], if all { out.limit } else { out.limit.min(3) }, all, &mut r);
            r.finish(out);
            return;
        }
    }
    // a loosely matched route must be about the question: every content word, or at least two distinct ones, appears in
    // its path, component, menu label or the endpoints it reaches (vague words must not land on an unrelated page)
    let about = |path: &str, component: &str| -> bool {
        let mut hay: Vec<String> = ident_words(path);
        hay.extend(ident_words(component));
        if let Some(m) = menu_of(c, path) {
            hay.extend(ident_words(&m.0));
        }
        for e in rows(c, "SELECT DISTINCT p.tbl FROM trace_paths p JOIN trace_keys k ON k.id=p.tid AND k.kind='route' WHERE k.key=? AND p.layer='endpoint'", &[&path]) {
            hay.extend(ident_words(&e[0]));
        }
        let matched: BTreeSet<&String> = content.iter().filter(|w| hay.iter().any(|h| h == *w || stem(h) == stem(w))).collect();
        matched.len() == content.len() || matched.len() >= 2
    };
    if route.is_none() {
        let rs = query::resolve_route(ix, &content.join(" "));
        if let Some(rt) = rs.iter().find(|rt| about(&rt["path"], &rt["component"])) {
            consumed.extend(ident_words(&rt["path"]));
            consumed.extend(ident_words(&rt["component"]));
            route = Some((rt["path"].clone(), format!("route/component {}", rt["component"])));
        }
    }
    // 4. FTS fallback to a route
    if route.is_none() {
        let hits = query::fts(ix, &content.join(" "), Some(&["menu", "route", "feature", "endpoint", "api"]), 5, false);
        for h in &hits {
            let cand = rows(c, "SELECT path, component FROM routes WHERE path=? OR page_file=? OR file=? LIMIT 1", &[&h.reference, &h.file, &h.file]);
            if let Some(p) = cand.first() {
                if !about(&p[0], &p[1]) {
                    continue;
                }
                route = Some((p[0].clone(), format!("search hit [{}] {}", h.kind, h.reference)));
                break;
            }
        }
    }
    let Some((path, how)) = route else {
        r.head.push(format!("== explain \"{q}\": no clear match (no menu label, route, endpoint or feature covers {}; try a screen name or a route path)", content.join(" + ")));
        let sug = query::did_you_mean(ix, &content.join(" "), 5);
        for (_, n, d) in sug {
            r.foot.push(format!("  did you mean {n}  {d}"));
        }
        explain_docs(ix, &q, &[], out.limit, all, &mut r);
        r.finish(out);
        return;
    };
    let focus: Vec<String> = content.iter().filter(|w| !consumed.iter().any(|c2| c2 == *w || stem(c2) == stem(w))).cloned().collect();
    r.head.push(format!("== explain \"{q}\": resolved via {how} -> route {path}"));
    if let Some(a) = alt {
        r.head.push(a);
    }
    trace_route(ix, &path, &focus, out.limit.min(6), roles_q, if focus.is_empty() { 0 } else { tables_cap }, flow_q, &mut r);
    if !roles_q {
        explain_docs(ix, &q, &[path.clone()], out.limit, all, &mut r);
    }
    r.finish(out);
}

fn short_roles_list(r: &str) -> String {
    query::short_roles_n(r, 4)
}

fn ep_lookup_key(ix: &Index, key: &str) -> Option<Vec<(i64, String, String, i64, i64)>> {
    let v = find_keys(&ix.conn, "endpoint", key);
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Related docs, findings and tests, from FTS5 over the stored entries and the findings / tests tables.
fn explain_docs(ix: &Index, q: &str, routes: &[String], limit: usize, all: bool, r: &mut Resp) {
    let c = &ix.conn;
    let n = limit.clamp(2, 5);
    let docs = query::fts(ix, q, Some(&["doc"]), n, false);
    if !docs.is_empty() {
        r.ans_cites("summary", format!("== docs ({})", docs.len()), vec![], "exact");
        for h in &docs {
            let line: i64 = h.line.parse().unwrap_or(0);
            r.ans_cites("doc", format!("  {}:{}  {}", h.file, h.line, aix_extract::text::clip(&h.text, 140)), vec![cite(&h.file, line)], "name");
        }
    }
    let (bugs, hidden_fixed) = query::filter_findings(ix, query::fts(ix, q, Some(&["bug", "commit"]), n * 3, false), all);
    let bugs: Vec<_> = bugs.into_iter().take(n).collect();
    if hidden_fixed > 0 {
        r.foot.push(format!("({hidden_fixed} already-fixed findings hidden; --all shows them)"));
    }
    if !bugs.is_empty() {
        r.ans_cites("summary", format!("== findings and fixes ({})", bugs.len()), vec![], "exact");
        for h in &bugs {
            let line: i64 = h.line.parse().unwrap_or(0);
            let loc = if h.file.is_empty() { h.reference.clone() } else { format!("{}:{}", h.file, h.line) };
            r.ans_cites("finding", format!("  {loc}  {}", aix_extract::text::clip(&h.text, 140)), if h.file.is_empty() { vec![] } else { vec![cite(&h.file, line)] }, "name");
        }
    }
    for p in routes.iter().take(1) {
        let sc = query::scenarios_for_route(ix, p);
        if !sc.is_empty() {
            r.ans_cites("summary", format!("== e2e scenarios visiting {p} ({})", sc.len()), vec![], "exact");
            for s in sc.iter().take(n) {
                r.ans_cites("test", format!("  {} {}  {}:{}  {}", s[0], s[1], s[2], s[3], aix_extract::text::clip(&s[4], 80)), vec![cite(&s[2], s[3].parse().unwrap_or(0))], "exact");
            }
        }
    }
    let _ = c;
}
