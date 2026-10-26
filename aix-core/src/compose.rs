//! Router composition across files. The framework extractors emit endpoints with router-local paths plus `ep:local`
//! and `ep:mount` bookkeeping notes (Express `app.use('/p', router)`, FastAPI `include_router`, Flask
//! `register_blueprint`, Django `include()`, chi `Mount`); this pass joins mount prefixes into the final `path`/`norm`,
//! expands Django `ANY` views into the methods their class or decorator serves, and marks endpoint files whose
//! path changed dirty so `trace` rebuilds them. Idempotent: it recomputes from the notes on every run.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use rusqlite::{params, Transaction};
use serde_json::Value;
use aix_extract::norm_path;

use crate::index::resolve_import;

type Key = (String, String); // (file, scope)

struct Local {
    key: Key,
    file: String,
    line: i64,
    #[allow(dead_code)]
    scope: String,
    local: String,
    method: String,
    handler: String,
    sub: bool,
    roles: Vec<String>,
}

struct Mount {
    file: String,
    lang: String,
    parent: String,
    prefix: String,
    child: String,
    src: String,
    roles: Vec<String>,
    mw: bool,
}

fn join(a: &str, b: &str) -> String {
    let mut s = format!("/{}/{}", a.trim_matches('/'), b.trim_matches('/'));
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    if s.len() > 1 {
        s = s.trim_end_matches('/').to_string();
    }
    s
}

/// File for a dotted Python module (relative `..x` from `from_file`, or absolute matched by path suffix).
pub fn module_file(from_file: &str, module: &str, files: &HashSet<String>) -> Option<String> {
    let dots = module.chars().take_while(|c| *c == '.').count();
    let rest = module.trim_start_matches('.').replace('.', "/");
    let cands = |base: &str| -> Vec<String> {
        let b = if base.is_empty() {
            rest.clone()
        } else if rest.is_empty() {
            base.to_string()
        } else {
            format!("{base}/{rest}")
        };
        vec![format!("{b}.py"), format!("{b}/__init__.py")]
    };
    if dots > 0 {
        let mut dir: Vec<&str> = from_file.split('/').collect();
        dir.pop();
        for _ in 1..dots {
            dir.pop();
        }
        return cands(&dir.join("/")).into_iter().find(|c| files.contains(c));
    }
    // absolute: try the full dotted path as a suffix, then drop leading components
    let parts: Vec<&str> = rest.split('/').collect();
    for skip in 0..parts.len() {
        let p = parts[skip..].join("/");
        let mut hits: Vec<&String> = files
            .iter()
            .filter(|f| {
                [format!("{p}.py"), format!("{p}/__init__.py")].iter().any(|s| *f == s || f.ends_with(&format!("/{s}")))
            })
            .collect();
        hits.sort_by_key(|f| std::cmp::Reverse(common_prefix(f, from_file)));
        if let Some(h) = hits.first() {
            return Some((*h).clone());
        }
    }
    None
}

fn common_prefix(a: &str, b: &str) -> usize {
    a.split('/').zip(b.split('/')).take_while(|(x, y)| x == y).count()
}

fn pick_scope(scopes: &BTreeMap<String, ()>, child: &str) -> Option<String> {
    if scopes.contains_key(child) {
        return Some(child.to_string());
    }
    if scopes.len() == 1 {
        return scopes.keys().next().cloned();
    }
    for pref in ["router", "urlpatterns", "api_router", "bp", "blueprint", "app", "default"] {
        if scopes.contains_key(pref) {
            return Some(pref.to_string());
        }
    }
    scopes.keys().next().cloned()
}

pub fn run(tx: &Transaction) -> Result<()> {
    let notes: Vec<(String, i64, String, String)> = tx
        .prepare("SELECT file, line, kind, ref FROM notes WHERE kind IN ('ep:local','ep:mount','ep:view') ORDER BY file, line")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    if notes.is_empty() {
        return Ok(());
    }
    let files: HashSet<String> =
        tx.prepare("SELECT path FROM files")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    // FastAPI dependency aliases (`CurrentUser = Annotated[User, Depends(get_current_user)]`) by (file, name)
    let dep_alias: HashMap<(String, String), String> = tx
        .prepare("SELECT file, ref, text FROM notes WHERE kind='py:dep'")?
        .query_map([], |r| Ok(((r.get::<_, String>(0)?, r.get::<_, String>(1)?), r.get::<_, String>(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut locals: Vec<Local> = vec![];
    let mut mounts: Vec<Mount> = vec![];
    let mut views: HashMap<String, Vec<String>> = HashMap::new();
    let s = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    for (file, line, kind, r) in notes {
        let Ok(v) = serde_json::from_str::<Value>(&r) else { continue };
        match kind.as_str() {
            "ep:local" => {
                let scope = s(&v, "s");
                // `@module|name`: the router is defined in another module (`from app.main import bp`)
                let key = match scope.strip_prefix('@').and_then(|r| r.split_once('|')) {
                    Some((m, n)) => (module_file(&file, m, &files).unwrap_or_else(|| file.clone()), n.to_string()),
                    None => (file.clone(), scope.clone()),
                };
                let file2 = file.clone();
                locals.push(Local {
                    key,
                    file,
                    line,
                    scope,
                    local: s(&v, "l"),
                    method: s(&v, "m"),
                    handler: s(&v, "h"),
                    sub: v.get("sub").and_then(|x| x.as_bool()).unwrap_or(false),
                    roles: resolve_deps(
                        &file2,
                        v.get("r")
                            .and_then(|x| x.as_array())
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default(),
                        &dep_alias,
                        &files,
                    ),
                })
            }
            "ep:mount" => mounts.push(Mount {
                file,
                lang: s(&v, "lang"),
                parent: s(&v, "p"),
                prefix: s(&v, "pre"),
                child: s(&v, "c"),
                src: s(&v, "src"),
                roles: v
                    .get("roles")
                    .and_then(|x| x.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                mw: v.get("mw").and_then(|x| x.as_bool()).unwrap_or(false),
            }),
            _ => {
                let e = views.entry(s(&v, "c")).or_default();
                for m in v.get("m").and_then(|m| m.as_array()).into_iter().flatten().filter_map(|x| x.as_str()) {
                    if !e.iter().any(|x| x == m) {
                        e.push(m.to_string());
                    }
                }
            }
        }
    }
    // `$NAME` prefixes name a path constant (`API_V1_STR = "/api/v1"`)
    let mut consts: HashMap<String, String> = HashMap::new();
    for (n, v) in tx
        .prepare("SELECT name, vals FROM consts WHERE vals LIKE '[\"/%'")?
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .flatten()
    {
        if let Some(x) = serde_json::from_str::<Vec<String>>(&v).ok().and_then(|v| v.into_iter().next()) {
            consts.entry(n.rsplit('.').next().unwrap_or(&n).to_string()).or_insert(x);
        }
    }
    for m in mounts.iter_mut() {
        if let Some(name) = m.prefix.strip_prefix('$') {
            m.prefix = consts.get(name).cloned().unwrap_or_default();
        }
    }
    // scopes known per file
    let mut scopes: BTreeMap<String, BTreeMap<String, ()>> = BTreeMap::new();
    for l in &locals {
        scopes.entry(l.key.0.clone()).or_default().insert(l.key.1.clone(), ());
    }
    for m in &mounts {
        scopes.entry(m.file.clone()).or_default().insert(m.parent.clone(), ());
    }
    // child scope -> (parent scope, prefix); first mount wins (notes are ordered by file, line)
    let mut parent_of: HashMap<Key, (Key, String, Vec<String>, bool)> = HashMap::new();
    for m in &mounts {
        let target: Option<Key> = match m.lang.as_str() {
            "ts" => {
                if m.src.is_empty() {
                    Some((m.file.clone(), m.child.clone()))
                } else {
                    let t = resolve_import(&m.file, &m.src, &files);
                    scopes.get(&t).and_then(|sc| pick_scope(sc, &m.child)).map(|sc| (t, sc))
                }
            }
            "py" | "dj" => {
                if m.src.is_empty() {
                    Some((m.file.clone(), m.child.clone()))
                } else {
                    module_file(&m.file, &m.src, &files)
                        .and_then(|t| scopes.get(&t).and_then(|sc| pick_scope(sc, &m.child)).map(|sc| (t, sc)))
                }
            }
            "go" => {
                let dir = |f: &str| f.rsplit_once('/').map(|x| x.0.to_string()).unwrap_or_default();
                let md = dir(&m.file);
                let mut hits: Vec<Key> = vec![];
                for (f, sc) in &scopes {
                    for name in sc.keys() {
                        if (name == &m.child || name.ends_with(&format!(".{}", m.child)))
                            && (dir(f) == md || hits.is_empty())
                        {
                            hits.push((f.clone(), name.clone()));
                        }
                    }
                }
                hits.sort_by_key(|(f, _)| (dir(f) != md, f.clone()));
                hits.into_iter().next()
            }
            _ => None,
        };
        let Some(t) = target else { continue };
        let p = (m.file.clone(), m.parent.clone());
        if t != p {
            parent_of.entry(t).or_insert((p, m.prefix.clone(), m.roles.clone(), m.mw));
        }
    }
    // (prefix, auth hints along the chain, unclassified middleware on the chain, mounted at all)
    let chain_of = |k: &Key| -> (String, Vec<String>, bool, bool) {
        let mut out = String::new();
        let mut cur = k.clone();
        let (mut roles, mut mw, mut mounted) = (Vec::<String>::new(), false, false);
        for _ in 0..12 {
            match parent_of.get(&cur) {
                Some((p, pre, r, w)) => {
                    out = join(pre, &out);
                    for x in r {
                        if !roles.contains(x) {
                            roles.push(x.clone());
                        }
                    }
                    mw |= *w;
                    mounted = true;
                    cur = p.clone();
                }
                None => break,
            }
        }
        (if out == "/" { String::new() } else { out }, roles, mw, mounted)
    };
    tx.execute("DELETE FROM notes WHERE kind='ep:rel'", [])?;
    let mut rel = tx.prepare("INSERT INTO notes(file, line, kind, ref, text) VALUES(?,?,'ep:rel',?,'')")?;

    let mut sel = tx.prepare("SELECT rowid, method, path, roles FROM endpoints WHERE file=? AND line=? AND handler=?")?;
    let mut upr = tx.prepare("UPDATE endpoints SET roles=?1, roles_raw=?2 WHERE rowid=?3")?;
    let mut upd = tx.prepare("UPDATE endpoints SET path=?, norm=? WHERE rowid=?")?;
    let mut dirty = tx.prepare(
        "INSERT OR IGNORE INTO dm_dirty VALUES(?1, 0, COALESCE((SELECT rowid FROM files WHERE path=?1), 0))",
    )?;
    for l in &locals {
        let (pre, croles, cmw, mounted) = chain_of(&l.key);
        let full = join(&pre, &l.local);
        let norm = norm_path(&full);
        let rows: Vec<(i64, String, String, String)> = sel
            .query_map(params![l.file, l.line, l.handler], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        let mut changed = false;
        // several routes can share one line and handler (DRF `register`): tell them apart by the local path they end with
        let tail = join("", &l.local);
        let rows: Vec<(i64, String, String, String)> =
            rows.into_iter().filter(|r| tail == "/" || r.2.ends_with(&tail)).collect();
        let wanted: Vec<String> =
            if l.method == "ANY" { views.get(&l.handler).cloned().unwrap_or_default() } else { vec![] };
        for (id, method, path, roles) in &rows {
            if *method != l.method && !(l.method == "ANY" && wanted.iter().any(|w| w == method)) {
                continue;
            }
            if *path != full {
                upd.execute(params![full, norm, id])?;
                changed = true;
            }
            // `public` is only the extractor's default marker: it holds when the whole mount chain is visible
            // and adds no auth; mount-level auth hints are merged in; otherwise the auth is unknown (empty).
            let mut cur: Vec<String> = l.roles.clone();
            let was: Vec<String> = roles.split(',').filter(|x| !x.is_empty()).map(String::from).collect();
            if cur == ["public"] {
                if !croles.is_empty() {
                    cur = croles.clone();
                } else if cmw || (l.sub && !mounted) {
                    cur.clear();
                }
            } else if !cur.is_empty() || !croles.is_empty() {
                for x in &croles {
                    if !cur.contains(x) {
                        cur.push(x.clone());
                    }
                }
            }
            if cur != was {
                let j = serde_json::to_string(&cur).unwrap_or_default();
                upr.execute(params![cur.join(","), j, id])?;
                changed = true;
            }
        }
        if l.sub && !mounted {
            rel.execute(params![l.file, l.line, l.handler])?;
        }
        if !wanted.is_empty() {
            if let Some((any_id, _, _, _)) = rows.iter().find(|r| r.1 == "ANY") {
                let have: HashSet<&str> = rows.iter().map(|r| r.1.as_str()).collect();
                for m in &wanted {
                    if !have.contains(m.as_str()) {
                        tx.execute(
                            "INSERT INTO endpoints SELECT file, line, ?, path, norm, class, handler, roles, roles_raw FROM endpoints WHERE rowid=?",
                            params![m, any_id],
                        )?;
                    }
                }
                tx.execute("DELETE FROM endpoints WHERE rowid=?", params![any_id])?;
                changed = true;
            }
        }
        if changed {
            dirty.execute([&l.file])?;
        }
    }
    Ok(())
}

/// `dep:<module>|<name>` roles (a handler parameter typed by an imported alias): the alias's auth dependencies when
/// it injects any (then the endpoint is not public), else nothing.
fn resolve_deps(file: &str, roles: Vec<String>, alias: &HashMap<(String, String), String>, files: &HashSet<String>) -> Vec<String> {
    if !roles.iter().any(|r| r.starts_with("dep:")) {
        return roles;
    }
    let mut auth: Vec<String> = vec![];
    for r in &roles {
        let Some((m, n)) = r.strip_prefix("dep:").and_then(|x| x.split_once('|')) else { continue };
        let Some(t) = module_file(file, m, files) else { continue };
        if let Some(fs) = alias.get(&(t, n.to_string())) {
            for f in fs.split(',').filter(|f| !f.is_empty()) {
                let a = format!("auth:{f}");
                if !auth.contains(&a) {
                    auth.push(a);
                }
            }
        }
    }
    let mut out: Vec<String> = roles.into_iter().filter(|r| !r.starts_with("dep:") && !(r == "public" && !auth.is_empty())).collect();
    for a in auth {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// True when no endpoint was indexed at all: either the repo serves none or no extractor of this stack ran.
pub fn no_endpoint_extractor(conn: &rusqlite::Connection) -> bool {
    conn.query_row("SELECT count(*) FROM endpoints", [], |r| r.get::<_, i64>(0)).map(|n| n == 0).unwrap_or(false)
}

/// Appended to "none" answers about endpoints when nothing was indexed.
pub const NO_EXTRACTOR: &str = "no endpoint extractor ran for this stack: 0 endpoints indexed (supported: Spring MVC, JAX-RS, Express/Koa/Fastify/Hono, Next.js, FastAPI, Flask, Django, Go net/http/chi/gin/echo, Rails, Laravel, ASP.NET Core, Ktor)";

/// The member an endpoint handler names, when the endpoint's own file does not decide it: a member of that name in the
/// same file, a member of the module the handler (or its receiver) was imported from, or the only/closest member of
/// that name in the repo. Returns (file, line).
pub fn handler_member(conn: &rusqlite::Connection, file: &str, class: &str, handler: &str) -> Option<(String, i64)> {
    if handler.is_empty() || handler.starts_with('(') {
        return None;
    }
    const KINDS: &str = "kind IN ('function','method','const','field','class')";
    let one = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Option<(String, i64)> {
        conn.prepare_cached(sql).ok()?.query_row(p, |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).ok()
    };
    // 1. same file
    if let Some(h) = one(&format!("SELECT file, line FROM members WHERE file=?1 AND name=?2 AND {KINDS} ORDER BY (container IS ?3) DESC, line LIMIT 1"), params![file, handler, class]) {
        return Some(h);
    }
    // 2. through the file's imports of the handler or its receiver
    let root = if class.is_empty() { handler } else { class };
    let targets: Vec<String> = conn
        .prepare_cached("SELECT target FROM imports WHERE file=? AND name=? AND target<>''")
        .ok()
        .map(|mut st| {
            st.query_map(params![file, root], |r| r.get(0)).map(|it| it.flatten().collect()).unwrap_or_default()
        })
        .unwrap_or_default();
    for t in targets {
        if let Some(h) = one(
            &format!("SELECT file, line FROM members WHERE file=?1 AND name=?2 AND {KINDS} ORDER BY line LIMIT 1"),
            params![t, handler],
        ) {
            return Some(h);
        }
    }
    // 3. the endpoint names its class (`[OverviewController::class, '__invoke']`, `Api::V1::GemsController#index`):
    //    a member of that name in a class of that name, nearest directory first (ties: give up)
    let cls = class.rsplit(['\\', ':', '.', '/']).next().unwrap_or("");
    if !cls.is_empty() {
        let hits: Vec<(String, i64)> = conn
            .prepare_cached(&format!("SELECT file, line FROM members WHERE name=?1 AND container IN (?2, ?3) AND {KINDS} LIMIT 40"))
            .ok()
            .map(|mut st| {
                st.query_map(params![handler, cls, class], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map(|it| it.flatten().collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if hits.len() == 1 {
            return hits.into_iter().next();
        }
        if let Some(best) = hits.iter().map(|(f, _)| common_prefix(f, file)).max() {
            let top: Vec<_> = hits.into_iter().filter(|(f, _)| common_prefix(f, file) == best).collect();
            if top.len() == 1 {
                return top.into_iter().next();
            }
            return None;
        }
    }
    // 4. repo-wide by name: the one in the nearest directory (ties: give up unless unique)
    let all: Vec<(String, i64)> = conn
        .prepare_cached(&format!(
            "SELECT file, line FROM members WHERE name=?1 AND {KINDS} AND file NOT LIKE '%test%' LIMIT 40"
        ))
        .ok()
        .map(|mut st| {
            st.query_map(params![handler], |r| Ok((r.get(0)?, r.get(1)?)))
                .map(|it| it.flatten().collect())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    if all.len() == 1 {
        return all.into_iter().next();
    }
    let best = all.iter().map(|(f, _)| common_prefix(f, file)).max()?;
    let mut top = all.into_iter().filter(|(f, _)| common_prefix(f, file) == best);
    let first = top.next()?;
    if top.next().is_some() {
        None
    } else {
        Some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn py_modules() {
        let files: HashSet<String> =
            ["app/api/routes/items.py", "app/api/main.py", "app/api/__init__.py", "other/items.py"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            module_file("app/api/main.py", "app.api.routes.items", &files).as_deref(),
            Some("app/api/routes/items.py")
        );
        assert_eq!(module_file("app/api/main.py", ".routes.items", &files).as_deref(), Some("app/api/routes/items.py"));
        assert_eq!(module_file("app/api/main.py", "backend.app.api", &files).as_deref(), Some("app/api/__init__.py"));
    }
    #[test]
    fn joins() {
        assert_eq!(join("/api", "/users/"), "/api/users");
        assert_eq!(join("", ""), "/");
    }
}
