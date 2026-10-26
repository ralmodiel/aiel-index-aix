//! Index-only code questions: `callers`, `callees`, `impact <symbol>` and `outline <file> [words]`. Every answer is
//! read from `members`, `refs`, `call_edges`, `sym_fanin` and the older fact tables; nothing scans the repo.
//! Each command also builds the `aix/v1` JSON envelope.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::index::Index;
use crate::query::Out;

pub struct Cite {
    pub file: String,
    pub line: i64,
    pub end: i64,
}

pub struct Answer {
    pub kind: &'static str,
    pub text: String,
    pub cites: Vec<Cite>,
    pub conf: &'static str,
}

#[derive(Default)]
pub struct Resp {
    pub cmd: &'static str,
    pub args: Vec<String>,
    pub answers: Vec<Answer>,
    pub truncated: bool,
    /// header / footer lines printed in text mode only
    pub head: Vec<String>,
    pub foot: Vec<String>,
}

impl Resp {
    pub(crate) fn new(cmd: &'static str, arg: &str) -> Resp {
        Resp { cmd, args: arg.split_whitespace().map(str::to_string).collect(), ..Default::default() }
    }
    pub(crate) fn ans(&mut self, kind: &'static str, text: String, file: &str, line: i64, end: i64, conf: &'static str) {
        self.answers.push(Answer { kind, text, cites: vec![Cite { file: file.to_string(), line, end }], conf });
    }
    pub(crate) fn finish(self, out: &mut Out) {
        for l in &self.head {
            out.emit(l.clone());
        }
        for a in &self.answers {
            out.emit(a.text.clone());
        }
        for l in &self.foot {
            out.emit(l.clone());
        }
        // the envelope carries the header / footer lines too (counts, "+N more") as cite-less answers
        let mk = |kind: &'static str, t: &String| Answer { kind, text: t.clone(), cites: vec![], conf: "exact" };
        let all: Vec<Answer> = self
            .head
            .iter()
            .map(|t| mk("summary", t))
            .chain(self.answers.iter().map(|a| Answer {
                kind: a.kind,
                text: a.text.clone(),
                cites: a.cites.iter().map(|c| Cite { file: c.file.clone(), line: c.line, end: c.end }).collect(),
                conf: a.conf,
            }))
            .chain(self.foot.iter().map(|t| mk("note", t)))
            .collect();
        let answers: Vec<Value> = all
            .iter()
            .map(|a| {
                json!({"kind": a.kind, "text": a.text,
                    "cites": a.cites.iter().map(|c| json!({"file": c.file, "line": c.line, "end": c.end})).collect::<Vec<_>>(),
                    "conf": a.conf})
            })
            .collect();
        out.v1 = Some(
            json!({"schema": "aix/v1", "cmd": self.cmd, "args": self.args, "answers": answers, "truncated": self.truncated}),
        );
    }
}

#[derive(Clone, Debug)]
struct Def {
    file: String,
    line: i64,
    end: i64,
    name: String,
    qname: String,
    kind: String,
    sig: String,
}

fn is_type(k: &str) -> bool {
    matches!(k, "class" | "interface" | "enum" | "record")
}

fn conf_str(c: &str) -> &'static str {
    match c {
        "exact" => "exact",
        "resolved" => "resolved",
        "heuristic" => "heuristic",
        _ => "name",
    }
}

fn norm_sym(s: &str) -> String {
    let s = s.trim().replace("::", ".").replace('#', ".");
    let s = s.split('(').next().unwrap_or("").trim().to_string();
    s.trim_matches('.').to_string()
}

fn find_defs(c: &Connection, sym: &str) -> Vec<Def> {
    find_defs_noted(c, sym).0
}

/// `Sub.method` where `Sub` does not declare `method`: the definition up the `extends`/`implements` chain.
fn inherited_defs(c: &Connection, cont: &str, name: &str) -> (Vec<Def>, Option<String>) {
    let mut seen: HashSet<String> = HashSet::from([cont.to_string()]);
    let mut frontier = vec![cont.to_string()];
    for _ in 0..6 {
        let mut next = vec![];
        for cls in &frontier {
            let supers: Vec<String> = c
                .prepare_cached("SELECT supers FROM members WHERE name=? AND kind IN ('class','interface','enum','record') AND supers<>''")
                .and_then(|mut st| st.query_map([cls], |r| r.get::<_, String>(0)).map(|i| i.flatten().collect()))
                .unwrap_or_default();
            for sup in supers.iter().flat_map(|x| x.split(',')) {
                let sup = sup.trim().split('<').next().unwrap_or("").trim().rsplit('.').next().unwrap_or("").to_string();
                if sup.is_empty() || !seen.insert(sup.clone()) {
                    continue;
                }
                let v: Vec<Def> = c
                    .prepare_cached("SELECT file, line, end_line, name, qname, kind, sig FROM members WHERE container=? AND name=? ORDER BY file, line LIMIT 12")
                    .and_then(|mut st| {
                        st.query_map(params![sup, name], |r| {
                            Ok(Def { file: r.get(0)?, line: r.get(1)?, end: r.get(2)?, name: r.get(3)?, qname: r.get(4)?, kind: r.get(5)?, sig: r.get(6)? })
                        })
                        .map(|i| i.flatten().collect())
                    })
                    .unwrap_or_default();
                if !v.is_empty() {
                    return (v, Some(format!("{cont}.{name} is inherited: defined in {sup}")));
                }
                next.push(sup);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    (vec![], None)
}

/// Definitions of a symbol, plus a note when they were found through a superclass.
fn find_defs_noted(c: &Connection, sym: &str) -> (Vec<Def>, Option<String>) {
    let v = find_defs_direct(c, sym);
    if v.is_empty() && !pathish(sym) {
        let sym = norm_sym(sym);
        let parts: Vec<&str> = sym.split('.').collect();
        if parts.len() >= 2 {
            return inherited_defs(c, parts[parts.len() - 2], parts[parts.len() - 1]);
        }
    }
    (v, None)
}

/// `path/to/file.rs:123` -> (file, line); the symbol of a position.
fn file_line(sym: &str) -> Option<(&str, i64)> {
    let (f, n) = sym.trim().rsplit_once(':')?;
    let n: i64 = n.parse().ok()?;
    (!f.is_empty() && !f.ends_with(':') && (f.contains('/') || f.contains('.'))).then_some((f, n))
}

/// `path/to/file.rs::name` / `dir/stem::Class.method`: a symbol qualified by the file (or module path) that defines it.
fn path_name(sym: &str) -> Option<(&str, &str)> {
    let (f, n) = sym.trim().split_once("::")?;
    (!f.is_empty() && !n.is_empty() && (f.contains('/') || f.contains('.'))).then_some((f, n))
}

/// Is this argument a position or a path-qualified name (it must reach `find_defs` unmangled by `norm_sym`)?
fn pathish(sym: &str) -> bool {
    file_line(sym).is_some() || path_name(sym).is_some()
}

/// Is `file` the module / file named by `want` (`src/a.rs`, `a.rs`, `src/a`, `a`)?
fn file_is(file: &str, want: &str) -> bool {
    let noext = file.rsplit_once('.').map(|x| x.0).unwrap_or(file);
    [file, noext].iter().any(|f| *f == want || f.ends_with(&format!("/{want}")))
}

fn sym_of(sym: &str) -> String {
    if pathish(sym) {
        sym.trim().to_string()
    } else {
        norm_sym(sym)
    }
}

fn find_defs_direct(c: &Connection, sym: &str) -> Vec<Def> {
    let rd = |r: &rusqlite::Row| -> rusqlite::Result<Def> {
        Ok(Def { file: r.get(0)?, line: r.get(1)?, end: r.get(2)?, name: r.get(3)?, qname: r.get(4)?, kind: r.get(5)?, sig: r.get(6)? })
    };
    if let Some((f, n)) = file_line(sym) {
        // the member that starts on that line, else the innermost one that holds it
        let all: Vec<Def> = c
            .prepare_cached("SELECT file, line, end_line, name, qname, kind, sig FROM members WHERE (file=?1 OR file LIKE '%/' || ?1) AND line<=?2 AND end_line>=?2 AND kind<>'field' ORDER BY (line=?2) DESC, end_line-line LIMIT 12")
            .and_then(|mut st| st.query_map(params![f, n], rd).map(|i| i.flatten().collect()))
            .unwrap_or_default();
        let starts: Vec<Def> = all.iter().filter(|d| d.line == n).cloned().collect();
        return if !starts.is_empty() { starts } else { all.into_iter().take(1).collect() };
    }
    if let Some((f, rest)) = path_name(sym) {
        let rest = norm_sym(rest);
        let (cont, name) = match rest.rsplit_once('.') {
            Some((a, b)) => (Some(a.rsplit('.').next().unwrap_or(a).to_string()), b.to_string()),
            None => (None, rest.clone()),
        };
        let v: Vec<Def> = c
            .prepare_cached("SELECT file, line, end_line, name, qname, kind, sig FROM members WHERE (name=?1 OR (qname=?1 AND instr(?1, ':') > 0)) AND kind<>'field' AND (?2 IS NULL OR container=?2) ORDER BY file, line LIMIT 200")
            .and_then(|mut st| st.query_map(params![name, cont], rd).map(|i| i.flatten().collect()))
            .unwrap_or_default();
        return v.into_iter().filter(|d| file_is(&d.file, f)).take(12).collect();
    }
    let sym = norm_sym(sym);
    let q = |sql: &str, a: &[&dyn rusqlite::ToSql]| -> Vec<Def> {
        let Ok(mut st) = c.prepare_cached(sql) else { return vec![] };
        st.query_map(a, |r| {
            Ok(Def {
                file: r.get(0)?,
                line: r.get(1)?,
                end: r.get(2)?,
                name: r.get(3)?,
                qname: r.get(4)?,
                kind: r.get(5)?,
                sig: r.get(6)?,
            })
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default()
    };
    const COLS: &str = "SELECT file, line, end_line, name, qname, kind, sig FROM members";
    let parts: Vec<&str> = sym.split('.').collect();
    let mut v = vec![];
    if parts.len() >= 2 {
        let (cont, name) = (parts[parts.len() - 2], parts[parts.len() - 1]);
        v = q(&format!("{COLS} WHERE container=? AND name=? ORDER BY file, line LIMIT 12"), &[&cont, &name]);
        if v.is_empty() {
            v = q(&format!("{COLS} WHERE qname=? ORDER BY file, line LIMIT 12"), &[&sym]);
        }
        if v.is_empty() {
            // `module.function` (Python `crud.create_user`, TS `api.fn`): a top-level member of the file named `module`
            let (a, b, c2, d) = (format!("%/{cont}.%"), format!("{cont}.%"), format!("%/{cont}/__init__.py"), format!("%/{cont}/index.%"));
            v = q(
                &format!("{COLS} WHERE name=? AND (container IS NULL OR container='') AND kind<>'field' AND (file LIKE ?2 OR file LIKE ?3 OR file LIKE ?4 OR file LIKE ?5) ORDER BY file, line LIMIT 12"),
                &[&name, &a, &b, &c2, &d],
            );
        }
    }
    let drop_stubs = |mut v: Vec<Def>| -> Vec<Def> {
        // `const Page = lazy(() => import('./Page'))` re-declares the component: keep it only when nothing real exists
        let real = v.iter().any(|d| !is_stub(d));
        if real {
            v.retain(|d| !is_stub(d));
        }
        v
    };
    if v.is_empty() && parts.len() == 1 || (v.is_empty() && !parts.is_empty() && parts.len() > 2) {
        let name = parts[parts.len() - 1];
        v = q(&format!("{COLS} WHERE name=? AND kind<>'field' ORDER BY (kind IN ('class','interface','enum','record')) DESC, file, line LIMIT 12"), &[&name]);
        if v.is_empty() {
            v = q(&format!("{COLS} WHERE name=? ORDER BY file, line LIMIT 12"), &[&name]);
        }
        if v.is_empty() && name.contains(':') {
            // XQuery `prefix:name` (members are named by their local name)
            v = q(&format!("{COLS} WHERE qname=? ORDER BY file, line LIMIT 12"), &[&name]);
        }
    }
    drop_stubs(v)
}

/// A `lazy(() => import(...))` / `dynamic(import(...))` binding, not a definition.
fn is_stub(d: &Def) -> bool {
    // the member carries only the declaration head (`const Page`): a bare const binding next to a real component
    d.kind == "const" || (d.kind != "class" && d.kind != "function" && d.kind != "method" && (d.sig.contains("lazy(") || d.sig.contains("import(") || d.sig.contains("dynamic(")))
}

pub(crate) fn find_defs_pub(c: &Connection, sym: &str) -> Vec<(String, i64, i64, String, String, String)> {
    find_defs(c, sym).into_iter().map(|d| (d.file, d.line, d.end, d.name, d.qname, d.kind)).collect()
}

/// Does the first non-flag token of an `impact` argument name an indexed symbol (so it is not a git rev)?
pub fn is_symbol_arg(ix: &Index, arg: &str) -> bool {
    let (sym, _) = split_depth(arg);
    if sym.is_empty() {
        return false;
    }
    if sym == "HEAD" || (sym.contains("..") && !pathish(&sym)) || sym.contains('~') || sym.contains('^') {
        return false;
    }
    !find_defs(&ix.conn, &sym).is_empty()
}

/// `impact` argument with `--conf <list>` / `--conf=<list>` taken out: (rest, whether `name` edges are wanted).
fn take_conf(arg: &str) -> (String, bool) {
    let toks: Vec<&str> = arg.split_whitespace().collect();
    let (mut rest, mut names, mut i) = (vec![], false, 0);
    while i < toks.len() {
        if toks[i] == "--conf" {
            names |= toks.get(i + 1).is_some_and(|v| v.split(',').any(|x| x.eq_ignore_ascii_case("name") || x.eq_ignore_ascii_case("name-only")));
            i += 2;
            continue;
        }
        if let Some(v) = toks[i].strip_prefix("--conf=") {
            names |= v.split(',').any(|x| x.eq_ignore_ascii_case("name") || x.eq_ignore_ascii_case("name-only"));
        } else {
            rest.push(toks[i]);
        }
        i += 1;
    }
    (rest.join(" "), names)
}

fn split_depth(arg: &str) -> (String, usize) {
    let (arg, _) = take_conf(arg);
    let arg = arg.as_str();
    let mut depth = 3usize;
    let mut rest = vec![];
    let toks: Vec<&str> = arg.split_whitespace().collect();
    let mut i = 0;
    while i < toks.len() {
        if toks[i] == "--depth" || toks[i] == "-d" {
            if let Some(n) = toks.get(i + 1).and_then(|x| x.parse::<usize>().ok()) {
                depth = n.clamp(1, 4);
            }
            i += 2;
            continue;
        }
        if let Some(n) = toks[i].strip_prefix("--depth=").and_then(|x| x.parse::<usize>().ok()) {
            depth = n.clamp(1, 4);
        } else {
            rest.push(toks[i]);
        }
        i += 1;
    }
    (rest.join(" "), depth)
}

/// One label per definition that names exactly that definition: its qualified name when that is unique among `defs`,
/// else `dir/file::name` (the shortest path suffix that tells them apart), else `file:line`.
fn def_labels(defs: &[Def]) -> Vec<String> {
    defs.iter()
        .map(|d| {
            let same: Vec<&Def> = defs.iter().filter(|x| x.qname == d.qname).collect();
            if same.len() == 1 {
                return d.qname.clone();
            }
            if !d.qname.contains('.') {
                let comps: Vec<&str> = d.file.split('/').collect();
                let stem = |c: &str| c.rsplit_once('.').map(|x| x.0).unwrap_or(c).to_string();
                for n in 1..=comps.len().min(4) {
                    let mut parts: Vec<String> = comps[comps.len() - n..].iter().map(|c| c.to_string()).collect();
                    let last = parts.len() - 1;
                    parts[last] = stem(&parts[last]);
                    let p = parts.join("/");
                    if same.iter().filter(|x| file_is(&x.file, &p)).count() == 1 {
                        return format!("{p}::{}", d.qname);
                    }
                }
            }
            format!("{}:{}", d.file, d.line)
        })
        .collect()
}

fn defs_header(defs: &[Def]) -> String {
    defs_header_n(defs, defs.len())
}

/// The first three definitions and how many more there are (`n`: every definition, also those not loaded).
fn defs_header_n(defs: &[Def], n: usize) -> String {
    let shown: Vec<String> = defs.iter().take(3).map(|d| format!("{}:{}", d.file, d.line)).collect();
    let n = n.max(defs.len());
    format!("{}{}", shown.join(", "), if n > 3 { format!(" (+{} more definitions)", n - 3) } else { String::new() })
}

fn where_defs(defs: &[Def], col_f: &str, col_l: &str) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut sql = vec![];
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    for d in defs {
        if d.kind == "field" {
            // several fields can share one declaration line: tell them apart by label
            sql.push(format!("({col_f}=? AND {col_l}=? AND callee=?)"));
            args.push(Box::new(d.file.clone()));
            args.push(Box::new(d.line));
            args.push(Box::new(d.qname.clone()));
            continue;
        }
        sql.push(format!("({col_f}=? AND {col_l}=?)"));
        args.push(Box::new(d.file.clone()));
        args.push(Box::new(d.line));
    }
    (sql.join(" OR "), args)
}

/// "none" for a symbol the (possibly filtered) member view does not show: a symbol that exists but is hidden by
/// --only / --exclude is named as such, not as unknown.
fn none_symbol(c: &rusqlite::Connection, cmd: &str, sym: &str) -> String {
    let name = sym.rsplit(['.', '#']).next().unwrap_or(sym);
    let exists = c.query_row("SELECT 1 FROM main.members WHERE qname=?1 OR (name=?2 AND ?1=?2) LIMIT 1", [sym, name], |_| Ok(())).is_ok();
    if exists {
        format!("== {cmd} of {sym}: none in the selected rows (the symbol exists; the --only/--exclude/-x filter hides its definition or every edge: rerun without it)")
    } else {
        format!("== {cmd} of {sym}: none (index has no symbol '{sym}')")
    }
}

pub fn callers(ix: &Index, arg: &str, out: &mut Out) {
    let all = arg.split_whitespace().any(|t| t == "--all");
    let arg = &arg.split_whitespace().filter(|t| *t != "--all").collect::<Vec<_>>().join(" ");
    let mut r = Resp::new("callers", arg);
    let c = &ix.conn;
    let sym = sym_of(arg);
    let (defs, inherited) = find_defs_noted(c, &sym);
    // a bare name with more definitions than the lookup keeps (12): the edges into every one of them, counted and
    // listed by SQL over all of them (`work` in 30 classes, `main` in 125 files), never the first 12 as the whole
    let ndefs_all: usize = if !sym.contains('.') && inherited.is_none() && !defs.is_empty() && defs.iter().all(|d| d.name == sym && d.kind != "field") {
        c.query_row("SELECT count(*) FROM members WHERE name=? AND kind<>'field'", [&sym], |x| x.get::<_, i64>(0)).unwrap_or(0) as usize
    } else {
        0
    };
    let by_name = ndefs_all > defs.len();
    let mut weak_note: Option<String> = None;
    let limit = out.limit;
    let mut rows: Vec<(String, i64, String, String, String, String)> = vec![]; // file, line, caller, conf, kind, target "file:line"
    let total: i64;
    let nfiles: i64;
    if defs.is_empty() {
        // synthetic targets (Panache `Entity.find`) are stored under their dotted label
        let n: i64 = c.query_row("SELECT count(*) FROM call_edges_v WHERE callee=?", [&sym], |x| x.get(0)).unwrap_or(0);
        if n == 0 {
            r.head.push(none_symbol(c, "callers", &sym));
            r.finish(out);
            return;
        }
        total = n;
        nfiles = c
            .query_row("SELECT count(DISTINCT file) FROM call_edges_v WHERE callee=?", [&sym], |x| x.get(0))
            .unwrap_or(0);
        if let Ok(mut st) = c.prepare_cached(
            "SELECT file, line, caller, conf, kind FROM call_edges_v WHERE callee=? GROUP BY file, line, caller_line
             ORDER BY CASE conf WHEN 'exact' THEN 0 WHEN 'resolved' THEN 1 WHEN 'heuristic' THEN 1 ELSE 2 END, file, line LIMIT ?",
        ) {
            rows = st
                .query_map(params![sym, limit as i64], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, String::new())))
                .map(|i| i.flatten().collect())
                .unwrap_or_default();
        }
        r.head.push(format!(
            "== callers of {sym} (synthetic target, e.g. Panache): {total} call sites in {nfiles} files"
        ));
    } else {
        let (w, a) = if by_name {
            ("(callee_file, callee_line) IN (SELECT file, line FROM members WHERE name=? AND kind<>'field')".to_string(), vec![Box::new(sym.clone()) as Box<dyn rusqlite::ToSql>])
        } else {
            where_defs(&defs, "callee_file", "callee_line")
        };
        let refs: Vec<&dyn rusqlite::ToSql> = a.iter().map(|b| b.as_ref()).collect();
        // call sites by evidence: rank 0/1 = exact/resolved, 2 = matched by name only
        let sql_total = format!(
            "SELECT rk, count(*), count(DISTINCT file) FROM (SELECT file, MIN(CASE conf WHEN 'exact' THEN 0 WHEN 'resolved' THEN 1 WHEN 'heuristic' THEN 1 ELSE 2 END) AS rk
             FROM call_edges_v WHERE {w} GROUP BY file, line, caller_line) GROUP BY rk = 2"
        );
        let (mut strong, mut strong_files, mut weak, mut weak_files) = (0i64, 0i64, 0i64, 0i64);
        if let Ok(mut st) = c.prepare(&sql_total) {
            let _ = st
                .query_map(refs.as_slice(), |x| Ok((x.get::<_, i64>(0)?, x.get::<_, i64>(1)?, x.get::<_, i64>(2)?)))
                .map(|it| {
                    for (rk, n, f) in it.flatten() {
                        if rk >= 2 {
                            weak = n;
                            weak_files = f;
                        } else {
                            strong = n;
                            strong_files = f;
                        }
                    }
                });
        }
        // exact/resolved sites first; the name-only ones collapse into one line when the target has real callers or the
        // name is shared widely (getStatus, get, list, save...); `--all` lists them
        let collapse = !all && weak > 0 && (strong > 0 || weak > 10);
        if collapse {
            weak_note = Some(format!("+{weak} name-only matches in {weak_files} files; add --all to list"));
            total = strong;
            nfiles = strong_files;
        } else {
            total = strong + weak;
            nfiles = if weak == 0 { strong_files } else { c.query_row(&format!("SELECT count(DISTINCT file) FROM call_edges_v WHERE {w}"), refs.as_slice(), |x| x.get(0)).unwrap_or(0) };
        }
        let maxrk = if collapse { 1 } else { 2 };
        let sql = format!(
            "SELECT file, line, caller, MIN(CASE conf WHEN 'exact' THEN 0 WHEN 'resolved' THEN 1 WHEN 'heuristic' THEN 1 ELSE 2 END) AS rk, kind, callee_file || ':' || callee_line, MIN(conf<>'heuristic') FROM call_edges_v WHERE {w}
             GROUP BY file, line, caller_line HAVING rk<={maxrk} ORDER BY 4, file, line LIMIT {limit}"
        );
        if let Ok(mut st) = c.prepare(&sql) {
            rows = st
                .query_map(refs.as_slice(), |x| {
                    let rank: i64 = x.get(3)?;
                    let guess = rank == 1 && x.get::<_, i64>(6)? == 0; // every edge at this site came from a mock wrapper (`verify(x).m()`)
                    Ok((
                        x.get(0)?,
                        x.get(1)?,
                        x.get(2)?,
                        if guess { "heuristic" } else { ["exact", "resolved", "name"][rank.clamp(0, 2) as usize] }.to_string(),
                        x.get(4)?,
                        x.get::<_, String>(5)?,
                    ))
                })
                .map(|i| i.flatten().collect())
                .unwrap_or_default();
        }
        // a class is used by being injected into a field, built, or called statically: those count as its call sites
        let class_uses = if defs.iter().any(|d| is_type(&d.kind)) {
            let name = &defs[0].name;
            let inj: i64 = c
                .query_row(
                    "SELECT count(*) FROM (SELECT 1 FROM refs_v r WHERE r.callee=? AND r.kind='type' AND EXISTS (SELECT 1 FROM members m WHERE m.file=r.file AND m.line=r.caller_line AND m.kind='field') GROUP BY r.file, r.caller_line)",
                    [name],
                    |x| x.get(0),
                )
                .unwrap_or(0);
            let inj_files: i64 = c
                .query_row(
                    "SELECT count(DISTINCT r.file) FROM refs_v r WHERE r.callee=? AND r.kind='type' AND EXISTS (SELECT 1 FROM members m WHERE m.file=r.file AND m.line=r.caller_line AND m.kind='field')",
                    [name],
                    |x| x.get(0),
                )
                .unwrap_or(0);
            let ctor = rows.iter().filter(|x| x.4 == "new").count() as i64;
            let all_types: i64 = c.query_row("SELECT count(*) FROM (SELECT 1 FROM refs_v WHERE callee=? AND kind='type' GROUP BY file, caller_line)", [name], |x| x.get(0)).unwrap_or(0);
            Some((inj, ctor, all_types, inj_files))
        } else {
            None
        };
        let header_total = total + class_uses.map(|u| u.0).unwrap_or(0);
        let nfiles = nfiles + class_uses.map(|u| u.3).unwrap_or(0);
        r.head.push(format!(
            "== callers of {} [{}]: {header_total} {}call sites in {nfiles} files",
            defs[0].qname,
            defs_header_n(&defs, ndefs_all),
            if weak_note.is_some() { "exact/resolved " } else { "" }
        ));
        if let Some((inj, ctor, all_types, _)) = class_uses {
            let stat = (total - ctor).max(0);
            r.head.push(format!(
                "   {} uses: {inj} injected, {stat} static calls, {ctor} constructed, {} other type uses (params, generics, locals)",
                inj + total + (all_types - inj).max(0),
                (all_types - inj).max(0)
            ));
        }
        if let Some(n) = &inherited {
            r.head.push(format!("   ({n})"));
        }
        if defs.len() > 1 && !sym.contains('.') {
            r.head.push(format!(
                "   '{sym}' has {} definitions; the call sites below belong to ANY of them (each is tagged with the one it resolves to{}). Pass one of these to pick it (Class.method, module::name or file:line): {}",
                defs.len().max(ndefs_all),
                if by_name { format!(" when it is one of the {} listed", defs.len()) } else { String::new() },
                def_labels(&defs).into_iter().take(8).collect::<Vec<_>>().join(", ")
            ));
        }
        for d in defs.iter().take(3) {
            r.ans(
                "definition",
                format!(
                    "{}:{}-{} defined: {} {}",
                    d.file,
                    d.line,
                    d.end,
                    d.kind,
                    d.sig.chars().take(100).collect::<String>()
                ),
                &d.file,
                d.line,
                d.end,
                "exact",
            );
        }
        // a class: add type uses (declarations, casts, generics) when the call sites do not fill the page
        if defs.iter().any(|d| is_type(&d.kind)) && rows.len() < limit {
            let name = &defs[0].name;
            if let Ok(mut st) = c.prepare_cached("SELECT file, line, caller, conf FROM refs_v WHERE callee=? AND kind='type' GROUP BY file, caller_line ORDER BY file, line LIMIT ?") {
                let more: Vec<(String, i64, String, String, String, String)> = st
                    .query_map(params![name, (limit - rows.len()) as i64], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, "name".to_string(), "type".to_string(), String::new())))
                    .map(|i| i.flatten().collect())
                    .unwrap_or_default();
                let tn: i64 = c.query_row("SELECT count(*) FROM (SELECT 1 FROM refs_v WHERE callee=? AND kind='type' GROUP BY file, caller_line)", [name], |x| x.get(0)).unwrap_or(0);
                if tn > 0 {
                    r.head.push(format!("   plus {tn} type uses (declarations, params, generics)"));
                }
                rows.extend(more);
            }
        }
    }
    let ambiguous = defs.len() > 1 && !sym.contains('.');
    let labels = def_labels(&defs);
    for (file, line, caller, conf, kind, tgt) in &rows {
        // with several definitions behind the name, say which one each site resolves to
        let to = if ambiguous {
            defs.iter().position(|d| format!("{}:{}", d.file, d.line) == *tgt).map(|i| format!(" -> {}", labels[i])).unwrap_or_default()
        } else {
            String::new()
        };
        let who = if caller.is_empty() { "(file level)".to_string() } else { caller.clone() };
        let k = match kind.as_str() {
            "call" => String::new(),
            "ref" => " used as value".to_string(),
            k => format!(" {k}"),
        };
        r.ans("caller", format!("{file}:{line} {who}{k} ({conf}){to}"), file, *line, *line, conf_str(conf));
    }
    let shown = rows.iter().filter(|x| x.4 != "type").count() as i64;
    if total > shown {
        r.foot.push(format!("(+{} more)", total - shown));
        r.truncated = true;
    }
    let guessed = rows.iter().filter(|x| x.3 == "heuristic").count();
    if guessed > 0 {
        r.foot.push(format!("({guessed} heuristic: the receiver is a mock wrapper, `verify(x).m()` / `when(x)`, typed as x)"));
    }
    if let Some(n) = weak_note {
        r.foot.push(n);
    }
    if rows.iter().all(|x| x.4 == "type") {
        if let Some(h) = framework_hint(c, &defs) {
            r.foot.push(h);
        }
    }
    if let Some(n) = skipped_note(c, None) {
        r.foot.push(n);
    }
    r.finish(out);
}

/// Annotations / decorators that are not a framework entry point.
const PLAIN_ANNOS: &[&str] = &[
    "Override", "Deprecated", "SuppressWarnings", "FunctionalInterface", "SafeVarargs", "staticmethod", "classmethod",
    "property", "abstractmethod", "cached_property", "wraps", "override", "dataclass", "Nullable", "NonNull", "Value",
    "Autowired", "Inject", "Transactional", "Getter", "Setter", "Data", "Builder",
];

/// A member nobody calls but that carries a framework annotation / decorator (`@GetMapping`, `@Scheduled`, `@app.get`,
/// `@InitBinder`): it is invoked by the framework, not by code in the index.
fn framework_hint(c: &Connection, defs: &[Def]) -> Option<String> {
    for d in defs.iter().filter(|d| !is_type(&d.kind) && d.kind != "field") {
        let annos: String = c
            .query_row("SELECT annos FROM members WHERE file=? AND line=? AND qname=? LIMIT 1", params![d.file, d.line, d.qname], |x| x.get(0))
            .unwrap_or_default();
        let names: Vec<String> = split_annos(&annos)
            .into_iter()
            .filter(|a| !a.is_empty())
            .map(|a| a.split('(').next().unwrap_or(a).trim().to_string())
            .filter(|a| !PLAIN_ANNOS.contains(&a.as_str()) && !PLAIN_ANNOS.contains(&a.rsplit('.').next().unwrap_or("")))
            .collect();
        if !names.is_empty() {
            let shown: Vec<String> = names.iter().take(3).map(|a| format!("@{a}")).collect();
            return Some(format!("invoked by the framework ({}): no call site in code is expected", shown.join(", ")));
        }
    }
    None
}

/// Files the extractor skipped (too deep, panic): their calls are missing from every answer.
fn skipped_note(c: &Connection, file: Option<&str>) -> Option<String> {
    let mut st = c.prepare_cached("SELECT file, text FROM notes WHERE kind='extract-skipped' ORDER BY (file=?1) DESC, file LIMIT 4").ok()?;
    let v: Vec<(String, String)> = st
        .query_map([file.unwrap_or("")], |x| Ok((x.get(0)?, x.get(1)?)))
        .map(|i| i.flatten().collect())
        .unwrap_or_default();
    if v.is_empty() {
        return None;
    }
    let n: i64 = c.query_row("SELECT count(*) FROM notes WHERE kind='extract-skipped'", [], |x| x.get(0)).unwrap_or(0);
    let list: Vec<String> =
        v.iter().map(|(f, t)| format!("{f} was skipped: {}", t.trim_start_matches("extract skipped: "))).collect();
    Some(format!("({n} file(s) skipped by the extractor, their calls are missing here: {})", list.join("; ")))
}

pub fn callees(ix: &Index, arg: &str, out: &mut Out) {
    let mut r = Resp::new("callees", arg);
    let c = &ix.conn;
    let sym = sym_of(arg);
    let (defs, inherited) = find_defs_noted(c, &sym);
    if defs.is_empty() {
        r.head.push(none_symbol(c, "callees", &sym));
        r.finish(out);
        return;
    }
    // several functions of that name (not the same class and its methods): never pick one silently
    let fns: Vec<&Def> = defs.iter().filter(|d| !is_type(&d.kind)).collect();
    if fns.len() > 1 && !sym.contains('.') {
        let labels = def_labels(&defs);
        r.head.push(format!("== callees of {sym}: ambiguous, {} definitions (none picked)", fns.len()));
        for (d, l) in defs.iter().zip(&labels).filter(|(d, _)| !is_type(&d.kind)).take(12) {
            let n: i64 = c
                .query_row(
                    "SELECT count(DISTINCT callee_file||':'||callee_line) FROM call_edges_v WHERE file=? AND caller_line=? AND kind<>'field'",
                    params![d.file, d.line],
                    |x| x.get(0),
                )
                .unwrap_or(0);
            r.ans("definition", format!("  {l}  ({}:{}-{}, {n} callees)", d.file, d.line, d.end), &d.file, d.line, d.end, "exact");
        }
        r.foot.push(format!(
            "pass one of the names above (Class.method, module::name or file:line), e.g. aix callees {}",
            labels.first().cloned().unwrap_or_default()
        ));
        r.finish(out);
        return;
    }
    // for a class, its methods' callees are too many: use the first definition only for methods, all for functions
    let d0 = defs.iter().find(|d| !is_type(&d.kind)).unwrap_or(&defs[0]).clone();
    let (lo, hi) = (d0.line, d0.end);
    let mut st = c
        .prepare_cached(
            "SELECT callee_file, callee_line, callee, MIN(CASE conf WHEN 'exact' THEN 0 WHEN 'resolved' THEN 1 WHEN 'heuristic' THEN 1 ELSE 2 END), count(*), MIN(line)
             FROM call_edges_v WHERE file=? AND caller_line>=? AND caller_line<=? AND (caller_line=? OR ?) AND kind<>'field' GROUP BY callee_file, callee_line ORDER BY MIN(line)",
        )
        .unwrap();
    let is_cls = is_type(&d0.kind);
    let rows: Vec<(String, i64, String, i64, i64, i64)> = st
        .query_map(params![d0.file, lo, hi, d0.line, is_cls], |x| {
            Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?, x.get(5)?))
        })
        .map(|i| i.flatten().collect())
        .unwrap_or_default();
    r.head.push(format!("== callees of {} [{}:{}-{}]: {} distinct", d0.qname, d0.file, d0.line, d0.end, rows.len()));
    if let Some(n) = &inherited {
        r.head.push(format!("   ({n})"));
    }
    // interface dispatch: a call through an interface also reaches its implementations at the same site; say so on the
    // interface row ("via interface I: impls A, B") and tag the implementation rows
    let is_iface = |q: &str| -> bool {
        q.rsplit_once('.').is_some_and(|(cont, _)| {
            c.query_row("SELECT 1 FROM members WHERE qname=? AND kind='interface' LIMIT 1", [cont], |_| Ok(())).is_ok()
        })
    };
    let bare = |q: &str| q.rsplit('.').next().unwrap_or(q).to_string();
    let mut via: HashMap<usize, String> = HashMap::new(); // row -> note
    for (i, (_, _, q, _, _, first)) in rows.iter().enumerate() {
        if !is_iface(q) {
            continue;
        }
        let impls: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(j, x)| *j != i && x.5 == *first && bare(&x.2) == bare(q) && !is_iface(&x.2))
            .map(|(j, _)| j)
            .collect();
        if impls.is_empty() {
            continue;
        }
        let cont = q.rsplit_once('.').map(|x| x.0).unwrap_or(q);
        let names: Vec<String> = impls.iter().map(|&j| rows[j].2.rsplit_once('.').map(|x| x.0.to_string()).unwrap_or_else(|| rows[j].2.clone())).collect();
        via.insert(i, format!(" via interface {cont}: impls {}", names.join(", ")));
        for j in impls {
            via.insert(j, format!(" implements {cont}"));
        }
    }
    for (i, (f, l, q, rank, n, first)) in rows.iter().enumerate().take(out.limit) {
        let conf = ["exact", "resolved", "name"][(*rank).clamp(0, 2) as usize];
        let times = if *n > 1 { format!(" x{n}") } else { String::new() };
        let note = via.get(&i).cloned().unwrap_or_default();
        r.ans("callee", format!("{f}:{l} {q} ({conf}){times}{note} <- called at line {first}"), f, *l, *l, conf_str(conf));
    }
    if rows.len() > out.limit {
        r.foot.push(format!("(+{} more)", rows.len() - out.limit));
        r.truncated = true;
    }
    // field reads/writes are edges too, but not calls: one line
    if let Ok(mut st) = c.prepare_cached(
        "SELECT DISTINCT callee FROM call_edges_v WHERE file=? AND caller_line>=? AND caller_line<=? AND (caller_line=? OR ?) AND kind='field' ORDER BY line LIMIT 40",
    ) {
        let fields: Vec<String> = st
            .query_map(params![d0.file, lo, hi, d0.line, is_cls], |x| x.get(0))
            .map(|i| i.flatten().collect())
            .unwrap_or_default();
        if !fields.is_empty() {
            let shown: Vec<&str> = fields.iter().take(12).map(String::as_str).collect();
            r.foot.push(format!(
                "fields read/written (not calls): {}{}",
                shown.join(", "),
                if fields.len() > 12 { format!(" (+{})", fields.len() - 12) } else { String::new() }
            ));
        }
    }
    // calls with no indexed target: library / external names
    let mut st = c
        .prepare_cached(
            "SELECT DISTINCT callee FROM refs_v WHERE file=? AND caller_line=? AND kind IN ('call','new','jsx')
             AND callee NOT IN (SELECT cname FROM call_edges_v WHERE file=? AND caller_line=?) LIMIT 40",
        )
        .unwrap();
    let ext: Vec<String> = st
        .query_map(params![d0.file, d0.line, d0.file, d0.line], |x| x.get(0))
        .map(|i| i.flatten().collect())
        .unwrap_or_default();
    if !ext.is_empty() {
        let shown: Vec<&str> = ext.iter().take(12).map(String::as_str).collect();
        r.foot.push(format!(
            "external/unresolved names (no indexed definition): {}{}",
            shown.join(", "),
            if ext.len() > 12 { format!(" (+{})", ext.len() - 12) } else { String::new() }
        ));
    }
    if let Some(n) = skipped_note(c, Some(&d0.file)) {
        r.foot.push(n);
    }
    r.finish(out);
}

/// Endpoints (method, norm) whose handlers reach the members of `file` that overlap `ranges` through resolved call
/// edges (callers, up to `maxd` hops, bounded). With no overlapping member every member of the file seeds the walk.
/// Returns (endpoints, seeds used, whether any member overlapped).
pub fn endpoints_reached(ix: &Index, file: &str, ranges: Option<&[(i64, i64)]>, maxd: usize) -> (Vec<(String, String)>, usize, bool) {
    let c = &ix.conn;
    let ms: Vec<(i64, i64)> = c
        .prepare_cached("SELECT line, end_line FROM members WHERE file=? AND kind NOT IN ('field','class','interface','enum','record') AND line>0")
        .and_then(|mut st| st.query_map([file], |x| Ok((x.get(0)?, x.get(1)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let hit: Vec<(i64, i64)> = match ranges {
        Some(rs) => ms.iter().copied().filter(|(a, b)| rs.iter().any(|(lo, hi)| *lo <= *b && *hi >= *a)).collect(),
        None => ms.clone(),
    };
    let overlapped = !hit.is_empty();
    let seeds = if overlapped { hit } else { ms };
    let mut seen: HashSet<(String, i64)> = seeds.iter().map(|s| (file.to_string(), s.0)).collect();
    let mut frontier: Vec<(String, i64)> = seen.iter().cloned().collect();
    let n_seeds = frontier.len();
    let Ok(mut st) = c.prepare_cached(
        "SELECT DISTINCT file, caller_line FROM call_edges_v WHERE callee_file=? AND callee_line=? AND caller_line>0 AND conf<>'name' AND kind IN ('call','new')",
    ) else {
        return (vec![], n_seeds, overlapped);
    };
    let mut eps: Vec<(String, String)> = vec![];
    let mut ep_q = c.prepare_cached("SELECT method, norm FROM endpoints WHERE file=? AND line=?").unwrap();
    for depth in 0..=maxd {
        let mut next = vec![];
        for (f, l) in &frontier {
            for e in ep_q.query_map(params![f, l], |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                if !eps.contains(&e) {
                    eps.push(e);
                }
            }
            if depth == maxd || seen.len() > 600 {
                continue;
            }
            for (cf, cl) in st.query_map(params![f, l], |x| Ok((x.get::<_, String>(0)?, x.get::<_, i64>(1)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                if seen.insert((cf.clone(), cl)) {
                    next.push((cf, cl));
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    (eps, n_seeds, overlapped)
}

/// What changed lines reach, walking callers up from the members they touch (file-level callers such as test
/// callbacks are leaves): the endpoints whose handlers are reached (method, path, handler file, line, changed member)
/// and the test files that call into the change (file, callers). `ranges` None = the whole file.
pub struct DiffReach {
    pub endpoints: Vec<(String, String, String, i64, String)>,
    pub tests: Vec<(String, usize)>,
    pub members: Vec<String>,
}

pub fn diff_reach(ix: &Index, changed: &[(String, Option<Vec<(i64, i64)>>)], maxd: usize) -> DiffReach {
    let c = &ix.conn;
    let mut out = DiffReach { endpoints: vec![], tests: vec![], members: vec![] };
    let mut seen: HashMap<(String, i64), String> = HashMap::new();
    let mut frontier: Vec<(String, i64, String)> = vec![];
    for (file, ranges) in changed {
        if aix_extract::is_test_path(file) {
            continue;
        }
        let ms: Vec<(i64, i64, String)> = c
            .prepare_cached("SELECT line, end_line, qname FROM members WHERE file=? AND kind NOT IN ('field','class','interface','enum','record','type','const') AND line>0")
            .and_then(|mut st| st.query_map([file], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?))).map(|i| i.flatten().collect()))
            .unwrap_or_default();
        for (a, b, q) in ms {
            if ranges.as_ref().is_none_or(|rs| rs.iter().any(|(lo, hi)| *lo <= b && *hi >= a)) && seen.insert((file.clone(), a), q.clone()).is_none() {
                out.members.push(q.clone());
                frontier.push((file.clone(), a, q));
            }
        }
    }
    let Ok(mut up) = c.prepare_cached(
        "SELECT DISTINCT file, caller_line FROM call_edges_v WHERE callee_file=? AND callee_line=? AND conf<>'name' AND kind IN ('call','new','jsx','ref')",
    ) else {
        return out;
    };
    let Ok(mut ep_q) = c.prepare_cached("SELECT method, path FROM endpoints WHERE file=? AND line=?") else { return out };
    let mut tests: BTreeMap<String, usize> = BTreeMap::new();
    for depth in 0..=maxd {
        let mut next = vec![];
        for (f, l, origin) in &frontier {
            if *l > 0 {
                for (m, p) in ep_q.query_map(params![f, l], |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                    if !out.endpoints.iter().any(|e| e.0 == m && e.1 == p) {
                        out.endpoints.push((m, p, f.clone(), *l, origin.clone()));
                    }
                }
            }
            if depth == maxd || seen.len() > 600 || *l == 0 {
                continue;
            }
            for (cf, cl) in up.query_map(params![f, l], |x| Ok((x.get::<_, String>(0)?, x.get::<_, i64>(1)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                if seen.insert((cf.clone(), cl), origin.clone()).is_none() {
                    if aix_extract::is_test_path(&cf) {
                        *tests.entry(cf.clone()).or_default() += 1;
                    }
                    next.push((cf, cl, origin.clone()));
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    out.tests = tests.into_iter().collect();
    out
}

#[derive(Clone)]
struct Node {
    file: String,
    line: i64,
    qname: String,
    depth: usize,
    conf: i64,
}

pub fn impact(ix: &Index, arg: &str, out: &mut Out) {
    let (sym, maxd) = split_depth(arg);
    let sym = sym_of(&sym);
    // `--conf name[,...]` (read here or already installed as the run's confidence filter) asks for the name-only edges too
    let with_names = take_conf(arg).1 || ix.excl().conf.iter().any(|c| c == "name");
    let mut r = Resp::new("impact", arg);
    let c = &ix.conn;
    let defs = find_defs(c, &sym);
    if defs.is_empty() {
        r.head.push(none_symbol(c, "impact", &sym));
        r.finish(out);
        return;
    }
    const CAP: usize = 500;
    let mut visited: HashMap<(String, i64), Node> = HashMap::new();
    let mut truncated = false;
    // a class: the union of its methods' callers (bounded), not only references to the type itself
    let mut seed_defs: Vec<Def> = defs.iter().take(6).cloned().collect();
    let mut class_note: Option<String> = None;
    if let Some(cd) = defs.iter().find(|d| is_type(&d.kind)).filter(|_| !sym.contains('.')) {
        let ms: Vec<Def> = c
            .prepare_cached("SELECT file, line, end_line, name, qname, kind, sig FROM members WHERE file=? AND container=? AND kind IN ('method','ctor','function') ORDER BY line LIMIT 41")
            .and_then(|mut st| {
                st.query_map(params![cd.file, cd.name], |r| {
                    Ok(Def { file: r.get(0)?, line: r.get(1)?, end: r.get(2)?, name: r.get(3)?, qname: r.get(4)?, kind: r.get(5)?, sig: r.get(6)? })
                })
                .map(|i| i.flatten().collect())
            })
            .unwrap_or_default();
        if !ms.is_empty() {
            class_note = Some(format!(
                "{} is a class: showing the union of its {} method(s){}; use Class.method for one",
                cd.qname,
                ms.len().min(40),
                if ms.len() > 40 { " (first 40 only)" } else { "" }
            ));
            seed_defs = ms.into_iter().take(40).collect();
            seed_defs.insert(0, cd.clone());
        }
    }
    let seeds: Vec<Node> = seed_defs
        .iter()
        .map(|d| Node { file: d.file.clone(), line: d.line, qname: d.qname.clone(), depth: 0, conf: 0 })
        .collect();
    for s in &seeds {
        visited.insert((s.file.clone(), s.line), s.clone());
    }
    let expand = |frontier: Vec<Node>, visited: &mut HashMap<(String, i64), Node>, trunc: &mut bool| {
        let mut st = c
            .prepare_cached(
                "SELECT file, caller_line, caller, MIN(CASE conf WHEN 'exact' THEN 0 WHEN 'resolved' THEN 1 WHEN 'heuristic' THEN 1 ELSE 2 END)
                 FROM call_edges_v WHERE callee_file=? AND callee_line=? AND (?3 OR conf<>'name') GROUP BY file, caller_line",
            )
            .unwrap();
        // a caller outside any member (a test callback `it(() => f())`, a script's top level) is a leaf: line 0
        let mut frontier = frontier;
        while !frontier.is_empty() {
            let mut next = vec![];
            for n in &frontier {
                if n.depth >= maxd {
                    continue;
                }
                let rows: Vec<(String, i64, String, i64)> = st
                    .query_map(params![n.file, n.line, with_names], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)))
                    .map(|i| i.flatten().collect())
                    .unwrap_or_default();
                for (f, l, q, rank) in rows {
                    let q = if l == 0 { "(file level)".to_string() } else { q };
                    let k = (f.clone(), l);
                    if visited.contains_key(&k) {
                        continue;
                    }
                    if visited.len() >= CAP {
                        *trunc = true;
                        return;
                    }
                    let node = Node { file: f, line: l, qname: q, depth: n.depth + 1, conf: rank.max(n.conf) };
                    visited.insert(k, node.clone());
                    next.push(node);
                }
            }
            frontier = next;
        }
    };
    expand(seeds.clone(), &mut visited, &mut truncated);

    // endpoints among the callers, then their client wrappers and the client-side callers (cross-layer, same bound)
    let ep_of = |file: &str, line: i64| -> Vec<(String, String, String, String)> {
        let mut st =
            c.prepare_cached("SELECT method, path, norm, roles FROM endpoints WHERE file=? AND line=?").unwrap();
        st.query_map(params![file, line], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)))
            .map(|i| i.flatten().collect())
            .unwrap_or_default()
    };
    let mut endpoints: Vec<(Node, (String, String, String, String))> = vec![];
    let mut keys: Vec<(String, i64)> = visited.keys().cloned().collect();
    keys.sort();
    for k in &keys {
        for e in ep_of(&k.0, k.1) {
            endpoints.push((visited[k].clone(), e));
        }
    }
    let mut client_seeds = vec![];
    {
        let mut st = c
            .prepare_cached(
                "SELECT file, obj, name FROM api_calls WHERE norm=? AND method=? AND obj IS NOT NULL AND obj<>''",
            )
            .unwrap();
        let mut mm = c
            .prepare_cached("SELECT file, line, qname FROM members WHERE file=? AND container=? AND name=? LIMIT 1")
            .unwrap();
        for (n, e) in &endpoints {
            let rows: Vec<(String, String, String)> = st
                .query_map(params![e.2, e.0], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)))
                .map(|i| i.flatten().collect())
                .unwrap_or_default();
            for (f, o, nm) in rows {
                if let Ok((mf, ml, mq)) = mm.query_row(params![f, o, nm], |x| {
                    Ok((x.get::<_, String>(0)?, x.get::<_, i64>(1)?, x.get::<_, String>(2)?))
                }) {
                    if !visited.contains_key(&(mf.clone(), ml)) && visited.len() < CAP {
                        let node = Node {
                            file: mf,
                            line: ml,
                            qname: mq,
                            depth: (n.depth + 1).min(maxd.saturating_sub(1)),
                            conf: 1,
                        };
                        visited.insert((node.file.clone(), node.line), node.clone());
                        client_seeds.push(node);
                    }
                }
            }
        }
    }
    expand(client_seeds, &mut visited, &mut truncated);

    let nfiles: HashSet<&str> = visited.values().map(|n| n.file.as_str()).collect();
    r.head.push(format!(
        "== impact of {} [{}] depth<={maxd}: {} symbols in {} files{}",
        defs[0].qname,
        defs_header(&defs),
        visited.len() - seeds.len().min(visited.len()),
        nfiles.len(),
        if truncated { " (truncated at 500)" } else { "" }
    ));
    // a word that is also a branch/tag (`impact main`): the symbol answered; say how to get the diff form
    if !sym.contains(['.', '/', ':']) && ix.rev_exists(&sym) {
        r.head.push(format!("(`{sym}` is also a git revision: this is the symbol; `aix impact {sym}..HEAD` is what changed since {sym})"));
    }
    // callers matched by name only are not followed: say so instead of letting "0 symbols" read as "nobody calls this"
    if !with_names {
        let mut st = c
            .prepare_cached("SELECT DISTINCT file, caller_line FROM call_edges_v WHERE callee_file=? AND callee_line=? AND caller_line>0 AND conf='name'")
            .unwrap();
        let mut skipped: HashSet<(String, i64)> = HashSet::new();
        for n in visited.values().take(200) {
            for k in st
                .query_map(params![n.file, n.line], |x| Ok((x.get::<_, String>(0)?, x.get::<_, i64>(1)?)))
                .map(|i| i.flatten().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                if !visited.contains_key(&k) {
                    skipped.insert(k);
                }
            }
        }
        if !skipped.is_empty() {
            let files: HashSet<&str> = skipped.iter().map(|k| k.0.as_str()).collect();
            r.head.push(format!(
                "   ({} name-only caller{} in {} file{} not followed; add --conf name to include)",
                skipped.len(),
                if skipped.len() == 1 { "" } else { "s" },
                files.len(),
                if files.len() == 1 { "" } else { "s" }
            ));
        }
    }
    let lim = out.limit.min(12);
    // endpoints
    let mut seen_ep = HashSet::new();
    let eps: Vec<&(Node, (String, String, String, String))> =
        endpoints.iter().filter(|(n, e)| seen_ep.insert((n.file.clone(), n.line, e.0.clone(), e.1.clone()))).collect();
    if let Some(n) = &class_note {
        r.head.push(format!("   ({n})"));
    }
    r.head.push(if eps.is_empty() {
        if crate::compose::no_endpoint_extractor(c) {
            format!("endpoints reached: none ({})", crate::compose::NO_EXTRACTOR)
        } else {
            "endpoints reached: none".into()
        }
    } else {
        format!("endpoints reached ({}):", eps.len())
    });
    for (n, e) in eps.iter().take(lim) {
        r.ans(
            "endpoint",
            format!("  {} {} [{}] {}:{} {} (depth {})", e.0, e.1, e.3, n.file, n.line, n.qname, n.depth),
            &n.file,
            n.line,
            n.line,
            if n.conf == 0 {
                "exact"
            } else if n.conf == 1 {
                "resolved"
            } else {
                "name"
            },
        );
    }
    if eps.len() > lim {
        r.truncated = true;
        r.answers.push(Answer {
            kind: "note",
            text: format!("  (+{} more endpoints)", eps.len() - lim),
            cites: vec![],
            conf: "exact",
        });
    }
    // routes (pages in the closure)
    let mut routes: Vec<(String, String, String)> = vec![];
    {
        let mut st =
            c.prepare_cached("SELECT DISTINCT path, component FROM routes WHERE page_file=? AND path<>''").unwrap();
        let mut files: Vec<&str> = nfiles.iter().copied().collect();
        files.sort();
        for f in files {
            for (p, comp) in st
                .query_map([f], |x| Ok((x.get::<_, String>(0)?, x.get::<_, String>(1)?)))
                .map(|i| i.flatten().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                routes.push((p, comp, f.to_string()));
            }
        }
    }
    r.answers.push(Answer {
        kind: "note",
        text: if routes.is_empty() {
            "routes reached: none".into()
        } else {
            format!("routes reached ({}):", routes.len())
        },
        cites: vec![],
        conf: "exact",
    });
    for (p, comp, f) in routes.iter().take(lim) {
        r.ans("route", format!("  {p} -> {comp} {f}"), f, 1, 1, "resolved");
    }
    if routes.len() > lim {
        r.truncated = true;
    }
    // tests and scripts: callers in test files, plus scripts that hit the reached endpoints
    let mut tests: Vec<(String, usize)> = {
        let mut m: HashMap<&str, usize> = HashMap::new();
        for n in visited.values() {
            if aix_extract::is_test_path(&n.file) {
                *m.entry(n.file.as_str()).or_default() += 1;
            }
        }
        let mut v: Vec<(String, usize)> = m.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        v.sort();
        v
    };
    let mut scripts: Vec<String> = vec![];
    {
        let mut st =
            c.prepare_cached("SELECT DISTINCT file FROM script_refs WHERE norm=? ORDER BY file LIMIT 20").unwrap();
        let mut seen = HashSet::new();
        for (_, e) in &endpoints {
            for f in st
                .query_map([&e.2], |x| x.get::<_, String>(0))
                .map(|i| i.flatten().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                if seen.insert(f.clone()) {
                    scripts.push(f);
                }
            }
        }
    }
    r.answers.push(Answer {
        kind: "note",
        text: if tests.is_empty() && scripts.is_empty() {
            "tests/scripts reached: none".into()
        } else {
            format!("tests/scripts reached ({} via calls, {} scripts hit the endpoints):", tests.len(), scripts.len())
        },
        cites: vec![],
        conf: "exact",
    });
    tests.truncate(lim);
    for (f, n) in &tests {
        r.ans("test", format!("  {f} ({n} callers)"), f, 1, 1, "resolved");
    }
    for f in scripts.iter().take(lim) {
        r.ans("script", format!("  {f} (hits an endpoint above)"), f, 1, 1, "name");
    }
    if scripts.len() > lim {
        r.truncated = true;
    }
    // where the rest lives
    let mut by_file: HashMap<&str, usize> = HashMap::new();
    for n in visited.values().filter(|n| n.depth > 0) {
        *by_file.entry(n.file.as_str()).or_default() += 1;
    }
    let mut bf: Vec<(&str, usize)> = by_file.into_iter().collect();
    bf.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if !bf.is_empty() {
        let top: Vec<String> = bf.iter().take(6).map(|(f, n)| format!("{f} ({n})")).collect();
        r.foot.push(format!(
            "callers by file: {}{}",
            top.join(", "),
            if bf.len() > 6 { format!(" (+{} files)", bf.len() - 6) } else { String::new() }
        ));
    }
    r.truncated |= truncated;
    r.finish(out);
}

// ---------------------------------------------------------------------------------------------------
// outline
// ---------------------------------------------------------------------------------------------------

struct Mem {
    line: i64,
    end: i64,
    name: String,
    qname: String,
    kind: String,
    sig: String,
    vis: String,
    annos: String,
    score: i64,
    exact: usize,
    sub: usize,
    hits: usize,
    cov: usize,
    facts: Vec<String>,
    hay: String,
}

const WRITE_VERBS: &[&str] = &[
    "persist",
    "persistAndFlush",
    "delete",
    "deleteById",
    "deleteAll",
    "update",
    "merge",
    "save",
    "saveAll",
    "deleteByIdOptimistic",
];

fn abbr(kind: &str) -> &'static str {
    match kind {
        "class" => "class",
        "interface" => "iface",
        "enum" => "enum",
        "record" => "record",
        "method" => "method",
        "ctor" => "ctor",
        "field" => "field",
        "function" => "fn",
        "component" => "comp",
        "const" => "const",
        "type" => "type",
        "namespace" => "ns",
        "module" => "module",
        _ => "?",
    }
}

pub fn outline(ix: &Index, arg: &str, out: &mut Out) {
    let mut r = Resp::new("outline", arg);
    let c = &ix.conn;
    let toks: Vec<&str> = arg.split_whitespace().collect();
    if toks.is_empty() {
        out.emit("usage: aix outline <file> [words]");
        return;
    }
    // a path with spaces (`src/with space.ts`): the longest run of words that is an indexed file, then the words
    let mut take = 1;
    for n in (2..=toks.len()).rev() {
        let p = toks[..n].join(" ");
        if crate::opts::path_is_file(ix, &p) {
            take = n;
            break;
        }
    }
    let spec_s = toks[..take].join(" ");
    let spec = &spec_s.as_str();
    let words: Vec<String> = toks[take..].iter().map(|w| w.to_lowercase()).collect();
    // file: exact path, else path suffix, else basename
    let mut cands: Vec<String> = vec![];
    for sql in [
        "SELECT path FROM files WHERE path=?1",
        "SELECT path FROM files WHERE path LIKE '%/' || ?1 ORDER BY length(path)",
        "SELECT path FROM files WHERE path LIKE '%' || ?1 || '%' ORDER BY length(path) LIMIT 5",
    ] {
        if let Ok(mut st) = c.prepare_cached(sql) {
            cands = st.query_map([spec], |x| x.get::<_, String>(0)).map(|i| i.flatten().collect()).unwrap_or_default();
        }
        if !cands.is_empty() {
            break;
        }
    }
    let Some(file) = cands.first().cloned() else {
        if crate::opts::path_shaped(spec) {
            r.head.push(format!("path not found: {spec} (outline: none, no indexed file matches '{spec}')"));
            let near = crate::query::file_near(ix, spec, 3);
            if !near.is_empty() {
                r.head.push(format!("  did you mean: {}", near.join(", ")));
            }
            r.finish(out);
            out.exit_code = Some(1);
            return;
        }
        r.head.push(format!("== outline {spec}: none (no indexed file matches '{spec}')"));
        r.finish(out);
        return;
    };
    let mut st = c.prepare_cached("SELECT line, end_line, name, qname, kind, sig, vis, annos FROM members WHERE file=? ORDER BY line, end_line DESC").unwrap();
    let mut mems: Vec<Mem> = st
        .query_map([&file], |x| {
            Ok(Mem {
                line: x.get(0)?,
                end: x.get(1)?,
                name: x.get(2)?,
                qname: x.get(3)?,
                kind: x.get(4)?,
                sig: x.get(5)?,
                vis: x.get(6)?,
                annos: x.get(7)?,
                score: 0,
                exact: 0,
                sub: 0,
                hits: 0,
                cov: 0,
                facts: vec![],
                hay: String::new(),
            })
        })
        .map(|i| i.flatten().collect())
        .unwrap_or_default();
    // the framework extractor adds a `route-handler` member for an inline callback the code graph already lists
    let spans: HashSet<(i64, i64)> = mems.iter().filter(|m| !m.annos.contains("route-handler")).map(|m| (m.line, m.end)).collect();
    mems.retain(|m| !(m.annos.contains("route-handler") && spans.contains(&(m.line, m.end))));
    let total_lines: i64 = c.query_row("SELECT lines FROM files WHERE path=?", [&file], |x| x.get(0)).unwrap_or(0);
    if mems.is_empty() {
        let why = skipped_note(c, Some(&file)).filter(|n| n.contains(&format!("{file} was skipped")));
        r.head.push(match why {
            Some(n) => format!("== outline {file}: none ({n})"),
            None => format!("== outline {file}: none (index has no members for this file: not a source file the code graph covers)"),
        });
        r.finish(out);
        return;
    }
    let skipped_here: Option<String> = skipped_note(c, Some(&file)).filter(|n| n.contains(&format!("{file} was skipped")));
    // bulk facts for the file
    let mut calls_out: HashMap<i64, Vec<(String, i64)>> = HashMap::new();
    if let Ok(mut st) = c.prepare_cached("SELECT caller_line, callee, count(*) FROM call_edges_v WHERE file=? AND caller_line>0 AND kind<>'field' AND conf<>'name' GROUP BY caller_line, callee ORDER BY caller_line, count(*) DESC") {
        for x in st.query_map([&file], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?, x.get::<_, i64>(2)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
            calls_out.entry(x.0).or_default().push((x.1, x.2));
        }
    }
    let entities: HashSet<String> = {
        let mut set = HashSet::new();
        if let Ok(mut st) = c.prepare_cached("SELECT name FROM members WHERE kind='class' AND (annos LIKE '%Entity%' OR supers LIKE '%Panache%' OR annos LIKE '%Table%')") {
            for n in st.query_map([], |x| x.get::<_, String>(0)).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
                set.insert(n);
            }
        }
        set
    };
    let mut writes: HashMap<i64, Vec<String>> = HashMap::new();
    let mut creates: HashMap<i64, Vec<String>> = HashMap::new();
    let mut rtypes: HashMap<i64, String> = HashMap::new();
    if let Ok(mut st) = c.prepare_cached("SELECT caller_line, callee, recv_type, kind FROM refs_v WHERE file=? AND caller_line>0 AND kind IN ('call','new','type')") {
        for (cl, callee, rt, kind) in st.query_map([&file], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?, x.get::<_, String>(2)?, x.get::<_, String>(3)?))).map(|i| i.flatten().collect::<Vec<_>>()).unwrap_or_default() {
            let h = rtypes.entry(cl).or_default();
            h.push(' ');
            h.push_str(&callee.to_lowercase());
            if kind == "call" && WRITE_VERBS.contains(&callee.as_str()) {
                let ent = if entities.contains(&rt) { Some(rt.clone()) } else { rt.strip_suffix("Repository").or_else(|| rt.strip_suffix("Repo")).filter(|e| entities.contains(*e)).map(str::to_string) };
                if let Some(e) = ent {
                    let v = writes.entry(cl).or_default();
                    if !v.contains(&e) {
                        v.push(e);
                    }
                }
            } else if kind == "new" && entities.contains(&callee) {
                let v = creates.entry(cl).or_default();
                if !v.contains(&callee) {
                    v.push(callee);
                }
            }
        }
    }
    // endpoints per member: a route decorator / registration call sits on a line inside (or just above) its handler,
    // and one handler can serve several routes and methods
    let mut eps: HashMap<i64, String> = HashMap::new();
    if let Ok(mut st) = c.prepare_cached("SELECT line, method, path, roles FROM endpoints WHERE file=? ORDER BY line, path, method") {
        let list: Vec<(i64, String, String, String)> = st
            .query_map([&file], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?, x.get::<_, String>(2)?, x.get::<_, String>(3)?)))
            .map(|i| i.flatten().collect())
            .unwrap_or_default();
        let fnlike = |m: &Mem| !is_type(&m.kind) && m.kind != "field";
        let mut by_member: HashMap<i64, Vec<(String, String, String)>> = HashMap::new();
        for (l, m, p, roles) in list {
            let target = mems
                .iter()
                .filter(|x| fnlike(x) && x.line <= l && l <= x.end)
                .min_by_key(|x| x.end - x.line)
                .or_else(|| mems.iter().filter(|x| fnlike(x) && x.line > l && x.line - l <= 12).min_by_key(|x| x.line))
                .map(|x| x.line);
            let Some(t) = target else { continue };
            let v = by_member.entry(t).or_default();
            match v.iter_mut().find(|e| e.1 == p && e.2 == roles) {
                Some(e) => {
                    if !e.0.split(',').any(|x| x == m) {
                        e.0 = format!("{},{m}", e.0);
                    }
                }
                None => v.push((m, p, roles)),
            }
        }
        for (line, v) in by_member {
            let txt: Vec<String> = v
                .iter()
                .map(|(m, p, roles)| format!("endpoint {m} {p}{} roles[{}]", crate::query::rel_tag(c, &file, line), if roles.is_empty() { "no auth declared" } else { roles }))
                .collect();
            eps.insert(line, txt.join("; "));
        }
    }
    let mut ui: Vec<(i64, String)> = vec![];
    if let Ok(mut st) = c.prepare_cached("SELECT line, text FROM ui_strings WHERE file=? ORDER BY line") {
        ui = st
            .query_map([&file], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?)))
            .map(|i| i.flatten().collect())
            .unwrap_or_default();
    }
    let mut fanin: HashMap<i64, i64> = HashMap::new();
    if let Ok(mut st) = c.prepare_cached("SELECT line, n FROM sym_fanin WHERE file=?") {
        for (l, n) in st
            .query_map([&file], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, i64>(1)?)))
            .map(|i| i.flatten().collect::<Vec<_>>())
            .unwrap_or_default()
        {
            fanin.insert(l, n);
        }
    }
    let table_of = |m: &Mem| -> Option<String> {
        if m.kind == "class" {
            split_annos(&m.annos).into_iter().find(|a| a.starts_with("Table(")).map(|a| {
                format!(
                    "table {}",
                    a.trim_start_matches("Table(").trim_end_matches(')').replace("name = ", "").replace("name=", "")
                )
            })
        } else {
            None
        }
    };
    // line numbers in the words mean "the member enclosing this line"
    let lines_asked: Vec<i64> = words.iter().filter_map(|w| w.parse::<i64>().ok()).collect();
    let text_words: Vec<&String> = words.iter().filter(|w| w.parse::<i64>().is_err()).collect();
    // innermost member per ui string
    let mut ui_by: HashMap<i64, Vec<String>> = HashMap::new();
    for (l, t) in &ui {
        if let Some(m) = mems
            .iter()
            .filter(|m| m.line <= *l && *l <= m.end && !is_type(&m.kind) && m.kind != "field")
            .min_by_key(|m| m.end - m.line)
        {
            ui_by.entry(m.line).or_default().push(t.clone());
        }
    }
    // a file edited since it was indexed (refresh pending or running elsewhere): members and ranges from the file
    // as it is now; the indexed facts follow a member by its qualified name (fresh line -> indexed line)
    let mut total_lines = total_lines;
    let mut remap: Option<HashMap<i64, i64>> = None;
    if crate::fresh::changed(ix, &file) {
        if let Some(rows) = crate::fresh::extract(ix, &file) {
            r.head.push(crate::fresh::note(&file));
            let mut old: HashMap<String, Vec<i64>> = HashMap::new();
            for m in &mems {
                old.entry(m.qname.clone()).or_default().push(m.line);
            }
            let mut map = HashMap::new();
            let rd = |s: &str| crate::par::rd(s);
            let mut fresh: Vec<Mem> = vec![];
            for m in &rows.members {
                if let Some(v) = old.get_mut(&m.qname).filter(|v| !v.is_empty()) {
                    map.insert(m.line as i64, v.remove(0));
                }
                fresh.push(Mem {
                    line: m.line as i64,
                    end: m.end_line as i64,
                    name: m.name.clone(),
                    qname: m.qname.clone(),
                    kind: m.kind.clone(),
                    sig: rd(&m.sig),
                    vis: m.vis.clone(),
                    annos: rd(&m.annos.join(", ")),
                    score: 0,
                    exact: 0,
                    sub: 0,
                    hits: 0,
                    cov: 0,
                    facts: vec![],
                    hay: String::new(),
                });
            }
            fresh.sort_by(|a, b| a.line.cmp(&b.line).then(b.end.cmp(&a.end)));
            mems = fresh;
            remap = Some(map);
            total_lines = crate::query::read_indexed(ix, &file).map(|t| t.lines().count() as i64).unwrap_or(total_lines);
        }
    }
    for m in mems.iter_mut() {
        // the line the index's facts are keyed on (a member new since indexing has none)
        let k = remap.as_ref().map_or(m.line, |r| r.get(&m.line).copied().unwrap_or(-1));
        if let Some(e) = eps.get(&k) {
            m.facts.push(e.clone());
        }
        if let Some(w) = writes.get(&k) {
            m.facts.push(format!("writes {}", w.join(", ")));
        }
        if let Some(w) = creates.get(&k) {
            m.facts.push(format!("creates {}", w.join(", ")));
        }
        if let Some(t) = table_of(m) {
            m.facts.push(t);
        }
        if let Some(n) = fanin.get(&k) {
            m.facts.push(format!("fan-in {n}"));
        }
        if let Some(u) = ui_by.get(&k) {
            let shown: Vec<String> =
                u.iter().take(2).map(|s| format!("\"{}\"", s.chars().take(28).collect::<String>())).collect();
            m.facts.push(format!(
                "ui {}{}",
                shown.join(" "),
                if u.len() > 2 { format!(" (+{})", u.len() - 2) } else { String::new() }
            ));
        }
        if let Some(v) = calls_out.get(&k) {
            let names: Vec<String> = v
                .iter()
                .filter(|(q, _)| *q != m.qname)
                .take(3)
                .map(|(q, n)| {
                    let short =
                        q.rsplit('.').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".");
                    if *n > 1 {
                        format!("{short}x{n}")
                    } else {
                        short
                    }
                })
                .collect();
            if !names.is_empty() {
                m.facts.push(format!(
                    "calls {}{}",
                    names.join(", "),
                    if v.len() > 3 { format!(" (+{})", v.len() - 3) } else { String::new() }
                ));
            }
        }
        m.hay = format!(
            "{} {} {} {} {}{}{}",
            m.qname.to_lowercase(),
            m.sig.to_lowercase(),
            m.annos.to_lowercase(),
            m.facts.join(" ").to_lowercase(),
            rtypes.get(&k).cloned().unwrap_or_default(),
            ui_by.get(&k).map(|u| u.join(" ").to_lowercase()).unwrap_or_default(),
            ""
        );
        let lname = m.name.to_lowercase();
        for w in &text_words {
            let w = w.as_str();
            let mut cov = false;
            if matches!(
                w,
                "write" | "writes" | "writing" | "persist" | "persists" | "save" | "saves" | "mutate" | "mutates"
            ) {
                // intent words match the entity-write fact, never a method that merely has the word in its name
                if m.facts.iter().any(|f| f.starts_with("writes ")) {
                    m.hits += 1;
                    cov = true;
                }
            } else if lname == w {
                m.exact += 1;
                cov = true;
            } else if lname.contains(w) {
                m.sub += 1;
                cov = true;
            } else if m.hay.contains(w) {
                m.hits += 1;
                cov = true;
            }
            if cov {
                m.cov += 1;
            }
        }
        for l in &lines_asked {
            if m.line <= *l && *l <= m.end {
                m.score += 100 - (m.end - m.line).min(90);
            }
        }
    }
    // selection: members covering every word (2+ words), else named exactly like a word, else named like it, else any fact match
    if !text_words.is_empty() {
        let nw = text_words.len();
        let all = nw >= 2 && mems.iter().any(|m| m.cov == nw);
        // `create update`: two words each naming members, none naming both -> every member named by a word (an
        // all-words match in the body text alone would hide the other names)
        let named: std::collections::BTreeSet<&str> = text_words.iter().filter(|w| mems.iter().any(|m| m.name.to_lowercase().contains(w.as_str()))).map(|w| w.as_str()).collect();
        // (only where the all-words tier would apply and no member is named exactly like a word)
        let names_or = all && nw >= 2 && named.len() >= 2 && !mems.iter().any(|m| m.exact + m.sub == nw || m.exact > 0);
        let tier = if names_or {
            5
        } else if all {
            4
        } else if mems.iter().any(|m| m.exact > 0) {
            3
        } else if mems.iter().any(|m| m.sub > 0) {
            2
        } else {
            1
        };
        for m in mems.iter_mut() {
            let ok = match tier {
                5 => m.exact + m.sub > 0,
                4 => m.cov == nw,
                3 => m.exact > 0,
                2 => m.sub > 0,
                _ => m.hits > 0,
            };
            if ok {
                m.score += (m.exact * 100 + m.sub * 10 + m.hits + 1) as i64;
            }
        }
    }
    let n_mem = mems.len();
    let ntypes = mems.iter().filter(|m| is_type(&m.kind)).count();
    let budget = out.limit.max(8);
    let ranked = !words.is_empty() && mems.iter().any(|m| m.score > 0);
    let mut idx: Vec<usize> = (0..mems.len()).collect();
    if ranked {
        idx.retain(|i| mems[*i].score > 0);
        idx.sort_by(|a, b| mems[*b].score.cmp(&mems[*a].score).then(mems[*a].line.cmp(&mems[*b].line)));
        idx.truncate(budget);
        idx.sort_by_key(|i| mems[*i].line);
    } else {
        // file order; skip a lone top-level type header and fields when the page would overflow
        let only_type = ntypes == 1 && mems.len() > budget;
        idx.retain(|i| !(only_type && is_type(&mems[*i].kind) && mems[*i].container_is_top()));
        if idx.len() > budget {
            idx.retain(|i| mems[*i].kind != "field");
        }
        if idx.len() > budget {
            idx.retain(|i| mems[*i].kind != "const" || mems[*i].vis == "export");
        }
        idx.truncate(budget);
    }
    let shown = idx.len();
    r.head.push(format!(
        "== outline {file} ({n_mem} members, {total_lines} lines){}",
        if ranked { format!(" ranked by: {}", words.join(" ")) } else { String::new() }
    ));
    if cands.len() > 1 {
        r.head.push(format!("(also matches: {})", cands[1..].join(", ")));
    }
    if skipped_here.is_some() {
        r.head.push(format!("   ({file} was skipped: too deep for a full parse; members are a flat scan of top-level declarations, calls are not indexed)"));
    }
    let shown_idx = idx.clone();
    for i in idx {
        let m = &mems[i];
        let annos: Vec<String> = split_annos(&m.annos)
            .into_iter()
            .filter(|a| !a.is_empty())
            .take(3)
            .map(|a| format!("@{}", a.split('(').next().unwrap_or(a)))
            .collect();
        let tag = if lines_asked.iter().any(|l| m.line <= *l && *l <= m.end) { " <- encloses line" } else { "" };
        let mut s = format!("L{}-{} {} {}", m.line, m.end, abbr(&m.kind), m.sig.chars().take(90).collect::<String>());
        let vis = if matches!(m.vis.as_str(), "package" | "local" | "export") { "" } else { m.vis.as_str() };
        if !vis.is_empty() || !annos.is_empty() {
            s.push_str(&format!(" [{}]", format!("{vis} {}", annos.join(" ")).trim()));
        }
        if !m.facts.is_empty() {
            s.push_str(&format!(" | {}", m.facts.join(" | ")));
        }
        s.push_str(tag);
        let s: String = if s.chars().count() > 300 { s.chars().take(299).collect::<String>() + "~" } else { s };
        r.ans("member", s, &file, m.line, m.end, "exact");
    }
    // the next step for a member's body (agents ran sed after an outline)
    if let Some(m) = idx_first_body(&mems, &shown_idx) {
        r.foot.push(format!("(a member's body: aix code {}  or  aix code {file}:{}-{})", m.qname, m.line, m.end));
    }
    if ranked && n_mem > shown {
        r.foot.push(format!("({} more members not matching)", mems.iter().filter(|m| m.score == 0).count()));
    } else if !ranked && n_mem > shown + ntypes.min(1) {
        r.foot.push(format!("(+{} more members: aix outline {} --limit {n_mem}  (or narrow with words))", n_mem - shown, crate::shell_quote(&file)));
        r.truncated = true;
    }
    if ranked && mems.iter().filter(|m| m.score > 0).count() > shown {
        r.truncated = true;
    }
    r.finish(out);
}

/// The first shown member that has a body worth reading (a method or function, else any member).
fn idx_first_body<'a>(mems: &'a [Mem], idx: &[usize]) -> Option<&'a Mem> {
    idx.iter().map(|i| &mems[*i]).find(|m| matches!(m.kind.as_str(), "method" | "function" | "ctor")).or_else(|| idx.first().map(|i| &mems[*i]))
}

impl Mem {
    fn container_is_top(&self) -> bool {
        !self.qname.contains('.')
    }
}

/// Split the stored annotation list (`A, B(x, y), C`) on the commas between annotations only, never on the ones
/// inside parentheses, braces or quotes (`RolesAllowed({"a", "b"})` is one annotation).
pub(crate) fn split_annos(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut quote, mut start) = (vec![], 0i32, None::<char>, 0usize);
    for (i, ch) in s.char_indices() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, '(' | '{' | '[') => depth += 1,
            (None, ')' | '}' | ']') => depth -= 1,
            (None, ',') if depth <= 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        out.push(s[start..].trim());
    }
    out
}
