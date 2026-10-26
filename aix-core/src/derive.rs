//! Cross-file layer, rebuilt after every update that changed something (tens of ms): resolve role
//! constants across files, link routes to page files, build menu-derived features and derived entries,
//! and reuse codemap summaries.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use rusqlite::params;

use crate::entries::{add, build, Built, Entry};
use crate::index::{resolve_import, Index};

/// meta: the signatures of the derived features and of the src=1 entries in place.
pub const DERIVED_SIG_F: &str = "derived_sig_f";
pub const DERIVED_SIG_E: &str = "derived_sig_e";
/// meta: present while no path was added or removed since the last derive (an update that does either removes it).
pub const PATHS_OK: &str = "derive_paths_ok";

/// `full`: everything is recomputed. An update instead fills symbols and resolves imports only for the files it
/// wrote (`cg_dirty`), unless a path appeared or went away since the last derive (then every relative import is
/// resolved again), and rewrites the derived features and entries only when they differ from the ones in place.
pub fn run(ix: &mut Index, full: bool) -> Result<()> {
    let tx = ix.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let meta = |k: &str| -> Option<String> { tx.query_row("SELECT value FROM meta WHERE key=?", [k], |r| r.get(0)).ok() };
    // the files written since the last derive are all in `cg_dirty` (the code graph clears it after this stage)
    let scoped = !full && meta("cg_built").is_some();
    let paths_same = scoped && meta(PATHS_OK).is_some();
    // 1. constants: name -> values (TS `NAME`, Java `Class.NAME`)
    let mut consts: HashMap<String, Vec<String>> = HashMap::new();
    let mut by_suffix: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT name, vals FROM consts")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (n, v) = r?;
            let v: Vec<String> = serde_json::from_str(&v).unwrap_or_default();
            if let Some((_, suf)) = n.rsplit_once('.') {
                by_suffix.entry(suf.to_string()).or_insert_with(|| v.clone());
            }
            consts.entry(n).or_insert(v);
        }
    }
    let resolve = |raw: &str| -> String {
        let vals: Vec<String> = serde_json::from_str(raw).unwrap_or_default();
        let mut out: Vec<String> = vec![];
        expand(&vals, &consts, &by_suffix, 0, &mut out);
        out.join(",")
    };
    for (table, cols) in [
        ("routes", vec![("roles", "roles_raw")]),
        ("endpoints", vec![("roles", "roles_raw")]),
        ("menu", vec![("roles", "roles_raw"), ("grp_roles", "grp_roles_raw")]),
    ] {
        for (col, raw) in cols {
            let rows: Vec<(i64, String)> = tx
                .prepare(&format!("SELECT rowid, {raw} FROM {table} WHERE {raw} LIKE '%@%'"))?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            let mut up = tx.prepare(&format!("UPDATE {table} SET {col}=? WHERE rowid=?"))?;
            for (id, r) in rows {
                up.execute(params![resolve(&r), id])?;
            }
        }
    }

    // 1a. late import resolution (before the router composition, which follows import targets). A target is
    // resolve_import(file, source, the file list) when its row is written; it goes stale only when the file list
    // changes: a path that appears (an import starts to resolve, or resolves to an earlier candidate) or goes away (an
    // import resolved to it). Then every relative import is resolved again, as a full build would; with the same
    // paths, only the rows written since the last derive can be unresolved.
    {
        let rel = "(source LIKE '.%' OR source LIKE '@/%' OR source LIKE '~/%')";
        let sql = if !scoped {
            format!("SELECT rowid, file, source, target FROM imports WHERE target='' AND {rel}")
        } else if paths_same {
            format!("SELECT rowid, file, source, target FROM imports WHERE target='' AND {rel} AND file IN (SELECT key FROM cg_dirty WHERE kind='f')")
        } else {
            format!("SELECT rowid, file, source, target FROM imports WHERE {rel}")
        };
        let rows: Vec<(i64, String, String, String)> =
            tx.prepare(&sql)?.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?;
        let files: HashSet<String> = if rows.is_empty() {
            HashSet::new()
        } else {
            tx.prepare("SELECT path FROM files")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?
        };
        let mut up = tx.prepare("UPDATE imports SET target=? WHERE rowid=?")?;
        for (id, f, s, old) in rows {
            let t = resolve_import(&f, &s, &files);
            if t != old && (!t.is_empty() || (scoped && !paths_same)) {
                up.execute(params![t, id])?;
            }
        }
    }

    // 1b. router composition across files (mount prefixes, Django view methods)
    crate::compose::run(&tx)?;

    // 1c. languages whose extractor yields code-graph members but no symbols (Go, Python...): fill `symbols` from the members
    if scoped {
        // only a file written since the last derive can have members and no symbols (the fill ran for every other one;
        // a file's rows are only ever replaced together, by an update that marks it dirty): same rows, same order
        tx.execute_batch(
            "INSERT INTO symbols(file, line, end_line, name, kind, exported, container)
               SELECT m.file, m.line, m.end_line, m.name, m.kind, (m.vis NOT IN ('private','local','protected')), NULLIF(m.container, '')
               FROM members m WHERE m.file IN (SELECT key FROM cg_dirty WHERE kind='f') AND m.kind<>'field' AND m.name<>''
                 AND NOT EXISTS (SELECT 1 FROM symbols s WHERE s.file=m.file) ORDER BY m.rowid;",
        )?;
    } else {
        tx.execute_batch(
            "INSERT INTO symbols(file, line, end_line, name, kind, exported, container)
               SELECT m.file, m.line, m.end_line, m.name, m.kind, (m.vis NOT IN ('private','local','protected')), NULLIF(m.container, '')
               FROM members m WHERE m.kind<>'field' AND m.name<>'' AND m.file NOT IN (SELECT DISTINCT file FROM symbols);",
        )?;
    }

    // 3. route -> page file
    tx.execute_batch(
        "UPDATE routes SET page_file = COALESCE(
           (SELECT i.target FROM imports i WHERE i.file = routes.file AND i.name = routes.component AND i.target != '' LIMIT 1),
           (SELECT s.file FROM symbols s WHERE s.file = routes.file AND s.name = routes.component LIMIT 1),
           (SELECT s.file FROM symbols s WHERE s.name = routes.component AND s.kind = 'component' AND s.exported = 1 LIMIT 1),
           '');",
    )?;

    // 4. menu-derived features + flag routes. Computed in full, then written only when they differ from the rows in
    // place (no other writer touches derived features or src=1 entries; a full build clears both and the signature).
    // Derived rows are never `help` features, so the reads below see the same rows with or without them.
    tx.execute("UPDATE features SET kind='help' WHERE kind='help-menu'", [])?;
    type Feat = (String, i64, String, String, String, String, String, String);
    let mut feats: Vec<Feat> = vec![];
    let mut ents: Vec<Built> = vec![];
    let feat = |feats: &mut Vec<Feat>, file: &str, line: i64, kind: &str, name: &str, route: &str, roles: &str, purpose: &str, extra: &str| {
        feats.push((file.into(), line, kind.into(), name.into(), route.into(), roles.into(), purpose.into(), extra.into()));
    };
    {
        let routes: HashMap<String, (String, String)> = tx
            .prepare("SELECT path, roles, page_file FROM routes")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, r.get::<_, String>(2)?))))?
            .filter_map(Result::ok)
            .collect();
        let help: HashMap<String, String> = tx
            .prepare("SELECT route, purpose FROM features WHERE kind='help'")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .filter_map(Result::ok)
            .collect();
        let subtitle = |file: &str| -> String {
            tx.query_row(
                "SELECT text FROM ui_strings WHERE file=? AND kind='prop:subtitle' ORDER BY line LIMIT 1",
                [file],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_default()
        };
        type MenuRow = (String, i64, String, Option<String>, String, String, String, String, String, String, String);
        let menu: Vec<MenuRow> = tx
            .prepare("SELECT file, line, nav, grp, label, href, roles, grp_roles, keywords, tooltip, tabs FROM menu")?
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            })?
            .collect::<Result<_, _>>()?;
        for (mfile, line, nav, grp, label, href, roles, groles, kw, tip, tabs) in &menu {
            let grp = grp.clone().unwrap_or_default();
            let (rroles, page) = routes.get(href.split('?').next().unwrap_or(href)).cloned().unwrap_or_default();
            let purpose = help
                .get(href)
                .cloned()
                .filter(|s| !s.is_empty())
                .or_else(|| Some(subtitle(&page)).filter(|s| !s.is_empty()))
                .or_else(|| Some(tip.clone()).filter(|s| !s.is_empty()))
                .or_else(|| {
                    tx.query_row("SELECT text FROM llm_notes WHERE kind='feature' AND key=?", [href], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                    .map(|t| format!("{t} (local-llm)"))
                })
                .unwrap_or_default();
            let eff = [rroles.as_str(), roles.as_str(), groles.as_str()]
                .into_iter()
                .find(|x| !x.is_empty())
                .unwrap_or("")
                .to_string();
            let file = if page.is_empty() { mfile.clone() } else { page.clone() };
            let extra = format!("{nav}/{grp}; tabs: {tabs}; keywords: {kw}");
            feat(&mut feats, &file, *line, "menu", label, href, &eff, &purpose, &extra);
            let text = format!(
                "page '{label}' ({href}, {nav}/{grp}) for {}: {purpose} {tip} keywords: {kw} {tabs}",
                if eff.is_empty() { "everyone" } else { &eff }
            );
            ents.push(build(Entry { kind: "feature", file: mfile, line: *line as u32, reference: href, text, src: 1 }));
            let mtext = format!("{label} {href} {grp} {nav} {kw} {tip} {tabs}");
            ents.push(build(Entry { kind: "menu", file: mfile, line: *line as u32, reference: href, text: mtext, src: 1 }));
            for t in tabs.split("; ").filter(|t| !t.is_empty()) {
                let (tt, tk) = t.split_once('=').unwrap_or((t, ""));
                feat(&mut feats, &file, *line, "tab", &format!("{label} › {tt}"), &format!("{href}?tab={tk}"), &eff, "", nav);
            }
        }
        // routes no menu item or help entry covers are features too (deep links, portals, auth pages)
        let lone: Vec<(String, i64, String, String, String, String)> = tx
            .prepare(
                "SELECT file, line, path, component, roles, page_file FROM routes WHERE component != ''
                 AND path NOT IN (SELECT href FROM menu) AND path NOT IN (SELECT route FROM features WHERE kind='help')",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?;
        for (f, l, p, c, roles, page) in lone {
            let purpose = subtitle(&page);
            let file = if page.is_empty() { f } else { page };
            feat(&mut feats, &file, l, "route", &c, &p, &roles, &purpose, "");
        }
        // per-page help for pages the menu already covers is folded into the menu feature
        tx.execute("UPDATE features SET kind='help-menu' WHERE kind='help' AND route IN (SELECT href FROM menu)", [])?;
        let flagged: Vec<(String, i64, String, String, String, String)> = tx
            .prepare("SELECT file, line, path, roles, feature, page_file FROM routes WHERE feature != ''")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?;
        for (f, l, p, roles, feat_name, page) in flagged {
            let file = if page.is_empty() { f } else { page };
            feat(&mut feats, &file, l, "flag-route", &feat_name, &p, &roles, &format!("route gated by feature flag '{feat_name}'"), "");
        }
        // route + endpoint entries (they carry resolved roles)
        let rts: Vec<(String, i64, String, String, String, String)> = tx
            .prepare("SELECT file, line, path, COALESCE(component,''), page_file, roles FROM routes")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?;
        for (f, l, p, c, pf, roles) in rts {
            let text = format!("{p} {c} {pf} roles {}", roles.replace(',', " "));
            ents.push(build(Entry { kind: "route", file: &f, line: l as u32, reference: &p, text, src: 1 }));
        }
        let eps: Vec<(String, i64, String, String, String, String, String)> = tx
            .prepare("SELECT file, line, method, path, class, handler, roles FROM endpoints")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?
            .collect::<Result<_, _>>()?;
        for (f, l, m, p, c, h, roles) in eps {
            let text = format!("{m} {p} {c}.{h} roles {}", roles.replace(',', " "));
            let r = format!("{m} {p}");
            ents.push(build(Entry { kind: "endpoint", file: &f, line: l as u32, reference: &r, text, src: 1 }));
        }
    }
    // the signatures of the rows to write, in order
    let hash = |rows: &mut dyn Iterator<Item = Vec<String>>| -> String {
        let mut h = blake3::Hasher::new();
        for r in rows {
            for x in r {
                h.update(&(x.len() as u64).to_le_bytes());
                h.update(x.as_bytes());
            }
            h.update(b"\n");
        }
        h.finalize().to_hex().to_string()
    };
    let sig_f = hash(&mut feats.iter().map(|f| vec![f.0.clone(), f.1.to_string(), f.2.clone(), f.3.clone(), f.4.clone(), f.5.clone(), f.6.clone(), f.7.clone()]));
    let sig_e = hash(&mut ents.iter().map(|e| e.key().to_vec()));
    // derived features also stay after every other feature (as a rewrite leaves them): a query that reads features in
    // table order sees the same rows first
    let after: bool = tx
        .query_row(
            "SELECT COALESCE((SELECT max(rowid) FROM features WHERE derived=0) < (SELECT min(rowid) FROM features WHERE derived=1), 1)",
            [],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if full || !after || meta(DERIVED_SIG_F).as_deref() != Some(sig_f.as_str()) {
        tx.execute("DELETE FROM features WHERE derived=1", [])?;
        let mut ins = tx.prepare(
            "INSERT INTO features(file,line,kind,name,route,roles,purpose,extra,derived) VALUES(?,?,?,?,?,?,?,?,1)",
        )?;
        for f in &feats {
            ins.execute(params![f.0, f.1, f.2, f.3, f.4, f.5, f.6, f.7])?;
        }
        tx.execute("INSERT OR REPLACE INTO meta VALUES(?, ?)", params![DERIVED_SIG_F, sig_f])?;
    }
    if full || meta(DERIVED_SIG_E).as_deref() != Some(sig_e.as_str()) {
        tx.execute("DELETE FROM entries WHERE src=1", [])?;
        crate::entries::write_built(&tx, &ents)?;
        tx.execute("INSERT OR REPLACE INTO meta VALUES(?, ?)", params![DERIVED_SIG_E, sig_e])?;
    }
    tx.execute("INSERT OR REPLACE INTO meta VALUES(?, '1')", [PATHS_OK])?;
    tx.commit()?;
    codemap_summaries(ix)?;
    infer_fixed(ix)?;
    Ok(())
}


/// Findings in docs and task lists that a later change probably fixed: an open doc finding becomes `likely-fixed` (shown
/// tagged, never hidden: on a real repo about 3 in 4 topic-word matches were wrong) (with the fix
/// commit in `sha`) when a later fix commit touches a file the finding names and its subject shares at least two topic
/// words with the finding, or when the finding quotes code (`like this(...)`) that its named file no longer contains.
/// Returns how many findings flipped.
pub fn infer_fixed(ix: &mut Index) -> Result<usize> {
    use std::sync::LazyLock;
    static FILE_TOK: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\b([A-Za-z][A-Za-z0-9_]*\.(?:java|kt|tsx|ts|py|go|rs|sql|sh|mjs|js))\b").unwrap());
    static TICKS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"`([^`\n]{10,140})`").unwrap());
    static IDENT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\b[a-z]+(?:[A-Z][a-z0-9]+){1,}\b|\b(?:[A-Z][a-z0-9]+){2,}\b").unwrap());
    static WORD: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[A-Za-z]{5,}").unwrap());
    const STOP: &[&str] = &["which", "there", "their", "would", "should", "could", "about", "other", "these", "those", "where", "while", "after", "before", "being", "between", "every", "still", "using", "under", "within", "without", "return", "returns", "because", "needs", "check", "checks", "never", "again", "first", "second", "third", "finding", "findings", "issue", "issues", "problem", "wrong", "fixed", "missing", "should", "bug"];
    let conn = &ix.conn;
    // basename -> the one path having it
    let mut by_base: HashMap<String, Vec<String>> = HashMap::new();
    for r in conn.prepare("SELECT path FROM files WHERE path NOT LIKE 'docs/%' AND path NOT LIKE '%.md'")?.query_map([], |r| r.get::<_, String>(0))?.flatten() {
        by_base.entry(r.rsplit('/').next().unwrap_or(&r).to_string()).or_default().push(r);
    }
    // fix commits: (seq, short, subject words, files)
    struct Fx {
        seq: i64,
        short: String,
        date: String,
        words: HashSet<String>,
        subject: String,
        files: HashSet<String>,
    }
    let mut fixes: Vec<Fx> = vec![];
    {
        let mut st = conn.prepare("SELECT c.seq, c.short, c.date, c.subject, group_concat(f.path, char(10)) FROM commits c JOIN commit_files f ON f.sha=c.sha WHERE c.is_fix=1 AND c.is_revert=0 GROUP BY c.sha")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?)))?.flatten() {
            let words = WORD.find_iter(&r.3).map(|m| m.as_str().to_lowercase().chars().take(6).collect::<String>()).collect();
            fixes.push(Fx { seq: r.0, short: r.1, date: r.2, words, subject: r.3.to_lowercase(), files: r.4.lines().map(str::to_string).collect() });
        }
    }
    if fixes.is_empty() {
        return Ok(0);
    }
    // when each finding file first appeared (seq)
    let first_seq: HashMap<String, i64> = {
        let mut st = conn.prepare("SELECT f.path, MIN(c.seq) FROM commit_files f JOIN commits c ON c.sha=f.sha WHERE f.path LIKE '%.md' GROUP BY f.path")?;
        let v = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?.flatten().collect();
        v
    };
    let cand: Vec<(String, i64, String, String, String)> = {
        let mut st = conn.prepare("SELECT file, line, kind, date, text FROM bugs WHERE kind IN ('doc','tasks-found') AND status IN ('','open')")?;
        let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.flatten().collect();
        v
    };
    let mut flips: Vec<(String, i64, String, String)> = vec![]; // file, line, kind, fixed-by
    let mut text_cache: HashMap<String, Option<String>> = HashMap::new();
    for (file, line, kind, date, text) in cand {
        let mut cited: Vec<String> = vec![];
        for m in FILE_TOK.captures_iter(&text) {
            if let Some(v) = by_base.get(&m[1]) {
                if v.len() == 1 && !cited.contains(&v[0]) {
                    cited.push(v[0].clone());
                }
            }
        }
        if cited.is_empty() {
            continue;
        }
        let stems: HashSet<String> = cited.iter().flat_map(|c| WORD.find_iter(c.rsplit('/').next().unwrap_or(c)).map(|m| m.as_str().to_lowercase().chars().take(6).collect::<String>()).collect::<Vec<_>>()).collect();
        let topic: HashSet<String> = WORD
            .find_iter(&text)
            .map(|m| m.as_str().to_lowercase())
            .filter(|w| !STOP.contains(&w.as_str()))
            .map(|w| w.chars().take(6).collect::<String>())
            .filter(|w| !stems.contains(w))
            .collect();
        let idents: Vec<String> = IDENT
            .find_iter(&text)
            .map(|m| m.as_str().to_lowercase())
            .filter(|i| !cited.iter().any(|c| c.to_lowercase().contains(i.as_str())) && !i.ends_with("java"))
            .collect();
        let lo = first_seq.get(&file).copied().unwrap_or(0);
        let mut by: Option<String> = None;
        for f in fixes.iter().filter(|f| f.seq > lo && (date.is_empty() || f.date.as_str() >= date.as_str())) {
            if !cited.iter().any(|c| f.files.contains(c)) {
                continue;
            }
            let shared = topic.intersection(&f.words).count();
            // strong: the fix names an identifier the finding names (a method / class), weak: several topic words, fewer
            // when the subject is short and so cannot match by accident
            let strong = idents.iter().any(|i| f.subject.contains(i.as_str())) && shared >= 1;
            if strong || shared >= if f.subject.len() > 140 { 3 } else { 2 } {
                // the words match; the commit must also change the code the finding points at (its cited lines, else
                // a hunk naming one of its identifiers): a commit that only touched the same file is not the fix
                if !fix_touches(&ix.repo, &f.short, &cited, &text, &idents) {
                    continue;
                }
                by = Some(f.short.clone());
                break;
            }
        }
        if by.is_none() {
            // the quoted code is gone from the file the finding names
            let snippets: Vec<String> = TICKS
                .captures_iter(&text)
                .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
                .filter(|s| s.contains(['(', '=']) && s.chars().any(|c| c.is_alphabetic()) && !FILE_TOK.is_match(s) && !s.starts_with(['/', '$']))
                .collect();
            if !snippets.is_empty() && fixes.iter().any(|f| f.seq > lo && cited.iter().any(|c| f.files.contains(c))) {
                let mut all_gone = true;
                for c in &cited {
                    let t = text_cache.entry(c.clone()).or_insert_with(|| crate::query::read_indexed(ix, c).map(|t| t.split_whitespace().collect::<Vec<_>>().join(" ")));
                    match t {
                        Some(t) => {
                            if snippets.iter().any(|s| t.contains(s.as_str())) {
                                all_gone = false;
                            }
                        }
                        None => all_gone = false,
                    }
                }
                if all_gone {
                    by = Some("code-changed".into());
                }
            }
        }
        if let Some(b) = by {
            flips.push((file, line, kind, b));
        }
    }
    let n = flips.len();
    if n > 0 {
        let tx = ix.conn.transaction()?;
        {
            let mut up = tx.prepare("UPDATE bugs SET status='likely-fixed', sha=CASE WHEN sha='' THEN ?4 ELSE sha END WHERE file=?1 AND line=?2 AND kind=?3")?;
            for (f, l, k, b) in &flips {
                up.execute(params![f, l, k, if b == "code-changed" { "" } else { b.as_str() }])?;
            }
        }
        tx.commit()?;
    }
    Ok(n)
}

/// Does commit `sha` change what a finding points at? Its hunks (old side, git's coordinates before the commit) must
/// overlap a `File.ext:A[-B]` range the finding cites in one of the `cited` files, or, with no range cited, a hunk
/// (its header context or changed lines) must name one of the finding's identifiers. No range and no identifier, or
/// git unavailable: true (the subject match stands, as before).
fn fix_touches(repo: &std::path::Path, sha: &str, cited: &[String], text: &str, idents: &[String]) -> bool {
    use std::sync::LazyLock;
    static RANGE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\b([A-Za-z][A-Za-z0-9_]*\.[A-Za-z]{1,6}):(\d{1,6})(?:-(\d{1,6}))?").unwrap());
    static HUNK: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@(.*)$").unwrap());
    let mut ranges: Vec<(String, i64, i64)> = vec![];
    for c in RANGE.captures_iter(text) {
        if let Some(f) = cited.iter().find(|f| f.rsplit('/').next() == Some(&c[1])) {
            let a: i64 = c[2].parse().unwrap_or(0);
            let b: i64 = c.get(3).and_then(|x| x.as_str().parse().ok()).unwrap_or(a).max(a);
            ranges.push((f.clone(), a, b));
        }
    }
    if ranges.is_empty() && idents.is_empty() {
        return true;
    }
    let Ok(o) = std::process::Command::new("git").arg("-C").arg(repo).args(["--no-pager", "show", "--format=", "-U0", "--no-color", "--no-ext-diff", sha, "--"]).args(cited).output() else { return true };
    if !o.status.success() {
        return true;
    }
    let diff = String::from_utf8_lossy(&o.stdout);
    let mut file = String::new();
    let mut cur_hit = false;
    for l in diff.lines() {
        if let Some(p) = l.strip_prefix("+++ b/").or_else(|| l.strip_prefix("--- a/")) {
            file = p.to_string();
            continue;
        }
        if let Some(h) = HUNK.captures(l) {
            let a: i64 = h[1].parse().unwrap_or(0);
            let n: i64 = h.get(2).and_then(|x| x.as_str().parse().ok()).unwrap_or(1);
            let (lo, hi) = (a, a + n.max(1) - 1);
            if ranges.iter().any(|(f, ra, rb)| *f == file && lo <= rb + 2 && hi + 2 >= *ra) {
                return true;
            }
            cur_hit = ranges.is_empty() && idents.iter().any(|i| h[3].to_lowercase().contains(i.as_str()));
            if cur_hit {
                return true;
            }
            continue;
        }
        if ranges.is_empty() && !cur_hit && (l.starts_with('+') || l.starts_with('-')) && idents.iter().any(|i| l.to_lowercase().contains(i.as_str())) {
            return true;
        }
    }
    false
}

/// Reuse `.ai/codemap.json` summaries (from the local-llm harness `codemap` tool) when the file's git blob
/// still matches the sha codemap recorded.
pub fn codemap_summaries(ix: &mut Index) -> Result<usize> {
    let p = ix.repo.join(".ai/codemap.json");
    let Ok(t) = std::fs::read_to_string(&p) else {
        return Ok(0);
    };
    let pending: i64 = ix.conn.query_row("SELECT count(*) FROM files WHERE summary=''", [], |r| r.get(0))?;
    if pending == 0 {
        return Ok(0);
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else {
        return Ok(0);
    };
    let Some(files) = v.get("files").and_then(|f| f.as_object()) else {
        return Ok(0);
    };
    let tx = ix.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut n = 0;
    {
        let empty: Vec<String> = tx
            .prepare("SELECT path FROM files WHERE summary=''")?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut up = tx.prepare("UPDATE files SET summary=?, summary_source='codemap' WHERE path=?")?;
        for path in empty {
            let Some(e) = files.get(&path) else { continue };
            let (Some(sum), Some(sha)) =
                (e.get("summary").and_then(|x| x.as_str()), e.get("sha").and_then(|x| x.as_str()))
            else {
                continue;
            };
            // codemap keys summaries by sha1(text)[:12]
            let text = std::fs::read(ix.repo.join(&path))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            if sum.is_empty()
                || sha.is_empty()
                || !sha1_smol::Sha1::from(text.as_bytes()).digest().to_string().starts_with(sha)
            {
                continue;
            }
            up.execute(params![aix_extract::text::redact(sum), path])?;
            tx.prepare_cached("DELETE FROM entries WHERE file=? AND src=3")?.execute([&path])?;
            add(
                &tx,
                Entry {
                    kind: "summary",
                    file: &path,
                    line: 1,
                    reference: "codemap",
                    text: format!("{path}: {sum}"),
                    src: 3,
                },
            )?;
            n += 1;
        }
    }
    tx.commit()?;
    Ok(n)
}

/// Expand `@NAME` references through the constant tables (recursively, bounded).
fn expand(
    vals: &[String],
    consts: &HashMap<String, Vec<String>>,
    by_suffix: &HashMap<String, Vec<String>>,
    depth: u8,
    out: &mut Vec<String>,
) {
    for v in vals {
        match v.strip_prefix('@') {
            Some(name) => {
                let name = name.trim_start_matches("...");
                let hit = consts.get(name).or_else(|| by_suffix.get(name.rsplit('.').next().unwrap_or(name)));
                match hit {
                    Some(vs) if depth < 8 => expand(vs, consts, by_suffix, depth + 1, out),
                    _ => {
                        if !out.iter().any(|x| x == name) {
                            out.push(name.to_string())
                        }
                    }
                }
            }
            None => {
                if !out.contains(v) {
                    out.push(v.clone())
                }
            }
        }
    }
}
