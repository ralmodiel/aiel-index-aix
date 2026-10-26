//! `aix privacy-check [--fix] [--deep] [--json]`: scans what aix holds for privacy incidents and says what to do.
//!
//! Read-only by default. Each finding is one line: severity, where, what, the exact fix command. A secret VALUE is never
//! printed: findings name the redactor rule and the location (table and row id, file:line) only. `--fix` applies the safe
//! fixes (purge offending rows/pastes, chmod, unwatch, delete stray temp files), lists every purge and vacuums. Exit status
//! is non-zero while a HIGH finding remains.
//!
//! Checks: (1) stored text the current redactor would still change (index.db, logs.db, pastes.db), (2) stored or registered
//! paths on the hard deny list or under hidden folders of $HOME, (3) pastes whose text came from an agent or the harness,
//! (4) tracked files that look private (deny markers, credential names, redactor hits; names/locations only), (5) permissions,
//! (6) exceeded budgets, (7) watches on files outside the repo.

use std::path::{Path, PathBuf};

use rusqlite::params;

use crate::index::Index;
use crate::logs::*;
use crate::query::Out;

#[derive(Debug, Clone)]
pub struct Finding {
    pub sev: &'static str,
    pub area: String,
    pub what: String,
    pub fix: String,
    pub fixed: bool,
}

fn f(sev: &'static str, area: impl Into<String>, what: impl Into<String>, fix: impl Into<String>) -> Finding {
    Finding { sev, area: area.into(), what: what.into(), fix: fix.into(), fixed: false }
}

/// Rule names the current redactor would still apply to `text` (empty = clean). Names only, never the text.
fn leaks(text: &str) -> Vec<String> {
    if text.is_empty() {
        return vec![];
    }
    let t = if text.len() > 64 * 1024 { &text[..text.floor_char_boundary(64 * 1024)] } else { text };
    let (r, hits) = aix_extract::redact::redact_with_hits(t);
    if r == t {
        return vec![];
    }
    let mut names: Vec<String> = hits.into_iter().map(|h| h.0).collect();
    if names.is_empty() {
        names.push("redactor".into());
    }
    names
}

fn rules_text(rules: &std::collections::BTreeSet<String>) -> String {
    rules.iter().take(4).cloned().collect::<Vec<_>>().join(",")
}

/// Home-relative display form (`~/.x`) back to a real path for the deny-list test.
fn real_of(src: &str) -> PathBuf {
    match (src.strip_prefix("~/"), crate::sys::home()) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(src),
    }
}

fn status_path(dir: &Path) -> PathBuf {
    dir.join("privacy.status")
}

/// Write the summary the SessionStart card reads (`ts issues high`).
fn write_status(dir: &Path, issues: usize, high: usize) {
    use std::io::Write;
    let p = status_path(dir);
    let _ = std::fs::remove_file(&p);
    if let Ok(mut f) = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(&p) {
        let _ = f.write_all(format!("{} {issues} {high}\n", now()).as_bytes());
    }
}

/// (issues, high) from the last check; `None` when none was recorded.
pub fn last_status(dir: &Path) -> Option<(usize, usize)> {
    let t = std::fs::read_to_string(status_path(dir)).ok()?;
    let mut it = t.split_whitespace().skip(1).filter_map(|x| x.parse::<usize>().ok());
    Some((it.next()?, it.next()?))
}

/// The one line of the SessionStart card: only when the last check (or an ingest check) found something that needs action.
pub fn card_line(dir: &Path) -> Option<String> {
    let (n, _) = last_status(dir)?;
    (n > 0).then(|| format!("aix privacy: {n} issue{} — aix privacy-check", if n == 1 { "" } else { "s" }))
}

/// Cheap check of the newest rows an ingest just stored (called after pastes, attachments and log ingests): a row the
/// redactor would still change raises the card's one-line notice until `aix privacy-check --fix` runs.
pub fn post_ingest(store: &Store, name: &str) {
    let Some(dir) = store.path.parent() else { return };
    let rows: Vec<(String, String)> = store
        .conn
        .prepare("SELECT msg, body FROM entries WHERE name=? ORDER BY id DESC LIMIT 100")
        .and_then(|mut q| q.query_map([name], |r| Ok((r.get(0)?, r.get(1)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    if rows.iter().any(|(m, b)| !leaks(m).is_empty() || !leaks(b).is_empty()) {
        let (n, h) = last_status(dir).unwrap_or((0, 0));
        write_status(dir, n.max(1), h.max(1));
    }
}

// ---- the scan ------------------------------------------------------------------------------------------------------------

struct Ctx<'a> {
    ix: &'a Index,
    dir: PathBuf,
    deep: bool,
    fix: bool,
    out: Vec<Finding>,
    purged: Vec<String>,
}

pub fn scan(ix: &Index, deep: bool, fix: bool) -> (Vec<Finding>, Vec<String>) {
    let dir = dir_of(&ix.db_path);
    let mut c = Ctx { ix, dir, deep, fix, out: vec![], purged: vec![] };
    check_perms(&mut c); // first: opening a store re-applies 0600 on its own
    check_logs_db(&mut c);
    check_pastes_db(&mut c);
    check_sets_db(&mut c);
    check_index_db(&mut c);
    check_registrations(&mut c);
    check_tracked(&mut c);
    check_budgets(&mut c);
    (c.out, c.purged)
}

/// Data sets (`aix put`): stored lines and named-field rows the redactor would still change; `--fix` re-redacts them.
fn check_sets_db(c: &mut Ctx) {
    let Ok(Some(st)) = crate::sets::open(&c.dir, false, false) else { return };
    let lim = if c.deep { i64::MAX } else { 2000 };
    for (table, col) in [("lines", "t"), ("recs", "j")] {
        let rows: Vec<(i64, String)> = st
            .conn
            .prepare(&format!("SELECT id, {col} FROM {table} ORDER BY id DESC LIMIT ?"))
            .and_then(|mut q| q.query_map([lim], |r| Ok((r.get(0)?, r.get(1)?))).map(|i| i.flatten().collect()))
            .unwrap_or_default();
        let mut bad = vec![];
        let mut rules = std::collections::BTreeSet::new();
        for (id, t) in &rows {
            let r = leaks(t);
            if !r.is_empty() {
                bad.push((*id, t.clone()));
                rules.extend(r);
            }
        }
        if bad.is_empty() {
            continue;
        }
        let mut fd = f("high", format!("sets.db {table}"), format!("{} stored data-set row(s) the redactor would still change (rules: {})", bad.len(), rules_text(&rules)), "aix privacy-check --fix");
        if c.fix {
            let _ = with_tx(&st.conn, |cn| {
                for (id, t) in &bad {
                    let red = if table == "recs" {
                        let mut v: serde_json::Value = serde_json::from_str(t).unwrap_or(serde_json::Value::Null);
                        aix_extract::redact::redact_json(&mut v);
                        v.to_string()
                    } else {
                        crate::logs::redact_text(t, false)
                    };
                    cn.execute(&format!("UPDATE {table} SET {col}=? WHERE id=?"), rusqlite::params![red, id])?;
                }
                Ok(())
            });
            c.purged.push(format!("sets.db: re-redacted {} {table} row(s)", bad.len()));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
}

fn check_logs_db(c: &mut Ctx) {
    let p = logs_db_path(&c.dir);
    if !p.exists() {
        return;
    }
    let Ok(st) = open_store(&p) else { return };
    let lim = if c.deep { i64::MAX } else { 400 };
    let rows: Vec<(i64, String, String, String, String)> = st
        .conn
        .prepare("SELECT id, msg, body, logger, thread FROM entries ORDER BY id DESC LIMIT ?")
        .and_then(|mut q| q.query_map([lim], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let (mut bad, mut rules, mut first) = (vec![], std::collections::BTreeSet::new(), 0i64);
    for (id, m, b, l, t) in &rows {
        let mut r: Vec<String> = vec![];
        for s in [m, b, l, t] {
            r.extend(leaks(s));
        }
        if !r.is_empty() {
            bad.push(*id);
            rules.extend(r);
            if first == 0 {
                first = *id;
            }
        }
    }
    if !bad.is_empty() {
        let mut fd = f("high", "logs.db entries", format!("{} stored entr{} the redactor would still change (rules: {}; e.g. e{first})", bad.len(), if bad.len() == 1 { "y" } else { "ies" }, rules_text(&rules)), "aix privacy-check --fix");
        if c.fix {
            let _ = with_tx(&st.conn, |cn| {
                for id in &bad {
                    cn.execute("DELETE FROM entries WHERE id=?", [id])?;
                }
                Ok(())
            });
            c.purged.push(format!("logs.db: purged {} entries (ids {}..{})", bad.len(), bad.iter().min().unwrap_or(&0), bad.iter().max().unwrap_or(&0)));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    // templates and alert hits carry a sample message
    let tpls: Vec<(String, String, String)> = st
        .conn
        .prepare("SELECT name, tid, tpl || char(10) || sample || char(10) || frames FROM tpl LIMIT ?")
        .and_then(|mut q| q.query_map([if c.deep { i64::MAX } else { 300 }], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let badt: Vec<&(String, String, String)> = tpls.iter().filter(|t| !leaks(&t.2).is_empty()).collect();
    if !badt.is_empty() {
        let mut fd = f("high", "logs.db templates", format!("{} message template(s) hold text the redactor would still change", badt.len()), "aix privacy-check --fix");
        if c.fix {
            for t in &badt {
                let _ = st.conn.execute("DELETE FROM tpl WHERE name=? AND tid=?", params![t.0, t.1]);
            }
            c.purged.push(format!("logs.db: purged {} templates", badt.len()));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    let hits: Vec<(i64, String)> = st.conn.prepare("SELECT id, msg FROM alert_hits LIMIT 300").and_then(|mut q| q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map(|i| i.flatten().collect())).unwrap_or_default();
    let badh: Vec<i64> = hits.iter().filter(|h| !leaks(&h.1).is_empty()).map(|h| h.0).collect();
    if !badh.is_empty() {
        let mut fd = f("high", "logs.db alert hits", format!("{} alert hit(s) hold text the redactor would still change", badh.len()), "aix privacy-check --fix");
        if c.fix {
            for id in &badh {
                let _ = st.conn.execute("DELETE FROM alert_hits WHERE id=?", [id]);
            }
            c.purged.push(format!("logs.db: purged {} alert hits", badh.len()));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    if c.fix && c.purged.iter().any(|p| p.starts_with("logs.db")) {
        shrink_full(&st.conn);
    }
}

fn purge_paste(st: &Store, id: i64, name: &str) {
    let _ = with_tx(&st.conn, |cn| {
        for t in ["entries", "files", "tpl", "agg", "usage", "prune_log"] {
            cn.execute(&format!("DELETE FROM {t} WHERE name=?"), [name])?;
        }
        cn.execute("DELETE FROM pastes WHERE id=?", [id])?;
        Ok(())
    });
}

fn check_pastes_db(c: &mut Ctx) {
    let p = pastes_db_path(&c.dir);
    if !p.exists() {
        return;
    }
    let Ok(st) = open_store(&p) else { return };
    let lim = if c.deep { i64::MAX } else { 60 };
    // (id, name, origin, src, text)
    let rows: Vec<(i64, String, String, String, String)> = st
        .conn
        .prepare("SELECT id, name, origin, src, text FROM pastes ORDER BY id DESC LIMIT ?")
        .and_then(|mut q| q.query_map([lim], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default(), r.get(3)?, r.get(4)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let mut purge: Vec<(i64, String)> = vec![];
    let (mut n_leak, mut rules) = (0, std::collections::BTreeSet::new());
    let (mut n_agent, mut n_path, mut n_dot) = (0, 0, 0);
    for (id, name, origin, src, text) in &rows {
        let mut bad = false;
        let r = leaks(text);
        if !r.is_empty() {
            n_leak += 1;
            rules.extend(r);
            bad = true;
        }
        if origin == "agent" || (origin != "user-dot" && crate::logq::agent_originated(text)) {
            n_agent += 1;
            bad = true;
        }
        if !src.is_empty() {
            let rp = real_of(src);
            if hard_denied(&rp).is_some() {
                n_path += 1;
                bad = true;
            } else if origin != "user-dot" && src.starts_with("~/.") {
                n_dot += 1;
                bad = true;
            }
        }
        if bad {
            purge.push((*id, name.clone()));
        }
    }
    if n_leak > 0 {
        c.out.push(f("high", "pastes.db text", format!("{n_leak} paste/attachment(s) hold text the redactor would still change (rules: {})", rules_text(&rules)), "aix privacy-check --fix"));
    }
    if n_agent > 0 {
        c.out.push(f("high", "pastes.db origin", format!("{n_agent} paste/attachment(s) came from agent or harness text (hand-backs, notifications, reminders), not from you"), "aix privacy-check --fix"));
    }
    if n_path > 0 {
        c.out.push(f("high", "pastes.db sources", format!("{n_path} attachment(s) come from a deny-listed file (history, keyring, credential store, browser data)"), "aix privacy-check --fix"));
    }
    if n_dot > 0 {
        c.out.push(f("medium", "pastes.db sources", format!("{n_dot} attachment(s) come from a hidden folder of your home without --allow-dotfile"), "aix privacy-check --fix"));
    }
    if c.fix && !purge.is_empty() {
        for (id, name) in &purge {
            purge_paste(&st, *id, name);
        }
        c.purged.push(format!("pastes.db: purged {} item(s) ({})", purge.len(), purge.iter().take(8).map(|p| p.1.clone()).collect::<Vec<_>>().join(", ")));
        shrink_full(&st.conn);
        for fd in c.out.iter_mut().filter(|x| x.area.starts_with("pastes.db")) {
            fd.fixed = true;
        }
    }
    // their parsed entries (sampled)
    let ents: Vec<(i64, String, String)> = st
        .conn
        .prepare("SELECT id, msg, body FROM entries ORDER BY id DESC LIMIT ?")
        .and_then(|mut q| q.query_map([if c.deep { i64::MAX } else { 300 }], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let bad: Vec<i64> = ents.iter().filter(|e| !leaks(&e.1).is_empty() || !leaks(&e.2).is_empty()).map(|e| e.0).collect();
    if !bad.is_empty() {
        let mut fd = f("high", "pastes.db entries", format!("{} parsed paste entr{} the redactor would still change", bad.len(), if bad.len() == 1 { "y" } else { "ies" }), "aix privacy-check --fix");
        if c.fix {
            for id in &bad {
                let _ = st.conn.execute("DELETE FROM entries WHERE id=?", [id]);
            }
            c.purged.push(format!("pastes.db: purged {} parsed entries", bad.len()));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
}

fn check_index_db(c: &mut Ctx) {
    let conn = &c.ix.conn;
    let lim = if c.deep { 1_000_000 } else { 300 };
    let mut changed_entries = false;
    for (table, col) in [("entries", "text"), ("files", "summary"), ("ui_strings", "text"), ("sections", "body"), ("notes", "text")] {
        let rows: Vec<(i64, String)> = conn
            .prepare(&format!("SELECT rowid, {col} FROM {table} WHERE length({col})>8 ORDER BY rowid DESC LIMIT {lim}"))
            .and_then(|mut q| q.query_map([], |r| Ok((r.get(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))).map(|i| i.flatten().collect()))
            .unwrap_or_default();
        let (mut bad, mut rules) = (vec![], std::collections::BTreeSet::new());
        for (id, t) in &rows {
            let r = leaks(t);
            if !r.is_empty() {
                bad.push((*id, t.clone()));
                rules.extend(r);
            }
        }
        if bad.is_empty() {
            continue;
        }
        let mut fd = f("high", format!("index.db {table}.{col}"), format!("{} row(s) hold text the redactor would still change (rules: {}; e.g. rowid {})", bad.len(), rules_text(&rules), bad[0].0), "aix privacy-check --fix (then aix update --full)");
        if c.fix {
            for (id, t) in &bad {
                let _ = conn.execute(&format!("UPDATE {table} SET {col}=?1 WHERE rowid=?2"), params![aix_extract::redact::redact_block(t), id]);
            }
            changed_entries |= table == "entries";
            c.purged.push(format!("index.db: re-redacted {} row(s) in {table}.{col}", bad.len()));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    if changed_entries {
        let _ = conn.execute("INSERT INTO entries_fts(entries_fts) VALUES('rebuild')", []);
    }
    // typed searches kept as usage counts or auto patterns that hold a secret-looking token
    let bad_s: i64 = conn
        .prepare("SELECT regex FROM grep_usage UNION ALL SELECT regex FROM patterns WHERE auto=1")
        .and_then(|mut q| q.query_map([], |r| r.get::<_, String>(0)).map(|i| i.flatten().filter(|r| crate::patterns::sensitive_query(r)).count() as i64))
        .unwrap_or(0);
    if bad_s > 0 {
        let mut fd = f("high", "index.db grep_usage/patterns", format!("{bad_s} stored search(es) or auto pattern(s) look like a secret or token"), "aix privacy-check --fix");
        if c.fix {
            let n = crate::patterns::purge_sensitive(conn);
            c.purged.push(format!("index.db: dropped {n} stored search(es)/auto pattern(s)"));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    // files that must never be indexed at all (shell/REPL history incl. backup and rotated copies, keyrings, ...)
    let paths: Vec<String> = conn
        .prepare("SELECT path FROM files")
        .and_then(|mut q| q.query_map([], |r| r.get::<_, String>(0)).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    let denied: Vec<&String> = paths.iter().filter(|p| hard_denied(Path::new(p.as_str())).is_some()).collect();
    if !denied.is_empty() {
        c.out.push(f(
            "high",
            "index.db files",
            format!("{} indexed file(s) are on the deny list (history, keyring, credential store), e.g. {}", denied.len(), denied.iter().take(3).map(|p| display_path(p)).collect::<Vec<_>>().join(", ")),
            "git rm --cached / delete the file or add it to .gitignore, then aix update --full",
        ));
    }
}

fn check_registrations(c: &mut Ctx) {
    let mut cfg = load_cfg(&c.dir);
    let repo = crate::sys::canonicalize(&c.ix.repo).unwrap_or_else(|_| c.ix.repo.clone());
    let mut remove: Vec<String> = vec![];
    let mut unwatch: Vec<String> = vec![];
    for s in &cfg.logs {
        let p = PathBuf::from(&s.path);
        if hard_denied(&p).is_some() {
            c.out.push(f("high", format!("logs.toml {}", s.name), "a registered log is a deny-listed file (history, keyring, credential store)", format!("aix logs rm {}", s.name)));
            remove.push(s.name.clone());
            continue;
        }
        let home = crate::sys::home().and_then(|h| crate::sys::canonicalize(&h).ok());
        let dot = home.is_some_and(|h| p.strip_prefix(&h).ok().and_then(|r| r.components().next()).is_some_and(|x| x.as_os_str().to_string_lossy().starts_with('.'))) && !p.starts_with(&repo);
        if dot && !s.allow_dot {
            c.out.push(f("high", format!("logs.toml {}", s.name), "a registered log is under a hidden folder of your home without --allow-dotfile", format!("aix logs rm {}", s.name)));
            remove.push(s.name.clone());
            continue;
        }
        let outside = !p.starts_with(&repo) && !s.path.starts_with(repo.to_string_lossy().as_ref());
        if outside && !s.paused {
            c.out.push(f("low", format!("logs.toml {}", s.name), format!("still watching a file outside the repo ({})", display_path(&s.path)), format!("aix logs unwatch {}", s.name)));
            unwatch.push(s.name.clone());
        }
    }
    if c.fix && (!remove.is_empty() || !unwatch.is_empty()) {
        if !remove.is_empty() {
            let p = logs_db_path(&c.dir);
            if let Ok(st) = open_store(&p) {
                for n in &remove {
                    let _ = purge_name(&st, n);
                }
            }
            cfg.logs.retain(|s| !remove.contains(&s.name));
            let _ = save_cfg(&c.dir, &cfg);
            c.purged.push(format!("logs.toml: unregistered and purged {} deny-listed log(s)", remove.len()));
        }
        if !unwatch.is_empty() {
            if let Ok(st) = open_store(&logs_db_path(&c.dir)) {
                for n in &unwatch {
                    set_paused(&st, &c.dir, n, "unwatched by privacy-check", false);
                }
            }
            c.purged.push(format!("watch stopped on {} file(s) outside the repo (resume: aix logs watch <name>)", unwatch.len()));
        }
        for fd in c.out.iter_mut().filter(|x| x.area.starts_with("logs.toml")) {
            fd.fixed = true;
        }
    }
}

/// The deny list is personal (words that must not reach one particular repo, e.g. before open-sourcing it), so it is
/// applied only to a repo that opts in: it ships `scripts/check-private.sh`, or `.aix/config.toml` says
/// `private_markers = true`. Elsewhere the same words are normal project text and would flood the check.
fn load_markers(repo: &std::path::Path) -> Vec<String> {
    let cfg = std::fs::read_to_string(repo.join(".aix/config.toml")).unwrap_or_default();
    let opted = repo.join("scripts/check-private.sh").is_file()
        || cfg.lines().any(|l| l.split('#').next().unwrap_or("").replace(' ', "") == "private_markers=true");
    if !opted {
        return vec![];
    }
    let path = std::env::var_os("AIX_PRIVATE_MARKERS").map(PathBuf::from).or_else(|| crate::sys::home().map(|h| h.join(".config/aix/private-markers")));
    let Some(p) = path else { return vec![] };
    std::fs::read_to_string(p).map(|t| t.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()).unwrap_or_default()
}

fn check_tracked(c: &mut Ctx) {
    let repo = &c.ix.repo;
    let Ok(o) = std::process::Command::new("git").arg("-C").arg(repo).args(["ls-files", "-z"]).output() else { return };
    if !o.status.success() {
        return;
    }
    let files: Vec<String> = String::from_utf8_lossy(&o.stdout).split('\0').filter(|s| !s.is_empty()).map(String::from).collect();
    // names that look private
    let mut names: Vec<&String> = vec![];
    for fl in &files {
        let low = fl.to_ascii_lowercase();
        if [".example", ".sample", ".template", ".dist", ".md"].iter().any(|x| low.ends_with(x)) {
            continue;
        }
        let base = fl.rsplit('/').next().unwrap_or(fl);
        if hard_denied(Path::new(fl)).is_some() || path_name_private(base) {
            names.push(fl);
        }
    }
    if !names.is_empty() {
        c.out.push(f("medium", "git tracked files", format!("{} tracked file name(s) look private, e.g. {}", names.len(), names.iter().take(3).map(|n| n.as_str()).collect::<Vec<_>>().join(", ")), "git rm --cached <path>; add it to .gitignore"));
    }
    // deny markers: file:line only, never the matched text
    let markers = load_markers(repo);
    if !markers.is_empty() {
        let tmp = c.dir.join(format!(".markers-{}", std::process::id()));
        if std::fs::write(&tmp, markers.join("\n") + "\n").is_ok() {
            let _ = crate::sys::chmod(&tmp, 0o600);
            if let Ok(g) = std::process::Command::new("git").arg("-C").arg(repo).args(["grep", "-n", "-I", "-i", "-E", "-f"]).arg(&tmp).arg("--").arg(".").output() {
                let locs: Vec<String> = String::from_utf8_lossy(&g.stdout).lines().filter_map(|l| {
                    let mut it = l.splitn(3, ':');
                    Some(format!("{}:{}", it.next()?, it.next()?))
                }).collect();
                if !locs.is_empty() {
                    c.out.push(f("high", "git tracked files", format!("{} line(s) match your private-marker list, e.g. {}", locs.len(), locs.iter().take(3).cloned().collect::<Vec<_>>().join(", ")), "remove the text from those lines, then scripts/check-private.sh (if the repo has it)"));
                }
            }
            let _ = std::fs::remove_file(&tmp);
        }
        let res: Vec<regex::Regex> = markers.iter().filter_map(|m| regex::RegexBuilder::new(m).case_insensitive(true).size_limit(1 << 20).build().ok()).collect();
        let nm: Vec<&String> = files.iter().filter(|fl| res.iter().any(|r| r.is_match(fl))).collect();
        if !nm.is_empty() {
            c.out.push(f("high", "git tracked files", format!("{} tracked file name(s) match your private-marker list, e.g. {}", nm.len(), nm.iter().take(2).map(|n| n.as_str()).collect::<Vec<_>>().join(", ")), "git mv / git rm --cached the file"));
        }
    }
    // secrets per the redactor (sampled: the 150 most recently changed small files; --deep: all up to 1 MB)
    let mut cand: Vec<(i64, &String)> = files.iter().filter_map(|fl| std::fs::metadata(repo.join(fl)).ok().filter(|m| m.is_file() && m.len() > 0 && m.len() <= if c.deep { 1 << 20 } else { 128 << 10 }).map(|m| (crate::sys::mtime(&m), fl))).collect();
    cand.sort_by_key(|x| std::cmp::Reverse(x.0));
    cand.truncate(if c.deep { 20_000 } else { 150 });
    let mut hit: Vec<(String, std::collections::BTreeSet<String>)> = vec![];
    for (_, fl) in cand {
        if !content_scan_wanted(fl) {
            continue;
        }
        let Ok(t) = std::fs::read_to_string(repo.join(fl)) else { continue };
        // inline unit tests (`#[cfg(test)]` to the end of a Rust file) hold fake secrets on purpose; comments and
        // key blocks elsewhere are still scanned: a real key pasted into a comment is a leak too
        let t = if fl.ends_with(".rs") { t.find("\n#[cfg(test)]").map_or(t.as_str(), |i| &t[..i]).to_string() } else { t };
        let (r, hits) = aix_extract::redact::redact_with_hits(&t[..t.floor_char_boundary(256 * 1024)]);
        let strong: std::collections::BTreeSet<String> = hits.into_iter().map(|h| h.0).filter(|h| !low_confidence_rule(h)).collect();
        if r != t[..t.floor_char_boundary(256 * 1024)] && !strong.is_empty() {
            hit.push((fl.clone(), strong));
        }
    }
    if !hit.is_empty() {
        c.out.push(f("medium", "git tracked files", format!("{} tracked file(s) contain text the redactor treats as a secret (rules named only), e.g. {} [{}]", hit.len(), hit[0].0, rules_text(&hit[0].1)), "check the file; move the value to an ignored env file and rotate it if it was real"));
    }
}

/// Rules that fire on prose, config docs, code shapes and random-looking text: a tracked file is not reported for
/// these alone (only typed provider/private-key/JWT-style rules count as a secret in a tracked file).
pub fn low_confidence_rule(name: &str) -> bool {
    matches!(
        name,
        "backtick" | "kv" | "prose" | "email" | "phone" | "card" | "ip" | "high-entropy" | "opaque-token" | "mixed-token" | "expr-literal" | "env-key" | "name-value" | "yaml-block-value"
            | "yaml-next-line" | "url-encoded-kv" | "cli-flag" | "curl-user" | "argv-secret" | "sql-default" | "sql-secret" | "call-arg" | "base64-secret" | "authz-header" | "national-id"
            | "secret" | "redacted" | "redactor"
    )
}

/// Tracked files whose content is worth a secret scan: not docs, not tests/fixtures, not the redactor's own corpus
/// and sources (they hold fake secrets on purpose).
pub fn content_scan_wanted(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    if [".md", ".mdx", ".rst", ".adoc", ".example", ".sample", ".template", ".dist"].iter().any(|x| low.ends_with(x)) {
        return false;
    }
    if matches!(crate::excl::file_class(path), "test" | "fixture" | "doc") {
        return false;
    }
    !low.split('/').any(|c| c.contains("redact") || c.contains("corpus") || c.starts_with("masks"))
}

/// Credential-like file name (key files, .env, secrets ...).
pub fn path_name_private(base: &str) -> bool {
    crate::logs::credential_like_name(base)
}

fn mode_of(p: &Path) -> Option<u32> {
    std::fs::symlink_metadata(p).ok().filter(|m| !m.file_type().is_symlink()).and_then(|m| crate::sys::mode(&m)).map(|m| m & 0o7777)
}

fn check_perms(c: &mut Ctx) {
    let mut bad: Vec<(PathBuf, u32)> = vec![];
    if let Some(m) = mode_of(&c.dir) {
        if m & 0o077 != 0 {
            bad.push((c.dir.clone(), 0o700));
        }
    }
    // Windows has no modes: the folder's access list (what is created in it inherits that)
    if crate::sys::inherits_acl(&c.dir) {
        let shown = display_path(&c.dir.to_string_lossy());
        let mut fd = f("medium", format!("permissions {shown}"), "it inherits its folder's permissions, so other users of this machine may read the index", "aix privacy-check --fix");
        if c.fix && crate::sys::owner_only_dir(&c.dir).is_ok() {
            c.purged.push(format!("{shown}: access for you only"));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
    if let Ok(rd) = std::fs::read_dir(&c.dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            let p = e.path();
            let sensitive = n.starts_with("index.db") || n.starts_with("logs.db") || n.starts_with("pastes.db") || matches!(n.as_str(), "logs.toml" | "config.toml" | "masks.toml" | "privacy.status");
            if sensitive && e.file_type().is_ok_and(|t| t.is_file()) {
                if let Some(m) = mode_of(&p) {
                    if m & 0o077 != 0 {
                        bad.push((p.clone(), 0o600));
                    }
                }
            }
            // a payload temp file whose worker never came for it
            if n.starts_with(".in-") && std::fs::metadata(&p).is_ok_and(|m| now() - crate::sys::mtime(&m) > 300) {
                c.out.push(f("medium", format!(".aix/{n}"), "a worker payload (raw text) was left behind", "aix privacy-check --fix"));
                if c.fix {
                    let _ = std::fs::remove_file(&p);
                    c.purged.push(format!(".aix: deleted stray worker payload {n}"));
                    if let Some(l) = c.out.last_mut() {
                        l.fixed = true;
                    }
                }
            }
        }
    }
    let masks = crate::sys::home().map(|h| h.join(".config/aix/masks.toml"));
    if let Some(p) = masks {
        if mode_of(&p).is_some_and(|m| m & 0o077 != 0) {
            bad.push((p, 0o600));
        }
    }
    let ld = lock_dir();
    if mode_of(&ld).is_some_and(|m| m & 0o007 != 0) && std::fs::metadata(&ld).is_ok_and(|m| crate::sys::owned_by_me(&m)) {
        bad.push((ld, 0o700));
    }
    for (p, want) in bad {
        let shown = display_path(&p.to_string_lossy());
        let mut fd = f("medium", format!("permissions {shown}"), format!("mode {:o} lets other users in (want {want:o})", mode_of(&p).unwrap_or(0)), format!("chmod {want:o} {shown}"));
        if c.fix && crate::sys::chmod(&p, want).is_ok() {
            c.purged.push(format!("chmod {want:o} {shown}"));
            fd.fixed = true;
        }
        c.out.push(fd);
    }
}

fn check_budgets(c: &mut Ctx) {
    let cfg = load_cfg(&c.dir);
    if let Ok(st) = open_store(&logs_db_path(&c.dir)) {
        let (_, bytes) = usage_of(&st.conn, None);
        if bytes > cfg.global_cap() {
            let mut fd = f("medium", "logs.db budget", format!("{} stored, over the {} budget", human(bytes), human(cfg.global_cap())), "aix privacy-check --fix (or aix logs prune)");
            if c.fix {
                let _ = prune_global(&st, &cfg);
                shrink_full(&st.conn);
                c.purged.push("logs.db: pruned to the budget".into());
                fd.fixed = true;
            }
            c.out.push(fd);
        }
    }
    if let Ok(st) = open_store(&pastes_db_path(&c.dir)) {
        let cap = cfg.budget.paste_global_mb.unwrap_or(PASTE_GLOBAL_MB) as i64 * 1048576;
        let used: i64 = st.conn.query_row("SELECT COALESCE(sum(length(text)),0)+(SELECT COALESCE(sum(bytes),0) FROM entries) FROM pastes", [], |r| r.get(0)).unwrap_or(0);
        let n: i64 = st.conn.query_row("SELECT count(*) FROM pastes", [], |r| r.get(0)).unwrap_or(0);
        if used > cap && n > 1 {
            let mut fd = f("medium", "pastes.db budget", format!("{} stored, over the {} budget", human(used), human(cap)), "aix privacy-check --fix (or aix paste prune)");
            if c.fix {
                let _ = prune_pastes(&st, &cfg);
                c.purged.push("pastes.db: pruned to the budget".into());
                fd.fixed = true;
            }
            c.out.push(fd);
        }
    }
}

// ---- the command -----------------------------------------------------------------------------------------------------------

pub fn run(ix: &mut Index, argv: &[String], out: &mut Out) {
    let fix = argv.iter().any(|a| a == "--fix");
    let deep = argv.iter().any(|a| a == "--deep");
    if fix && std::env::var_os("AIX_LOGS_CLI").is_none() {
        return out.fail("`aix privacy-check --fix` changes stored data: run it in a terminal (the MCP tool runs the read-only check)");
    }
    let (found, purged) = scan(ix, deep, fix);
    let dir = dir_of(&ix.db_path);
    let open: Vec<&Finding> = found.iter().filter(|x| !x.fixed).collect();
    let actionable = open.iter().filter(|x| x.sev != "low").count();
    let high = open.iter().filter(|x| x.sev == "high").count();
    write_status(&dir, actionable, high);
    out.emit(format!(
        "== privacy-check ({}): {} finding(s){}{}",
        if deep { "deep" } else { "sampled" },
        found.len(),
        if found.is_empty() { String::new() } else { format!(", {high} high") },
        if fix { format!(", {} fixed", found.iter().filter(|x| x.fixed).count()) } else { String::new() }
    ));
    let mut sorted: Vec<&Finding> = found.iter().collect();
    sorted.sort_by_key(|x| match x.sev {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    });
    for x in sorted.iter().take(40) {
        out.emit(format!("  [{}] {}: {} -> {}{}", x.sev.to_uppercase(), x.area, x.what, x.fix, if x.fixed { "  (FIXED)" } else { "" }));
        out.hits.push(serde_json::json!({"severity": x.sev, "area": x.area, "what": x.what, "fix": x.fix, "fixed": x.fixed}));
    }
    if sorted.len() > 40 {
        out.emit(format!("  (+{} more)", sorted.len() - 40));
    }
    for p in &purged {
        out.emit(format!("  fixed: {p}"));
    }
    if found.is_empty() {
        out.emit("  nothing found: stored text is clean under the current redactor, paths are not deny-listed, permissions are private");
    } else if !fix && found.iter().any(|x| x.fixed || x.fix.contains("--fix")) {
        out.emit("  `aix privacy-check --fix` applies the safe fixes (purge, chmod, unwatch) and lists each one");
    }
    if high > 0 {
        crate::logq::set_exit(1);
    }
}
