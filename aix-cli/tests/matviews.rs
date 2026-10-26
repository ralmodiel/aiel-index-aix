//! Materialized summaries (aix_core::matviews): filled by a full build, kept equal to the queries they replace by an
//! incremental update after edits, and equal to what a full rebuild of the same tree produces.

use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn repo(fixture: &str) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("acme");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures").join(fixture), &r);
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    (d, r)
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("AIX_EMBED_URL", "")
        .env("HOME", repo)
        .output()
        .unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// The summaries with file ids spelled as paths (ids are not stable across a full rebuild).
fn dump(repo: &Path) -> (Vec<(String, i64)>, Vec<(String, String, String, i64, i64)>) {
    let c = rusqlite::Connection::open(repo.join(".aix/index.db")).unwrap();
    assert!(aix_core::matviews::ready(&c), "summaries current after an update");
    let bad = aix_core::matviews::check(&c);
    assert!(bad.is_empty(), "{bad:?}");
    let a = c
        .prepare("SELECT target, n FROM mv_import_fanin ORDER BY target")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let b = c
        .prepare("SELECT a.tbl, a.rw, f.path, a.cline, a.n FROM mv_table_access a JOIN files f ON f.rowid=a.cfid ORDER BY 1, 2, 3, 4")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (a, b)
}

fn edit(repo: &Path, file: &str, f: impl Fn(String) -> String) {
    let p = repo.join(file);
    let t = std::fs::read_to_string(&p).unwrap();
    std::fs::write(&p, f(t)).unwrap();
}

#[test]
fn summaries_follow_incremental_updates_and_match_a_full_rebuild() {
    for fixture in ["webapp", "datamodel"] {
        let (_d, r) = repo(fixture);
        sk(&r, &["update", "--full"]);
        let (fanin0, access0) = dump(&r);
        assert!(!fanin0.is_empty(), "{fixture}: imports summarized");
        if fixture == "datamodel" {
            assert!(!access0.is_empty(), "{fixture}: table accesses summarized");
        }
        // three edits: a new import, imports removed, and a service change that moves table accesses
        edit(&r, "frontend/src/pages/Orders.tsx", |t| format!("import {{ ROLES as R2 }} from '../lib/roles';\n{t}"));
        edit(&r, "frontend/src/pages/Reports.tsx", |t| t.lines().filter(|l| !l.trim_start().starts_with("import ")).collect::<Vec<_>>().join("\n"));
        let svc = if fixture == "datamodel" { "backend/src/main/java/com/acme/service/OrderService.java" } else { "backend/src/main/java/com/acme/api/OrderResource.java" };
        edit(&r, svc, |t| format!("// moved\n\n\n{t}"));
        sk(&r, &["update"]);
        let inc = dump(&r);
        assert_ne!(inc.0, fanin0, "{fixture}: the import edits changed the fan-in summary");
        if fixture == "datamodel" {
            assert_ne!(inc.1, access0, "{fixture}: the shifted lines changed the access summary");
        }
        sk(&r, &["update", "--full"]);
        let full = dump(&r);
        assert_eq!(inc, full, "{fixture}: incremental summaries equal a full rebuild");
    }
}

#[test]
fn an_index_without_summaries_is_migrated_in_place_and_answers_the_same() {
    let (_d, r) = repo("datamodel");
    sk(&r, &["update", "--full"]);
    let before = (sk(&r, &["--no-refresh", "table", "orders"]), sk(&r, &["--no-refresh", "trace", "/orders"]), sk(&r, &["--no-refresh", "brief", "/orders"]));
    // as an index built before the summaries existed
    {
        let c = rusqlite::Connection::open(r.join(".aix/index.db")).unwrap();
        c.execute_batch("DROP TABLE mv_import_fanin; DROP TABLE mv_table_access; DELETE FROM meta WHERE key IN ('mv_ver','mv_built');").unwrap();
        assert!(!aix_core::matviews::ready(&c));
    }
    // the base-table queries answer meanwhile
    let fallback = (sk(&r, &["--no-refresh", "table", "orders"]), sk(&r, &["--no-refresh", "trace", "/orders"]), sk(&r, &["--no-refresh", "brief", "/orders"]));
    assert_eq!(before, fallback);
    // the next update (nothing changed in the tree) creates and fills them
    sk(&r, &["update"]);
    dump(&r);
    let after = (sk(&r, &["--no-refresh", "table", "orders"]), sk(&r, &["--no-refresh", "trace", "/orders"]), sk(&r, &["--no-refresh", "brief", "/orders"]));
    assert_eq!(before, after);
}
