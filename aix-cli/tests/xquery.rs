//! XQuery / MarkLogic end to end: cross-module callers through `import module … at` (relative and absolute
//! locations, the nearest of two copies of a module) and through the namespace URI alone, arity overloads,
//! `local:` functions, `xdmp:invoke` edges, `code` / `outline` on .xqy, REST extension and rewriter endpoints, SJS
//! `require`, and an incremental update equal to a full build.

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

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("mlapp");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/lang/xquery"), &r);
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
    assert!(o.status.success(), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const LIB: &str = "src/main/ml-modules/root/lib";
const APP: &str = "src/main/ml-modules/root/app";

#[test]
fn xquery_graph() {
    let (_d, r) = repo();
    assert!(sk(&r, &["update", "--full"]).starts_with("full build:"));
    let c = sk(&r, &["callers", "u:greet"]);
    // the 1-argument greet: called by the 2-argument one, the attribute expression, the function reference, job.xqy
    // (relative location) and the REST extension (absolute location: the copy nearest to the importer, not vendor-copy/)
    for site in [
        format!("{LIB}/utils.xqy:24 u:greet (exact) -> {LIB}/utils.xqy:17"),
        format!("{LIB}/utils.xqy:29 u:helper (exact) -> {LIB}/utils.xqy:17"),
        format!("{LIB}/utils.xqy:38 u:apply used as value (exact) -> {LIB}/utils.xqy:17"),
        format!("{APP}/job.xqy:4 job.xqy (exact) -> {LIB}/utils.xqy:17"),
        "src/main/ml-modules/services/hello.xqy:7 hello:get (exact) -> src/main/ml-modules/root/lib/utils.xqy:17".to_string(),
        // two arguments: the other overload
        format!("{APP}/main.xqy:7 local:page (exact) -> {LIB}/utils.xqy:22"),
    ] {
        assert!(c.contains(&site), "{site}\n{c}");
    }
    assert!(!c.contains("-> vendor-copy/"), "{c}");
    // a same-named function of another module has its own callers
    let c = sk(&r, &["callers", "other:greet"]);
    assert!(c.contains("1 call sites") && c.contains(&format!("{LIB}/utils.xqy:39 u:apply (exact)")), "{c}");
    // the namespace URI alone (no `at`): resolved, not exact
    let c = sk(&r, &["callers", "other:shout"]);
    assert!(c.contains(&format!("{APP}/main.xqy:14 main.xqy (resolved)")) && c.contains(&format!("{LIB}/utils.xqy:31 u:helper (exact)")), "{c}");
    // local: functions and modules invoked by path
    let c = sk(&r, &["callers", "local:page"]);
    assert!(c.contains(&format!("{APP}/main.xqy:13 main.xqy (exact)")), "{c}");
    let c = sk(&r, &["callers", "job.xqy"]);
    assert!(c.contains(&format!("{APP}/main.xqy:10 main.xqy (exact)")) && c.contains(&format!("{APP}/main.xqy:11 main.xqy (exact)")), "{c}");
    let c = sk(&r, &["callees", "u:apply"]);
    assert!(c.contains("u:helper (exact)") && c.contains("other:greet (exact)") && c.contains("u:greet (exact)"), "{c}");
    let c = sk(&r, &["callees", "main.xqy"]);
    assert!(c.contains("xdmp:invoke") && c.contains("xdmp:eval"), "library names keep their prefix: {c}");
    let i = sk(&r, &["impact", "other:shout"]);
    assert!(i.contains("== impact of other:shout"), "{i}");
    // code and outline
    let c = sk(&r, &["code", "u:helper"]);
    assert!(c.contains(&format!("{LIB}/utils.xqy:27-35")) && c.contains("declare %private function u:helper"), "{c}");
    let c = sk(&r, &["code", &format!("{LIB}/utils.xqy:31")]);
    assert!(c.contains("== u:helper") && c.contains("27 declare %private function"), "{c}");
    let o = sk(&r, &["outline", &format!("{LIB}/utils.xqy")]);
    assert!(o.contains("L1-40 module module namespace u") && o.contains("L27-35 fn declare function u:helper($x) as element(div) [private]"), "{o}");
    // endpoints
    let e = sk(&r, &["sql", "SELECT method || ' ' || path || ' ' || handler FROM endpoints ORDER BY 1"]);
    for x in [
        "GET /v1/resources/hello hello:get",
        "POST /v1/resources/hello hello:post",
        "GET /app/{} /app/main.xqy",
        "ANY /jobs/ /app/job.xqy",
        "ANY /legacy/{} /app/main.xqy",
        "GET /v1/resources/calc GET",
    ] {
        assert!(e.contains(x), "{x}\n{e}");
    }
    // SJS: `require("/lib/tools.sjs")` with an absolute module path
    let c = sk(&r, &["callers", "twice"]);
    assert!(c.contains("src/main/ml-modules/services/calc.sjs:6 get"), "{c}");
}

#[test]
fn xquery_incremental_equals_full() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let q = |r: &Path| {
        let mut s = String::new();
        for sym in ["u:greet", "other:shout", "other:greet", "job.xqy", "local:page"] {
            s.push_str(&sk(r, &["callers", sym, "--all"]));
        }
        s.push_str(&sk(r, &["sql", "SELECT f.path, e.line, e.caller_line, g.path, e.callee_line, e.callee, e.conf FROM call_edges e JOIN files f ON f.rowid=e.fid JOIN files g ON g.rowid=e.cfid ORDER BY 1,2,3,4,5,6"]));
        s
    };
    // job.xqy now calls the 2-argument greet; other.xqy gains a line above shout; vendor-copy disappears
    std::fs::write(r.join(APP).join("job.xqy"), "xquery version \"1.0-ml\";\nimport module namespace u = \"http://example.com/utils\" at \"../lib/utils.xqy\";\n\nu:greet(\"job\", \"Ms\")\n").unwrap();
    let p = r.join(LIB).join("other.xqy");
    std::fs::write(&p, std::fs::read_to_string(&p).unwrap().replacen("declare function other:shout", "(: moved :)\ndeclare function other:shout", 1)).unwrap();
    std::fs::remove_file(r.join("vendor-copy/lib/utils.xqy")).unwrap();
    git(&r, &["add", "-A"]);
    sk(&r, &["update"]);
    let inc = q(&r);
    assert!(inc.contains(&format!("{APP}/job.xqy:4 job.xqy (exact) -> {LIB}/utils.xqy:22")), "{inc}");
    assert!(inc.contains(&format!("{LIB}/other.xqy:5-")), "{inc}");
    sk(&r, &["update", "--full"]);
    assert_eq!(inc, q(&r));
}
