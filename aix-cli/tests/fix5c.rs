//! FIX-5C: incremental updates equal full builds (trait impl order, members sharing a line, go.mod / tsconfig edits),
//! plus the Rust / callees / ambiguity / impact / fixture / find behaviours fixed with them.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn aixdb(repo: &Path, db: &Path, args: &[&str]) -> String {
    let o = Command::new(std::env::var("AIX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_aix").to_string())).arg("--repo").arg(repo).arg("--db").arg(db).args(args).output().unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}{}", String::from_utf8_lossy(&o.stderr), String::from_utf8_lossy(&o.stdout));
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn aix(repo: &Path, args: &[&str]) -> String {
    let db = repo.join("..").join(format!("{}.db", repo.file_name().unwrap().to_string_lossy()));
    aixdb(repo, &db, args)
}

fn write(repo: &Path, rel: &str, text: &str) {
    let p = repo.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r");
    std::fs::create_dir_all(&r).unwrap();
    for (p, t) in files {
        write(&r, p, t);
    }
    git(&r, &["init", "-q"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "init"]);
    (d, r)
}

const EDGES: &str = "SELECT file||':'||line||' '||caller_line||' -> '||callee_file||':'||callee_line||' '||callee||' '||kind||' '||conf FROM call_edges_v ORDER BY 1";

/// The incremental index (updated in place) and a fresh full build of the same tree list the same edges.
fn assert_equal_to_full(r: &Path, what: &str) {
    let inc = aix(r, &["sql", EDGES]);
    let full_db = r.join("..").join("full.db");
    let _ = std::fs::remove_file(&full_db);
    aixdb(r, &full_db, &["update", "--full"]);
    let full = aixdb(r, &full_db, &["sql", EDGES]);
    assert_eq!(inc, full, "{what}: incremental edges differ from a full build");
}

#[test]
fn trait_impl_order_does_not_change_what_an_incremental_update_resolves() {
    // eight implementations of one interface (the resolver follows at most six): which six must not depend on the
    // order the rows were inserted in
    let mut files: Vec<(String, String)> = (0..8).map(|i| (format!("I{i}.java"), format!("public class Impl{i} implements Api {{\n  public void run() {{}}\n  void go(Api a) {{\n    a.run();\n  }}\n}}\n"))).collect();
    files.push(("Api.java".into(), "public interface Api {\n  void run();\n}\n".into()));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (_d, r) = repo(&refs);
    aix(&r, &["update", "--full"]);
    write(&r, "I1.java", "\npublic class Impl1 implements Api {\n  public void run() {}\n  void go(Api a) {\n    a.run();\n  }\n}\n");
    aix(&r, &["update"]);
    assert_equal_to_full(&r, "blank line in an implementation");
}

#[test]
fn members_on_one_line_are_one_unit_when_definitions_move() {
    let (_d, r) = repo(&[
        ("a.php", "<?php\nclass P { function a(){} function b(){} }\nclass Q { function z(){} }\n"),
        ("u.php", "<?php\nfunction u(P $p){ $p->a(); $p->b(); }\n"),
    ]);
    aix(&r, &["update", "--full"]);
    write(&r, "a.php", "<?php\nclass P { function a(){} }\nclass Q { function z(){} function b(){} }\n");
    aix(&r, &["update"]);
    assert_equal_to_full(&r, "b moved from P to Q");
}

#[test]
fn deleting_a_method_keeps_edges_to_fields_declared_beside_a_changed_name() {
    let (_d, r) = repo(&[
        (
            "de.rs",
            "enum Inner {\n    Normal(i32),\n    Broken { path: i32, depth: i32 },\n}\n\npub struct D;\n\nimpl D {\n    pub fn depth(&self) -> i32 { 0 }\n}\n\nimpl Other for D {\n    fn path(&self) -> i32 {\n        0\n    }\n}\n",
        ),
        ("walk.rs", "fn go() {\n    make().depth();\n}\n"),
    ]);
    aix(&r, &["update", "--full"]);
    write(
        &r,
        "de.rs",
        "enum Inner {\n    Normal(i32),\n    Broken { path: i32, depth: i32 },\n}\n\npub struct D;\n\nimpl D {\n    pub fn depth(&self) -> i32 { 0 }\n}\n\nimpl Other for D {\n        0\n    }\n}\n",
    );
    aix(&r, &["update"]);
    assert_equal_to_full(&r, "method signature line deleted");
}

#[test]
fn go_mod_edit_alone_re_resolves_imports() {
    let (_d, r) = repo(&[
        ("go.mod", "module example.com/old\n\ngo 1.21\n"),
        ("util/util.go", "package util\n\nfunc Do() int { return 1 }\n"),
        ("app/app.go", "package app\n\nimport \"example.com/old/util\"\n\nfunc Run() int { return util.Do() }\n"),
    ]);
    aix(&r, &["update"]);
    let before = aix(&r, &["sql", EDGES]);
    assert!(before.contains("util/util.go"), "edge into util before the edit: {before}");
    write(&r, "go.mod", "module example.com/new\n\ngo 1.21\n");
    let out = aix(&r, &["update"]);
    assert!(!out.contains("no update needed") || !aix(&r, &["sql", EDGES]).contains("util/util.go"), "{out}");
    assert_equal_to_full(&r, "go.mod module path changed");
    assert_ne!(before, aix(&r, &["sql", EDGES]), "the module rename moved the edges");
}

fn rust_repo() -> (tempfile::TempDir, PathBuf) {
    repo(&[
        (
            "src/lib.rs",
            "pub mod a;\npub mod b;\npub mod ts_util;\npub mod ext;\nuse crate::ts_util::*;\nuse crate::a::run as arun;\n\nmod m1 { pub fn f() -> i32 { 1 } }\nmod m2 {\n    pub fn f() -> i32 { 2 }\n    pub fn g() { f(); }\n}\n\npub fn top() {\n    walk(1);\n    arun();\n    a::run();\n    b::run();\n    m1::f();\n    m2::f();\n}\npub fn dynr(e: &dyn ext::Extractor) { e.extract(1); }\npub fn gener<T: ext::Extractor>(e: T) { e.extract(2); }\npub fn lens(v: Vec<i32>) { v.len(); v.iter(); }\npub fn unk() { make().len(); }\n",
        ),
        ("src/s.rs", "pub struct S;\nimpl S {\n    pub fn len(&self) -> usize { 0 }\n}\n"),
        ("src/a.rs", "pub fn run() {}\n"),
        ("src/b.rs", "pub fn run() {}\n"),
        ("src/ts_util.rs", "pub fn walk(x: i32) {}\n"),
        (
            "src/ext.rs",
            "pub trait Extractor { fn extract(&self, x: i32); }\npub struct A1;\nimpl Extractor for A1 { fn extract(&self, x: i32) {} }\npub struct A2;\nimpl Extractor for A2 { fn extract(&self, x: i32) {} }\npub struct A3;\nimpl Extractor for A3 { fn extract(&self, x: i32) {} }\npub struct A4;\nimpl Extractor for A4 { fn extract(&self, x: i32) {} }\npub struct A5;\nimpl Extractor for A5 { fn extract(&self, x: i32) {} }\npub struct A6;\nimpl Extractor for A6 { fn extract(&self, x: i32) {} }\npub struct A7;\nimpl Extractor for A7 { fn extract(&self, x: i32) {} }\npub struct A8;\nimpl Extractor for A8 { fn extract(&self, x: i32) {} }\n",
        ),
    ])
}

/// "file:line -> callee_file:callee_line" for the edges leaving `file:line`.
fn edges_from(r: &Path, file: &str, line: u32) -> Vec<String> {
    let q = format!("SELECT callee_file||':'||callee_line||' '||callee FROM call_edges_v WHERE file='{file}' AND line={line} ORDER BY 1");
    aix(r, &["sql", &q]).lines().skip(1).map(str::to_string).collect()
}

#[test]
fn rust_paths_imports_globs_modules_and_trait_dispatch_resolve() {
    let (_d, r) = rust_repo();
    aix(&r, &["update", "--full"]);
    // glob import `use crate::ts_util::*;`
    assert_eq!(edges_from(&r, "src/lib.rs", 15), ["src/ts_util.rs:1 walk"]);
    // `use crate::a::run as arun;`
    assert_eq!(edges_from(&r, "src/lib.rs", 16), ["src/a.rs:1 run"]);
    // `a::run()` and `b::run()` each reach their own module only
    assert_eq!(edges_from(&r, "src/lib.rs", 17), ["src/a.rs:1 run"]);
    assert_eq!(edges_from(&r, "src/lib.rs", 18), ["src/b.rs:1 run"]);
    // same-file inline modules: `m1::f()`, `m2::f()`, and a bare `f()` inside m2
    assert_eq!(edges_from(&r, "src/lib.rs", 19), ["src/lib.rs:8 f"]);
    assert_eq!(edges_from(&r, "src/lib.rs", 20), ["src/lib.rs:10 f"]);
    assert_eq!(edges_from(&r, "src/lib.rs", 11), ["src/lib.rs:10 f"]);
    // `&dyn Trait` and `T: Trait` receivers reach the trait method and all eight implementations (not just six)
    for line in [22, 23] {
        let e = edges_from(&r, "src/lib.rs", line);
        assert_eq!(e.len(), 9, "{line}: {e:?}");
        assert!(e.iter().any(|x| x.ends_with("A8.extract")), "{e:?}");
    }
    // std methods with a known library receiver make no edges
    assert!(edges_from(&r, "src/lib.rs", 24).is_empty());
    // a std method name on a receiver of unknown type is not pinned on a project type that happens to have it
    assert!(edges_from(&r, "src/lib.rs", 25).is_empty(), "{:?}", edges_from(&r, "src/lib.rs", 25));
}

#[test]
fn rust_incremental_equals_full_with_inline_modules_and_globs() {
    let (_d, r) = rust_repo();
    aix(&r, &["update", "--full"]);
    // a module's function renamed: the glob caller loses its edge, the alias caller keeps hers
    write(&r, "src/ts_util.rs", "\npub fn walk(x: i32) {}\npub fn walk2() {}\n");
    aix(&r, &["update"]);
    assert_equal_to_full(&r, "blank line + new fn in a glob-imported module");
    let lib = std::fs::read_to_string(r.join("src/lib.rs")).unwrap();
    write(&r, "src/lib.rs", &lib.replace("mod m1 { pub fn f() -> i32 { 1 } }", "mod m3 { pub fn f() -> i32 { 1 } }"));
    aix(&r, &["update"]);
    assert_equal_to_full(&r, "inline module renamed");
    assert!(edges_from(&r, "src/lib.rs", 19).is_empty(), "m1::f() no longer resolves: {:?}", edges_from(&r, "src/lib.rs", 19));
}

fn two_helpers() -> (tempfile::TempDir, PathBuf) {
    repo(&[
        ("a.py", "def helper():\n    return 1\n"),
        ("b.py", "def helper():\n    return 2\n"),
        ("main.py", "from a import helper\n\n\ndef go():\n    return helper()\n"),
    ])
}

#[test]
fn same_named_functions_are_told_apart_and_selectable() {
    let (_d, r) = two_helpers();
    aix(&r, &["update"]);
    let c = aix(&r, &["callers", "helper"]);
    assert!(c.contains("a::helper") && c.contains("b::helper"), "the hint lists distinguishing qualifiers: {c}");
    assert!(!c.contains("helper, helper"), "{c}");
    // path::name and file:line pick one definition
    for pick in ["b.py::helper", "b.py:1"] {
        let c = aix(&r, &["callers", pick]);
        assert!(c.contains("callers of helper [b.py:1]"), "{pick}: {c}");
    }
    let c = aix(&r, &["callers", "a.py::helper"]);
    assert!(c.contains("main.py:5"), "{c}");
    let c = aix(&r, &["impact", "a.py:1"]);
    assert!(c.contains("impact of helper [a.py:1]"), "{c}");
    // callees never picks one of several silently
    write(&r, "main.py", "from a import helper\n\n\ndef go():\n    return helper()\n\n\ndef helper():\n    return 3\n");
    git(&r, &["add", "-A"]);
    let c = aix(&r, &["callees", "helper"]);
    assert!(c.contains("ambiguous") && c.contains("a::helper") && c.contains("main::helper"), "{c}");
    assert!(aix(&r, &["callees", "main.py::helper"]).contains("callees of helper [main.py:8"), "one is selectable");
}

#[test]
fn impact_says_when_name_only_callers_were_not_followed() {
    let (_d, r) = repo(&[
        ("m.py", "class A:\n    def execute(self):\n        return 1\n\n\nclass B:\n    def execute(self):\n        return 2\n"),
        ("use.py", "def go(x):\n    return x.execute()\n"),
    ]);
    aix(&r, &["update"]);
    let c = aix(&r, &["impact", "A.execute"]);
    assert!(c.contains("1 name-only caller in 1 file not followed; add --conf name to include"), "{c}");
    let c = aix(&r, &["impact", "A.execute", "--conf", "name"]);
    assert!(c.contains("callers by file: use.py (1)") && !c.contains("not followed"), "{c}");
}

#[test]
fn find_points_at_a_symbol_the_keyword_index_does_not_hold() {
    // a method far down a big class is not in the file's keyword text
    let big: String = std::iter::once("class Svc:\n".to_string()).chain((0..80).map(|i| format!("    def method_number_{i}(self):\n        return {i}\n"))).collect();
    let (_d, r) = repo(&[("svc.py", &big)]);
    aix(&r, &["update"]);
    let c = aix(&r, &["find", "method_number_79"]);
    assert!(c.contains("is a symbol") && c.contains("aix symbol method_number_79") && c.contains("[symbol] svc.py:160"), "{c}");
}

#[test]
fn fixtures_are_not_project_facts_for_tasks_feature_endpoint_and_hints() {
    let (_d, r) = repo(&[
        ("TASKS.md", "# Tasks\n\n- [ ] real open item about billing\n"),
        ("tests/fixtures/app/TASKS.md", "# Tasks\n\n- [ ] fixture open item about widgets\n"),
    ]);
    aix(&r, &["update"]);
    let c = aix(&r, &["tasks"]);
    assert!(c.contains("real open item") && !c.contains("fixture open item"), "{c}");
    assert!(c.contains("default excludes: fixtures"), "{c}");
    let c = aix(&r, &["tasks", "--no-default-excludes"]);
    assert!(c.contains("real open item") && c.contains("fixture open item"), "{c}");
}
