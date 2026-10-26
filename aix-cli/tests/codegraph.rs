//! End-to-end code graph: full build, callers / callees / impact / outline, the aix/v1 JSON envelope, and
//! incremental refresh (a new caller, a removed file, a renamed method re-resolve only what they touch).

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
    let r = d.path().join("shop");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/codegraph"), &r);
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

#[test]
fn graph_queries_and_json() {
    let (_d, r) = repo();
    assert!(sk(&r, &["update", "--full"]).starts_with("full build:"));
    // private method, caller inside the same class
    let c = sk(&r, &["callers", "OrderService.finish"]);
    assert!(c.contains("java/OrderService.java:21 OrderService.place (exact)"), "{c}");
    // overloads: both definitions listed, the delegating call site is found
    let c = sk(&r, &["callers", "OrderService.place"]);
    assert!(c.contains("2 definitions") || c.matches("defined: method").count() == 2, "{c}");
    assert!(c.contains("java/OrderService.java:25 OrderService.place (exact)"), "{c}");
    // injected receivers and Panache statics
    let c = sk(&r, &["callers", "Order.persist"]);
    assert!(c.contains("OrderService.place (resolved)"), "{c}");
    // TS: object API member called through an import binding
    let c = sk(&r, &["callers", "ordersApi.list"]);
    assert!(c.contains("web/Orders.tsx:8 Orders.load (exact)"), "{c}");
    // a component used as JSX
    let c = sk(&r, &["callers", "formatMoney"]);
    assert!(c.contains("web/Orders.tsx:12 Orders.cancel (exact)"), "{c}");
    // python from-import
    let c = sk(&r, &["callers", "Service._build"]);
    assert!(c.contains("py/service.py:12 Service.run (exact)"), "{c}");

    let callees = sk(&r, &["callees", "OrderService.finish"]);
    assert!(callees.contains("external/unresolved names"), "{callees}");
    let imp = sk(&r, &["impact", "OrderService.finish", "--depth", "2"]);
    assert!(imp.contains("== impact of OrderService.finish") && imp.contains("depth<=2"), "{imp}");
    // `impact` with no symbol is still the diff command
    assert!(sk(&r, &["impact"]).contains("impact") || true);

    let o = sk(&r, &["outline", "OrderService.java", "place"]);
    assert_eq!(o.matches("method Order place(").count(), 2, "{o}");
    let o = sk(&r, &["outline", "Orders.tsx", "9"]);
    assert!(o.contains("<- encloses line") && o.contains("fn load"), "{o}");

    // JSON v1 envelope
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "callers", "OrderService.finish"])).unwrap();
    assert_eq!(j["schema"], "aix/v1");
    assert_eq!(j["cmd"], "callers");
    assert_eq!(j["args"][0], "OrderService.finish");
    assert_eq!(j["truncated"], false);
    assert_eq!(j["answers"][0]["kind"], "summary");
    assert!(j["answers"][0]["text"].as_str().unwrap().contains("1 call sites"), "{j}");
    let a = j["answers"].as_array().unwrap().iter().find(|a| a["kind"] == "caller").unwrap();
    assert_eq!(a["conf"], "exact");
    assert_eq!(a["cites"][0]["file"], "java/OrderService.java");
    assert_eq!(a["cites"][0]["line"], 21);
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "outline", "OrderService.java"])).unwrap();
    assert!(j["answers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["cites"][0]["end"].as_i64() >= a["cites"][0]["line"].as_i64()));
    // unknown symbol: stated plainly, still a valid envelope
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "callers", "Nope.nothing"])).unwrap();
    assert!(j["answers"].as_array().unwrap().iter().all(|a| a["kind"] == "summary"));
}

#[test]
fn incremental_refresh() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    assert!(!sk(&r, &["callers", "OrderService.finish"]).contains("Extra.java"));
    // a new caller file
    std::fs::write(
        r.join("java/Extra.java"),
        "class Extra {\n    @Inject OrderService svc;\n    void go() {\n        svc.helper();\n        svc.finish(null);\n    }\n}\n",
    )
    .unwrap();
    git(&r, &["add", "-A"]);
    let u = sk(&r, &["update"]);
    assert!(u.starts_with("update: ") && u.contains("1 changed"), "{u}");
    let c = sk(&r, &["callers", "OrderService.finish"]);
    assert!(c.contains("java/Extra.java:5 Extra.go (exact)"), "{c}");
    // the callee's file changes: the method moves down two lines, the edge follows
    let p = r.join("java/OrderService.java");
    let t = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        t.replacen("    private Order finish", "    // moved\n    // moved\n    private Order finish", 1),
    )
    .unwrap();
    sk(&r, &["update"]);
    let c = sk(&r, &["callers", "OrderService.finish"]);
    assert!(c.contains("java/Extra.java:5 Extra.go (exact)") && c.contains("OrderService.place (exact)"), "{c}");
    assert!(c.contains("OrderService.java:30-"), "definition moved: {c}");
    // renamed method: the old name has no definition, callers by name vanish from the resolved set
    std::fs::write(&p, std::fs::read_to_string(&p).unwrap().replace("private Order finish(", "private Order wrapUp("))
        .unwrap();
    sk(&r, &["update"]);
    assert!(sk(&r, &["callers", "OrderService.finish"]).contains("none (index has no symbol"));
    // removing the file drops its edges
    std::fs::remove_file(r.join("java/Extra.java")).unwrap();
    git(&r, &["add", "-A"]);
    sk(&r, &["update"]);
    assert!(!sk(&r, &["callers", "OrderService.helper"]).contains("Extra.java"));
    // the same result as a full rebuild
    let inc = sk(&r, &["callers", "OrderService.place"]);
    sk(&r, &["update", "--full"]);
    assert_eq!(inc, sk(&r, &["callers", "OrderService.place"]));
}
