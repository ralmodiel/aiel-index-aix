//! Incremental code-graph updates: in a repo with a tsconfig the graph is not re-resolved from scratch on every
//! update, and an edit that only moves definitions keeps the callers into them, at the new lines.

use std::path::Path;
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn aix(repo: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(repo).args(args).output().unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).to_string()
}

#[test]
fn moved_definitions_keep_their_callers_and_the_tsconfig_signature_is_remembered() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    std::fs::write(r.join("tsconfig.json"), r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}"#).unwrap();
    std::fs::create_dir_all(r.join("src")).unwrap();
    let util = "export function helperOne(x: number) {\n  return x + 1;\n}\n\nexport function helperTwo() {\n  return 2;\n}\n";
    std::fs::write(r.join("src/util.ts"), util).unwrap();
    std::fs::write(r.join("src/app.ts"), "import { helperOne, helperTwo } from '@/util';\n\nexport function run() {\n  return helperOne(1) + helperTwo();\n}\n").unwrap();
    git(r, &["init", "-q"]);
    git(r, &["add", "-A"]);
    git(r, &["commit", "-qm", "init"]);
    aix(r, &["update"]);
    let sig = aix(r, &["sql", "SELECT value FROM meta WHERE key='cg_tscfg'"]);
    assert!(sig.contains("tsconfig"), "the tsconfig signature is stored, so the next update need not re-resolve everything: {sig}");
    // two blank lines on top: both helpers move down by 2, nothing else changes
    std::fs::write(r.join("src/util.ts"), format!("\n\n{util}")).unwrap();
    let c = aix(r, &["callers", "helperTwo", "--conf", "exact,resolved"]);
    assert!(c.contains("src/util.ts:7") && c.contains("src/app.ts:4"), "moved definition and its caller: {c}");
    let c = aix(r, &["callers", "helperOne", "--conf", "exact,resolved"]);
    assert!(c.contains("src/util.ts:3") && c.contains("src/app.ts:4"), "{c}");
    // a real change to helperOne's signature re-resolves it; helperTwo still only moved
    std::fs::write(r.join("src/util.ts"), format!("\n\n{}", util.replace("helperOne(x: number)", "helperOne(x: number, y = 0)"))).unwrap();
    let c = aix(r, &["callers", "helperOne", "--conf", "exact,resolved"]);
    assert!(c.contains("src/app.ts:4"), "{c}");
    let c = aix(r, &["callers", "helperTwo", "--conf", "exact,resolved"]);
    assert!(c.contains("src/util.ts:7") && c.contains("src/app.ts:4"), "{c}");
}

#[test]
fn an_absolute_path_inside_the_repo_works_like_the_relative_one() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().canonicalize().unwrap();
    std::fs::create_dir_all(r.join("src")).unwrap();
    let body: String = (1..=280).map(|i| format!("  const v{i} = {i};\n")).collect();
    std::fs::write(r.join("src/a.ts"), format!("export function big() {{\n{body}  return 0;\n}}\n")).unwrap();
    git(&r, &["init", "-q"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "init"]);
    let abs = r.join("src/a.ts").display().to_string();
    let o = aix(&r, &["outline", &abs]);
    assert!(o.contains("== outline src/a.ts") && o.contains("big"), "{o}");
    let c = aix(&r, &["code", "src/a.ts:1"]);
    assert!(c.contains("--max") && c.contains("--full"), "the cut-off names the one-call options: {c}");
}
