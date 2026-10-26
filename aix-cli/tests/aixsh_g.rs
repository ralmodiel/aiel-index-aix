//! The .gitignore preflight: `aix ignore-check`, the first-build gate (STOP, exit 2), aix-init's stop (exit 3) and the
//! acceptance hash in .aix/config, the card warning for a new secret, the tooling bypass, the MCP command.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const STOP: &str = "STOP: .gitignore is missing or incomplete";
const CLEAN_IGNORE: &str = ".env*\n.DS_Store\n";

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

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A git repo with the given files committed (`gitignore` None: no .gitignore at all).
fn repo(d: &Path, gitignore: Option<&str>, files: &[(&str, &str)]) -> PathBuf {
    let r = d.join("repo");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, "src/app.ts", "export function hello(): number {\n  return 1;\n}\n");
    if let Some(g) = gitignore {
        write(&r, ".gitignore", g);
    }
    for (p, t) in files {
        write(&r, p, t);
    }
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    r
}

/// (exit code, stdout, stderr) of `aix --repo <r> args`, with the harness bypass removed.
fn aix(r: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(r)
        .args(args)
        .env_remove("AIX_ACCEPT_IGNORE")
        .env_remove("AIX_DB")
        .env("HOME", r.parent().unwrap())
        .env("AIX_EMBED_URL", "")
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn no_gitignore_is_high_and_lists_what_would_be_indexed() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[]);
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("(no .gitignore)") && out.contains("[HIGH] no .gitignore at the repo root"), "{out}");
    assert!(out.contains("would index: 1 files") && out.contains("src/ 1 files"), "{out}");
    assert!(!r.join(".aix").exists(), "a read-only check never creates .aix");
    let (_, sug, _) = aix(&r, &["ignore-check", "--suggest"]);
    assert!(sug.contains("# any stack\n.env*\n.DS_Store"), "{sug}");
}

#[test]
fn node_modules_untracked_is_high_and_absent_is_medium() {
    let d = tempfile::tempdir().unwrap();
    // present: node_modules exists, untracked, not ignored
    let r = repo(d.path(), Some(CLEAN_IGNORE), &[("package.json", "{}\n")]);
    write(&r, "node_modules/left-pad/index.js", "module.exports = 1;\n");
    write(&r, "node_modules/left-pad/package.json", "{}\n");
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(
        out.contains("[HIGH] expected .gitignore entry missing for Node: node_modules/ (present, untracked)"),
        "{out}"
    );
    assert!(out.contains("-> add to .gitignore: `node_modules/`"), "{out}");
    // absent: a Node repo whose .gitignore lacks node_modules is still asked about (medium)
    let d2 = tempfile::tempdir().unwrap();
    let r2 = repo(d2.path(), Some(CLEAN_IGNORE), &[("web/package.json", "{}\n")]);
    let (c, out, _) = aix(&r2, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(
        out.contains("[MEDIUM] expected .gitignore entry missing for Node: node_modules/ (not present yet)"),
        "{out}"
    );
    assert_eq!(out.matches("[HIGH]").count(), 0, "{out}");
    let (_, sug, _) = aix(&r2, &["ignore-check", "--suggest"]);
    assert!(sug.contains("# Node\n") && sug.contains("\nnode_modules/\n") && sug.contains("\ndist/"), "{sug}");
    // asked once: the first build stops, accepted, then it builds and is not asked again
    let (c, out, _) = aix(&r2, &["brief", "src/app.ts"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains(STOP), "{out}");
    let (c, _, e) = aix(&r2, &["--accept-ignore", "update"]);
    assert_eq!(c, 0, "{e}");
    let (c, out, _) = aix(&r2, &["brief", "src/app.ts"]);
    assert!(c != 2 && !out.contains(STOP), "{out}");
}

#[test]
fn an_untracked_env_is_named_never_shown() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), Some(".DS_Store\n"), &[]);
    write(&r, ".env", "API_TOKEN=zz-very-secret-value-0042\n");
    write(&r, "conf/.env.local", "DB_PASSWORD=zz-other-secret-0043\n");
    for args in [vec!["ignore-check"], vec!["ignore-check", "--json"], vec!["ignore-check", "--suggest"]] {
        let (c, out, err) = aix(&r, &args);
        assert_eq!(c, 1, "{out}");
        assert!(!out.contains("zz-very-secret") && !out.contains("zz-other-secret") && !err.contains("zz-"), "{out}");
        assert!(out.contains(".env*"), "{out}");
    }
    let (_, out, _) = aix(&r, &["ignore-check"]);
    assert!(
        out.contains("[HIGH] expected .gitignore entry missing for any stack: .env* (present, untracked)"),
        "{out}"
    );
    assert!(out.contains("2 files"), "both .env files counted: {out}");
}

#[test]
fn a_tracked_build_artifact_suggests_git_rm_cached() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), Some(CLEAN_IGNORE), &[("app/__pycache__/m.cpython-312.pyc", "x"), ("app/m.py", "x = 1\n")]);
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("__pycache__/ is tracked") && out.contains("git rm -r --cached app/__pycache__"), "{out}");
    let (_, sug, _) = aix(&r, &["ignore-check", "--suggest"]);
    assert!(sug.contains("#   git rm -r --cached app/__pycache__"), "{sug}");
}

#[test]
fn a_rust_target_present_and_not_ignored_is_high() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), Some(CLEAN_IGNORE), &[("Cargo.toml", "[package]\nname = \"x\"\n")]);
    write(&r, "target/debug/x", "bin");
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(
        out.contains("[HIGH] expected .gitignore entry missing for Rust: target/ (present, untracked) (1 file"),
        "{out}"
    );
}

#[test]
fn a_mixed_java_and_node_repo_gets_both_stacks() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(
        d.path(),
        Some(".env*\n.DS_Store\nnode_modules/\n"),
        &[("pom.xml", "<project/>\n"), ("web/package.json", "{}\n")],
    );
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("missing for Maven: target/"), "{out}");
    assert!(out.contains("missing for Node: dist/") && !out.contains("Node: node_modules/"), "{out}");
    assert!(out.contains("stacks: Maven, Node") || out.contains("stacks: Node, Maven"), "{out}");
}

#[test]
fn a_covered_repo_is_clean_and_builds() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(
        d.path(),
        Some(".env*\n.DS_Store\ntarget/\nnode_modules/\ndist/\nbuild/\n.next/\ncoverage/\n*.log\n"),
        &[("Cargo.toml", "[package]\n"), ("package.json", "{}\n")],
    );
    write(&r, "target/debug/x", "bin");
    write(&r, "node_modules/a/i.js", "1");
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("0 finding(s)") && out.contains("clean"), "{out}");
    let (c, out, _) = aix(&r, &["brief", "src/app.ts"]);
    assert!(c != 2 && !out.contains(STOP), "{out}");
    assert!(r.join(".aix/index.db").exists() && !r.join(".aix/config").exists());
}

#[test]
fn a_non_git_dir_is_high_and_lists_the_walk() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("plain");
    write(&r, "src/a.ts", "export const a = 1;\n");
    write(&r, "certs/server.pem", "-----BEGIN zz-pem-body-0044\n");
    write(&r, "node_modules/x/i.js", "1");
    let (c, out, _) = aix(&r, &["ignore-check"]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("(not a git repo)") && out.contains("[HIGH] not a git repository"), "{out}");
    assert!(out.contains("certs/server.pem") && !out.contains("zz-pem-body"), "{out}");
    assert!(out.contains("node_modules/: dependencies") && out.contains("would index: 1 files"), "{out}");
    // the first build stops here too
    let (c, out, _) = aix(&r, &["stats"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains(STOP), "{out}");
}

#[test]
fn first_build_refuses_then_acceptance_is_stored_once_and_a_new_env_warns_in_the_card() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[]);
    let (c, out, _) = aix(&r, &["brief", "src/app.ts"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains(STOP) && out.contains("--accept-ignore") && out.contains("aix ignore-check"), "{out}");
    let (c, out, _) = aix(&r, &["update"]);
    assert_eq!(c, 2, "{out}");
    let card = aix(&r, &["card"]).1;
    assert!(card.contains("aix: STOP: .gitignore is missing or incomplete"), "{card}");
    // the user accepted: recorded as a hash in .aix/config, asked once
    let (c, _, e) = aix(&r, &["--accept-ignore", "update"]);
    assert_eq!(c, 0, "{e}");
    let cfg = std::fs::read_to_string(r.join(".aix/config")).unwrap();
    let (_, js, _) = aix(&r, &["ignore-check", "--json"]);
    let v: serde_json::Value = serde_json::from_str(js.trim()).unwrap();
    assert!(v["accepted"].as_bool().unwrap(), "{js}");
    assert!(cfg.contains(&format!("accept_ignore = \"{}\"", v["hash"].as_str().unwrap())), "{cfg}");
    let (c, out, _) = aix(&r, &["brief", "src/app.ts"]);
    assert!(c != 2 && !out.contains(STOP), "{out}");
    assert!(!aix(&r, &["card"]).1.contains("ignore-check"), "accepted: no card line");
    let (c, _, e) = aix(&r, &["update", "--full"]);
    assert_eq!(c, 0, "same findings: a full rebuild is not asked again: {e}");
    // a new .env appears: refresh never blocks, the card and stats say it once
    write(&r, ".env", "TOKEN=zz-new-secret-0045\n");
    let (c, out, _) = aix(&r, &["update"]);
    assert_eq!(c, 0, "{out}");
    let card = aix(&r, &["card"]).1;
    assert!(
        card.contains("aix ignore-check: 1 new high-severity .gitignore finding(s)") && !card.contains("zz-new-secret"),
        "{card}"
    );
    let stats = aix(&r, &["stats"]).1;
    assert!(stats.contains("new high-severity .gitignore finding"), "{stats}");
    // a full rebuild with changed findings is the first-build rule again
    let (c, out, _) = aix(&r, &["update", "--full"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains(STOP), "{out}");
}

#[test]
fn an_explicit_db_outside_the_repo_is_tooling_and_not_gated() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[]);
    let db = d.path().join("bench.db");
    let (c, out, e) = aix(&r, &["--db", db.to_str().unwrap(), "stats"]);
    assert_eq!(c, 0, "{out}{e}");
    assert!(!out.contains(STOP) && db.exists(), "{out}");
    let (c, _, _) = aix(&r, &["--db", db.to_str().unwrap(), "update", "--full"]);
    assert_eq!(c, 0);
    // AIX_ACCEPT_IGNORE=1 (CI, test harnesses) is not gated either, and nothing is recorded
    let o = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .args(["stats"])
        .env("AIX_ACCEPT_IGNORE", "1")
        .env("HOME", d.path())
        .env("AIX_EMBED_URL", "")
        .output()
        .unwrap();
    assert!(o.status.success() && !r.join(".aix/config").exists());
}

// the aix-init / aix-refresh tests below run the bash scripts with symlinked commands: Unix only
#[cfg(unix)]
fn init_env(d: &Path) -> (PathBuf, String) {
    let bin = d.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_aix"), bin.join("aix")).unwrap();
    std::os::unix::fs::symlink(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-refresh.sh"),
        bin.join("aix-refresh"),
    )
    .unwrap();
    (bin.clone(), format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()))
}

#[cfg(unix)]
fn init(d: &Path, r: &Path, path: &str, extra: &[&str]) -> std::process::Output {
    Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-init.sh"))
        .arg(r)
        .args(["--no-git-hook", "--no-watch"])
        .args(extra)
        .env("PATH", path)
        .env("HOME", d.join("home"))
        .env("XDG_DATA_HOME", d.join("share"))
        .env_remove("AIX_ACCEPT_IGNORE")
        .env_remove("AIX_DB")
        .env("AIX_EMBED_URL", "")
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn aix_init_stops_with_exit_3_before_touching_anything_and_accept_ignore_proceeds() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[("package.json", "{}\n")]);
    std::fs::create_dir_all(d.path().join("home")).unwrap();
    let (_bin, path) = init_env(d.path());
    let o = init(d.path(), &r, &path, &[]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.status.code(), Some(3), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains(STOP) && out.contains("no .gitignore") && out.contains("--accept-ignore"), "{out}");
    for p in [".aix", ".claude", ".claude/settings.local.json", ".claude/settings.json", ".mcp.json"] {
        assert!(!r.join(p).exists(), "{p} must not exist after the stop");
    }
    // the user chose to index as is
    let o = init(d.path(), &r, &path, &["--accept-ignore"]);
    assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(r.join(".aix/index.db").exists() && r.join(".claude/settings.local.json").exists());
    assert!(std::fs::read_to_string(r.join(".aix/config")).unwrap().contains("accept_ignore = \""));
    let s = std::fs::read_to_string(r.join(".claude/settings.local.json")).unwrap();
    assert!(s.contains("Bash(aix ignore-check)") && !s.contains("ignore-check --accept"), "{s}");
    // re-running needs no flag: the same findings were accepted
    let o = init(d.path(), &r, &path, &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
}

#[test]
fn the_mcp_command_reports_and_the_mcp_first_build_stops() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[]);
    write(&r, ".env", "K=zz-mcp-secret-0046\n");
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .arg("mcp")
        .env_remove("AIX_ACCEPT_IGNORE")
        .env_remove("AIX_DB")
        .env("HOME", d.path())
        .env("AIX_EMBED_URL", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut w = c.stdin.take().unwrap();
    let call = |id: i64, cmd: &str, args: &str| serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "aix", "arguments": {"command": cmd, "args": args}}});
    for m in [
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        call(2, "ignore-check", ""),
        call(3, "brief", "src/app.ts"),
        call(4, "ignore-check", "--accept"),
    ] {
        writeln!(w, "{m}").unwrap();
    }
    w.flush().unwrap();
    let mut got: std::collections::HashMap<i64, serde_json::Value> = Default::default();
    for l in BufReader::new(c.stdout.take().unwrap()).lines() {
        let Ok(l) = l else { break };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) else { continue };
        if let Some(id) = v["id"].as_i64() {
            got.insert(id, v);
        }
        if (2..=4).all(|i| got.contains_key(&i)) {
            break;
        }
    }
    drop(w);
    let _ = c.kill();
    let _ = c.wait();
    let text = |id: i64| got[&id]["result"]["content"][0]["text"].as_str().unwrap_or("").to_string();
    let t2 = text(2);
    assert!(t2.contains("[HIGH] no .gitignore") && t2.contains(".env") && !t2.contains("zz-mcp-secret"), "{t2}");
    let t3 = text(3);
    assert!(t3.contains(STOP) && got[&3]["result"]["isError"].as_bool() == Some(true), "{t3}");
    assert!(text(4).contains("read-only") && !r.join(".aix/config").exists(), "{}", text(4));
}

#[cfg(unix)]
#[test]
fn aix_refresh_full_refuses_like_a_first_build() {
    let d = tempfile::tempdir().unwrap();
    let r = repo(d.path(), None, &[]);
    let (_bin, path) = init_env(d.path());
    let run = |extra: &[&str]| {
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-refresh.sh"))
            .arg(&r)
            .args(extra)
            .env("PATH", &path)
            .env("HOME", d.path())
            .env("AIX_LOCK_DIR", d.path().join("locks"))
            .env_remove("AIX_ACCEPT_IGNORE")
            .env_remove("AIX_DB")
            .env("AIX_EMBED_URL", "")
            .output()
            .unwrap()
    };
    let o = run(&["--full"]);
    assert_eq!(o.status.code(), Some(3), "{}", String::from_utf8_lossy(&o.stdout));
    assert!(String::from_utf8_lossy(&o.stderr).contains(STOP));
    // a hook's plain refresh stays quiet (exit 0) and builds nothing
    let o = run(&[]);
    assert!(o.status.success() && !r.join(".aix/config").exists());
    let o = run(&["--full", "--accept-ignore"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(r.join(".aix/config").exists());
}
