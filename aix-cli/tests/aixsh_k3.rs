//! Round-5 QA (integration and safety): redaction gaps and false positives, multi-line redaction in diff, credential
//! files refused, query text kept out of `savings`, a deleted-and-restored file, the ignore gate before a new index
//! (no db left behind) and its note for an outside --db, a worktree inheriting the main tree's acceptance, MCP
//! protocol errors, tracked files of unindexed types named, `howto` for domain words, `tasks` continuation, hook
//! silence after `cd` and on PowerShell redirects, and the lifecycle scripts refusing a subdirectory.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn write(r: &Path, rel: &str, body: &str) {
    let p = r.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn run(r: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(r).args(args).env("AIX_EMBED_URL", "").env("HOME", r.parent().unwrap()).env("AIX_LOCK_DIR", r.parent().unwrap().join("locks"));
    for (k, v) in env {
        c.env(k, v);
    }
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(t) = stdin {
        ch.stdin.take().unwrap().write_all(t.as_bytes()).unwrap();
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn aix(r: &Path, args: &[&str]) -> (i32, String, String) {
    run(r, args, None, &[])
}

fn repo_in(d: &Path, files: &[(&str, &str)]) -> PathBuf {
    let r = d.join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".env*\n.DS_Store\n.aix/\n");
    for (p, b) in files {
        write(&r, p, b);
    }
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    r
}

#[test]
fn redaction_forms_and_false_positives() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "x = 1\n")]);
    aix(&r, &["update"]);
    let input = "credential: CredKeyFF66gg\nsigning_key: SignQQ77rr88\nmaster_key=MasterSS99tt00\nencryption_key: EncAB12cd34\nbot 123456789:AAH-abcdefghijklmnopqrstuvwxyz12345678\ndefine('DB_PASSWORD','WpConfigLL11mm22nn');\ntokenize='porter unicode61'\ncurl -H \"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\" https://example.test/x\napi_key = foo || \"UntermValue1\u{2026}\n";
    let (c, out, err) = run(&r, &["filter", "--head", "50", "-"], Some(input), &[]);
    assert!(c == 0 && !err.contains("panicked"), "{err}");
    for v in ["UntermValue1", "CredKeyFF66gg", "SignQQ77rr88", "MasterSS99tt00", "EncAB12cd34", "abcdefghijklmnopqrstuvwxyz12345678", "WpConfigLL11mm22nn", "abcdefghijklmnopqrstuvwxyz123456"] {
        assert!(!out.contains(v), "{v}: {out}");
    }
    assert!(out.contains("tokenize='porter unicode61'"), "{out}");
    assert!(out.contains("\" https://example.test/x"), "{out}");
}

#[test]
fn diff_redacts_yaml_block_scalars_and_credential_files_are_refused() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("conf/app.yml", "name: x\n"), ("web/.htpasswd", "admin:$apr1$abcdefgh$ABCDEFGHIJKLMNOPQRSTUV\n"), ("site/wp-config.php", "<?php define('DB_PASSWORD','WpConfigLL11mm22nn');\n")]);
    write(&r, "conf/app.yml", "name: x\nsecret: |\n  MultiLineSecretLine1abc\n  MultiLineSecretLine2abc\npassword: >-\n  FoldedSecretLine3abc\n");
    git(&r, &["commit", "-qam", "add"]);
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["diff", "HEAD~1..HEAD"]);
    assert!(out.contains("conf/app.yml") && !out.contains("MultiLineSecret") && !out.contains("FoldedSecret"), "{out}");
    let (c, out, _) = aix(&r, &["files", "--bare"]);
    assert!(c == 0 && !out.contains("htpasswd") && !out.contains("wp-config"), "{out}");
}

#[test]
fn savings_keep_no_query_text() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "x = 1\n")]);
    aix(&r, &["update"]);
    aix(&r, &["grep", "-F", "correct-horse-battery-staple"]);
    let (_, out, _) = aix(&r, &["sql", "select cmd, arg from savings"]);
    assert!(!out.contains("correct-horse"), "{out}");
}

#[test]
fn a_deleted_and_restored_file_is_noticed() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "def a():\n    pass\n"), ("b.txt", "x\n")]);
    let n = |r: &Path| aix(r, &["files", "--bare"]).1.lines().filter(|l| !l.starts_with('\u{2026}')).count();
    let before = n(&r);
    assert_eq!(before, 2, "a.py and b.txt");
    std::fs::rename(r.join("b.txt"), r.join("b.bak")).unwrap();
    assert_eq!(n(&r), before - 1);
    std::fs::rename(r.join("b.bak"), r.join("b.txt")).unwrap();
    assert_eq!(n(&r), before);
}

#[test]
fn the_gate_leaves_no_index_and_says_when_an_outside_db_skips_it() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, "src/a.py", "x = 1\n");
    write(&r, ".env", "K=zz\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).arg("stats").env_remove("AIX_ACCEPT_IGNORE").env_remove("AIX_DB").env("HOME", d.path()).env("AIX_EMBED_URL", "").output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(!r.join(".aix/index.db").exists() && !r.join(".aix/index.db-wal").exists());
    let db = d.path().join("x.db");
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).arg("--db").arg(&db).args(["grep", "x"]).env_remove("AIX_ACCEPT_IGNORE").env("HOME", d.path()).env("AIX_EMBED_URL", "").output().unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains(".gitignore check skipped"), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn a_worktree_inherits_the_main_trees_acceptance() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("main");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, "src/a.py", "x = 1\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    let base = |dir: &Path, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(dir).args(args).env_remove("AIX_ACCEPT_IGNORE").env_remove("AIX_DB").env("HOME", d.path()).env("AIX_EMBED_URL", "").output().unwrap()
    };
    assert_eq!(base(&r, &["stats"]).status.code(), Some(2)); // no .gitignore: STOP
    assert!(base(&r, &["--accept-ignore", "update"]).status.success());
    let wt = d.path().join("wt");
    git(&r, &["worktree", "add", "-q", wt.to_str().unwrap(), "-b", "feature"]);
    let o = base(&wt, &["grep", "x"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    // a worktree whose findings differ (an untracked .env) is asked
    let wt2 = d.path().join("wt2");
    git(&r, &["worktree", "add", "-q", wt2.to_str().unwrap(), "-b", "other"]);
    write(&wt2, ".env", "K=zz-other\n");
    assert_eq!(base(&wt2, &["grep", "x"]).status.code(), Some(2));
    // a secret-like file committed after the acceptance is shared history, not a new decision for a new worktree
    write(&r, "deploy/secrets.yaml", "kind: Secret\ndata:\n  k: dmFsdWUtcmVhbA==\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "s"]);
    let wt3 = d.path().join("wt3");
    git(&r, &["worktree", "add", "-q", wt3.to_str().unwrap(), "-b", "third"]);
    let o = base(&wt3, &["grep", "x"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
}

#[test]
fn mcp_protocol_errors_and_hints() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "x = 1\n")]);
    aix(&r, &["update"]);
    let mut ch = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).arg("mcp").env("AIX_EMBED_URL", "").env("HOME", d.path()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut w = ch.stdin.take().unwrap();
    let mut rd = BufReader::new(ch.stdout.take().unwrap());
    let mut ask = |line: &str| -> serde_json::Value {
        writeln!(w, "{line}").unwrap();
        w.flush().unwrap();
        let mut s = String::new();
        rd.read_line(&mut s).unwrap();
        serde_json::from_str(s.trim()).unwrap()
    };
    ask(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#);
    // a notification has no reply: sent with the next request (the reply read is that request's)
    let mut ask = {
        let mut first = true;
        move |line: &str| -> serde_json::Value {
            if first {
                first = false;
                return ask(&format!("{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n{line}"));
            }
            ask(line)
        }
    };
    assert_eq!(ask("not json at all")["error"]["code"], -32700);
    assert_eq!(ask(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aix","arguments":[1]}}"#)["error"]["code"], -32602);
    let v = ask(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"aix","arguments":{"command":"grep","args":"x -l | put s"}}}"#);
    assert!(v["error"]["message"].as_str().unwrap_or("").contains("command \"pipe\""), "{v}");
    let v = ask(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"aix","arguments":{"command":"grpe","args":"x"}}}"#);
    assert!(v.to_string().contains("did you mean: grep"), "{v}");
    let v = ask(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"aix","arguments":{"command":"pipe","args":"grep ZZ_NONE"}}}"#);
    assert_eq!(v["result"]["structuredContent"]["none"], true, "{v}");
    let v = ask(r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"aix","arguments":{"command":"stats"}}}"#);
    assert!(!v.to_string().contains("== savings"), "{v}");
    drop(ask);
    let _ = ch.kill();
    let _ = ch.wait();
}

#[test]
fn tracked_files_of_unindexed_types_are_named() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "alpha = 1\n"), ("build.gradle", "alpha 'x'\n"), ("Makefile", "alpha:\n\techo\n"), ("styles/x.scss", "alpha {}\n")]);
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["grep", "alpha"]);
    assert!(out.contains("a.py:1") && out.contains("not indexed") && out.contains(".gradle") && out.contains("Makefile"), "{out}");
    let (_, _, err) = aix(&r, &["grep", "-c", "alpha", "--bare"]);
    assert!(err.contains("not indexed"), "{err}");
    let (_, out, _) = aix(&r, &["ls"]);
    assert!(out.contains("not indexed") && out.contains(".gradle"), "{out}");
    let (_, out, _) = aix(&r, &["files", "styles"]);
    assert!(out.contains("its type is not indexed: .scss"), "{out}");
}

#[test]
fn howto_domain_words_and_tasks_continuation() {
    let d = tempfile::tempdir().unwrap();
    let mut t = String::from("# Tasks\n");
    for i in 0..30 {
        t.push_str(&format!("- [ ] Found: issue number {i}\n"));
    }
    let r = repo_in(d.path(), &[("TASKS.md", &t)]);
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["howto", "attendance"]);
    assert!(out.contains("aix brief attendance") && out.contains("aix find attendance"), "{out}");
    let (_, out, _) = aix(&r, &["tasks", "found"]);
    assert!(out.contains("newest of 30") && out.contains("10 older: aix tasks found --page 2"), "{out}");
}

#[test]
fn hook_silent_after_cd_and_on_powershell_redirects() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("src/Owner.java", "class Owner {}\n")]);
    aix(&r, &["update"]);
    let rs = r.display().to_string();
    let hook = |tool: &str, cmd: &str| run(&r, &["hook", "pretool"], Some(&serde_json::json!({"session_id": "s", "tool_name": tool, "tool_input": {"command": cmd}, "cwd": rs}).to_string()), &[]).1;
    // after `cd src` the suggestion is relative to src, where the shell now is: `.` there is that directory
    let h = hook("Bash", "cd src && grep -rn Owner .");
    assert!(h.contains("aix grep Owner ."), "{h}");
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("grep").arg("Owner").arg(".").current_dir(r.join("src")).env("AIX_EMBED_URL", "").env("HOME", r.parent().unwrap()).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("src/Owner.java:1"), "{}", String::from_utf8_lossy(&o.stdout));
    assert!(hook("PowerShell", "Get-Content src/Owner.java > out.txt").trim().is_empty());
    assert!(!hook("Bash", "grep -rn Owner src").trim().is_empty());
}

// the lifecycle scripts are bash, run with symlinked commands on PATH: Unix only
#[cfg(unix)]
#[test]
fn lifecycle_scripts_refuse_a_subdirectory_and_validate_flags() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "x = 1\n")]);
    std::fs::create_dir_all(r.join("sub")).unwrap();
    let bin = d.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_aix"), bin.join("aix")).unwrap();
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let sh = |script: &str, args: &[&str], cwd: &Path| {
        Command::new("bash").arg(scripts.join(script)).args(args).current_dir(cwd).env("PATH", &path).env("HOME", d.path()).env("AIX_LOCK_DIR", d.path().join("locks")).env("XDG_DATA_HOME", d.path().join("share")).env("AIX_EMBED_URL", "").output().unwrap()
    };
    for s in ["aix-init.sh", "aix-refresh.sh", "aix-watch.sh"] {
        let o = sh(s, &[], &r.join("sub"));
        assert_eq!(o.status.code(), Some(2), "{s}: {}", String::from_utf8_lossy(&o.stderr));
        assert!(String::from_utf8_lossy(&o.stderr).contains("not its root"), "{s}");
    }
    assert!(!r.join(".aix").exists() && !r.join(".claude").exists());
    let o = sh("aix-watch.sh", &[r.to_str().unwrap(), "--idle", "abc"], &r);
    assert_eq!(o.status.code(), Some(2));
    let o = sh("aix-watch.sh", &[r.to_str().unwrap(), "--stop"], &r);
    assert!(o.status.code() == Some(1) && String::from_utf8_lossy(&o.stderr).contains("no watcher running"));
    // a watcher without logs.toml polls quietly
    let o = sh("aix-watch.sh", &[r.to_str().unwrap(), "--idle", "1", "--poll", "1", "--exit-after", "3"], &r);
    assert!(!String::from_utf8_lossy(&o.stderr).contains("integer expected"), "{}", String::from_utf8_lossy(&o.stderr));
}

#[cfg(unix)]
#[test]
fn init_then_uninstall_leaves_existing_json_byte_identical() {
    let d = tempfile::tempdir().unwrap();
    let r = repo_in(d.path(), &[("a.py", "x = 1\n")]);
    let mcp = "{\"mcpServers\":{\"other\":{\"command\":\"x\"}}}\n";
    let set = "{\"permissions\":{\"allow\":[\"Bash(ls:*)\"]}}\n";
    write(&r, ".mcp.json", mcp);
    write(&r, ".claude/settings.local.json", set);
    let bin = d.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_aix"), bin.join("aix")).unwrap();
    std::os::unix::fs::symlink(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-refresh.sh"), bin.join("aix-refresh")).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let init = |extra: &[&str]| {
        Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-init.sh"))
            .arg(&r)
            .args(["--no-git-hook", "--no-watch", "--mcp"])
            .args(extra)
            .env("PATH", &path)
            .env("HOME", d.path())
            .env("AIX_LOCK_DIR", d.path().join("locks"))
            .env("XDG_DATA_HOME", d.path().join("share"))
            .env("AIX_EMBED_URL", "")
            .env_remove("AIX_DB")
            .output()
            .unwrap()
    };
    let o = init(&["--accept-ignore"]);
    assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(std::fs::read_to_string(r.join(".mcp.json")).unwrap().contains("\"aix\""));
    let o = init(&["--uninstall"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read_to_string(r.join(".mcp.json")).unwrap(), mcp);
    assert_eq!(std::fs::read_to_string(r.join(".claude/settings.local.json")).unwrap(), set);
}
