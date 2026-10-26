//! Privacy, redaction and UX fixes (FIX-5P): MCP allow-list, history/credential deny list, privacy-check noise,
//! masks, stored searches, query-size caps, paste truncation notes, script file modes, help text.
//! Every secret-shaped value is built at run time; nothing touches the real HOME.

use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Env {
    _d: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
}

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn env(files: &[(&str, &str)]) -> Env {
    let d = tempfile::tempdir().unwrap();
    let (repo, home) = (d.path().join("proj"), d.path().join("home"));
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(repo.join("main.py"), "def load(x):\n    return x\n").unwrap();
    for (p, t) in files {
        let f = repo.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A", "-f"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    Env { _d: d, repo, home }
}

impl Env {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&self.repo).args(args).env("AIX_EMBED_URL", "").env("HOME", &self.home).env("AIX_MASK_KDF_ITERS", "1000").env("AIX_LOCK_DIR", self._d.path().join("locks"));
        c
    }
    fn run(&self, args: &[&str]) -> (String, String, bool) {
        let o = self.cmd(args).stdin(Stdio::null()).output().unwrap();
        (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned(), o.status.success())
    }
    fn out(&self, args: &[&str]) -> String {
        let (o, e, _) = self.run(args);
        format!("{o}{e}")
    }
    fn stdin(&self, args: &[&str], input: &[u8]) -> String {
        let mut c = self.cmd(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut si = c.stdin.take().unwrap();
        let data = input.to_vec();
        let t = std::thread::spawn(move || {
            let _ = si.write_all(&data);
        });
        let o = c.wait_with_output().unwrap();
        let _ = t.join();
        format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
    }
}

/// Drive `aix mcp` over stdio: returns (isError, text) per tool call.
fn mcp(e: &Env, calls: &[(&str, String)]) -> Vec<(bool, String)> {
    let mut ch = e.cmd(&["mcp"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut si = ch.stdin.take().unwrap();
    let mut so = BufReader::new(ch.stdout.take().unwrap());
    let send = |si: &mut std::process::ChildStdin, v: serde_json::Value| {
        si.write_all(format!("{v}\n").as_bytes()).unwrap();
        si.flush().unwrap();
    };
    let read_id = |so: &mut BufReader<std::process::ChildStdout>, id: i64| -> serde_json::Value {
        loop {
            let mut l = String::new();
            assert!(so.read_line(&mut l).unwrap() > 0, "mcp closed");
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                if v["id"] == id {
                    return v;
                }
            }
        }
    };
    send(&mut si, serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}));
    read_id(&mut so, 0);
    send(&mut si, serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let mut res = vec![];
    for (i, (c, a)) in calls.iter().enumerate() {
        let id = i as i64 + 1;
        send(&mut si, serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"aix","arguments":{"command":c,"args":a}}}));
        let v = read_id(&mut so, id);
        let text = v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string();
        res.push((v["result"]["isError"].as_bool().unwrap_or(false) || v.get("error").is_some(), if text.is_empty() { v.to_string() } else { text }));
    }
    drop(si);
    let _ = ch.kill();
    let _ = ch.wait();
    res
}

#[test]
fn mcp_patterns_is_read_only_and_long_queries_are_refused() {
    let e = env(&[]);
    e.out(&["update"]);
    let long = "word ".repeat(2000);
    let r = mcp(
        &e,
        &[
            ("patterns", "add mine 'foo.*bar'".into()),
            ("patterns", "rm mine".into()),
            ("patterns", "pin mine".into()),
            ("patterns", "unpin mine".into()),
            ("patterns", "list".into()),
            ("patterns", "check 'load'".into()),
            ("find", long.clone()),
            ("text", long),
        ],
    );
    for (i, (err, t)) in r.iter().take(4).enumerate() {
        assert!(*err && t.contains("not available through the MCP tool"), "call {i}: {t}");
    }
    assert!(!r[4].0 && !r[5].0, "{:?}", &r[4..6]);
    for (err, t) in &r[6..] {
        assert!(*err && t.contains("too long"), "{t}");
        assert!(t.lines().count() <= 2);
    }
    // nothing was added
    let (l, _, _) = e.run(&["patterns", "list"]);
    assert!(!l.contains("pat:mine"), "{l}");
}

#[test]
fn cli_caps_long_query_arguments_in_a_blink() {
    let e = env(&[]);
    e.out(&["update"]);
    // Windows caps a whole command line at 32K characters; 10K still exceeds MAX_QUERY_BYTES
    let big = "term ".repeat(if cfg!(windows) { 2_000 } else { 20_000 });
    let t0 = std::time::Instant::now();
    let (o, err, ok) = e.run(&["find", &big]);
    assert!(!ok && err.contains("too long") && o.is_empty(), "{o}{err}");
    let (_, err, ok) = e.run(&["ask", &big]);
    assert!(!ok && err.contains("too long"), "{err}");
    let many = (0..80).map(|i| format!("w{i}")).collect::<Vec<_>>().join(" ");
    let (_, err, ok) = e.run(&["text", &many]);
    assert!(!ok && err.contains("80 terms"), "{err}");
    assert!(t0.elapsed().as_secs() < 20);
    // a normal query still works
    assert!(e.run(&["find", "load"]).2);
}

#[test]
fn history_copies_and_more_credential_stores_are_hard_denied() {
    use aix_core::logs::{credential_like_name, hard_denied};
    for n in [
        ".bash_history", ".bash_history.bak", ".bash_history.old", ".bash_history-2026", ".bash_history~", ".zsh_history.1", "bash_history.txt", "zsh_history.log", "fish_history.0",
        "mysql_history.log", ".psql_history~", ".python_history.bak", ".mysql_history", "sh_history", ".node_repl_history.old", "release.history.bak",
    ] {
        assert!(hard_denied(Path::new(&format!("/srv/data/{n}"))).is_some(), "{n} should be denied");
    }
    for n in ["history.md", "git-history.md", "release-history.html", "history_of_things.txt", "app.log", "my_history_notes.md", "ahistory.go"] {
        assert!(hard_denied(Path::new(&format!("/srv/data/{n}"))).is_none(), "{n} must stay allowed");
    }
    for p in [
        "/srv/x/.config/doctl/config.yaml", "/srv/x/.oci/config", "/srv/x/.config/heroku/credentials", "/srv/x/.config/stripe/config.toml", "/srv/x/.m2/settings.xml",
        "/srv/x/.config/Signal/config.json", "/srv/x/.docker/config.json", "/srv/x/.kube/config",
    ] {
        assert!(hard_denied(Path::new(p)).is_some(), "{p} should be denied outside home");
    }
    assert!(hard_denied(Path::new("/srv/x/.config/other/config.json")).is_none());
    assert!(hard_denied(Path::new("/srv/x/.docker/notes.md")).is_none());
    for n in [".vault-token", ".boto", ".s3cfg", ".databrickscfg", ".netrc", ".pgpass", ".npmrc", ".pypirc", "id_rsa", "server.pem", "private_key.json", "my-private-key", "private"] {
        assert!(credential_like_name(n), "{n} should look like a credential");
    }
    for n in ["check-private.sh", "private-markers", "private_notes.md", "private.rs.bak", "privateer.txt", "make-private.sh"] {
        assert!(!credential_like_name(n), "{n} is not a credential name");
    }
}

#[test]
fn attach_refuses_history_copies_and_credential_dirs() {
    let e = env(&[]);
    let d = e.repo.join("stash");
    std::fs::create_dir_all(d.join(".config/doctl")).unwrap();
    for (rel, body) in [(".bash_history.bak", "ls\n"), (".zsh_history.1", "ls\n"), (".config/doctl/config.yaml", "k: v\n"), (".vault-token", "x\n"), ("fine.log", "hello\n")] {
        std::fs::write(d.join(rel), body).unwrap();
    }
    for rel in [".bash_history.bak", ".zsh_history.1", ".config/doctl/config.yaml", ".vault-token"] {
        let o = e.out(&["attach", d.join(rel).to_str().unwrap()]);
        assert!(o.contains("refused"), "{rel}: {o}");
    }
    let o = e.out(&["attach", d.join("fine.log").to_str().unwrap()]);
    assert!(!o.contains("refused"), "{o}");
}

#[test]
fn privacy_check_skips_redactor_fixtures_docs_and_prose_but_flags_real_shapes() {
    let tok = ["gh", "p_", "Qw3rTy9uIoPa5sDf7gHj1kLz4xCv6bNm8Aq2"].concat();
    let e = env(&[
        ("scripts/check-private.sh", "#!/bin/sh\necho ok\n"),
        ("private-markers", "none\n"),
        ("tests/redact_cases.py", &format!("T = '{tok}'\n")),
        ("docs/guide.md", &format!("the token is {tok}\n")),
        ("README.md", "Run `aix --fix` when the secret token is stale; see `~/.config/x`.\npassword = hunter22abc\n"),
        ("src/conf.yaml", "password: Zq81xKvP9mNb\ncontact: someone@example.test\n"),
    ]);
    e.out(&["update"]);
    let o = e.out(&["privacy-check", "--deep"]);
    assert!(!o.contains("look private"), "name false positive: {o}");
    assert!(!o.contains("tests/redact_cases.py") && !o.contains("docs/guide.md") && !o.contains("README.md") && !o.contains("src/conf.yaml"), "{o}");
    // a typed provider token in a source file is still reported
    std::fs::write(e.repo.join("src/leak.py"), format!("KEY = '{tok}'\n")).unwrap();
    git(&e.repo, &["add", "-A"]);
    git(&e.repo, &["commit", "-q", "-m", "leak"]);
    let o = e.out(&["privacy-check", "--deep"]);
    assert!(o.contains("src/leak.py") && o.contains("github-token"), "{o}");
}

#[test]
fn privacy_check_flags_indexed_history_copies_high() {
    let e = env(&[("notes/.zsh_history.1", "ls -la\ncd /srv\n"), ("notes/readme.txt", "hello world notes\n")]);
    e.out(&["update", "--full"]);
    let (n, _, _) = e.run(&["sql", "SELECT count(*) FROM files WHERE path LIKE '%zsh_history%'"]);
    if n.lines().any(|l| l.trim() == "0") {
        return; // the walker already keeps such files out of the index: nothing to flag
    }
    let o = e.out(&["privacy-check"]);
    assert!(o.contains("[HIGH]") && o.contains("deny list"), "{o}");
}

#[test]
fn mask_icase_upgrade_and_honest_wording() {
    let e = env(&[("notes.txt", "Visit Zeta-Quartz-4417 soon\n")]);
    e.out(&["update"]);
    let lit = ["Zeta", "-Quartz-", "4417"].concat();
    let o = e.out(&["mask", "add", "--literal", &lit, "--hint", "cust"]);
    assert!(o.contains("added mask"), "{o}");
    assert!(o.contains("paths keep their raw names"), "claim must be accurate: {o}");
    // the same text again, case-sensitively: refused, naming YOUR mask (not the built-in redactor)
    let o = e.out(&["mask", "add", "--literal", &lit, "--hint", "cust2"]);
    assert!(o.contains("refused") && o.contains("your mask") && !o.contains("built-in"), "{o}");
    // --icase upgrades the existing mask
    let o = e.out(&["mask", "add", "--literal", &lit, "--icase", "--hint", "cust3"]);
    assert!(o.contains("added mask") && !o.contains("refused"), "{o}");
    let l = e.out(&["mask", "list"]);
    assert_eq!(l.matches("literal,").count(), 1, "{l}");
    assert!(l.contains("case-insensitive"), "{l}");
    let o = e.out(&["mask", "test", &format!("x {} y", lit.to_uppercase())]);
    assert!(o.contains("***cust3***"), "{o}");
}

#[test]
fn typed_searches_that_look_like_tokens_are_never_stored_or_promoted() {
    let e = env(&[("src/a.py", "TOKEN_X = 'hq8vxz2lmp4trw9'\ndef alpha_beta():\n    pass\n")]);
    e.out(&["update"]);
    for _ in 0..6 {
        e.out(&["grep", "hq8vxz2lmp4trw9"]);
        e.out(&["grep", "alpha_beta"]);
    }
    let (g, _, _) = e.run(&["sql", "SELECT regex FROM grep_usage"]);
    assert!(!g.contains("hq8vxz"), "stored a token-looking search: {g}");
    let l = e.out(&["patterns", "list"]);
    assert!(!l.contains("hq8vxz"), "{l}");
    // a search holding a user-masked value is not stored either
    let lit = ["Zeta", "-Quartz-", "4417"].concat();
    e.out(&["mask", "add", "--literal", &lit, "--hint", "cust"]);
    for _ in 0..5 {
        e.out(&["grep", &lit]);
    }
    let (g, _, _) = e.run(&["sql", "SELECT regex FROM grep_usage"]);
    assert!(!g.contains("Zeta") && !g.contains("Quartz"), "{g}");
    // a masked value already stored is dropped by `mask add` (re-mask pass)
    {
        let conn = rusqlite::Connection::open(e.repo.join(".aix/index.db")).unwrap();
        conn.execute("INSERT INTO grep_usage(regex,n,last) VALUES(?,3,0)", [format!("find {}x", ["Orange", "-Walrus-", "9921"].concat())]).unwrap();
    }
    e.out(&["mask", "add", "--literal", &["Orange", "-Walrus-", "9921"].concat(), "--hint", "cust9"]);
    let (g, _, _) = e.run(&["sql", "SELECT regex FROM grep_usage"]);
    assert!(!g.contains("Walrus"), "{g}");
}

#[test]
fn big_paste_says_what_was_dropped_and_help_does_not_block() {
    let e = env(&[]);
    // ~9.5 MB of short lines: over the 8 MB cap
    let mut big = String::new();
    let mut i = 0;
    while big.len() < 9_500_000 {
        big.push_str(&format!("2026-01-01 10:00:{:02} INFO worker line number {i}\n", i % 60));
        i += 1;
    }
    let o = e.stdin(&["paste", "add"], big.as_bytes());
    let total: usize = o.split("lines (the text").next().and_then(|h| h.rsplit(" of ").next()).and_then(|n| n.trim().parse().ok()).unwrap_or(0);
    assert!(o.contains("truncated: kept") && total >= i - 1 && total <= i + 1, "{i} lines sent: {}", &o[..o.len().min(600)]);
    let l = e.out(&["paste", "list"]);
    assert!(l.contains("truncated: kept"), "{l}");
    // a small paste carries no note
    let o = e.stdin(&["paste", "add"], b"one\ntwo\nthree\n");
    assert!(!o.contains("truncated"), "{o}");
    // --help prints usage and returns at once, without reading stdin
    let mut ch = e.cmd(&["paste", "add", "--help"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let _keep_open = ch.stdin.take();
    let t0 = std::time::Instant::now();
    loop {
        if let Some(st) = ch.try_wait().unwrap() {
            assert!(st.success());
            break;
        }
        assert!(t0.elapsed().as_secs() < 15, "paste add --help blocked on stdin");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut s = String::new();
    BufReader::new(ch.stdout.take().unwrap()).read_line(&mut s).unwrap();
    assert!(s.contains("usage: aix paste"), "{s}");
}

#[cfg(unix)]
#[test]
fn scripts_create_private_files() {
    let e = env(&[]);
    let bin = e._d.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let scripts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts");
    let run = |script: &str, args: &[&str]| {
        let mut c = Command::new("bash");
        c.arg(scripts.join(script)).arg(&e.repo).args(args).env("HOME", &e.home).env("AIX_BIN", env!("CARGO_BIN_EXE_aix")).env("AIX_EMBED_URL", "").env("AIX_LOCK_DIR", e._d.path().join("locks")).env("PATH", format!("{}:{}", Path::new(env!("CARGO_BIN_EXE_aix")).parent().unwrap().display(), std::env::var("PATH").unwrap()));
        // a permissive umask in the caller must not leak into the files
        let o = Command::new("sh").arg("-c").arg("umask 022; exec \"$0\" \"$@\"").arg("bash").args(c.get_args()).envs(c.get_envs().filter_map(|(k, v)| v.map(|v| (k, v)))).output().unwrap();
        String::from_utf8_lossy(&o.stderr).into_owned()
    };
    let _ = run("aix-refresh.sh", &[]);
    let _ = run("aix-watch.sh", &["--once"]);
    let aix = e.repo.join(".aix");
    let mut checked = 0;
    for f in ["refresh.log", "index.db.watch.sig"] {
        if let Ok(m) = std::fs::metadata(aix.join(f)) {
            assert_eq!(m.permissions().mode() & 0o077, 0, "{f} is group/other accessible: {:o}", m.permissions().mode());
            checked += 1;
        }
    }
    assert!(checked >= 1, "no script file was created");
}

#[test]
fn per_command_help_lists_the_flags_and_howto_is_not_cut() {
    let e = env(&[]);
    for c in ["grep", "callers", "brief", "find"] {
        let h = e.out(&[c, "--help"]);
        for f in ["--exclude", "--only", "--conf", "--plan", "--page", "--exists", "--group-by"] {
            assert!(h.contains(f), "{c} --help lacks {f}: {h}");
        }
    }
    let h = e.out(&["logs", "--help"]);
    assert!(h.contains("--level") && h.contains("--since") && h.contains("--follow"), "{h}");
    let h = e.out(&["howto", "find who calls a function"]);
    for l in h.lines().filter(|l| l.contains("aix code")) {
        assert!(l.matches('<').count() == l.matches('>').count(), "cut-off line: {l}");
    }
}
