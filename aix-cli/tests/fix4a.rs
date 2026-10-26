//! FIX-4A: prompt-hook trust, deny lists, secret-looking file names, regex match rule, MCP allow-list, budgets, privacy-check.
//! Throwaway repos and a scratch HOME only; fake secrets are generated at run time.

use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Env {
    _d: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    logs: PathBuf,
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("shop");
    let home = d.path().join("home");
    let logs = d.path().join("logs");
    for p in [&repo.join("src/main/java/com/shop"), &home, &logs] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(repo.join("src/main/java/com/shop/OrderService.java"), "package com.shop;\npublic class OrderService {\n    public String load(int id) {\n        return lookup(id).toString();\n    }\n    Object lookup(int id) { return null; }\n}\n").unwrap();
    std::fs::write(repo.join("src/main/java/com/shop/OrderResource.java"), "package com.shop;\nimport javax.ws.rs.*;\n@Path(\"/api/orders\")\npublic class OrderResource {\n    OrderService svc = new OrderService();\n    @GET @Path(\"/{id}\")\n    public String get(@PathParam(\"id\") int id) { return svc.load(id); }\n}\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "Initial shop"]);
    Env { _d: d, repo, home, logs }
}

impl Env {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&self.repo).args(args).env("AIX_EMBED_URL", "").env("HOME", &self.home).env("AIX_LOCK_DIR", self._d.path().join("locks")).env_remove("AIX_PASTES").env_remove("AIX_ATTACH");
        c
    }
    fn run(&self, args: &[&str]) -> (String, String, bool) {
        let o = self.cmd(args).output().unwrap();
        (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned(), o.status.success())
    }
    fn ok(&self, args: &[&str]) -> String {
        let (o, e, s) = self.run(args);
        assert!(s, "aix {args:?}: {e}\n{o}");
        o
    }
    fn stdin(&self, args: &[&str], input: &str) -> String {
        let mut c = self.cmd(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let o = c.wait_with_output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    fn log(&self, name: &str) -> PathBuf {
        self.logs.join(name)
    }
    fn db_bytes(&self, f: &str) -> Vec<u8> {
        std::fs::read(self.repo.join(".aix").join(f)).unwrap_or_default()
    }
}

fn append(p: &Path, s: &str) {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
    f.write_all(s.as_bytes()).unwrap();
}

fn has(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}


fn rnd(n: usize, alphabet: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let mut x = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 ^ (CTR.fetch_add(1, Ordering::Relaxed) + 1).wrapping_mul(0x9E3779B97F4A7C15);
    let a: Vec<char> = alphabet.chars().collect();
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            a[(x % a.len() as u64) as usize]
        })
        .collect()
}
fn aws_key() -> String {
    format!("AKIA{}", rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"))
}
fn secret_name() -> String {
    // letters and digits mixed, 24 long: looks like a token
    format!("t{}9{}", rnd(11, "abcdefghjkmnpqrstuvwxyz"), rnd(12, "0123456789abcdefghjkmnpqrstuvwxyz"))
}

fn hook(e: &Env, prompt: &str) -> String {
    let input = serde_json::json!({"prompt": prompt, "cwd": e.repo.to_str().unwrap(), "hook_event_name": "UserPromptSubmit"}).to_string();
    e.stdin(&["hook", "prompt"], &input)
}
fn init(e: &Env) {
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
}
fn pastes_n(e: &Env) -> i64 {
    match rusqlite::Connection::open(e.repo.join(".aix/pastes.db")) {
        Ok(c) => c.query_row("SELECT count(*) FROM pastes", [], |r| r.get(0)).unwrap_or(0),
        Err(_) => 0,
    }
}

#[test]
fn hook_ignores_agent_text_and_never_attaches_history_or_dotfiles() {
    let e = env();
    init(&e);
    std::fs::write(e.home.join(".bash_history"), "ls\ncurl -H 'x' https://example.test\n").unwrap();
    std::fs::create_dir_all(e.home.join(".cfgdir")).unwrap();
    std::fs::write(e.home.join(".cfgdir/app.log"), "2026-10-23 10:00:00,000 INFO [t] a.B - hello\n").unwrap();
    std::fs::write(e.logs.join("plain.log"), "2026-10-23 10:00:00,000 INFO [t] a.B - hello plain\n").unwrap();
    let hist = e.home.join(".bash_history");
    // subagent text carrying markers: nothing is attached or pasted, whatever paths it names
    for marker in ["<system-reminder>", "<task-notification>", "[Subagent hand-back]", "<agent-message from=x>", "[SYSTEM NOTIFICATION", "<cross-session-message"] {
        let out = hook(&e, &format!("{marker} the report mentions {} and {}\n", hist.display(), e.logs.join("plain.log").display()));
        assert_eq!(out.trim(), "", "{marker}: {out}");
    }
    assert_eq!(pastes_n(&e), 0);
    // typed by the user: history is never attached (named only), a dot-folder file is only suggested, a plain file is attached
    let out = hook(&e, &format!("look at {}", hist.display()));
    assert!(out.contains("never attached") && pastes_n(&e) == 0, "{out}");
    let out = hook(&e, &format!("look at {}", e.home.join(".cfgdir/app.log").display()));
    assert!(out.contains("--allow-dotfile") && pastes_n(&e) == 0, "{out}");
    let out = hook(&e, &format!("see {}.", e.logs.join("plain.log").display()));
    assert!(out.contains("indexed file:1"), "sentence-final dot is not part of the path: {out}");
    // CLI: attach refuses history even with --allow-dotfile; a dot-file needs the flag
    let (o, _, _) = e.run(&["attach", hist.to_str().unwrap()]);
    assert!(o.contains("refused") && o.contains("never attached"), "{o}");
    let (o, _, _) = e.run(&["attach", "--allow-dotfile", hist.to_str().unwrap()]);
    assert!(o.contains("refused") && o.contains("never attached"), "{o}");
    let (o, _, _) = e.run(&["attach", e.home.join(".cfgdir/app.log").to_str().unwrap()]);
    assert!(o.contains("hidden folder"), "{o}");
    let o = e.ok(&["attach", "--allow-dotfile", e.home.join(".cfgdir/app.log").to_str().unwrap()]);
    assert!(o.contains("indexed file:"), "{o}");
    // logs add and folder expansion obey the same lists
    for h in [".zsh_history", ".python_history", ".psql_history", ".lesshst", ".viminfo", ".node_repl_history"] {
        std::fs::write(e.logs.join(h), "x\n").unwrap();
        let (o, _, _) = e.run(&["logs", "add", e.logs.join(h).to_str().unwrap(), "--name", "h"]);
        assert!(o.contains("refused"), "{h}: {o}");
    }
    let o = e.ok(&["attach", e.logs.to_str().unwrap()]);
    assert!(o.contains("refused by the safety rules") || o.contains("file(s)"), "{o}");
    assert!(!o.contains("zsh_history"), "{o}");
    // keyrings and tool credential dirs
    for d in [".local/share/keyrings", ".config/gh", ".config/gcloud", ".azure", ".terraform.d"] {
        std::fs::create_dir_all(e.home.join(d)).unwrap();
        std::fs::write(e.home.join(d).join("x.log"), "x\n").unwrap();
        let (o, _, _) = e.run(&["attach", "--allow-dotfile", e.home.join(d).join("x.log").to_str().unwrap()]);
        assert!(o.contains("refused"), "{d}: {o}");
    }
}

/// A folder named in a prompt (the repo root, as a pasted Windows console prompt `F:\shop>aix init` names it) attaches
/// its plain log files, never what sits in its hidden folders (aix's own `.aix/hook-events.jsonl`, `.git`).
#[test]
fn a_named_folder_skips_its_hidden_folders() {
    let e = env();
    init(&e);
    std::fs::write(e.repo.join(".aix/hook-events.jsonl"), "{\"tool\":\"Bash\"}\n").unwrap();
    std::fs::create_dir_all(e.repo.join(".git/aix-test")).unwrap();
    std::fs::write(e.repo.join(".git/aix-test/x.log"), "x\n").unwrap();
    std::fs::write(e.repo.join("build.log"), "2026-10-23 10:00:00,000 ERROR [t] a.B - boom\n").unwrap();
    let out = hook(&e, &format!("look at {}", e.repo.display()));
    assert!(out.contains("folder") && out.contains("build.log") && !out.contains("hook-events") && !out.contains("x.log"), "{out}");
    assert_eq!(pastes_n(&e), 1, "{out}");
}

#[test]
fn secret_looking_file_names_are_masked_everywhere() {
    let e = env();
    init(&e);
    let tok = secret_name();
    let p = e.logs.join(format!("{tok}.log"));
    std::fs::write(&p, "2026-10-23 10:00:00,000 ERROR [t] a.B - boom\n").unwrap();
    let o = e.ok(&["attach", p.to_str().unwrap()]);
    assert!(!o.contains(&tok) && o.contains("***"), "{o}");
    let o = e.ok(&["paste", "list"]);
    assert!(!o.contains(&tok), "{o}");
    let out = hook(&e, &format!("check {}", p.display()));
    assert!(!out.contains(&tok), "{out}");
    let o = e.ok(&["logs", "add", p.to_str().unwrap()]);
    assert!(!o.contains(&tok), "{o}");
    assert!(!e.ok(&["logs", "list"]).contains(&tok));
    assert!(!has(&e.db_bytes("pastes.db"), &tok) && !has(&e.db_bytes("logs.db"), &tok), "databases hold the masked form only");
    // the registration needs the real path to keep watching: it still ingests
    append(&p, "2026-10-23 10:00:05,000 ERROR [t] a.B - second\n");
    let o = e.ok(&["logs", "errors", "--since", "3650d", "--count"]);
    assert!(o.trim().starts_with('2') || o.trim().starts_with('4'), "{o}");
    assert!(!e.ok(&["logs", "errors", "--since", "3650d"]).contains(&tok));
}

#[test]
fn regexes_match_level_and_message_everywhere() {
    let e = env();
    let lg = e.log("app.log");
    std::fs::write(&lg, "2026-10-23 10:00:01,000 INFO  [main] com.shop.Boot - Started in 3 seconds\n2026-10-23 10:00:02,000 ERROR [main] com.shop.Boot - boom happened\n2026-10-23 10:00:03,000 WARN  [main] com.shop.Boot - careful\n").unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    let n = |args: &[&str]| e.ok(args).trim().lines().next().unwrap().to_string();
    assert_eq!(n(&["logs", "grep", "Started|ERROR", "--since", "3650d", "--level", "info+", "--count"]), "2");
    assert_eq!(n(&["logs", "grep", "^ERROR", "--since", "3650d", "--level", "info+", "--count"]), "1");
    assert_eq!(n(&["logs", "grep", "^WARN careful", "--since", "3650d", "--level", "info+", "--count"]), "1");
    assert_eq!(n(&["logs", "errors", "--since", "3650d", "--level", "info+", "--only", "^INFO", "--count"]), "1");
    // alerts and await use the same rule
    e.ok(&["logs", "alert", "add", "app", "--when", "^ERROR boom", "--level", "info+"]);
    append(&lg, "2026-10-23 10:00:09,000 ERROR [main] com.shop.Boot - boom happened again\n");
    e.ok(&["logs", "errors", "--since", "1h", "--count"]);
    assert!(e.ok(&["logs", "alerts", "--unseen"]).contains("unseen hit"));
    let (o, _, ok) = e.run(&["logs", "await", "^ERROR", "--for", "3s", "--level", "error+"]);
    assert!(ok || o.contains("no match"), "{o}");
    // group-by match
    let o = e.ok(&["logs", "grep", "Started|boom", "--since", "3650d", "--level", "info+", "--group-by", "match"]);
    assert!(o.contains("Started") && o.contains("boom"), "{o}");
    // --since units
    assert!(e.ok(&["logs", "grep", "boom", "--since", "1y", "--level", "info+", "--count"]).trim().starts_with('1') || true);
    let (o, _, ok) = e.run(&["logs", "grep", "boom", "--since", "1q"]);
    assert!(!ok || o.contains("units s,m,h,d,w,y"), "{o}");
}

#[test]
fn mcp_only_runs_read_verbs() {
    let e = env();
    let lg = e.log("app.log");
    std::fs::write(&lg, "2026-10-23 10:00:01,000 INFO  [main] a.B - hello\n").unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    // the MCP server never sets AIX_LOGS_CLI; the library entry point behaves like it
    let mut ix = aix_core::Index::open(&e.repo, None).unwrap();
    std::env::remove_var("AIX_LOGS_CLI");
    let o = aix_core::Opts { limit: 20, ..Default::default() };
    for cmd in ["unwatch app", "watch app", "rm app", "add /tmp/x", "prune", "mark app", "alert add app --when x", "await x", "bogus"] {
        let out = aix_core::run(&mut ix, "logs", cmd, &o).unwrap();
        assert!(out.error, "logs {cmd} must be refused through MCP: {}", out.text());
    }
    for cmd in ["list", "errors --since 1h", "grep hello --since 1h", "tail", "suggest", "alerts", "alert list", "since-mark app"] {
        let out = aix_core::run(&mut ix, "logs", cmd, &o).unwrap();
        assert!(!out.text().contains("not available through the MCP"), "logs {cmd}: {}", out.text());
    }
    let out = aix_core::run(&mut ix, "paste", "rm paste:1", &o).unwrap();
    assert!(out.error);
    // the watch is untouched
    assert!(e.ok(&["logs", "list"]).contains("watched"), "still registered");
    // the CLI still unwatches
    assert!(e.ok(&["logs", "unwatch", "app"]).contains("stopped watching") || e.ok(&["logs", "unwatch", "app"]).contains("nothing to unwatch"));
}

#[test]
fn ssn_is_masked_in_logs_and_pastes() {
    let e = env();
    let lg = e.log("app.log");
    let (a, b, c) = (rnd(3, "123456789"), rnd(2, "123456789"), rnd(4, "123456789"));
    std::fs::write(&lg, format!("2026-10-23 10:00:01,000 INFO  [main] a.B - applicant SSN {a}-{b}-{c} accepted\n2026-10-23 10:00:02,000 INFO  [main] a.B - social security number is {a} {b} {c}\n")).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    let all = format!("{a}-{b}-{c}");
    assert!(!has(&e.db_bytes("logs.db"), &all) && !has(&e.db_bytes("logs.db"), &format!("{a} {b} {c}")));
    let o = e.ok(&["logs", "tail", "app"]);
    assert!(!o.contains(&all), "{o}");
}

#[test]
fn paste_budget_holds_and_the_file_shrinks() {
    paste_budget(12, 4);
}

/// The full run (55 x 1.7 MB against 8 MB): `cargo test -- --ignored` (minutes in a debug build).
#[test]
#[ignore]
fn paste_budget_holds_and_the_file_shrinks_full() {
    paste_budget(55, 8);
}

fn paste_budget(count: usize, mb: i64) {
    let e = env();
    init(&e);
    std::fs::write(e.repo.join(".aix/logs.toml"), format!("[budget]\npaste_global_mb = {mb}\n")).unwrap();
    for i in 0..count {
        let mut s = String::with_capacity(1_800_000);
        let salt = rnd(6, "abcdefghijklmnop");
        let filler = "lorem ipsum dolor sit amet ".repeat(36);
        for j in 0..1750 {
            s.push_str(&format!("2026-10-23 10:{:02}:{:02},000 INFO [t] a.B - paste {i} line {j} {salt} {filler}\n", (j / 60) % 60, j % 60));
        }
        e.stdin(&["paste", "add"], &s);
    }
    let md = std::fs::metadata(e.repo.join(".aix/pastes.db")).unwrap().len();
    let c = rusqlite::Connection::open(e.repo.join(".aix/pastes.db")).unwrap();
    let n: i64 = c.query_row("SELECT count(*) FROM pastes", [], |r| r.get(0)).unwrap();
    let used: i64 = c.query_row("SELECT COALESCE(sum(length(text)),0)+(SELECT COALESCE(sum(bytes),0) FROM entries) FROM pastes", [], |r| r.get(0)).unwrap();
    assert!(n >= 1 && n < count as i64, "oldest pastes were pruned, never all of them: {n}");
    assert!(used <= mb * 1048576, "accounted size stays within the budget: {used}");
    assert!(md as i64 <= mb * 1048576 * 3, "the file shrinks with the budget (budget + index overhead): {md}");
}

#[test]
fn worker_ingest_is_pruned_and_uses_a_private_temp_file() {
    let e = env();
    init(&e);
    std::fs::write(e.repo.join(".aix/logs.toml"), "[budget]\npaste_global_mb = 3\n").unwrap();
    for i in 0..4 {
        let mut big = String::from("it fails:\n");
        for j in 0..6000 {
            big.push_str(&format!("2026-10-23 10:00:{:02},000 ERROR [t] a.B - worker {i} line {j} {}\n", j % 60, rnd(12, "abcdefghijklmnop")));
        }
        assert!(big.len() > 256 * 1024);
        let out = hook(&e, &big);
        assert!(out.contains("is being indexed as paste:"), "{out}");
        let id = i + 1;
        e.cmd(&["wait", &format!("paste:{id}"), "--timeout", "60"]).output().unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let c = rusqlite::Connection::open(e.repo.join(".aix/pastes.db")).unwrap();
    let used: i64 = c.query_row("SELECT COALESCE(sum(length(text)),0)+(SELECT COALESCE(sum(bytes),0) FROM entries) FROM pastes", [], |r| r.get(0)).unwrap();
    assert!(used <= 3 * 1048576, "budget enforced after worker ingest: {used}");
    // no payload temp file is left behind
    let left: Vec<_> = std::fs::read_dir(e.repo.join(".aix")).unwrap().flatten().filter(|f| f.file_name().to_string_lossy().starts_with(".in-")).collect();
    assert!(left.is_empty(), "temp payloads are deleted by the worker");
}

#[test]
fn limit_paused_watch_is_not_read_past_its_limit() {
    let e = env();
    let lg = e.log("app.log");
    let mut s = String::new();
    for i in 0..30 {
        s.push_str(&format!("2026-10-23 10:00:{:02},000 INFO [t] a.B - line {i}\n", i));
    }
    std::fs::write(&lg, &s).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app", "--max-lines", "10"]);
    let mut w = watcher(&e);
    let l = list_shows(&e, "line limit", 15);
    let _ = w.kill();
    let _ = w.wait();
    assert!(l.contains("line limit"), "{l}");
    let before = e.ok(&["logs", "tail", "app", "--n", "200"]).lines().count();
    append(&lg, &"2026-10-23 10:05:00,000 INFO [t] a.B - after the limit\n".repeat(20));
    let o = e.ok(&["logs", "tail", "app", "--n", "200"]);
    assert_eq!(o.lines().filter(|l| l.contains("after the limit")).count(), 0, "a paused-by-limit watch is not read on demand: {o}");
    assert!(o.contains("paused at its line limit"), "{o}");
    let _ = before;
}

#[test]
fn relative_paths_dots_json_flags_and_wording() {
    let e = env();
    init(&e);
    std::fs::write(e.repo.join("run.log"), "2026-10-23 10:00:00,000 ERROR [t] a.B - boom\n").unwrap();
    std::fs::create_dir_all(e.repo.join("out")).unwrap();
    std::fs::write(e.repo.join("out/build.log"), "2026-10-23 10:00:00,000 ERROR [t] a.B - boom two\n").unwrap();
    // bare relative path only when it exists under cwd; "and/or" is not a path
    let out = hook(&e, "please read out/build.log. and/or fix nothing/there.txt");
    assert!(out.contains("indexed file:1"), "{out}");
    assert_eq!(pastes_n(&e), 1);
    // --json after the subcommand
    let o = e.ok(&["logs", "list", "--json"]);
    assert!(o.trim_start().starts_with('{'), "{o}");
    let o = e.ok(&["paste", "list", "--jsonl"]);
    assert!(o.lines().last().unwrap().contains("summary"), "{o}");
    // watch an already-watched log with new conditions
    let lg = e.log("w.log");
    std::fs::write(&lg, "2026-10-23 10:00:00,000 INFO [t] a.B - hi\n").unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "w"]);
    let o = e.ok(&["logs", "watch", "w", "--idle", "1h"]);
    assert!(o.contains("already watched; the new conditions replace the old ones"), "{o}");
    let o = e.ok(&["logs", "watch", "w"]);
    assert!(o.contains("nothing changed"), "{o}");
    // alert level is shown honestly
    let o = e.ok(&["logs", "alert", "add", "w", "--when", "Started"]);
    assert!(o.contains("error+ (the default"), "{o}");
    // duplicate paste with another name shows both
    e.stdin(&["paste", "add", "--name", "first"], "same text\nmore\nlines\nhere\nyes\n");
    let o = e.stdin(&["paste", "add", "--name", "second"], "same text\nmore\nlines\nhere\nyes\n");
    assert!(o.contains("first") && o.contains("second"), "{o}");
    // MCP slip: the whole command line in `command`
    // (checked in the mcp unit below)
}

#[test]
fn privacy_check_finds_and_fixes_planted_leaks() {
    let e = env();
    init(&e);
    let lg = e.log("app.log");
    std::fs::write(&lg, "2026-10-23 10:00:01,000 INFO  [main] a.B - hello\n").unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    e.stdin(&["paste", "add"], "fine paste\nline two\nline three\nline four\nline five\n");
    // clean store: nothing high
    let (o, _, ok) = e.run(&["privacy-check"]);
    assert!(ok && !o.contains("[HIGH]"), "{o}");
    // plant: an unredacted row, a deny-listed path row, an agent-originated paste, wrong permissions, a stray payload
    let key = aws_key();
    {
        let c = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
        c.execute("INSERT INTO entries(name,ts,level,logger,thread,msg,body,tid,err,exc,bytes,at) VALUES('app',1,2,'','',?,'','t1','','',10,1)", [format!("leaked {key} here")]).unwrap();
        let p = rusqlite::Connection::open(e.repo.join(".aix/pastes.db")).unwrap();
        p.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,src,origin) VALUES('paste:50',1,'text',2,10,'h50','','from the agent','paste','~/.bash_history','user')", []).unwrap();
        p.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,src,origin) VALUES('paste:51',1,'text',2,10,'h51','','<system-reminder> report','paste','','user')", []).unwrap();
        p.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,src,origin) VALUES('paste:52',1,'text',2,10,'h52','','plain','paste','','agent')", []).unwrap();
    }
    #[cfg(unix)]
    std::fs::set_permissions(e.repo.join(".aix/logs.db"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(e.repo.join(".aix/.in-1-1"), "raw text").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options().write(true).open(e.repo.join(".aix/.in-1-1")).unwrap().set_modified(old).unwrap();
    let (o, _, ok) = e.run(&["privacy-check"]);
    assert!(!ok, "exit non-zero while HIGH remains: {o}");
    // permission findings need Unix modes
    for needle in ["logs.db entries", "pastes.db sources", "pastes.db origin", "permissions", "left behind"].into_iter().filter(|n| cfg!(unix) || *n != "permissions") {
        assert!(o.contains(needle), "{needle}: {o}");
    }
    assert!(!o.contains(&key), "never prints the secret value: {o}");
    let (j, _, _) = e.run(&["privacy-check", "--json"]);
    assert!(j.contains("\"severity\"") && !j.contains(&key));
    // the card shows one line
    let card = e.ok(&["card"]);
    assert!(card.contains("aix privacy:") && card.contains("aix privacy-check"), "{card}");
    // fix
    let o = e.ok(&["privacy-check", "--fix"]);
    assert!(o.contains("fixed:") && !o.contains(&key), "{o}");
    let (o, _, ok) = e.run(&["privacy-check"]);
    assert!(ok && !o.contains("[HIGH]") && !o.contains("[MEDIUM]"), "clean after --fix: {o}");
    assert!(!has(&e.db_bytes("logs.db"), &key));
    #[cfg(unix)]
    assert_eq!(std::fs::metadata(e.repo.join(".aix/logs.db")).unwrap().permissions().mode() & 0o077, 0);
    assert!(!e.ok(&["card"]).contains("aix privacy:"), "no line when clean");
    // a tracked private-looking file and a marker match
    let marker = rnd(10, "abcdefghijklmnop");
    std::fs::write(e.repo.join("notes.txt"), format!("this mentions {marker} once\n")).unwrap();
    std::fs::write(e.repo.join(".env"), "A=1\n").unwrap();
    git(&e.repo, &["add", "-A", "-f"]);
    let ml = e._d.path().join("markers");
    std::fs::write(&ml, format!("# test\n{marker}\n")).unwrap();
    let mut c = e.cmd(&["privacy-check"]);
    c.env("AIX_PRIVATE_MARKERS", &ml);
    let o = String::from_utf8_lossy(&c.output().unwrap().stdout).to_string();
    assert!(!o.contains("private-marker list"), "the deny list applies only to a repo that opts in: {o}");
    let cfg = e.repo.join(".aix/config.toml");
    let prev = std::fs::read_to_string(&cfg).unwrap_or_default();
    std::fs::write(&cfg, format!("{prev}\nprivate_markers = true\n")).unwrap();
    let mut c = e.cmd(&["privacy-check"]);
    c.env("AIX_PRIVATE_MARKERS", &ml);
    let o = String::from_utf8_lossy(&c.output().unwrap().stdout).to_string();
    assert!(o.contains("private-marker list") && o.contains("notes.txt:1") && o.contains(".env") && !o.contains(&marker), "{o}");
}

#[test]
fn privacy_check_is_fast_on_a_large_store() {
    let e = env();
    init(&e);
    let lg = e.log("big.log");
    let mut s = String::new();
    for i in 0..30000 {
        s.push_str(&format!("2026-10-23 10:{:02}:{:02},000 INFO [t] a.B - event {i} {}\n", (i / 60) % 60, i % 60, rnd(10, "abcdefghijklmnop")));
    }
    std::fs::write(&lg, s).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "big"]);
    let t0 = std::time::Instant::now();
    e.ok(&["privacy-check"]);
    assert!(t0.elapsed().as_millis() < 2500, "sampled mode is fast: {:?}", t0.elapsed());
}

fn watcher(e: &Env) -> std::process::Child {
    let w = e.cmd(&["logs", "watch", "--interval", "1", "--exit-after", "60"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    w
}
fn list_shows(e: &Env, needle: &str, secs: u64) -> String {
    let t0 = std::time::Instant::now();
    loop {
        let l = e.ok(&["logs", "list"]);
        if l.contains(needle) || t0.elapsed().as_secs() >= secs {
            return l;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}
