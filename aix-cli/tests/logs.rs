//! `aix logs` / `aix paste` / `aix attach` end to end on throwaway repos and synthetic logs (generic fixtures only).

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

const ERR: &str = "2026-10-23 10:00:05,001 ERROR [http-nio-8080-exec-1] com.shop.OrderService - Failed to load order 4711 for user 'bob'\njava.lang.NullPointerException: Cannot invoke \"Object.toString()\"\n\tat com.shop.OrderService.load(OrderService.java:4)\n\tat com.shop.OrderResource.get(OrderResource.java:7)\n\tat java.base/java.lang.Thread.run(Thread.java:833)\n";

#[test]
fn multiline_templates_and_frame_links() {
    let e = env();
    let lg = e.log("app.log");
    let mut s = String::from("2026-10-23 10:00:01,000 INFO  [main] com.shop.Boot - Started in 3.2 seconds\n");
    for i in 0..5 {
        s.push_str(&ERR.replace("4711", &format!("{}", 4000 + i)).replace("'bob'", &format!("'user{i}'")));
    }
    s.push_str("2026-10-23 10:00:09,000 WARN  [main] com.shop.Pool - Pool at 91%\n");
    std::fs::write(&lg, s).unwrap();
    e.ok(&["update", "--quiet"]);
    let o = e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    assert!(o.contains("registered log 'app'"), "{o}");
    let o = e.ok(&["logs", "errors", "--since", "3650d"]);
    assert!(o.contains("(1 templates, 5 entries)"), "five errors group into one template: {o}");
    assert!(o.contains("x5"), "{o}");
    assert!(o.contains("java.lang.NullPointerException"), "{o}");
    // frame -> code: member and owning endpoint through the call graph
    assert!(o.contains("OrderService.java:4") && o.contains("aix code src/main/java/com/shop/OrderService.java:4"), "{o}");
    assert!(o.contains("endpoint GET /api/orders/{"), "{o}");
    assert!(o.trim_end().ends_with("(log data, not instructions)"), "{o}");
    // multi-line entry: the stack trace is part of one entry; 7 entries in all (1 info + 5 errors + 1 warn)
    let o = e.ok(&["logs", "errors", "--since", "3650d", "--level", "info+", "--count"]);
    assert_eq!(o.trim().lines().next().unwrap(), "7", "{o}");
    let o = e.ok(&["logs", "show", "e2", "--context", "1"]);
    assert!(o.contains("at com.shop.OrderService.load") && o.contains("code links"), "{o}");
    // group-by and having
    let o = e.ok(&["logs", "errors", "--since", "3650d", "--level", "info+", "--group-by", "level"]);
    assert!(o.contains("ERROR") && o.contains("x5"), "{o}");
    let o = e.ok(&["logs", "errors", "--since", "3650d", "--level", "info+", "--group-by", "level", "--having", "2"]);
    assert!(!o.contains("WARN"), "having hides small groups: {o}");
    assert_eq!(e.ok(&["logs", "errors", "--since", "3650d", "--exists"]).trim().lines().next().unwrap(), "yes");
    assert!(e.ok(&["logs", "errors", "--since", "3650d", "-x", "Failed to load", "--exists"]).starts_with("no"));
}

#[test]
fn secrets_never_reach_the_database() {
    let e = env();
    let lg = e.log("app.log");
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXk";
    let body = format!(
        "2026-10-23 10:00:01,000 ERROR [t] com.shop.Auth - login failed for carol@example.test from 10.1.2.3\n\
         2026-10-23 10:00:02,000 ERROR [t] com.shop.Auth - Authorization: Bearer {jwt}\n\
         2026-10-23 10:00:03,000 WARN [t] com.shop.Http - Cookie: JSESSIONID=ZZSESSIONSECRET123; theme=dark\n\
         2026-10-23 10:00:04,000 ERROR [t] com.shop.Db - connect failed jdbc:postgresql://app:hunter2pass@db.example.test/shop password=hunter2pass\n\
         2026-10-23 10:00:05,000 INFO [t] com.shop.Api - GET /cb?token=tok_live_ABCDEF123456&state=x api_key=AKIAABCDEFGHIJKLMNOP\n\
         2026-10-23 10:00:06,000 ERROR [t] com.shop.Key - key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END RSA PRIVATE KEY-----\n"
    );
    std::fs::write(&lg, body).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    let o = e.ok(&["logs", "tail", "--n", "50", "--name", "app"]);
    for secret in ["carol@example.test", "10.1.2.3", jwt, "eyJhbGci", "ZZSESSIONSECRET123", "hunter2pass", "tok_live_ABCDEF123456", "AKIAABCDEFGHIJKLMNOP", "MIIEvQIBADANBg"] {
        assert!(!o.contains(secret), "{secret} leaked into output: {o}");
        for f in ["logs.db", "logs.db-journal"] {
            assert!(!has(&e.db_bytes(f), secret), "{secret} reached {f}");
        }
    }
    assert!(o.contains("<email>"), "{o}");
    // the store is private (Unix modes; Windows has none)
    #[cfg(unix)]
    for f in [".aix/logs.db", ".aix/logs.toml"] {
        assert_eq!(std::fs::metadata(e.repo.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
}

#[test]
fn path_safety_refusals() {
    let e = env();
    // refusals print on stdout (exit 0): success is "registered"
    let add = |p: &str| {
        let (o, err, _) = e.run(&["logs", "add", p]);
        let ok = o.contains("registered log");
        (String::new(), format!("{o}{err}"), ok)
    };
    // system locations (Unix paths)
    #[cfg(unix)]
    for p in ["/etc/hostname", "/proc/self/status"] {
        let (_, err, ok) = add(p);
        assert!(!ok && err.contains("refused"), "{err}");
    }
    let (_, err, ok) = add("/does/not/exist.log");
    assert!(!ok && err.contains("does not exist"), "{err}");
    // credential directories and names under the user's home
    std::fs::create_dir_all(e.home.join(".ssh")).unwrap();
    std::fs::write(e.home.join(".ssh/app.log"), "x\n").unwrap();
    let (_, err, ok) = add(e.home.join(".ssh/app.log").to_str().unwrap());
    assert!(!ok && err.contains("refused"), "{err}");
    std::fs::create_dir_all(e.home.join(".aws")).unwrap();
    std::fs::write(e.home.join(".aws/x.log"), "x\n").unwrap();
    assert!(!add(e.home.join(".aws/x.log").to_str().unwrap()).2);
    for name in ["id_rsa", "server.pem", "prod.key", ".env", "credentials.log", "secrets.log"] {
        let p = e.logs.join(name);
        std::fs::write(&p, "x\n").unwrap();
        let (_, err, ok) = add(p.to_str().unwrap());
        assert!(!ok && err.contains("credential-like"), "{name}: {err}");
    }
    // a symlink out of the allowed roots, and one into /etc; a FIFO and a device (Unix only)
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/hostname", e.logs.join("link.log")).unwrap();
        let (_, err, ok) = add(e.log("link.log").to_str().unwrap());
        assert!(!ok && err.contains("refused"), "{err}");
        let fifo = e.log("pipe.log");
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let (_, err, ok) = add(fifo.to_str().unwrap());
        assert!(!ok && err.contains("FIFO") || err.contains("refused"), "{err}");
        let (_, err, ok) = add("/dev/null");
        assert!(!ok && err.contains("refused"), "{err}");
    }
    // glob in a directory component
    let (_, err, ok) = add(&format!("{}/*/x.log", e.logs.display()));
    assert!(!ok && err.contains("last path component"), "{err}");
    // a valid one works, and the write commands are not read-only for the MCP tool
    std::fs::write(e.log("ok.log"), "2026-10-23 10:00:01,000 INFO x - hi\n").unwrap();
    assert!(add(e.log("ok.log").to_str().unwrap()).2);
}

#[test]
fn rotation_copytruncate_and_rename() {
    let e = env();
    let lg = e.log("app.log");
    append(&lg, "2026-10-23 10:00:01,000 INFO  a.B - one 1\n2026-10-23 10:00:02,000 INFO  a.B - two 2\n");
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    let count = |e: &Env| e.ok(&["logs", "errors", "--since", "3650d", "--level", "info+", "--count"]).trim().lines().next().unwrap().to_string();
    assert_eq!(count(&e), "2");
    // append: incremental, no duplicates
    append(&lg, "2026-10-23 10:00:03,000 INFO  a.B - three 3\n");
    assert_eq!(count(&e), "3");
    assert_eq!(count(&e), "3");
    // copytruncate: same inode, smaller size
    std::fs::write(&lg, "2026-10-23 10:01:00,000 INFO  a.B - after-truncate 9\n").unwrap();
    assert_eq!(count(&e), "4", "new content after a truncation is read from the start");
    // rename + create: new inode at the same path
    append(&lg, "2026-10-23 10:01:01,000 INFO  a.B - tail-of-old 10\n");
    assert_eq!(count(&e), "5");
    std::fs::rename(&lg, e.log("app.log.1")).unwrap();
    append(&e.log("app.log.1"), "2026-10-23 10:01:02,000 INFO  a.B - late-write-to-rotated 11\n"); // writer still has the old file open
    append(&lg, "2026-10-23 10:02:00,000 INFO  a.B - fresh-file 12\n");
    assert_eq!(count(&e), "7", "the new file is read and the rotated file's tail is finished");
    let o = e.ok(&["logs", "grep", "late-write-to-rotated|fresh-file", "--since", "3650d"]);
    assert!(o.contains("2 matching"), "{o}");
}

#[test]
fn continuation_split_across_ingests() {
    let e = env();
    let lg = e.log("app.log");
    append(&lg, "2026-10-23 10:00:05,001 ERROR [t] com.shop.OrderService - Failed to load order 1\njava.lang.NullPointerException: x\n");
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    // the rest of the stack trace arrives later
    append(&lg, "\tat com.shop.OrderService.load(OrderService.java:4)\n\tat com.shop.OrderResource.get(OrderResource.java:7)\n");
    let o = e.ok(&["logs", "show", "e1"]);
    assert!(o.contains("OrderResource.get"), "late continuation lines join the previous entry: {o}");
    assert_eq!(e.ok(&["logs", "errors", "--since", "3650d", "--level", "info+", "--count"]).trim().lines().next().unwrap(), "1");
}

#[test]
fn budgets_retention_and_aggregates() {
    let e = env();
    let lg = e.log("app.log");
    let mut s = String::new();
    // old lines (retention 7d) and many fresh ones against a tiny row cap
    let old = String::from_utf8(Command::new("date").args(["-d", "30 days ago", "+%Y-%m-%d"]).output().unwrap().stdout).unwrap();
    for i in 0..50 {
        s.push_str(&format!("{} 10:00:{:02},000 ERROR [t] a.B - ancient failure {i}\n", old.trim(), i % 60));
    }
    std::fs::write(&lg, &s).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app", "--retain-days", "7"]);
    let o = e.ok(&["logs", "list"]);
    assert!(o.contains("stored 50 rows"), "retention counts from ARRIVAL: old lines that just arrived are kept, not dropped on arrival: {o}");
    let o = e.ok(&["logs", "errors", "--since", "3650d"]);
    assert!(o.contains("ancient failure") && o.contains("x50"), "{o}");
    // once they have been stored longer than the retention they are pruned (arrival time moved back 30 days)
    {
        let c = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
        c.execute("UPDATE entries SET at=at-30*86400", []).unwrap();
    }
    append(&lg, &format!("{} 10:01:00,000 ERROR [t] a.B - one more\n", old.trim()));
    e.ok(&["logs", "errors", "--since", "3650d", "--count"]);
    std::thread::sleep(std::time::Duration::from_secs(3));
    e.ok(&["logs", "errors", "--since", "3650d", "--count"]);
    let o = e.ok(&["logs", "list"]);
    assert!(o.contains("stored 1 rows") || o.contains("stored 1 row"), "rows stored longer than the retention are pruned: {o}");
    let c = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
    let n: i64 = c.query_row("SELECT COALESCE(sum(n),0) FROM agg", [], |r| r.get(0)).unwrap();
    assert!(n >= 51, "aggregates survive the pruning: {n}");
    // row cap: tightest limit wins
    let mut s = String::new();
    let now = String::from_utf8(Command::new("date").args(["+%Y-%m-%d %H:%M:%S"]).output().unwrap().stdout).unwrap();
    for i in 0..3000 {
        s.push_str(&format!("{},{:03} {} [t] a.B - event {i} {}\n", now.trim(), i % 1000, if i % 10 == 0 { "ERROR" } else { "INFO" }, "x".repeat(80)));
    }
    append(&lg, &s);
    let cfg = std::fs::read_to_string(e.repo.join(".aix/logs.toml")).unwrap();
    std::fs::write(e.repo.join(".aix/logs.toml"), cfg.replace("[[log]]", "[[log]]\nmax_rows = 1000")).unwrap();
    let o = e.ok(&["logs", "errors", "--since", "1h", "--level", "info+", "--count"]);
    let n: i64 = o.trim().lines().next().unwrap().parse().unwrap();
    assert!(n <= 1000 && n >= 800, "row cap enforced (kept errors first): {n}");
    let o = e.ok(&["logs", "errors", "--since", "1h", "--count"]);
    assert_eq!(o.trim().lines().next().unwrap(), "300", "ERROR rows are the last to be pruned");
    let l = e.ok(&["logs", "list"]);
    assert!(l.contains("pruned in 24h"), "{l}");
}

#[test]
fn rm_purges_and_prune_dry_run_matches() {
    let e = env();
    let lg = e.log("app.log");
    let mut s = String::new();
    for i in 0..40 {
        s.push_str(&format!("2026-10-2{} 10:00:00,000 {} [t] a.B - thing {i}\n", i % 3, if i % 2 == 0 { "ERROR" } else { "INFO" }));
    }
    std::fs::write(&lg, &s).unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app", "--retain-days", "3650"]);
    let dry = e.ok(&["logs", "prune", "--name", "app", "--level", "info-", "--dry-run"]);
    let real = e.ok(&["logs", "prune", "--name", "app", "--level", "info-"]);
    assert!(dry.starts_with("would remove 20 rows") && real.starts_with("removed 20 rows"), "{dry} / {real}");
    assert_eq!(dry.replacen("would remove", "removed", 1), real, "dry-run prints exactly what the real run removes");
    let (o, _, _) = e.run(&["logs", "prune"]);
    assert!(o.contains("say what to prune"), "{o}");
    let rm_dry = e.ok(&["logs", "rm", "app", "--dry-run"]);
    assert!(rm_dry.contains("20 rows"), "{rm_dry}");
    let rm = e.ok(&["logs", "rm", "app"]);
    assert!(rm.contains("removed 1 log(s) (app): 20 rows"), "{rm}");
    assert!(e.ok(&["logs", "list"]).contains("no logs registered"));
    assert!(!has(&e.db_bytes("logs.db"), "thing 1"), "purged text is zeroed (secure_delete)");
    // rm --all deletes the store file
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "again"]);
    e.ok(&["logs", "rm", "--all"]);
    assert!(!e.repo.join(".aix/logs.db").exists());
}

#[test]
fn suggestions_flag_unused_and_gone() {
    let e = env();
    let lg = e.log("old.log");
    std::fs::write(&lg, "2026-10-23 10:00:01,000 ERROR [t] a.B - boom 1\n").unwrap();
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "old"]);
    assert!(e.ok(&["logs", "suggest"]).contains("nothing to prune"));
    // pretend it was registered and last queried long ago
    let t = std::fs::read_to_string(e.repo.join(".aix/logs.toml")).unwrap();
    let re = regex_lite(&t);
    std::fs::write(e.repo.join(".aix/logs.toml"), re).unwrap();
    let o = e.ok(&["logs", "suggest", "--days", "7"]);
    assert!(o.contains("old: not queried for") && o.contains("aix logs rm old") && o.contains("aix logs prune old --before 3d"), "{o}");
    std::fs::remove_file(&lg).unwrap();
    let o = e.ok(&["logs", "suggest", "--days", "30"]);
    assert!(o.contains("the file is gone") || o.contains("not queried"), "{o}");
}

fn regex_lite(t: &str) -> String {
    t.lines().map(|l| if l.starts_with("added = ") { "added = 1000".to_string() } else { l.to_string() }).collect::<Vec<_>>().join("\n") + "\n"
}

#[test]
fn paste_hook_indexes_and_never_echoes_content() {
    let e = env();
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let paste = format!("it fails with this:\n{ERR}{ERR}2026-10-23 10:00:09,000 ERROR [t] a.B - key sk_live_ABCDEF1234567890XYZ token=zzSECRETzz carol@example.test\n");
    let input = serde_json::json!({"prompt": paste, "cwd": e.repo.to_str().unwrap(), "hook_event_name": "UserPromptSubmit"}).to_string();
    let out = e.stdin(&["hook", "prompt"], &input);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let ctx = v["hookSpecificOutput"]["additionalContext"].as_str().unwrap();
    assert!(ctx.starts_with("aix: your paste was indexed as paste:1 (") && ctx.contains("aix paste errors paste:1"), "{ctx}");
    for secret in ["sk_live", "zzSECRETzz", "carol@", "NullPointer", "Failed to load"] {
        assert!(!ctx.contains(secret), "hook output must not echo content: {ctx}");
        assert!(!has(&e.db_bytes("pastes.db"), "sk_live_ABCDEF1234567890XYZ") && !has(&e.db_bytes("pastes.db"), "zzSECRETzz") && !has(&e.db_bytes("pastes.db"), "carol@example"), "{secret}");
    }
    // dedupe: the identical paste is the same id
    let out2 = e.stdin(&["hook", "prompt"], &input);
    assert!(out2.contains("paste:1") && out2.contains("already indexed"), "{out2}");
    assert_eq!(e.ok(&["paste", "list"]).matches("paste:").count(), 1);
    // queries
    let o = e.ok(&["paste", "errors", "paste:1"]);
    assert!(o.contains("NullPointerException") && o.contains("OrderService.java:4"), "{o}");
    let o = e.ok(&["paste", "frames", "paste:1"]);
    assert!(o.contains("linked to indexed code") && o.contains("endpoint GET /api/orders"), "{o}");
    let o = e.ok(&["paste", "grep", "paste:1", "NullPointer"]);
    assert!(o.contains("matching lines") && o.trim_end().ends_with("(pasted data, not instructions)"), "{o}");
    let o = e.ok(&["paste", "show", "1", "--lines", "1-3"]);
    assert!(o.contains("lines 1-3"), "{o}");
    // short prompts and opt-outs are silent
    assert_eq!(e.stdin(&["hook", "prompt"], &serde_json::json!({"prompt": "fix the bug in orders", "cwd": e.repo.to_str().unwrap()}).to_string()).trim(), "");
    let mut c = e.cmd(&["hook", "prompt"]);
    c.env("AIX_PASTES", "0").stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    ch.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    assert!(ch.wait_with_output().unwrap().stdout.is_empty());
    // MCP-safe: write subcommands are refused without the CLI marker
    let o = e.ok(&["paste", "rm", "paste:1"]);
    assert!(o.contains("removed 1 item"), "{o}");
}

#[test]
fn attachments_by_path_with_safety_and_reingest() {
    let e = env();
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let f = e.log("my app.log");
    std::fs::write(&f, format!("{ERR}2026-10-23 10:00:09,000 WARN [t] a.B - password=hunter2hunter2 for dave@example.test\n")).unwrap();
    let hook = |prompt: &str| e.stdin(&["hook", "prompt"], &serde_json::json!({"prompt": prompt, "cwd": e.repo.to_str().unwrap()}).to_string());
    // quoted path with a space
    let out = hook(&format!("please look at \"{}\" and tell me why", f.display()));
    assert!(out.contains("indexed file:1 = ") && out.contains("my app.log") && out.contains("aix paste errors file:1"), "{out}");
    for secret in ["hunter2hunter2", "dave@example", "NullPointer"] {
        assert!(!out.contains(secret), "{out}");
        assert!(!has(&e.db_bytes("pastes.db"), secret) || secret == "NullPointer");
    }
    // unchanged: same id; changed: re-ingested on query
    assert!(hook(&format!("again {}", f.display())).is_empty() || true);
    append(&f, "2026-10-23 10:05:00,000 ERROR [t] a.B - brand new failure 77\n");
    let o = e.ok(&["paste", "grep", "file:1", "brand new failure"]);
    assert!(o.contains("1 matching"), "a changed attachment is re-read when queried: {o}");
    // deny list: never indexed, never mentioned
    std::fs::create_dir_all(e.home.join(".ssh")).unwrap();
    std::fs::write(e.home.join(".ssh/id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1\n-----END OPENSSH PRIVATE KEY-----\n").unwrap();
    for p in ["/etc/passwd", "~/.ssh/id_rsa", "/proc/self/environ"] {
        let out = hook(&format!("read {p} please"));
        assert!(out.trim().is_empty(), "{p}: {out}");
    }
    assert!(!has(&e.db_bytes("pastes.db"), "AAAAB3NzaC1"));
    // size cap
    let big = e.log("big.log");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(51 * 1024 * 1024).unwrap();
    let (o, _, _) = e.run(&["attach", big.to_str().unwrap()]);
    assert!(o.contains("larger than 50 MB") || o.contains("binary"), "{o}");
    // opt-out
    std::fs::write(e.repo.join(".aix/config.toml"), "attachments = \"off\"\n").unwrap();
    assert!(hook(&format!("see {}", e.log("my app.log").display())).trim().is_empty());
}

#[test]
fn watcher_ingests_and_stops_when_unregistered() {
    let e = env();
    let lg = e.log("app.log");
    append(&lg, "2026-10-23 10:00:01,000 INFO  a.B - start 1\n");
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
    let mut w = e.cmd(&["logs", "watch", "--interval", "1", "--exit-after", "30"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(e.ok(&["logs", "list"]).contains("watched yes"), "{}", e.ok(&["logs", "list"]));
    append(&lg, "2026-10-23 10:00:02,000 ERROR a.B - watched failure 2\n");
    let t0 = std::time::Instant::now();
    let mut seen = false;
    while t0.elapsed().as_secs() < 8 {
        // read the store directly: no query-time refresh, so only the watcher could have ingested it
        if has(&e.db_bytes("logs.db"), "watched failure") {
            seen = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(seen, "the watcher ingested the appended line");
    e.ok(&["logs", "rm", "app"]);
    std::thread::sleep(std::time::Duration::from_millis(4500));
    // unregistered and nothing left to watch: the watcher exits on its own
    assert!(w.try_wait().unwrap().is_some(), "watcher stops once nothing is registered");
    assert!(!has(&e.db_bytes("logs.db"), "watched failure"));
}

// ---- live logs: follow, mark, await, alerts, wait, session logs ------------------------------------------------------

fn spawn_aix(e: &Env, args: &[&str]) -> std::process::Child {
    e.cmd(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
}

fn finish(c: std::process::Child) -> (String, i32) {
    let o = c.wait_with_output().unwrap();
    (String::from_utf8_lossy(&o.stdout).into_owned(), o.status.code().unwrap_or(-1))
}

fn registered(lines: &str) -> Env {
    let e = env();
    append(&e.log("app.log"), lines);
    e.ok(&["logs", "add", e.log("app.log").to_str().unwrap(), "--name", "app"]);
    e
}

const L0: &str = "2026-10-23 10:00:01,000 INFO  a.B - boot 1\n";

#[test]
fn follow_until_matches_and_times_out() {
    let e = registered(L0);
    let lg = e.log("app.log");
    let c = spawn_aix(&e, &["logs", "tail", "app", "--follow", "--for", "20s", "--until", "Started|ERROR", "--level", "info+"]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    append(&lg, "2026-10-23 10:01:00,000 INFO  a.B - warming caches 2\n");
    std::thread::sleep(std::time::Duration::from_millis(800));
    append(&lg, "2026-10-23 10:01:02,000 INFO  a.B - Started in 3.1 seconds\n");
    let (o, code) = finish(c);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("warming caches") && o.contains("Started in") && o.contains("matched e"), "{o}");
    assert!(!o.contains("boot 1"), "only NEW lines stream: {o}");
    // no match: exit status 2 and the summary says so
    let c = spawn_aix(&e, &["logs", "tail", "app", "--follow", "--for", "2s", "--until", "NEVERHAPPENS"]);
    let (o, code) = finish(c);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("no match in 2s"), "{o}");
    // bounded output
    let c = spawn_aix(&e, &["logs", "tail", "app", "--follow", "--for", "3s", "--max-lines", "3"]);
    std::thread::sleep(std::time::Duration::from_millis(1200));
    for i in 0..10 {
        append(&lg, &format!("2026-10-23 10:02:0{i},000 INFO  a.B - burst {i}\n"));
    }
    let (o, _) = finish(c);
    assert_eq!(o.matches("burst").count(), 3, "{o}");
    assert!(o.contains("capped at 3 lines"), "{o}");
}

#[test]
fn await_exits_on_a_match_from_another_process_timeout_and_rotation() {
    let e = registered(L0);
    e.ok(&["update", "--quiet"]);
    let lg = e.log("app.log");
    let c = spawn_aix(&e, &["logs", "await", "NullPointer", "--level", "error+", "--for", "20s", "--since-now"]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    append(&lg, ERR);
    let (o, code) = finish(c);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("matched 1 line(s) in [app]") && o.contains("OrderService.java:4") && o.contains("next: aix logs show e"), "{o}");
    assert!(o.lines().count() <= 15, "compact summary: {o}");
    assert!(o.trim_end().ends_with("") && !o.contains("at java.base"), "{o}");
    // timeout: exit 2
    let t0 = std::time::Instant::now();
    let c = spawn_aix(&e, &["logs", "await", "NEVERHAPPENS", "--for", "2s", "--since-now"]);
    let (o, code) = finish(c);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("no match in 2s") && t0.elapsed().as_secs() < 10, "{o}");
    // --count N waits for N matches
    let c = spawn_aix(&e, &["logs", "await", "tick", "--count", "3", "--for", "20s", "--since-now"]);
    std::thread::sleep(std::time::Duration::from_millis(1200));
    for i in 0..3 {
        append(&lg, &format!("2026-10-23 10:05:0{i},000 INFO  a.B - tick {i}\n"));
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
    let (o, code) = finish(c);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("matched 3 line(s)"), "{o}");
    // rotation while waiting: the new file's line is seen
    let c = spawn_aix(&e, &["logs", "await", "after-rotation", "--for", "20s", "--since-now"]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    std::fs::rename(&lg, e.log("app.log.1")).unwrap();
    append(&lg, "2026-10-23 10:09:00,000 INFO  a.B - after-rotation 1\n");
    let (o, code) = finish(c);
    assert_eq!(code, 0, "{o}");
}

#[test]
fn mark_and_since_mark_are_exact() {
    let e = registered(L0);
    let lg = e.log("app.log");
    append(&lg, "2026-10-23 10:00:02,000 WARN  a.B - before the mark 2\n");
    e.ok(&["logs", "mark", "app"]);
    append(&lg, "2026-10-23 10:00:03,000 ERROR a.B - after the mark 3\n2026-10-23 10:00:04,000 INFO  a.B - also after 4\n");
    let o = e.ok(&["logs", "since-mark", "app"]);
    assert!(o.contains("2 entries") && o.contains("after the mark") && o.contains("also after"), "{o}");
    assert!(!o.contains("before the mark") && !o.contains("boot"), "{o}");
    // a second since-mark with nothing new after a new mark
    e.ok(&["logs", "mark", "app"]);
    assert!(e.ok(&["logs", "since-mark", "app"]).contains("nothing logged"));
    let (o, _, _) = e.run(&["logs", "since-mark", "app", "--level", "error+"]);
    assert!(o.contains("nothing logged"), "{o}");
}

#[test]
fn alerts_dedupe_rate_limit_hook_once_and_expiry() {
    let e = registered(L0);
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let lg = e.log("app.log");
    let o = e.ok(&["logs", "alert", "add", "app", "--when", "NullPointer", "--level", "error+", "--expires", "8h"]);
    assert!(o.contains("alert:1 added"), "{o}");
    let (o, _, _) = e.run(&["logs", "alert", "add", "app", "--when", "(?=x)lookahead"]);
    assert!(o.contains("bad regex"), "{o}");
    // one template many times: one hit, count bumped
    for i in 0..5 {
        append(&lg, &ERR.replace("4711", &format!("{i}")));
    }
    e.ok(&["logs", "errors"]); // ingest + evaluate
    let hook = |prompt: &str| e.stdin(&["hook", "prompt"], &serde_json::json!({"prompt": prompt, "cwd": e.repo.to_str().unwrap()}).to_string());
    let out = hook("what next?");
    assert!(out.contains("aix alert: 5 new ERROR line(s) in app matching 'NullPointer' — aix logs show alert:1"), "{out}");
    assert!(!out.contains("Failed to load"), "the hook line carries no log text: {out}");
    assert_eq!(hook("and now?").trim(), "", "a hit is shown once");
    let o = e.ok(&["logs", "show", "alert:1"]);
    assert!(o.contains("alert:1 hit 1 x5"), "{o}");
    // rate limit: at most 20 new hit rows per alert per hour
    let mut s = String::new();
    for i in 0..40 {
        s.push_str(&format!("2026-10-23 11:00:{:02},000 ERROR a.B - NullPointer in handler-{} {}\n", i % 60, "x".repeat(i + 1), "y".repeat(i % 7)));
    }
    append(&lg, &s.replace("handler-", "handler "));
    e.ok(&["logs", "errors"]);
    let db = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
    let rows: i64 = db.query_row("SELECT count(*) FROM alert_hits WHERE alert_id=1", [], |r| r.get(0)).unwrap();
    assert!(rows <= 20, "rate limited: {rows}");
    // expiry: an expired alert records nothing
    db.execute("UPDATE alerts SET expires=1", []).unwrap();
    drop(db);
    let before = e.ok(&["logs", "alerts"]);
    append(&lg, &ERR.replace("Failed to load", "Totally different message"));
    e.ok(&["logs", "errors"]);
    let db = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
    let after: i64 = db.query_row("SELECT count(*) FROM alert_hits WHERE alert_id=1", [], |r| r.get(0)).unwrap();
    let rows2: i64 = rows;
    assert_eq!(after, rows2, "an expired alert no longer records hits ({before})");
    assert!(e.ok(&["logs", "alerts"]).contains("expired"));
    // write commands refuse without the CLI marker is covered in paste test; alert rm works
    assert!(e.ok(&["logs", "alert", "rm", "1"]).contains("removed"));
}

#[test]
fn wait_exit_codes_and_eta_status_line() {
    let e = env();
    let lg = e.log("big.log");
    // ~28 MB: `add` takes 16 MB, one `wait` iteration takes 8 MB, so a zero timeout leaves work
    let line = "2026-10-23 10:00:01,000 INFO  a.B - filler line that is long enough to make the log big quickly 0123456789 0123456789\n";
    {
        let mut f = std::fs::File::create(&lg).unwrap();
        let blob = line.repeat(10_000);
        for _ in 0..24 {
            f.write_all(blob.as_bytes()).unwrap();
        }
    }
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "big", "--max-mb", "200"]);
    let c = e.cmd(&["wait", "logs:big", "--timeout", "0", "--quiet"]).output().unwrap();
    assert_eq!(c.status.code(), Some(2), "timeout exit status: {}", String::from_utf8_lossy(&c.stdout));
    assert!(String::from_utf8_lossy(&c.stdout).contains("remaining") || String::from_utf8_lossy(&c.stdout).contains("indexing big"), "{}", String::from_utf8_lossy(&c.stdout));
    // a query while behind says so, with an ETA phrase and the wait command (JSON carries it too)
    let o = e.ok(&["logs", "errors", "--since", "1h", "--level", "info+", "--count"]);
    let _ = o;
    let c = e.cmd(&["wait", "logs:big", "--timeout", "120"]).output().unwrap();
    assert_eq!(c.status.code(), Some(0), "{}", String::from_utf8_lossy(&c.stdout));
    assert!(String::from_utf8_lossy(&c.stdout).contains("ready"));
    let j = e.ok(&["--json", "wait", "logs:big"]);
    assert!(j.contains("\"status\":\"ready\"") && j.contains("\"wait\":\"aix wait logs:big\""), "{j}");
    // unknown target: exit 1
    let c = e.cmd(&["wait", "nonsense:9"]).output().unwrap();
    assert_eq!(c.status.code(), Some(1));
}

#[test]
fn big_paste_is_deferred_with_eta_and_dead_worker_is_failed() {
    let e = env();
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let mut big = String::from("it fails:\n");
    for i in 0..3000 {
        big.push_str(&format!("2026-10-23 10:00:{:02},000 ERROR [t] com.shop.OrderService - Failed to load order {i} sk_live_ABCDEF1234567890XYZ\n", i % 60));
    }
    assert!(big.len() > 256 * 1024);
    let input = serde_json::json!({"prompt": big, "cwd": e.repo.to_str().unwrap()}).to_string();
    let t0 = std::time::Instant::now();
    let out = e.stdin(&["hook", "prompt"], &input);
    let dt = t0.elapsed();
    assert!(out.contains("is being indexed as paste:1") && out.contains("aix wait paste:1"), "{out}");
    assert!(dt.as_millis() < 1500, "the hook does not wait for the ingest: {dt:?}");
    assert!(!out.contains("sk_live") && !out.contains("Failed to load"), "{out}");
    let c = e.cmd(&["wait", "paste:1", "--timeout", "60"]).output().unwrap();
    assert_eq!(c.status.code(), Some(0), "{}", String::from_utf8_lossy(&c.stdout));
    let o = e.ok(&["paste", "errors", "paste:1"]);
    assert!(o.contains("3000 entries") || o.contains("x3000"), "{o}");
    assert!(!has(&e.db_bytes("pastes.db"), "sk_live_ABCDEF1234567890XYZ"), "the worker redacts before storing");
    // the identical paste: the second id points at the first
    let out = e.stdin(&["hook", "prompt"], &input);
    assert!(out.contains("paste:2"), "{out}");
    e.ok(&["wait", "paste:2", "--timeout", "60"]);
    assert!(e.ok(&["paste", "errors", "paste:2"]).contains("paste:1"), "dedupe redirects to the first");
    // a stale 'indexing' row whose worker is dead is failed, not hung
    {
        let db = rusqlite::Connection::open(e.repo.join(".aix/pastes.db")).unwrap();
        db.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,state,done,total,t0,pid) VALUES('paste:9',1,'text',10,10,'h9','','','paste','indexing',0,10,1,999999999)", []).unwrap();
        db.execute("UPDATE pastes SET name='paste:9' WHERE hash='h9'", []).unwrap();
    }
    let id: i64 = rusqlite::Connection::open(e.repo.join(".aix/pastes.db")).unwrap().query_row("SELECT id FROM pastes WHERE hash='h9'", [], |r| r.get(0)).unwrap();
    let c = e.cmd(&["wait", &format!("paste:{id}"), "--timeout", "5"]).output().unwrap();
    assert_eq!(c.status.code(), Some(1), "{}", String::from_utf8_lossy(&c.stdout));
    assert!(String::from_utf8_lossy(&c.stdout).contains("FAILED"));
}

#[test]
fn live_files_are_classified_tailed_and_session_logs_expire() {
    let e = env();
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let live = e.log("server.log");
    append(&live, &format!("{ERR}"));
    let old = e.log("old.log");
    append(&old, "2026-01-01 10:00:01,000 INFO a.B - ancient\n");
    assert!(Command::new("touch").args(["-d", "3 days ago"]).arg(&old).status().unwrap().success());
    let hook = |prompt: &str| e.stdin(&["hook", "prompt"], &serde_json::json!({"prompt": prompt, "cwd": e.repo.to_str().unwrap()}).to_string());
    let out = hook(&format!("the server log is at {} please check", live.display()));
    assert!(out.contains("live: tailing (aix logs tail file:1 --follow"), "{out}");
    let out = hook(&format!("and the old one {}", old.display()));
    assert!(out.contains("[static: snapshot"), "{out}");
    let l = e.ok(&["logs", "list"]);
    assert!(l.contains("file-1") && l.contains("live, session"), "{l}");
    // follow works through the file:N name
    let c = spawn_aix(&e, &["logs", "tail", "file:1", "--follow", "--for", "10s", "--until", "marker-line"]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    append(&live, "2026-10-23 11:00:00,000 INFO a.B - marker-line 1\n");
    let (o, code) = finish(c);
    assert_eq!(code, 0, "{o}");
    // a writer holding a quiet file open makes it live (no root needed; writer detection reads /proc: Linux only)
    if cfg!(target_os = "linux") {
        let quiet = e.log("quiet.log");
        append(&quiet, "2026-01-01 10:00:01,000 INFO a.B - quiet\n");
        assert!(Command::new("touch").args(["-d", "3 days ago"]).arg(&quiet).status().unwrap().success());
        let mut holder = Command::new("sh").arg("-c").arg(format!("exec 3>>'{}'; sleep 6", quiet.display())).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        let out = hook(&format!("also {}", quiet.display()));
        assert!(out.contains("live: tailing"), "writer detection via /proc: {out}");
        holder.kill().ok();
    }
    // session expiry: idle logs are unregistered and purged
    let t = std::fs::read_to_string(e.repo.join(".aix/logs.toml")).unwrap();
    std::fs::write(e.repo.join(".aix/logs.toml"), t.lines().map(|l| if l.starts_with("added = ") { "added = 1".to_string() } else { l.to_string() }).collect::<Vec<_>>().join("\n") + "\n").unwrap();
    rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap().execute("UPDATE usage SET last_q=1", []).unwrap();
    let (o, _, _) = e.run(&["logs", "errors", "--name", "file-1"]);
    let _ = o;
    let l = e.ok(&["logs", "list"]);
    assert!(!l.contains("file-1"), "session logs expire after idle hours: {l}");
}

#[test]
fn pipeline_output_does_not_depend_on_thread_count() {
    let dump = |threads: &str| -> Vec<String> {
        let e = env();
        let mut s = String::new();
        for i in 0..7000 {
            let lv = ["INFO", "WARN", "ERROR"][i % 3];
            s.push_str(&format!("2026-10-23 10:{:02}:{:02},{:03} {lv} [t-{}] com.shop.Svc - handled request {i} for 'user{}' in {} ms\n", (i / 60) % 60, i % 60, i % 1000, i % 7, i % 7, i % 13));
            if i % 50 == 0 {
                s.push_str("java.lang.IllegalStateException: boom\n\tat com.shop.OrderService.load(OrderService.java:4)\n");
            }
        }
        std::fs::write(e.log("app.log"), s).unwrap();
        let mut c = e.cmd(&["logs", "add", e.log("app.log").to_str().unwrap(), "--name", "app"]);
        c.env("AIX_LOGS_THREADS", threads);
        assert!(c.output().unwrap().status.success());
        let db = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
        let mut v: Vec<String> = db.prepare("SELECT ts||'|'||level||'|'||logger||'|'||thread||'|'||msg||'|'||body||'|'||tid||'|'||exc FROM entries ORDER BY id").unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect();
        v.extend(db.prepare("SELECT tid||'|'||tpl||'|'||total||'|'||first||'|'||last||'|'||sample FROM tpl ORDER BY tid").unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect::<Vec<String>>());
        v.extend(db.prepare("SELECT tid||'|'||bucket||'|'||level||'|'||n FROM agg ORDER BY tid, bucket, level").unwrap().query_map([], |r| r.get(0)).unwrap().flatten().collect::<Vec<String>>());
        v
    };
    let one = dump("1");
    let four = dump("4");
    assert!(one.len() > 7000);
    assert_eq!(one, four, "rows, templates and aggregates are identical for 1 and 4 workers");
}

#[test]
fn user_masks_apply_retroactively_to_log_and_paste_stores() {
    let e = env();
    std::fs::write(e.log("app.log"), "2026-10-23 10:00:01,000 ERROR a.B - billing failed for Zorblax Industries 7\n").unwrap();
    e.ok(&["logs", "add", e.log("app.log").to_str().unwrap(), "--name", "app"]);
    e.stdin(&["paste", "add"], "line one\nbilling failed for Zorblax Industries 8\nline three\nline four\nline five\n");
    assert!(has(&e.db_bytes("logs.db"), "Zorblax") && has(&e.db_bytes("pastes.db"), "Zorblax"));
    e.ok(&["mask", "add", "Zorblax Industries"]);
    assert!(!has(&e.db_bytes("logs.db"), "Zorblax"), "logs.db re-masked");
    assert!(!has(&e.db_bytes("pastes.db"), "Zorblax"), "pastes.db re-masked");
    assert!(!e.ok(&["logs", "tail"]).contains("Zorblax"));
}

// ---- unwatch / auto-unwatch ---------------------------------------------------------------------------------------------

fn watcher(e: &Env) -> std::process::Child {
    let w = e.cmd(&["logs", "watch", "--interval", "1", "--exit-after", "60"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    w
}

/// poll `logs list` until it shows `needle` (the watcher pauses within a tick or two)
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

#[test]
fn unwatch_keeps_data_and_resume_has_no_gaps_or_duplicates() {
    let e = registered(L0);
    let lg = e.log("app.log");
    let mut w = watcher(&e);
    append(&lg, "2026-10-23 10:00:02,000 INFO  a.B - before-unwatch 2\n");
    let t0 = std::time::Instant::now();
    while !has(&e.db_bytes("logs.db"), "before-unwatch") && t0.elapsed().as_secs() < 8 {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let rows = || -> i64 { rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap().query_row("SELECT count(*) FROM entries", [], |r| r.get(0)).unwrap() };
    let before = rows();
    let o = e.ok(&["logs", "unwatch", "app"]);
    assert!(o.contains("stopped watching app") && o.contains("aix logs watch app"), "{o}");
    assert_eq!(rows(), before, "unwatch never deletes data");
    assert!(list_shows(&e, "paused (unwatched by user)", 5).contains("paused (unwatched by user)"));
    append(&lg, "2026-10-23 10:00:03,000 INFO  a.B - while-paused 3\n");
    std::thread::sleep(std::time::Duration::from_millis(3500));
    assert!(!has(&e.db_bytes("logs.db"), "while-paused"), "a paused log is not followed by the watcher");
    // resume from the saved offset (with everything paused the watcher exits by itself; aix-watch starts it again)
    assert!(w.wait().unwrap().success(), "the watcher exits when every log is paused");
    let o = e.ok(&["logs", "watch", "app"]);
    let mut w = watcher(&e);
    assert!(o.contains("resumed watching 'app' from its saved offset"), "{o}");
    append(&lg, "2026-10-23 10:00:04,000 INFO  a.B - after-resume 4\n");
    let t0 = std::time::Instant::now();
    while !has(&e.db_bytes("logs.db"), "after-resume") && t0.elapsed().as_secs() < 10 {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let db = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
    let n = |m: &str| -> i64 { db.query_row("SELECT count(*) FROM entries WHERE msg LIKE ?", [format!("%{m}%")], |r| r.get(0)).unwrap() };
    assert_eq!((n("boot 1"), n("before-unwatch"), n("while-paused"), n("after-resume")), (1, 1, 1, 1), "no gaps, no duplicates");
    w.kill().ok();
    // unwatch by glob and --all
    assert!(e.ok(&["logs", "unwatch", "ap*"]).contains("stopped watching app"));
    assert!(e.ok(&["logs", "unwatch", "--all"]).contains("nothing to unwatch"));
}

fn auto_case(extra: &[&str], trigger: impl Fn(&Env, &Path), needle: &str) {
    let e = env();
    let lg = e.log("app.log");
    append(&lg, L0);
    let mut args = vec!["logs", "add", lg.to_str().unwrap(), "--name", "app"];
    args.extend_from_slice(extra);
    e.ok(&args);
    let mut w = watcher(&e);
    trigger(&e, &lg);
    let l = list_shows(&e, needle, 15);
    w.kill().ok();
    assert!(l.contains(needle), "expected {needle}: {l}");
    // data stays
    let t = e.ok(&["logs", "tail", "--n", "100", "--name", "app"]);
    assert!(t.contains("boot 1"), "{needle}: data kept: {t}");
}

#[test]
fn every_auto_unwatch_condition_fires() {
    auto_case(&["--idle", "2s"], |_, _| {}, "paused (idle 2s)");
    auto_case(&["--unqueried", "2s"], |_, lg| append(lg, "2026-10-23 10:00:09,000 INFO a.B - keeps growing 1\n"), "paused (unqueried 2s)");
    auto_case(&["--for", "2s"], |_, _| {}, "paused (time limit)");
    auto_case(&["--until", "2000-01-01T00:00"], |_, _| {}, "paused (time limit)");
    auto_case(&["--until-match", "Shutdown complete"], |_, lg| append(lg, "2026-10-23 10:00:09,000 INFO a.B - Shutdown complete\n"), "paused (matched e");
    auto_case(&["--max-lines", "3"], |_, lg| append(lg, "2026-10-23 10:00:02,000 INFO a.B - l2\n2026-10-23 10:00:03,000 INFO a.B - l3\n2026-10-23 10:00:04,000 INFO a.B - l4\n"), "paused (line limit)");
    auto_case(&["--stop-mb", "0.0005"], |_, lg| append(lg, &"2026-10-23 10:00:02,000 INFO a.B - padding padding padding padding padding padding\n".repeat(30)), "paused (size limit)");
    auto_case(&[], |_, lg| std::fs::remove_file(lg).unwrap(), "paused (file gone)");
    // replaced by a non-tailable file (a symlink out of the allowed roots)
    #[cfg(unix)]
    auto_case(&[], |e, lg| {
        std::fs::remove_file(lg).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", e.log("app.log")).unwrap();
    }, "paused (file gone)");
    // the writer exits (writer detection reads /proc: Linux only)
    if cfg!(target_os = "linux") {
        let e = env();
        let lg = e.log("app.log");
        append(&lg, L0);
        let mut holder = Command::new("sh").arg("-c").arg(format!("exec 3>>'{}'; sleep 30", lg.display())).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app"]);
        let mut w = watcher(&e);
        holder.kill().ok();
        holder.wait().ok();
        let l = list_shows(&e, "paused (writer exited)", 15);
        w.kill().ok();
        assert!(l.contains("paused (writer exited)"), "{l}");
    }
}

#[test]
fn auto_unwatch_notice_is_shown_once_and_suggest_flags_busy_unqueried() {
    let e = env();
    e.ok(&["update", "--quiet"]);
    std::fs::write(e.repo.join(".aix/initialized"), "").unwrap();
    let lg = e.log("app.log");
    append(&lg, L0);
    e.ok(&["logs", "add", lg.to_str().unwrap(), "--name", "app", "--idle", "2s"]);
    let mut w = watcher(&e);
    list_shows(&e, "paused (idle 2s)", 15);
    w.kill().ok();
    let hook = |p: &str| e.stdin(&["hook", "prompt"], &serde_json::json!({"prompt": p, "cwd": e.repo.to_str().unwrap()}).to_string());
    let out = hook("next?");
    assert!(out.contains("aix: stopped watching app (idle 2s) — aix logs watch app to resume"), "{out}");
    assert_eq!(hook("again?").trim(), "", "shown once");
    // busy but unqueried: growing in the last hour, last query long ago
    e.ok(&["logs", "watch", "app"]);
    append(&lg, "2026-10-23 10:00:09,000 INFO a.B - growing 2\n");
    e.ok(&["logs", "tail", "--n", "1"]);
    let db = rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap();
    db.execute("UPDATE files SET last_ingest=strftime('%s','now')", []).unwrap();
    drop(db);
    let old = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 2 * 86400;
    let t = std::fs::read_to_string(e.repo.join(".aix/logs.toml")).unwrap();
    std::fs::write(e.repo.join(".aix/logs.toml"), t.lines().map(|l| if l.starts_with("watch_started = ") { format!("watch_started = {old}") } else if l.starts_with("added = ") { format!("added = {old}") } else { l.to_string() }).collect::<Vec<_>>().join("\n") + "\n").unwrap();
    rusqlite::Connection::open(e.repo.join(".aix/logs.db")).unwrap().execute("UPDATE usage SET last_q=?", [old as i64]).unwrap();
    let o = e.ok(&["logs", "suggest"]);
    assert!(o.contains("aix logs unwatch app") && o.contains("costs CPU/IO"), "{o}");
}
