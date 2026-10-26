//! `aix init`, `aix refresh`, `aix watch` and `aix hook session-start`: the repo lifecycle the bash scripts provide on
//! Unix, in the binary on every platform. Throwaway repos, a scratch HOME, share dir and lock dir.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

struct Env {
    d: tempfile::TempDir,
    repo: PathBuf,
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"]).args(args).output().unwrap();
    assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("shop");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".gitignore"), ".aix/\n.env*\n.DS_Store\nnode_modules/\n").unwrap();
    std::fs::write(repo.join("app.py"), "def hello():\n    return 1\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    // the installed skill, commands and rules aix init copies (install.sh / install.ps1 put them there)
    let share = d.path().join("share/aix/claude-code");
    for sub in ["skills/aix/reference", "commands", "rules"] {
        std::fs::create_dir_all(share.join(sub)).unwrap();
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../integrations/claude-code");
    for f in ["skills/aix/SKILL.md", "skills/aix/reference/rules.md", "commands/brief.md", "commands/bugs.md", "commands/impact.md", "rules/aix.md"] {
        std::fs::copy(src.join(f), share.join(f)).unwrap();
    }
    Env { d, repo }
}

impl Env {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.current_dir(&self.repo)
            .args(args)
            .env("HOME", self.d.path().join("home"))
            .env("XDG_DATA_HOME", self.d.path().join("share"))
            .env("AIX_LOCK_DIR", self.d.path().join("locks"))
            .env("AIX_EMBED_URL", "")
            .env_remove("AIX_DB")
            .stdin(Stdio::null());
        c
    }
    fn run(&self, args: &[&str]) -> (i32, String) {
        let o = self.cmd(args).output().unwrap();
        (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
    }
    fn settings(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.repo.join(".claude/settings.local.json")).unwrap()).unwrap()
    }
    /// Symbols named `name` in the index, read straight from the database (no refresh).
    fn symbols(&self, name: &str) -> i64 {
        rusqlite::Connection::open(self.repo.join(".aix/index.db")).ok().and_then(|c| c.query_row("SELECT count(*) FROM symbols WHERE name=?", [name], |r| r.get(0)).ok()).unwrap_or(0)
    }
}

/// Every (event, command, args) of our hooks in a settings object.
fn ours(s: &Value) -> Vec<(String, String)> {
    let mut v = vec![];
    for (ev, groups) in s["hooks"].as_object().unwrap() {
        for g in groups.as_array().unwrap() {
            for h in g["hooks"].as_array().unwrap() {
                if h["args"].is_array() {
                    v.push((ev.clone(), h["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect::<Vec<_>>().join(" ")));
                }
            }
        }
    }
    v.sort();
    v
}

#[test]
fn init_merges_settings_and_uninstall_restores_them() {
    let e = env();
    std::fs::create_dir_all(e.repo.join(".claude")).unwrap();
    let mine = "{\n  \"env\": {\"X\": \"1\"},\n  \"hooks\": {\"PreToolUse\": [{\"matcher\": \"Bash\", \"hooks\": [{\"type\": \"command\", \"command\": \"/opt/mine/lint.sh\"}]}]},\n  \"permissions\": {\"allow\": [\"Bash(npm test:*)\"]}\n}\n";
    std::fs::write(e.repo.join(".claude/settings.local.json"), mine).unwrap();
    let (rc, out) = e.run(&["init", "--no-watch", "--no-git-hook"]);
    assert_eq!(rc, 0, "{out}");
    let s = e.settings();
    // the user's keys, hook and rule stay, in their order; ours are exec form
    assert_eq!(s.as_object().unwrap().keys().collect::<Vec<_>>(), ["env", "hooks", "permissions"]);
    assert!(s["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "/opt/mine/lint.sh", "{s}");
    assert_eq!(ours(&s), [("PreToolUse".into(), "hook pretool".into()), ("SessionStart".into(), "hook session-start".into()), ("UserPromptSubmit".into(), "hook prompt".into())]);
    let exe = s["hooks"]["SessionStart"][0]["hooks"][0]["command"].as_str().unwrap().to_string();
    assert!(Path::new(&exe).is_file(), "the hook runs this binary: {exe}");
    let allow: Vec<&str> = s["permissions"]["allow"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
    assert_eq!(allow[0], "Bash(npm test:*)");
    assert!(allow.contains(&"Bash(aix brief:*)") && allow.contains(&"Bash(aix privacy-check)") && !allow.contains(&"Bash(aix:*)") && !allow.contains(&"Bash(aix put:*)"), "{allow:?}");
    assert_eq!(allow.contains(&"PowerShell(aix brief:*)"), cfg!(windows), "PowerShell rules on Windows only");
    for f in [".claude/skills/aix/SKILL.md", ".claude/commands/brief.md", ".claude/rules/aix.md", ".aix/initialized", ".aix/index.db"] {
        assert!(e.repo.join(f).exists(), "{f}: {out}");
    }
    // idempotent: a second run changes nothing it already did
    let (rc, out) = e.run(&["init", "--no-watch", "--no-git-hook"]);
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("already current"), "{out}");
    assert_eq!(e.settings(), s);
    // --allow-data adds exactly the data-set rules; --uninstall takes back everything aix added
    let (rc, out) = e.run(&["init", "--no-watch", "--no-git-hook", "--allow-data"]);
    assert!(rc == 0 && e.settings()["permissions"]["allow"].as_array().unwrap().iter().any(|r| r == "Bash(aix put:*)"), "{out}");
    let (rc, out) = e.run(&["init", "--uninstall"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(std::fs::read_to_string(e.repo.join(".claude/settings.local.json")).unwrap(), mine, "the original bytes come back");
    assert!(!e.repo.join(".aix").exists() && !e.repo.join(".claude/skills").exists() && !e.repo.join(".claude/rules").exists(), "{out}");
}

#[test]
fn init_refuses_a_subdirectory_and_unparseable_settings() {
    let e = env();
    std::fs::create_dir_all(e.repo.join("sub")).unwrap();
    let (rc, out) = e.run(&["init", "sub"]);
    assert!(rc == 2 && out.contains("not its root") && !e.repo.join(".aix").exists(), "{out}");
    std::fs::create_dir_all(e.repo.join(".claude")).unwrap();
    std::fs::write(e.repo.join(".claude/settings.local.json"), "{ // a comment\n}\n").unwrap();
    let (rc, out) = e.run(&["init", "--no-watch", "--no-git-hook"]);
    assert!(rc == 1 && out.contains("not plain JSON") && out.contains("nothing was changed") && !e.repo.join(".aix").exists(), "{out}");
}

#[test]
fn refresh_logs_its_run_and_skips_behind_a_held_lock() {
    let e = env();
    let (rc, out) = e.run(&["refresh"]);
    assert!(rc == 0 && out.contains(" rc=0 ") && out.contains("update rc=0"), "{out}");
    let log = std::fs::read_to_string(e.repo.join(".aix/refresh.log")).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert_eq!(e.symbols("hello"), 1);
    // the same lock file aix-refresh.sh takes (keyed by the db path): held, the run skips and says so
    let locks = e.d.path().join("locks");
    let key = aix_core::logs::sha_key(&e.repo.join(".aix/index.db"));
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(locks.join(format!("{key}.refresh.lock"))).unwrap();
    f.try_lock().unwrap();
    let (rc, out) = e.run(&["refresh", "--wait", "0"]);
    assert_eq!(rc, 0, "{out}");
    let log = std::fs::read_to_string(e.repo.join(".aix/refresh.log")).unwrap();
    assert!(log.lines().last().unwrap().contains("skipped: another refresh held the lock"), "{log}");
    drop(f);
    // --strict: a failure is an exit code (here: no repo at that path)
    let (rc, _) = e.run(&["refresh", "--strict", e.d.path().join("nowhere").to_str().unwrap()]);
    assert_eq!(rc, 1);
}

#[test]
fn watch_refreshes_after_edits_go_quiet_and_stop_ends_it() {
    let e = env();
    e.run(&["refresh"]);
    let (rc, out) = e.run(&["watch", "--stop"]);
    assert!(rc == 1 && out.contains("no watcher running"), "{out}");
    // --once: refresh only when something changed since the last refresh
    std::fs::write(e.repo.join("app.py"), "def hello():\n    return 1\n\ndef once_added():\n    return 2\n").unwrap();
    let (rc, out) = e.run(&["watch", "--once"]);
    assert!(rc == 0 && e.symbols("once_added") == 1, "{out}");
    // a registered log: the watcher runs an `aix logs watch` child, which --stop ends with it
    std::fs::write(e.repo.join("app.log"), "2026-10-23 10:00:00,000 ERROR [t] a.B - boom\n").unwrap();
    let (rc, out) = e.run(&["logs", "add", "app.log", "--name", "app"]);
    assert_eq!(rc, 0, "{out}");
    let mut w = e.cmd(&["watch", "--poll", "0.2", "--idle", "0.3", "--exit-after", "60", "--backlog", "0"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let pidfile = |e: &Env| std::fs::read_dir(e.d.path().join("locks")).ok().into_iter().flatten().flatten().any(|f| f.file_name().to_string_lossy().ends_with(".watch.pid"));
    let t = Instant::now();
    while !pidfile(&e) && t.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(pidfile(&e), "the watcher records its pid");
    // a second watcher for the same index exits at once
    let (rc, _) = e.run(&["watch", "--exit-after", "60"]);
    assert_eq!(rc, 0);
    std::fs::write(e.repo.join("app.py"), "def hello():\n    return 1\n\ndef watched_added():\n    return 3\n").unwrap();
    let t = Instant::now();
    while e.symbols("watched_added") == 0 && t.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(e.symbols("watched_added"), 1, "the watcher indexed the edit without any query");
    let key = aix_core::logs::sha_key(&e.repo.join(".aix/index.db"));
    let logs_pid = e.d.path().join("locks").join(format!("{key}.watch.logs.pid"));
    let t = Instant::now();
    while !logs_pid.exists() && t.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let child: i64 = std::fs::read_to_string(&logs_pid).unwrap().split_whitespace().next().unwrap().parse().unwrap();
    assert!(aix_core::sys::pid_alive(child));
    let (rc, out) = e.run(&["watch", "--stop"]);
    assert!(rc == 0 && out.contains("stopped"), "{out}");
    assert!(!aix_core::sys::pid_alive(child), "the logs child ended with the watcher");
    let t = Instant::now();
    while w.try_wait().unwrap().is_none() && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(w.try_wait().unwrap().is_some(), "the watcher ended");
}

#[test]
fn session_start_prints_the_card_only_where_aix_init_ran() {
    let e = env();
    let (rc, out) = e.run(&["hook", "session-start"]);
    assert!(rc == 0 && out.contains("run `aix init` here") && !e.repo.join(".aix/index.db").exists(), "{out}");
    let (rc, out) = e.run(&["init", "--no-watch", "--no-git-hook"]);
    assert_eq!(rc, 0, "{out}");
    let (rc, out) = e.run(&["hook", "session-start"]);
    assert!(rc == 0 && out.contains("aix index shop:"), "{out}");
    // it started a watcher in the background: stop it once it is up (its pidfile written)
    let t = Instant::now();
    while e.run(&["watch", "--stop"]).0 != 0 && t.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(t.elapsed() < Duration::from_secs(20), "the session-start watcher was never seen");
}
