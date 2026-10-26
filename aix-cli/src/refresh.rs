//! `aix refresh`: scripts/aix-refresh.sh in Rust, so it also runs where bash cannot (Windows). The one way to update
//! an index from a hook, the watcher or cron: a locked, logged, low-priority `aix update`, then optionally
//! deadline-bound embedding and local-LLM summaries. Same lock files (`<lock dir>/<key>.{refresh,embed,log}.lock`) and
//! log (`<db dir>/refresh.log`, the last 500 lines) as the script, so the two never run an update side by side.
//! Also the helpers `aix watch` and `aix init` share: the repo root of a path, the checked lock dir, the child `aix`.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Opts {
    pub full: bool,
    pub embed: f64,
    pub summaries: f64,
    pub backfill: bool,
    pub wait: f64,
    pub strict: bool,
    pub accept_ignore: bool,
}

/// `git rev-parse --show-toplevel` of `dir`.
pub fn toplevel(dir: &Path) -> Option<PathBuf> {
    let o = Command::new("git").arg("-C").arg(dir).args(["rev-parse", "--show-toplevel"]).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    let t = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !t.is_empty()).then(|| aix_core::sys::canonicalize(&t).unwrap_or_else(|_| PathBuf::from(t)))
}

/// The repo REPO (or the cwd) names: its git toplevel, else (`need_git` false) the directory itself.
/// Err((exit code, message)) when it is no repo, or a subdirectory of one: acting on the enclosing repo without
/// saying so is refused, as the scripts do.
pub fn root_of(arg: Option<&Path>, name: &str, need_git: bool) -> Result<PathBuf, (i32, String)> {
    let here = match arg {
        Some(a) => a.to_path_buf(),
        None => std::env::current_dir().map_err(|e| (2, format!("aix {name}: {e}")))?,
    };
    let shown = arg.map_or_else(|| "the current directory".to_string(), |a| a.display().to_string());
    let canon = aix_core::sys::canonicalize(&here).map_err(|_| (2, format!("aix {name}: no such directory: {shown}")))?;
    let root = match toplevel(&canon) {
        Some(t) => t,
        None if need_git => return Err((2, format!("aix {name}: not a git repository: {shown}"))),
        None => canon.clone(),
    };
    if !aix_core::sys::same_path(&canon, &root) {
        return Err((2, format!("aix {name}: {shown} is inside the git repo {}, not its root: run aix {name} {}", root.display(), root.display())));
    }
    Ok(root)
}

/// The shared lock directory (AIX_LOCK_DIR, else /tmp/aix-locks-UID or %TEMP%\aix-locks), created owner-only;
/// None when it is unsafe (a symlink, or not ours).
pub fn lock_dir() -> Option<PathBuf> {
    let d = aix_core::logs::lock_dir();
    let _ = aix_core::sys::private_dir(std::fs::DirBuilder::new().recursive(true)).create(&d);
    let md = std::fs::symlink_metadata(&d).ok()?;
    (md.is_dir() && !md.file_type().is_symlink() && aix_core::sys::owned_by_me(&md)).then_some(d)
}

/// `<lock dir>/<key of db>.<name>.lock`, opened (not locked).
pub fn lock_file(ld: &Path, db: &Path, name: &str) -> std::io::Result<File> {
    aix_core::sys::private_file(std::fs::OpenOptions::new().create(true).truncate(false).write(true)).open(ld.join(format!("{}.{name}.lock", aix_core::logs::sha_key(db))))
}

/// Take `f`'s lock, waiting up to `secs`.
pub fn lock_wait(f: &File, secs: f64) -> bool {
    let until = Instant::now() + Duration::from_secs_f64(secs.max(0.0));
    loop {
        if f.try_lock().is_ok() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// This binary, for children and hook registrations, and after an upgrade replaced it under a running watcher, the
/// new one: Linux /proc/self/exe then ends in " (deleted)"; Windows install.ps1 renamed the running aix.exe aside to
/// `.aix.exe.old-N`.
pub fn self_exe() -> PathBuf {
    let Ok(p) = std::env::current_exe() else { return PathBuf::from("aix") };
    if let Some(live) = p.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        return PathBuf::from(live);
    }
    if p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".aix.exe.old-")) {
        return p.with_file_name("aix.exe");
    }
    p
}

/// This aix binary for `repo`/`db`, low priority (niced, AIX_LOW=1: fewer threads, smaller batches), no console
/// window, stdin closed.
pub fn aix(repo: &Path, db: &Path) -> Command {
    let mut c = Command::new(self_exe());
    c.arg("--repo").arg(repo).arg("--db").arg(db).env("AIX_LOW", "1").stdin(Stdio::null());
    aix_core::sys::background(&mut c, true);
    c
}

/// Run `c` to the end: (exit code, stdout then stderr, CRLF as LF, trailing newlines dropped).
pub fn output(mut c: Command) -> (i32, String) {
    match c.stdout(Stdio::piped()).stderr(Stdio::piped()).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.code().unwrap_or(1), s.replace("\r\n", "\n").trim_end_matches('\n').to_string())
        }
        Err(e) => (127, e.to_string()),
    }
}

/// Entries still waiting for an embedding: 0 when no embedder is configured (nothing could fill them; the script
/// retried every minute anyway) or the index cannot be read.
pub fn pending(repo: &Path, db: &Path) -> usize {
    let Ok(ix) = aix_core::Index::open_hook(repo, db) else { return 0 };
    if ix.cfg.embed.is_none() {
        return 0;
    }
    aix_core::semantic::pending_capped(&ix, usize::MAX).unwrap_or(0)
}

/// Append one line to the refresh log under the log lock, keeping its last 500 lines once it passes 600.
fn log(ld: &Path, db: &Path, path: &Path, line: &str) {
    let Ok(l) = lock_file(ld, db, "log") else { return };
    if !lock_wait(&l, 10.0) {
        return;
    }
    if let Ok(mut f) = aix_core::sys::private_file(std::fs::OpenOptions::new().create(true).append(true)).open(path) {
        let _ = writeln!(f, "{line}");
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > 600 {
        let tmp = path.with_extension("log.tmp");
        if std::fs::write(&tmp, lines[lines.len() - 500..].join("\n") + "\n").is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn secs(s: f64) -> String {
    format!("{s}")
}

/// `aix refresh [REPO] [--full] [--embed SECS] [--summaries SECS] [--backfill] [--wait SECS] [--strict]`: the exit code.
pub fn run(arg: Option<&Path>, db: Option<&Path>, o: &Opts) -> i32 {
    let fail = |msg: &str| {
        eprintln!("aix refresh: {msg}");
        i32::from(o.strict)
    };
    let repo = match root_of(arg, "refresh", false) {
        Ok(r) => r,
        Err((2, m)) if m.contains("not its root") => {
            eprintln!("{m}");
            return 2;
        }
        Err((_, m)) => return fail(m.trim_start_matches("aix refresh: ")),
    };
    let db = aix_core::index::resolve_db(&repo, db);
    let Some(dir) = db.parent().filter(|d| std::fs::create_dir_all(d).is_ok()) else {
        return fail(&format!("cannot create {}", db.parent().unwrap_or(&db).display()));
    };
    let logp = dir.join("refresh.log");
    let _ = aix_core::sys::chmod(&logp, 0o600); // an older run may have made it group-readable
    let Some(ld) = lock_dir() else { return fail(&format!("unsafe lock dir {}", aix_core::logs::lock_dir().display())) };
    let Ok(upd) = lock_file(&ld, &db, "refresh") else { return fail("cannot open lock") };
    if !lock_wait(&upd, o.wait) {
        log(&ld, &db, &logp, &format!("{} skipped: another refresh held the lock for {}s", aix_core::local_second(now()), secs(o.wait)));
        return 0;
    }
    let t0 = Instant::now();
    let mut c = aix(&repo, &db);
    if o.accept_ignore {
        c.arg("--accept-ignore");
    }
    c.args(["update", "--quiet", "--embed-deadline", "0"]);
    if o.full {
        c.arg("--full");
    }
    let (mut rc, out) = output(c);
    if rc == 2 && out.lines().any(|l| l.starts_with("STOP: .gitignore is missing or incomplete")) {
        // the .gitignore preflight refused a first build / --full: the user decides (aix ignore-check, --accept-ignore)
        eprintln!("{out}");
        log(&ld, &db, &logp, &format!("{} refused: .gitignore findings not accepted (aix ignore-check)", aix_core::local_second(now())));
        return if o.strict || o.full { 3 } else { 0 };
    }
    // the update alone (the watcher reads its time from this note)
    let mut notes = vec![format!("update rc={rc} {}ms{}", t0.elapsed().as_millis(), if out.is_empty() { String::new() } else { format!(": {}", out.replace('\n', " | ")) })];
    drop(upd); // update done: later refreshes may start while this one embeds
    let want = rc == 0 && (o.embed > 0.0 || o.backfill || o.summaries > 0.0);
    // embedding never queues: another run embedding means this one skips it
    let emb = want.then(|| lock_file(&ld, &db, "embed").ok().filter(|f| f.try_lock().is_ok())).flatten();
    if want && emb.is_none() {
        notes.push("embed/summaries skipped: another run is embedding".into());
    }
    if emb.is_some() && o.embed > 0.0 {
        let mut c = aix(&repo, &db);
        c.args(["--no-refresh", "embed", "--deadline", &secs(o.embed)]);
        let (_, out) = output(c);
        notes.push(format!("embed: {}", out.lines().last().unwrap_or("")));
    }
    if emb.is_some() && o.backfill {
        let mut before = pending(&repo, &db);
        while before > 0 {
            let mut c = aix(&repo, &db);
            c.args(["--no-refresh", "embed", "--deadline", "300"]);
            let (r, _) = output(c);
            if r != 0 {
                rc = r;
                break;
            }
            let after = pending(&repo, &db);
            if after >= before {
                notes.push(format!("backfill stalled at {after} pending (embedder down?)"));
                break;
            }
            before = after;
        }
        notes.push(format!("backfill: {before} pending"));
    }
    if emb.is_some() && rc == 0 && o.summaries > 0.0 {
        let mut c = aix(&repo, &db);
        c.args(["--no-refresh", "summarize", "--deadline", &secs(o.summaries)]);
        let (_, out) = output(c);
        notes.push(format!("summaries: {}", out.lines().last().unwrap_or("")));
    }
    let line = format!("{} rc={rc} {}ms {}", aix_core::local_second(now()), t0.elapsed().as_millis(), notes.join("; "));
    log(&ld, &db, &logp, &line);
    println!("{line}");
    if rc != 0 {
        return fail(&format!("failed (rc={rc}), see {}", logp.display()));
    }
    0
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
