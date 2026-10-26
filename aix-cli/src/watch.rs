//! `aix watch`: scripts/aix-watch.sh in Rust, so the auto-refresh also runs where bash cannot (Windows). Once files
//! changed and then stayed untouched for a quiet time, it runs `aix refresh --embed N`, so the index and its embeddings
//! catch up without anyone asking. Quiet time (ms): adaptive, the 25th percentile of the recent gaps between edits +
//! 500, kept within 2500..10500 (3500 until 5 gaps are seen); 10500 when a change touches more than 200 files; never
//! more than 30500 after the first pending change. Slow storage (network or removable drive, measured slow updates or
//! polls) gets about twice that. Polls `git status` + the mtimes of dirty files every 0.5 s while changes are pending
//! and every --poll seconds (default 2) otherwise. One watcher per index (`<lock dir>/<key>.watch.lock`, the script's
//! lock, so a bash and a Rust watcher exclude each other); pid and start time in `<key>.watch.pid` for --stop. Exits
//! after --exit-after seconds without a change (default 4 h; 0 = never) or when the repo is gone.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::refresh;

pub struct Opts {
    pub idle: Option<f64>,
    pub poll: Option<f64>,
    pub exit_after: f64,
    pub embed: f64,
    pub backlog: f64,
    pub storage: String,
    pub storage_check: bool,
    pub once: bool,
    pub stop: bool,
}

fn git(repo: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let o = Command::new("git").arg("-C").arg(repo).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    o.status.success().then_some(o.stdout)
}

/// Change signature: HEAD + the dirty/untracked paths (`git status -z`, exact for odd names and renames) + their
/// full-precision mtimes and sizes (repeated edits of a dirty file count). Above AIX_WATCH_BIG (20000) changed paths
/// one hash of `git ls-files -m -o` replaces the stat pass. None when the repo is gone.
fn sig(repo: &Path) -> Option<String> {
    if !repo.is_dir() {
        return None;
    }
    let mut h = sha1_smol::Sha1::new();
    h.update(&git(repo, &["rev-parse", "HEAD"]).unwrap_or_default());
    let status = git(repo, &["status", "--porcelain=v1", "-z", "-uall", "--ignore-submodules"]).unwrap_or_default();
    let mut paths: Vec<String> = vec![];
    let mut skip = false;
    for rec in status.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let rec = String::from_utf8_lossy(rec);
        if skip {
            // the other half of a rename/copy
            skip = false;
            h.update(format!("old:{rec}\0").as_bytes());
            continue;
        }
        let (xy, p) = (rec.get(..2).unwrap_or(""), rec.get(3..).unwrap_or(""));
        skip = xy.contains(['R', 'C']);
        if format!("/{p}").contains("/.aix/") {
            continue;
        }
        h.update(format!("{rec}\0").as_bytes());
        paths.push(p.to_string());
    }
    let big = std::env::var("AIX_WATCH_BIG").ok().and_then(|v| v.parse().ok()).unwrap_or(20000);
    if paths.len() > big {
        h.update(&git(repo, &["ls-files", "-m", "-o", "--exclude-standard", "-z"]).unwrap_or_default());
    } else {
        for p in paths {
            if let Ok(m) = std::fs::metadata(repo.join(&p)) {
                h.update(format!("{p} {} {} {}\0", aix_core::sys::mtime(&m), aix_core::sys::mtime_nsec(&m), m.len()).as_bytes());
            }
        }
    }
    Some(h.digest().to_string())
}

fn changed_count(repo: &Path) -> usize {
    git(repo, &["status", "--porcelain", "-z", "--untracked-files=normal"]).map_or(0, |o| o.iter().filter(|b| **b == 0).count())
}

/// Is `pid` (recorded with start time `start`) a live watcher: this binary's `watch`, or aix-watch.sh?
fn is_watcher(pid: i64, start: &str) -> bool {
    if pid == i64::from(std::process::id()) || !aix_core::sys::pid_alive(pid) {
        return false;
    }
    if aix_core::sys::proc_start(pid).is_some_and(|s| s.to_string() != start) {
        return false; // the pid was reused
    }
    #[cfg(target_os = "linux")]
    {
        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let args: Vec<String> = cmd.split(|b| *b == 0).map(|a| String::from_utf8_lossy(a).rsplit('/').next().unwrap_or("").to_string()).collect();
        args.iter().any(|a| a == "aix-watch" || a == "aix-watch.sh") || args.first().is_some_and(|a| a == "aix") && args.iter().any(|a| a == "watch")
    }
    #[cfg(not(target_os = "linux"))]
    {
        // install.ps1 renames a running aix.exe aside to .aix.exe.old-N: the image keeps that name
        aix_core::sys::proc_exe_name(pid).is_none_or(|n| n.eq_ignore_ascii_case("aix.exe") || n == "aix" || n.starts_with(".aix.exe.old-"))
    }
}

fn pidfile(ld: &Path, db: &Path) -> PathBuf {
    ld.join(format!("{}.watch.pid", aix_core::logs::sha_key(db)))
}

/// The watcher's `aix logs watch` child: a stopped (killed) watcher runs no cleanup, so --stop ends the child too.
fn logs_pidfile(ld: &Path, db: &Path) -> PathBuf {
    ld.join(format!("{}.watch.logs.pid", aix_core::logs::sha_key(db)))
}

fn record_pid(p: &Path, pid: i64) {
    let _ = std::fs::write(p, format!("{pid} {}\n", aix_core::sys::proc_start(pid).map(|s| s.to_string()).unwrap_or_default()));
}

/// Stop the process a pidfile names when it checks out (pid + start time + command), waiting up to 2 s for it to end.
/// A live process that does not check out keeps its pidfile (deleting it would make a watcher unstoppable).
fn stop_recorded(pf: &Path) -> Option<i64> {
    let t = std::fs::read_to_string(pf).ok()?;
    let mut it = t.split_whitespace();
    let pid: i64 = it.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let stopped = is_watcher(pid, it.next().unwrap_or("")) && aix_core::sys::terminate(pid);
    for _ in 0..10 {
        if !stopped || !aix_core::sys::pid_alive(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if !aix_core::sys::pid_alive(pid) {
        let _ = std::fs::remove_file(pf);
    }
    stopped.then_some(pid)
}

/// Stop this repo's watcher(s), found by pidfile (never a pattern kill), and their `aix logs watch` children. The
/// stopped watchers' pids.
pub fn stop(repo: &Path, db: &Path) -> Vec<i64> {
    let Some(ld) = refresh::lock_dir() else { return vec![] };
    let mut dbs = vec![db.to_path_buf(), aix_core::index::default_db(repo)];
    dbs.dedup();
    let mut out = vec![];
    for d in dbs {
        out.extend(stop_recorded(&pidfile(&ld, &d)));
        stop_recorded(&logs_pidfile(&ld, &d));
    }
    out
}

/// Start `aix watch` for `repo` in the background (detached; a second one exits at once).
pub fn spawn(repo: &Path, db: Option<&Path>) -> bool {
    let mut c = Command::new(crate::refresh::self_exe());
    c.arg("--repo").arg(repo);
    if let Some(d) = db {
        c.arg("--db").arg(d);
    }
    c.arg("watch").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    detached(&mut c);
    c.spawn().is_ok()
}

/// Detach `c` and start it outside the repo: on Windows a process's working directory cannot be deleted or renamed,
/// so a watcher started in the repo would pin it for hours (every path it uses is absolute).
pub fn detached(c: &mut Command) {
    c.current_dir(std::env::temp_dir());
    aix_core::sys::detach(c);
}

/// Timings of one storage class.
struct Class {
    slow: bool,
    min_q: u64,
    max_q: u64,
    big_q: u64,
    cap: u64,
    start_q: u64,
    poll: f64,
    pend_poll: f64,
}

fn class(slow: bool, user_poll: Option<f64>) -> Class {
    if slow {
        Class { slow, min_q: 5000, max_q: 20500, big_q: 30500, cap: 60500, start_q: 7000, poll: user_poll.unwrap_or(5.0), pend_poll: 1.5 }
    } else {
        Class { slow, min_q: 2500, max_q: 10500, big_q: 10500, cap: 30500, start_q: 3500, poll: user_poll.unwrap_or(2.0), pend_poll: 0.5 }
    }
}

fn median(v: &[u64]) -> u64 {
    let mut s = v.to_vec();
    s.sort_unstable();
    s.get(s.len().saturating_sub(1) / 2).copied().unwrap_or(0)
}

/// Registered logs that are not paused (`.aix/logs.toml`): the `aix logs watch` child is needed.
fn logs_registered(dir: &Path) -> bool {
    let t = std::fs::read_to_string(dir.join("logs.toml")).unwrap_or_default();
    t.lines().filter(|l| l.starts_with("[[log]]")).count() > t.lines().filter(|l| l.starts_with("paused = true")).count()
}

/// Kills the `aix logs watch` child when the watcher ends normally (a killed watcher's child is ended by --stop, from
/// the child's pidfile).
struct LogsChild(Option<Child>, PathBuf);
impl Drop for LogsChild {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = std::fs::remove_file(&self.1);
        }
    }
}

/// Removes the pidfile on a normal exit.
struct PidFile(Option<PathBuf>);
impl Drop for PidFile {
    fn drop(&mut self) {
        if let Some(p) = &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `aix watch [REPO] [--idle S] [--poll S] [--exit-after S] [--embed S] [--backlog S] [--storage auto|fast|slow]
/// [--storage-check] [--once] [--stop]`: the exit code.
pub fn run(arg: Option<&Path>, db: Option<&Path>, o: &Opts) -> i32 {
    // --stop looks the repo up from a subdirectory too; an explicit path that is no repo is a usage error, the cwd
    // form stays quiet (hooks start it freely)
    let repo = if o.stop {
        match refresh::toplevel(&arg.map_or_else(|| std::env::current_dir().unwrap_or_default(), Path::to_path_buf)) {
            Some(r) => r,
            None => {
                eprintln!("aix watch: not a git repo: {}", arg.map_or_else(|| "the current directory".into(), |a| a.display().to_string()));
                return if arg.is_some() { 2 } else { 0 };
            }
        }
    } else {
        match refresh::root_of(arg, "watch", true) {
            Ok(r) => r,
            Err((c, m)) => {
                eprintln!("{m}");
                return if arg.is_some() || m.contains("not its root") { c } else { 0 };
            }
        }
    };
    let (slow0, reason0) = aix_core::sys::storage_class(&repo);
    if o.storage_check {
        println!("{} {reason0}", if slow0 { "slow" } else { "fast" });
        return 0;
    }
    let db = aix_core::index::resolve_db(&repo, db);
    if o.stop {
        let s = stop(&repo, &db);
        if s.is_empty() {
            eprintln!("aix watch: no watcher running for {}", repo.display());
            return 1;
        }
        for p in s {
            println!("aix watch: stopped {p}");
        }
        return 0;
    }
    let Some(ld) = refresh::lock_dir() else {
        eprintln!("aix watch: unsafe lock dir {}", aix_core::logs::lock_dir().display());
        return 0;
    };
    let Some(dir) = db.parent().filter(|d| std::fs::create_dir_all(d).is_ok()).map(Path::to_path_buf) else { return 0 };
    let stamp = PathBuf::from(format!("{}.watch.sig", db.display()));
    let Ok(lock) = refresh::lock_file(&ld, &db, "watch") else { return 0 };
    if lock.try_lock().is_err() {
        return 0; // another watcher already covers this index
    }
    let _pid = PidFile((!o.once).then(|| {
        let p = pidfile(&ld, &db);
        record_pid(&p, i64::from(std::process::id()));
        p
    }));
    aix_core::sys::nice(5);
    let mut upd: Vec<u64> = vec![]; // the last 10 index update times (ms), from the refresh line
    let do_refresh = |embed: f64, wait: &str, upd: &mut Vec<u64>| {
        let mut c = refresh::aix(&repo, &db);
        c.arg("refresh").arg(&repo).args(["--embed", &format!("{embed}"), "--wait", wait]);
        let (_, line) = refresh::output(c);
        static UPD: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"update rc=0 (\d+)ms").unwrap());
        if let Some(ms) = UPD.captures_iter(&line).last().and_then(|m| m[1].parse().ok()) {
            upd.push(ms);
            if upd.len() > 10 {
                upd.remove(0);
            }
        }
        if let Some(s) = sig(&repo) {
            let _ = std::fs::write(&stamp, s);
        }
    };
    let last_stamp = || std::fs::read_to_string(&stamp).unwrap_or_default();
    let cur = sig(&repo).unwrap_or_default();
    if cur != last_stamp() {
        do_refresh(o.embed, "30", &mut upd); // catch up on edits made while no watcher ran
    }
    if o.once {
        return 0;
    }
    let set_class = |slow: bool, why: &str| {
        let _ = std::fs::write(format!("{}.watch.storage", db.display()), format!("{} {} {why}\n", aix_core::local_second(refresh::now()), if slow { "slow" } else { "fast" }));
        class(slow, o.poll)
    };
    let auto = o.storage == "auto";
    let mut cl = match o.storage.as_str() {
        "slow" => set_class(true, "set by --storage"),
        "fast" => set_class(false, "set by --storage"),
        _ => set_class(slow0, &reason0),
    };
    let mut logs = LogsChild(None, logs_pidfile(&ld, &db));
    let t0 = Instant::now();
    let ms = || t0.elapsed().as_millis() as u64;
    let mut gaps: Vec<u64> = vec![];
    let mut polls: Vec<u64> = vec![];
    // start from the signature the last refresh recorded: an edit made while the watcher started still counts
    let mut last = last_stamp();
    let (mut changed_at, mut first_change, mut last_change, mut pending_files, mut bad) = (0u64, 0u64, 0u64, 0usize, 0);
    let mut quiet_since = ms();
    let mut backlog_at = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs_f64(if changed_at != 0 { cl.pend_poll } else { cl.poll }));
        // registered logs: one `aix logs watch` child, restarted if it died
        if logs_registered(&dir) && !logs.0.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None))) {
            let mut c = refresh::aix(&repo, &db);
            c.args(["--no-refresh", "logs", "watch", "--exit-after", &format!("{}", o.exit_after)]).stdout(Stdio::null()).stderr(Stdio::null());
            logs.0 = c.spawn().ok();
            if let Some(ch) = &logs.0 {
                record_pid(&logs.1, i64::from(ch.id()));
            }
        }
        // repo moved/deleted (or no longer a git repo): give up after 5 failed checks in a row
        if !repo.is_dir() || git(&repo, &["rev-parse", "--git-dir"]).is_none() {
            bad += 1;
            if bad >= 5 {
                return 0;
            }
            continue;
        }
        bad = 0;
        let now = ms();
        let s = sig(&repo).unwrap_or_default();
        polls.push(ms() - now);
        if polls.len() > 20 {
            polls.remove(0);
        }
        if s != last {
            last = s;
            if last_change != 0 && now - last_change <= 600_000 {
                gaps.push(now - last_change);
                if gaps.len() > 20 {
                    gaps.remove(0);
                }
            }
            last_change = now;
            changed_at = now;
            if first_change == 0 {
                first_change = now;
            }
            pending_files = changed_count(&repo);
            quiet_since = now;
            continue;
        }
        let quiet = match o.idle {
            Some(i) => (i * 1000.0) as u64,
            None if pending_files > 200 => cl.big_q,
            None if gaps.len() < 5 => cl.start_q,
            None => {
                let mut g = gaps.clone();
                g.sort_unstable();
                (g[(g.len() - 1) / 4] + 500).clamp(cl.min_q, cl.max_q)
            }
        };
        if changed_at != 0 && (now - changed_at >= quiet || now - first_change >= cl.cap) {
            do_refresh(o.embed, "30", &mut upd);
            // auto: switch on what refreshes and polls actually cost
            if auto && upd.len() >= 5 && polls.len() >= 5 {
                let (u, p) = (median(&upd), median(&polls));
                if !cl.slow && (u > 1500 || p > 200) {
                    cl = set_class(true, &format!("measured: median update {u} ms, poll {p} ms"));
                } else if cl.slow && u < 750 && p < 100 {
                    cl = set_class(false, &format!("measured: median update {u} ms, poll {p} ms"));
                }
            }
            (changed_at, first_change) = (0, 0);
            quiet_since = ms();
        } else if changed_at == 0 && o.backlog > 0.0 && now - backlog_at >= (o.backlog * 1000.0) as u64 {
            backlog_at = now;
            if refresh::pending(&repo, &db) > 0 {
                do_refresh(o.embed, "0", &mut upd);
            }
        }
        if o.exit_after > 0.0 && changed_at == 0 && ms() - quiet_since >= (o.exit_after * 1000.0) as u64 {
            return 0;
        }
    }
}
