//! The incremental engine: open the DB, detect changed files (stat, then blake3), re-extract only those,
//! refresh git history when HEAD moves, and rebuild the small cross-file layer (role names, page files,
//! the feature catalogue, derived search entries).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use aix_extract::{self as sx, Extractor, Rows, SourceFile};

use crate::config::Config;
use crate::entries;
use crate::schema::{FILE_TABLES, SCHEMA, SCHEMA_VERSION};
use crate::walk;

pub struct Index {
    pub conn: Connection,
    pub repo: PathBuf,
    pub db_path: PathBuf,
    pub cfg: Config,
    exts: Vec<Box<dyn Extractor>>,
    exclude: Vec<Regex>,
    /// how long a lock (the update lock, SQLite's write lock) may be waited for: long for `update`, short for queries
    wait: Duration,
    /// the exclusion criteria of the query in flight (read by the SQL functions `aix_drop` / `aix_class`)
    excl: std::sync::Arc<std::sync::RwLock<std::sync::Arc<crate::excl::Excl>>>,
    /// a query's refresh: more changed files than this are refreshed by a background `aix update` instead of inline
    /// (None: always inline, as `aix update` itself)
    pub defer_over: Option<usize>,
}

/// Changed files a query refreshes inline at most (AIX_INLINE_REFRESH_MAX overrides): past it, a branch switch or a
/// formatter run would make the next query wait a minute.
pub fn inline_refresh_max() -> usize {
    std::env::var("AIX_INLINE_REFRESH_MAX").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

/// Register `aix_drop(path)` (1 when the query's PRE criteria drop that path) and `aix_class(path)` on a connection.
fn register_fns(conn: &Connection, st: &std::sync::Arc<std::sync::RwLock<std::sync::Arc<crate::excl::Excl>>>) {
    use rusqlite::functions::FunctionFlags;
    let st1 = st.clone();
    let _ = conn.create_scalar_function("aix_drop", 1, FunctionFlags::SQLITE_UTF8, move |c| {
        let p: Option<String> = c.get(0)?;
        let e = st1.read().map(|g| g.clone()).unwrap_or_default();
        Ok(i64::from(p.is_some_and(|p| e.drops(&p))))
    });
    let st2 = st.clone();
    let _ = conn.create_scalar_function("aix_conf", 1, FunctionFlags::SQLITE_UTF8, move |c| {
        let v: Option<String> = c.get(0)?;
        let e = st2.read().map(|g| g.clone()).unwrap_or_default();
        let v = v.unwrap_or_default();
        Ok(i64::from(e.conf.is_empty() || e.conf.iter().any(|k| *k == v || (v.is_empty() && k == "exact"))))
    });
    let _ = conn.create_scalar_function("aix_class", 1, FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC, |c| {
        let p: String = c.get::<Option<String>>(0)?.unwrap_or_default();
        Ok(crate::excl::file_class(&p).to_string())
    });
}

/// Progress of the files stage of an update: `<db>.progress` holds "done total" (refreshed about once a second, removed
/// when the stage ends) so another process can say how far a first build is; with AIX_PROGRESS=1 (`aix update
/// --progress`) a line goes to stderr every 5 s as well. Quiet by default.
struct Progress {
    path: PathBuf,
    total: usize,
    t0: Instant,
    last_file: Instant,
    last_err: Instant,
}
impl Progress {
    fn new(db: &Path, total: usize) -> Progress {
        let now = Instant::now();
        // the file is written at the first tick (a waiting query can say "0 of N" at once), then once a second
        let first = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        Progress { path: sidecar(db, ".progress"), total, t0: now, last_file: first, last_err: now }
    }
    fn tick(&mut self, done: usize) {
        if self.last_file.elapsed() >= Duration::from_secs(1) {
            self.last_file = Instant::now();
            let _ = std::fs::write(&self.path, format!("{done} {}", self.total));
        }
        if crate::par::progress() && self.last_err.elapsed() >= Duration::from_secs(5) {
            self.last_err = Instant::now();
            eprintln!("aix: indexed {done} of {} files ({}%), {} s", self.total, done * 100 / self.total.max(1), self.t0.elapsed().as_secs());
        }
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How far the files stage of a running update is: (done, total), when one is running.
pub fn build_progress(db: &Path) -> Option<(usize, usize)> {
    let t = std::fs::read_to_string(sidecar(db, ".progress")).ok()?;
    let (a, b) = t.trim().split_once(' ')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// The index is being written by another process and the wait ran out.
#[derive(Debug)]
pub struct IndexBusy;
impl std::fmt::Display for IndexBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("index busy (another aix is updating it)")
    }
}
impl std::error::Error for IndexBusy {}

/// True when `e` means "someone else holds the write lock" (not a real failure: answer from the existing index).
pub fn is_busy(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<IndexBusy>().is_some()
            || matches!(
                c.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(f, _))
                    if matches!(f.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            )
    })
}

/// The line above an answer given while another process holds the update lock (a refresh can take minutes on a
/// big change, so no promise of "a few seconds").
pub const BUSY_NOTE: &str = "(index busy: another aix is updating it; answers about files changed since may lag until it finishes)";
const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// Cross-process lock serialising updaters (an flock on `<db>.lock`, released when dropped or the process dies).
struct UpdateGuard(std::fs::File);
impl Drop for UpdateGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct UpdateStats {
    pub scanned: usize,
    pub changed: usize,
    pub removed: usize,
    pub rows: usize,
    pub new_commits: usize,
    pub ms: u128,
    pub full: bool,
    /// an earlier update did not finish (crash, lock timeout, failed stage): every stage was run again
    pub resumed: bool,
    /// changed files left to a background refresh (a query's refresh over `defer_over`); the index is not updated
    pub deferred: usize,
}

impl UpdateStats {
    pub fn is_noop(&self) -> bool {
        self.changed == 0 && self.removed == 0 && self.new_commits == 0 && !self.resumed && self.deferred == 0
    }
    pub fn line(&self) -> String {
        if self.deferred > 0 {
            return format!("{} files changed since the last update: refreshing in the background; `code`/`outline` read changed files as they are now, other answers may lag until it finishes", self.deferred);
        }
        format!(
            "{} {} files scanned, {} changed, {} removed, {} rows, {} new commits in {} ms",
            if self.full { "full build:" } else { "update:" },
            self.scanned,
            self.changed,
            self.removed,
            self.rows,
            self.new_commits,
            self.ms
        )
    }
}

struct FileMeta {
    path: String,
    hash: String,
    mtime_ns: i64,
    bytes: u64,
    lines: usize,
    rows: Option<Rows>,
}

struct Plan {
    full: bool,
    listed: Vec<walk::Listed>,
    skipped: walk::Skipped,
    known: HashMap<String, (String, i64, i64)>,
    unreadable: Vec<(String, String)>,
    /// indexes into `listed` of files whose stat differs from the index (or that are new)
    cands: Vec<usize>,
    removed: Vec<String>,
    /// an earlier update did not finish
    pending: bool,
    head_moved: bool,
    /// patterns added since the last refresh (a promoted search, `patterns add`) wait to be materialized
    dirty_patterns: bool,
}

impl Plan {
    fn has_work(&self) -> bool {
        self.full || self.pending || self.head_moved || self.dirty_patterns || !self.cands.is_empty() || !self.removed.is_empty()
    }
}

fn skipped_meta(conn: &Connection, skipped: &walk::Skipped, unreadable: &[(String, String)]) -> String {
    let mut v: Vec<String> = skipped.files.iter().map(|(p, why)| format!("{why}\t{p}")).collect();
    v.extend(unreadable.iter().map(|(p, why)| format!("{why}\t{p}")));
    // files the extractor gave up on (too deep, panic) are recorded as notes: name them too
    if let Ok(mut st) = conn.prepare("SELECT text, file FROM notes WHERE kind='extract-skipped' ORDER BY file") {
        if let Ok(rows) = st.query_map([], |r| Ok(format!("{}\t{}", r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            v.extend(rows.flatten());
        }
    }
    v.truncate(2000);
    v.join("\n")
}

/// Tracked files of types aix does not index, one per line (at most 5000).
fn unsupported_meta(skipped: &walk::Skipped) -> String {
    skipped.unsupported.iter().take(5000).cloned().collect::<Vec<_>>().join("\n")
}

fn put_meta(c: &Connection, k: &str, v: &str) -> Result<()> {
    c.execute("INSERT OR REPLACE INTO meta VALUES(?, ?)", [k, v])?;
    Ok(())
}

/// Find the repo root (git toplevel, else the directory itself).
pub fn find_repo(start: &Path) -> PathBuf {
    let start = crate::sys::canonicalize(&start).unwrap_or_else(|_| start.to_path_buf());
    let mut cur = start.as_path();
    loop {
        if cur.join(".git").exists() {
            return cur.to_path_buf();
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => return start,
        }
    }
}

pub fn default_db(repo: &Path) -> PathBuf {
    repo.join(".aix").join("index.db")
}

/// The `--db` to use: the given one, else `<repo>/.aix/index.db`.
pub fn resolve_db(repo: &Path, db: Option<&Path>) -> PathBuf {
    db.map(Path::to_path_buf).unwrap_or_else(|| default_db(repo))
}

/// The indexed checkout a first index of `repo` can start from: its parent (`ignorecheck::parent_repo`: a worktree's
/// main tree, a local clone's source, an enclosing checkout of the same remote) when that has `.aix/index.db`.
pub fn seed_source(repo: &Path) -> Option<(PathBuf, PathBuf)> {
    let parent = crate::ignorecheck::parent_repo(repo)?;
    let db = default_db(&parent);
    std::fs::metadata(&db).is_ok_and(|m| m.is_file() && m.len() > 0).then_some((parent, db))
}

/// What `seed` did: the checkout it copied from and how long the copy took.
#[derive(Debug, Clone)]
pub struct Seeded {
    pub parent: PathBuf,
    pub ms: u128,
}

/// A first index for a clone or worktree of an indexed repo: a consistent copy of the parent's index (`VACUUM INTO`,
/// a snapshot even while the parent updates) that then describes `repo`; the next update re-reads only what differs
/// (same content = same hash, so a fresh checkout costs a stat + hash per file, not a parse). None when there is no
/// parent index, `db` exists already, or the parent's index has another schema (it would be dropped on open).
/// The caller runs the .gitignore gate first: a seed never skips the user's decision.
pub fn seed(repo: &Path, db: &Path) -> Option<Seeded> {
    if crate::config::env_var("SEED").is_some_and(|v| v == "0") || std::fs::symlink_metadata(db).is_ok() {
        return None;
    }
    let t0 = Instant::now();
    let repo = crate::sys::canonicalize(&repo).ok()?;
    let (parent, pdb) = seed_source(&repo)?;
    let src = Connection::open_with_flags(&pdb, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
    let _ = src.busy_timeout(Duration::from_secs(10));
    if !is_aix_db(&src) {
        return None;
    }
    let ver: Option<String> = src.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).ok();
    if ver.as_deref() != Some(SCHEMA_VERSION) {
        return None;
    }
    let dir = db.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if dir.file_name().is_some_and(|n| n == ".aix") {
        check_aix_dir(&repo, dir, db, true).ok()?;
    } else if !dir.is_dir() {
        return None;
    }
    let tmp = dir.join(format!(".seed.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let res = (|| -> Result<()> {
        src.execute("VACUUM INTO ?1", [tmp.to_string_lossy().as_ref()])?;
        drop(src);
        tighten(&tmp, 0o600);
        let c = Connection::open(&tmp)?;
        c.execute("INSERT OR REPLACE INTO meta VALUES('repo', ?)", [repo.to_string_lossy().as_ref()])?;
        c.execute("INSERT OR REPLACE INTO meta VALUES('seeded_from', ?)", [parent.to_string_lossy().as_ref()])?;
        // the parent's no-op signature describes the parent's tree: the first update here walks and compares
        c.execute("DELETE FROM meta WHERE key='fast_sig'", [])?;
        c.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        drop(c);
        std::fs::rename(&tmp, db)?;
        Ok(())
    })();
    if res.is_err() {
        for s in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(sidecar(&tmp, s));
        }
        return None;
    }
    if dir.file_name().is_some_and(|n| n == ".aix") {
        tighten_index(Some(dir), db);
        let gi = dir.join(".gitignore");
        if std::fs::symlink_metadata(&gi).is_err() {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create_new(true).open(&gi) {
                use std::io::Write;
                let _ = f.write_all(b"# aix index (local cache)\n*\n");
            }
        }
    }
    Some(Seeded { parent, ms: t0.elapsed().as_millis() })
}

/// True when `conn` holds an aix index: a `meta` table with the aix marker, or (indexes written
/// before the marker existed) a `meta.schema` row next to the `files` and `entries` tables.
fn is_aix_db(conn: &Connection) -> bool {
    let has = |t: &str| {
        conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [t], |_| Ok(())).optional().ok().flatten().is_some()
    };
    if !has("meta") {
        return false;
    }
    let get = |k: &str| -> Option<String> {
        conn.query_row("SELECT value FROM meta WHERE key=?", [k], |r| r.get(0)).optional().ok().flatten()
    };
    matches!(get("app").as_deref(), Some(APP_MARKER)) || (get("schema").is_some() && has("files") && has("entries"))
}

fn user_tables(conn: &Connection) -> Result<Vec<String>> {
    Ok(conn
        .prepare("SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?)
}

const APP_MARKER: &str = "aix";

fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut o = db.as_os_str().to_owned();
    o.push(suffix);
    PathBuf::from(o)
}

/// Owner-only permissions on the index (it holds the repo's text and commit history): `.aix` 0700, the database
/// and its -wal/-shm/-journal 0600. Only touches what the current user owns; never fails the caller.
fn tighten(path: &Path, mode: u32) {
    let Ok(m) = std::fs::symlink_metadata(path) else { return };
    if m.file_type().is_symlink() || !crate::sys::owned_by_me(&m) || crate::sys::mode(&m).is_none_or(|m| m & 0o777 == mode) {
        return;
    }
    let _ = crate::sys::chmod(path, mode);
}

fn tighten_index(dir: Option<&Path>, db: &Path) {
    if let Some(d) = dir {
        tighten(d, 0o700);
    }
    for f in [db.to_path_buf(), sidecar(db, "-wal"), sidecar(db, "-shm"), sidecar(db, "-journal")] {
        tighten(&f, 0o600);
    }
}

/// The index lives in `<repo>/.aix`, which a repo can commit as a symlink: refuse a `.aix` (or an
/// index/-wal/-shm/.gitignore inside it) that is a symlink or resolves outside the repo, and never create
/// directories through one. With `create`, a missing `.aix` is created (one level, never recursively).
fn check_aix_dir(repo: &Path, dir: &Path, db: &Path, create: bool) -> Result<()> {
    let in_repo = dir == repo.join(".aix");
    match std::fs::symlink_metadata(dir) {
        Ok(m) => {
            anyhow::ensure!(!m.file_type().is_symlink(), "{} is a symlink; refusing to write through it", dir.display());
            anyhow::ensure!(m.is_dir(), "{} is not a directory", dir.display());
            let c = crate::sys::canonicalize(&dir).with_context(|| dir.display().to_string())?;
            anyhow::ensure!(!in_repo || c.starts_with(repo), "{} resolves outside the repo; refusing", dir.display());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if create && in_repo {
                // a parallel first run may have created it a moment ago: that is fine, it is checked below
                match crate::sys::private_dir(&mut std::fs::DirBuilder::new()).create(dir) {
                    Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                        return Err(e).with_context(|| format!("creating {}", dir.display()))
                    }
                    // Windows: the mode above does nothing; the user's alone through its access list
                    Ok(()) if cfg!(windows) => {
                        let _ = crate::sys::owner_only_dir(dir);
                    }
                    _ => {}
                }
                return check_aix_dir(repo, dir, db, false);
            }
        }
        Err(e) => return Err(e.into()),
    }
    for f in [db.to_path_buf(), sidecar(db, "-wal"), sidecar(db, "-shm"), sidecar(db, "-journal"), dir.join(".gitignore")] {
        if std::fs::symlink_metadata(&f).is_ok_and(|m| m.file_type().is_symlink()) {
            anyhow::bail!("{} is a symlink; refusing to write through it", f.display());
        }
    }
    Ok(())
}

fn uri_immutable(db: &Path) -> String {
    format!("file:{}?mode=ro&immutable=1", db.display().to_string().replace('%', "%25").replace('?', "%3f").replace('#', "%23"))
}

/// Before opening a database that is not ours to modify: a file with a hot `-wal` that does not look like a
/// aix index (judged from the main file alone, read-only and immutable, so nothing is replayed or
/// checkpointed) is refused untouched. Opening it normally would checkpoint foreign data.
fn refuse_foreign_wal(db: &Path) -> Result<()> {
    let wal = sidecar(db, "-wal");
    if !std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0) || !db.exists() {
        return Ok(());
    }
    let seen = db_damage().is_some();
    let ours = Connection::open_with_flags(
        uri_immutable(db),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()
    .is_some_and(|c| is_aix_db(&c))
        || wal_holds_new_aix_db(db, &wal);
    // the main file read alone may reach pages only the log holds: that is no damage of the index itself
    if !seen {
        if let Ok(mut d) = DB_DAMAGE.lock() {
            *d = None;
        }
    }
    anyhow::ensure!(
        ours,
        "{} has a write-ahead log ({}) and is not a recognisable aix index; refusing to open it (that would checkpoint it). Delete the -wal/-shm files if they are stale",
        db.display(),
        wal.display()
    );
    Ok(())
}

/// A first build killed before its first checkpoint leaves a main file with no tables and the whole schema in
/// the `-wal`; killed during that checkpoint, a main file whose first pages point at pages only the log holds. The
/// immutable check cannot see either, so judge a copy instead: the main file and the log are copied
/// into a private temp dir next to the db (never /tmp), the copy is opened normally (the replay happens there) and
/// checked. Only for a main file that is empty or not consistent alone, so a foreign database with tables of its
/// own is still refused unread.
fn wal_holds_new_aix_db(db: &Path, wal: &Path) -> bool {
    let alone = Connection::open_with_flags(
        uri_immutable(db),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    );
    let empty_main = std::fs::metadata(db).is_ok_and(|m| m.len() == 0)
        || alone.as_ref().map_or(true, |c| {
            user_tables(c).map_or(true, |t| t.is_empty()) || c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0)).map_or(true, |s| s != "ok")
        });
    drop(alone);
    if !empty_main {
        return false;
    }
    let Some(dir) = db.parent().map(|d| if d.as_os_str().is_empty() { Path::new(".") } else { d }) else { return false };
    let tmp = dir.join(format!(".aix-walcheck-{}-{:x}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos())));
    if crate::sys::private_dir(&mut std::fs::DirBuilder::new()).create(&tmp).is_err() {
        return false;
    }
    let copy = tmp.join("check.db");
    let ours = std::fs::copy(db, &copy).is_ok()
        && std::fs::copy(wal, sidecar(&copy, "-wal")).is_ok()
        && Connection::open(&copy).is_ok_and(|c| is_aix_db(&c));
    let _ = std::fs::remove_dir_all(&tmp);
    ours
}

/// The first SQLITE_CORRUPT / SQLITE_NOTADB SQLite reported in this process (any statement, even one whose error a
/// query swallows): a damaged index answers with plausible but truncated rows, so `run` refuses to answer at all.
static DB_DAMAGE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Route SQLite's error log to `DB_DAMAGE`. Must run before the first connection (SQLite ignores it afterwards);
/// `main` and `Index::open` both call it, the first call wins.
pub fn watch_db_damage() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn log(code: std::os::raw::c_int, msg: &str) {
            // primary codes: 11 SQLITE_CORRUPT (incl. CORRUPT_VTAB/INDEX/SEQUENCE), 26 SQLITE_NOTADB
            if matches!(code & 0xff, 11 | 26) {
                if let Ok(mut d) = DB_DAMAGE.lock() {
                    d.get_or_insert_with(|| msg.to_string());
                }
            }
        }
        // SAFETY: called once, before any connection is opened by this process (else SQLite returns MISUSE, ignored)
        let _ = unsafe { rusqlite::trace::config_log(Some(log)) };
    });
}

/// SQLite's own report of a damaged database, if one was seen in this process.
pub fn db_damage() -> Option<String> {
    DB_DAMAGE.lock().ok().and_then(|d| d.clone())
}

/// The recovery hint for a damaged or unreadable index file.
pub fn rebuild_hint(db: &Path) -> String {
    let d = db.display();
    // aix-refresh is a bash script (flock, setsid): Windows runs `aix update` itself
    let (r, or) = if cfg!(windows) { ("aix update", "") } else { ("aix-refresh", " (or `aix update`)") };
    format!("the index is damaged; nothing it holds is trusted. Rebuild it: `{r} --full`, or if that fails delete {d} (and {d}-wal, {d}-shm) and run `{r}`{or}")
}

impl Index {
    pub fn open(repo: &Path, db: Option<&Path>) -> Result<Index> {
        watch_db_damage();
        let repo = crate::sys::canonicalize(&repo).with_context(|| format!("repo {}", repo.display()))?;
        let db_path = resolve_db(&repo, db);
        if let Some(d) = db_path.parent() {
            let d = if d.as_os_str().is_empty() { Path::new(".") } else { d };
            if d.file_name().is_some_and(|n| n == ".aix") {
                // the default location lives inside the repo: create it (never through a symlink) and keep it out of git
                check_aix_dir(&repo, d, &db_path, true)?;
                let gi = d.join(".gitignore");
                if std::fs::symlink_metadata(&gi).is_err() {
                    // create_new: two first runs never truncate each other's file
                    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create_new(true).open(&gi) {
                        use std::io::Write;
                        let _ = f.write_all(b"# aix index (local cache)\n*\n");
                    }
                }
            } else if !d.is_dir() {
                anyhow::bail!("--db {}: directory {} does not exist (aix only creates <repo>/.aix)", db_path.display(), d.display());
            } else if std::fs::metadata(&db_path).is_ok_and(|m| m.is_file() && m.len() == 0) {
                anyhow::bail!("--db {}: an existing empty file that is not under <repo>/.aix; refusing to turn it into an index (remove it or pick a new name)", db_path.display());
            }
        }
        refuse_foreign_wal(&db_path)?;
        let sk_dir = db_path.parent().filter(|d| d.file_name().is_some_and(|n| n == ".aix")).map(Path::to_path_buf);
        tighten_index(sk_dir.as_deref(), &db_path);
        crate::par::init_global();
        let conn = Connection::open(&db_path)?;
        tighten_index(sk_dir.as_deref(), &db_path);
        conn.busy_timeout(DEFAULT_WAIT)?;
        // A parallel first run may be creating the index right now (the file exists, the tables are not committed
        // yet, or an older aix wrote its tables in several steps): look again for a moment before judging.
        let mut tries = 0;
        let (existing, ver) = loop {
            // Identify the file before changing anything (even the journal mode is a write): a foreign database
            // is never migrated, dropped from, or written to.
            let existing = user_tables(&conn).map_err(|e| anyhow::anyhow!("{} is not a usable SQLite database: {e}; {}", db_path.display(), rebuild_hint(&db_path)))?;
            if existing.is_empty() || is_aix_db(&conn) {
                let ver: Option<String> =
                    conn.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional().unwrap_or(None);
                break (existing, ver);
            }
            tries += 1;
            if tries > 20 {
                anyhow::bail!("{} is not an aix index (no aix meta table); refusing to touch it", db_path.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // An index records the repo it describes. Pointing --db at another repo's index would make the next update
        // treat every file as changed/removed and wipe it: refuse before anything is written.
        if !existing.is_empty() {
            let stored: Option<String> =
                conn.query_row("SELECT value FROM meta WHERE key='repo'", [], |r| r.get(0)).optional().unwrap_or(None);
            if let Some(s) = stored.filter(|s| !s.is_empty()) {
                let other = Path::new(&s);
                if other.exists() && crate::sys::canonicalize(&other).ok().as_deref() != Some(repo.as_path()) {
                    anyhow::bail!(
                        "--db {} indexes another repository ({}), not {}; refusing to use or refresh it (use that repo's own index, or a new --db path)",
                        db_path.display(),
                        s,
                        repo.display()
                    );
                }
            }
        }
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;")?;
        // Writes on open only when there is something to set up (a new index, or a schema change): an ordinary open
        // takes no lock, so a running update never makes a query wait or fail.
        if existing.is_empty() || ver.as_deref() != Some(SCHEMA_VERSION) {
            let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap_or_default();
            if !mode.eq_ignore_ascii_case("wal") {
                conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
            }
            // one transaction under the write lock (waiting for a parallel first run), re-checked once the lock is ours
            let tx = rusqlite::Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)?;
            let existing = user_tables(&tx)?;
            if !existing.is_empty() && !is_aix_db(&tx) {
                anyhow::bail!("{} is not an aix index (no aix meta table); refusing to touch it", db_path.display());
            }
            let ver: Option<String> =
                tx.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0)).optional().unwrap_or(None);
            if existing.is_empty() || ver.as_deref() != Some(SCHEMA_VERSION) {
                if !existing.is_empty() {
                    // schema changed: start over (the index is a cache; vectors are cheap to keep but simpler to drop)
                    let objs: Vec<(String, String)> = tx
                        .prepare("SELECT type, name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'entries_fts_%' ORDER BY type DESC")?
                        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<_, _>>()?;
                    for (ty, t) in objs {
                        if ty == "view" {
                            tx.execute_batch(&format!("DROP VIEW IF EXISTS \"{t}\""))?;
                        } else if !matches!(t.as_str(), "vectors" | "savings" | "llm_notes" | "script_usage" | "grep_usage" | "patterns") {
                            tx.execute_batch(&format!("DROP TABLE IF EXISTS \"{t}\""))?;
                        }
                    }
                }
                // tables kept across schema resets may predate a column
                if tx.prepare("SELECT ms FROM savings LIMIT 0").is_err() {
                    let _ = tx.execute_batch("ALTER TABLE savings ADD COLUMN ms INT");
                }
                tx.execute_batch(SCHEMA)?;
                tx.execute_batch(crate::codegraph::SCHEMA)?;
                tx.execute_batch(crate::datamodel::SCHEMA)?;
                tx.execute_batch(crate::trace::SCHEMA)?;
                tx.execute("INSERT OR REPLACE INTO meta VALUES('schema', ?)", [SCHEMA_VERSION])?;
                tx.execute("INSERT OR REPLACE INTO meta VALUES('app', ?)", [APP_MARKER])?;
                tx.execute("INSERT OR REPLACE INTO meta VALUES('repo', ?)", [repo.to_string_lossy().as_ref()])?;
            }
            tx.commit()?;
            tighten_index(sk_dir.as_deref(), &db_path);
        }
        let db_dir = db_path.parent().map(Path::to_path_buf).unwrap_or_else(|| repo.clone());
        let cfg = Config::load(&repo, &db_dir);
        let exclude = cfg.exclude.iter().filter_map(|x| Regex::new(x).ok()).collect();
        let exts = sx::detected(&repo);
        let excl: std::sync::Arc<std::sync::RwLock<std::sync::Arc<crate::excl::Excl>>> = Default::default();
        register_fns(&conn, &excl);
        // older indexes: add and fill the file class column (best effort; the filters compute the class from the path)
        if conn.prepare("SELECT class FROM files LIMIT 0").is_err() && conn.execute_batch("ALTER TABLE files ADD COLUMN class TEXT DEFAULT ''").is_ok() {
            let _ = conn.execute_batch("UPDATE files SET class=aix_class(path)");
        }
        Ok(Index { conn, repo, db_path, cfg, exts, exclude, wait: DEFAULT_WAIT, excl, defer_over: None })
    }

    /// Open an existing index for a hook: no directory/file creation, no migration, no writes on open, and a
    /// 100 ms busy timeout. Errors (locked, missing, foreign or older schema) mean "stay silent".
    pub fn open_hook(repo: &Path, db: &Path) -> Result<Index> {
        use rusqlite::OpenFlags;
        let repo_arg = repo;
        let repo = crate::sys::canonicalize(&repo).with_context(|| format!("repo {}", repo.display()))?;
        let sk = repo.join(".aix");
        if let Some(d) = db.parent().filter(|d| d.file_name().is_some_and(|n| n == ".aix")) {
            let d = if d == repo_arg.join(".aix") { sk.as_path() } else { d };
            check_aix_dir(&repo, d, db, false)?;
        }
        if !std::fs::metadata(db).is_ok_and(|m| m.is_file()) {
            anyhow::bail!("no index");
        }
        refuse_foreign_wal(db)?;
        // Judge the file read-only first: opening it read-write can create -wal/-shm files, so that only happens
        // for an index that is ours and current (the hook then records pattern usage and "nudged" markers).
        {
            // immutable when no -wal exists: a plain read-only open of a WAL database creates (and leaves) -wal/-shm files
            let ro = if sidecar(db, "-wal").exists() {
                Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?
            } else {
                Connection::open_with_flags(
                    uri_immutable(db),
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?
            };
            ro.busy_timeout(std::time::Duration::from_millis(100))?;
            let ver: String = ro.query_row("SELECT value FROM meta WHERE key='schema'", [], |r| r.get(0))?;
            if ver != SCHEMA_VERSION || !is_aix_db(&ro) {
                anyhow::bail!("not a current aix index");
            }
        }
        let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .or_else(|_| Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        conn.busy_timeout(std::time::Duration::from_millis(100))?;
        let db_dir = db.parent().map(Path::to_path_buf).unwrap_or_else(|| repo.clone());
        let cfg = Config::load(&repo, &db_dir);
        let exclude = cfg.exclude.iter().filter_map(|x| Regex::new(x).ok()).collect();
        let excl: std::sync::Arc<std::sync::RwLock<std::sync::Arc<crate::excl::Excl>>> = Default::default();
        register_fns(&conn, &excl);
        Ok(Index { conn, repo, db_path: db.to_path_buf(), cfg, exts: vec![], exclude, wait: Duration::from_millis(100), excl, defer_over: None })
    }

    pub fn extractor_names(&self) -> Vec<&'static str> {
        self.exts.iter().map(|e| e.name()).collect()
    }

    /// Extract one file in memory with this index's extractors (nothing is written): `fresh.rs` reads a file
    /// edited since it was indexed this way while a refresh is pending or running elsewhere.
    pub fn extract_now(&self, path: &str, text: String) -> Rows {
        sx::extract_file(&self.repo, &self.exts, &SourceFile::new(path.to_string(), text))
    }

    pub fn meta(&self, k: &str) -> Option<String> {
        self.conn.query_row("SELECT value FROM meta WHERE key=?", [k], |r| r.get(0)).optional().ok().flatten()
    }
    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES(?, ?)", [k, v])?;
        Ok(())
    }

    /// Wait at most `d` for locks (`update` waits long, interactive commands and the card a moment).
    pub fn set_wait(&mut self, d: Duration) {
        self.wait = d;
        let _ = self.conn.busy_timeout(d);
    }
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// Criteria of the query in flight (empty outside `run`).
    pub fn excl(&self) -> std::sync::Arc<crate::excl::Excl> {
        self.excl.read().map(|g| g.clone()).unwrap_or_default()
    }
    pub fn set_excl(&self, e: crate::excl::Excl) {
        if let Ok(mut g) = self.excl.write() {
            *g = std::sync::Arc::new(e);
        }
    }

    fn lock_path(&self) -> PathBuf {
        sidecar(&self.db_path, ".lock")
    }

    /// Serialise updaters: only one process at a time extracts, writes and resolves, the others wait (up to `wait`)
    /// and then usually find nothing left to do. A lock file that cannot be created or locked is not a reason to fail.
    fn lock_update(&self) -> Result<Option<UpdateGuard>> {
        let p = self.lock_path();
        let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p) else {
            return Ok(None);
        };
        tighten(&p, 0o600);
        let deadline = Instant::now() + self.wait;
        loop {
            match f.try_lock() {
                Ok(()) => return Ok(Some(UpdateGuard(f))),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(IndexBusy.into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Ok(None),
            }
        }
    }

    /// Is the update lock free right now (no wait)?
    fn lock_path_free(&self) -> bool {
        let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(self.lock_path()) else { return true };
        f.try_lock().is_ok()
    }

    /// Start `aix update` for this index in the background (detached, its own process group). Only from the aix
    /// binary itself (a test harness or another host has no `update` command).
    fn spawn_refresh(&self, low: bool) -> bool {
        let Ok(exe) = std::env::current_exe() else { return false };
        if !exe.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "aix" || n == "aix.exe") {
            return false;
        }
        let mut c = std::process::Command::new(exe);
        c.arg("--repo").arg(&self.repo).arg("--db").arg(&self.db_path).args(["update", "--quiet", "--embed-deadline", "0"]);
        c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        // low priority like aix-refresh: fewer threads, smaller batches, niced (the write lock still serialises it).
        // A first build someone is waiting for keeps the normal thread count.
        if low {
            c.env("AIX_LOW", "1");
        }
        crate::sys::background(&mut c, low);
        match c.spawn() {
            Ok(mut ch) => {
                std::thread::spawn(move || {
                    let _ = ch.wait();
                });
                true
            }
            Err(_) => false,
        }
    }

    /// What an update would have to do: files to (re)read or drop, and whether an earlier update is unfinished.
    /// Reads only (no lock, no write).
    fn plan(&self, full: bool, rev: &str) -> Result<Plan> {
        let pending = self.meta("update_pending").is_some()
            || self.conn.query_row("SELECT EXISTS(SELECT 1 FROM cg_dirty UNION ALL SELECT 1 FROM dm_dirty)", [], |r| r.get::<_, i64>(0)).unwrap_or(0) != 0;
        let full = full || self.meta("built").is_none() || self.meta("extract_rev").as_deref() != Some(rev);
        let (listed, skipped) = walk::list_with_skips(&self.repo, &self.exclude, self.cfg.max_file_bytes, self.cfg.index_untracked, &self.cfg.include);
        let mut known: HashMap<String, (String, i64, i64)> = HashMap::new();
        if !full {
            let mut st = self.conn.prepare("SELECT path, hash, mtime_ns, bytes FROM files")?;
            for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))? {
                let (p, v) = r?;
                known.insert(p, v);
            }
        }
        // files that are listed but cannot be opened: skipped with the reason (and dropped when they were indexed)
        let mut unreadable: Vec<(String, String)> = vec![];
        let mut cands: Vec<usize> = vec![];
        for (i, l) in listed.iter().enumerate() {
            let stale = match known.get(&l.path) {
                Some((_, m, b)) => full || *m != l.mtime_ns || *b as u64 != l.size,
                None => true,
            };
            if !stale {
                continue;
            }
            // Windows: no open here. Defender scans a file on its first open (26 s for a 3,200-file fresh clone,
            // paid before the build can go to the background); the build's own read drops an unreadable one the same way
            if cfg!(windows) {
                cands.push(i);
                continue;
            }
            match std::fs::File::open(self.repo.join(&l.path)) {
                Ok(_) => cands.push(i),
                Err(e) => unreadable.push((l.path.clone(), format!("unreadable: {}", e.kind().to_string().to_lowercase()))),
            }
        }
        let listed_set: HashSet<&str> =
            listed.iter().map(|l| l.path.as_str()).filter(|p| !unreadable.iter().any(|u| u.0 == *p)).collect();
        let removed: Vec<String> = known.keys().filter(|p| !listed_set.contains(p.as_str())).cloned().collect();
        let head = sx::git::head(&self.repo);
        let head_moved = head.is_some() && self.meta("git_head") != head;
        let dirty_patterns = self
            .conn
            .query_row("SELECT EXISTS(SELECT 1 FROM patterns WHERE dirty=1 AND dormant=0 AND removed=0)", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            != 0;
        Ok(Plan { full, listed, skipped, known, unreadable, cands, removed, pending, head_moved, dirty_patterns })
    }

    /// Bring the index up to date. Cheap when nothing changed (stat walk + HEAD check, no write lock).
    ///
    /// Crash safety: the first transaction (files) records `meta.update_pending`; it is cleared, together with
    /// `built`/`extract_rev`/`fast_sig`, only after the last stage (history, derived layer, code graph, patterns).
    /// An update that finds it set re-runs every stage, so a kill or a lock timeout between stages heals on the next run.
    pub fn update(&mut self, full: bool) -> Result<UpdateStats> {
        let t0 = Instant::now();
        // the first build of a repo waits for the user's .gitignore decision (ignorecheck.rs; tooling is not gated)
        if self.meta("built").is_none() {
            crate::ignorecheck::gate(&self.repo, &self.db_path, false).map_err(|e| anyhow::anyhow!(e))?;
            if let Some(n) = crate::ignorecheck::skipped_note(&self.repo, &self.db_path) {
                eprintln!("{n}");
            }
        }
        let _ = self.conn.busy_timeout(self.wait);
        // summaries (crate::matviews) added since this index was built: created and filled once, in place
        crate::matviews::ensure(&self.conn)?;
        let sig = if full { None } else { self.tree_sig() };
        if let Some(sig) = &sig {
            if let Some(n) = self.fast_noop(sig) {
                return Ok(UpdateStats { scanned: n, ms: t0.elapsed().as_millis(), ..Default::default() });
            }
        }
        let rev = sx::REVISION.to_string();
        // `data_version` changes when another connection commits: the plan is from an unchanged index if it is the same
        let version = |c: &Connection| c.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0)).ok();
        let v0 = version(&self.conn);
        let mut plan = { let _s = crate::par::span("walk+plan"); self.plan(full, &rev)? };
        // a query after a big change (branch switch, formatter): answer from the index now, refresh in the background
        if let Some(max) = self.defer_over {
            let n = plan.cands.len() + plan.removed.len();
            if n > max && !plan.full && self.meta("built").is_some() {
                let free = self.lock_path_free();
                if free && self.spawn_refresh(true) {
                    return Ok(UpdateStats { scanned: plan.listed.len(), deferred: n, ms: t0.elapsed().as_millis(), ..Default::default() });
                }
                if !free {
                    return Err(IndexBusy.into());
                }
            }
        }
        // a query on a repo never indexed, with more than a quick inline build to do: the build runs in its own process
        // (it survives this call); the query waits for it up to AIX_COLD_BUILD_WAIT_MS (default 5 s), then says
        // "index not ready (N of M files)" instead of holding the caller (an MCP tool call) for minutes
        if self.defer_over.is_some() && self.meta("built").is_none() && plan.cands.len() > inline_refresh_max() {
            let free = self.lock_path_free();
            if !free || self.spawn_refresh(false) {
                let wait_ms = std::env::var("AIX_COLD_BUILD_WAIT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(5000u64);
                let end = Instant::now() + Duration::from_millis(wait_ms);
                while Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(100));
                    if self.meta("built").is_some() {
                        return Ok(UpdateStats { scanned: plan.listed.len(), changed: plan.cands.len(), full: true, ms: t0.elapsed().as_millis(), ..Default::default() });
                    }
                }
                return Err(IndexBusy.into());
            }
        }
        let mut _guard = None;
        if plan.has_work() {
            // writers take turns; the plan is made again once the lock is ours if another updater wrote meanwhile
            _guard = self.lock_update()?;
            if v0.is_none() || version(&self.conn) != v0 {
                let _s = crate::par::span("walk+plan");
                plan = self.plan(full, &rev)?;
            }
        }
        if !plan.has_work() {
            let scanned = plan.listed.len();
            // go.mod / tsconfig*.json are not (all) indexed files, but a change to one moves edges anywhere: the code
            // graph compares their content signature (cg_tscfg) and re-resolves when it differs
            let cfg = self.cg_cfg_stat();
            match self.meta("cg_cfgstat") {
                Some(prev) if prev != cfg => {
                    let _g = self.lock_update()?;
                    crate::codegraph::resolve(self, false)?;
                    self.set_meta("cg_cfgstat", &cfg)?;
                    self.set_meta("fast_sig", "")?;
                }
                None => self.set_meta("cg_cfgstat", &cfg)?,
                _ => {}
            }
            self.note_current(&plan);
            return Ok(UpdateStats { scanned, ms: t0.elapsed().as_millis(), ..Default::default() });
        }
        let Plan { full, listed, skipped, known, unreadable, cands, mut removed, pending, head_moved: _, dirty_patterns: _ } = plan;
        let mut unreadable = unreadable;
        // git history is read by its own thread while the files are extracted; it is applied after the commit
        let hist_job = self.history_plan(full);
        let file_set: HashSet<String> =
            listed.iter().map(|l| l.path.clone()).filter(|p| !unreadable.iter().any(|u| &u.0 == p)).collect();
        let mut stats = UpdateStats { scanned: listed.len(), removed: removed.len(), full, resumed: pending, ..Default::default() };

        // ONE write transaction for the files stage (a kill leaves the old index intact, readers see the old index
        // until the commit); extraction runs in worker threads and overlaps with the single writer (this thread).
        let mut dropped_idx: Vec<String> = vec![];
        let sp_w = crate::par::span("write");
        // a bigger page cache for the bulk write (many indexes + FTS): bounded, per connection
        // (an eighth of the memory budget at most); under a tight budget the sorts of the index rebuild spill to temp files
        let budget_kb = crate::par::mem_budget_mb() * 1024;
        let cache_kb = (if cands.len() > 200 { 262_144 } else { 32_768 }).min(budget_kb / 8).max(8_192);
        let _ = self.conn.execute_batch(&format!("PRAGMA cache_size=-{cache_kb}"));
        if budget_kb < 2 * 1024 * 1024 {
            let _ = self.conn.execute_batch("PRAGMA temp_store=FILE");
        }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR REPLACE INTO meta VALUES('update_pending', ?)", [chrono_now()])?;
        // the summaries are stale until the last stage refreshes them: readers use the base tables meanwhile
        tx.execute("DELETE FROM meta WHERE key='mv_built'", [])?;
        tx.execute_batch(crate::datamodel::LATE_DDL)?; // tables added since the index was created
        tx.execute_batch(crate::trace::LATE_DDL)?;
        tx.execute_batch(crate::codegraph::LATE_DDL)?;
        tx.execute_batch(crate::semantic::GEN_DDL)?;
        if full {
            // a build interrupted after this transaction must start over: forget that the index was ever complete
            tx.execute("DELETE FROM meta WHERE key IN ('built','cg_built','dm_built','trace_built','fast_sig','git_head',?1,?2,?3)", [crate::derive::DERIVED_SIG_F, crate::derive::DERIVED_SIG_E, crate::derive::PATHS_OK])?;
            for t in FILE_TABLES.iter().chain(crate::codegraph::WIPE_TABLES).chain(crate::datamodel::FILE_TABLES).chain(crate::datamodel::WIPE_TABLES) {
                tx.execute(&format!("DELETE FROM {t}"), [])?;
            }
            tx.execute("DELETE FROM features", [])?;
            // bulk FTS: no per-row trigger work; the index is rebuilt in one pass before the commit (same transaction)
            tx.execute_batch("DROP TRIGGER IF EXISTS entries_ai; DROP TRIGGER IF EXISTS entries_ad;")?;
            // and no per-row index upkeep either: the secondary indexes of the bulk tables are rebuilt sorted at the end
            let bulk: HashSet<&str> = FILE_TABLES
                .iter()
                .chain(crate::codegraph::FILE_TABLES)
                .chain(crate::codegraph::WIPE_TABLES)
                .chain(crate::datamodel::FILE_TABLES)
                .copied()
                .chain(["features", "entries"])
                .collect();
            let idx: Vec<(String, String, String)> = tx
                .prepare("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY rowid")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            for (name, tbl, sql) in idx {
                if bulk.contains(tbl.as_str()) {
                    tx.execute_batch(&format!("DROP INDEX IF EXISTS \"{name}\""))?;
                    dropped_idx.push(sql);
                }
            }
            tx.execute("DELETE FROM entries WHERE src IN (0,1,3)", [])?;
            tx.execute("DELETE FROM files", [])?;
        }
        for p in &removed {
            delete_file(&tx, p)?;
            tx.execute("DELETE FROM files WHERE path=?", [p])?;
        }
        let mut changed_paths: Vec<String> = vec![];
        let mut late_unreadable: Vec<(String, String)> = vec![];
        let n = cands.len();
        let nt = crate::par::threads().min(n.max(1));
        let gate = Gate::new((nt * 4).max(8));
        let hist = std::thread::scope(|sc| -> Result<Option<HistoryFetch>> {
            let hist_h = hist_job.map(|j| sc.spawn(move || j.fetch()));
            let (txc, rxc) = std::sync::mpsc::channel::<(usize, Prepared)>();
            let (listed, known, repo, exts, cands) = (&listed, &known, &self.repo, &self.exts, &cands);
            let gate_r = &gate;
            for _ in 0..nt {
                let txc = txc.clone();
                let _ = std::thread::Builder::new().name("aix-extract".into()).stack_size(16 << 20).spawn_scoped(sc, move || {
                    while let Some(k) = gate_r.claim(n) {
                        let l = &listed[cands[k]];
                        let msg = prepare_file(repo, exts, l, known, full);
                        if txc.send((k, msg)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(txc);
            let _abort = AbortOnDrop(&gate);
            let mut buf: std::collections::BTreeMap<usize, Prepared> = Default::default();
            let mut progress = Progress::new(&self.db_path, n);
            for next in 0..n {
                progress.tick(next);
                let _sr = crate::par::span("w:wait_recv");
                while !buf.contains_key(&next) {
                    match rxc.recv() {
                        Ok((k, m)) => {
                            buf.insert(k, m);
                        }
                        Err(_) => anyhow::bail!("an extraction worker stopped early"),
                    }
                }
                drop(_sr);
                let pm = buf.remove(&next).unwrap();
                let _sw = crate::par::span("w:file_total");
                gate.advance(next + 1);
                let m = match pm.meta {
                    Ok(m) => m,
                    Err(u) => {
                        late_unreadable.push(u);
                        continue;
                    }
                };
                match &m.rows {
                    None => {
                        tx.execute("UPDATE files SET mtime_ns=? WHERE path=?", params![m.mtime_ns, m.path])?;
                    }
                    Some(rows) => {
                        stats.changed += 1;
                        stats.rows += rows.len();
                        if !full {
                            delete_file(&tx, &m.path)?;
                        }
                        let kind = walk::file_kind(&m.path);
                        let lang = sx::ext_of(&m.path);
                        tx.execute(
                            "INSERT INTO files(path, kind, lang, lines, bytes, hash, mtime_ns, class) VALUES(?,?,?,?,?,?,?,aix_class(?1))
                             ON CONFLICT(path) DO UPDATE SET class=excluded.class, kind=excluded.kind, lang=excluded.lang, lines=excluded.lines,
                             bytes=excluded.bytes, hash=excluded.hash, mtime_ns=excluded.mtime_ns, summary='', summary_source=''",
                            params![m.path, kind, lang, m.lines as i64, m.bytes as i64, m.hash, m.mtime_ns],
                        )?;
                        if !full && !known.contains_key(&m.path) {
                            // a new path: an import elsewhere may now resolve, or resolve to it (derive re-reads them all)
                            tx.prepare_cached("DELETE FROM meta WHERE key=?")?.execute([crate::derive::PATHS_OK])?;
                            // a path that comes back after a delete (or a rename target): its last commit is still in the history
                            tx.execute(
                                "UPDATE files SET
                                   commit_sha=COALESCE((SELECT c.short FROM commit_files cf JOIN commits c ON c.sha=cf.sha WHERE cf.path=files.path ORDER BY c.seq DESC LIMIT 1), ''),
                                   commit_date=COALESCE((SELECT c.date FROM commit_files cf JOIN commits c ON c.sha=cf.sha WHERE cf.path=files.path ORDER BY c.seq DESC LIMIT 1), '')
                                 WHERE path=?",
                                [&m.path],
                            )?;
                        }
                        // redaction and entry text were computed by the worker: the writer only inserts
                        crate::par::set_memo(pm.memo);
                        { let _s = crate::par::span("w:insert_rows"); insert_rows(&tx, rows, &file_set)?; }
                        crate::par::set_memo(Default::default());
                        { let _s = crate::par::span("w:entries"); entries::write_built(&tx, &pm.entries)?; }
                        changed_paths.push(m.path.clone());
                    }
                }
            }
            Ok(hist_h.and_then(|h| h.join().ok()).flatten())
        })?;
        // a file that could not be read after the plan was made: dropped like any unreadable file
        for u in late_unreadable {
            if known.contains_key(&u.0) && !removed.contains(&u.0) {
                delete_file(&tx, &u.0)?;
                tx.execute("DELETE FROM files WHERE path=?", [&u.0])?;
                removed.push(u.0.clone());
            }
            unreadable.push(u);
        }
        // an indexed file that can no longer be read is dropped, as a fresh build would not see it either
        for (p, _) in &unreadable {
            if known.contains_key(p) && !removed.contains(p) {
                delete_file(&tx, p)?;
                tx.execute("DELETE FROM files WHERE path=?", [p])?;
                removed.push(p.clone());
            }
        }
        stats.removed = removed.len();
        if !removed.is_empty() {
            // a path went away: imports that resolved to it (or past it) resolve again (derive)
            tx.execute("DELETE FROM meta WHERE key=?", [crate::derive::PATHS_OK])?;
        }
        if full {
            let _s = crate::par::span("w:fts_rebuild");
            tx.execute_batch("INSERT INTO entries_fts(entries_fts) VALUES('rebuild');")?;
            tx.execute_batch(crate::schema::FTS_TRIGGERS)?;
            let _s = crate::par::span("w:index_rebuild");
            for sql in &dropped_idx {
                tx.execute_batch(sql)?;
            }
        }
        tx.commit()?;
        drop(sp_w);
        crate::par::trim();

        stats.new_commits = { let _s = crate::par::span("history"); self.apply_history(hist)? };
        crate::par::test_pause();
        crate::par::progress_note("files written; derived layer");
        { let _s = crate::par::span("derive"); crate::derive::run(self, full)?; }
        crate::par::test_pause();
        crate::par::progress_note("code graph");
        { let _s = crate::par::span("codegraph"); crate::codegraph::resolve(self, full)?; }
        crate::par::trim();
        crate::par::test_pause();
        crate::par::progress_note("data model, traces, patterns");
        { let _s = crate::par::span("datamodel"); crate::datamodel::resolve(self, full)?; }
        { let _s = crate::par::span("trace"); crate::trace::build(self, full)?; }
        let sp_p = crate::par::span("patterns");
        crate::patterns::seed(&self.conn, self.cfg.seed_patterns)?;
        let dirty_patterns: i64 = self
            .conn
            .query_row("SELECT count(*) FROM patterns WHERE dirty=1 AND dormant=0 AND removed=0", [], |r| r.get(0))
            .unwrap_or(0);
        if full || pending || !changed_paths.is_empty() || !removed.is_empty() || dirty_patterns > 0 {
            // after an unfinished update the changed-file list of that run is gone: rescan everything
            crate::patterns::refresh(self, &changed_paths, &removed, full || pending)?;
        }
        drop(sp_p);
        // wanted files that are not searchable (too big, unusable name, unreadable): `grep` reports how many are in scope
        let sk = skipped_meta(&self.conn, &skipped, &unreadable);
        stats.ms = t0.elapsed().as_millis();
        let sig_now = self.tree_sig();
        let cfg_now = self.cg_cfg_stat();
        // the last stage: only now is the index complete
let absent_now = self.absent_tracked();
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        put_meta(&tx, "skipped", &sk)?;
        put_meta(&tx, "unsupported", &unsupported_meta(&skipped))?;
        let built = chrono_now();
        put_meta(&tx, "built", &built)?;
        { let _s = crate::par::span("matviews"); crate::matviews::refresh(&tx)?; }
        crate::matviews::stamp(&tx, &built)?;
        put_meta(&tx, "repo", &self.repo.to_string_lossy())?;
        put_meta(&tx, "extract_rev", &rev)?;
        put_meta(&tx, "cg_cfgstat", &cfg_now)?;
        if !stats.is_noop() {
            put_meta(&tx, "last_update", &stats.line())?;
        }
        // remember what the tree looked like when the index was brought up to date: the next query can skip the
        // git calls and the walk when nothing moved (see `fast_noop`)
        if let Some(sig) = sig_now {
            put_meta(&tx, "fast_sig", &sig)?;
            put_meta(&tx, "fast_at", &chrono_now())?;
            put_meta(&tx, "fast_absent", &absent_now)?;
        }
        tx.execute("DELETE FROM meta WHERE key='update_pending'", [])?;
        // the session card's cached "N files changed vs HEAD" (hooks.rs) is counted again after any change
        tx.execute("DELETE FROM meta WHERE key='card_dirty'", [])?;
        tx.commit()?;
        crate::par::report();
        Ok(stats)
    }

    /// Nothing changed: refresh the cheap-check fingerprint and the skipped list, only when they differ, and never
    /// wait for a lock (a running writer must not slow a query down).
    fn note_current(&self, plan: &Plan) {
        let _ = self.conn.busy_timeout(Duration::ZERO);
        let sk = skipped_meta(&self.conn, &plan.skipped, &plan.unreadable);
        if self.meta("skipped").as_deref() != Some(sk.as_str()) {
            let _ = self.set_meta("skipped", &sk);
        }
        let un = unsupported_meta(&plan.skipped);
        if self.meta("unsupported").as_deref() != Some(un.as_str()) {
            let _ = self.set_meta("unsupported", &un);
        }
        if let Some(sig) = self.tree_sig() {
            let at: u64 = self.meta("fast_at").and_then(|v| v.parse().ok()).unwrap_or(0);
            let now: u64 = chrono_now().parse().unwrap_or(0);
            if self.meta("fast_sig").as_deref() != Some(sig.as_str()) || now.saturating_sub(at) > 300 {
                let _ = self.set_meta("fast_sig", &sig);
                let _ = self.set_meta("fast_at", &chrono_now());
                let _ = self.set_meta("fast_absent", &self.absent_tracked());
            }
        }
        let _ = self.conn.busy_timeout(self.wait);
    }

    /// Size and mtime of the files that steer the code graph's import resolution but need not be indexed: every
    /// tsconfig*.json / jsconfig.json known to the index and the go.mod of each directory holding Go source (and its parents).
    fn cg_cfg_stat(&self) -> String {
        let paths: Vec<String> = match self.conn.prepare_cached("SELECT path FROM files WHERE path LIKE '%.go' OR path LIKE '%.json'") {
            Ok(mut st) => st.query_map([], |r| r.get::<_, String>(0)).map(|r| r.flatten().collect()).unwrap_or_default(),
            Err(_) => vec![],
        };
        let mut cands: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for p in &paths {
            if p.ends_with(".go") {
                let mut d = p.rsplit_once('/').map(|x| x.0).unwrap_or("");
                loop {
                    let gm = if d.is_empty() { "go.mod".to_string() } else { format!("{d}/go.mod") };
                    if !cands.insert(gm) {
                        break;
                    }
                    match d.rsplit_once('/') {
                        Some((up, _)) => d = up,
                        None if !d.is_empty() => d = "",
                        None => break,
                    }
                }
            } else {
                let base = p.rsplit('/').next().unwrap_or("");
                if base == "jsconfig.json" || (base.starts_with("tsconfig") && base.ends_with(".json")) {
                    cands.insert(p.clone());
                }
            }
        }
        let mut s = String::new();
        for c in cands {
            if let Ok(m) = std::fs::metadata(self.repo.join(&c)) {
                let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
                s.push_str(&format!("{c}:{t}:{};", m.len()));
            }
        }
        s
    }

    /// Cheap fingerprint of the repository state that decides what `update` would list: HEAD and its ref, the git
    /// index, the root ignore files and the config file. None when it cannot be computed cheaply (not a plain
    /// `.git` directory, untracked files indexed): `update` then always does the full check.
    fn tree_sig(&self) -> Option<String> {
        if self.cfg.index_untracked || !self.cfg.include.is_empty() {
            return None;
        }
        let git = self.repo.join(".git");
        if !git.is_dir() {
            return None;
        }
        let st = |p: &Path| -> String {
            std::fs::metadata(p)
                .ok()
                .map(|m| {
                    let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
                    format!("{t}:{}", m.len())
                })
                .unwrap_or_default()
        };
        let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
        let head = head.trim();
        let mut s = format!("{}|{head}", sx::REVISION);
        if let Some(r) = head.strip_prefix("ref: ") {
            match std::fs::read_to_string(git.join(r)) {
                Ok(v) => s.push_str(&format!("|{}", v.trim())),
                Err(_) => s.push_str(&format!("|packed:{}", st(&git.join("packed-refs")))),
            }
        }
        for f in ["index", "info/exclude"] {
            s.push_str(&format!("|{}", st(&git.join(f))));
        }
        s.push_str(&format!("|{}|{}", st(&self.repo.join(".gitignore")), st(&self.repo.join(".gitattributes"))));
        s.push_str(&format!("|{}", self.cg_cfg_stat()));
        s.push_str(&format!("|{}:{}|{}", self.cfg.source, st(Path::new(&self.cfg.source)), self.exclude.len()));
        Some(s)
    }

    /// Tracked files missing from the work tree (`git ls-files --deleted`), one per line; `*` when there are too many
    /// to check cheaply (the fast path then always walks).
    fn absent_tracked(&self) -> String {
        let o = std::process::Command::new("git").arg("-C").arg(&self.repo).args(["ls-files", "--deleted", "-z"]).stderr(std::process::Stdio::null()).output();
        let Some(o) = o.ok().filter(|o| o.status.success()) else { return "*".into() };
        let v: Vec<String> = o.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
        if v.len() > 500 || v.iter().any(|p| p.contains('\n')) {
            return "*".into();
        }
        v.join("\n")
    }

    /// Would an update find nothing to do? The same fast check `update` starts with (no lock, no git, no write); false
    /// when it cannot tell cheaply (then `update` decides).
    pub fn is_current(&self) -> bool {
        self.tree_sig().is_some_and(|s| self.fast_noop(&s).is_some())
    }

    /// Nothing to do? True (with the number of files checked) when the tree fingerprint is unchanged since the last
    /// complete update (checked at most 5 minutes ago), no pattern is waiting for a refresh, and every indexed file
    /// still has the size and mtime recorded. No git process, no directory walk, no write.
    fn fast_noop(&self, sig: &str) -> Option<usize> {
        if self.meta("fast_sig").as_deref() != Some(sig) || self.meta("extract_rev").as_deref() != Some(sx::REVISION.to_string().as_str()) {
            return None;
        }
        let at: u64 = self.meta("fast_at")?.parse().ok()?;
        let now: u64 = chrono_now().parse().ok()?;
        if now.saturating_sub(at) > 300 {
            return None;
        }
        let dirty: i64 = self
            .conn
            .query_row("SELECT count(*) FROM patterns WHERE dirty=1 AND dormant=0 AND removed=0", [], |r| r.get(0))
            .ok()?;
        if dirty > 0 || self.meta("update_pending").is_some() || self.meta("built").is_none() {
            return None;
        }
        // an unfinished update leaves code-graph work behind
        if self.conn.query_row("SELECT EXISTS(SELECT 1 FROM cg_dirty UNION ALL SELECT 1 FROM dm_dirty)", [], |r| r.get::<_, i64>(0)).ok()? != 0 {
            return None;
        }
        let mut st = self.conn.prepare_cached("SELECT path, mtime_ns, bytes FROM files").ok()?;
        let known: Vec<(String, i64, i64)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok()?.flatten().collect();
        let repo = &self.repo;
        // never "current" with nothing indexed, and a tracked file that was missing at the last update and is back
        // (deleted and restored with the same mtime and size: git's index does not change) is work
        if known.is_empty() {
            return None;
        }
        let absent = self.meta("fast_absent")?;
        if absent == "*" || absent.split('\n').filter(|p| !p.is_empty()).any(|p| std::fs::symlink_metadata(repo.join(p)).is_ok()) {
            return None;
        }
        let same = known.par_iter().all(|(p, m, b)| {
            std::fs::symlink_metadata(repo.join(p)).is_ok_and(|md| {
                md.file_type().is_file()
                    && md.len() as i64 == *b
                    && md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos() as i64) == Some(*m)
            })
        });
        same.then_some(known.len())
    }

    /// Refresh commits when HEAD moved: append new ones if the old HEAD is an ancestor, else rebuild.
    /// What the history stage needs from git, decided before the files stage (None: HEAD did not move, or no git).
    fn history_plan(&self, full: bool) -> Option<HistoryJob> {
        let head = sx::git::head(&self.repo)?;
        let old = self.meta("git_head");
        if !full && old.as_deref() == Some(head.as_str()) {
            return None;
        }
        Some(HistoryJob { repo: self.repo.clone(), head, old, full })
    }

    fn apply_history(&mut self, f: Option<HistoryFetch>) -> Result<usize> {
        let Some(HistoryFetch { head, commits, append }) = f else {
            return Ok(0);
        };
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !append {
            tx.execute_batch("DELETE FROM commits; DELETE FROM commit_files; DELETE FROM bugs WHERE kind='commit'; DELETE FROM entries WHERE src=2; UPDATE files SET commit_sha='', commit_date='';")?;
        }
        let base: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM commits", [], |r| r.get(0))?;
        let n = commits.len() as i64;
        {
            let mut ic = tx.prepare_cached("INSERT OR IGNORE INTO commits VALUES(?,?,?,?,?,?,?)")?;
            let mut icf = tx.prepare_cached("INSERT INTO commit_files VALUES(?,?)")?;
            let mut upd = tx.prepare_cached(
                "UPDATE files SET commit_sha=?, commit_date=? WHERE path=? AND (commit_date='' OR commit_date<=?)",
            )?;
            for (i, c) in commits.iter().enumerate() {
                // seq grows with age reversed: newest commit gets the largest seq
                let seq = base + n - i as i64;
                ic.execute(params![c.sha, c.short, c.date, c.subject, c.is_fix, c.is_revert, seq])?;
                for f in &c.files {
                    icf.execute(params![c.sha, f])?;
                }
                if c.is_fix {
                    entries::commit_entry(&tx, c)?;
                }
            }
            // newest first: the first commit seen for a path is its latest
            let mut seen = HashSet::new();
            for c in &commits {
                for f in &c.files {
                    if seen.insert(f.as_str()) {
                        upd.execute(params![c.short, c.date, f, c.date])?;
                    }
                }
            }
        }
        // recorded in the same transaction as the commits: a kill never leaves commits that are applied twice
        put_meta(&tx, "git_head", &head)?;
        tx.commit()?;
        Ok(commits.len())
    }

    /// Files of exactly one commit (`scope --commit <sha>`): no working-tree or untracked changes. None when `sha`
    /// is not a commit.
    pub fn commit_files(&self, sha: &str) -> Option<Vec<String>> {
        let full = sx::git::git(&self.repo, &["rev-parse", "--verify", "--quiet", &format!("{sha}^{{commit}}")])?;
        let d = sx::git::git_z(&self.repo, &["diff-tree", "-z", "--no-commit-id", "--name-only", "-r", "--root", "-m", "--first-parent", full.trim()])?;
        let mut seen = HashSet::new();
        Some(d.into_iter().filter(|x| seen.insert(x.clone())).collect())
    }

    /// True when `rev` names a commit (or, with a `..` range, both ends do): `git rev-parse --verify`.
    pub fn rev_exists(&self, rev: &str) -> bool {
        !rev.starts_with('-')
            && sx::git::git(&self.repo, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")]).is_some()
    }

    /// First token of a revision argument that git does not know (`A..B` and `A...B` are checked end by end).
    pub fn unknown_rev(&self, arg: &str) -> Option<String> {
        let rev = arg.split_whitespace().next()?;
        if rev.starts_with("--") {
            return None;
        }
        let ends: Vec<&str> = match rev.split_once("...").or_else(|| rev.split_once("..")) {
            Some((a, b)) => vec![a, b],
            None => vec![rev],
        };
        // an empty end of a range means HEAD
        for e in ends.into_iter().filter(|e| !e.is_empty()) {
            // a repository without commits: HEAD is unborn (changed_files then reads the staged changes)
            if e == "HEAD" && sx::git::head(&self.repo).is_none() {
                continue;
            }
            if !self.rev_exists(e) {
                return Some(e.to_string());
            }
        }
        None
    }

    /// Changed (modified + untracked) files vs `rev`, for `impact`. Without any commit (no HEAD) the staged files.
    pub fn changed_files(&self, rev: &str) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        // the two gits each walk the tree (stat of every tracked file / a directory walk): side by side, not in turn
        let repo = self.repo.clone();
        let (d, u) = std::thread::scope(|sc| {
            let others = sc.spawn(move || sx::git::git_z(&repo, &["ls-files", "-z", "--others", "--exclude-standard"]));
            let d = if rev == "HEAD" && sx::git::head(&self.repo).is_none() {
                sx::git::git_z(&self.repo, &["diff", "-z", "--name-only", "--cached"])
            } else {
                sx::git::git_z(&self.repo, &["diff", "-z", "--name-only", rev, "--"])
            };
            (d, others.join().ok().flatten())
        });
        out.extend(d.unwrap_or_default());
        if let Some(u) = u {
            out.extend(u.into_iter().filter(|l| walk::wanted(l, &self.exclude)));
        }
        let mut seen = HashSet::new();
        out.retain(|x| seen.insert(x.clone()));
        out
    }
}

/// The git half of the history stage: runs in its own thread while files are extracted.
struct HistoryJob {
    repo: PathBuf,
    head: String,
    old: Option<String>,
    full: bool,
}
struct HistoryFetch {
    head: String,
    commits: Vec<aix_extract::git::Commit>,
    append: bool,
}
impl HistoryJob {
    fn fetch(self) -> Option<HistoryFetch> {
        let HistoryJob { repo, head, old, full } = self;
        let append = !full
            && old.as_ref().is_some_and(|o| {
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&repo)
                    .args(["merge-base", "--is-ancestor", o, &head])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            });
        let commits = sx::git::history(&repo, if append { old.as_deref() } else { None });
        Some(HistoryFetch { head, commits, append })
    }
}

/// Hands out file indexes in order, never more than `window` ahead of the writer: bounds memory (items in flight)
/// and keeps the write order equal to the serial order (same rowids as a single-threaded build).
struct Gate {
    st: std::sync::Mutex<(usize, usize, bool)>, // (next to claim, next to write, abort)
    cv: std::sync::Condvar,
    window: usize,
}
impl Gate {
    fn new(window: usize) -> Gate {
        Gate { st: std::sync::Mutex::new((0, 0, false)), cv: std::sync::Condvar::new(), window }
    }
    fn claim(&self, n: usize) -> Option<usize> {
        let mut g = self.st.lock().ok()?;
        loop {
            if g.2 || g.0 >= n {
                return None;
            }
            if g.0 < g.1 + self.window {
                g.0 += 1;
                return Some(g.0 - 1);
            }
            g = self.cv.wait(g).ok()?;
        }
    }
    fn advance(&self, written: usize) {
        if let Ok(mut g) = self.st.lock() {
            g.1 = written;
        }
        self.cv.notify_all();
    }
}
struct AbortOnDrop<'a>(&'a Gate);
impl Drop for AbortOnDrop<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.0.st.lock() {
            g.2 = true;
        }
        self.0.cv.notify_all();
    }
}

/// One file after the parallel stages: read, hashed, extracted, redacted, its search entries built.
struct Prepared {
    meta: Result<FileMeta, (String, String)>,
    entries: Vec<entries::Built>,
    memo: HashMap<String, String>,
}

fn prepare_file(
    repo: &Path,
    exts: &[Box<dyn Extractor>],
    l: &walk::Listed,
    known: &HashMap<String, (String, i64, i64)>,
    full: bool,
) -> Prepared {
    let unread = |e: std::io::Error| (l.path.clone(), format!("unreadable: {}", e.kind().to_string().to_lowercase()));
    let bytes = {
        let _s = crate::par::span("cpu:read");
        match std::fs::read(repo.join(&l.path)) {
            Ok(b) => b,
            Err(e) => return Prepared { meta: Err(unread(e)), entries: vec![], memo: HashMap::new() },
        }
    };
    let hash = {
        let _s = crate::par::span("cpu:hash");
        blake3::hash(&bytes).to_hex()[..32].to_string()
    };
    let same = known.get(&l.path).is_some_and(|(h, _, _)| *h == hash);
    let text = crate::query::decode_text(&bytes);
    let lines = text.lines().count();
    let (rows, entries, memo) = if same && !full {
        (None, vec![], HashMap::new())
    } else {
        let sf = SourceFile::new(l.path.clone(), text);
        let rows = {
            let _s = crate::par::span("cpu:extract");
            sx::extract_file(repo, exts, &sf)
        };
        let _s = crate::par::span("cpu:redact");
        let kind = walk::file_kind(&l.path);
        let mut entries = entries::build_file_entries(&l.path, kind, &rows);
        let memo = prime_redactions(&rows);
        entries.extend(entries::build_code_chunks(&l.path, &sf.text, &rows, &memo));
        (Some(rows), entries, memo)
    };
    Prepared { meta: Ok(FileMeta { path: l.path.clone(), hash, mtime_ns: l.mtime_ns, bytes: l.size, lines, rows }), entries, memo }
}

pub fn chrono_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

fn delete_file(tx: &rusqlite::Transaction, path: &str) -> Result<()> {
    crate::codegraph::mark_dirty_file(tx, path)?;
    crate::datamodel::mark_dirty_file(tx, path)?;
    for t in FILE_TABLES.iter().chain(crate::codegraph::FILE_TABLES).chain(crate::datamodel::FILE_TABLES) {
        tx.prepare_cached(&format!("DELETE FROM {t} WHERE file=?"))?.execute([path])?;
    }
    tx.prepare_cached("DELETE FROM features WHERE file=? AND derived=0")?.execute([path])?;
    tx.prepare_cached("DELETE FROM entries WHERE file=? AND src IN (0,3)")?.execute([path])?;
    Ok(())
}

/// Resolve a module specifier from `file` to a repo file path ('' if not local / not found).
pub fn resolve_import(file: &str, source: &str, files: &HashSet<String>) -> String {
    let base: Option<String> = if source.starts_with('.') {
        let dir = file.rsplit_once('/').map(|x| x.0).unwrap_or("");
        Some(normalize(&format!("{dir}/{source}")))
    } else if let Some(rest) = source.strip_prefix("@/").or_else(|| source.strip_prefix("~/")) {
        // alias to the nearest `src/` above the importing file
        file.find("src/").map(|i| normalize(&format!("{}src/{rest}", &file[..i])))
    } else {
        None
    };
    let Some(base) = base else {
        return String::new();
    };
    let base = base.trim_end_matches(".js").to_string();
    for c in [
        base.clone(),
        format!("{base}.tsx"),
        format!("{base}.ts"),
        format!("{base}.jsx"),
        format!("{base}.js"),
        format!("{base}.mjs"),
        format!("{base}/index.tsx"),
        format!("{base}/index.ts"),
        format!("{base}/index.js"),
    ] {
        if files.contains(&c) {
            return c;
        }
    }
    String::new()
}

fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

fn rd(s: &str) -> String {
    crate::par::rd(s)
}

/// Redact every string `insert_rows` (and the code-graph and data-model inserts) will redact, in the worker
/// thread: the writer then finds each result in the memo. Missing a field only costs speed, never correctness.
fn prime_redactions(r: &Rows) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    let mut p = |s: &str| {
        if !s.is_empty() && !m.contains_key(s) {
            m.insert(s.to_string(), aix_extract::text::redact(s));
        }
    };
    r.ui_strings.iter().for_each(|x| p(&x.text));
    for x in &r.sections { p(&x.heading); p(&x.body); }
    for x in &r.scripts { p(&x.header); p(&x.usage); p(&x.flags); }
    for x in &r.tasks { p(&x.heading); p(&x.text); }
    for x in &r.consts { for v in &x.values { p(v); } }
    for x in &r.menu { p(&x.keywords); p(&x.tooltip); }
    for x in &r.tests { p(&x.title); p(&x.texts.join(" | ")); }
    for x in &r.test_steps { p(&x.value); }
    for x in &r.bugs { p(&x.title); p(&x.text); }
    for x in &r.features { p(&x.purpose); p(&x.extra); }
    for x in &r.notes { p(&x.text); }
    for x in &r.members { p(&x.sig); p(&x.annos.join(", ")); }
    for x in &r.refs { p(&x.recv); }
    for x in &r.entity_fields { p(&x.flags); }
    for x in &r.migrations { p(&x.detail); }
    m
}

fn j(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn insert_rows(tx: &rusqlite::Transaction, r: &Rows, files: &HashSet<String>) -> Result<()> {
    macro_rules! ins {
        ($sql:expr, $items:expr, |$x:ident| $p:expr) => {{
            let mut st = tx.prepare_cached($sql)?;
            for $x in $items {
                st.execute($p)?;
            }
        }};
    }
    ins!("INSERT INTO symbols VALUES(?,?,?,?,?,?,?)", &r.symbols, |x| params![
        x.file,
        x.line,
        x.end_line,
        x.name,
        x.kind,
        x.exported,
        x.container
    ]);
    ins!("INSERT INTO ui_strings VALUES(?,?,?,?,?)", &r.ui_strings, |x| params![
        x.file,
        x.line,
        x.kind,
        rd(&x.text),
        x.component
    ]);
    ins!("INSERT INTO sections VALUES(?,?,?,?,?,?)", &r.sections, |x| params![
        x.file, x.line, x.end_line, x.level, rd(&x.heading), rd(&x.body)
    ]);
    ins!("INSERT OR REPLACE INTO scripts VALUES(?,?,?,?,?)", &r.scripts, |x| params![
        x.file, x.kind, rd(&x.header), rd(&x.usage), rd(&x.flags)
    ]);
    ins!("INSERT INTO script_refs VALUES(?,?,?)", &r.script_refs, |x| params![x.file, x.line, x.norm_path]);
    ins!("INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?)", &r.tasks, |x| params![
        x.file, x.line, x.status, x.kind, x.round, x.sha, rd(&x.heading), rd(&x.text)
    ]);
    ins!("INSERT INTO imports VALUES(?,?,?,?,?)", &r.imports, |x| params![
        x.file,
        x.line,
        x.name,
        x.source,
        resolve_import(&x.file, &x.source, files)
    ]);
    ins!("INSERT INTO calls VALUES(?,?,?,?)", &r.calls, |x| params![x.file, x.line, x.object, x.member]);
    ins!("INSERT INTO api_calls VALUES(?,?,?,?,?,?,?)", &r.api_calls, |x| params![
        x.file,
        x.line,
        x.object,
        x.name,
        x.method,
        x.path,
        x.norm_path
    ]);
    ins!("INSERT INTO consts VALUES(?,?,?,?)", &r.consts, |x| params![x.file, x.line, x.name, j(&x.values.iter().map(|v| rd(v)).collect::<Vec<_>>())]);
    ins!("INSERT INTO routes(file,line,path,component,roles,role_expr,feature,redirect,roles_raw) VALUES(?,?,?,?,?,?,?,?,?)", &r.routes,
        |x| params![x.file, x.line, x.path, x.component.clone().unwrap_or_default(), x.roles.join(","), x.role_expr, x.feature, x.redirect, j(&x.roles)]);
    ins!("INSERT INTO menu VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", &r.menu, |x| params![
        x.file,
        x.line,
        x.nav,
        x.group,
        x.label,
        x.path,
        x.roles.join(","),
        x.group_roles.join(","),
        rd(&x.keywords),
        rd(&x.tooltip),
        x.tabs.join("; "),
        j(&x.roles),
        j(&x.group_roles)
    ]);
    ins!("INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?,?)", &r.endpoints, |x| params![
        x.file,
        x.line,
        x.method,
        x.path,
        x.norm_path,
        x.class,
        x.handler,
        x.roles.join(","),
        j(&x.roles)
    ]);
    ins!("INSERT INTO tests VALUES(?,?,?,?,?,?,?)", &r.tests, |x| params![
        x.file,
        x.line,
        x.id,
        rd(&x.title),
        x.role,
        x.routes.join(" "),
        rd(&x.texts.join(" | "))
    ]);
    ins!("INSERT INTO test_steps VALUES(?,?,?,?,?)", &r.test_steps, |x| params![
        x.file, x.line, x.sid, x.kind, rd(&x.value)
    ]);
    ins!("INSERT INTO bugs VALUES(?,?,?,?,?,?,?,?,?,?)", &r.bugs, |x| params![
        x.file, x.line, x.kind, x.date, x.severity, x.status, x.round, x.sha, rd(&x.title), rd(&x.text)
    ]);
    ins!(
        "INSERT INTO features(file,line,kind,name,route,roles,purpose,extra) VALUES(?,?,?,?,?,?,?,?)",
        &r.features,
        |x| params![x.file, x.line, x.kind, x.name, x.route, x.roles, rd(&x.purpose), rd(&x.extra)]
    );
    ins!("INSERT INTO db_tables VALUES(?,?,?,?)", &r.db_tables, |x| params![x.file, x.line, x.table, x.op]);
    ins!("INSERT INTO notes VALUES(?,?,?,?,?)", &r.notes, |x| params![x.file, x.line, x.kind, x.reference, rd(&x.text)]);
    crate::codegraph::insert(tx, r)?;
    crate::datamodel::insert(tx, r)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_resolve() {
        let files: HashSet<String> = ["web/src/pages/A.tsx", "web/src/lib/api.ts", "web/src/components/x/index.tsx"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(resolve_import("web/src/App.tsx", "./pages/A", &files), "web/src/pages/A.tsx");
        assert_eq!(resolve_import("web/src/pages/A.tsx", "../lib/api", &files), "web/src/lib/api.ts");
        assert_eq!(resolve_import("web/src/pages/A.tsx", "@/components/x", &files), "web/src/components/x/index.tsx");
        assert_eq!(resolve_import("web/src/pages/A.tsx", "react", &files), "");
    }
}

#[cfg(test)]
mod wal_tests {
    use super::*;

    /// A main file with only a header page and the whole schema in an un-checkpointed `-wal`, as a first build
    /// killed before its first checkpoint leaves it. The connection is leaked so closing cannot checkpoint.
    fn killed_first_build(dir: &Path, ours: bool) -> PathBuf {
        let db = dir.join("index.db");
        let c = Connection::open(&db).unwrap();
        c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;").unwrap();
        c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);").unwrap();
        if ours {
            c.execute("INSERT INTO meta VALUES('app', ?)", [APP_MARKER]).unwrap();
        }
        std::mem::forget(c);
        assert!(std::fs::metadata(sidecar(&db, "-wal")).unwrap().len() > 0);
        db
    }

    #[test]
    fn a_killed_first_build_reopens_and_a_foreign_log_is_still_refused() {
        let d = tempfile::tempdir().unwrap();
        let db = killed_first_build(d.path(), true);
        refuse_foreign_wal(&db).expect("our own interrupted first build must reopen");
        let leftovers: Vec<_> = std::fs::read_dir(d.path()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with(".aix-walcheck-")).collect();
        assert!(leftovers.is_empty(), "the temp copy is removed");
        let d2 = tempfile::tempdir().unwrap();
        let db2 = killed_first_build(d2.path(), false);
        assert!(refuse_foreign_wal(&db2).is_err(), "a log that is not an aix index stays refused");
    }

    /// ... killed during its first checkpoint: the log's page 1 already in the main file, which alone now lists
    /// tables whose pages only the log holds (seen on Windows, where PowerShell kills a piped build mid-write)
    #[test]
    fn a_first_build_killed_mid_checkpoint_reopens() {
        for ours in [true, false] {
            let d = tempfile::tempdir().unwrap();
            let db = killed_first_build(d.path(), ours);
            let wal = std::fs::read(sidecar(&db, "-wal")).unwrap();
            let ps = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
            let page1 = wal[32..].chunks(24 + ps).filter(|f| f.len() == 24 + ps && f[..4] == [0, 0, 0, 1]).last().unwrap()[24..].to_vec();
            let mut main = std::fs::read(&db).unwrap();
            main.resize(main.len().max(ps), 0);
            main[..ps].copy_from_slice(&page1);
            std::fs::write(&db, main).unwrap();
            assert_eq!(refuse_foreign_wal(&db).is_ok(), ours, "ours reopens, a foreign one stays refused");
        }
    }
}
