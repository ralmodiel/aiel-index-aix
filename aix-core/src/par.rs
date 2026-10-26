//! Parallelism knobs and optional per-stage timing for the update pipeline.
//!
//! `AIX_THREADS=n` sets the worker count (default: min(available cores, 16)); `AIX_LOW=1` (watcher and post-commit
//! paths) caps it at 2 and lowers the process priority. `AIX_PROFILE=1` prints a per-stage table to stderr.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const CAP: usize = 16;
static OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Worker threads for this process.
pub fn threads() -> usize {
    let o = OVERRIDE.load(Ordering::Relaxed);
    if o > 0 {
        return o;
    }
    let env = std::env::var("AIX_THREADS").ok().and_then(|v| v.trim().parse::<usize>().ok()).filter(|n| *n > 0);
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    // an explicit memory budget also bounds the workers (each holds one file's parse and rows): ~96 MB apiece
    let mem = explicit_budget_mb().map(|mb| ((mb / 96) as usize).max(1)).unwrap_or(usize::MAX);
    let n = env.unwrap_or_else(|| cores.min(CAP).min(mem));
    if low() { n.min(env.unwrap_or(2)) } else { n }
}

/// Memory budget of an update in MB: `AIX_MAX_MEMORY` (`aix update --max-memory`; plain MB, or with a G/M suffix),
/// else half of what the machine (or the cgroup) has available when the update starts. It caps the extraction
/// workers, SQLite's page cache and sorter, and switches the code graph to batches resolved against the members
/// they need (read from the index) when the whole graph would not fit.
pub fn mem_budget_mb() -> u64 {
    static B: OnceLock<u64> = OnceLock::new();
    *B.get_or_init(|| explicit_budget_mb().unwrap_or_else(|| (available_mb() / 2).max(256)))
}

/// The budget the user set (`AIX_MAX_MEMORY`), if any.
pub fn explicit_budget_mb() -> Option<u64> {
    let v = std::env::var("AIX_MAX_MEMORY").ok()?;
    parse_mb(&v)
}

/// "2048", "2048M", "2G", "1.5g" -> MB (None for anything else or 0).
pub fn parse_mb(v: &str) -> Option<u64> {
    let v = v.trim().to_ascii_lowercase();
    let (num, mul) = match v.strip_suffix(['g']).or_else(|| v.strip_suffix("gb")) {
        Some(n) => (n.to_string(), 1024.0),
        None => (v.trim_end_matches("mb").trim_end_matches('m').to_string(), 1.0),
    };
    num.trim().parse::<f64>().ok().map(|n| (n * mul) as u64).filter(|n| *n > 0)
}

/// MemAvailable, lowered to the cgroup v2 limit minus its current use when one is set (containers). 4096 when unknown.
fn available_mb() -> u64 {
    let mut avail = crate::sys::mem_available_mb().unwrap_or(4096);
    let rd = |p: &str| std::fs::read_to_string(p).ok().and_then(|s| s.trim().parse::<u64>().ok());
    if let (Some(max), Some(cur)) = (rd("/sys/fs/cgroup/memory.max"), rd("/sys/fs/cgroup/memory.current")) {
        avail = avail.min(max.saturating_sub(cur) / (1024 * 1024));
    }
    avail
}

/// AIX_PROGRESS=1 (`aix update --progress`): progress lines on stderr during long updates.
pub fn progress() -> bool {
    std::env::var("AIX_PROGRESS").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// One progress line (the stage an update enters), only with AIX_PROGRESS=1.
pub fn progress_note(what: &str) {
    if progress() {
        eprintln!("aix: {what}");
    }
}

/// Background mode (watcher, post-commit hook): few threads, low priority.
pub fn low() -> bool {
    std::env::var("AIX_LOW").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Pin the thread count (tests, benchmarks).
pub fn set_threads(n: usize) {
    OVERRIDE.store(n, Ordering::Relaxed);
}

static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

/// The shared pool: sized once from `threads()`.
pub fn pool() -> &'static rayon::ThreadPool {
    POOL.get_or_init(|| rayon::ThreadPoolBuilder::new().num_threads(threads()).build().expect("thread pool"))
}

static STAGES: Mutex<Vec<(&'static str, f64)>> = Mutex::new(Vec::new());

fn profiling() -> bool {
    static P: OnceLock<bool> = OnceLock::new();
    *P.get_or_init(|| std::env::var("AIX_PROFILE").is_ok_and(|v| !v.is_empty() && v != "0"))
}

/// Test hook: `AIX_TEST_STAGE_PAUSE_MS` sleeps between the committed stages of an update (files, derived layer, code
/// graph), so a test can read while an update is half applied. Unset: nothing.
pub fn test_pause() {
    static MS: OnceLock<u64> = OnceLock::new();
    let ms = *MS.get_or_init(|| std::env::var("AIX_TEST_STAGE_PAUSE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0));
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// `AIX_PROFILE=2`: also print per-stage detail lines.
pub fn verbose() -> bool {
    profiling() && std::env::var("AIX_PROFILE").is_ok_and(|v| v == "2")
}

/// Time a stage until dropped (adds to the stage's total when it runs more than once).
pub struct Span(&'static str, Instant);
pub fn span(name: &'static str) -> Span {
    Span(name, Instant::now())
}
impl Drop for Span {
    fn drop(&mut self) {
        if profiling() {
            if std::env::var("AIX_PROFILE").is_ok_and(|v| v == "2") && !self.0.starts_with("cpu:") && !self.0.starts_with("w:") {
                eprintln!("  .. {} done in {:.0} ms{}", self.0, self.1.elapsed().as_secs_f64() * 1000.0, mem_note());
            }
            if let Ok(mut s) = STAGES.lock() {
                s.push((self.0, self.1.elapsed().as_secs_f64() * 1000.0));
            }
        }
    }
}

/// Hand freed heap back to the OS between update stages (glibc keeps it per thread arena otherwise), so the
/// next stage's peak does not stack on the previous stage's leftovers. No-op elsewhere.
pub fn trim() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim only releases free pages of the allocator; it takes no pointers.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// ", rss N MB, peak M MB" from /proc/self/status (Linux), so `AIX_PROFILE=2` shows which stage grows memory.
fn mem_note() -> String {
    let Ok(s) = std::fs::read_to_string("/proc/self/status") else { return String::new() };
    let kb = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok());
    match (kb("VmRSS:"), kb("VmHWM:")) {
        (Some(r), Some(h)) => format!(", rss {} MB, peak {} MB", r / 1024, h / 1024),
        _ => String::new(),
    }
}

/// Print and clear the stage table (no-op unless AIX_PROFILE is set).
pub fn report() {
    if !profiling() {
        return;
    }
    let Ok(mut s) = STAGES.lock() else { return };
    let mut order: Vec<&'static str> = vec![];
    for (n, _) in s.iter() {
        if !order.contains(n) {
            order.push(n);
        }
    }
    for n in order {
        let t: f64 = s.iter().filter(|(m, _)| *m == n).map(|(_, v)| v).sum();
        eprintln!("stage {n:<22} {t:>9.1} ms");
    }
    s.clear();
}

thread_local! {
    static MEMO: std::cell::RefCell<std::collections::HashMap<String, String>> = Default::default();
}

/// Hand the writer thread the redactions a worker already computed for the file about to be inserted.
pub fn set_memo(m: std::collections::HashMap<String, String>) {
    MEMO.with(|c| *c.borrow_mut() = m);
}

/// `text::redact`, answered from the worker's precomputed results when the exact string was primed (the writer
/// thread then does no redaction work); computed on the spot otherwise, so the result never depends on priming.
pub fn rd(s: &str) -> String {
    let hit = MEMO.with(|c| {
        let c = c.borrow();
        if c.is_empty() { None } else { c.get(s).cloned() }
    });
    hit.unwrap_or_else(|| aix_extract::text::redact(s))
}

/// Apply AIX_THREADS / AIX_LOW to rayon's global pool (queries' parallel grep, pattern scans) and the priority.
/// Without either variable nothing changes: rayon's default (one thread per core) stays.
pub fn init_global() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let set = std::env::var("AIX_THREADS").is_ok_and(|v| !v.is_empty());
        if low() {
            crate::sys::be_nice();
        }
        if set || low() {
            let _ = rayon::ThreadPoolBuilder::new().num_threads(threads()).build_global();
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn memory_sizes_parse() {
        assert_eq!(super::parse_mb("800"), Some(800));
        assert_eq!(super::parse_mb("800M"), Some(800));
        assert_eq!(super::parse_mb("2G"), Some(2048));
        assert_eq!(super::parse_mb("1.5g"), Some(1536));
        assert_eq!(super::parse_mb("lots"), None);
        assert_eq!(super::parse_mb("0"), None);
    }
}
