//! `aix logs` storage side: registration (.aix/logs.toml), path safety, the separate log store (.aix/logs.db, 0600),
//! incremental ingest with rotation handling, redaction before storage, templating, budgets and pruning, the watcher
//! loop. Pastes (`.aix/pastes.db`) reuse the same store and ingest. Queries and commands live in `logq.rs`.
//!
//! Privacy: every stored text field goes through `redact_text` (the single wrapper around the shared redactor plus the
//! log-only PII scrub) BEFORE any INSERT; nothing raw is ever written, hashed or logged. The store is a separate file so
//! pruning/vacuuming never touches the code index.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use aix_extract::logparse::{self, Format};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

pub const DEFAULT_GLOBAL_MB: u64 = 64;
pub const DEFAULT_PER_LOG_MB: u64 = 16;
pub const DEFAULT_MAX_ROWS: u64 = 200_000;
pub const DEFAULT_RETAIN_DAYS: u64 = 7;
pub const PASTE_GLOBAL_MB: u64 = 32;
pub const PASTE_RETAIN_DAYS: u64 = 14;
/// logs above this size stop storing DEBUG/TRACE lines (aggregates only) unless `store_debug = true`
pub const DEBUG_AUTO_BYTES: u64 = 8 * 1024 * 1024;
const ROW_OVERHEAD: usize = 96;
const BODY_MAX_BYTES: usize = 12_000;
const BODY_MAX_LINES: usize = 120;
pub const ATTACH_MAX_BYTES: u64 = 50 * 1024 * 1024;
pub const ATTACH_TEXT_MAX: usize = 8 * 1024 * 1024;
const CHUNK: usize = 4 * 1024 * 1024;

// ---- helpers ------------------------------------------------------------------------------------------------------

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Offset (seconds east of UTC) of the local time zone at `epoch`.
pub fn local_offset(epoch: i64) -> i64 {
    crate::sys::local_time(epoch).map_or(0, |(off, _)| off)
}

/// `MM-DD HH:MM:SS` in local time ("-" for 0).
pub fn fmt_ts(epoch: i64) -> String {
    if epoch <= 0 {
        return "-".into();
    }
    match crate::sys::local_time(epoch) {
        Some((_, [mo, d, h, mi, s])) => format!("{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"),
        None => epoch.to_string(),
    }
}

pub fn human(n: i64) -> String {
    let n = n.max(0) as f64;
    if n >= 1048576.0 {
        format!("{:.1} MB", n / 1048576.0)
    } else if n >= 1024.0 {
        format!("{:.0} KB", n / 1024.0)
    } else {
        format!("{n:.0} B")
    }
}

pub fn ago(secs: i64) -> String {
    let s = secs.max(0);
    if s < 90 {
        format!("{s}s")
    } else if s < 5400 {
        format!("{}m", s / 60)
    } else if s < 172800 {
        format!("{}h", s / 3600)
    } else {
        format!("{}d", s / 86400)
    }
}

/// `10m`, `2h`, `3d`, `1w`, `45s` -> seconds.
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    let (n, u) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = n.parse().ok().filter(|n: &i64| *n >= 0 && !s.starts_with('+'))?;
    Some(n * match u {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        "y" => 31_536_000,
        _ => return None,
    })
}

/// `10m` / `1h` (ago) or an ISO date-time (`2025-03-01`, `2025-03-01T10:00`, local time) -> epoch seconds.
pub fn parse_since(s: &str, now: i64) -> Option<i64> {
    if let Some(d) = parse_duration(s) {
        return Some(now - d);
    }
    let mut t = s.trim().replace('T', " ");
    if t.len() == 10 {
        t.push_str(" 00:00:00");
    } else if t.len() == 16 {
        t.push_str(":00");
    }
    let (e, known, _) = logparse::parse_ts(&t)?;
    Some(if known { e } else { e - local_offset(e) })
}

fn blake_hex(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

/// THE match rule for every user regex over stored entries (grep, errors, await, alert, tail --until, -x/--only): the
/// message, the entry body (first line included), `<LEVEL> <msg>` and `<LEVEL> <logger> <msg>`, so `Started|ERROR` and
/// `^WARN` work the way they do on the raw line.
pub fn entry_matches(re: &regex::Regex, level: i64, logger: &str, msg: &str, body: &str) -> bool {
    if re.is_match(msg) || (!body.is_empty() && re.is_match(body)) {
        return true;
    }
    let lv = logparse::level_name(level.clamp(0, 5) as u8);
    if re.is_match(&format!("{lv} {msg}")) {
        return true;
    }
    !logger.is_empty() && re.is_match(&format!("{lv} {logger} {msg}"))
}

/// Stable template id: 8 hex chars of the template text hash.
pub fn tid_of(tpl: &str) -> String {
    blake_hex(tpl.as_bytes())[..8].to_string()
}

/// THE redaction wrapper for everything `aix logs` / `aix paste` stores: log-only PII scrub (emails, auth/cookie header
/// values, IPs), then the shared redactor. Switching to the shared `redact_line` / `redact_block` API is a change here only.
pub fn redact_text(s: &str, keep_ips: bool) -> String {
    let scrubbed: Vec<String> = s.split('\n').map(|l| logparse::pii_scrub(l, keep_ips)).collect();
    aix_extract::redact::redact_block(&scrubbed.join("\n"))
}

fn clip_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(n.saturating_sub(1)).collect();
        o.push('…');
        o
    }
}

// ---- registration (.aix/logs.toml) -----------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Budget {
    pub global_mb: Option<u64>,
    pub per_log_mb: Option<u64>,
    pub max_rows: Option<u64>,
    pub retain_days: Option<u64>,
    /// "auto" (default: DEBUG/TRACE lines are aggregated only once a log passes 8 MB), "true" or "false"
    pub store_debug: Option<String>,
    pub paste_global_mb: Option<u64>,
    pub paste_retain_days: Option<u64>,
    /// hours of idleness after which a prompt-named live log (session) is unregistered (default 4)
    pub session_hours: Option<u64>,
    /// auto-unwatch defaults in hours (0 = never): no new lines for `watch_idle_hours` (default 2), not queried for `watch_unqueried_hours` (default 24)
    pub watch_idle_hours: Option<u64>,
    pub watch_unqueried_hours: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Spec {
    pub name: String,
    /// absolute path as registered (file, directory or glob in the last component)
    pub path: String,
    /// file | dir | glob
    pub kind: String,
    pub format: String,
    pub max_mb: Option<u64>,
    pub retain_days: Option<u64>,
    pub max_rows: Option<u64>,
    /// registered with `--allow-dotfile` (a file under a hidden folder of $HOME; the hard deny list still applies)
    #[serde(default)]
    pub allow_dot: bool,
    #[serde(default)]
    pub keep_ips: bool,
    #[serde(default)]
    pub added: i64,
    /// registered automatically for a live file the user named (session only: expires after `session_hours` idle)
    #[serde(default)]
    pub session: bool,
    /// watch state: `paused` = the watcher no longer follows it (data and registration stay; queries still refresh on demand)
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub pause_reason: String,
    #[serde(default)]
    pub paused_at: i64,
    /// the next prompt's hook says once that the watch was stopped
    #[serde(default)]
    pub notice_pending: bool,
    #[serde(default)]
    pub watch_started: i64,
    /// auto-unwatch conditions (None = the config default for idle/unqueried, otherwise off)
    pub idle_secs: Option<i64>,
    pub unqueried_secs: Option<i64>,
    pub until_ts: Option<i64>,
    pub until_match: Option<String>,
    pub stop_lines: Option<i64>,
    pub stop_bytes: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cfg {
    #[serde(default)]
    pub budget: Budget,
    #[serde(default, rename = "log")]
    pub logs: Vec<Spec>,
}

/// Effective limits for one log: the tightest of the per-log value, the budget section and the defaults.
#[derive(Debug, Clone, Copy)]
pub struct Eff {
    pub cap_bytes: i64,
    pub max_rows: i64,
    pub retain_secs: i64,
    pub store_debug: Option<bool>,
}

impl Cfg {
    pub fn eff(&self, s: &Spec) -> Eff {
        let mb = |a: Option<u64>, b: Option<u64>, c: u64| a.unwrap_or(c).min(b.unwrap_or(c)).min(c.max(1));
        let _ = mb;
        let cap = [s.max_mb, self.budget.per_log_mb, self.budget.global_mb].iter().flatten().copied().min().unwrap_or(DEFAULT_PER_LOG_MB.min(DEFAULT_GLOBAL_MB));
        let rows = [s.max_rows, self.budget.max_rows].iter().flatten().copied().min().unwrap_or(DEFAULT_MAX_ROWS);
        let days = [s.retain_days, self.budget.retain_days].iter().flatten().copied().min().unwrap_or(DEFAULT_RETAIN_DAYS);
        let sd = match self.budget.store_debug.as_deref() {
            Some("true") | Some("on") | Some("yes") => Some(true),
            Some("false") | Some("off") | Some("no") => Some(false),
            _ => None,
        };
        Eff { cap_bytes: cap as i64 * 1048576, max_rows: rows as i64, retain_secs: days as i64 * 86400, store_debug: sd }
    }
    pub fn global_cap(&self) -> i64 {
        self.budget.global_mb.unwrap_or(DEFAULT_GLOBAL_MB) as i64 * 1048576
    }
    pub fn find(&self, key: &str) -> Option<&Spec> {
        let alt = key.replace(':', "-"); // file:4 names the session log file-4
        self.logs.iter().find(|s| s.name == key || s.path == key || s.name == alt)
    }
}

pub fn dir_of(ix_db: &Path) -> PathBuf {
    ix_db.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(".aix"))
}
pub fn toml_path(dir: &Path) -> PathBuf {
    dir.join("logs.toml")
}
pub fn logs_db_path(dir: &Path) -> PathBuf {
    dir.join("logs.db")
}
pub fn pastes_db_path(dir: &Path) -> PathBuf {
    dir.join("pastes.db")
}

pub fn load_cfg(dir: &Path) -> Cfg {
    std::fs::read_to_string(toml_path(dir)).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

pub fn save_cfg(dir: &Path, c: &Cfg) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = toml_path(dir);
    let tmp = dir.join(format!("logs.toml.tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let body = format!("# aix log registrations (repo-local; managed by `aix logs add|rm`)\n{}", toml::to_string_pretty(c)?);
    {
        use std::io::Write;
        let mut f = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(&tmp)?;
        f.write_all(body.as_bytes())?;
    }
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Per-repo opt-out: `pastes = "off"` in .aix/config.toml (or logs.toml) or env AIX_PASTES=0.
pub fn pastes_enabled(dir: &Path) -> bool {
    if std::env::var("AIX_PASTES").map(|v| matches!(v.as_str(), "0" | "off" | "false")).unwrap_or(false) {
        return false;
    }
    for f in ["config.toml", "logs.toml"] {
        if let Some(v) = std::fs::read_to_string(dir.join(f)).ok().and_then(|t| t.parse::<toml::Table>().ok()).and_then(|t| t.get("pastes").cloned()) {
            let off = match v {
                toml::Value::String(s) => matches!(s.as_str(), "off" | "false" | "0" | "no"),
                toml::Value::Boolean(b) => !b,
                _ => false,
            };
            if off {
                return false;
            }
        }
    }
    true
}

// ---- displayed paths -------------------------------------------------------------------------------------------------

/// A path component that looks like (or contains) a secret: a long mixed letters+digits run with high entropy.
fn secretish_component(c: &str) -> bool {
    c.split(|ch: char| !ch.is_ascii_alphanumeric()).any(|run| {
        if run.len() < 16 || !run.bytes().any(|b| b.is_ascii_digit()) || !run.bytes().any(|b| b.is_ascii_alphabetic()) {
            return false;
        }
        let mut freq = [0u32; 256];
        for b in run.bytes() {
            freq[b as usize] += 1;
        }
        let n = run.len() as f64;
        let h: f64 = freq.iter().filter(|f| **f > 0).map(|f| {
            let p = *f as f64 / n;
            -p * p.log2()
        }).sum();
        h >= 3.3
    })
}

/// THE way a path is shown or stored for display: `~` for $HOME, the shared redactor over the whole path, and every
/// component that looks like a secret replaced by `***`. Never used to open a file.
pub fn display_path(p: &str) -> String {
    let mut s = p.to_string();
    if let Some(h) = home() {
        let h = h.to_string_lossy().to_string();
        if !h.is_empty() && h != "/" && (s == h || s.starts_with(&format!("{h}/"))) {
            s = format!("~{}", &s[h.len()..]);
        }
    }
    let comps: Vec<String> = s.split('/').map(|c| if secretish_component(c) { "***".to_string() } else { c.to_string() }).collect();
    let joined = comps.join("/");
    redact_text(&joined, true)
}

/// Private salted hash of a real path (re-find an attachment's row without storing the path): the salt lives in the store.
pub fn path_hash(conn: &Connection, path: &str) -> String {
    let salt: Option<String> = conn.query_row("SELECT value FROM meta WHERE key='path_salt'", [], |r| r.get(0)).ok();
    let salt = salt.unwrap_or_else(|| {
        let mut b = [0u8; 16];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut b);
        }
        // std's hash keys come from the OS random source on every platform (Windows has no /dev/urandom)
        let r = std::hash::BuildHasher::hash_one(&std::collections::hash_map::RandomState::new(), 0u8);
        let v = blake_hex(&[&b[..], &r.to_le_bytes()[..], &now().to_le_bytes()[..], &std::process::id().to_le_bytes()[..]].concat())[..32].to_string();
        let _ = conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('path_salt',?)", [&v]);
        conn.query_row("SELECT value FROM meta WHERE key='path_salt'", [], |r| r.get(0)).unwrap_or(v)
    });
    blake_hex(format!("{salt}\0{path}").as_bytes())[..24].to_string()
}

// ---- path safety -----------------------------------------------------------------------------------------------------

fn home() -> Option<PathBuf> {
    crate::sys::home().filter(|p| p.is_absolute())
}

fn denied_roots() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run/secrets", "/var/lib/docker", "/var/run/secrets", "/var/mail", "/var/spool/mail", "/var/spool/cron"].iter().map(PathBuf::from).collect();
    if let Some(h) = home() {
        for d in [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud", ".password-store", ".netrc", ".pgpass", ".config/gh", ".npmrc", ".terraform.d", ".local/share/keyrings", ".local/share/keychains", ".config/1Password", ".config/Bitwarden", ".config/keepassxc", ".config/op", ".config/rclone", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge", ".config/vivaldi", ".mozilla", ".thunderbird", ".mail", "Mail", "Library/Keychains", "Library/Application Support/Google/Chrome", "snap/firefox", "snap/chromium", ".var/app/org.mozilla.firefox", ".var/app/com.google.Chrome", ".msmtprc", ".mbsyncrc", ".fetchmailrc", ".vault-token", ".boto", ".s3cfg", ".databrickscfg", ".config/doctl", ".oci", ".config/heroku", ".config/stripe", ".m2/settings.xml", ".config/Signal", ".docker/config.json", ".kube/config"] {
            v.push(h.join(d));
        }
        // Windows keeps the same kinds of stores under AppData, which is no dot-folder
        if cfg!(windows) {
            for d in ["AppData/Roaming/Microsoft/Credentials", "AppData/Local/Microsoft/Credentials", "AppData/Roaming/Microsoft/Protect", "AppData/Roaming/Microsoft/Crypto", "AppData/Roaming/Microsoft/SystemCertificates", "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine", "AppData/Roaming/Microsoft/Outlook", "AppData/Local/Microsoft/Outlook", "AppData/Roaming/GitHub CLI", "AppData/Roaming/gcloud", "AppData/Roaming/doctl", "AppData/Roaming/rclone", "AppData/Roaming/1Password", "AppData/Local/1Password", "AppData/Roaming/Bitwarden", "AppData/Roaming/KeePass", "AppData/Roaming/KeePassXC", "AppData/Roaming/Signal", "AppData/Local/Google/Chrome/User Data", "AppData/Local/Microsoft/Edge/User Data", "AppData/Local/BraveSoftware", "AppData/Local/Vivaldi", "AppData/Roaming/Mozilla", "AppData/Roaming/Thunderbird"] {
                v.push(h.join(d));
            }
        }
    }
    v
}

fn allowed_roots(repo: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![repo.to_path_buf()];
    if let Some(h) = home() {
        v.push(h);
    }
    // Unix only: on Windows `/tmp` is \tmp on whatever drive the cwd is on
    for p in ["/var/log", "/tmp", "/var/tmp", "/srv", "/opt", "/mnt", "/data", "/workspaces", "/run/user"].iter().filter(|_| cfg!(unix)) {
        v.push(PathBuf::from(p));
    }
    // Windows: the per-user temp dir is its /tmp
    if cfg!(windows) {
        v.push(std::env::temp_dir());
    }
    if let Ok(extra) = std::env::var("AIX_LOG_ROOTS") {
        v.extend(std::env::split_paths(&extra).filter(|p| p.is_absolute()));
    }
    v.into_iter().map(|p| crate::sys::canonicalize(&p).unwrap_or(p)).collect()
}

fn cred_name(name: &str) -> bool {
    use std::sync::LazyLock;
    static R: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)(^|[._-])(id_rsa|id_ed25519|id_ecdsa|id_dsa|credentials?|secrets?|passwd|shadow|netrc|pgpass|keystore|truststore|private[._-]?key|kubeconfig)([._-]|$)|^private$|\.(pem|key|p12|pfx|jks|kdbx|gpg|asc|keytab)$|^\.env(\.|$)|^\.(npmrc|pypirc|git-credentials|netrc|pgpass|vault-token|boto|s3cfg|databrickscfg)$").unwrap()
    });
    R.is_match(name)
}

/// Names that are never read or registered, wherever they are (shell/REPL history, keyrings and keychains, browser
/// profile databases, password-manager and mail stores). Not overridable, not even by `--allow-dotfile`.
fn hard_denied_name(name: &str, last: bool) -> Option<&'static str> {
    use std::sync::LazyLock;
    // shell/REPL histories, also as backup or rotated copies (.bak, .old, .1, -2026, ~, .txt, .log ...): the named
    // shells and REPLs with ANY suffix; any other `*_history` / `history` only with a backup-style suffix
    static HIST: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(concat!(
            r"(?i)(^|[._-])history$",
            r"|^\.?(bash|zsh|fish|sh|ksh|csh|tcsh|dash|ash|mysql|psql|python|ipython|node_repl|sqlite|rediscli|redis|irb|pry|mongo|php|lesshst|dbshell)[_-]?(history|hsts)([._~-].*|~)?$",
            r"|^\.?(lesshst|viminfo|dbshell|wget-hsts)([._~-].*|~)?$",
            // PowerShell's PSReadLine history (Windows and pwsh elsewhere), also VS Code's PowerShell host
            r"|^(consolehost|visual studio code host)_history\.txt$",
            r"|[._-]history([._-](bak|backup|old|orig|save|saved|swp|swo|tmp|temp|copy|\d+)|[._-]\d[\w.-]*|~)$",
        ))
        .unwrap()
    });
    static KEYS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)^(keyrings?|keychains?|login\.keyring)$|\.(keyring|keychain|keychain-db|kdbx|kdb|1pif|opvault|agilekeychain)$").unwrap());
    static BROWSER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)^(cookies(\.sqlite)?(-journal|-wal)?|login data( for account)?(-journal)?|web data|logins\.json|key[34]\.db|signons\.sqlite|places\.sqlite|formhistory\.sqlite|network persistent state|trust tokens)$|\.(mbox|pst|ost)$").unwrap());
    if last && HIST.is_match(name) {
        Some("shell/REPL history")
    } else if KEYS.is_match(name) {
        Some("keyring or password store")
    } else if last && BROWSER.is_match(name) {
        Some("browser profile, cookie or mail data")
    } else {
        None
    }
}

/// `Some(reason)` when the path (as typed or as resolved) is on the hard deny list.
pub fn hard_denied(p: &Path) -> Option<&'static str> {
    let comps: Vec<_> = p.components().filter_map(|c| if let std::path::Component::Normal(n) = c { Some(n.to_string_lossy().to_string()) } else { None }).collect();
    for (i, n) in comps.iter().enumerate() {
        if let Some(r) = hard_denied_name(n, i + 1 == comps.len()) {
            return Some(r);
        }
        if n == ".oci" {
            return Some("cloud or service credential store");
        }
        if let Some(next) = comps.get(i + 1) {
            if CRED_DIR_PAIRS.iter().any(|(a, b)| a == n && b == next) {
                return Some("cloud or service credential store");
            }
        }
    }
    None
}

/// (dir, entry) pairs that hold credentials wherever they sit (not only under $HOME), never overridable.
const CRED_DIR_PAIRS: &[(&str, &str)] = &[
    (".config", "doctl"),
    (".config", "heroku"),
    (".config", "stripe"),
    (".config", "Signal"),
    (".m2", "settings.xml"),
    (".docker", "config.json"),
    (".kube", "config"),
];

/// Under a dot-directory (or a dotfile) directly in $HOME and not inside the repo: needs an explicit `--allow-dotfile`.
fn in_home_dot(canon: &Path, repo: &Path) -> bool {
    let Some(h) = home() else { return false };
    let h = crate::sys::canonicalize(&h).unwrap_or(h);
    let repo = crate::sys::canonicalize(&repo).unwrap_or_else(|_| repo.to_path_buf());
    if canon.starts_with(&repo) {
        return false;
    }
    canon.strip_prefix(&h).ok().and_then(|rel| rel.components().next()).is_some_and(|c| c.as_os_str().to_string_lossy().starts_with('.'))
}

/// Credential-like file name (key files, `.env`, secrets ...), for `privacy-check`.
pub fn credential_like_name(name: &str) -> bool {
    cred_name(name)
}

/// Safety rules for anything registered or ingested. Returns the canonical path.
/// Refuses: missing paths; symlinks whose target is outside the allowed roots; /etc, /proc, /sys, /dev, ~/.ssh, ~/.aws,
/// ~/.gnupg and other credential stores; credential-like names (keys, .env, secrets ...); anything not owned by the
/// current user; devices, FIFOs and sockets.
pub fn check_path(p: &Path, repo: &Path) -> Result<PathBuf> {
    check_path_with(p, repo, false)
}

/// `allow_dot`: the user explicitly allowed files under $HOME's dot-directories (`--allow-dotfile`); the hard deny list
/// (history, keyrings, browser profiles, credential stores) still applies.
pub fn check_path_with(p: &Path, repo: &Path, allow_dot: bool) -> Result<PathBuf> {
    let shown = display_path(&p.to_string_lossy());
    let lm = std::fs::symlink_metadata(p).map_err(|e| anyhow!("{shown}: {}", if e.kind() == std::io::ErrorKind::NotFound { "does not exist".to_string() } else { redact_text(&e.to_string(), true) }))?;
    let canon = crate::sys::canonicalize(&p).with_context(|| format!("{shown}: cannot resolve"))?;
    for q in [p, canon.as_path()] {
        if let Some(why) = hard_denied(q) {
            bail!("{shown}: refused ({why}: never attached or indexed)");
        }
    }
    for d in denied_roots() {
        let d = crate::sys::canonicalize(&d).unwrap_or(d);
        if canon.starts_with(&d) {
            bail!("{shown}: refused (under {}, a system or credential location)", display_path(&d.to_string_lossy()));
        }
    }
    for c in canon.components() {
        if let std::path::Component::Normal(n) = c {
            if cred_name(&n.to_string_lossy()) {
                bail!("{shown}: refused (credential-like name)");
            }
        }
    }
    if !allow_dot && in_home_dot(&canon, repo) {
        bail!("{shown}: refused (under a hidden folder of your home; if you really mean it: aix attach --allow-dotfile <path> or aix logs add --allow-dotfile <path>)");
    }
    if !allowed_roots(repo).iter().any(|r| canon.starts_with(r)) {
        let roots = if cfg!(windows) { "the repo, your user folder, %TEMP%; AIX_LOG_ROOTS (;-separated) adds more" } else { "the repo, $HOME, /var/log, /tmp, /var/tmp, /srv, /opt, /mnt, /data, /workspaces; AIX_LOG_ROOTS adds more" };
        bail!("{shown}: refused ({}outside the allowed roots: {roots})", if lm.file_type().is_symlink() { "symlink target is " } else { "" });
    }
    let md = std::fs::metadata(&canon)?;
    if !(md.is_file() || md.is_dir()) {
        bail!("{shown}: refused (not a regular file or directory: device, FIFO or socket)");
    }
    if !crate::sys::owned_by_me(&md) {
        bail!("{shown}: refused (not owned by the current user)");
    }
    Ok(canon)
}

/// Open a file for reading after the checks, without following symlinks or blocking (FIFO swap race).
fn open_checked(p: &Path, repo: &Path, allow_dot: bool) -> Result<(std::fs::File, std::fs::Metadata, PathBuf)> {
    let canon = check_path_with(p, repo, allow_dot)?;
    let f = crate::sys::open_nofollow(&canon, true)?;
    let md = f.metadata()?;
    if !md.is_file() || !crate::sys::owned_by_me(&md) {
        bail!("{}: refused (not a regular file owned by you)", display_path(&p.to_string_lossy()));
    }
    Ok((f, md, canon))
}

fn glob_match(pat: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    fn go(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && go(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    go(&p, &t)
}

fn looks_like_log(name: &str) -> bool {
    use std::sync::LazyLock;
    static R: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)\.(log|out|err|txt|jsonl|ndjson)(\.\d+)?(\.gz)?$|\.log[.-]\d").unwrap());
    R.is_match(name)
}

/// Concrete files a registration currently covers (each re-checked by `check_path`); `skipped` counts refusals.
pub fn expand(spec: &Spec, repo: &Path) -> (Vec<PathBuf>, usize) {
    let p = PathBuf::from(&spec.path);
    let mut out = vec![];
    let mut skipped = 0;
    let push = |q: PathBuf, out: &mut Vec<PathBuf>, skipped: &mut usize| match check_path_with(&q, repo, spec.allow_dot) {
        Ok(c) if c.is_file() => out.push(c),
        Ok(_) => {}
        Err(_) => *skipped += 1,
    };
    match spec.kind.as_str() {
        "file" => push(p, &mut out, &mut skipped),
        "dir" => {
            let mut stack = vec![(p, 0)];
            while let Some((d, depth)) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&d) else { continue };
                for e in rd.flatten().take(2000) {
                    let q = e.path();
                    let Ok(ft) = e.file_type() else { continue };
                    // hidden folders (.aix's own hook log, .git, .claude) only with --allow-dotfile: a folder named in a
                    // prompt (a pasted `F:\repo>` console prompt) attached .aix\hook-events.jsonl
                    let hidden = e.file_name().to_string_lossy().starts_with('.');
                    if ft.is_dir() && depth < 2 && (!hidden || spec.allow_dot) {
                        stack.push((q, depth + 1));
                    } else if (ft.is_file() || ft.is_symlink()) && looks_like_log(&e.file_name().to_string_lossy()) && out.len() < 200 {
                        push(q, &mut out, &mut skipped);
                    }
                }
            }
        }
        _ => {
            if let (Some(dir), Some(pat)) = (p.parent(), p.file_name().map(|n| n.to_string_lossy().to_string())) {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for e in rd.flatten().take(5000) {
                        if glob_match(&pat, &e.file_name().to_string_lossy()) && out.len() < 200 {
                            push(e.path(), &mut out, &mut skipped);
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    (out, skipped)
}

/// Validate and describe a new registration (path may be a file, a directory, or `dir/pattern*`).
pub fn make_spec(raw: &str, repo: &Path, name: Option<&str>, format: &str, max_mb: Option<u64>, retain_days: Option<u64>, keep_ips: bool) -> Result<Spec> {
    make_spec_ex(raw, repo, name, format, max_mb, retain_days, keep_ips, false)
}

#[allow(clippy::too_many_arguments)]
pub fn make_spec_ex(raw: &str, repo: &Path, name: Option<&str>, format: &str, max_mb: Option<u64>, retain_days: Option<u64>, keep_ips: bool, allow_dot: bool) -> Result<Spec> {
    let mut p = PathBuf::from(raw);
    if !p.is_absolute() {
        p = std::env::current_dir()?.join(p);
    }
    let is_glob = raw.contains(['*', '?', '[']);
    let (kind, shown): (&str, PathBuf) = if is_glob {
        let dir = p.parent().ok_or_else(|| anyhow!("bad glob"))?;
        if dir.to_string_lossy().contains(['*', '?', '[']) {
            bail!("a glob may only be in the last path component (dir/pattern*.log)");
        }
        let d = check_path_with(dir, repo, allow_dot)?;
        if !d.is_dir() {
            bail!("{}: not a directory", display_path(&dir.to_string_lossy()));
        }
        ("glob", d.join(p.file_name().unwrap()))
    } else {
        let c = check_path_with(&p, repo, allow_dot)?;
        (if c.is_dir() { "dir" } else { "file" }, c)
    };
    if Format::parse(format).is_none() {
        bail!("--format must be auto|json|logfmt|java|plain");
    }
    let mut base = shown.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "log".into());
    if name.is_none() && display_path(&base) != base {
        // a secret-looking file name never becomes the log's name (it is printed everywhere)
        base = format!("log-{}", &blake_hex(shown.to_string_lossy().as_bytes())[..6]);
    }
    let mut nm: String = name.map(|s| s.to_string()).unwrap_or_else(|| base.trim_end_matches(".log").trim_matches(|c: char| !c.is_alphanumeric()).to_string());
    nm = nm.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let nm = nm.trim_matches('-').chars().take(32).collect::<String>();
    if nm.is_empty() || nm.starts_with("paste") {
        bail!("pick a --name (letters, digits, - and _; not starting with 'paste')");
    }
    Ok(Spec { name: nm, path: shown.to_string_lossy().to_string(), kind: kind.into(), format: format.into(), max_mb, retain_days, max_rows: None, allow_dot, keep_ips, added: now(), watch_started: now(), ..Default::default() })
}

// ---- the store ---------------------------------------------------------------------------------------------------------

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(name TEXT, dev INT, ino INT, path TEXT, size INT, off INT, mtime INT, head_len INT, head_hash TEXT,
  last_ingest INT, last_entry INT, in_pem INT DEFAULT 0, PRIMARY KEY(name, dev, ino));
CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ts INT, level INT, logger TEXT, thread TEXT, msg TEXT, body TEXT,
  tid TEXT, err TEXT, exc TEXT, bytes INT, at INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS entries_nt ON entries(name, ts, bytes);
CREATE INDEX IF NOT EXISTS entries_tid ON entries(tid);
CREATE INDEX IF NOT EXISTS entries_err ON entries(err) WHERE err<>'';
CREATE INDEX IF NOT EXISTS entries_ts ON entries(ts);
CREATE TABLE IF NOT EXISTS tpl(name TEXT, tid TEXT, tpl TEXT, level INT, exc TEXT, logger TEXT, first INT, last INT, total INT, sample TEXT,
  sample_ts INT, frames TEXT, PRIMARY KEY(name, tid));
CREATE TABLE IF NOT EXISTS agg(name TEXT, tid TEXT, bucket INT, level INT, n INT, PRIMARY KEY(name, tid, bucket, level)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS prune_log(ts INT, name TEXT, rows INT, bytes INT, young INT);
CREATE TABLE IF NOT EXISTS watch_events(ts INT, name TEXT, event TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS usage(name TEXT PRIMARY KEY, last_q INT, n INT);
CREATE TABLE IF NOT EXISTS pastes(id INTEGER PRIMARY KEY, name TEXT, ts INT, kind TEXT, lines INT, bytes INT, hash TEXT UNIQUE, label TEXT, text TEXT,
  ns TEXT DEFAULT 'paste', src TEXT DEFAULT '', src_mtime INT DEFAULT 0, src_size INT DEFAULT 0,
  state TEXT DEFAULT 'ready', done INT DEFAULT 0, total INT DEFAULT 0, t0 INT DEFAULT 0, pid INT DEFAULT 0, err TEXT DEFAULT '',
  src_hash TEXT DEFAULT '', origin TEXT DEFAULT 'user', trunc TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, name TEXT, re TEXT, min_level INT, once INT, expires INT, created INT, active INT DEFAULT 1, last_id INT DEFAULT 0, hits INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS alert_hits(id INTEGER PRIMARY KEY, alert_id INT, entry_id INT, name TEXT, tid TEXT, level INT, ts INT, last_ts INT, count INT, msg TEXT, seen INT DEFAULT 0, at INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS alert_hits_a ON alert_hits(alert_id, tid, last_ts);
"#;

pub struct Store {
    pub conn: Connection,
    pub path: PathBuf,
}

/// Open (creating with mode 0600) a log or paste store. `auto_vacuum=INCREMENTAL` is set before the first table so
/// `incremental_vacuum` really shrinks the file; `secure_delete` zeroes deleted content.
pub fn open_store(path: &Path) -> Result<Store> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let fresh = !path.exists();
    if fresh {
        let _ = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(path)?;
    } else if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("{} is a symlink: refused", path.display());
    }
    let conn = Connection::open(path)?;
    let busy_ms = std::env::var("AIX_STORE_BUSY_MS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(5000);
    conn.busy_timeout(std::time::Duration::from_millis(busy_ms))?;
    if fresh {
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
    }
    conn.execute_batch("PRAGMA secure_delete=ON; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;")?;
    conn.execute_batch(SCHEMA)?;
    // columns added after the first release: older stores are upgraded in place (once: user_version marks it)
    let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap_or(0);
    if ver < 2 {
    for (t, c, d) in [("entries", "at", "INT DEFAULT 0"), ("pastes", "src_hash", "TEXT DEFAULT ''"), ("pastes", "origin", "TEXT DEFAULT 'user'"), ("pastes", "trunc", "TEXT DEFAULT ''")] {
        let has = conn.prepare(&format!("PRAGMA table_info({t})")).and_then(|mut st| st.query_map([], |r| r.get::<_, String>(1)).map(|i| i.flatten().any(|n| n == c))).unwrap_or(true);
        if !has {
            let _ = conn.execute_batch(&format!("ALTER TABLE {t} ADD COLUMN {c} {d};"));
        }
    }
    let _ = conn.execute_batch("CREATE INDEX IF NOT EXISTS entries_at ON entries(at); PRAGMA user_version=2;");
    }
    let _ = crate::sys::chmod(path, 0o600);
    Ok(Store { conn, path: path.to_path_buf() })
}

pub fn with_tx<T>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match f(conn) {
        Ok(v) => {
            conn.execute_batch("COMMIT")?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

// ---- ingest --------------------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct Carry {
    pub in_pem: bool,
    pub last_entry: Option<i64>,
}

pub struct ChunkOpts {
    pub fmt: Format,
    pub keep_ips: bool,
    pub store_debug: bool,
    pub now: i64,
    /// the text was redacted as a whole block already (pastes): fields are not redacted a second time
    pub pre_redacted: bool,
}

#[derive(Default)]
struct TplUp {
    tpl: String,
    level: u8,
    exc: String,
    logger: String,
    first: i64,
    last: i64,
    n: i64,
    sample: String,
    frames: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ChunkStats {
    pub entries: u64,
    pub stored: u64,
    pub bytes: u64,
}

fn limit_body(s: &str) -> String {
    let mut out = String::new();
    for (i, l) in s.lines().enumerate() {
        if i >= BODY_MAX_LINES || out.len() + l.len() > BODY_MAX_BYTES {
            out.push_str("\n... (truncated)");
            break;
        }
        if i > 0 {
            out.push('\n');
        }
        out.push_str(l);
    }
    out
}

struct Raw {
    first: String,
    cont: Vec<String>,
}

/// One parsed, redacted entry, ready to store (pure function of its raw lines: independent of thread timing).
struct Row {
    ts: i64,
    level: u8,
    logger: String,
    thread: String,
    msg: String,
    body: String,
    tid: String,
    err: String,
    exc: String,
    tpl: String,
    frames: String,
}

fn build_row(r: &Raw, o: &ChunkOpts) -> Row {
    let red = |t: &str, ips: bool| if o.pre_redacted { t.to_string() } else { redact_text(t, ips) };
    let p = logparse::parse_entry(&r.first, &r.cont, o.fmt);
    let ts = match p.ts {
        Some(t) if p.tz_known => t,
        Some(t) => t - local_offset(t),
        None => o.now,
    };
    let level = p.level.unwrap_or(logparse::INFO);
    let msg = clip_chars(&red(p.message.trim(), o.keep_ips), 600);
    let tpl = logparse::template(&msg);
    let tid = tid_of(if tpl.is_empty() { "(empty)" } else { &tpl });
    let logger = clip_chars(&red(&p.logger, o.keep_ips), 120);
    let thread = clip_chars(&red(&p.thread, o.keep_ips), 80);
    let exc = clip_chars(&red(&p.exception, o.keep_ips), 120);
    let err = clip_chars(&red(&p.error_id, o.keep_ips), 64);
    // single-line entries keep only `msg`: the body would repeat it
    let body = if r.cont.is_empty() && p.stack.is_empty() {
        String::new()
    } else {
        let mut raw_body = r.first.clone();
        for l in r.cont.iter().map(|s| s.as_str()).chain(p.stack.lines()) {
            raw_body.push('\n');
            raw_body.push_str(l);
        }
        red(&limit_body(&raw_body), o.keep_ips)
    };
    let frames = if level >= logparse::WARN && !body.is_empty() { body.lines().filter(|l| l.trim_start().starts_with("at ") || l.contains("File \"")).take(8).map(|l| clip_chars(l.trim(), 300)).collect::<Vec<_>>().join("\n") } else { String::new() };
    Row { ts, level, logger, thread, msg, body, tid, err, exc, tpl, frames }
}

static LOW_PRIORITY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Parser/redactor pool size: AIX_LOGS_THREADS, else cores-1 capped at 4; 2 under the watcher (which also runs niced).
pub fn pipeline_workers() -> usize {
    if let Some(n) = std::env::var("AIX_LOGS_THREADS").ok().and_then(|v| v.parse::<usize>().ok()) {
        return n.clamp(1, 16);
    }
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if LOW_PRIORITY.load(std::sync::atomic::Ordering::Relaxed) {
        return 2.min(cores.saturating_sub(1)).max(1);
    }
    cores.saturating_sub(1).clamp(1, 4)
}

const PIPE_MIN_ENTRIES: usize = 2000;
const PIPE_BATCH: usize = 1000;

/// reader -> parser/redactor pool -> writer (the caller's thread), joined by bounded channels (backpressure). Batches are
/// numbered and the writer releases them in order, so the stored rows never depend on thread timing. A sink error does not
/// stop the pipeline (it keeps draining so no thread blocks) and is returned at the end.
fn build_rows(raws: Vec<Raw>, o: &ChunkOpts, workers: usize, sink: &mut dyn FnMut(Row) -> Result<()>) -> Result<()> {
    use std::sync::{mpsc::sync_channel, Mutex};
    if workers <= 1 || raws.len() < PIPE_MIN_ENTRIES {
        for r in &raws {
            sink(build_row(r, o))?;
        }
        return Ok(());
    }
    let mut batches: Vec<Vec<Raw>> = vec![];
    let mut it = raws.into_iter().peekable();
    while it.peek().is_some() {
        batches.push(it.by_ref().take(PIPE_BATCH).collect());
    }
    let (tx_in, rx_in) = sync_channel::<(usize, Vec<Raw>)>(workers * 2);
    let rx_in = Mutex::new(rx_in);
    let (tx_out, rx_out) = sync_channel::<(usize, Vec<Row>)>(workers * 2);
    let low = LOW_PRIORITY.load(std::sync::atomic::Ordering::Relaxed);
    let mut err: Option<anyhow::Error> = None;
    std::thread::scope(|sc| {
        sc.spawn(move || {
            for (i, b) in batches.into_iter().enumerate() {
                if tx_in.send((i, b)).is_err() {
                    break;
                }
            }
        });
        for _ in 0..workers {
            let tx = tx_out.clone();
            let rx = &rx_in;
            sc.spawn(move || {
                if low {
                    crate::sys::nice(10);
                }
                loop {
                    let m = rx.lock().unwrap().recv();
                    let Ok((i, b)) = m else { break };
                    let rows: Vec<Row> = b.iter().map(|r| build_row(r, o)).collect();
                    if tx.send((i, rows)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx_out);
        let mut pending: std::collections::BTreeMap<usize, Vec<Row>> = Default::default();
        let mut next = 0;
        for (i, rows) in rx_out {
            pending.insert(i, rows);
            while let Some(rows) = pending.remove(&next) {
                for r in rows {
                    if err.is_none() {
                        if let Err(e) = sink(r) {
                            err = Some(e);
                        }
                    }
                }
                next += 1;
            }
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Parse and store one block of complete lines for `name`: entries (multi-line grouped), redacted, templated, aggregated.
pub fn process_chunk(conn: &Connection, name: &str, text: &str, o: &ChunkOpts, carry: &mut Carry) -> Result<ChunkStats> {
    let mut st = ChunkStats::default();
    let mut raws: Vec<Raw> = vec![];
    let mut append: Vec<String> = vec![];
    let mut cur: Option<Raw> = None;
    for l in text.split('\n') {
        let l = l.strip_suffix('\r').unwrap_or(l);
        let line = logparse::strip_ansi(l);
        // a private-key block is dropped wholesale, also across chunk boundaries
        if carry.in_pem {
            if line.contains("-----END") {
                carry.in_pem = false;
            }
            continue;
        }
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
            carry.in_pem = !line.contains("-----END");
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if logparse::is_entry_start(&line, o.fmt) {
            if let Some(c) = cur.take() {
                raws.push(c);
            }
            cur = Some(Raw { first: line, cont: vec![] });
        } else if let Some(c) = cur.as_mut() {
            c.cont.push(line);
        } else if carry.last_entry.is_some() {
            append.push(line);
        } else {
            cur = Some(Raw { first: line, cont: vec![] });
        }
    }
    if let Some(c) = cur.take() {
        raws.push(c);
    }
    if let (Some(id), false) = (carry.last_entry, append.is_empty()) {
        let extra = redact_text(&limit_body(&append.join("\n")), o.keep_ips);
        conn.execute("UPDATE entries SET body=substr(body || char(10) || ?1, 1, ?2), bytes=bytes+length(?1) WHERE id=?3", params![extra, BODY_MAX_BYTES as i64 * 2, id])?;
    }
    let mut aggs: HashMap<(String, i64, u8), i64> = HashMap::new();
    let mut tpls: HashMap<String, TplUp> = HashMap::new();
    let mut ins = conn.prepare_cached("INSERT INTO entries(name,ts,level,logger,thread,msg,body,tid,err,exc,bytes,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")?;
    let mut last_id: Option<i64> = None;
    let had = !raws.is_empty();
    build_rows(raws, o, pipeline_workers(), &mut |r: Row| {
        st.entries += 1;
        let (ts, level) = (r.ts, r.level);
        *aggs.entry((r.tid.clone(), ts.div_euclid(3600), level)).or_default() += 1;
        let t = tpls.entry(r.tid.clone()).or_insert_with(|| TplUp { first: ts, last: ts, tpl: r.tpl.clone(), ..Default::default() });
        t.level = t.level.max(level);
        t.first = t.first.min(ts);
        t.n += 1;
        if ts >= t.last {
            t.last = ts;
            t.sample = clip_chars(&r.msg, 300);
            if !r.frames.is_empty() {
                t.frames = r.frames.clone();
            }
            t.logger = r.logger.clone();
        }
        if !r.exc.is_empty() {
            t.exc = r.exc.clone();
        }
        if level <= logparse::DEBUG && !o.store_debug {
            last_id = None;
            return Ok(());
        }
        let bytes = r.msg.len() + r.body.len() + r.logger.len() + r.thread.len() + r.exc.len() + r.err.len() + ROW_OVERHEAD;
        ins.execute(params![name, ts, level as i64, r.logger, r.thread, r.msg, r.body, r.tid, r.err, r.exc, bytes as i64, o.now])?;
        last_id = Some(conn.last_insert_rowid());
        st.stored += 1;
        st.bytes += bytes as u64;
        Ok(())
    })?;
    drop(ins);
    carry.last_entry = last_id.or(if !had { carry.last_entry } else { None });
    for ((tid, bucket, level), n) in aggs {
        conn.execute("INSERT INTO agg VALUES(?,?,?,?,?) ON CONFLICT(name,tid,bucket,level) DO UPDATE SET n=n+excluded.n", params![name, tid, bucket, level as i64, n])?;
    }
    for (tid, t) in tpls {
        conn.execute(
            "INSERT INTO tpl(name,tid,tpl,level,exc,logger,first,last,total,sample,sample_ts,frames) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?8,?11)
             ON CONFLICT(name,tid) DO UPDATE SET level=max(level,excluded.level), first=min(first,excluded.first),
               exc=CASE WHEN excluded.exc<>'' THEN excluded.exc ELSE exc END, total=total+excluded.total,
               sample=CASE WHEN excluded.last>=last THEN excluded.sample ELSE sample END,
               frames=CASE WHEN excluded.last>=last AND excluded.frames<>'' THEN excluded.frames ELSE frames END,
               logger=CASE WHEN excluded.last>=last THEN excluded.logger ELSE logger END,
               last=max(last,excluded.last), sample_ts=max(sample_ts,excluded.last)",
            params![name, tid, t.tpl, t.level as i64, t.exc, t.logger, t.first, t.last, t.n, t.sample, t.frames],
        )?;
    }
    Ok(st)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Ingested {
    pub files: usize,
    pub bytes: u64,
    pub entries: u64,
    pub changed: bool,
}

fn still_registered(dir: &Path, spec: &Spec) -> bool {
    load_cfg(dir).logs.iter().any(|s| s.name == spec.name && s.path == spec.path)
}

type State = (i64, i64, i64, String, Option<i64>, bool); // size, off, mtime, head_hash(+len), last_entry, in_pem

fn load_state(conn: &Connection, name: &str, dev: i64, ino: i64) -> Option<(State, i64)> {
    conn.query_row("SELECT size, off, mtime, head_hash, last_entry, in_pem, head_len FROM files WHERE name=? AND dev=? AND ino=?", params![name, dev, ino], |r| {
        Ok(((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, String>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, i64>(5)? != 0), r.get::<_, i64>(6)?))
    })
    .ok()
}

/// Incrementally ingest one file for `spec`. Returns bytes consumed and entries seen. Handles truncation (copytruncate),
/// replaced content under the same inode, and a new inode at the same path (rename + create: new state from offset 0).
fn ingest_file(store: &Store, dir: &Path, repo: &Path, cfg: &Cfg, spec: &Spec, path: &Path, left: u64) -> Result<(u64, u64)> {
    let (mut f, md, canon) = open_checked(path, repo, spec.allow_dot)?;
    let (dev, ino) = crate::sys::open_file_id(&f, &md);
    let (dev, ino, size, mtime) = (dev as i64, ino as i64, md.len() as i64, crate::sys::mtime(&md));
    let eff = cfg.eff(spec);
    let conn = &store.conn;
    let fmt = Format::parse(&spec.format).unwrap_or(Format::Auto);
    let name = spec.name.as_str();
    let is_gz = canon.extension().is_some_and(|e| e == "gz");
    if is_gz {
        if let Some(((sz, _, _, _, _, _), _)) = load_state(conn, name, dev, ino) {
            if sz == size {
                return Ok((0, 0));
            }
        }
        drop(f);
        let mut data = std::fs::File::open(&canon).map(gunzip).context("open")?;
        if data.len() as i64 > eff.cap_bytes {
            data.drain(..data.len() - eff.cap_bytes as usize);
        }
        let text = String::from_utf8_lossy(&data).to_string();
        return with_tx(conn, |c| {
            if !still_registered(dir, spec) {
                bail!("log '{}' was unregistered", name);
            }
            let mut carry = Carry::default();
            let st = process_chunk(c, name, &text, &ChunkOpts { fmt, keep_ips: spec.keep_ips, store_debug: eff.store_debug.unwrap_or(size as u64 <= DEBUG_AUTO_BYTES), now: now(), pre_redacted: false }, &mut carry)?;
            c.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?,?,?,?,?,0)", params![name, dev, ino, display_path(&canon.to_string_lossy()), size, size, mtime, 0, "", now(), Option::<i64>::None])?;
            Ok((data.len() as u64, st.entries))
        });
    }
    with_tx(conn, |c| {
        if !still_registered(dir, spec) {
            bail!("log '{}' was unregistered", name);
        }
        let prior = load_state(c, name, dev, ino);
        let (mut off, mut carry) = match &prior {
            Some(((_, off, _, hh, le, pem), hl)) => {
                let mut o = *off;
                if size < o {
                    o = 0; // truncated in place (copytruncate)
                } else if *hl > 0 && o > 0 {
                    let mut buf = vec![0u8; (*hl as usize).min(size as usize)];
                    f.seek(SeekFrom::Start(0))?;
                    f.read_exact(&mut buf)?;
                    if &blake_hex(&buf)[..16] != hh {
                        o = 0; // same inode, different content: rewritten
                    }
                }
                (o, if o == 0 { Carry::default() } else { Carry { in_pem: *pem, last_entry: *le } })
            }
            None => {
                let mut o = 0;
                // first sight of a huge log: only the newest `cap` bytes can survive the budget anyway
                if size > eff.cap_bytes * 2 {
                    o = size - eff.cap_bytes;
                    f.seek(SeekFrom::Start(o as u64))?;
                    let mut one = [0u8; 1];
                    while o < size && f.read(&mut one)? == 1 {
                        o += 1;
                        if one[0] == b'\n' {
                            break;
                        }
                    }
                }
                (o, Carry::default())
            }
        };
        let mut consumed = 0u64;
        let mut entries = 0u64;
        let mut budget = left;
        let mut stop = false;
        while off < size && budget > 0 && !stop {
            let want = (size - off).min(CHUNK as i64).min(budget as i64) as usize;
            let mut buf = vec![0u8; want];
            f.seek(SeekFrom::Start(off as u64))?;
            let n = f.read(&mut buf)?;
            buf.truncate(n);
            if n == 0 {
                break;
            }
            let end = match buf.iter().rposition(|b| *b == b'\n') {
                Some(i) => i + 1,
                None if buf.len() >= 65536 || (off + n as i64 >= size && now() - mtime >= 2 && !buf.is_empty()) => buf.len(),
                None => {
                    stop = true;
                    0
                }
            };
            if end == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buf[..end]).to_string();
            let st = process_chunk(c, name, &text, &ChunkOpts { fmt, keep_ips: spec.keep_ips, store_debug: eff.store_debug.unwrap_or(size as u64 <= DEBUG_AUTO_BYTES), now: now(), pre_redacted: false }, &mut carry)?;
            entries += st.entries;
            off += end as i64;
            consumed += end as u64;
            budget = budget.saturating_sub(end as u64);
            if end < buf.len() && n as i64 + (off - end as i64) >= size {
                stop = true; // trailing partial line: wait for its newline
            }
        }
        let hl = size.min(256);
        let mut hb = vec![0u8; hl as usize];
        f.seek(SeekFrom::Start(0))?;
        let hh = if f.read_exact(&mut hb).is_ok() { blake_hex(&hb)[..16].to_string() } else { String::new() };
        c.execute(
            "INSERT OR REPLACE INTO files(name,dev,ino,path,size,off,mtime,head_len,head_hash,last_ingest,last_entry,in_pem) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            params![name, dev, ino, display_path(&canon.to_string_lossy()), size, off, mtime, hl, hh, now(), carry.last_entry, carry.in_pem as i64],
        )?;
        Ok((consumed, entries))
    })
}

/// The registration is paused because its line or size limit was reached (queries must not read beyond it).
pub fn limit_reached(conn: &Connection, spec: &Spec) -> bool {
    spec.paused
        && matches!(spec.pause_reason.as_str(), "line limit" | "size limit")
        && (spec.stop_lines.is_some_and(|n| meta_get(conn, &format!("wl:{}", spec.name)).unwrap_or(0) >= n)
            || spec.stop_bytes.is_some_and(|n| meta_get(conn, &format!("wb:{}", spec.name)).unwrap_or(0) >= n))
}

/// Ingest everything new for one registration (at most `left` bytes), then enforce the budgets. Cheap when nothing changed.
pub fn ingest_spec(store: &Store, dir: &Path, repo: &Path, cfg: &Cfg, spec: &Spec, mut left: u64) -> Result<Ingested> {
    let t_start = std::time::Instant::now();
    // a watch that stopped at its --max-lines / --stop-mb limit stays at the limit: on-demand refreshes do not read past it
    if limit_reached(&store.conn, spec) {
        return Ok(Ingested::default());
    }
    let mut r = Ingested::default();
    let (mut files, _) = expand(spec, repo);
    // a rotated-away file (rename + new): finish its tail when it is still next to the path under a known inode
    if spec.kind == "file" {
        let known: Vec<(i64, i64)> = {
            let mut st = store.conn.prepare("SELECT dev, ino FROM files WHERE name=? ORDER BY last_ingest DESC LIMIT 6")?;
            let v = st.query_map([&spec.name], |x| Ok((x.get(0)?, x.get(1)?)))?.flatten().collect();
            v
        };
        if !known.is_empty() {
            let p = PathBuf::from(&spec.path);
            if let (Some(d), Some(b)) = (p.parent(), p.file_name().map(|n| n.to_string_lossy().to_string())) {
                if let Ok(rd) = std::fs::read_dir(d) {
                    for e in rd.flatten().take(5000) {
                        let n = e.file_name().to_string_lossy().to_string();
                        if n.starts_with(&format!("{b}.")) || n.starts_with(&format!("{b}-")) {
                            if let Ok(md) = e.metadata() {
                                let (dev, ino) = crate::sys::file_id(&e.path(), &md);
                                if known.contains(&(dev as i64, ino as i64)) {
                                    files.push(e.path());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for f in files {
        if left == 0 {
            break;
        }
        // stat-only fast path: nothing new
        if let Ok(md) = std::fs::metadata(&f) {
            let (dev, ino) = crate::sys::file_id(&f, &md);
            if let Some(((sz, off, mt, ..), _)) = load_state(&store.conn, &spec.name, dev as i64, ino as i64) {
                if sz == md.len() as i64 && off == sz && mt == crate::sys::mtime(&md) {
                    continue;
                }
            }
        }
        match ingest_file(store, dir, repo, cfg, spec, &f, left) {
            Ok((b, e)) => {
                r.files += 1;
                r.bytes += b;
                r.entries += e;
                left = left.saturating_sub(b.max(1));
                r.changed |= b > 0;
            }
            Err(e) if e.to_string().contains("unregistered") => return Ok(r),
            Err(_) => {}
        }
    }
    if r.changed {
        if r.bytes >= 256 * 1024 {
            rate_update(&store.conn, "logs_bytes", r.bytes as f64, t_start.elapsed().as_secs_f64());
        }
        if r.bytes > 0 {
            meta_add(&store.conn, &format!("wl:{}", spec.name), r.entries as i64);
            meta_add(&store.conn, &format!("wb:{}", spec.name), r.bytes as i64);
            meta_set(&store.conn, &format!("wlast:{}", spec.name), now());
        }
        prune_log(store, cfg, spec)?;
        if r.bytes > 0 {
            crate::privacy::post_ingest(store, &spec.name);
        }
    }
    Ok(r)
}

/// Ingest all registrations (query-time refresh and the watcher's tick). Returns what was ingested.
pub fn refresh(store: &Store, dir: &Path, repo: &Path, cfg: &Cfg, max_bytes: u64) -> Ingested {
    let mut t = Ingested::default();
    let mut left = max_bytes;
    for s in &cfg.logs {
        if let Ok(r) = ingest_spec(store, dir, repo, cfg, s, left) {
            left = left.saturating_sub(r.bytes);
            t.files += r.files;
            t.bytes += r.bytes;
            t.entries += r.entries;
            t.changed |= r.changed;
        }
    }
    if t.changed {
        prune_global(store, cfg).ok();
    }
    t
}

// ---- budgets and pruning -------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
pub struct Pruned {
    pub rows: i64,
    pub bytes: i64,
    pub young: i64,
}

pub fn usage_of(conn: &Connection, name: Option<&str>) -> (i64, i64) {
    match name {
        Some(n) => conn.query_row("SELECT count(*), COALESCE(sum(bytes),0) FROM entries WHERE name=?", [n], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((0, 0)),
        None => conn.query_row("SELECT count(*), COALESCE(sum(bytes),0) FROM entries", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((0, 0)),
    }
}

/// Delete one batch of the oldest rows (low levels first). Returns rows, bytes and how many were younger than `young_before`.
fn prune_batch(conn: &Connection, name: Option<&str>, low_only: bool, older_than: Option<i64>, young_before: i64, n: i64) -> Result<(String, Pruned)> {
    let mut sql = String::from("DELETE FROM entries WHERE id IN (SELECT id FROM entries WHERE 1=1");
    if name.is_some() {
        sql.push_str(" AND name=?1");
    }
    if low_only {
        sql.push_str(" AND level<4");
    }
    if let Some(t) = older_than {
        sql.push_str(&format!(" AND COALESCE(NULLIF(at,0),ts)<{t}"));
    }
    sql.push_str(&format!(" ORDER BY ts LIMIT {n}) RETURNING name, bytes, COALESCE(NULLIF(at,0),ts)"));
    let mut st = conn.prepare(&sql)?;
    let mut p = Pruned::default();
    let mut nm = String::new();
    let mut rows = if name.is_some() { st.query([name.unwrap()])? } else { st.query([])? };
    while let Some(r) = rows.next()? {
        p.rows += 1;
        p.bytes += r.get::<_, i64>(1)?;
        if r.get::<_, i64>(2)? >= young_before {
            p.young += 1;
        }
        if nm.is_empty() {
            nm = r.get(0)?;
        }
    }
    Ok((nm, p))
}

fn note_prune(conn: &Connection, name: &str, p: &Pruned) {
    if p.rows > 0 {
        let _ = conn.execute("INSERT INTO prune_log VALUES(?,?,?,?,?)", params![now(), name, p.rows, p.bytes, p.young]);
    }
}

/// Enforce retention, row cap and byte cap for one log (batches of 2000 rows, oldest first, DEBUG/INFO/WARN before
/// ERROR/FATAL; down to 90 % of the cap so it does not re-prune every tick), then shrink the file a little.
pub fn prune_log(store: &Store, cfg: &Cfg, spec: &Spec) -> Result<Pruned> {
    let e = cfg.eff(spec);
    let conn = &store.conn;
    let mut total = Pruned::default();
    let t = now();
    let young_before = t - e.retain_secs;
    for _ in 0..40 {
        let (_, p) = with_tx(conn, |c| prune_batch(c, Some(&spec.name), false, Some(young_before), young_before, 2000))?;
        if p.rows == 0 {
            break;
        }
        total.rows += p.rows;
        total.bytes += p.bytes;
    }
    let (rows, bytes) = usage_of(conn, Some(&spec.name));
    let (mut over_b, mut over_r) = (if bytes > e.cap_bytes { bytes - e.cap_bytes * 9 / 10 } else { 0 }, if rows > e.max_rows { rows - e.max_rows * 9 / 10 } else { 0 });
    let mut guard = 0;
    let avg = (bytes / rows.max(1)).max(1);
    while (over_b > 0 || over_r > 0) && guard < 40 {
        guard += 1;
        // exactly as many rows as are needed (at most 2000 per transaction)
        let need = over_r.max(over_b / avg + 1).clamp(1, 2000);
        let (_, p) = with_tx(conn, |c| {
            let r = prune_batch(c, Some(&spec.name), true, None, young_before, need)?;
            if r.1.rows == 0 {
                return prune_batch(c, Some(&spec.name), false, None, young_before, need);
            }
            Ok(r)
        })?;
        if p.rows == 0 {
            break;
        }
        total.rows += p.rows;
        total.bytes += p.bytes;
        total.young += p.young;
        over_b -= p.bytes;
        over_r -= p.rows;
    }
    note_prune(conn, &spec.name, &total);
    if total.rows > 0 {
        shrink(conn);
    }
    trim_aggregates(conn, Some(&spec.name))?;
    Ok(total)
}

/// Global budget across all logs: oldest low-level rows anywhere first.
pub fn prune_global(store: &Store, cfg: &Cfg) -> Result<Pruned> {
    let conn = &store.conn;
    let cap = cfg.global_cap();
    let (_, mut bytes) = usage_of(conn, None);
    let mut total = Pruned::default();
    if bytes <= cap {
        return Ok(total);
    }
    let target = cap * 9 / 10;
    let mut guard = 0;
    let (rows, _) = usage_of(conn, None);
    let avg = (bytes / rows.max(1)).max(1);
    while bytes > target && guard < 60 {
        guard += 1;
        let need = ((bytes - target) / avg + 1).clamp(1, 2000);
        let (nm, p) = with_tx(conn, |c| {
            let r = prune_batch(c, None, true, None, 0, need)?;
            if r.1.rows == 0 {
                return prune_batch(c, None, false, None, 0, need);
            }
            Ok(r)
        })?;
        if p.rows == 0 {
            break;
        }
        total.rows += p.rows;
        total.bytes += p.bytes;
        bytes -= p.bytes;
        note_prune(conn, &nm, &p);
    }
    shrink(conn);
    Ok(total)
}

/// Release free pages in small steps (auto_vacuum=INCREMENTAL).
pub fn shrink(conn: &Connection) {
    for _ in 0..6 {
        let free: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0)).unwrap_or(0);
        let total: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(1);
        if free * 20 < total || free < 64 {
            break;
        }
        let _ = conn.execute_batch("PRAGMA incremental_vacuum(8000);");
    }
}

/// Aggregates stay for 90 days; at most 5000 templates per log (least recently seen go first).
fn trim_aggregates(conn: &Connection, name: Option<&str>) -> Result<()> {
    let cut = now() - 90 * 86400;
    let n = name.unwrap_or("");
    let nf = if name.is_some() { "AND name=?1" } else { "AND ?1=?1" };
    conn.execute(&format!("DELETE FROM agg WHERE bucket<{} {nf}", cut / 3600), [n])?;
    conn.execute(&format!("DELETE FROM tpl WHERE last<{cut} {nf}"), [n])?;
    conn.execute(
        &format!("DELETE FROM tpl WHERE rowid IN (SELECT rowid FROM tpl WHERE 1=1 {nf} ORDER BY last DESC LIMIT -1 OFFSET 5000)"),
        [n],
    )?;
    Ok(())
}

/// Purge every trace of one log (rows, aggregates, templates, file states, usage): returns (rows, bytes).
pub fn purge_name(store: &Store, name: &str) -> Result<(i64, i64)> {
    let conn = &store.conn;
    let r = with_tx(conn, |c| {
        let (rows, bytes) = usage_of(c, Some(name));
        for t in ["entries", "files", "tpl", "agg", "usage", "prune_log"] {
            c.execute(&format!("DELETE FROM {t} WHERE name=?"), [name])?;
        }
        Ok((rows, bytes))
    })?;
    shrink(conn);
    Ok(r)
}

fn purge_name_quiet(store: &Store, name: &str) -> Result<(i64, i64)> {
    let conn = &store.conn;
    with_tx(conn, |c| {
        let (rows, bytes) = usage_of(c, Some(name));
        for t in ["entries", "files", "tpl", "agg", "usage", "prune_log"] {
            c.execute(&format!("DELETE FROM {t} WHERE name=?"), [name])?;
        }
        Ok((rows, bytes))
    })
}

/// Overwrite then delete a store file (rm --all).
pub fn destroy_file(p: &Path) {
    if let Ok(md) = std::fs::metadata(p) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
            use std::io::Write;
            let z = vec![0u8; 1 << 16];
            let mut left = md.len();
            while left > 0 {
                let n = left.min(z.len() as u64) as usize;
                if f.write_all(&z[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut s = p.as_os_str().to_os_string();
        s.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(s));
    }
}

// ---- watcher -------------------------------------------------------------------------------------------------------------

/// The lock-file key of a path: 16 hex digits of the sha1 of its canonical form (aix-refresh.sh and aix-watch.sh
/// key theirs the same way, from `readlink -m`, so the Rust and bash refresh/watch exclude each other).
pub fn sha_key(p: &Path) -> String {
    let c = crate::sys::canonicalize(&p).unwrap_or_else(|_| p.to_path_buf());
    let mut h = sha1_smol::Sha1::new();
    h.update(c.to_string_lossy().as_bytes());
    h.digest().to_string()[..16].to_string()
}

pub fn lock_dir() -> PathBuf {
    std::env::var_os("AIX_LOCK_DIR").map(PathBuf::from).unwrap_or_else(crate::sys::lock_dir)
}

pub fn watch_lock_path(dir: &Path) -> PathBuf {
    lock_dir().join(format!("{}.logs.lock", sha_key(&logs_db_path(dir))))
}

pub fn heartbeat_path(dir: &Path) -> PathBuf {
    dir.join("logs.watch")
}

/// `(alive, config mtime the watcher last loaded, seconds since its last tick)`.
pub fn watcher_status(dir: &Path) -> (bool, i64, i64) {
    let lock = watch_lock_path(dir);
    let held = match std::fs::OpenOptions::new().read(true).open(&lock) {
        Ok(f) => match f.try_lock() {
            Ok(()) => {
                let _ = f.unlock();
                false
            }
            Err(_) => true,
        },
        Err(_) => false,
    };
    let hb = std::fs::read_to_string(heartbeat_path(dir)).unwrap_or_default();
    let mut it = hb.split_whitespace();
    let ts: i64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let cm: i64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    (held && now() - ts < 60, cm, now() - ts)
}

pub fn cfg_mtime(dir: &Path) -> i64 {
    std::fs::metadata(toml_path(dir)).map(|m| crate::sys::mtime(&m) * 1000 + crate::sys::mtime_nsec(&m) / 1_000_000).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Default)]
struct Sig(Vec<(PathBuf, u64, i64, u64)>);

fn spec_sig(spec: &Spec, repo: &Path) -> Sig {
    let (files, _) = expand(spec, repo);
    Sig(files
        .into_iter()
        .filter_map(|f| {
            let m = std::fs::metadata(&f).ok()?;
            let ino = crate::sys::file_id(&f, &m).1;
            Some((f, m.len(), crate::sys::mtime(&m) * 1_000_000_000 + crate::sys::mtime_nsec(&m), ino))
        })
        .collect())
}

pub struct WatchOpts {
    pub interval_ms: u64,
    pub exit_after_secs: u64,
    pub tick_bytes: u64,
    pub max_ticks: Option<u64>,
}

/// The watcher loop (`aix logs watch`): stat-polls only the registered logs, debounces bursts, ingests at most
/// `tick_bytes` per tick, re-reads logs.toml when it changes (unregistered logs stop being watched at once) and exits when
/// nothing is registered or after `exit_after_secs` without any change. One per store (flock in the shared lock dir).
pub fn watch(dir: &Path, repo: &Path, o: &WatchOpts) -> Result<()> {
    let ld = lock_dir();
    std::fs::create_dir_all(&ld)?;
    let _ = crate::sys::chmod(&ld, 0o700);
    let lock = crate::sys::private_file(std::fs::OpenOptions::new().create(true).truncate(false).write(true)).open(watch_lock_path(dir))?;
    if lock.try_lock().is_err() {
        return Ok(()); // another watcher already covers this store
    }
    LOW_PRIORITY.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::sys::nice(5);
    let store = open_store(&logs_db_path(dir))?;
    let mut cfg_m = -1;
    let mut cfg = Cfg::default();
    let mut sigs: HashMap<String, Sig> = HashMap::new();
    let mut dirty: HashMap<String, u32> = HashMap::new();
    let mut quiet_since = now();
    let mut empty_ticks = 0;
    let mut ticks = 0u64;
    let mut last_paste_prune = 0;
    loop {
        let m = cfg_mtime(dir);
        if m != cfg_m {
            cfg_m = m;
            cfg = load_cfg(dir);
            let names: Vec<String> = cfg.logs.iter().map(|s| s.name.clone()).collect();
            sigs.retain(|k, _| names.contains(k)); // unregistered logs stop being watched at once
            dirty.retain(|k, _| names.contains(k));
            for s in &cfg.logs {
                dirty.entry(s.name.clone()).or_insert(1);
            }
        }
        let _ = std::fs::write(heartbeat_path(dir), format!("{} {} {}\n", now(), cfg_m, std::process::id()));
        let _ = crate::sys::chmod(&heartbeat_path(dir), 0o600);
        if cfg.logs.iter().all(|s| s.paused) {
            empty_ticks += 1;
            if empty_ticks >= 3 {
                let _ = std::fs::remove_file(heartbeat_path(dir));
                return Ok(());
            }
        } else {
            empty_ticks = 0;
        }
        if !repo.exists() {
            return Ok(());
        }
        let mut left = o.tick_bytes;
        let mut any = false;
        for s in cfg.logs.clone() {
            if s.paused {
                continue;
            }
            let sig = spec_sig(&s, repo);
            let changed = sigs.get(&s.name) != Some(&sig);
            sigs.insert(s.name.clone(), sig);
            let d = dirty.entry(s.name.clone()).or_insert(0);
            if changed {
                *d += 1;
                any = true;
                // debounce: wait one quiet tick unless the burst has lasted 3 ticks
                if *d < 3 && *d != 1 {
                    continue;
                }
                if *d == 1 || *d >= 3 {
                    // fallthrough to ingest below
                }
            } else if *d == 0 {
                continue;
            }
            if let Ok(r) = ingest_spec(&store, dir, repo, &cfg, &s, left) {
                left = left.saturating_sub(r.bytes);
                if r.bytes > 0 {
                    any = true;
                }
                // more left in the file than this tick could take: stay dirty
                if left == 0 {
                    *d = 1;
                    continue;
                }
            }
            *d = 0;
        }
        if any {
            quiet_since = now();
            let _ = prune_global(&store, &cfg);
            let _ = eval_alerts(&store.conn);
        }
        // auto-unwatch conditions are evaluated every tick against the current registration file
        if !check_auto_unwatch(&store, dir, repo).is_empty() {
            cfg_m = -1; // re-read the settings on the next tick
        }
        if ticks % 30 == 0 {
            expire_sessions(&store, dir);
        }
        if now() - last_paste_prune > 600 {
            last_paste_prune = now();
            if let Ok(ps) = open_store(&pastes_db_path(dir)) {
                let _ = prune_pastes(&ps, &cfg);
            }
        }
        ticks += 1;
        if o.max_ticks.is_some_and(|m| ticks >= m) || (o.exit_after_secs > 0 && now() - quiet_since > o.exit_after_secs as i64) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(o.interval_ms));
    }
}

// ---- pastes --------------------------------------------------------------------------------------------------------------

/// Guess what a pasted block is.
pub fn detect_kind(text: &str) -> &'static str {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let n = lines.len().max(1);
    let frames = logparse::frames(text, 200);
    if frames.len() >= 2 || text.contains("Traceback (most recent call last)") {
        return match frames.first().map(|f| f.lang) {
            Some("python") => "python traceback",
            Some("js") => "js stack trace",
            _ => "java stack traces",
        };
    }
    let stamped = lines.iter().filter(|l| logparse::parse_ts(l.trim_start()).is_some() || logparse::level_from(l.split_whitespace().next().unwrap_or("").trim_matches(|c| c == '[' || c == ']' || c == ':')).is_some()).count();
    if stamped * 10 >= n * 3 && n >= 3 {
        return "log lines";
    }
    let t = text.trim_start();
    if (t.starts_with('{') || t.starts_with('[')) && serde_json::from_str::<serde_json::Value>(text.trim()).is_ok() || lines.iter().filter(|l| l.trim_start().starts_with('{') && l.trim_end().ends_with('}')).count() * 2 >= n && n >= 3 {
        return "json";
    }
    if lines.iter().any(|l| l.starts_with("diff --git") || l.starts_with("@@ ") || l.starts_with("+++ ")) {
        return "diff";
    }
    let up = text.to_ascii_uppercase();
    if ["SELECT ", "INSERT INTO", "CREATE TABLE", "UPDATE ", "ALTER TABLE"].iter().filter(|k| up.contains(*k)).count() >= 1 && text.contains(';') && up.contains(" FROM ") | up.contains("INSERT") | up.contains("CREATE") | up.contains("ALTER") {
        return "sql";
    }
    if n >= 5 {
        let commas: Vec<usize> = lines.iter().take(20).map(|l| l.matches(',').count()).collect();
        if commas[0] >= 2 && commas.iter().all(|c| *c == commas[0]) {
            return "csv";
        }
    }
    if text.lines().filter(|l| l.contains('=') && !l.contains(' ')).count() * 2 >= n && n >= 3 {
        return "env/config";
    }
    "text"
}

#[derive(Debug, Clone)]
pub struct PasteAdded {
    pub id: i64,
    pub dup: bool,
    pub kind: String,
    pub lines: i64,
    pub bytes: i64,
    pub ns: String,
    /// "" or "truncated: kept N of M lines ..." when part of the text was not kept
    pub note: String,
}

/// Where a stored attachment came from (original path and the stat snapshot used to notice a change).
#[derive(Debug, Clone)]
pub struct SrcInfo {
    pub path: String,
    pub mtime: i64,
    pub size: i64,
}

fn ingest_paste_text(c: &Connection, name: &str, text: &str, kind: &str) -> Result<()> {
    let mut carry = Carry::default();
    let fmt = if kind == "json" { Format::Json } else { Format::Auto };
    let mut off = 0;
    // bounded: at most 200k lines become entries; the whole text stays in `pastes.text` for show/grep
    let body: String = text.lines().take(200_000).collect::<Vec<_>>().join("\n");
    while off < body.len() {
        let end = (off + CHUNK).min(body.len());
        let end = if end < body.len() { body[off..end].rfind('\n').map(|i| off + i + 1).unwrap_or(end) } else { end };
        process_chunk(c, name, &body[off..end], &ChunkOpts { fmt, keep_ips: false, store_debug: true, now: now(), pre_redacted: true }, &mut carry)?;
        off = end;
    }
    Ok(())
}

fn clean_paste(raw: &str) -> String {
    let raw: String = raw.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r')).collect();
    let raw = if raw.len() > ATTACH_TEXT_MAX { raw[raw.ceil_char_boundary(raw.len() - ATTACH_TEXT_MAX)..].to_string() } else { raw };
    redact_text(&raw.replace("\r\n", "\n"), false)
}

/// Store a paste or attachment (`ns` = "paste" | "file"): redacted first (block redaction), hashed on the redacted text
/// (dedupe), then ingested like a log named `<ns>:<id>`. The raw text is never stored, hashed or echoed.
pub fn add_paste(store: &Store, raw: &str, label: &str, kind: Option<&str>, ns: &str, src: Option<&SrcInfo>) -> Result<PasteAdded> {
    add_paste_from(store, raw, label, kind, ns, src, "user")
}

/// `origin`: "user" (typed or piped by the user) or "agent" (text that came from an agent or the harness).
pub fn add_paste_from(store: &Store, raw: &str, label: &str, kind: Option<&str>, ns: &str, src: Option<&SrcInfo>, origin: &str) -> Result<PasteAdded> {
    add_paste_noted(store, raw, label, kind, ns, src, origin, None)
}

/// `pre_lines`: the caller already cut the input to fit (stdin cap) and knows how many lines the whole input had.
#[allow(clippy::too_many_arguments)]
pub fn add_paste_noted(store: &Store, raw: &str, label: &str, kind: Option<&str>, ns: &str, src: Option<&SrcInfo>, origin: &str, pre_lines: Option<usize>) -> Result<PasteAdded> {
    let text = clean_paste(raw);
    let kept_lines = text.lines().count();
    let total_lines = pre_lines.unwrap_or_else(|| raw.lines().count());
    let note = if total_lines > kept_lines {
        format!("truncated: kept {kept_lines} of {total_lines} lines (the text is capped at {} MB)", ATTACH_TEXT_MAX / 1048576)
    } else if kept_lines > 200_000 {
        format!("truncated: parsed entries cover the first 200000 of {kept_lines} lines (paste show/grep read all of the text)")
    } else {
        String::new()
    };
    let hash = blake_hex(text.as_bytes())[..32].to_string();
    let conn = &store.conn;
    if let Ok((id, kind, lines, bytes, n)) = conn.query_row("SELECT id, kind, lines, bytes, ns FROM pastes WHERE hash=?", [&hash], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?))) {
        if n == ns {
            conn.execute("UPDATE pastes SET ts=? WHERE id=?", params![now(), id])?;
            let note: String = conn.query_row("SELECT COALESCE(trunc,'') FROM pastes WHERE id=?", [id], |r| r.get(0)).unwrap_or_default();
            return Ok(PasteAdded { id, dup: true, kind, lines, bytes, ns: n, note });
        }
    }
    let kind = kind.map(|k| k.to_string()).unwrap_or_else(|| detect_kind(&text).to_string());
    let lines = text.lines().count() as i64;
    let bytes = text.len() as i64;
    let hash_col = if conn.query_row("SELECT 1 FROM pastes WHERE hash=?", [&hash], |_| Ok(())).is_ok() { format!("{hash}:{ns}") } else { hash.clone() };
    let id = with_tx(conn, |c| {
        let (sp, sm, ss, sh) = src.map(|s| (display_path(&s.path), s.mtime, s.size, path_hash(c, &s.path))).unwrap_or_default();
        c.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,src,src_mtime,src_size,src_hash,origin,trunc) VALUES('',?,?,?,?,?,?,?,?,?,?,?,?,?,?)", params![now(), kind, lines, bytes, hash_col, redact_text(label, true), text, ns, sp, sm, ss, sh, origin, note])?;
        let id = c.last_insert_rowid();
        let name = format!("{ns}:{id}");
        c.execute("UPDATE pastes SET name=? WHERE id=?", params![name, id])?;
        ingest_paste_text(c, &name, &text, &kind)?;
        Ok(id)
    })?;
    let _ = id;
    crate::privacy::post_ingest(store, &format!("{ns}:{id}"));
    Ok(PasteAdded { id, dup: false, kind, lines, bytes, ns: ns.to_string(), note })
}

/// An attachment whose source file changed since the snapshot: re-read it (same id, old entries dropped).
pub fn refresh_attachment(store: &Store, id: i64, repo: &Path) -> Result<bool> {
    refresh_attachment_at(store, id, repo, None, false)
}

/// `real`: the caller knows the real path (the store keeps only a redacted display form, which is a usable path only when
/// nothing in it needed redacting).
pub fn refresh_attachment_at(store: &Store, id: i64, repo: &Path, real: Option<&Path>, allow_dot: bool) -> Result<bool> {
    let conn = &store.conn;
    let Ok((ns, src, mt, sz, name)) = conn.query_row("SELECT ns, src, src_mtime, src_size, name FROM pastes WHERE id=?", [id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?))) else { return Ok(false) };
    if ns != "file" || src.is_empty() {
        return Ok(false);
    }
    let p = real.map(|r| r.to_path_buf()).unwrap_or_else(|| PathBuf::from(&src));
    let Ok(md) = std::fs::metadata(&p) else { return Ok(false) };
    if crate::sys::mtime(&md) == mt && md.len() as i64 == sz {
        return Ok(false);
    }
    let (raw, info) = read_attachment_with(&p, repo, allow_dot)?;
    let text = clean_paste(&raw);
    let kind = detect_kind(&text).to_string();
    with_tx(conn, |c| {
        for t in ["entries", "tpl", "agg"] {
            c.execute(&format!("DELETE FROM {t} WHERE name=?"), [&name])?;
        }
        let hash = blake_hex(text.as_bytes())[..32].to_string();
        c.execute("UPDATE pastes SET text=?, kind=?, lines=?, bytes=?, hash=?, src_mtime=?, src_size=?, ts=? WHERE id=?", params![text, kind, text.lines().count() as i64, text.len() as i64, format!("{hash}:{id}"), info.mtime, info.size, now(), id])?;
        ingest_paste_text(c, &name, &text, &kind)
    })?;
    Ok(true)
}

/// Read a file named by the user for attaching: safety checks, regular file, size cap, text only.
pub fn read_attachment(p: &Path, repo: &Path) -> Result<(String, SrcInfo)> {
    read_attachment_with(p, repo, false)
}

pub fn read_attachment_with(p: &Path, repo: &Path, allow_dot: bool) -> Result<(String, SrcInfo)> {
    let (f, md, canon) = open_checked(p, repo, allow_dot)?;
    if md.len() > ATTACH_MAX_BYTES {
        bail!("{}: refused (larger than {} MB)", display_path(&p.to_string_lossy()), ATTACH_MAX_BYTES / 1048576);
    }
    let mut buf = Vec::with_capacity(md.len().min(ATTACH_MAX_BYTES) as usize);
    f.take(ATTACH_MAX_BYTES).read_to_end(&mut buf)?;
    if canon.extension().is_some_and(|e| e == "gz") {
        buf = gunzip(&buf[..]);
    }
    // UTF-16 with its BOM (Windows PowerShell's Out-File) is text: decoded, not refused as binary
    let utf16 = matches!(buf.as_slice(), [0xff, 0xfe, ..] | [0xfe, 0xff, ..]);
    if !utf16 && buf[..buf.len().min(4096)].contains(&0) {
        bail!("{}: skipped (binary file)", display_path(&p.to_string_lossy()));
    }
    Ok((crate::query::decode_text(&buf), SrcInfo { path: canon.to_string_lossy().to_string(), mtime: crate::sys::mtime(&md), size: md.len() as i64 }))
}

/// A gzip file's bytes, every member, decompressed in process (no `gzip` on PATH needed); a damaged member ends it
/// with what came before, as `gzip -dc` prints.
fn gunzip(r: impl Read) -> Vec<u8> {
    let mut out = vec![];
    let _ = flate2::read::MultiGzDecoder::new(r).read_to_end(&mut out);
    out
}

/// Pastes: whole-paste pruning by retention then by the global byte budget (oldest first). Each item's size is what it
/// really holds (its text plus its entry rows); pruning stops as soon as the total is within the budget and never removes
/// the newest item (an item larger than the whole budget is kept alone and reported by `aix logs list`/privacy-check).
pub fn prune_pastes(store: &Store, cfg: &Cfg) -> Result<Pruned> {
    let conn = &store.conn;
    let days = cfg.budget.paste_retain_days.unwrap_or(PASTE_RETAIN_DAYS) as i64;
    let cap = cfg.budget.paste_global_mb.unwrap_or(PASTE_GLOBAL_MB) as i64 * 1048576;
    let mut total = Pruned::default();
    // fast path (the hook calls this on every paste): the text bytes alone, times a generous row-overhead factor, fit the budget
    let (n_old, text_sum): (i64, i64) = conn.query_row("SELECT COALESCE(sum(ts<?1),0), COALESCE(sum(bytes),0) FROM pastes", [now() - days * 86400], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if n_old == 0 && text_sum.saturating_mul(6) <= cap {
        return Ok(total);
    }
    let mut drop_ids: Vec<(i64, String, i64)> = vec![];
    {
        let mut st = conn.prepare("SELECT id, name, bytes FROM pastes WHERE ts<?")?;
        drop_ids.extend(st.query_map([now() - days * 86400], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.flatten());
    }
    // (id, name, real size) oldest first
    let items: Vec<(i64, String, i64, i64)> = conn
        .prepare("SELECT p.id, p.name, p.bytes, length(p.text) + COALESCE((SELECT sum(bytes) FROM entries e WHERE e.name=p.name),0) FROM pastes p ORDER BY p.ts, p.id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .flatten()
        .collect();
    let mut used: i64 = items.iter().filter(|i| !drop_ids.iter().any(|d| d.0 == i.0)).map(|i| i.3).sum();
    let n_items = items.len();
    let mut kept = n_items - items.iter().filter(|i| drop_ids.iter().any(|d| d.0 == i.0)).count();
    for (id, name, bytes, size) in &items {
        if used <= cap || kept <= 1 {
            break;
        }
        if drop_ids.iter().any(|d| d.0 == *id) {
            continue;
        }
        used -= size;
        kept -= 1;
        drop_ids.push((*id, name.clone(), *bytes));
    }
    for (id, name, b) in drop_ids {
        let (r, by) = purge_name_quiet(store, &name)?;
        conn.execute("DELETE FROM pastes WHERE id=?", [id])?;
        total.rows += r.max(1);
        total.bytes += by + b;
    }
    if total.rows > 0 {
        shrink_full(conn);
    }
    Ok(total)
}

/// Give every free page back (the paste store must really shrink, not just stop growing).
pub fn shrink_full(conn: &Connection) {
    let av: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0)).unwrap_or(0);
    if av == 2 {
        let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
    } else {
        let _ = conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;");
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

// ---- hook helpers --------------------------------------------------------------------------------------------------------

/// A PreToolUse Bash command reading a registered log with tail/grep/cat/...: the registered name, when it does.
pub fn registered_log_in_command(dir: &Path, cmd: &str) -> Option<String> {
    if !toml_path(dir).exists() {
        return None;
    }
    let first = cmd.split_whitespace().next().unwrap_or("");
    let reads = cmd.split(['|', ';', '&']).any(|seg| {
        let w = seg.split_whitespace().next().unwrap_or("");
        matches!(w.rsplit('/').next().unwrap_or(""), "tail" | "grep" | "egrep" | "fgrep" | "cat" | "less" | "head" | "zgrep" | "zcat" | "awk" | "sed" | "rg" | "more")
    }) || matches!(first, "tail" | "grep" | "cat" | "less" | "head");
    if !reads {
        return None;
    }
    let cfg = load_cfg(dir);
    for tok in cmd.split_whitespace() {
        let t = tok.trim_matches(|c| c == '"' || c == '\'');
        if !t.starts_with('/') && !t.starts_with("./") && !t.starts_with("~/") && !t.contains('.') {
            continue;
        }
        let t = if let (Some(rest), Some(h)) = (t.strip_prefix("~/"), home()) { h.join(rest).to_string_lossy().to_string() } else { t.to_string() };
        for s in &cfg.logs {
            let hit = match s.kind.as_str() {
                "file" => t == s.path || t.starts_with(&format!("{}.", s.path)),
                "dir" => t.starts_with(&format!("{}/", s.path.trim_end_matches('/'))) || t == s.path,
                _ => Path::new(&s.path).parent().is_some_and(|d| Path::new(&t).parent() == Some(d)) && glob_match(&Path::new(&s.path).file_name().unwrap().to_string_lossy(), &Path::new(&t).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()),
            };
            if hit {
                return Some(s.name.clone());
            }
        }
    }
    None
}


// ---- live detection ----------------------------------------------------------------------------------------------------

/// Is another process of ours holding (dev, ino) open for writing? Reads /proc/<pid>/fd of the user's own processes only
/// (no root needed), bounded to 600 processes.
pub fn has_writer(dev: u64, ino: u64) -> bool {
    writer_pid(dev, ino).is_some()
}

/// The pid of another process of ours holding (dev, ino) open for writing, if one can be seen.
pub fn writer_pid(dev: u64, ino: u64) -> Option<i64> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return None };
    let me = std::process::id().to_string();
    for e in rd.flatten().take(4000).filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit())).take(600) {
        let pid = e.file_name().to_string_lossy().to_string();
        if pid == me {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten().take(64) {
            let Ok(md) = std::fs::metadata(fd.path()) else { continue };
            if crate::sys::file_id(&fd.path(), &md) == (dev, ino) {
                let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", fd.file_name().to_string_lossy())).unwrap_or_default();
                let flags = info.lines().find_map(|l| l.strip_prefix("flags:")).map(|f| u32::from_str_radix(f.trim(), 8).unwrap_or(0)).unwrap_or(0);
                if flags & 3 != 0 {
                    return pid.parse().ok();
                }
            }
        }
    }
    None
}

/// `live` (growing, a writer holds it open, or a recently touched *.log), `rotated` (rotation-style name, quiet),
/// `static` or `gone`; and whether it can be tailed (regular, readable, not compressed).
pub fn classify(path: &Path, check_writer: bool) -> (&'static str, bool) {
    let Ok(md) = std::fs::metadata(path) else { return ("gone", false) };
    if !md.is_file() {
        return ("static", false);
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let gz = name.ends_with(".gz");
    let age = now() - crate::sys::mtime(&md);
    let readable = std::fs::File::open(path).is_ok();
    let rotated_name = {
        use std::sync::LazyLock;
        static R: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(\.\d+|\.\d{4}-?\d\d-?\d\d.*|-\d{8}.*|\.old)(\.gz)?$|\.gz$").unwrap());
        R.is_match(&name)
    };
    let live = !gz && (age <= 120 || (check_writer && {
        let (dev, ino) = crate::sys::file_id(path, &md);
        has_writer(dev, ino)
    }) || (name.contains(".log") && !rotated_name && age < 3600));
    let class = if live { "live" } else if rotated_name { "rotated" } else { "static" };
    (class, readable && !gz)
}

// ---- throughput (ETA) --------------------------------------------------------------------------------------------------

pub fn rate_get(conn: &Connection, key: &str) -> Option<f64> {
    conn.query_row("SELECT value FROM meta WHERE key=?", [format!("rate:{key}")], |r| r.get::<_, String>(0)).ok().and_then(|v| v.parse().ok())
}

/// EWMA (0.7 old + 0.3 new) of units/second after a run that did enough work to measure.
pub fn rate_update(conn: &Connection, key: &str, units: f64, secs: f64) {
    if secs <= 0.0 || units <= 0.0 {
        return;
    }
    let obs = units / secs;
    let v = rate_get(conn, key).map(|o| o * 0.7 + obs * 0.3).unwrap_or(obs);
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", params![format!("rate:{key}"), v.to_string()]);
}

/// "~9 s left" / "estimating..." for `left` units at the stored rate of `key`.
pub fn eta_text(conn: &Connection, key: &str, left: f64) -> (String, Option<f64>) {
    match rate_get(conn, key) {
        Some(r) if r > 0.0 => {
            let s = left / r;
            (if s < 1.0 { "<1 s left".to_string() } else if s < 90.0 { format!("~{:.0} s left", s) } else { format!("~{:.0} min left", s / 60.0) }, Some(s))
        }
        _ => ("estimating...".to_string(), None),
    }
}

// ---- session logs (prompt-named live files) ------------------------------------------------------------------------------

/// Unregister (and purge) session logs idle for `session_hours`. Returns the names removed.
pub fn expire_sessions(store: &Store, dir: &Path) -> Vec<String> {
    let mut cfg = load_cfg(dir);
    let hours = cfg.budget.session_hours.unwrap_or(4) as i64;
    let t = now();
    let mut gone = vec![];
    for s in cfg.logs.clone() {
        if !s.session {
            continue;
        }
        let last_q: i64 = store.conn.query_row("SELECT last_q FROM usage WHERE name=?", [&s.name], |r| r.get(0)).unwrap_or(0);
        if t - last_q.max(s.added) > hours * 3600 {
            gone.push(s.name.clone());
        }
    }
    if !gone.is_empty() {
        cfg.logs.retain(|s| !gone.contains(&s.name));
        if save_cfg(dir, &cfg).is_ok() {
            for n in &gone {
                let _ = purge_name(store, n);
            }
        }
    }
    gone
}

// ---- alerts --------------------------------------------------------------------------------------------------------------

pub const MAX_ALERTS: i64 = 20;

/// Evaluate active alerts against entries ingested since each alert's last look. Hits are deduped by template (a template
/// that hit within 10 minutes only bumps its count) and rate-limited to 20 new hit rows per alert per hour. Returns new hit rows.
pub fn eval_alerts(conn: &Connection) -> Result<i64> {
    let t = now();
    conn.execute("UPDATE alerts SET active=0 WHERE active=1 AND expires<?", [t])?;
    let alerts: Vec<(i64, String, String, i64, i64, i64)> = conn.prepare("SELECT id, name, re, min_level, once, last_id FROM alerts WHERE active=1")?.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.flatten().collect();
    let max_id: i64 = conn.query_row("SELECT COALESCE(max(id),0) FROM entries", [], |r| r.get(0))?;
    let mut new_hits = 0;
    for (id, name, re_s, min_level, once, last_id) in alerts {
        if last_id >= max_id {
            continue;
        }
        let Ok(re) = regex::RegexBuilder::new(&re_s).size_limit(1 << 20).build() else { continue };
        let mut st = conn.prepare("SELECT id, name, ts, level, tid, msg, body, logger FROM entries WHERE id>?1 AND id<=?2 AND level>=?3 AND (?4='' OR ?4='all' OR name=?4) ORDER BY id LIMIT 20000")?;
        let rows: Vec<(i64, String, i64, i64, String, String, String, String)> = st.query_map(params![last_id, max_id, min_level, name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)))?.flatten().collect();
        let mut fired = false;
        for (eid, ename, ts, level, tid, msg, body, logger) in rows {
            if !entry_matches(&re, level, &logger, &msg, &body) {
                continue;
            }
            conn.execute("UPDATE alerts SET hits=hits+1 WHERE id=?", [id])?;
            let existing: Option<i64> = conn.query_row("SELECT id FROM alert_hits WHERE alert_id=? AND tid=? AND last_ts>? ORDER BY last_ts DESC LIMIT 1", params![id, tid, ts - 600], |r| r.get(0)).ok();
            if let Some(h) = existing {
                conn.execute("UPDATE alert_hits SET count=count+1, last_ts=max(last_ts,?), entry_id=? WHERE id=?", params![ts, eid, h])?;
                continue;
            }
            let recent: i64 = conn.query_row("SELECT count(*) FROM alert_hits WHERE alert_id=? AND at>?", params![id, t - 3600], |r| r.get(0))?;
            if recent >= 20 {
                continue; // rate limit
            }
            conn.execute("INSERT INTO alert_hits(alert_id, entry_id, name, tid, level, ts, last_ts, count, msg, seen, at) VALUES(?,?,?,?,?,?,?,1,?,0,?)", params![id, eid, ename, tid, level, ts, ts, clip_chars(&msg, 200), t])?;
            new_hits += 1;
            fired = true;
        }
        conn.execute("UPDATE alerts SET last_id=? WHERE id=?", params![max_id, id])?;
        if fired && once != 0 {
            conn.execute("UPDATE alerts SET active=0 WHERE id=?", [id])?;
        }
    }
    Ok(new_hits)
}

/// The one line the prompt hook may print: unseen alert hits (then marked seen). Never repeats.
pub fn unseen_alert_line(dir: &Path) -> Option<String> {
    let p = logs_db_path(dir);
    if !p.exists() {
        return None;
    }
    let st = open_store(&p).ok()?;
    let c = &st.conn;
    let n: i64 = c.query_row("SELECT count(*) FROM alert_hits WHERE seen=0", [], |r| r.get(0)).ok()?;
    if n == 0 {
        return None;
    }
    let rows: Vec<(i64, String, String, i64, i64)> = c
        .prepare("SELECT h.alert_id, h.name, a.re, sum(h.count), max(h.level) FROM alert_hits h JOIN alerts a ON a.id=h.alert_id WHERE h.seen=0 GROUP BY h.alert_id ORDER BY sum(h.count) DESC")
        .ok()?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .ok()?
        .flatten()
        .collect();
    let (id, name, re, cnt, lv) = rows.first()?.clone();
    c.execute("UPDATE alert_hits SET seen=1 WHERE seen=0", []).ok()?;
    let more = if rows.len() > 1 { format!(" (+{} more alerts: aix logs alerts --unseen)", rows.len() - 1) } else { String::new() };
    Some(format!("aix alert: {cnt} new {} line(s) in {name} matching '{}' — aix logs show alert:{id}{more}", logparse::level_name(lv as u8), clip_chars(&re, 40)))
}


// ---- background paste / attachment ingest ----------------------------------------------------------------------------------

/// A row for an item whose text is still being redacted and ingested by a detached worker.
pub fn placeholder_paste(store: &Store, ns: &str, kind: &str, lines: i64, bytes: i64, src: Option<&SrcInfo>) -> Result<i64> {
    let c = &store.conn;
    let tmp = format!("pending:{}:{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    let (sp, sm, ss, sh) = src.map(|s| (display_path(&s.path), s.mtime, s.size, path_hash(c, &s.path))).unwrap_or_default();
    c.execute("INSERT INTO pastes(name,ts,kind,lines,bytes,hash,label,text,ns,src,src_mtime,src_size,src_hash,state,done,total,t0,pid) VALUES('',?,?,?,?,?,'','',?,?,?,?,?,'indexing',0,?,?,0)", params![now(), kind, lines, bytes, tmp, ns, sp, sm, ss, sh, lines, now()])?;
    let id = c.last_insert_rowid();
    c.execute("UPDATE pastes SET name=? WHERE id=?", params![format!("{ns}:{id}"), id])?;
    Ok(id)
}

/// The worker side: redact, dedupe, store the text, then ingest in small transactions so progress is visible.
pub fn finish_paste(store: &Store, id: i64, raw: &str) -> Result<()> {
    let c = &store.conn;
    let (ns, name): (String, String) = c.query_row("SELECT ns, name FROM pastes WHERE id=?", [id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    c.execute("UPDATE pastes SET pid=? WHERE id=?", params![std::process::id() as i64, id])?;
    let t0 = std::time::Instant::now();
    let text = clean_paste(raw);
    let hash = blake_hex(text.as_bytes())[..32].to_string();
    if let Ok((other, oname)) = c.query_row("SELECT id, name FROM pastes WHERE hash=? AND id<>?", params![hash, id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) {
        let _ = other;
        c.execute("UPDATE pastes SET state='dup', err=?, text='' WHERE id=?", params![oname, id])?;
        return Ok(());
    }
    let kind = detect_kind(&text).to_string();
    let lines = text.lines().count() as i64;
    c.execute("UPDATE pastes SET text=?, kind=?, lines=?, bytes=?, hash=?, total=? WHERE id=?", params![text, kind, lines, text.len() as i64, hash, lines, id])?;
    let fmt = if kind == "json" { Format::Json } else { Format::Auto };
    let body: String = text.lines().take(200_000).collect::<Vec<_>>().join("\n");
    let mut carry = Carry::default();
    let (mut off, mut done) = (0usize, 0i64);
    while off < body.len() {
        let end = (off + 256 * 1024).min(body.len());
        let end = if end < body.len() { body[off..end].rfind('\n').map(|i| off + i + 1).unwrap_or(end) } else { end };
        let chunk = &body[off..end];
        with_tx(c, |c| {
            process_chunk(c, &name, chunk, &ChunkOpts { fmt, keep_ips: false, store_debug: true, now: now(), pre_redacted: true }, &mut carry)?;
            Ok(())
        })?;
        done += chunk.lines().count() as i64;
        c.execute("UPDATE pastes SET done=? WHERE id=?", params![done, id])?;
        off = end;
    }
    c.execute("UPDATE pastes SET state='ready', done=total, pid=0 WHERE id=?", [id])?;
    rate_update(c, "paste_lines", lines as f64, t0.elapsed().as_secs_f64());
    let _ = ns;
    Ok(())
}

/// Start a detached worker (own session, no inherited fds). `stdin_data` goes through a private temp file in the aix
/// directory (0600, `--input PATH`, deleted by the worker once read) so the caller (a hook with a latency budget) never
/// blocks on a pipe while the worker starts.
pub fn spawn_worker(repo: &Path, db: &Path, args: &[&str], stdin_data: Option<&str>) -> Result<()> {
    use std::io::Write;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--repo").arg(repo).arg("--db").arg(db).arg("--no-refresh").args(args).env("AIX_LOGS_CLI", "1").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    let mut tmp: Option<PathBuf> = None;
    if let Some(d) = stdin_data {
        let dir = dir_of(db);
        std::fs::create_dir_all(&dir)?;
        let p = dir.join(format!(".in-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
        let mut f = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(&p)?;
        f.write_all(d.as_bytes())?;
        cmd.arg("--input").arg(&p);
        tmp = Some(p);
    }
    cmd.stdin(std::process::Stdio::null());
    crate::sys::detach(&mut cmd);
    match cmd.spawn() {
        Ok(ch) => {
            std::mem::forget(ch); // detached: the worker outlives the hook
            Ok(())
        }
        Err(e) => {
            if let Some(p) = tmp {
                let _ = std::fs::remove_file(p);
            }
            Err(e.into())
        }
    }
}

/// (state, done, total, eta text) of a paste row, cleaning up a dead worker.
pub fn paste_state(conn: &Connection, id: i64) -> Option<(String, i64, i64, String, String)> {
    let (state, done, total, pid, t0, err): (String, i64, i64, i64, i64, String) = conn.query_row("SELECT state, done, total, pid, t0, err FROM pastes WHERE id=?", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).ok()?;
    if state == "indexing" && ((pid > 0 && !crate::sys::pid_alive(pid)) || (pid == 0 && now() - t0 > 30)) {
        let _ = conn.execute("UPDATE pastes SET state='failed', err='the indexing worker died (re-add the paste or file)' WHERE id=?", [id]);
        return Some(("failed".into(), done, total, String::new(), "the indexing worker died (re-add the paste or file)".into()));
    }
    let eta = if state == "indexing" { eta_text(conn, "paste_lines", (total - done).max(0) as f64).0 } else { String::new() };
    Some((state, done, total, eta, err))
}


/// Retroactive user masks (`aix mask add`) for the log and paste stores: the same re-masking `remask` does for the code
/// index, over their text columns. Returns (values changed, tables touched).
pub fn remask_stores(index_db: &Path, progress: &mut dyn FnMut(String)) -> (usize, usize) {
    let dir = dir_of(index_db);
    let (mut changed, mut tables) = (0, 0);
    for (file, specs) in [("logs.db", &[("entries", &["msg", "body", "logger", "thread", "err", "exc"][..]), ("tpl", &["tpl", "sample", "frames", "exc", "logger"][..]), ("alert_hits", &["msg"][..])][..]), ("pastes.db", &[("entries", &["msg", "body", "logger", "thread", "err", "exc"][..]), ("tpl", &["tpl", "sample", "frames", "exc", "logger"][..]), ("pastes", &["text", "label", "src"][..])][..])] {
        let p = dir.join(file);
        if !p.exists() {
            continue;
        }
        let Ok(st) = open_store(&p) else { continue };
        for (t, cols) in specs {
            let mut n_t = 0;
            let sel = format!("SELECT rowid, {} FROM {t}", cols.join(", "));
            let rows: Vec<(i64, Vec<String>)> = match st.conn.prepare(&sel) {
                Ok(mut q) => q.query_map([], |r| Ok((r.get(0)?, (0..cols.len()).map(|i| r.get::<_, Option<String>>(i + 1).map(|o| o.unwrap_or_default())).collect::<rusqlite::Result<Vec<_>>>()?))).map(|i| i.flatten().collect()).unwrap_or_default(),
                Err(_) => continue,
            };
            let _ = with_tx(&st.conn, |c| {
                for (rid, vals) in &rows {
                    for (col, v) in cols.iter().zip(vals) {
                        if let Some(new) = aix_extract::masks::apply(v) {
                            c.execute(&format!("UPDATE {t} SET {col}=? WHERE rowid=?"), params![new, rid])?;
                            n_t += 1;
                        }
                    }
                }
                Ok(())
            });
            if n_t > 0 {
                changed += n_t;
                tables += 1;
                progress(format!("re-masked {n_t} value(s) in {file}:{t}"));
            }
        }
    }
    // data sets (`aix put`): stored lines and named-field rows
    let n_sets = crate::sets::remask(&dir);
    if n_sets > 0 {
        changed += n_sets;
        tables += 1;
        progress(format!("re-masked {n_sets} value(s) in sets.db"));
    }
    (changed, tables)
}


// ---- unwatch / auto-unwatch ----------------------------------------------------------------------------------------------

pub fn meta_set(conn: &Connection, key: &str, v: i64) {
    let _ = conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", params![key, v.to_string()]);
}

pub fn meta_get(conn: &Connection, key: &str) -> Option<i64> {
    conn.query_row("SELECT value FROM meta WHERE key=?", [key], |r| r.get::<_, String>(0)).ok().and_then(|v| v.parse().ok())
}

fn meta_add(conn: &Connection, key: &str, n: i64) {
    meta_set(conn, key, meta_get(conn, key).unwrap_or(0) + n);
}

fn dur_short(secs: i64) -> String {
    if secs % 86400 == 0 && secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Counters and baselines for a (re)started watch: lines/bytes since, last growth, match cursor, writer pid.
pub fn watch_started(store: &Store, repo: &Path, spec: &Spec, seq: i64) {
    let c = &store.conn;
    for k in ["wl", "wb"] {
        meta_set(c, &format!("{k}:{}", spec.name), 0);
    }
    meta_set(c, &format!("wlast:{}", spec.name), now());
    meta_set(c, &format!("wmatch:{}", spec.name), seq);
    let (files, _) = expand(spec, repo);
    let pid = files
        .first()
        .and_then(|f| {
            let (dev, ino) = crate::sys::file_id(f, &std::fs::metadata(f).ok()?);
            writer_pid(dev, ino)
        })
        .unwrap_or(0);
    meta_set(c, &format!("wpid:{}", spec.name), pid);
}

/// Pause a watch (data and registration stay). `reason` is shown by `aix logs list` and once by the prompt hook.
pub fn set_paused(store: &Store, dir: &Path, name: &str, reason: &str, notify: bool) -> bool {
    let mut cfg = load_cfg(dir);
    let Some(s) = cfg.logs.iter_mut().find(|s| s.name == name) else { return false };
    if s.paused {
        return false;
    }
    s.paused = true;
    s.pause_reason = reason.to_string();
    s.paused_at = now();
    s.notice_pending = notify;
    let ok = save_cfg(dir, &cfg).is_ok();
    let _ = store.conn.execute("INSERT INTO watch_events VALUES(?,?,?,?)", params![now(), name, "paused", reason]);
    ok
}

/// Evaluate every auto-unwatch condition of every watched log; pauses the ones that hit. Returns (name, reason).
pub fn check_auto_unwatch(store: &Store, dir: &Path, repo: &Path) -> Vec<(String, String)> {
    let cfg = load_cfg(dir);
    let t = now();
    let c = &store.conn;
    let mut done = vec![];
    for s in cfg.logs.iter().filter(|s| !s.paused) {
        let base = s.watch_started.max(s.added);
        let last_growth = meta_get(c, &format!("wlast:{}", s.name)).unwrap_or(0).max(base);
        let last_q = c.query_row("SELECT last_q FROM usage WHERE name=?", [&s.name], |r| r.get::<_, i64>(0)).unwrap_or(0).max(base);
        let idle = s.idle_secs.or(if s.session { Some(3600) } else { Some(cfg.budget.watch_idle_hours.unwrap_or(2) as i64 * 3600) }).filter(|x| *x > 0);
        let unq = s.unqueried_secs.or(Some(cfg.budget.watch_unqueried_hours.unwrap_or(24) as i64 * 3600)).filter(|x| *x > 0);
        let mut why: Option<String> = None;
        if s.until_ts.is_some_and(|u| t >= u) {
            why = Some("time limit".into());
        }
        if why.is_none() {
            if let Some(i) = idle.filter(|i| t - last_growth > *i) {
                why = Some(format!("idle {}", dur_short(i)));
            }
        }
        if why.is_none() {
            if let Some(u) = unq.filter(|u| t - last_q > *u) {
                why = Some(format!("unqueried {}", dur_short(u)));
            }
        }
        if why.is_none() {
            if let Some(re) = s.until_match.as_deref().and_then(|r| regex::RegexBuilder::new(r).size_limit(1 << 20).build().ok()) {
                let last = meta_get(c, &format!("wmatch:{}", s.name)).unwrap_or(0);
                let rows: Vec<(i64, String, String, i64, String)> = c.prepare("SELECT id, msg, body, level, logger FROM entries WHERE name=? AND id>? ORDER BY id LIMIT 20000").and_then(|mut q| q.query_map(params![s.name, last], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).map(|i| i.flatten().collect())).unwrap_or_default();
                if let Some(m) = rows.iter().find(|(_, m, b, lv, lg)| entry_matches(&re, *lv, lg, m, b)) {
                    why = Some(format!("matched e{}", m.0));
                }
                if let Some(l) = rows.last() {
                    meta_set(c, &format!("wmatch:{}", s.name), l.0);
                }
            }
        }
        if why.is_none() && s.stop_lines.is_some_and(|n| meta_get(c, &format!("wl:{}", s.name)).unwrap_or(0) >= n) {
            why = Some("line limit".into());
        }
        if why.is_none() && s.stop_bytes.is_some_and(|n| meta_get(c, &format!("wb:{}", s.name)).unwrap_or(0) >= n) {
            why = Some("size limit".into());
        }
        if why.is_none() {
            let (files, _) = expand(s, repo);
            if files.is_empty() {
                why = Some("file gone".into());
            } else if files.iter().all(|f| !classify(f, false).1) {
                why = Some("not tailable".into());
            }
        }
        if why.is_none() {
            if let Some(pid) = meta_get(c, &format!("wpid:{}", s.name)).filter(|p| *p > 0) {
                if !crate::sys::pid_alive(pid) {
                    why = Some("writer exited".into());
                }
            }
        }
        if let Some(w) = why {
            // finish what is already in the file before stopping (not past a line/size limit that just fired)
            if !matches!(w.as_str(), "line limit" | "size limit") {
                let _ = ingest_spec(store, dir, repo, &cfg, s, 16 * 1024 * 1024);
            }
            if set_paused(store, dir, &s.name, &w, true) {
                done.push((s.name.clone(), w));
            }
        }
    }
    done
}

/// The one line the prompt hook prints about auto-stopped watches (then cleared: shown once).
pub fn paused_notices(dir: &Path) -> Option<String> {
    let mut cfg = load_cfg(dir);
    let pending: Vec<(String, String)> = cfg.logs.iter().filter(|s| s.paused && s.notice_pending).map(|s| (s.name.clone(), s.pause_reason.clone())).collect();
    if pending.is_empty() {
        return None;
    }
    for s in cfg.logs.iter_mut() {
        s.notice_pending = false;
    }
    let _ = save_cfg(dir, &cfg);
    let l: Vec<String> = pending.iter().take(2).map(|(n, r)| format!("stopped watching {n} ({r}) — aix logs watch {n} to resume")).collect();
    Some(format!("aix: {}{}", l.join("; "), if pending.len() > 2 { format!(" (+{} more: aix logs list)", pending.len() - 2) } else { String::new() }))
}
