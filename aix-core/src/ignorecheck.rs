//! `aix ignore-check [--json] [--suggest]`: a read-only .gitignore preflight before a repo is indexed.
//!
//! Each finding is one line: severity, what, how many files and bytes, and the exact .gitignore line to add (or the
//! `git rm --cached` to run). Checks: no .gitignore / not a git repo; entries normally ignored for each detected stack
//! (`STACKS`, probed with `git check-ignore --no-index`, so a missing `node_modules/` is reported before the directory
//! exists); untracked, not-ignored build output, dependencies, caches, logs, data and large files; secret-like files
//! (`walk::is_secret`, names only, never contents); tracked files that should not be; aix's own `.aix/`.
//! Exit status: 0 clean, 1 findings, 2 error. aix never writes .gitignore: `--suggest` prints a block to append.
//!
//! The gate: the first index build of a repo (and `update --full`) refuses while there are findings the user has not
//! accepted, printing the STOP block. `--accept-ignore` (or `aix ignore-check --accept`) records the findings' hash in
//! `.aix/config`; the same findings are not asked about again. Not gated (tooling): an index outside `<repo>/.aix`
//! (an explicit `--db`/`AIX_DB` elsewhere: benches, evals), and `AIX_ACCEPT_IGNORE=1` (CI and test harnesses).
//! After acceptance a refresh never blocks: a new high-severity finding adds one line to `aix card` and `stats`.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::walk;

/// One stack: marker files (a name, `*.ext`, or `*.ext/` for a directory component), the .gitignore entries it
/// normally needs, and whether the entries are probed at the repo root instead of next to each marker.
pub struct Stack {
    pub name: &'static str,
    pub markers: &'static [&'static str],
    pub entries: &'static [&'static str],
    pub at_root: bool,
}

/// Expected .gitignore entries per stack (several stacks can apply; extend here).
pub const STACKS: &[Stack] = &[
    Stack {
        name: "Node",
        markers: &["package.json"],
        entries: &["node_modules/", "dist/", "build/", ".next/", "coverage/", "*.log"],
        at_root: false,
    },
    Stack { name: "Rust", markers: &["Cargo.toml"], entries: &["target/"], at_root: false },
    Stack { name: "Maven", markers: &["pom.xml"], entries: &["target/"], at_root: false },
    Stack {
        name: "Gradle",
        markers: &["build.gradle", "build.gradle.kts"],
        entries: &["build/", ".gradle/"],
        at_root: false,
    },
    Stack {
        name: "Python",
        markers: &["pyproject.toml", "requirements.txt", "setup.py"],
        entries: &["__pycache__/", "*.pyc", ".venv/", "venv/", ".pytest_cache/", "*.egg-info/"],
        at_root: false,
    },
    Stack { name: "Go", markers: &["go.mod"], entries: &["vendor/"], at_root: false },
    Stack { name: ".NET", markers: &["*.csproj", "*.sln"], entries: &["bin/", "obj/"], at_root: false },
    Stack { name: "CocoaPods", markers: &["Podfile"], entries: &["Pods/"], at_root: false },
    Stack {
        name: "Xcode",
        markers: &["*.xcodeproj/", "*.xcworkspace/"],
        entries: &["DerivedData/", "xcuserdata/"],
        at_root: true,
    },
    Stack {
        name: "Android",
        markers: &["AndroidManifest.xml"],
        entries: &["local.properties", ".gradle/", "build/"],
        at_root: true,
    },
    Stack { name: "PHP", markers: &["composer.json"], entries: &["vendor/"], at_root: false },
    Stack { name: "Ruby", markers: &["Gemfile"], entries: &["vendor/bundle/", ".bundle/"], at_root: false },
    Stack { name: "Terraform", markers: &["*.tf"], entries: &[".terraform/", "*.tfstate*"], at_root: false },
    Stack { name: "any", markers: &[], entries: &[".env*", ".DS_Store"], at_root: true },
];

/// Expected entries that hold secrets: missing is high even before such a file exists.
const SECRET_ENTRIES: &[&str] = &[".env*", "*.tfstate*"];

/// Untracked directories by name: (name, what they are).
const JUNK_DIRS: &[(&str, &str)] = &[
    ("node_modules", "dependencies"),
    ("target", "build output"),
    ("dist", "build output"),
    ("build", "build output"),
    ("out", "build output"),
    (".next", "build output"),
    (".nuxt", "build output"),
    ("coverage", "test coverage"),
    (".venv", "virtualenv"),
    ("venv", "virtualenv"),
    ("env", "virtualenv"),
    ("__pycache__", "cache"),
    (".pytest_cache", "cache"),
    (".gradle", "cache"),
    (".cache", "cache"),
    (".terraform", "dependencies"),
    ("Pods", "dependencies"),
    ("DerivedData", "build output"),
    ("obj", "build output"),
    (".idea", "editor settings (ignoring them is a choice)"),
    (".vscode", "editor settings (ignoring them is a choice)"),
    ("logs", "logs"),
    ("tmp", "temp files"),
];

/// Tracked directories that are never source.
const TRACKED_JUNK_DIRS: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".venv",
    ".pytest_cache",
    ".next",
    ".nuxt",
    ".gradle",
    ".terraform",
    "DerivedData",
    "xcuserdata",
];

const LARGE_BYTES: u64 = 5 * 1024 * 1024;
/// Findings shown (text); `--json` lists all.
pub const SHOWN: usize = 20;
/// Entries counted per directory (a bigger one says "N+").
const COUNT_CAP: u64 = 5000;

pub const STOP_LINE: &str = "STOP: .gitignore is missing or incomplete. Ask the user before continuing: fix .gitignore (suggested lines above), or re-run with --accept-ignore to index as is.";

#[derive(Clone, Debug)]
pub struct Finding {
    pub sev: &'static str,
    pub kind: &'static str,
    /// stacks / group for --suggest
    pub group: String,
    pub what: String,
    pub paths: Vec<String>,
    /// lines to add to .gitignore
    pub suggest: Vec<String>,
    /// a command instead of (or besides) a .gitignore line
    pub fix: String,
    pub files: u64,
    pub bytes: u64,
    pub capped: bool,
}

impl Finding {
    fn new(sev: &'static str, kind: &'static str, group: &str, what: String, suggest: Option<String>) -> Finding {
        Finding {
            sev,
            kind,
            group: group.into(),
            what,
            paths: vec![],
            suggest: suggest.into_iter().collect(),
            fix: String::new(),
            files: 0,
            bytes: 0,
            capped: false,
        }
    }
    /// Stable identity: counts left out (a growing node_modules is not a new finding), presence kept (a first `.env`
    /// under an entry that was only "expected" is).
    pub fn key(&self) -> String {
        let present = self.files > 0 || self.bytes > 0;
        format!(
            "{}|{}|{}|{}|{present}",
            self.sev,
            self.kind,
            self.suggest.join(","),
            if self.suggest.is_empty() { self.paths.join(",") } else { String::new() }
        )
    }
    pub fn item_hash(&self) -> String {
        blake3::hash(self.key().as_bytes()).to_hex()[..12].to_string()
    }
    fn size_text(&self) -> String {
        if self.files == 0 && self.bytes == 0 {
            return String::new();
        }
        let plus = if self.capped { "+" } else { "" };
        format!("{}{plus} file{}, {}{plus}", self.files, if self.files == 1 { "" } else { "s" }, human(self.bytes))
    }
    pub fn line(&self) -> String {
        let size = self.size_text();
        let names = if self.paths.is_empty() || self.kind == "expected" {
            String::new()
        } else {
            let mut n: Vec<&str> = self.paths.iter().take(3).map(String::as_str).collect();
            if self.paths.len() > 3 {
                n.push("...");
            }
            n.join(" ")
        };
        let detail = match (size.is_empty(), names.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!(" ({size})"),
            (true, false) => format!(" ({names})"),
            (false, false) => format!(" ({size}: {names})"),
        };
        let mut fix = vec![];
        if !self.suggest.is_empty() {
            let mut l: Vec<String> = self.suggest.iter().take(3).map(|s| format!("`{s}`")).collect();
            if self.suggest.len() > 3 {
                l.push(format!("(+{} more: --suggest)", self.suggest.len() - 3));
            }
            fix.push(format!("add to .gitignore: {}", l.join(" ")));
        }
        if !self.fix.is_empty() {
            fix.push(self.fix.clone());
        }
        format!(
            "[{}] {}{detail}{}",
            self.sev.to_uppercase(),
            self.what,
            if fix.is_empty() { String::new() } else { format!(" -> {}", fix.join("; ")) }
        )
    }
    fn json(&self) -> serde_json::Value {
        serde_json::json!({"severity": self.sev, "kind": self.kind, "group": self.group, "what": self.what, "paths": self.paths, "suggest": self.suggest,
            "fix": self.fix, "files": self.files, "bytes": self.bytes, "capped": self.capped})
    }
}

#[derive(Default, Debug)]
pub struct Report {
    pub git: bool,
    pub gitignore: bool,
    pub findings: Vec<Finding>,
    /// what the walk would index / skip (no .gitignore, not a git repo): context for the user's decision
    pub info: Vec<String>,
    /// detected stacks (name, marker dirs)
    pub stacks: Vec<(String, Vec<String>)>,
}

impl Report {
    pub fn high(&self) -> usize {
        self.findings.iter().filter(|f| f.sev == "high").count()
    }
    /// Hash of the whole set of findings (what an acceptance covers).
    pub fn hash(&self) -> String {
        let mut items: Vec<String> = self.findings.iter().map(Finding::item_hash).collect();
        items.sort();
        blake3::hash(items.join(" ").as_bytes()).to_hex()[..16].to_string()
    }
}

pub fn human(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1024 {
        format!("{:.0} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

// ---- git helpers ------------------------------------------------------------------------------------------------------

fn git_z(repo: &Path, args: &[&str]) -> Option<Vec<String>> {
    let o =
        Command::new("git").arg("-C").arg(repo).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(
        o.stdout
            .split(|b| *b == 0)
            .filter(|x| !x.is_empty())
            .map(|x| String::from_utf8_lossy(x).into_owned())
            .collect(),
    )
}

/// The paths `git check-ignore` says are ignored (`no_index`: also when tracked; used for probes).
fn ignored(repo: &Path, paths: &[String], no_index: bool) -> HashSet<String> {
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut c = Command::new("git");
    c.arg("-C").arg(repo).args(["check-ignore", "--stdin", "-z"]);
    if no_index {
        c.arg("--no-index");
    }
    let Ok(mut ch) = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return HashSet::new();
    };
    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_bytes());
        input.push(0);
    }
    let mut stdin = ch.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(&input);
        }
        drop(stdin);
    });
    let out = ch.wait_with_output().ok();
    let _ = writer.join();
    out.map(|o| {
        o.stdout.split(|b| *b == 0).filter(|x| !x.is_empty()).map(|x| String::from_utf8_lossy(x).into_owned()).collect()
    })
    .unwrap_or_default()
}

fn is_git(repo: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--is-inside-work-tree"])
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success() && o.stdout.starts_with(b"true"))
}

fn toplevel(repo: &Path) -> Option<PathBuf> {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--show-toplevel"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status.success().then(|| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
}

// ---- small helpers ----------------------------------------------------------------------------------------------------

fn base(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        rel.to_string()
    } else {
        format!("{dir}/{rel}")
    }
}

/// `*.log` -> matches `x.log`; only `*` is special.
fn glob_match(glob: &str, name: &str) -> bool {
    let parts: Vec<&str> = glob.split('*').collect();
    if parts.len() == 1 {
        return glob == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || !name[first.len()..].ends_with(last) || name.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// A path under `entry` that `git check-ignore` can test before anything exists there.
fn probe_of(entry: &str) -> String {
    let e = entry.replace('*', "aixprobe");
    if let Some(d) = e.strip_suffix('/') {
        format!("{d}/aixprobe")
    } else {
        e
    }
}

/// Does `rel` (a repo path) lead through a symlinked directory (any proper ancestor is a symlink)?
fn beyond_symlink(repo: &Path, rel: &str) -> bool {
    let mut cur = repo.to_path_buf();
    let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    for p in parts.iter().take(parts.len().saturating_sub(1)) {
        cur.push(p);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

/// (files, bytes, capped) under a directory, never following symlinks; `node_modules` is not walked (top level only).
fn count(abs: &Path) -> (u64, u64, bool) {
    if abs.file_name().is_some_and(|n| n == "node_modules") {
        let n = std::fs::read_dir(abs).map(|r| r.count() as u64).unwrap_or(0);
        return (n, 0, true);
    }
    let Ok(md) = std::fs::symlink_metadata(abs) else { return (0, 0, false) };
    if !md.is_dir() {
        return (1, md.len(), false);
    }
    let (mut files, mut bytes, mut seen) = (0u64, 0u64, 0u64);
    let mut stack = vec![abs.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > COUNT_CAP {
                return (files, bytes, true);
            }
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() && !e.file_type().is_ok_and(|t| t.is_symlink()) {
                stack.push(e.path());
            } else if m.is_file() {
                files += 1;
                bytes += m.len();
            }
        }
    }
    (files, bytes, false)
}

/// The .gitignore line for a secret-like file: a pattern for the common families, else the anchored path.
fn secret_line(rel: &str) -> String {
    let name = base(rel).to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|x| x.1).unwrap_or("");
    if name.starts_with(".env") {
        return ".env*".into();
    }
    for p in ["id_rsa", "id_ed25519", "id_ecdsa"] {
        if name.starts_with(p) {
            return format!("{p}*");
        }
    }
    if matches!(ext, "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" | "tok" | "token") {
        return format!("*.{ext}");
    }
    if name.starts_with("service-account") || name.starts_with("service_account") {
        return "service-account*.json".into();
    }
    format!("/{}", rel.trim_end_matches('/'))
}

fn junk_dir(abs: &Path, name: &str) -> Option<&'static str> {
    let why = JUNK_DIRS.iter().find(|(n, _)| *n == name).map(|x| x.1)?;
    // `env/` is a common source folder name: only a virtualenv counts
    if name == "env" && !abs.join("pyvenv.cfg").exists() && !abs.join("bin/activate").exists() {
        return None;
    }
    Some(why)
}

/// (kind, severity, why, .gitignore line) for an untracked file.
fn junk_file(rel: &str, size: u64) -> Option<(&'static str, &'static str, String, String)> {
    let name = base(rel);
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|x| x.1).unwrap_or("");
    if walk::is_secret(rel) {
        return Some((
            "secret",
            "high",
            "secret-like file, untracked and not ignored (`git add .` would commit it)".into(),
            secret_line(rel),
        ));
    }
    let pat = match () {
        _ if ext == "pyc" => Some(("*.pyc", "Python bytecode")),
        _ if ext == "log" => Some(("*.log", "log file")),
        _ if name == ".DS_Store" => Some((".DS_Store", "macOS metadata")),
        _ if name == "Thumbs.db" => Some(("Thumbs.db", "Windows thumbnails")),
        _ if matches!(ext, "sqlite" | "sqlite3") => Some(("*.sqlite*", "local database")),
        _ if ext == "db" => Some(("*.db", "local database")),
        _ => None,
    };
    if let Some((p, why)) = pat {
        return Some(("junk", "medium", format!("{why}, untracked and not ignored"), p.to_string()));
    }
    if size > LARGE_BYTES {
        return Some((
            "large",
            "medium",
            format!("large file (> {}), untracked and not ignored", human(LARGE_BYTES)),
            format!("/{rel}"),
        ));
    }
    None
}

/// Findings merged by (kind, first suggested line).
#[derive(Default)]
struct Acc {
    map: BTreeMap<(String, String), Finding>,
}

impl Acc {
    fn add(&mut self, f: Finding, path: &str, files: u64, bytes: u64, capped: bool) {
        // large files group by folder (one finding, one anchored line each); the rest by their .gitignore line
        // untracked findings with the same .gitignore line are one finding (an expected `.env*` and a `conf/.env.local`)
        let class = match f.kind {
            "large" => "large",
            k if k.starts_with("tracked") => "tracked",
            _ => "untracked",
        };
        let second = if f.kind == "large" {
            format!("{}/", path.rsplit_once('/').map(|x| x.0).unwrap_or(""))
        } else {
            f.suggest.first().cloned().unwrap_or_else(|| path.to_string())
        };
        let e = self.map.entry((class.to_string(), second)).or_insert(f.clone());
        if e.kind == "expected" && files > 0 {
            e.what = e.what.replace("(not present yet)", "(present, untracked)");
        }
        if e.fix.is_empty() && !f.fix.is_empty() {
            e.fix = f.fix.clone();
        }
        for l in &f.suggest {
            if !e.suggest.contains(l) {
                e.suggest.push(l.clone());
            }
        }
        if sev_rank(f.sev) < sev_rank(e.sev) {
            e.sev = f.sev;
            e.what = f.what.clone();
        }
        if !f.group.is_empty() && !e.group.split(" + ").any(|g| g == f.group) {
            e.group = if e.group.is_empty() { f.group.clone() } else { format!("{} + {}", e.group, f.group) };
        }
        if !path.is_empty() && !e.paths.iter().any(|p| p == path) {
            e.paths.push(path.to_string());
        }
        e.files += files;
        e.bytes += bytes;
        e.capped |= capped;
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

fn marker_match(marker: &str, rel: &str) -> Option<String> {
    let dir = rel.rsplit_once('/').map(|x| x.0).unwrap_or("").to_string();
    if let Some(m) = marker.strip_suffix('/') {
        // a directory component (`App.xcodeproj/`)
        let comps: Vec<&str> = rel.split('/').collect();
        let i = comps.iter().take(comps.len().saturating_sub(1)).position(|c| glob_match(m, c))?;
        return Some(comps[..i].join("/"));
    }
    glob_match(marker, base(rel)).then_some(dir)
}

/// Stacks found in a file list: (stack index, marker dirs, shallowest first, at most 6).
fn detect(files: &[String]) -> Vec<(usize, Vec<String>)> {
    let mut out = vec![];
    for (i, s) in STACKS.iter().enumerate() {
        let mut dirs: Vec<String> = vec![];
        if s.markers.is_empty() {
            dirs.push(String::new());
        }
        for f in files {
            // test fixtures and examples are not this repo's stacks
            if f.split('/').any(|c| {
                matches!(c, "node_modules" | "vendor" | ".git" | "fixtures" | "__fixtures__" | "testdata" | "examples")
            }) || f.ends_with('/')
            {
                continue;
            }
            for m in s.markers {
                if let Some(d) = marker_match(m, f) {
                    let d = if s.at_root { String::new() } else { d };
                    if !dirs.contains(&d) {
                        dirs.push(d);
                    }
                }
            }
        }
        if dirs.is_empty() {
            continue;
        }
        dirs.sort_by_key(|d| (d.matches('/').count() + usize::from(!d.is_empty()), d.clone()));
        dirs.truncate(6);
        out.push((i, dirs));
    }
    out
}

fn sorted_has_prefix(sorted: &[String], prefix: &str) -> usize {
    let start = sorted.partition_point(|x| x.as_str() < prefix);
    sorted[start..].iter().take_while(|x| x.starts_with(prefix)).count()
}

// ---- the scan ---------------------------------------------------------------------------------------------------------

pub fn scan(repo: &Path) -> Report {
    let repo = crate::sys::canonicalize(&repo).unwrap_or_else(|_| repo.to_path_buf());
    if !is_git(&repo) {
        return scan_plain(&repo);
    }
    let mut r = Report { git: true, ..Default::default() };
    r.gitignore = repo.join(".gitignore").is_file() || toplevel(&repo).is_some_and(|t| t.join(".gitignore").is_file());
    let mut tracked = git_z(&repo, &["ls-files", "-z", "--cached"]).unwrap_or_default();
    tracked.sort();
    let untracked =
        git_z(&repo, &["ls-files", "-z", "-o", "--exclude-standard", "--directory", "--no-empty-directory"])
            .unwrap_or_default();
    let mut acc = Acc::default();
    let mut top: Vec<Finding> = vec![];
    if !r.gitignore {
        top.push(Finding::new(
            "high",
            "no-gitignore",
            "",
            "no .gitignore at the repo root: nothing keeps build output, dependencies or secrets out of git (`git add .` would commit them) or out of an index of untracked files".into(),
            None,
        ));
        r.info = would_index(&repo);
    }
    // aix's own directory
    if repo.join(".aix").is_dir() {
        let n = sorted_has_prefix(&tracked, ".aix/");
        if n > 0 {
            let mut f = Finding::new(
                "high",
                "aix-dir",
                "aix",
                ".aix/ (the local index) has tracked files".into(),
                Some(".aix/".into()),
            );
            f.fix = "git rm -r --cached .aix".into();
            f.files = n as u64;
            top.push(f);
        } else if repo.join(".aix/.gitignore").exists()
            && !ignored(&repo, &[".aix/index.db".to_string()], true).contains(".aix/index.db")
        {
            // (no .aix/.gitignore yet: aix writes it when it opens the index)
            top.push(Finding::new(
                "high",
                "aix-dir",
                "aix",
                ".aix/ (the local index) is not ignored: .aix/.gitignore is missing or overridden".into(),
                Some(".aix/".into()),
            ));
        }
    }
    // stack-expected entries
    let mut marker_src: Vec<String> = tracked.clone();
    marker_src.extend(untracked.iter().filter(|u| !u.ends_with('/')).cloned());
    let stacks = detect(&marker_src);
    let mut probes: Vec<(usize, String, &'static str, String)> = vec![]; // (stack, dir, entry, probe)
    for (si, dirs) in &stacks {
        r.stacks.push((STACKS[*si].name.to_string(), dirs.clone()));
        for d in dirs {
            for e in STACKS[*si].entries {
                probes.push((*si, d.clone(), e, join(d, &probe_of(e))));
            }
        }
    }
    let mut extra_probes: Vec<String> = vec![];
    if stacks.iter().any(|(si, _)| STACKS[*si].name == "any") {
        extra_probes.push(".env.local".into()); // `.env` alone leaves `.env.local` unignored
    }
    // git refuses a whole check-ignore batch when one path goes through a symlink ("beyond a symbolic link"), and a
    // symlinked directory (a worktree's node_modules linked to the main tree's) holds nothing git or aix reads through
    let all: Vec<String> =
        probes.iter().map(|p| p.3.clone()).chain(extra_probes.iter().cloned()).filter(|p| !beyond_symlink(&repo, p)).collect();
    let ign = ignored(&repo, &all, true);
    let mut covered: Vec<String> = vec![];
    for (si, d, e, probe) in &probes {
        if beyond_symlink(&repo, probe) {
            covered.push(join(d, e.trim_end_matches('/')));
            continue;
        }
        let mut missing = !ign.contains(probe);
        if *e == ".env*" && !ign.contains(".env.local") {
            missing = true;
        }
        if !missing {
            continue;
        }
        let s = &STACKS[*si];
        let glob = e.contains('*');
        let plain = e.trim_end_matches('/');
        let target = join(d, plain);
        // intentionally committed (a tracked vendor/ or a source dir named build/): not "missing"
        if !glob && (sorted_has_prefix(&tracked, &format!("{target}/")) > 0 || tracked.binary_search(&target).is_ok()) {
            continue;
        }
        let (mut files, mut bytes, mut capped) = (0, 0, false);
        let mut exists = false;
        if glob {
            let pat = plain;
            for u in &untracked {
                let under = d.is_empty() || u.starts_with(&format!("{d}/"));
                if under && glob_match(pat, base(u)) && (u.ends_with('/') == e.ends_with('/')) {
                    exists = true;
                    let (f, b, c) = count(&repo.join(u.trim_end_matches('/')));
                    files += f;
                    bytes += b;
                    capped |= c;
                    covered.push(u.trim_end_matches('/').to_string());
                }
            }
        } else if std::fs::symlink_metadata(repo.join(&target)).is_ok() {
            exists = true;
            (files, bytes, capped) = count(&repo.join(&target));
            covered.push(target.clone());
        }
        let secret = SECRET_ENTRIES.contains(e);
        let sev = if exists || secret { "high" } else { "medium" };
        let group = if s.name == "any" { "any stack".to_string() } else { s.name.to_string() };
        let state = if exists { "present, untracked".to_string() } else { "not present yet".to_string() };
        let what = format!("expected .gitignore entry missing for {group}: {e} ({state})");
        let f = Finding::new(sev, "expected", &group, what, Some(e.to_string()));
        acc.add(f, &target, files, bytes, capped);
    }
    // untracked, not ignored
    let is_covered = |u: &str| {
        let u = u.trim_end_matches('/');
        covered.iter().any(|c| u == c || u.starts_with(&format!("{c}/")))
    };
    for u in &untracked {
        if is_covered(u) || u == ".aix/" || u.starts_with(".aix/") {
            continue;
        }
        let abs = repo.join(u.trim_end_matches('/'));
        if let Some(dir) = u.strip_suffix('/') {
            if walk::is_secret(&format!("{dir}/x")) {
                let (f, b, c) = count(&abs);
                let fd = Finding::new(
                    "high",
                    "secret",
                    "secrets",
                    "secret-like directory, untracked and not ignored (`git add .` would commit it)".into(),
                    Some(format!("/{dir}/")),
                );
                acc.add(fd, dir, f, b, c);
                continue;
            }
            if let Some(why) = junk_dir(&abs, base(dir)) {
                let (f, b, c) = count(&abs);
                let fd = Finding::new(
                    "medium",
                    "untracked-dir",
                    "build output, dependencies, caches",
                    format!("{}/: {why}, untracked and not ignored", base(dir)),
                    Some(format!("{}/", base(dir))),
                );
                acc.add(fd, dir, f, b, c);
                continue;
            }
            expand(&repo, dir, &mut acc);
            continue;
        }
        let size = std::fs::symlink_metadata(&abs).map(|m| m.len()).unwrap_or(0);
        if let Some((kind, sev, why, line)) = junk_file(u, size) {
            let group = if kind == "secret" { "secrets" } else { "build output, dependencies, caches" };
            acc.add(Finding::new(sev, kind, group, why, Some(line)), u, 1, size, false);
        }
    }
    // tracked files that should not be
    tracked_checks(&repo, &tracked, &mut acc);
    let mut found: Vec<Finding> = acc.map.into_values().collect();
    found.sort_by(|a, b| {
        (sev_rank(a.sev), kind_rank(a.kind), &a.what).cmp(&(sev_rank(b.sev), kind_rank(b.kind), &b.what))
    });
    top.extend(found);
    r.findings = top;
    r
}

fn kind_rank(k: &str) -> u8 {
    match k {
        "no-gitignore" | "not-git" => 0,
        "secret" | "tracked-secret" => 1,
        "aix-dir" => 2,
        "expected" => 3,
        _ => 4,
    }
}

/// An untracked directory git collapsed: look inside (capped, junk dirs not entered) for secrets, junk and large files.
fn expand(repo: &Path, dir: &str, acc: &mut Acc) {
    let mut files: Vec<(String, u64)> = vec![];
    let mut dirs: Vec<(String, &'static str)> = vec![];
    let mut stack = vec![dir.to_string()];
    let mut seen = 0u64;
    'w: while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(repo.join(&d)) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > COUNT_CAP {
                break 'w;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = format!("{d}/{name}");
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if name == ".git" {
                    continue;
                }
                if let Some(why) = junk_dir(&e.path(), &name) {
                    dirs.push((rel, why));
                } else {
                    stack.push(rel);
                }
            } else if ft.is_file() {
                files.push((rel, e.metadata().map(|m| m.len()).unwrap_or(0)));
            }
        }
    }
    let mut q: Vec<String> = files.iter().map(|f| f.0.clone()).collect();
    q.extend(dirs.iter().map(|d| format!("{}/aixprobe", d.0)));
    let ign = ignored(repo, &q, false);
    for (rel, why) in dirs {
        if ign.contains(&format!("{rel}/aixprobe")) {
            continue;
        }
        let (f, b, c) = count(&repo.join(&rel));
        let n = base(&rel).to_string();
        acc.add(
            Finding::new(
                "medium",
                "untracked-dir",
                "build output, dependencies, caches",
                format!("{n}/: {why}, untracked and not ignored"),
                Some(format!("{n}/")),
            ),
            &rel,
            f,
            b,
            c,
        );
    }
    for (rel, size) in files {
        if ign.contains(&rel) {
            continue;
        }
        if let Some((kind, sev, why, line)) = junk_file(&rel, size) {
            let group = if kind == "secret" { "secrets" } else { "build output, dependencies, caches" };
            acc.add(Finding::new(sev, kind, group, why, Some(line)), &rel, 1, size, false);
        }
    }
}

/// A file secret-like by name only whose content holds no credential value: a template (`.env.example`,
/// `config.sample`, `*.template`, `*.dist`) with blank or placeholder values, or a SQL migration named after a
/// password/token column. Its text is read (at most 256 KB) and must pass the redactor unchanged.
fn clean_secret_name(repo: &Path, rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let template = name.split('.').skip(1).any(|p| matches!(p, "example" | "sample" | "template" | "tmpl" | "dist" | "defaults")) || name.ends_with("-example") || name.ends_with("_example");
    let migration = walk::ext_lower(&name) == "sql";
    if !(template || migration) {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(repo.join(rel)) else { return false };
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(repo.join(rel)) else { return false };
    // every line: a `KEY=value` whose value is a placeholder (blank, <...>, ${...}, changeme ...) is fine; any other
    // line must pass the redactor unchanged, and a secret-named key must not hold a real-looking value
    !text.lines().any(|l| {
        let l = l.trim();
        if let Some((k, v)) = l.split_once(['=', ':']) {
            let k = k.trim().trim_start_matches("export ").to_ascii_lowercase();
            let v = v.trim().trim_matches(['"', '\'']);
            if !k.contains(' ') && placeholder(v) {
                return false;
            }
            let secret_key = ["password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential"].iter().any(|w| k.contains(w));
            if secret_key && !k.contains(' ') {
                return true;
            }
        }
        !aix_extract::redact::redact_with_hits(l).1.is_empty()
    })
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.is_empty()
        || v.starts_with(['<', '$', '{', '%'])
        || l.chars().all(|c| c == 'x' || c == '*' || c == '.' || c == '-' || c == '_')
        || ["changeme", "change-me", "change_me", "replace", "your", "example", "placeholder", "dummy", "secret", "password", "todo", "fixme", "none", "null", "xxx", "redacted", "<", "set-me", "setme"].iter().any(|w| l.contains(w))
}

fn tracked_checks(repo: &Path, tracked: &[String], acc: &mut Acc) {
    let set: HashSet<&str> = tracked.iter().map(String::as_str).collect();
    let size = |t: &str| std::fs::symlink_metadata(repo.join(t)).map(|m| m.len()).unwrap_or(0);
    for t in tracked {
        if t.starts_with(".aix/") {
            continue;
        }
        if walk::is_secret(t) && !clean_secret_name(repo, t) {
            let mut f = Finding::new(
                "high",
                "tracked-secret",
                "secrets",
                "secret-like file is tracked (committed)".into(),
                Some(secret_line(t)),
            );
            f.fix = "git rm --cached <file> (and rotate the secret if it was pushed)".into();
            acc.add(f, t, 1, size(t), false);
            continue;
        }
        let comps: Vec<&str> = t.split('/').collect();
        let name = comps[comps.len() - 1];
        let dir_hit =
            comps[..comps.len() - 1].iter().position(|c| TRACKED_JUNK_DIRS.contains(c)).map(|i| comps[..=i].join("/"));
        // target/ next to Cargo.toml or pom.xml, dist/ next to package.json: build output by construction
        let built = comps[..comps.len() - 1].iter().position(|c| *c == "target" || *c == "dist").and_then(|i| {
            let parent = comps[..i].join("/");
            let markers: &[&str] = if comps[i] == "target" { &["Cargo.toml", "pom.xml"] } else { &["package.json"] };
            markers.iter().any(|m| set.contains(join(&parent, m).as_str())).then(|| comps[..=i].join("/"))
        });
        if let Some(d) = dir_hit.or(built) {
            let mut f = Finding::new(
                "medium",
                "tracked-junk",
                "tracked build output",
                format!("{}/ is tracked (build output, dependencies or caches)", base(&d)),
                Some(format!("{}/", base(&d))),
            );
            f.fix = format!("git rm -r --cached {d}");
            acc.add(f, &d, 1, size(t), false);
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if name == ".DS_Store" || name == "Thumbs.db" || lower.ends_with(".pyc") || lower.contains(".tfstate") {
            let line = if lower.ends_with(".pyc") {
                "*.pyc".to_string()
            } else if lower.contains(".tfstate") {
                "*.tfstate*".to_string()
            } else {
                name.to_string()
            };
            let sev = if lower.contains(".tfstate") { "high" } else { "medium" };
            let mut f = Finding::new(
                sev,
                "tracked-junk",
                "tracked build output",
                format!("{line} files are tracked"),
                Some(line),
            );
            f.fix = "git rm --cached <file>".into();
            acc.add(f, t, 1, size(t), false);
        }
    }
}

/// Not a git repo: there is nothing to ignore by. Say so, and list what the plain walk would index and skip.
fn scan_plain(repo: &Path) -> Report {
    let mut r = Report { git: false, ..Default::default() };
    let mut top = vec![Finding::new(
        "high",
        "not-git",
        "",
        "not a git repository: there is no .gitignore to go by, so aix would index every wanted file of a plain walk (build/vendor dirs and secret-named files are skipped by name only)".into(),
        None,
    )];
    top[0].fix = "`git init` and add a .gitignore, or accept the walk as is".into();
    let mut acc = Acc::default();
    let mut files: Vec<String> = vec![];
    let mut stack = vec![String::new()];
    let mut seen = 0u64;
    'w: while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(repo.join(&d)) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > 50_000 {
                break 'w;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = join(&d, &name);
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if matches!(name.as_str(), ".git" | ".aix") {
                    continue;
                }
                if walk::is_secret(&format!("{rel}/x")) {
                    let (f, b, c) = count(&e.path());
                    acc.add(
                        Finding::new(
                            "high",
                            "secret",
                            "secrets",
                            "secret-like directory (skipped by name, never read)".into(),
                            Some(format!("/{rel}/")),
                        ),
                        &rel,
                        f,
                        b,
                        c,
                    );
                } else if let Some(why) = junk_dir(&e.path(), &name) {
                    let (f, b, c) = count(&e.path());
                    acc.add(
                        Finding::new(
                            "medium",
                            "untracked-dir",
                            "build output, dependencies, caches",
                            format!(
                                "{name}/: {why} (the walk skips some by name; a .gitignore would make it explicit)"
                            ),
                            Some(format!("{name}/")),
                        ),
                        &rel,
                        f,
                        b,
                        c,
                    );
                } else {
                    stack.push(rel);
                }
            } else if ft.is_file() {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                if walk::is_secret(&rel) {
                    acc.add(
                        Finding::new(
                            "high",
                            "secret",
                            "secrets",
                            "secret-like file (skipped by name, never read)".into(),
                            Some(secret_line(&rel)),
                        ),
                        &rel,
                        1,
                        size,
                        false,
                    );
                } else if size > LARGE_BYTES {
                    acc.add(
                        Finding::new(
                            "medium",
                            "large",
                            "build output, dependencies, caches",
                            format!("large file (> {})", human(LARGE_BYTES)),
                            Some(format!("/{rel}")),
                        ),
                        &rel,
                        1,
                        size,
                        false,
                    );
                }
                files.push(rel);
            }
        }
    }
    for (si, dirs) in detect(&files) {
        r.stacks.push((STACKS[si].name.to_string(), dirs));
    }
    let mut found: Vec<Finding> = acc.map.into_values().collect();
    found.sort_by(|a, b| {
        (sev_rank(a.sev), kind_rank(a.kind), &a.what).cmp(&(sev_rank(b.sev), kind_rank(b.kind), &b.what))
    });
    top.extend(found);
    r.findings = top;
    r.info = would_index(repo);
    r
}

/// "would index: N files (B) — top dirs ..." from the same listing the index uses.
fn would_index(repo: &Path) -> Vec<String> {
    let (listed, skipped) = walk::list_with_skips(repo, &[], 1_500_000, false, &[]);
    let mut by: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total = 0u64;
    for l in &listed {
        let top = l.path.split_once('/').map(|x| format!("{}/", x.0)).unwrap_or_else(|| "(root files)".into());
        let e = by.entry(top).or_default();
        e.0 += 1;
        e.1 += l.size;
        total += l.size;
    }
    let mut v: Vec<(String, (u64, u64))> = by.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1 .0));
    let tops: Vec<String> = v.iter().take(8).map(|(d, (n, b))| format!("{d} {n} files {}", human(*b))).collect();
    let mut out = vec![format!(
        "would index: {} files, {}{}",
        listed.len(),
        human(total),
        if tops.is_empty() { String::new() } else { format!(" — {}", tops.join(", ")) }
    )];
    if !skipped.files.is_empty() {
        out.push(format!("would skip as too big or unreadable: {} files", skipped.files.len()));
    }
    out
}

// ---- acceptance (.aix/config) -----------------------------------------------------------------------------------------

fn accept_path(repo: &Path) -> PathBuf {
    repo.join(".aix").join("config")
}

/// (hash, accepted item hashes) from `.aix/config`.
/// The main working tree of a linked `git worktree` (None for the main tree itself or a non-git dir).
pub fn main_worktree(repo: &Path) -> Option<PathBuf> {
    let o = Command::new("git").arg("-C").arg(repo).args(["rev-parse", "--path-format=absolute", "--git-common-dir"]).stderr(Stdio::null()).output().ok()?;
    if !o.status.success() {
        return None;
    }
    let common = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim());
    if common.file_name().is_none_or(|n| n != ".git") {
        return None; // a bare repo's worktree: no main working tree to inherit from
    }
    let main = common.parent()?.to_path_buf();
    let a = crate::sys::canonicalize(&main).ok()?;
    let b = crate::sys::canonicalize(&repo).ok()?;
    (a != b).then_some(a)
}

fn origin_url(repo: &Path) -> Option<String> {
    let o = Command::new("git").arg("-C").arg(repo).args(["config", "--get", "remote.origin.url"]).stderr(Stdio::null()).output().ok()?;
    let u = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.status.success() && !u.is_empty()).then_some(u)
}

/// A remote URL without the forms that name the same repository differently (`x.git`, `x/`, `x/.git`).
fn same_url(u: &str) -> String {
    let u = u.trim_end_matches('/');
    let u = u.strip_suffix("/.git").unwrap_or(u);
    u.strip_suffix(".git").unwrap_or(u).to_string()
}

/// The checkout this one was made from, when there is one on this machine: the main working tree of a linked
/// `git worktree`, the directory a local clone was cloned from (`origin` is a path or file:// URL), or the enclosing
/// repository when this clone sits inside it with the same `origin` (a scratch clone under a project). Never itself.
pub fn parent_repo(repo: &Path) -> Option<PathBuf> {
    if let Some(m) = main_worktree(repo) {
        return Some(m);
    }
    let me = crate::sys::canonicalize(&repo).ok()?;
    if !me.join(".git").exists() {
        return None;
    }
    let url = origin_url(&me)?;
    // Windows: file:///C:/x is C:/x
    let file = |p: &str| match p.as_bytes() {
        [b'/', d, b':', ..] if cfg!(windows) && d.is_ascii_alphabetic() => p[1..].to_string(),
        _ => p.to_string(),
    };
    let local = url.strip_prefix("file://").map(file).or_else(|| (!url.contains("://") && !url.contains('@')).then(|| url.clone()));
    if let Some(p) = local {
        let p = if Path::new(&p).is_absolute() { PathBuf::from(&p) } else { me.join(&p) };
        let p = if p.file_name().is_some_and(|n| n == ".git") { p.parent().map(Path::to_path_buf).unwrap_or(p) } else { p };
        if let Ok(c) = crate::sys::canonicalize(&p) {
            if c != me && c.join(".git").exists() {
                return Some(c);
            }
        }
    }
    // a clone of the same remote nested inside a checkout of it
    let up = crate::index::find_repo(me.parent()?);
    if up != me && up.join(".git").exists() && me.starts_with(&up) && origin_url(&up).is_some_and(|u| same_url(&u) == same_url(&url)) {
        return Some(up);
    }
    None
}

/// The accepted findings for this checkout: its own `.aix/config`, else the parent checkout's (a linked worktree's
/// main working tree, or the repo a local clone came from: `parent_repo`). Only the hash decides: a checkout whose
/// findings differ (another untracked .env, a changed .gitignore) is asked.
pub fn read_accept_or_main(repo: &Path) -> Option<(String, HashSet<String>)> {
    read_accept(repo).or_else(|| parent_repo(repo).and_then(|m| read_accept(&m)))
}

pub fn read_accept(repo: &Path) -> Option<(String, HashSet<String>)> {
    let p = accept_path(repo);
    if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
        return None;
    }
    let t = std::fs::read_to_string(p).ok()?;
    let val = |k: &str| {
        t.lines().find_map(|l| {
            let (a, b) = l.split_once('=')?;
            (a.trim() == k).then(|| b.trim().trim_matches('"').to_string())
        })
    };
    let h = val("accept_ignore")?;
    let items = val("accept_ignore_items").unwrap_or_default().split_whitespace().map(str::to_string).collect();
    Some((h, items))
}

/// Record that the user accepted these findings (`.aix/config`, private; `.aix` is created like the index does).
pub fn write_accept(repo: &Path, r: &Report) -> Result<(), String> {
    let dir = repo.join(".aix");
    match std::fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(format!("{} is a symlink or not a directory; refusing to write through it", dir.display()))
        }
        Ok(_) => {}
        Err(_) => {
            crate::sys::private_dir(&mut std::fs::DirBuilder::new()).create(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
    }
    // keep it out of git like Index::open does (never through a symlink: create_new refuses an existing name)
    if std::fs::symlink_metadata(dir.join(".gitignore")).is_err() {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create_new(true).open(dir.join(".gitignore")) {
            let _ = f.write_all(b"# aix index (local cache)\n*\n");
        }
    }
    let p = accept_path(repo);
    if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("{} is a symlink; refusing to write through it", p.display()));
    }
    let mut items: Vec<String> = r.findings.iter().map(Finding::item_hash).collect();
    items.sort();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let body = format!(
        "# aix: .gitignore findings the user accepted (aix ignore-check). Delete this file to be asked again.\naccept_ignore = \"{}\"\naccept_ignore_items = \"{}\"\naccepted_at = \"{now}\"\n",
        r.hash(),
        items.join(" ")
    );
    let tmp = dir.join(format!(".config.{}.tmp", std::process::id()));
    let mut f = crate::sys::private_file(std::fs::OpenOptions::new().write(true).create_new(true)).open(&tmp).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, &p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("writing {}: {e}", p.display())
    })
}

// ---- the gate ---------------------------------------------------------------------------------------------------------

static PASSED: AtomicBool = AtomicBool::new(false);

/// Tooling and harnesses are not interactive first builds: an index outside `<repo>/.aix` (explicit `--db`/`AIX_DB`
/// elsewhere, as benches and evals use) and `AIX_ACCEPT_IGNORE=1` are never gated.
pub fn bypassed(repo: &Path, db: &Path) -> bool {
    if crate::config::env_var("ACCEPT_IGNORE").is_some_and(|v| v == "1") {
        return true;
    }
    let repo = crate::sys::canonicalize(&repo).unwrap_or_else(|_| repo.to_path_buf());
    let Some(parent) = db.parent() else { return true };
    let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let parent = crate::sys::canonicalize(&parent).unwrap_or_else(|_| parent.to_path_buf());
    // `.aix` itself may not exist yet (a first build): resolve the directory it would be created in
    let up = parent.parent().map(|p| if p.as_os_str().is_empty() { Path::new(".") } else { p }).map(|p| crate::sys::canonicalize(&p).unwrap_or_else(|_| p.to_path_buf()));
    !(up.as_deref() == Some(repo.as_path()) && parent.file_name().is_some_and(|n| n == ".aix"))
}

/// A first build that the gate let through only because its index lives outside `<repo>/.aix` (an explicit
/// `--db`/`AIX_DB`): one line saying the check was skipped, when there is something it would have stopped on.
pub fn skipped_note(repo: &Path, db: &Path) -> Option<String> {
    if crate::config::env_var("ACCEPT_IGNORE").is_some_and(|v| v == "1") || !bypassed(repo, db) {
        return None;
    }
    let r = scan(repo);
    if r.findings.is_empty() || read_accept_or_main(repo).is_some_and(|(h, _)| h == r.hash()) {
        return None;
    }
    Some(format!(
        "aix: .gitignore check skipped (the index is outside {}): {} finding(s), {} high; `aix ignore-check` lists them",
        crate::logs::display_path(&repo.join(".aix").to_string_lossy()),
        r.findings.len(),
        r.high()
    ))
}

/// Would a first build of `repo` (index in `<repo>/.aix`) stop for the .gitignore decision? Some(number of findings)
/// when it would; None when clean, accepted here or in the parent checkout, or bypassed by AIX_ACCEPT_IGNORE=1.
pub fn would_stop(repo: &Path) -> Option<usize> {
    if crate::config::env_var("ACCEPT_IGNORE").is_some_and(|v| v == "1") {
        return None;
    }
    let r = scan(repo);
    if r.findings.is_empty() || read_accept_or_main(repo).is_some_and(|(h, _)| h == r.hash()) {
        return None;
    }
    Some(r.findings.len())
}

/// The STOP block: findings (capped), the STOP line, the commands.
pub fn stop_block(r: &Report) -> String {
    let mut v: Vec<String> = vec![format!("== ignore-check: {} finding(s), {} high", r.findings.len(), r.high())];
    for f in r.findings.iter().take(SHOWN) {
        v.push(format!("  {}", f.line()));
    }
    if r.findings.len() > SHOWN {
        v.push(format!("  (+{} more: `aix ignore-check --json` lists all)", r.findings.len() - SHOWN));
    }
    for i in &r.info {
        v.push(format!("  {i}"));
    }
    v.push(STOP_LINE.into());
    v.push("  `aix ignore-check` shows the findings, `aix ignore-check --suggest` the lines to append (aix never edits .gitignore); --accept-ignore records the decision in .aix/config (asked once).".into());
    v.join("\n")
}

/// Before a first build (or a full rebuild): Ok when clean, accepted (now or earlier, same findings) or bypassed;
/// Err(the STOP block) otherwise. With `accept`, the current findings are recorded as accepted.
pub fn gate(repo: &Path, db: &Path, accept: bool) -> Result<(), String> {
    if PASSED.load(Ordering::Relaxed) || bypassed(repo, db) {
        return Ok(());
    }
    let r = scan(repo);
    if r.findings.is_empty() {
        PASSED.store(true, Ordering::Relaxed);
        return Ok(());
    }
    if accept {
        write_accept(repo, &r)?;
        eprintln!(
            "aix: accepted {} .gitignore finding(s) (hash {}) in .aix/config; `aix ignore-check` still lists them",
            r.findings.len(),
            r.hash()
        );
        PASSED.store(true, Ordering::Relaxed);
        return Ok(());
    }
    if read_accept(repo).is_some_and(|(h, _)| h == r.hash()) {
        PASSED.store(true, Ordering::Relaxed);
        return Ok(());
    }
    // a linked worktree (or a local clone) of a repo whose (identical) findings were accepted there
    if parent_repo(repo).and_then(|m| read_accept(&m)).is_some_and(|(h, _)| h == r.hash()) {
        PASSED.store(true, Ordering::Relaxed);
        return Ok(());
    }
    Err(stop_block(&r))
}

/// The one-line warning for `aix card` / `stats`: before the first build, the STOP; after it, high-severity findings
/// that were not part of the accepted set (a new .env, say). None when clean, accepted or bypassed.
pub fn card_line(repo: &Path, db: &Path, built: bool) -> Option<String> {
    if bypassed(repo, db) {
        return None;
    }
    let r = scan(repo);
    if r.findings.is_empty() {
        return None;
    }
    let acc = read_accept_or_main(repo);
    if !built {
        if acc.as_ref().is_some_and(|(h, _)| *h == r.hash()) {
            return None;
        }
        return Some(format!(
            "aix: STOP: .gitignore is missing or incomplete ({} finding(s), {} high); the index is not built until the user decides. Show them `aix ignore-check`; never edit .gitignore or pass --accept-ignore yourself",
            r.findings.len(),
            r.high()
        ));
    }
    let items = acc.map(|a| a.1).unwrap_or_default();
    let new: Vec<&Finding> = r.findings.iter().filter(|f| f.sev == "high" && !items.contains(&f.item_hash())).collect();
    let first = new.first()?;
    let name = first.paths.first().map(|p| format!(": {p}")).unwrap_or_default();
    Some(format!("aix ignore-check: {} new high-severity .gitignore finding(s) ({}{name}); ask the user — `aix ignore-check --suggest`", new.len(), first.kind))
}

// ---- output -----------------------------------------------------------------------------------------------------------

/// The ready-to-append block, grouped by stack / kind.
pub fn suggest_block(r: &Report) -> Vec<String> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cmds: Vec<String> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    for f in &r.findings {
        let g = if f.group.is_empty() { "other".to_string() } else { f.group.clone() };
        for s in &f.suggest {
            if seen.insert(s.clone()) {
                groups.entry(g.clone()).or_default().push(s.clone());
            }
        }
        if f.kind.starts_with("tracked") || f.kind == "aix-dir" {
            if !f.fix.is_empty() && !f.fix.contains('<') {
                cmds.push(f.fix.clone());
            } else {
                for p in f.paths.iter().take(10) {
                    cmds.push(format!("git rm --cached {}", sh_quote(p)));
                }
            }
        }
    }
    // a repo with no .gitignore (or no git) also gets the expected entries of the stacks it has
    if !r.gitignore {
        for (name, _) in &r.stacks {
            if let Some(s) = STACKS.iter().find(|s| s.name == name) {
                for e in s.entries {
                    if seen.insert(e.to_string()) {
                        groups
                            .entry(if s.name == "any" { "any stack".into() } else { s.name.to_string() })
                            .or_default()
                            .push(e.to_string());
                    }
                }
            }
        }
    }
    let mut out = vec![
        "# --- suggested by `aix ignore-check --suggest`: review, then append to .gitignore (aix never writes it) ---"
            .to_string(),
    ];
    if !r.git {
        out.push("# not a git repository yet: `git init`, then save these lines as .gitignore".into());
    }
    for (g, lines) in groups {
        out.push(format!("# {g}"));
        out.extend(lines);
    }
    if !cmds.is_empty() {
        cmds.dedup();
        out.push(
            "# tracked files that should leave git (run these, then commit; rotate any secret that was pushed):".into(),
        );
        out.extend(cmds.into_iter().map(|c| format!("#   {c}")));
    }
    out
}

fn sh_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The report as text lines (header, up to SHOWN findings, info, acceptance state, next step).
pub fn report_lines(repo: &Path, r: &Report) -> Vec<String> {
    let state = if !r.git {
        "not a git repo"
    } else if r.gitignore {
        ".gitignore present"
    } else {
        "no .gitignore"
    };
    let mut v = vec![format!(
        "== ignore-check ({state}): {} finding(s){}",
        r.findings.len(),
        if r.findings.is_empty() { String::new() } else { format!(", {} high", r.high()) }
    )];
    for f in r.findings.iter().take(SHOWN) {
        v.push(format!("  {}", f.line()));
    }
    if r.findings.len() > SHOWN {
        v.push(format!("  (+{} more: `aix ignore-check --json` lists all)", r.findings.len() - SHOWN));
    }
    if r.stacks.iter().any(|s| s.0 != "any") {
        v.push(format!(
            "  stacks: {}",
            r.stacks.iter().map(|s| s.0.as_str()).filter(|s| *s != "any").collect::<Vec<_>>().join(", ")
        ));
    }
    for i in &r.info {
        v.push(format!("  {i}"));
    }
    if r.findings.is_empty() {
        v.push("  clean: .gitignore covers what this repo needs".into());
    } else {
        match read_accept_or_main(repo) {
            Some((h, _)) if h == r.hash() => v.push(format!("  accepted by the user (hash {h} in .aix/config{})", if read_accept(repo).is_none() { " of the main working tree" } else { "" })),
            Some(_) => v.push("  the findings changed since the user last accepted them".into()),
            None => {}
        }
        v.push("  `aix ignore-check --suggest` prints the lines to append; aix never edits .gitignore. Ask the user before fixing or accepting.".into());
    }
    v
}

fn report_json(repo: &Path, r: &Report) -> serde_json::Value {
    serde_json::json!({
        "cmd": "ignore-check", "git": r.git, "gitignore": r.gitignore, "high": r.high(), "hash": r.hash(),
        "accepted": read_accept_or_main(repo).is_some_and(|(h, _)| h == r.hash()),
        "findings": r.findings.iter().map(Finding::json).collect::<Vec<_>>(),
        "stacks": r.stacks.iter().map(|s| serde_json::json!({"stack": s.0, "dirs": s.1})).collect::<Vec<_>>(),
        "info": r.info,
    })
}

/// The CLI command (runs before the index is opened, so it never creates `.aix`). Exit status 0 clean, 1 findings,
/// 2 error. `--gate` answers for a build (0 clean/accepted/bypassed, 1 STOP); `--accept` records the findings.
pub fn cli(repo: &Path, db: Option<&Path>, args: &[String], json: bool) -> i32 {
    let (mut suggest, mut accept, mut gate_mode, mut json) = (false, false, false, json);
    for a in args {
        match a.as_str() {
            "--suggest" => suggest = true,
            "--accept" | "--accept-ignore" => accept = true,
            "--gate" => gate_mode = true,
            "--json" => json = true,
            other => {
                eprintln!("aix ignore-check: unknown argument {}\nusage: aix ignore-check [--json] [--suggest] [--gate] [--accept]", aix_extract::redact::redact_line(other));
                return 2;
            }
        }
    }
    if !repo.is_dir() {
        eprintln!("aix ignore-check: {} is not a directory", repo.display());
        return 2;
    }
    let print = |s: &str| {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{}", aix_extract::redact::redact_block(s));
    };
    if gate_mode {
        let db = db.map(Path::to_path_buf).unwrap_or_else(|| crate::index::default_db(repo));
        return match gate(repo, &db, accept) {
            Ok(()) => {
                print("ignore-check: ok (clean, accepted, or not gated)");
                0
            }
            Err(stop) => {
                print(&stop);
                1
            }
        };
    }
    let r = scan(repo);
    if accept {
        if r.findings.is_empty() {
            print("ignore-check: clean, nothing to accept");
            return 0;
        }
        return match write_accept(repo, &r) {
            Ok(()) => {
                print(&format!("accepted {} finding(s) (hash {}) in .aix/config; the first build proceeds, new high-severity findings still show in `aix card`", r.findings.len(), r.hash()));
                0
            }
            Err(e) => {
                eprintln!("aix ignore-check: {e}");
                2
            }
        };
    }
    if json {
        let mut v = report_json(repo, &r);
        if suggest {
            v["suggest"] = serde_json::json!(suggest_block(&r));
        }
        print(&v.to_string());
    } else if suggest {
        print(&suggest_block(&r).join("\n"));
    } else {
        print(&report_lines(repo, &r).join("\n"));
    }
    i32::from(!r.findings.is_empty())
}

/// The MCP / library form (read-only: `--accept` is CLI only).
pub fn run(repo: &Path, arg: &str, out: &mut crate::query::Out) {
    let toks: Vec<&str> = arg.split_whitespace().collect();
    if toks.iter().any(|t| matches!(*t, "--accept" | "--accept-ignore" | "--gate")) {
        return out.fail("aix ignore-check --accept records the user's decision: run it in a terminal after the user agrees (the MCP tool is read-only)");
    }
    if let Some(bad) = toks.iter().find(|t| !matches!(**t, "--suggest" | "--json")) {
        return out.fail_usage(format!("usage: aix ignore-check [--json] [--suggest] (unknown argument {bad})"));
    }
    let r = scan(repo);
    let lines = if toks.contains(&"--suggest") { suggest_block(&r) } else { report_lines(repo, &r) };
    for l in lines {
        out.emit(l);
    }
    for f in &r.findings {
        out.hits.push(f.json());
    }
}

/// One line for `stats` when there are high-severity findings the user has not accepted.
pub fn stats_line(repo: &Path, db: &Path, built: bool, out: &mut crate::query::Out) {
    if let Some(l) = card_line(repo, db, built) {
        out.emit(l);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn globs_and_probes() {
        assert!(
            glob_match("*.log", "a.log")
                && !glob_match("*.log", "a.logx")
                && glob_match(".env*", ".env")
                && glob_match("*.tfstate*", "x.tfstate.backup")
        );
        assert!(glob_match("*.egg-info", "pkg.egg-info") && !glob_match("Cargo.toml", "cargo.toml"));
        assert_eq!(probe_of("node_modules/"), "node_modules/aixprobe");
        assert_eq!(probe_of("*.log"), "aixprobe.log");
        assert_eq!(secret_line("a/.env.local"), ".env*");
        assert_eq!(secret_line("certs/x.pem"), "*.pem");
        assert_eq!(marker_match("*.xcodeproj/", "ios/App.xcodeproj/project.pbxproj").as_deref(), Some("ios"));
        assert_eq!(marker_match("package.json", "web/package.json").as_deref(), Some("web"));
    }
}
