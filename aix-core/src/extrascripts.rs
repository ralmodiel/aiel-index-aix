//! Opt-in script folders outside the repo (`script_dirs` in `.aix/config.toml`, or `AIX_SCRIPT_DIRS`, colon separated):
//! `aix script` lists their executables/scripts by name and first usage line. They are never indexed for grep, code or
//! text; the lines are redacted; the privacy deny list applies (hidden folders of $HOME, credential-like names,
//! history/keyring files and anything outside the allowed roots are skipped without a trace).

use std::path::{Path, PathBuf};

use crate::config::{env_var, Config};
use crate::logs;

const MAX_FILES_PER_DIR: usize = 300;
const SCRIPT_EXTS: &[&str] = &["sh", "bash", "zsh", "py", "mjs", "js", "cjs", "ts", "rb", "pl", "ps1", "lua", "php"];

#[derive(Debug, Clone, PartialEq)]
pub struct ExtraScript {
    /// Home-relative display path (`~/tools/x.sh`).
    pub path: String,
    pub name: String,
    pub usage: String,
}

fn expand(d: &str) -> Option<PathBuf> {
    let d = d.trim();
    if d.is_empty() {
        return None;
    }
    let home = crate::sys::home();
    if d == "~" {
        return home;
    }
    if let Some(rest) = d.strip_prefix("~/") {
        return home.map(|h| h.join(rest));
    }
    if let Some(rest) = d.strip_prefix("$HOME/") {
        return home.map(|h| h.join(rest));
    }
    Some(PathBuf::from(d))
}

/// The configured folders, expanded (config first, then the environment), without duplicates.
pub fn configured_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = cfg.script_dirs.iter().filter_map(|d| expand(d)).collect();
    if let Some(e) = env_var("SCRIPT_DIRS") {
        // ':'-separated, ';' on Windows (a drive letter has a ':')
        v.extend(std::env::split_paths(&e).filter_map(|p| expand(&p.to_string_lossy())));
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|p| seen.insert(p.clone()));
    v
}

fn usage_line(text: &str) -> String {
    let (header, usage) = aix_extract::scripts::header_and_usage(text);
    let first = if !usage.is_empty() { usage } else { header };
    let first = first.split(" | ").next().unwrap_or("").to_string();
    aix_extract::text::clip(&aix_extract::text::redact(&first), 140)
}

fn looks_like_script(p: &Path, head: &[u8]) -> bool {
    if head.contains(&0) {
        return false;
    }
    if head.starts_with(b"#!") {
        return true;
    }
    p.extension().and_then(|e| e.to_str()).is_some_and(|e| SCRIPT_EXTS.contains(&e))
}

/// Scripts in the configured folders (one level), sorted by name. Unreadable, denied or non-script entries are skipped.
pub fn list(cfg: &Config, repo: &Path) -> Vec<ExtraScript> {
    let mut out = vec![];
    for dir in configured_dirs(cfg) {
        let Ok(dir) = logs::check_path(&dir, repo) else { continue };
        if !dir.is_dir() {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut names: Vec<_> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        names.sort();
        for name in names.into_iter().filter(|n| !n.starts_with('.')).take(MAX_FILES_PER_DIR) {
            // check_path resolves symlinks and refuses credential-like names, denied locations and foreign owners
            let Ok(f) = logs::check_path(&dir.join(&name), repo) else { continue };
            if !f.is_file() {
                continue;
            }
            let Ok(mut fh) = std::fs::File::open(&f) else { continue };
            let mut buf = vec![0u8; 8192];
            let n = std::io::Read::read(&mut fh, &mut buf).unwrap_or(0);
            buf.truncate(n);
            if !looks_like_script(&f, &buf) {
                continue;
            }
            out.push(ExtraScript {
                path: logs::display_path(&dir.join(&name).to_string_lossy()),
                name,
                usage: usage_line(&String::from_utf8_lossy(&buf)),
            });
        }
    }
    out
}

/// The scripts whose name or usage line contains every word of `q` (all of them when `q` has no words).
pub fn matching(cfg: &Config, repo: &Path, q: &str) -> Vec<ExtraScript> {
    let words: Vec<String> = q.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase).collect();
    list(cfg, repo)
        .into_iter()
        .filter(|s| {
            let hay = format!("{} {}", s.name, s.usage).to_lowercase();
            words.iter().all(|w| hay.contains(w))
        })
        .collect()
}
