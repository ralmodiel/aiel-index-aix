//! Git history: commits with subject and touched files; fix/bug/revert commits flagged.

use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Commit {
    pub sha: String,
    pub short: String,
    pub date: String,
    pub subject: String,
    pub is_fix: bool,
    pub is_revert: bool,
    pub files: Vec<String>,
}

static FIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(fix(es|ed)?|bug|regress\w*|blocker|revert|hotfix|broken|crash)\b").unwrap());

pub fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(repo).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Like `git`, for commands run with `-z`: the NUL-separated items (paths are never quoted or escaped, so names with
/// spaces, newlines or non-ASCII bytes come back exactly).
pub fn git_z(repo: &Path, args: &[&str]) -> Option<Vec<String>> {
    let out = Command::new("git").arg("-C").arg(repo).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect())
}

pub fn head(repo: &Path) -> Option<String> {
    git(repo, &["rev-parse", "HEAD"]).map(|s| s.trim().to_string())
}

/// Commits reachable from HEAD (newest first), only those after `since` when given and still an ancestor.
pub fn history(repo: &Path, since: Option<&str>) -> Vec<Commit> {
    let range;
    let mut args = vec!["log", "--no-merges", "-z", "--format=%x1e%H%x1f%h%x1f%cs%x1f%s", "--name-only"];
    if let Some(s) = since {
        range = format!("{s}..HEAD");
        args.push(&range);
    }
    let Some(log) = git(repo, &args) else {
        return vec![];
    };
    parse_log(&log)
}

pub fn parse_log(log: &str) -> Vec<Commit> {
    let mut out = vec![];
    for rec in log.split('\u{1e}').skip(1) {
        let (head, rest) = rec.split_once('\0').unwrap_or((rec, ""));
        let rest = rest.strip_prefix('\n').unwrap_or(rest);
        let mut p = head.split('\u{1f}');
        let sha = p.next().unwrap_or("").to_string();
        let short = p.next().unwrap_or("").to_string();
        let date = p.next().unwrap_or("").to_string();
        let subject = crate::text::redact(p.next().unwrap_or(""));
        let files = rest.split('\0').filter(|l| !l.is_empty()).map(str::to_string).collect();
        out.push(Commit {
            is_fix: FIX.is_match(&subject),
            is_revert: subject.to_lowercase().starts_with("revert"),
            sha,
            short,
            date,
            subject,
            files,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        let log = "\u{1e}aaa\u{1f}a\u{1f}2026-10-01\u{1f}Fix login crash\0\nsrc/a.ts\0src/b é.ts\0\u{1e}bbb\u{1f}b\u{1f}2026-09-30\u{1f}Add page\0\nsrc/c.ts\0";
        let c = parse_log(log);
        assert_eq!(c.len(), 2);
        assert!(c[0].is_fix && !c[1].is_fix);
        assert_eq!(c[0].files, vec!["src/a.ts", "src/b é.ts"]);
    }
}
