//! Deny-with-answer: the exact output of a read the hook can prove it reproduces byte for byte (`sed -n A,Bp F`,
//! `head`/`tail -n`, `cat`, and the built-in Grep / Glob tools over a scope where every file is indexed and unchanged).
//! Every function returns Err(reason) instead of an approximation; the caller then only nudges.

use std::path::{Path, PathBuf};
use std::time::Instant;

use regex::RegexBuilder;
use serde_json::Value;

use crate::hooksh::{glob_re, FileRow, Filt, Probe, ReadOp};

/// Largest answer put into a deny reason (the Bash tool itself truncates at about 30 000 characters).
pub const MAX_ANSWER: usize = 20_000;
pub const MAX_LINES: usize = 600;
/// Longer matching lines are cut in a Grep answer (the row stays; its text ends with `…`).
const LONG_LINE: usize = 300;
const MAX_FILE: u64 = 4 << 20;

/// The file's bytes, only when it is indexed and unchanged since (size and mtime match the index row), text, no NUL.
fn fresh_text(repo: &Path, probe: &dyn Probe, rel: &str) -> Result<(String, FileRow), String> {
    let fr = probe.file(rel).ok_or("not-indexed")?;
    let p = repo.join(rel);
    let md = std::fs::symlink_metadata(&p).map_err(|_| "missing")?;
    if !md.file_type().is_file() || md.len() > MAX_FILE {
        return Err("not-a-small-file".into());
    }
    let m = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos() as i64);
    if md.len() as i64 != fr.bytes || m != Some(fr.mtime_ns) {
        return Err("stale".into());
    }
    let b = std::fs::read(&p).map_err(|_| "unreadable")?;
    if b.contains(&0) {
        return Err("binary".into());
    }
    let s = String::from_utf8(b).map_err(|_| "not-utf8")?;
    Ok((s, fr))
}

/// The bytes a sequence of exact reads prints (shell `;`/`&&` concatenation).
pub fn reads(repo: &Path, probe: &dyn Probe, ops: &[ReadOp]) -> Result<String, String> {
    let mut out = String::new();
    for op in ops {
        out.push_str(&one(repo, probe, op)?);
        if out.len() > MAX_ANSWER {
            return Err("too-big".into());
        }
    }
    if out.lines().count() > MAX_LINES {
        return Err("too-big".into());
    }
    redaction_free(&out)?;
    Ok(out)
}

/// The bytes one exact read prints.
fn one(repo: &Path, probe: &dyn Probe, op: &ReadOp) -> Result<String, String> {
    Ok(match op {
        ReadOp::Echo(t) => t.clone(),
        ReadOp::Cat { files } => {
            let mut s = String::new();
            for f in files {
                s.push_str(&fresh_text(repo, probe, f)?.0);
            }
            s
        }
        ReadOp::Head { file, n } => fresh_text(repo, probe, file)?.0.split_inclusive('\n').take(*n).collect(),
        ReadOp::Tail { file, n } => {
            let t = fresh_text(repo, probe, file)?.0;
            let lines: Vec<&str> = t.split_inclusive('\n').collect();
            lines[lines.len().saturating_sub(*n)..].concat()
        }
        ReadOp::TailFrom { file, k } => fresh_text(repo, probe, file)?.0.split_inclusive('\n').skip(k.saturating_sub(1)).collect(),
        ReadOp::Sed { file, ranges } => {
            let t = fresh_text(repo, probe, file)?.0;
            let lines: Vec<&str> = t.split_inclusive('\n').collect();
            let last = lines.len();
            let mut s = String::new();
            for (i, l) in lines.iter().enumerate() {
                let n = i + 1;
                for (a, b) in ranges {
                    let a = if *a == usize::MAX { last } else { *a };
                    let b = if *b == usize::MAX { last } else { (*b).max(a) };
                    if n >= a && n <= b {
                        // GNU sed ends a line printed again after a missing final newline with one
                        if !s.is_empty() && !s.ends_with('\n') {
                            s.push('\n');
                        }
                        s.push_str(l);
                    }
                }
            }
            // Git for Windows' sed reads in text mode: a CRLF line prints with LF only (its head/tail/cat keep CR)
            if cfg!(windows) { s.replace("\r\n", "\n") } else { s }
        }
        ReadOp::Grep { .. } | ReadOp::Piped { .. } => piped(repo, probe, op)?,
    })
}

/// A grep / pipe read: GNU grep, head, tail and `wc -l` over the indexed bytes. ASCII text only where a regex runs
/// (the regex crate and grep agree there), every line newline-terminated.
fn piped(repo: &Path, probe: &dyn Probe, op: &ReadOp) -> Result<String, String> {
    let (lines, filters): (Vec<String>, &[Filt]) = match op {
        ReadOp::Piped { src, filters } => {
            if matches!(src.as_ref(), ReadOp::Piped { .. }) {
                return Err("nested".into());
            }
            let t = one(repo, probe, src)?;
            (to_lines(&t)?, filters.as_slice())
        }
        ReadOp::Grep { files, filt } => {
            let Filt::Grep { re, n, v, c, i } = filt else { return Err("filter".into()) };
            let rx = Matcher::new(re, *i)?;
            let mut out = vec![];
            for (rel, typed) in files {
                let t = fresh_text(repo, probe, rel)?.0;
                let pre = if files.len() > 1 { format!("{typed}:") } else { String::new() };
                let mut cnt = 0usize;
                for (k, l) in to_lines(&t)?.iter().enumerate() {
                    if rx.is_match(l)? != *v {
                        cnt += 1;
                        if !c {
                            out.push(if *n { format!("{pre}{}:{l}", k + 1) } else { format!("{pre}{l}") });
                        }
                    }
                }
                if *c {
                    out.push(format!("{pre}{cnt}"));
                }
            }
            return Ok(out.iter().map(|l| format!("{l}\n")).collect());
        }
        _ => return Err("op".into()),
    };
    let mut cur = lines;
    for f in filters {
        cur = match f {
            Filt::Grep { re, n, v, c, i } => {
                let rx = Matcher::new(re, *i)?;
                let mut hits: Vec<String> = vec![];
                for (k, l) in cur.iter().enumerate() {
                    if rx.is_match(l)? != *v {
                        hits.push(if *n { format!("{}:{l}", k + 1) } else { l.clone() });
                    }
                }
                if *c {
                    vec![hits.len().to_string()]
                } else {
                    hits
                }
            }
            Filt::Head(k) => cur.into_iter().take(*k).collect(),
            Filt::Tail(k) => {
                let s = cur.len().saturating_sub(*k);
                cur.split_off(s)
            }
            Filt::TailFrom(k) => cur.into_iter().skip(k.saturating_sub(1)).collect(),
            Filt::WcL => vec![cur.len().to_string()],
            // ASCII only: cut counts bytes or characters by locale, which agree only there
            Filt::Cut { from, to } => cur
                .into_iter()
                .map(|l| if l.is_ascii() { Ok(l.chars().skip(from - 1).take(to.map_or(usize::MAX, |t| t + 1 - from)).collect()) } else { Err("cut".to_string()) })
                .collect::<Result<_, _>>()?,
        };
    }
    Ok(cur.iter().map(|l| format!("{l}\n")).collect())
}

/// A grep pattern on one line, the same whatever the shell's locale: an ASCII line is read the same by grep and the
/// regex crate; on any other line the byte reading (C locale) and the Unicode reading (UTF-8 locale) must agree,
/// or there is no exact answer.
struct Matcher {
    uni: regex::Regex,
    bytes: Option<regex::bytes::Regex>,
}
impl Matcher {
    fn new(re: &str, i: bool) -> Result<Matcher, String> {
        let uni = RegexBuilder::new(re).case_insensitive(i).build().map_err(|_| "regex")?;
        let bytes = regex::bytes::RegexBuilder::new(re).unicode(false).case_insensitive(i).build().ok();
        Ok(Matcher { uni, bytes })
    }
    fn is_match(&self, l: &str) -> Result<bool, String> {
        let u = self.uni.is_match(l);
        if l.is_ascii() || self.bytes.as_ref().is_some_and(|b| b.is_match(l.as_bytes()) == u) {
            Ok(u)
        } else {
            Err("locale".into())
        }
    }
}

/// Text -> lines without their `\n`; Err for a final line without one (the tools differ there) or a CR.
fn to_lines(t: &str) -> Result<Vec<String>, String> {
    if t.is_empty() {
        return Ok(vec![]);
    }
    if !t.ends_with('\n') || t.contains('\r') {
        return Err("line-ends".into());
    }
    Ok(t[..t.len() - 1].split('\n').map(str::to_string).collect())
}

/// Err when redaction would change any line: a redacted answer is not the tool's output.
fn redaction_free(s: &str) -> Result<(), String> {
    // redaction works on `\n` lines; a CRLF file is compared without its `\r`s
    let plain = s.replace("\r\n", "\n");
    if aix_extract::redact::redact_block(&plain) != plain {
        return Err("redacted".into());
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ scope walk

struct Budget {
    t0: Instant,
    ms: u128,
    entries: usize,
    max_entries: usize,
}
impl Budget {
    fn tick(&mut self) -> Result<(), String> {
        self.entries += 1;
        if self.entries > self.max_entries || self.t0.elapsed().as_millis() > self.ms {
            return Err("budget".into());
        }
        Ok(())
    }
}

/// Files under `dir` (repo-relative, "" = root) whose path matches `keep`; indexed or not. Directories without any
/// indexed file are not descended: they are returned in `opaque` for the ignore check. `.git` is skipped.
fn scope_files(repo: &Path, probe: &dyn Probe, dir: &str, keep: &dyn Fn(&str) -> bool, b: &mut Budget, files: &mut Vec<String>, opaque: &mut Vec<String>) -> Result<(), String> {
    let abs = if dir.is_empty() { repo.to_path_buf() } else { repo.join(dir) };
    let rd = std::fs::read_dir(&abs).map_err(|_| "unreadable-dir")?;
    let mut ents: Vec<_> = rd.flatten().collect();
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        b.tick()?;
        let name = e.file_name().to_string_lossy().to_string();
        if name == ".git" {
            continue;
        }
        let rel = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
        let ft = e.file_type().map_err(|_| "stat")?;
        if ft.is_symlink() {
            if keep(&rel) {
                return Err("symlink".into());
            }
            continue;
        }
        if ft.is_dir() {
            if probe.dir_has(&rel) {
                scope_files(repo, probe, &rel, keep, b, files, opaque)?;
            } else {
                opaque.push(format!("{rel}/"));
            }
        } else if ft.is_file() && keep(&rel) {
            files.push(rel);
        }
    }
    Ok(())
}

fn hidden(rel: &str) -> bool {
    rel.split('/').any(|s| s.starts_with('.') && s.len() > 1)
}

fn rel_of(repo: &Path, cwd: &Path, p: &str) -> Result<String, String> {
    let abs = if p.is_empty() { cwd.to_path_buf() } else if Path::new(p).is_absolute() { PathBuf::from(p) } else { cwd.join(p) };
    crate::hooksh::repo_rel(repo, &abs.display().to_string()).ok_or_else(|| "outside-repo".into())
}

/// A repo file as the Grep/Glob tools print it: native separators (ripgrep on Windows prints `C:\r\src\a.ts`).
fn abs(repo: &Path, rel: &str) -> String {
    rel.split('/').fold(repo.to_path_buf(), |p, s| p.join(s)).display().to_string()
}

// ------------------------------------------------------------------------------------------------ Grep tool

/// The Grep tool's result for `input`, computed from the indexed files, or Err(reason).
pub fn grep_tool(repo: &Path, cwd: &Path, probe: &dyn Probe, input: &Value, budget_ms: u128) -> Result<String, String> {
    let obj = input.as_object().ok_or("input")?;
    for k in obj.keys() {
        if !matches!(k.as_str(), "pattern" | "path" | "glob" | "output_mode" | "-i" | "-n" | "-A" | "-B" | "-C" | "context" | "head_limit" | "offset") {
            return Err(format!("field:{k}"));
        }
    }
    let pat = input["pattern"].as_str().ok_or("pattern")?;
    let mode = input["output_mode"].as_str().unwrap_or("files_with_matches");
    if !matches!(mode, "content" | "files_with_matches" | "count") {
        return Err("mode".into());
    }
    if input["offset"].as_u64().unwrap_or(0) != 0 {
        return Err("offset".into());
    }
    let num = |k: &str| input[k].as_u64().map(|n| n as usize);
    let ctx = num("-C").or(num("context"));
    let (before, after) = (num("-B").or(ctx).unwrap_or(0), num("-A").or(ctx).unwrap_or(0));
    if mode != "content" && (before > 0 || after > 0) {
        return Err("context-mode".into());
    }
    let show_n = input["-n"].as_bool().unwrap_or(true);
    let re = RegexBuilder::new(pat).case_insensitive(input["-i"].as_bool() == Some(true)).build().map_err(|_| "regex")?;
    let rel = rel_of(repo, cwd, input["path"].as_str().unwrap_or(""))?;
    let glob = input["glob"].as_str().filter(|g| !g.is_empty());
    let gre = match glob {
        Some(g) if g.contains('{') && !g.contains('/') || !g.contains('/') => Some((glob_re(g).ok_or("glob")?, true)),
        Some(g) => Some((glob_re(g).ok_or("glob")?, false)),
        None => None,
    };
    let scope_root = rel.clone();
    let keep = |p: &str| -> bool {
        match &gre {
            None => true,
            Some((r, true)) => r.is_match(p.rsplit('/').next().unwrap_or(p)),
            Some((r, false)) => {
                let sub = if scope_root.is_empty() { p } else { p.strip_prefix(&format!("{scope_root}/")).unwrap_or(p) };
                r.is_match(sub)
            }
        }
    };
    let mut b = Budget { t0: Instant::now(), ms: budget_ms, entries: 0, max_entries: 6000 };
    let mut files = vec![];
    let mut opaque = vec![];
    if probe.file(&rel).is_some() {
        files.push(rel.clone());
    } else if probe.dir_has(&rel) {
        scope_files(repo, probe, &rel, &keep, &mut b, &mut files, &mut opaque)?;
    } else {
        return Err("not-indexed".into());
    }
    // files the index does not hold (binary, data, an odd extension): gitignored ones Grep skips too; the others are
    // searched from disk below (a binary one must not match: Grep skips it)
    let ignored_dirs = ignored_of(repo, &opaque)?;
    // a directory with no indexed file that git does not ignore (assets, data): every file in it, walked
    for o in opaque.iter().map(|o| o.trim_end_matches('/')).filter(|o| !ignored_dirs.contains(*o)) {
        scope_files_every(repo, o, &keep, &mut b, &mut files)?;
    }
    let unindexed: Vec<String> = files.iter().filter(|f| probe.file(f).is_none()).cloned().collect();
    let ignored = ignored_of(repo, &unindexed)?;
    files.retain(|f| !ignored.contains(f));
    files.sort();
    let base = rel_of(repo, cwd, "").ok();
    let shown = |f: &str| -> String {
        match &base {
            Some(b) if b.is_empty() => f.to_string(),
            Some(b) => f.strip_prefix(&format!("{b}/")).map(str::to_string).unwrap_or_else(|| abs(repo, f)),
            None => abs(repo, f),
        }
    };
    // per file: matching line numbers
    let mut out: Vec<String> = vec![];
    // the text of each content row (out[i] holds its `path:line:` prefix, or "--" with an empty text)
    let mut texts: Vec<String> = vec![];
    let mut total_bytes = 0usize;
    let mut file_hits: Vec<(String, usize)> = vec![];
    let mut last_printed: Option<(String, usize)> = None;
    for f in &files {
        b.tick()?;
        let text = if probe.file(f).is_some() {
            fresh_text(repo, probe, f)?.0
        } else {
            match disk_text(repo, f)? {
                Some(t) => t,
                None => {
                    // binary: Grep skips it; only one without a match keeps the rows the same
                    let raw = std::fs::read(repo.join(f)).map_err(|_| "unreadable")?;
                    if re.is_match(&String::from_utf8_lossy(&raw)) {
                        return Err("binary-match".into());
                    }
                    continue;
                }
            }
        };
        total_bytes += text.len();
        if total_bytes > 24 << 20 {
            return Err("budget".into());
        }
        // rg drops a UTF-8 BOM (Visual Studio and Windows PowerShell write one): line 1 starts after it
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let lines: Vec<&str> = text.split('\n').collect();
        let n_lines = if text.ends_with('\n') { lines.len() - 1 } else { lines.len() };
        let hits: Vec<usize> = (0..n_lines).filter(|&i| re.is_match(lines[i])).collect();
        if hits.is_empty() {
            continue;
        }
        file_hits.push((f.clone(), hits.len()));
        if mode == "content" {
            let path = shown(f);
            let mut show = vec![false; n_lines];
            let mut is_hit = vec![false; n_lines];
            for &h in &hits {
                is_hit[h] = true;
                for k in h.saturating_sub(before)..=(h + after).min(n_lines - 1) {
                    show[k] = true;
                }
            }
            for k in 0..n_lines {
                if !show[k] {
                    continue;
                }
                if before > 0 || after > 0 {
                    let gap = match &last_printed {
                        Some((pf, pk)) => pf != f || *pk + 1 != k,
                        None => false,
                    };
                    if gap {
                        out.push("--".into());
                        texts.push(String::new());
                    }
                }
                last_printed = Some((f.clone(), k));
                let sep = if is_hit[k] { ':' } else { '-' };
                // a long line (minified, generated) is cut: the row is the same, its text bounded
                let cut: String;
                let t = if lines[k].chars().count() > LONG_LINE {
                    cut = format!("{}…", lines[k].chars().take(LONG_LINE).collect::<String>());
                    cut.as_str()
                } else {
                    lines[k]
                };
                out.push(if show_n { format!("{path}{sep}{}{sep}", k + 1) } else { format!("{path}{sep}") });
                texts.push(t.to_string());
            }
        }
        if out.len() > MAX_LINES || file_hits.len() > MAX_LINES {
            return Err("too-big".into());
        }
    }
    let total: usize = file_hits.iter().map(|x| x.1).sum();
    // aix's answer (labelled as such, not as Grep's bytes): a secret in a row's text is redacted (the whole text
    // block at once, so multi-line secrets are seen), the `path:line:` prefix stays
    let red = aix_extract::redact::redact_block(&texts.join("\n"));
    let red: Vec<&str> = red.split('\n').collect();
    if !texts.is_empty() && red.len() != texts.len() {
        return Err("redacted".into());
    }
    let out: Vec<String> = out.iter().zip(red).map(|(p, t)| if p == "--" { p.clone() } else { format!("{p}{t}") }).collect();
    let body: Vec<String> = match mode {
        "content" => out,
        "count" => file_hits.iter().map(|(f, n)| format!("{}:{n}", shown(f))).collect(),
        _ => file_hits.iter().map(|(f, _)| shown(f)).collect(),
    };
    if let Some(h) = num("head_limit") {
        if body.len() > h {
            return Err("head_limit".into());
        }
    }
    // the Grep tool's own shapes: a header for file lists, a footer for counts
    let s = match mode {
        _ if file_hits.is_empty() => if mode == "files_with_matches" { "No files found\n".to_string() } else { "No matches found\n".to_string() },
        "files_with_matches" => format!("Found {} file{}\n{}\n", file_hits.len(), if file_hits.len() == 1 { "" } else { "s" }, body.join("\n")),
        "count" => format!("{}\n\nFound {total} total occurrence{} across {} file{}.\n", body.join("\n"), if total == 1 { "" } else { "s" }, file_hits.len(), if file_hits.len() == 1 { "" } else { "s" }),
        _ => body.join("\n") + "\n",
    };
    if s.len() > 4 * MAX_ANSWER {
        return Err("too-big".into());
    }
    Ok(s)
}

/// A file outside the index read from disk: Some(text) for UTF-8 text, None for binary (a NUL byte), Err otherwise.
fn disk_text(repo: &Path, rel: &str) -> Result<Option<String>, String> {
    let p = repo.join(rel);
    let md = std::fs::symlink_metadata(&p).map_err(|_| "missing")?;
    if !md.file_type().is_file() || md.len() > MAX_FILE {
        return Err("not-a-small-file".into());
    }
    let b = std::fs::read(&p).map_err(|_| "unreadable")?;
    if b.contains(&0) {
        return Ok(None);
    }
    String::from_utf8(b).map(Some).map_err(|_| "not-utf8".into())
}

/// Which of `paths` git ignores (a directory as `dir/` matches `dir`).
fn ignored_of(repo: &Path, paths: &[String]) -> Result<std::collections::HashSet<String>, String> {
    let mut set = std::collections::HashSet::new();
    if paths.is_empty() {
        return Ok(set);
    }
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut ch = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["check-ignore", "--stdin", "-z"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "git")?;
    let mut input = ch.stdin.take().ok_or("git")?;
    let payload: Vec<u8> = paths.iter().flat_map(|f| f.bytes().chain([0u8])).collect();
    let w = std::thread::spawn(move || {
        let _ = input.write_all(&payload);
    });
    let out = ch.wait_with_output().map_err(|_| "git")?;
    let _ = w.join();
    for x in out.stdout.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        set.insert(String::from_utf8_lossy(x).trim_end_matches('/').to_string());
    }
    Ok(set)
}

// ------------------------------------------------------------------------------------------------ Glob tool

/// The Glob tool's file list for `input` from the index, or Err(reason). Paths absolute, sorted by modification time
/// (newest first).
pub fn glob_tool(repo: &Path, cwd: &Path, probe: &dyn Probe, input: &Value, budget_ms: u128) -> Result<String, String> {
    let obj = input.as_object().ok_or("input")?;
    if obj.keys().any(|k| !matches!(k.as_str(), "pattern" | "path")) {
        return Err("field".into());
    }
    let pat = input["pattern"].as_str().ok_or("pattern")?;
    if pat.starts_with('/') || pat.contains("..") || pat.starts_with('!') {
        return Err("pattern".into());
    }
    // a bare `*.ts` (no directory part, no **) is read differently by glob libraries: nudge only
    if !pat.contains('/') {
        return Err("glob-shape".into());
    }
    let re = glob_re(pat).ok_or("glob")?;
    let rel = rel_of(repo, cwd, input["path"].as_str().unwrap_or(""))?;
    if !probe.dir_has(&rel) {
        return Err("not-indexed".into());
    }
    let root = rel.clone();
    let keep = |p: &str| {
        let sub = if root.is_empty() { p } else { p.strip_prefix(&format!("{root}/")).unwrap_or(p) };
        re.is_match(sub)
    };
    let mut b = Budget { t0: Instant::now(), ms: budget_ms, entries: 0, max_entries: 6000 };
    let mut files = vec![];
    let mut opaque = vec![];
    // the literal directory prefix of the pattern bounds the walk
    let lit: String = pat.split('/').take_while(|s| !s.contains(['*', '?', '[', '{'])).collect::<Vec<_>>().join("/");
    let lit = if lit == pat { String::new() } else { lit };
    let start = match (root.is_empty(), lit.is_empty()) {
        (_, true) => root.clone(),
        (true, false) => lit.clone(),
        (false, false) => format!("{root}/{lit}"),
    };
    if !probe.dir_has(&start) {
        return Err("not-indexed".into());
    }
    scope_files(repo, probe, &start, &keep, &mut b, &mut files, &mut opaque)?;
    // an opaque (unindexed) directory could hold matches the tool would list: it must be empty of them
    for o in &opaque {
        let mut sub = vec![];
        scope_files_all(repo, o.trim_end_matches('/'), &keep, &mut b, &mut sub)?;
        if !sub.is_empty() {
            return Err("unindexed-match".into());
        }
    }
    if files.iter().any(|f| probe.file(f).is_none() || hidden(f)) {
        return Err("unindexed-match".into());
    }
    if files.len() > 100 {
        return Err("too-big".into());
    }
    let mut with_m: Vec<(i64, String)> = files.iter().map(|f| (probe.file(f).map(|r| r.mtime_ns).unwrap_or(0), abs(repo, f))).collect();
    // the index row must still describe the file
    for f in &files {
        fresh_text(repo, probe, f).map(|_| ()).or_else(|e| if e == "binary" || e == "not-utf8" { Ok(()) } else { Err(e) })?;
    }
    with_m.sort_by(|x, y| y.0.cmp(&x.0).then(x.1.cmp(&y.1)));
    let s = if with_m.is_empty() { "No files found\n".to_string() } else { with_m.into_iter().map(|x| x.1).collect::<Vec<_>>().join("\n") + "\n" };
    redaction_free(&s)?;
    Ok(s)
}

/// Every file under `dir` matching `keep` (no index; `.git` skipped; a symlink to a kept path: Err), budgeted.
fn scope_files_every(repo: &Path, dir: &str, keep: &dyn Fn(&str) -> bool, b: &mut Budget, files: &mut Vec<String>) -> Result<(), String> {
    let rd = std::fs::read_dir(repo.join(dir)).map_err(|_| "unreadable-dir")?;
    for e in rd.flatten() {
        b.tick()?;
        let name = e.file_name().to_string_lossy().to_string();
        if name == ".git" {
            continue;
        }
        let rel = format!("{dir}/{name}");
        let ft = e.file_type().map_err(|_| "stat")?;
        if ft.is_symlink() {
            if keep(&rel) {
                return Err("symlink".into());
            }
        } else if ft.is_dir() {
            scope_files_every(repo, &rel, keep, b, files)?;
        } else if ft.is_file() && keep(&rel) {
            files.push(rel);
        }
    }
    Ok(())
}

/// A plain walk (no index) of an unindexed directory for matching files, budgeted.
fn scope_files_all(repo: &Path, dir: &str, keep: &dyn Fn(&str) -> bool, b: &mut Budget, files: &mut Vec<String>) -> Result<(), String> {
    let rd = std::fs::read_dir(repo.join(dir)).map_err(|_| "unreadable-dir")?;
    for e in rd.flatten() {
        b.tick()?;
        let name = e.file_name().to_string_lossy().to_string();
        let rel = format!("{dir}/{name}");
        let ft = e.file_type().map_err(|_| "stat")?;
        if ft.is_dir() && !ft.is_symlink() {
            scope_files_all(repo, &rel, keep, b, files)?;
        } else if keep(&rel) {
            files.push(rel);
            return Ok(());
        }
    }
    Ok(())
}
