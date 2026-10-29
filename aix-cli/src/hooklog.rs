//! PreToolUse steering decisions (nudge / deny-with-answer / silent), the hook event log (`.aix/hook-events.jsonl`),
//! `aix stats --hooks`, and `aix hook classify` (the same decision code over a transcript, for the missed-opportunity
//! rate).

use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::hookans;
use crate::hooksh::{self, Cx, Dialect, Probe, Quote, Tr, Verdict};

/// Claude Code tool names the hook steers. `AIX_HOOK_SHELL_TOOLS` adds names (comma separated) of other shell tools
/// whose `tool_input.command` is PowerShell (the built-in one is `PowerShell`).
fn ps_tool(name: &str) -> bool {
    name == "PowerShell" || aix_core::config::env_var("HOOK_SHELL_TOOLS").is_some_and(|v| v.split(',').any(|t| t.trim() == name))
}

/// Deny-with-answer is on (for Bash exact reads) unless `AIX_HOOK_DENY=0|off|false`, which turns every deny off.
pub fn deny_enabled() -> bool {
    !aix_core::config::env_var("HOOK_DENY").is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "0" | "off" | "false" | "no"))
}

/// The built-in Grep/Glob tools are answered by aix (deny-with-answer, labelled as aix's answer) unless
/// `AIX_HOOK_DENY_GREP=0|off|false`: a nudge rides along with the tool's own result, so it cannot save that call.
pub fn deny_grep_enabled() -> bool {
    !aix_core::config::env_var("HOOK_DENY_GREP").is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "0" | "off" | "false" | "no"))
}

/// After this many nudges in a session with no aix call since, a steerable lookup is answered by running its aix
/// line (deny-with-answer, labelled as aix's answer). `AIX_HOOK_ESCALATE=0` turns it off; default 2.
fn escalate_after() -> usize {
    aix_core::config::env_var("HOOK_ESCALATE").and_then(|v| v.trim().parse().ok()).unwrap_or(2)
}

/// Lines of a non-exact answer shown in a deny (the rest is one aix call away).
const ANSWER_LINES: usize = 120;

const THROTTLE_SECS: i64 = 120;
const REPEAT_SECS: i64 = 600;
const LOG_MAX: u64 = 4 << 20;

/// One decision.
#[derive(Debug, Default, Clone)]
pub struct Decision {
    pub tool: String,
    pub intent: String,
    /// nudge | deny | silent | aix | none (not a lookup)
    pub decision: String,
    pub reason: String,
    pub suggestion: String,
    pub notes: Vec<String>,
    pub answer: Option<String>,
    /// identity of the call (for the repeat-to-bypass rule)
    pub key: String,
    /// large data files read outside the index: (absolute path, data-set name, query)
    pub data: Vec<(String, String, String)>,
    /// indexed files this call reads with a text tool (sed/head/tail/cat/Read): (repo path, ~bytes it prints)
    pub reads: Vec<(String, i64)>,
    /// what a deny's answer is: "exact" (byte-identical tool output), "grep" (the same rows as the Grep tool), "glob",
    /// "callers" (the call graph instead of a symbol search), "aix" (the aix line's own answer, escalation)
    pub kind: String,
    /// a `cd DIR` the answered command would have run (the shell's directory did not change)
    pub cd: Option<String>,
    /// every part of the call is a lookup with an aix line (escalation may answer it)
    pub steerable: bool,
    /// the suggestion quoted for sh, which escalation runs (a PowerShell call's suggestion is quoted for PowerShell)
    pub run: String,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn fnv(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn cwd_of(v: &Value, repo: &Path) -> PathBuf {
    v["cwd"].as_str().filter(|c| !c.is_empty()).map(PathBuf::from).unwrap_or_else(|| repo.to_path_buf())
}

/// Decide for one PreToolUse event (no side effects; the throttle and the log are applied by the caller).
/// The time a Grep/Glob deny-with-answer may take (ms, default 250: about what the Grep tool itself takes on a
/// mid-size repo, and the answer replaces that run); over it the hook nudges instead. `AIX_HOOK_DENY_MS` overrides.
fn deny_answer_ms() -> u128 {
    aix_core::config::env_var("HOOK_DENY_MS").and_then(|v| v.trim().parse().ok()).unwrap_or(250)
}

pub fn decide(repo: &Path, probe: &dyn Probe, v: &Value, allow_deny: bool) -> Decision {
    let tool = v["tool_name"].as_str().unwrap_or("").to_string();
    let input = &v["tool_input"];
    let cwd = cwd_of(v, repo);
    let mut d = Decision { tool: tool.clone(), decision: "none".into(), key: fnv(&format!("{tool}\u{1}{input}")), ..Default::default() };
    let shell = if tool == "Bash" {
        Some(Dialect::Posix)
    } else if ps_tool(&tool) {
        Some(Dialect::Ps)
    } else {
        None
    };
    // .gitignore is the user's decision (aix ignore-check reports, Claude asks): never steered, never answered
    if input.to_string().contains(".gitignore") {
        d.decision = "silent".into();
        d.intent = if shell.is_some() { "bash:gitignore".into() } else { tool.clone() };
        d.reason = "gitignore".into();
        return d;
    }
    if let Some(dialect) = shell {
        let cmd = input["command"].as_str().unwrap_or("");
        let mut cx = Cx::new(repo, Some(&cwd), probe);
        let verdict = hooksh::evaluate(&mut cx, cmd, dialect);
        return from_verdict(repo, &cwd, probe, d, verdict, dialect, allow_deny);
    }
    match tool.as_str() {
        "Grep" => {
            d.intent = format!("Grep:{}", input["output_mode"].as_str().unwrap_or("files_with_matches"));
            // an invalid pattern (`(`): the Grep tool fails on it by itself; a suggestion would repeat the error
            let bad = regex::Regex::new(input["pattern"].as_str().unwrap_or("")).is_err_and(|e| !matches!(e, regex::Error::CompiledTooBig(_)));
            match if bad { Err("bad-regex".to_string()) } else { grep_tool_line(repo, &cwd, probe, input) } {
                Ok(line) => {
                    d.suggestion = line;
                    d.notes.extend(hooksh::semantic_alt(input["pattern"].as_str().unwrap_or(""), probe));
                    d.decision = "nudge".into();
                    d.steerable = true;
                    if allow_deny && deny_grep_enabled() {
                        if !symbol_upgrade(&mut d, probe, input["pattern"].as_str().unwrap_or(""), input["-i"].as_bool() == Some(true) || input["output_mode"] == "count") {
                            match hookans::grep_tool(repo, &cwd, probe, input, deny_answer_ms()) {
                                Ok(ans) => {
                                    d.decision = "deny".into();
                                    d.kind = "grep".into();
                                    d.answer = Some(ans);
                                }
                                Err(e) => d.reason = format!("no-answer:{e}"),
                            }
                        }
                    }
                }
                Err(e) => {
                    d.decision = "silent".into();
                    d.reason = e;
                }
            }
        }
        "Glob" => {
            d.intent = "Glob".into();
            match glob_tool_line(repo, &cwd, probe, input) {
                Ok(line) => {
                    d.suggestion = line;
                    d.decision = "nudge".into();
                    d.steerable = true;
                    if allow_deny && deny_grep_enabled() {
                        match hookans::glob_tool(repo, &cwd, probe, input, deny_answer_ms()) {
                            Ok(ans) => {
                                d.decision = "deny".into();
                                d.kind = "glob".into();
                                d.answer = Some(ans);
                            }
                            Err(e) => d.reason = format!("no-answer:{e}"),
                        }
                    }
                }
                Err(e) => {
                    d.decision = "silent".into();
                    d.reason = e;
                }
            }
        }
        "Read" => {
            // never denied: Edit and Write need the Read
            d.intent = "Read".into();
            let f = input["file_path"].as_str().unwrap_or("");
            let limited = input.get("limit").is_some_and(|l| !l.is_null()) || input.get("offset").is_some_and(|l| !l.is_null());
            let rel = hooksh::repo_rel(repo, f).unwrap_or_default();
            if let Some(fr) = probe.file(&rel).filter(|_| !rel.is_empty()) {
                let lim = input["limit"].as_i64().unwrap_or(2000).min(fr.lines.max(1));
                d.reads.push((rel.clone(), if fr.lines > 0 { fr.bytes * lim / fr.lines.max(1) } else { fr.bytes }));
            }
            match probe.file(&rel) {
                Some(fr) if !rel.is_empty() && !limited && fr.lines > 600 => {
                    d.decision = "nudge".into();
                    d.suggestion = format!("aix outline {rel}");
                    d.notes.push(format!("{rel} has {} lines; read one member with aix code {rel}:<line> or Read with offset/limit", fr.lines));
                }
                Some(_) => {
                    d.decision = "silent".into();
                    d.reason = if limited { "range".into() } else { "small".into() };
                }
                None => {
                    d.decision = "silent".into();
                    d.reason = if rel.is_empty() { "outside-repo".into() } else { "not-indexed".into() };
                }
            }
        }
        _ => {}
    }
    d
}

/// The indexed files a read prints and about how many bytes of each (from the index's line and byte counts).
fn read_bytes(probe: &dyn Probe, op: &hooksh::ReadOp) -> Vec<(String, i64)> {
    use hooksh::ReadOp::*;
    let est = |f: &str, n: Option<usize>| -> Option<(String, i64)> {
        let r = probe.file(f)?;
        let b = match n {
            Some(n) if r.lines > 0 => r.bytes * (n as i64).min(r.lines) / r.lines,
            _ => r.bytes,
        };
        Some((f.to_string(), b))
    };
    match op {
        Sed { file, ranges } => {
            let n: usize = ranges.iter().map(|(a, b)| b.saturating_sub(*a).saturating_add(1)).fold(0usize, |x, y| x.saturating_add(y));
            est(file, Some(n)).into_iter().collect()
        }
        Head { file, n } | Tail { file, n } => est(file, Some(*n)).into_iter().collect(),
        TailFrom { file, .. } => est(file, None).into_iter().collect(),
        Cat { files } => files.iter().filter_map(|f| est(f, None)).collect(),
        Echo(_) => vec![],
        Grep { files, .. } => files.iter().filter_map(|(f, _)| est(f, None)).collect(),
        Piped { src, .. } => read_bytes(probe, src),
    }
}

fn from_verdict(repo: &Path, cwd: &Path, probe: &dyn Probe, mut d: Decision, v: Verdict, dialect: Dialect, allow_deny: bool) -> Decision {
    let lookups: Vec<&hooksh::Seg> = v.segs.iter().filter(|s| s.intent != "echo").collect();
    if lookups.is_empty() {
        return d;
    }
    d.intent = lookups.iter().map(|s| s.intent.as_str()).collect::<Vec<_>>().join("+");
    if lookups.iter().all(|s| s.is_aix) {
        d.decision = "aix".into();
        return d;
    }
    if v.bypass {
        d.decision = "silent".into();
        d.reason = "bypass".into();
        return d;
    }
    d.data = v.segs.iter().filter_map(|s| s.data.clone()).collect();
    d.reads = v.segs.iter().filter_map(|s| s.read.as_ref()).flat_map(|op| read_bytes(probe, op)).collect();
    let trs: Vec<&Tr> = v.segs.iter().filter_map(|s| s.tr.as_ref()).collect();
    if trs.is_empty() {
        d.decision = "silent".into();
        d.reason = lookups.iter().filter(|s| !s.is_aix).map(|s| s.reason.as_str()).filter(|r| !r.is_empty()).collect::<Vec<_>>().join(",");
        return d;
    }
    let qt = if dialect == Dialect::Ps { Quote::Ps } else { Quote::Posix };
    let mut prefix = "aix".to_string();
    if v.cwd_outside {
        prefix = format!("aix --repo {}", hooksh::sh_quote(&repo.display().to_string()));
    }
    d.suggestion = hooksh::render_all(&trs, qt, &prefix);
    d.run = hooksh::render_all(&trs, Quote::Posix, &prefix);
    d.notes = trs.iter().filter_map(|t| t.note.clone()).collect();
    d.decision = "nudge".into();
    // escalation may answer it only when every pipeline is a lookup with an aix line (nothing else would be skipped)
    d.steerable = !v.other && v.segs.iter().all(|s| s.tr.is_some() || s.read.is_some());
    if allow_deny && dialect == Dialect::Posix {
        if let Some(ops) = &v.reads {
            match hookans::reads(repo, probe, ops) {
                Ok(ans) => {
                    d.decision = "deny".into();
                    d.kind = "exact".into();
                    // the cd did not run: the next call starts where this one did
                    let at_root = hooksh::lexical(&cwd.display().to_string()) == hooksh::lexical(&repo.display().to_string());
                    d.cd = v.cd.as_ref().map(|c| if at_root && !c.is_empty() { c.clone() } else { repo.join(c).display().to_string() });
                    d.answer = Some(ans);
                }
                Err(e) => d.reason = format!("no-answer:{e}"),
            }
        }
        // `grep -rn name .` for a symbol: the call graph answers it
        if d.decision == "nudge" && !v.other && v.segs.len() == 1 && deny_grep_enabled() {
            if let Some(p) = v.segs[0].pattern.clone() {
                symbol_upgrade(&mut d, probe, &p, false);
            }
        }
    }
    d
}

/// A search for a symbol the index has call sites for: answered with `aix callers` (plus the endpoints that reach
/// it). False (nothing changed) for any other pattern, or when `skip` (case-insensitive, filtered, counting).
fn symbol_upgrade(d: &mut Decision, probe: &dyn Probe, pat: &str, skip: bool) -> bool {
    if skip {
        return false;
    }
    let Some((sym, _)) = hooksh::symbol_of(pat) else { return false };
    let Some(ans) = probe.callers_answer(&sym, deny_answer_ms()) else { return false };
    d.decision = "deny".into();
    d.kind = "callers".into();
    d.intent = format!("{}:callers", d.intent.split(':').next().unwrap_or("Grep"));
    d.suggestion = format!("aix callers {}", quote_word(&sym));
    d.notes = vec![format!("aix impact {} (endpoints, routes, tests reached)", quote_word(&sym))];
    d.answer = Some(ans);
    true
}

/// The aix line for a built-in Grep call, or the silent reason.
fn grep_tool_line(repo: &Path, cwd: &Path, probe: &dyn Probe, input: &Value) -> Result<String, String> {
    let pat = input["pattern"].as_str().filter(|p| !p.is_empty()).ok_or("pattern")?;
    if input["multiline"].as_bool() == Some(true) {
        return Err("flag:multiline".into());
    }
    let mut cx = Cx::new(repo, Some(cwd), probe);
    cx.cwd = Some(cwd.to_path_buf());
    let mut args: Vec<String> = vec!["grep".into()];
    if input["-i"].as_bool() == Some(true) {
        args.push("-i".into());
    }
    match input["output_mode"].as_str().unwrap_or("files_with_matches") {
        "files_with_matches" => args.push("-l".into()),
        "count" => args.push("-c".into()),
        _ => {
            for k in ["-A", "-B", "-C"] {
                if let Some(n) = input[k].as_u64() {
                    if n > 120 {
                        return Err("flag:context>120".into());
                    }
                    args.extend([k.to_string(), n.to_string()]);
                }
            }
        }
    }
    if let Some(g) = input["glob"].as_str().filter(|g| !g.is_empty()) {
        args.extend(["--include".into(), g.to_string()]);
    }
    if let Some(t) = input["type"].as_str().filter(|g| !g.is_empty()) {
        args.extend(["-t".into(), t.to_string()]);
    }
    if pat.starts_with('-') {
        args.push("-e".into());
    }
    args.push(pat.to_string());
    let path = input["path"].as_str().unwrap_or("");
    let w = hooksh::W { s: path.to_string(), ..Default::default() };
    let rel = if path.is_empty() { cx_rel_cwd(repo, cwd)? } else { cx.rel(&w, Dialect::Posix)? };
    if !(probe.file(&rel).is_some() || probe.dir_has(&rel)) {
        return Err("not-indexed".into());
    }
    if !rel.is_empty() {
        args.push(rel);
    }
    if let Some(h) = input["head_limit"].as_u64() {
        args.extend(["--head".into(), h.to_string()]);
    }
    Ok(format!("aix {}", args.iter().map(|x| quote_word(x)).collect::<Vec<_>>().join(" ")))
}

fn cx_rel_cwd(repo: &Path, cwd: &Path) -> Result<String, String> {
    hooksh::repo_rel(repo, &cwd.display().to_string()).ok_or_else(|| "outside-repo".into())
}

fn quote_word(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:,=+@%".contains(c)) {
        s.to_string()
    } else {
        hooksh::sh_quote(s)
    }
}

/// The aix line for a built-in Glob call: `aix files [dir] -name '<basename glob>'` for `dir/**/*.ext`-shaped patterns.
fn glob_tool_line(repo: &Path, cwd: &Path, probe: &dyn Probe, input: &Value) -> Result<String, String> {
    let pat = input["pattern"].as_str().filter(|p| !p.is_empty()).ok_or("pattern")?;
    let path = input["path"].as_str().unwrap_or("");
    let base_rel = if path.is_empty() { cx_rel_cwd(repo, cwd)? } else {
        let p = if Path::new(path).is_absolute() { PathBuf::from(path) } else { cwd.join(path) };
        cx_rel_cwd(repo, &p)?
    };
    let (dir, name) = match pat.rsplit_once('/') {
        Some((d, n)) => (d.trim_end_matches("/**").trim_end_matches("**").trim_end_matches('/').to_string(), n.to_string()),
        None => (String::new(), pat.to_string()),
    };
    if dir.contains(['*', '?', '[', '{']) || name.contains("**") {
        return Err("glob-shape".into());
    }
    let full = [base_rel.as_str(), dir.as_str()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("/");
    if !probe.dir_has(&full) {
        return Err("not-indexed".into());
    }
    let mut args = vec!["files".to_string()];
    if !full.is_empty() {
        args.push(full);
    }
    // `dir/*.ts` (no **) is one level only
    if !pat.contains("**") {
        args.extend(["-maxdepth".into(), "1".into()]);
    }
    args.extend(["-name".into(), name]);
    Ok(format!("aix {}", args.iter().map(|x| quote_word(x)).collect::<Vec<_>>().join(" ")))
}

// ------------------------------------------------------------------------------------------------ event log

fn log_path(db: &Path) -> PathBuf {
    aix_core::logs::dir_of(db).join("hook-events.jsonl")
}

/// The recent tail of the event log (for the throttle and the repeat rule).
fn recent(db: &Path) -> Vec<Value> {
    let p = log_path(db);
    let Ok(mut f) = std::fs::File::open(&p) else { return vec![] };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let from = len.saturating_sub(96 * 1024);
    if f.seek(std::io::SeekFrom::Start(from)).is_err() {
        return vec![];
    }
    let mut s = String::new();
    let _ = f.take(96 * 1024).read_to_string(&mut s);
    s.lines().skip(usize::from(from > 0)).filter_map(|l| serde_json::from_str(l).ok()).collect()
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn append(db: &Path, row: &Value) {
    let p = log_path(db);
    if !p.parent().is_some_and(|d| d.is_dir()) {
        return;
    }
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = std::fs::rename(&p, p.with_extension("jsonl.1"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
        let _ = writeln!(f, "{row}");
    }
}

/// A data file at least this big is guarded on its first read.
const BIG_DATA: u64 = 64 * 1024;

/// A data file read again in this session: nudge to save it once as a data set (`aix put`) and query `@name`.
pub fn apply_data(d: &mut Decision, seen: &dyn Fn(&str) -> bool) {
    if d.decision != "silent" {
        return;
    }
    // a test/build/history run (`cmd:`) or a big file is guarded on the first read, other data files on the second
    // only whole-file reads: a `tail -3` or `grep -m` of a big log is already bounded
    let whole = matches!(d.intent.as_str(), "bash:cat" | "bash:jq" | "bash:python" | "bash:python3" | "bash:sort" | "bash:less");
    let big = |p: &str| p.starts_with("cmd:") || whole && std::fs::metadata(p).is_ok_and(|m| m.len() >= BIG_DATA);
    if let Some((abs, name, q)) = d.data.iter().find(|x| seen(&fnv(&x.0)) || big(&x.0)).cloned() {
        d.decision = "nudge".into();
        if let Some(cmd) = abs.strip_prefix("cmd:") {
            d.intent = "guard:output".into();
            d.suggestion = format!("{cmd} 2>&1 | aix put {name} -");
            d.notes = vec![format!("its whole output would land in context; saved once, read the verdict: {q} (bounded)")];
            return;
        }
        d.intent = format!("data:{}", d.intent.split(':').nth(1).unwrap_or("read"));
        d.suggestion = format!("aix put {name} {}", quote_word(&abs));
        let why = if seen(&fnv(&abs)) { "this file was read before in this session".to_string() } else { format!("this file is {} KB", std::fs::metadata(&abs).map(|m| m.len() / 1024).unwrap_or(0)) };
        d.notes = vec![format!("{why}; after saving it once: {q} (bounded, redacted)")];
    }
}

/// Apply the throttle and the repeat-to-bypass rule, write the log row, and return the hook's stdout JSON (None =
/// print nothing).
pub fn finish(db: &Path, v: &Value, mut d: Decision) -> Option<Value> {
    if d.decision == "none" {
        return None;
    }
    let sid = v["session_id"].as_str().unwrap_or("").chars().take(36).collect::<String>();
    let t = now();
    let rec = if matches!(d.decision.as_str(), "nudge" | "deny") || !d.data.is_empty() || !d.reads.is_empty() { recent(db) } else { vec![] };
    let same_sid = |r: &Value| r["sid"].as_str().unwrap_or("") == sid;
    // the same file read again and again with a text tool: name the bounded way to read it, with what it cost so far
    let read_keys: Vec<Value> = d.reads.iter().map(|(f, b)| json!([fnv(f), b])).collect();
    let mut reread = false;
    if d.decision == "nudge" {
        for (f, b) in &d.reads {
            let k = fnv(f);
            let prev: Vec<i64> = rec
                .iter()
                .filter(|r| same_sid(r))
                .filter_map(|r| r["rf"].as_array().and_then(|a| a.iter().find(|x| x[0] == k.as_str())).and_then(|x| x[1].as_i64()))
                .collect();
            if prev.len() >= 2 {
                let kb = (prev.iter().sum::<i64>() + b) as f64 / 1024.0;
                let fq = quote_word(f);
                d.notes.push(format!(
                    "{fq} read {} times in this session with text tools (~{kb:.1} KB of output so far): `aix outline {fq}` once (members with line ranges), then `aix code {fq}:A-B` or `aix code <member>` per part",
                    prev.len() + 1
                ));
                reread = true;
                break;
            }
        }
    }
    let data_keys: Vec<String> = d.data.iter().map(|x| fnv(&x.0)).collect();
    apply_data(&mut d, &|k: &str| rec.iter().any(|r| same_sid(r) && r["data"].as_array().is_some_and(|a| a.iter().any(|x| x == k))));
    if d.decision == "deny" && rec.iter().any(|r| same_sid(r) && r["key"] == d.key.as_str() && r["decision"] == "deny" && t - r["ts"].as_i64().unwrap_or(0) < REPEAT_SECS) {
        // the same call again right after a denial: the agent wants the real tool
        d.decision = "silent".into();
        d.reason = "repeat-after-deny".into();
        d.answer = None;
    }
    // escalation: nudges this session has not followed get an answer instead (the aix line run here)
    if d.decision == "nudge" && d.steerable && !sid.is_empty() && deny_enabled() && escalate_after() > 0 && !d.intent.starts_with("data:") {
        let since_aix = rec.iter().rev().filter(|r| same_sid(r)).take_while(|r| r["decision"] != "aix").filter(|r| r["decision"] == "nudge").count();
        if since_aix >= escalate_after() && !rec.iter().any(|r| same_sid(r) && r["key"] == d.key.as_str() && r["decision"] == "deny" && t - r["ts"].as_i64().unwrap_or(0) < REPEAT_SECS) {
            let cwd = v["cwd"].as_str().filter(|c| !c.is_empty()).map(PathBuf::from).unwrap_or_else(|| db.parent().unwrap_or(Path::new(".")).to_path_buf());
            match run_line(if d.run.is_empty() { &d.suggestion } else { &d.run }, &cwd, escalate_ms()) {
                Ok(ans) => {
                    d.decision = "deny".into();
                    d.kind = "aix".into();
                    d.reason = format!("escalated:{since_aix}");
                    d.answer = Some(ans);
                }
                Err(e) => d.reason = format!("escalate-failed:{e}"),
            }
        }
    }
    if d.decision == "nudge" && !reread && rec.iter().any(|r| same_sid(r) && r["suggestion"] == d.suggestion.as_str() && r["decision"] == "nudge" && t - r["ts"].as_i64().unwrap_or(0) < THROTTLE_SECS) {
        d.decision = "silent".into();
        d.reason = "throttled".into();
    }
    let cmd = v["tool_input"]["command"].as_str().or(v["tool_input"]["pattern"].as_str()).or(v["tool_input"]["file_path"].as_str()).unwrap_or("");
    let row = json!({
        "ts": t, "sid": sid, "tool": d.tool, "intent": d.intent, "decision": d.decision, "reason": d.reason,
        "suggestion": aix_extract::redact::redact_line(&clip(&d.suggestion, 300)),
        "cmd": aix_extract::redact::redact_line(&clip(cmd, 200)), "key": d.key,
        "answer_bytes": d.answer.as_ref().map(|a| a.len()),
    });
    let mut row = row;
    if d.decision == "deny" && !d.kind.is_empty() {
        row["kind"] = json!(d.kind);
    }
    if !data_keys.is_empty() {
        row["data"] = json!(data_keys);
    }
    if !read_keys.is_empty() {
        row["rf"] = json!(read_keys);
    }
    append(db, &row);
    output(&d)
}

/// Time an escalated answer may take (ms, default 1500: the hook's own limit is 3 s). `AIX_HOOK_ESCALATE_MS`.
fn escalate_ms() -> u128 {
    aix_core::config::env_var("HOOK_ESCALATE_MS").and_then(|v| v.trim().parse().ok()).unwrap_or(1500)
}

/// Run an aix line (`aix ...` calls, `;`-separated, each optionally piped through plain text filters) with this
/// binary, bounded in time; its stdout when it answered (exit 0, or 1 = nothing found), else Err(why). Every word
/// is literal and re-quoted, no redirection, filters only from a fixed read-only set: nothing else can run.
fn run_line(line: &str, cwd: &Path, budget_ms: u128) -> Result<String, String> {
    const FILTERS: &[&str] = &["grep", "egrep", "head", "tail", "wc", "cut", "uniq", "tr", "sort"];
    let pls = hooksh::parse_posix(line);
    if pls.is_empty() || pls.len() > 8 {
        return Err("shape".into());
    }
    let mut script = vec![];
    for (i, pl) in pls.iter().enumerate() {
        if i + 1 < pls.len() && !matches!(pl.sep.as_str(), ";" | "\n") {
            return Err(format!("sep:{}", pl.sep));
        }
        let mut stages = vec![];
        for (k, st) in pl.stages.iter().enumerate() {
            let prog = st.w.first().map(|w| w.s.as_str()).unwrap_or("");
            let ok_prog = if k == 0 { prog == "aix" } else { FILTERS.contains(&prog) };
            if !ok_prog || st.writes || st.stdin.is_some() || !st.env.is_empty() || st.w.iter().any(|w| w.var || w.glob) {
                return Err(format!("stage:{prog}"));
            }
            // `uniq IN OUT` writes OUT
            if prog == "uniq" && st.w[1..].iter().any(|w| !w.s.starts_with('-')) {
                return Err("stage:uniq-out".into());
            }
            // sort -o / --output writes a file
            if prog == "sort" && st.w.iter().any(|w| w.s.starts_with("-o") || w.s.starts_with("--output") || (w.s.starts_with('-') && !w.s.starts_with("--") && w.s.contains('o'))) {
                return Err("stage:sort-o".into());
            }
            let mut words: Vec<String> = st.w.iter().map(|w| hooksh::sh_quote(&w.s)).collect();
            if k == 0 {
                words.insert(1, "--no-refresh".into());
            }
            stages.push(words.join(" "));
        }
        script.push(stages.join(" | "));
    }
    let exe = std::env::current_exe().map_err(|_| "exe")?;
    let dir = exe.parent().ok_or("exe")?.to_path_buf();
    // Windows: Git for Windows' sh and its text tools (a hook's PATH rarely has them)
    let (sh, tools) = aix_core::sys::posix_sh().ok_or("no-sh")?;
    let mut dirs = vec![dir];
    dirs.extend(tools);
    dirs.extend(std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default());
    let path = std::env::join_paths(dirs).map_err(|_| "path")?;
    let mut cmd = std::process::Command::new(sh);
    // MSYS_NO_PATHCONV: Git for Windows' sh would turn a `/route` or `/pattern/` word into `C:/Program Files/Git/...`
    cmd.arg("-c").arg(script.join("\n")).current_dir(cwd).env("PATH", path).env("AIX_HOOK", "off").env("MSYS_NO_PATHCONV", "1");
    aix_core::sys::own_group(&mut cmd);
    let mut ch = cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().map_err(|_| "spawn")?;
    let mut stdout = ch.stdout.take().ok_or("stdout")?;
    let reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = (&mut stdout).take(1 << 20).read_to_string(&mut s);
        s
    });
    let t0 = std::time::Instant::now();
    let status = loop {
        if let Ok(Some(st)) = ch.try_wait() {
            break st;
        }
        if t0.elapsed().as_millis() > budget_ms {
            // the whole group: sh and the aix / filter processes under it
            aix_core::sys::kill_tree(&mut ch);
            let _ = ch.wait();
            return Err("budget".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let out = reader.join().map_err(|_| "read")?;
    if !matches!(status.code(), Some(0 | 1)) || out.trim().is_empty() {
        return Err(format!("exit:{:?}", status.code()));
    }
    Ok(out)
}

/// The hook's stdout for a decision. Deny: `permissionDecision: "deny"` with the answer as the reason (Claude reads
/// it); nudge: `additionalContext` only (the tool still runs).
pub fn output(d: &Decision) -> Option<Value> {
    match d.decision.as_str() {
        "deny" if d.kind != "exact" && !d.kind.is_empty() => Some(json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": labelled(d)}})),
        "deny" => {
            let ans = d.answer.as_deref().unwrap_or("");
            let mut reason = String::from("aix answered this from its index instead of running it (every file read is indexed and unchanged since; the text between the markers is byte-identical to what the tool prints).\n");
            if d.cd.is_some() {
                reason.push_str("Its `cd` did not run either: your shell's working directory is unchanged.\n");
            }
            reason.push_str("<<<aix-answer\n");
            reason.push_str(ans);
            let no_eol = !ans.ends_with('\n') && !ans.is_empty();
            if no_eol {
                reason.push('\n');
            }
            reason.push_str("aix-answer>>>\n");
            if no_eol {
                // said outside the markers: the text between them stays the tool's output
                reason.push_str("(the output ends without a newline: the line break before aix-answer>>> is not part of it)\n");
            }
            let next = match &d.cd {
                Some(c) => format!("cd {} && {}", quote_word(c), d.suggestion),
                None => d.suggestion.clone(),
            };
            reason.push_str(&format!("Same answer next time: {}\n", aix_extract::redact::redact_line(&next)));
            reason.push_str(if d.tool == "Bash" {
                "Need the real command anyway (e.g. to see the file as it is right now)? Run it again unchanged, or prefix it with AIX_HOOK=off."
            } else {
                "Need the real tool anyway? Repeat the identical call and it runs."
            });
            // the answer was proven redaction-free (hookans); a second pass would only strip CRs and break identity
            Some(json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}))
        }
        "nudge" => {
            // a listing answers from the index: tracked files of types aix does not index are named in its footer,
            // not listed, so it is not "the same answer" as ls / find
            let listing = ["aix ls", "aix files"].iter().any(|p| d.suggestion.starts_with(p));
            let mut ctx = if listing {
                format!("Next similar lookup: run `{}` instead (the indexed files, bounded, one call; tracked files of unindexed types are named in its footer).", d.suggestion)
            } else {
                format!("Next similar lookup: run `{}` instead (same answer, bounded and redacted, one call).", d.suggestion)
            };
            for n in &d.notes {
                ctx.push_str(&format!("\n  note: {n}"));
            }
            let mut v = json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": ctx}});
            aix_extract::redact::redact_json(&mut v);
            Some(v)
        }
        _ => None,
    }
}

/// A deny whose answer is aix's own (not the tool's output byte for byte): said plainly, bounded, with the aix line
/// that continues it and the way to get the tool's own result.
fn labelled(d: &Decision) -> String {
    // the Grep/Glob rows were proven redaction-free; aix's own answers get the redaction pass here
    let ans = if matches!(d.kind.as_str(), "grep" | "glob") { d.answer.clone().unwrap_or_default() } else { aix_extract::redact::redact_block(d.answer.as_deref().unwrap_or("")) };
    let sug = aix_extract::redact::redact_line(&d.suggestion);
    let what = if d.tool == "Bash" { "command" } else { d.tool.as_str() };
    let head = match d.kind.as_str() {
        "grep" => "Answered by aix from its index; Grep did not run. These are the same matching rows Grep returns here (every file in scope indexed and unchanged or read from disk, gitignored and binary files skipped as Grep does); only the row order may differ, lines over 300 characters are cut (…) and secrets are redacted.".to_string(),
        "glob" => "Answered by aix from its index; Glob did not run. These are the same files Glob lists here (newest first).".to_string(),
        "callers" => format!(
            "Answered by aix's call graph; the {what} did not run. The pattern is a symbol, so this is its definition, its resolved call sites (each with the method that contains it) and the HTTP endpoints that reach it. It is NOT grep output: comments, strings and other text mentions are not listed."
        ),
        _ => format!("Answered by running `{sug}` (aix, from its index); the {what} did not run. This is aix's answer, not the {what}'s output."),
    };
    let lines: Vec<&str> = ans.lines().collect();
    let mut s = format!("{head}\n<<<aix-answer\n");
    for l in lines.iter().take(ANSWER_LINES) {
        s.push_str(l);
        s.push('\n');
    }
    s.push_str("aix-answer>>>\n");
    if lines.len() > ANSWER_LINES {
        s.push_str(&format!("(first {ANSWER_LINES} of {} lines; all of them: `{sug}` (paged) or repeat the identical call)\n", lines.len()));
    }
    // a PowerShell call's line is quoted for PowerShell
    let how = if d.tool == "PowerShell" { "directly" } else { "with Bash directly" };
    match d.kind.as_str() {
        "callers" => s.push_str(&format!("Next time run `{sug}` (call sites) or `{}` {how}.\n", d.notes.first().map(|n| n.split(" (").next().unwrap_or(n)).unwrap_or("aix impact <symbol>"))),
        _ => s.push_str(&format!("Next time run `{sug}` {how}.\n")),
    }
    s.push_str(if d.tool == "Bash" {
        "Need the real command's output? Run it again unchanged (or prefix it with AIX_HOOK=off)."
    } else if d.kind == "callers" {
        "Need the raw text matches? Repeat the identical call and it runs."
    } else {
        "Need the tool itself? Repeat the identical call and it runs."
    });
    s
}

// ------------------------------------------------------------------------------------------------ stats --hooks

/// `aix stats --hooks [--since D]`: decisions by intent from the event log. D = YYYY-MM-DD or 30m/12h/7d.
pub fn stats(db: &Path, since: Option<&str>) -> String {
    let from = since.and_then(parse_since).unwrap_or(0);
    let mut rows: Vec<Value> = vec![];
    for p in [log_path(db).with_extension("jsonl.1"), log_path(db)] {
        if let Ok(s) = std::fs::read_to_string(&p) {
            rows.extend(s.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["ts"].as_i64().unwrap_or(0) >= from));
        }
    }
    if rows.is_empty() {
        return format!("no hook events{} ({})", since.map(|s| format!(" since {s}")).unwrap_or_default(), log_path(db).display());
    }
    use std::collections::BTreeMap;
    let mut by: BTreeMap<String, [u64; 4]> = BTreeMap::new();
    let mut reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut tot = [0u64; 4];
    for r in &rows {
        let k = match r["decision"].as_str().unwrap_or("") {
            "nudge" => 0,
            "deny" => 1,
            "silent" => 2,
            "aix" => 3,
            _ => continue,
        };
        let intent = r["intent"].as_str().unwrap_or("?").split('+').next().unwrap_or("?").to_string();
        by.entry(intent).or_default()[k] += 1;
        tot[k] += 1;
        if k == 2 {
            *reasons.entry(r["reason"].as_str().unwrap_or("").split(',').next().unwrap_or("").to_string()).or_default() += 1;
        }
    }
    let mut out = vec![format!(
        "== hook events{}: {} decisions: {} nudged, {} answered (deny), {} silent, {} aix calls",
        since.map(|s| format!(" since {s}")).unwrap_or_default(),
        rows.len(),
        tot[0],
        tot[1],
        tot[2],
        tot[3]
    )];
    let steered = tot[0] + tot[1];
    if steered + tot[3] > 0 {
        out.push(format!("aix share of steerable lookups: {:.0}% (aix / (aix + nudged + answered))", 100.0 * tot[3] as f64 / (steered + tot[3]) as f64));
    }
    let mut v: Vec<_> = by.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1.iter().sum::<u64>()));
    out.push("intent                         nudge  deny silent   aix".into());
    for (k, c) in v.iter().take(30) {
        out.push(format!("{:<30} {:>6} {:>5} {:>6} {:>5}", clip(k, 30), c[0], c[1], c[2], c[3]));
    }
    if v.len() > 30 {
        out.push(format!("(+{} more intents)", v.len() - 30));
    }
    let mut rs: Vec<_> = reasons.into_iter().collect();
    rs.sort_by_key(|x| std::cmp::Reverse(x.1));
    out.push(format!("silent because: {}", rs.iter().take(10).map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ")));
    out.extend(follow_lines(&rows));
    out.join("\n")
}

/// Was each nudge followed? Followed = an aix call among the same session's next 3 logged calls (within 10 min);
/// ignored = those calls came and none was aix; open = the session had not made them yet.
pub fn follow_stats(rows: &[Value]) -> Vec<(String, [u64; 3])> {
    use std::collections::BTreeMap;
    let mut by: BTreeMap<String, [u64; 3]> = BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        if r["decision"] != "nudge" {
            continue;
        }
        let sid = r["sid"].as_str().unwrap_or("");
        let ts = r["ts"].as_i64().unwrap_or(0);
        let next: Vec<&Value> = rows[i + 1..]
            .iter()
            .filter(|x| x["sid"].as_str().unwrap_or("") == sid && x["decision"].as_str().is_some_and(|d| d != "none"))
            .take(3)
            .collect();
        let within: Vec<&&Value> = next.iter().filter(|x| x["ts"].as_i64().unwrap_or(0) - ts <= 600).collect();
        let k = if within.iter().any(|x| x["decision"] == "aix") {
            0
        } else if within.len() == 3 || next.len() > within.len() {
            1
        } else {
            2
        };
        by.entry(sid.to_string()).or_default()[k] += 1;
    }
    let mut v: Vec<(String, [u64; 3])> = by.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1.iter().sum::<u64>()));
    v
}

fn follow_lines(rows: &[Value]) -> Vec<String> {
    let per = follow_stats(rows);
    if per.is_empty() {
        return vec![];
    }
    let t = per.iter().fold([0u64; 3], |a, (_, c)| [a[0] + c[0], a[1] + c[1], a[2] + c[2]]);
    let mut out = vec![format!(
        "nudges followed: {} ({:.0}%), ignored: {}, open: {} (followed = an aix call among the session's next 3 calls within 10 min)",
        t[0],
        100.0 * t[0] as f64 / (t[0] + t[1]).max(1) as f64,
        t[1],
        t[2]
    )];
    out.push("session        followed ignored  open".into());
    for (sid, c) in per.iter().take(8) {
        out.push(format!("{:<14} {:>8} {:>7} {:>5}", clip(if sid.is_empty() { "?" } else { sid }, 12), c[0], c[1], c[2]));
    }
    if per.len() > 8 {
        out.push(format!("(+{} more sessions)", per.len() - 8));
    }
    out
}

fn parse_since(s: &str) -> Option<i64> {
    let n = |x: &str| x.parse::<i64>().ok();
    if let Some(m) = s.strip_suffix('m').and_then(n) {
        return Some(now() - m * 60);
    }
    if let Some(h) = s.strip_suffix('h').and_then(n) {
        return Some(now() - h * 3600);
    }
    if let Some(d) = s.strip_suffix('d').and_then(n) {
        return Some(now() - d * 86400);
    }
    day_epoch(s)
}

/// YYYY-MM-DD (UTC) -> epoch seconds.
fn day_epoch(s: &str) -> Option<i64> {
    let p: Vec<i64> = s.get(..10)?.split('-').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let (y, m, d) = (p[0], p[1], p[2]);
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400)
}

// ------------------------------------------------------------------------------------------------ classify

/// `aix hook classify [FILE] [--summary]`: Claude Code transcript JSONL (or PreToolUse event lines) on stdin or FILE
/// -> one TSV row per tool call: `ts  tool  class  intent  suggestion-or-reason`, where class is aix | miss (the hook
/// would nudge or answer) | silent (a lookup the hook leaves alone, with the reason) | other. Same rules as the hook,
/// without throttling.
pub fn classify(repo: &Path, probe: &dyn Probe, args: &[String]) -> i32 {
    let summary_only = args.iter().any(|a| a == "--summary");
    let path = args.iter().find(|a| !a.starts_with("--"));
    let mut s = String::new();
    let ok = match path {
        Some(p) => std::fs::File::open(p).and_then(|f| f.take(1 << 30).read_to_string(&mut s)).is_ok(),
        None => std::io::stdin().take(1 << 30).read_to_string(&mut s).is_ok(),
    };
    aix_core::sys::strip_stdin_bom(&mut s);
    if !ok {
        eprintln!("aix hook classify: cannot read input");
        return 2;
    }
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    let mut seen: std::collections::HashSet<String> = Default::default();
    let mut out = std::io::stdout().lock();
    for line in s.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        for ev in events(&v) {
            let mut d = decide(repo, probe, &ev, false);
            let keys: Vec<String> = d.data.iter().map(|x| fnv(&x.0)).collect();
            apply_data(&mut d, &|k: &str| seen.contains(k));
            seen.extend(keys);
            let class = match d.decision.as_str() {
                _ if d.intent.starts_with("data:") && d.decision == "nudge" => "data",
                "aix" => "aix",
                "nudge" | "deny" => "miss",
                "silent" => "silent",
                _ => "other",
            };
            *counts.entry(class.to_string()).or_default() += 1;
            if !summary_only {
                let what = if class == "miss" || class == "data" { d.suggestion.clone() } else { d.reason.clone() };
                let _ = writeln!(out, "{}\t{}\t{class}\t{}\t{}", ev["ts"].as_str().unwrap_or(""), d.tool, d.intent, aix_extract::redact::redact_line(&clip(&what, 240)).replace(['\t', '\n'], " "));
            }
        }
    }
    let (m, a) = (counts.get("miss").copied().unwrap_or(0), counts.get("aix").copied().unwrap_or(0));
    let rate = if m + a > 0 { format!("{:.1}%", 100.0 * m as f64 / (m + a) as f64) } else { "n/a".into() };
    let _ = writeln!(
        out,
        "# summary: miss {m}, aix {a}, silent {}, data {}, other {}; missed-opportunity rate {rate} (miss / (miss + aix))",
        counts.get("silent").copied().unwrap_or(0),
        counts.get("data").copied().unwrap_or(0),
        counts.get("other").copied().unwrap_or(0)
    );
    0
}

/// Tool calls in one JSONL line: a transcript entry (assistant message with tool_use blocks) or a hook event.
fn events(v: &Value) -> Vec<Value> {
    if v.get("tool_name").is_some() {
        return vec![v.clone()];
    }
    let mut out = vec![];
    if let Some(items) = v["message"]["content"].as_array() {
        for it in items {
            if it["type"] == "tool_use" {
                let name = it["name"].as_str().unwrap_or("");
                let name = if name == "mcp__aix__aix" { "aix-mcp" } else { name };
                let mut ev = json!({"tool_name": name, "tool_input": it["input"].clone(), "cwd": v["cwd"].clone(), "ts": v["timestamp"].clone()});
                if name == "aix-mcp" {
                    ev["tool_name"] = json!("Bash");
                    ev["tool_input"] = json!({"command": "aix mcp-call"});
                }
                out.push(ev);
            }
        }
    }
    out
}
