//! `aix init`: scripts/aix-init.sh in Rust, so a repo can be set up where bash and python3 are missing (Windows). In
//! one idempotent command: the .gitignore preflight, then Claude Code's hooks (exec form: the hook runs this binary
//! directly, no shell, no wrapper script), the allow rules for the read-only `aix <query>` commands (PowerShell ones
//! too on Windows), the skill, /brief /impact /bugs and the rules file, a post-commit git hook, the index (with 30 s of
//! embedding) and the auto-refresh watcher. Existing settings are merged, never overwritten. What it adds is recorded in
//! `.aix/created-files` in the script's format, so `--uninstall` (here or in the script) removes only that.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::{refresh, watch};

pub struct Opts {
    pub shared: bool,
    pub mcp: bool,
    pub no_git_hook: bool,
    pub no_watch: bool,
    /// Some(true) --allow-data, Some(false) --no-allow-data
    pub data: Option<bool>,
    pub accept: bool,
    pub uninstall: bool,
}

/// The read-only query commands Claude may run without asking (scripts/aix-init.sh's list; a test keeps the two
/// equal). Not a blanket `aix:*`: that would also approve install-git-hook, --db/--repo redirection, mcp and update.
const QUERIES: &[&str] = &[
    "brief", "impact", "scope", "callers", "callees", "outline", "trace", "explain", "bugs", "qa", "feature", "text", "endpoint", "symbol", "script", "tasks", "history", "find", "ask",
    "hints", "grep", "howto", "code", "table", "route", "sql", "schema", "stats", "card", "mask list", "mask test", "redact-test",
    // logs/pastes: queries only, not add|rm|prune|mark|watch|alert (they change what is indexed: Claude asks you)
    "logs errors", "logs unwatch", "logs grep", "logs show", "logs tail", "logs list", "logs suggest", "logs since-mark", "logs await", "logs alerts", "paste list", "paste show",
    "paste grep", "paste errors", "paste frames", "paste suggest", "file list", "wait",
];
/// Exact read-only forms (`privacy-check --fix` purges, `sets rm` deletes, `ignore-check --accept` records a decision).
const EXACT: &[&str] = &[
    "aix privacy-check", "aix privacy-check --deep", "aix privacy-check --json", "aix privacy-check --deep --json", "aix sets", "aix sets --global", "aix sets list:*", "aix sets show:*",
    "aix ignore-check", "aix ignore-check --json", "aix ignore-check --suggest", "aix-refresh:*", "aix refresh:*",
];
/// Opt-in (--allow-data): store and delete data sets without asking (sets prune still asks).
const DATA: &[&str] = &["aix put:*", "aix sets rm:*"];
const LEGACY_RULE: &str = "Bash(aix:*)";

/// The shells Claude Code runs commands with here: rules are written for each.
fn shells() -> &'static [&'static str] {
    if cfg!(windows) {
        &["Bash", "PowerShell"]
    } else {
        &["Bash"]
    }
}

pub fn allow_rules() -> Vec<String> {
    let inner = QUERIES.iter().map(|q| format!("aix {q}:*")).chain(EXACT.iter().map(|e| e.to_string())).collect::<Vec<_>>();
    shells().iter().flat_map(|sh| inner.iter().map(move |r| format!("{sh}({r})"))).collect()
}

fn data_rules() -> Vec<String> {
    shells().iter().flat_map(|sh| DATA.iter().map(move |r| format!("{sh}({r})"))).collect()
}

type Res<T> = Result<T, String>;

/// One of our hook entries: exec form running an aix binary (`args` starting with `hook` or `card`), a shell form
/// spelling the same, or the script's `aix-hook-*` wrappers.
fn ours(h: &Value) -> bool {
    let cmd = h.get("command").and_then(Value::as_str).unwrap_or("");
    if cmd.contains("aix-hook-") {
        return true;
    }
    static SHELL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#"(^|[/\\])aix(\.exe)?['"]?\s+(hook|card)\b"#).unwrap());
    let name = cmd.rsplit(['/', '\\']).next().unwrap_or("");
    let first = h.get("args").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str);
    (matches!(name, "aix" | "aix.exe") && matches!(first, Some("hook" | "card"))) || SHELL.is_match(cmd)
}

fn hook_entries(s: &Map<String, Value>) -> Vec<&Value> {
    let mut out = vec![];
    if let Some(Value::Object(hooks)) = s.get("hooks") {
        for groups in hooks.values() {
            for g in groups.as_array().into_iter().flatten() {
                out.extend(g.get("hooks").and_then(Value::as_array).into_iter().flatten().filter(|h| h.is_object()));
            }
        }
    }
    out
}

fn allow_of(s: &Map<String, Value>) -> Vec<String> {
    s.get("permissions").and_then(|p| p.get("allow")).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// (existed, the object; None = unparseable and none of our business).
fn load(path: &Path, required: bool) -> Res<(bool, Option<Map<String, Value>>)> {
    if !path.exists() {
        return Ok((false, Some(Map::new())));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {} ({e}); nothing was changed.", path.display()))?;
    let raw = raw.trim_start_matches('\u{feff}');
    let parsed = if raw.trim().is_empty() {
        Ok(Map::new())
    } else {
        match serde_json::from_str::<Value>(raw) {
            Ok(Value::Object(m)) => Ok(m),
            Ok(_) => Err("the top level is not a JSON object".to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    match parsed {
        Ok(m) => Ok((true, Some(m))),
        Err(_) if !required && !raw.contains("aix-hook") && !raw.contains("\"pretool\"") => Ok((true, None)),
        Err(e) => Err(format!(
            "{} is not plain JSON ({e}).\n  Claude Code accepts comments/trailing commas there, but aix init cannot merge into them safely.\n  Fix or remove the comments, or add the hooks by hand (see integrations/claude-code/settings.hooks.json); nothing was changed.",
            path.display()
        )),
    }
}

/// missing | plain | legacy | ours
fn probe(path: &Path, required: bool) -> Res<&'static str> {
    Ok(match load(path, required)? {
        (false, _) => "missing",
        (true, None) => "plain",
        (true, Some(s)) if allow_of(&s).iter().any(|r| r == LEGACY_RULE) => "legacy",
        (true, Some(s)) if hook_entries(&s).iter().any(|h| ours(h)) => "ours",
        _ => "plain",
    })
}

fn writable(path: &Path) -> bool {
    if path.exists() {
        return !path.is_dir() && std::fs::OpenOptions::new().append(true).open(path).is_ok();
    }
    let mut d = path.parent();
    while let Some(x) = d.filter(|x| !x.exists()) {
        d = x.parent();
    }
    let d = d.unwrap_or(Path::new("."));
    let probe = d.join(format!(".aix-write-probe-{}", std::process::id()));
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(probe);
    ok
}

/// The `.aix/created-files` record: config files aix created itself, rules it added, hashes of what it copied.
struct Marker(PathBuf);
impl Marker {
    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.0).unwrap_or_default().lines().map(String::from).collect()
    }
    fn append(&self, lines: &[String]) -> Res<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let mut f = aix_core::sys::private_file(std::fs::OpenOptions::new().create(true).append(true)).open(&self.0).map_err(|e| format!("cannot write {} ({e})", self.0.display()))?;
        f.write_all((lines.join("\n") + "\n").as_bytes()).map_err(|e| e.to_string())
    }
    fn hash(&self, rel: &str) -> Option<String> {
        self.lines().iter().rev().find_map(|l| l.strip_prefix(&format!("hash\t{rel}\t")).map(String::from))
    }
    fn set_hash(&self, rel: &str, sum: &str) {
        if self.hash(rel).as_deref() == Some(sum) {
            return;
        }
        let mut ls: Vec<String> = self.lines().into_iter().filter(|l| !l.starts_with(&format!("hash\t{rel}\t"))).collect();
        ls.push(format!("hash\t{rel}\t{sum}"));
        let _ = std::fs::write(&self.0, ls.join("\n") + "\n");
    }
    /// Where the bytes a config file had before aix first rewrote it are kept (uninstall restores them when nothing
    /// else changed).
    fn orig(&self, p: &Path) -> PathBuf {
        self.0.with_file_name(format!("orig-{}.json", aix_core::logs::sha_key(p)))
    }
    fn keep_orig(&self, p: &Path) {
        let o = self.orig(p);
        if p.exists() && !o.exists() {
            if let Ok(b) = std::fs::read(p) {
                if std::fs::write(&o, b).is_ok() {
                    let _ = aix_core::sys::chmod(&o, 0o600);
                }
            }
        }
    }
    /// The original bytes when they parse to the same object as `s`.
    fn restored(&self, p: &Path, s: &Map<String, Value>) -> Option<Vec<u8>> {
        let b = std::fs::read(self.orig(p)).ok()?;
        let t = String::from_utf8_lossy(&b);
        let v: Value = if t.trim().is_empty() { json!({}) } else { serde_json::from_str(&t).ok()? };
        (v.as_object() == Some(s)).then_some(b)
    }
}

/// Write `s` to `path` through a temp file (the mode kept): the original bytes instead when `orig` is given.
fn write_json(path: &Path, s: &Map<String, Value>, orig: Option<Vec<u8>>) -> Res<()> {
    let fail = |e: std::io::Error| format!("cannot write {} ({e}); the file was left as it was.", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(fail)?;
    }
    let tgt = aix_core::sys::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let tmp = PathBuf::from(format!("{}.aix-tmp", tgt.display()));
    let bytes = orig.unwrap_or_else(|| (serde_json::to_string_pretty(&Value::Object(s.clone())).unwrap_or_default() + "\n").into_bytes());
    std::fs::write(&tmp, bytes).map_err(fail)?;
    if let Some(m) = std::fs::metadata(&tgt).ok().and_then(|md| aix_core::sys::mode(&md)) {
        let _ = aix_core::sys::chmod(&tmp, m & 0o7777);
    }
    std::fs::rename(&tmp, &tgt).map_err(fail)
}

#[derive(PartialEq, Clone, Copy)]
enum Action {
    Install,
    /// drop the old blanket rule only
    Clean,
    Uninstall,
}

/// The hooks aix registers: (event, matcher, args, timeout).
const HOOKS: [(&str, Option<&str>, [&str; 2], u64); 3] = [
    ("SessionStart", None, ["hook", "session-start"], 20),
    ("PreToolUse", Some("Bash|PowerShell|Grep|Glob|Read"), ["hook", "pretool"], 5),
    ("UserPromptSubmit", None, ["hook", "prompt"], 5),
];

/// Merge (install), or take out (clean / uninstall), our hooks and allow rules in one settings file.
fn apply(path: &Path, action: Action, marker: &Marker, exe: &str) -> Res<()> {
    let (existed, s) = load(path, action == Action::Install)?;
    let Some(mut s) = s else { return Ok(()) };
    if !existed && action != Action::Install {
        return Ok(());
    }
    let before = Value::Object(s.clone());
    let created = marker.lines();
    let recorded: BTreeSet<String> = created.iter().filter_map(|l| l.strip_prefix(&format!("rule\t{}\t", path.display())).map(String::from)).collect();
    let tracked = created.contains(&format!("tracked\t{}", path.display()));
    // keys are updated in place (insert keeps an existing key's position), so the file keeps its order
    let hooks_is_obj = s.get("hooks").is_none_or(Value::is_object);
    let mut hooks = s.get("hooks").and_then(Value::as_object).cloned().unwrap_or_default();
    for (ev, matcher, args, timeout) in HOOKS {
        let mut out: Vec<Value> = vec![];
        for g in hooks.get(ev).and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some(hs) = g.get("hooks").and_then(Value::as_array) else {
                out.push(g);
                continue;
            };
            let keep: Vec<Value> = hs.iter().filter(|h| action == Action::Clean || !ours(h)).cloned().collect();
            if keep.len() == hs.len() {
                out.push(g); // not ours: untouched
            } else if !keep.is_empty() {
                let mut g = g.clone(); // a user's own hook shares the group: only our entries go
                g["hooks"] = Value::Array(keep);
                out.push(g);
            }
        }
        if action == Action::Install {
            let mut g = Map::new();
            if let Some(m) = matcher {
                g.insert("matcher".into(), json!(m));
            }
            g.insert("hooks".into(), json!([{"type": "command", "command": exe, "args": args, "timeout": timeout}]));
            out.push(Value::Object(g));
        }
        if out.is_empty() {
            hooks.shift_remove(ev);
        } else {
            hooks.insert(ev.into(), Value::Array(out));
        }
    }
    if !hooks_is_obj {
        // not an object: not ours to fix
    } else if hooks.is_empty() {
        s.shift_remove("hooks");
    } else {
        s.insert("hooks".into(), Value::Object(hooks));
    }
    let ours_rules: BTreeSet<String> = allow_rules().into_iter().chain(data_rules()).collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut allow: Vec<Value> = vec![];
    for x in s.get("permissions").and_then(|p| p.get("allow")).and_then(Value::as_array).cloned().unwrap_or_default() {
        let Some(r) = x.as_str() else {
            allow.push(x);
            continue;
        };
        if r == LEGACY_RULE
            || action == Action::Uninstall && (r == "mcp__aix" || r.starts_with("mcp__aix__"))
            // only the rules aix added (an identical rule the user wrote stays); no record = an older aix-init
            || action == Action::Uninstall && ours_rules.contains(r) && (recorded.contains(r) || !tracked)
        {
            continue;
        }
        if seen.insert(r.to_string()) {
            allow.push(x);
        }
    }
    let added: Vec<String> = if action == Action::Install { allow_rules().into_iter().filter(|r| !seen.contains(r)).collect() } else { vec![] };
    allow.extend(added.iter().cloned().map(Value::String));
    set_allow(&mut s, allow);
    if action == Action::Uninstall && s.is_empty() && created.iter().any(|l| Path::new(l) == path) {
        std::fs::remove_file(path).map_err(|e| format!("cannot remove {} ({e}).", path.display()))?;
        println!("removed {} (aix created it and nothing else was in it)", path.display());
        return Ok(());
    }
    let changed = Value::Object(s.clone()) != before;
    if changed || !existed {
        if action == Action::Install && existed {
            marker.keep_orig(path);
        }
        let orig = if action == Action::Install { None } else { marker.restored(path, &s) };
        write_json(path, &s, orig)?;
    }
    if action == Action::Install {
        let mut rec = vec![];
        if !existed && !created.iter().any(|l| Path::new(l) == path) {
            rec.push(path.display().to_string());
        }
        if !tracked {
            rec.push(format!("tracked\t{}", path.display()));
        }
        rec.extend(added.iter().map(|r| format!("rule\t{}\t{r}", path.display())));
        marker.append(&rec)?;
        println!("hooks + allow rules -> {}", path.display());
    } else if changed {
        println!("{}{}", if action == Action::Uninstall { "removed aix hooks/permissions from " } else { "removed the old blanket Bash(aix:*) rule from " }, path.display());
    }
    Ok(())
}

/// `permissions.allow` = `allow`, in place; an empty list (and then an empty `permissions`) is dropped.
fn set_allow(s: &mut Map<String, Value>, allow: Vec<Value>) {
    let mut perms = s.get("permissions").and_then(Value::as_object).cloned().unwrap_or_default();
    if allow.is_empty() {
        perms.shift_remove("allow");
    } else {
        perms.insert("allow".into(), Value::Array(allow));
    }
    if perms.is_empty() {
        s.shift_remove("permissions");
    } else {
        s.insert("permissions".into(), Value::Object(perms));
    }
}

/// --allow-data / --no-allow-data: add or remove exactly the data-set rules.
fn apply_data(path: &Path, on: bool, marker: &Marker) -> Res<()> {
    let (existed, s) = load(path, true)?;
    let mut s = s.unwrap_or_default();
    let al: Vec<Value> = s.get("permissions").and_then(|p| p.get("allow")).and_then(Value::as_array).cloned().unwrap_or_default();
    let has = |r: &str| al.iter().any(|x| x.as_str() == Some(r));
    let new: Vec<Value> = if on {
        al.iter().cloned().chain(data_rules().into_iter().filter(|r| !has(r)).map(Value::String)).collect()
    } else {
        al.iter().filter(|x| !x.as_str().is_some_and(|r| data_rules().iter().any(|d| d == r))).cloned().collect()
    };
    let same = new == al;
    let added: Vec<String> = data_rules().into_iter().filter(|r| on && !has(r)).collect();
    set_allow(&mut s, new);
    if same && existed {
        println!("data-set rules already {} in {}", if on { "on" } else { "off" }, path.display());
        return Ok(());
    }
    write_json(path, &s, None)?;
    if on {
        let mut rec = vec![];
        if !existed {
            rec.push(path.display().to_string());
        }
        rec.extend(added.iter().map(|r| format!("rule\t{}\t{r}", path.display())));
        marker.append(&rec)?;
        println!("data sets: put / sets rm allowed without asking (sets prune still asks) -> {}", path.display());
    } else {
        println!("data sets: put / sets rm ask again -> {}", path.display());
    }
    Ok(())
}

/// `allow_data = true` in `.aix/config.toml` (a top-level key, before the first [table]); MCP reads it.
fn config_allow_data(p: &Path, on: bool) {
    let text = std::fs::read_to_string(p).unwrap_or_default();
    let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim_start().starts_with("allow_data") || !l.contains('=')).collect();
    if on {
        let k = lines.iter().position(|l| l.trim().starts_with('[')).unwrap_or(lines.len());
        lines.insert(k, "allow_data = true   # aix init --allow-data: put / sets rm through MCP");
    }
    let t = lines.join("\n").trim_matches('\n').to_string();
    if !t.is_empty() || p.exists() {
        let _ = std::fs::write(p, if t.is_empty() { t } else { t + "\n" });
        let _ = aix_core::sys::chmod(p, 0o600);
    }
}

/// `.mcp.json`: (existed, object), or the reason it cannot be merged.
fn mcp_load(p: &Path) -> Res<(bool, Map<String, Value>)> {
    match load(p, true) {
        Ok((e, Some(s))) => Ok((e, s)),
        Ok((e, None)) => Ok((e, Map::new())),
        Err(_) => Err(format!("{} is not plain JSON; fix it or add/remove the MCP server by hand. Nothing was changed.", p.display())),
    }
}

fn mcp_apply(p: &Path, install: bool, marker: &Marker, exe: &str) -> Res<()> {
    let (existed, mut s) = mcp_load(p)?;
    let mut srv = s.get("mcpServers").and_then(Value::as_object).cloned().unwrap_or_default();
    if !install {
        srv.shift_remove("aix");
        if srv.is_empty() {
            s.shift_remove("mcpServers");
        } else {
            s.insert("mcpServers".into(), Value::Object(srv));
        }
        if s.is_empty() && marker.lines().iter().any(|l| Path::new(l) == p) {
            std::fs::remove_file(p).map_err(|e| e.to_string())?;
            println!("removed {}", p.display());
            return Ok(());
        }
        let orig = marker.restored(p, &s);
        return write_json(p, &s, orig);
    }
    // keep a customised entry (extra args, env, ...): only the executable of a stock entry is swapped
    let mut e = srv.get("aix").and_then(Value::as_object).cloned().unwrap_or_default();
    e.entry("type").or_insert(json!("stdio"));
    let cur = e.get("command").and_then(Value::as_str).unwrap_or("");
    if cur.is_empty() || matches!(cur.rsplit(['/', '\\']).next(), Some("aix" | "aix.exe")) {
        e.insert("command".into(), json!(exe));
    }
    if !e.get("args").is_some_and(Value::is_array) {
        e.insert("args".into(), json!(["mcp"]));
    }
    srv.insert("aix".into(), Value::Object(e));
    s.insert("mcpServers".into(), Value::Object(srv));
    if existed {
        marker.keep_orig(p);
    } else {
        marker.append(&[p.display().to_string()])?;
    }
    write_json(p, &s, None)?;
    println!("MCP server -> {}", p.display());
    Ok(())
}

fn sha256_hex(b: &[u8]) -> String {
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn files_under(d: &Path) -> Vec<(String, PathBuf)> {
    let mut out = vec![];
    let mut stack = vec![d.to_path_buf()];
    while let Some(x) = stack.pop() {
        for e in std::fs::read_dir(&x).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(rel) = p.strip_prefix(d) {
                out.push((format!("./{}", aix_core::sys::slash(rel)), p));
            }
        }
    }
    out.sort();
    out
}

/// sha256 of a file, or of a tree (`find . -type f | sort | xargs sha256sum | sha256sum`, byte order).
fn hash_of(p: &Path) -> Option<String> {
    if p.is_dir() {
        let lines: String = files_under(p).into_iter().map(|(rel, f)| format!("{}  {rel}\n", sha256_hex(&std::fs::read(f).unwrap_or_default()))).collect();
        Some(sha256_hex(lines.as_bytes()))
    } else {
        std::fs::read(p).ok().map(|b| sha256_hex(&b))
    }
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    for (rel, f) in files_under(from) {
        let t = to.join(rel.trim_start_matches("./"));
        std::fs::create_dir_all(t.parent().unwrap_or(to))?;
        std::fs::copy(f, t)?;
    }
    Ok(())
}

/// Where scripts/install.sh / install.ps1 put the skill, commands and rules aix init copies.
fn share_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).or_else(|| aix_core::sys::home().map(|h| h.join(".local/share")))?;
    Some(base.join("aix/claude-code"))
}

/// Skill + slash commands + rules into `.claude/`: a copy that differs from the installed one is replaced (what changed
/// is printed); a copy YOU edited since aix copied it (hash in created-files) is saved as .bak first.
fn copy_skill(repo: &Path, share: &Path, marker: &Marker) -> Res<()> {
    let claude = repo.join(".claude");
    let mut changes: Vec<String> = vec![];
    let src = share.join("skills/aix");
    let dst = claude.join("skills").join("aix");
    let shipped = hash_of(&src).unwrap_or_default();
    if dst.is_dir() {
        let ch = hash_of(&dst).unwrap_or_default();
        if ch != shipped && marker.hash("skills/aix").is_some_and(|r| r != ch) {
            // SKILL.md is renamed inside the copy so Claude Code does not load it as a second skill
            let bak = claude.join("skills").join("aix.bak");
            let _ = std::fs::remove_dir_all(&bak);
            copy_tree(&dst, &bak).map_err(|e| e.to_string())?;
            for (rel, f) in files_under(&bak) {
                if rel.ends_with("/SKILL.md") {
                    let _ = std::fs::rename(&f, f.with_extension("md.bak"));
                }
            }
            println!("your edited skill was saved as {} (SKILL.md.bak) before the update", bak.display());
        }
        let a: Vec<(String, PathBuf)> = files_under(&src);
        let b: Vec<(String, PathBuf)> = files_under(&dst);
        for (rel, f) in &a {
            match b.iter().find(|x| &x.0 == rel) {
                Some((_, g)) if std::fs::read(f).ok() != std::fs::read(g).ok() => changes.push(format!("skill: updated {}", rel.rsplit('/').next().unwrap_or(rel))),
                None => changes.push(format!("skill: {} added or removed", rel.trim_start_matches("./"))),
                _ => {}
            }
        }
        changes.extend(b.iter().filter(|x| !a.iter().any(|y| y.0 == x.0)).map(|x| format!("skill: {} added or removed", x.0.trim_start_matches("./"))));
    } else {
        changes.push("skill: installed".into());
    }
    if hash_of(&dst).as_deref() != Some(shipped.as_str()) {
        let _ = std::fs::remove_dir_all(&dst);
        copy_tree(&src, &dst).map_err(|e| format!("cannot copy the skill into {} ({e})", dst.display()))?;
    }
    marker.set_hash("skills/aix", &shipped);
    let cmds = claude.join("commands");
    std::fs::create_dir_all(&cmds).map_err(|e| e.to_string())?;
    for (rel, f) in files_under(&share.join("commands")) {
        let name = rel.trim_start_matches("./").to_string();
        if !name.ends_with(".md") || name.contains('/') {
            continue;
        }
        let t = cmds.join(&name);
        let key = format!("commands/{name}");
        let theirs = std::fs::read_to_string(&t).ok();
        if theirs.as_ref().is_some_and(|x| !x.to_lowercase().contains("aix")) && marker.hash(&key).is_none() {
            println!("kept your own {}", t.display());
            continue;
        }
        let same = std::fs::read(&f).ok() == std::fs::read(&t).ok();
        if theirs.is_none() {
            changes.push(format!("command: {name} installed"));
        } else if !same {
            if marker.hash(&key).is_some_and(|r| hash_of(&t).as_deref() != Some(r.as_str())) {
                let _ = std::fs::copy(&t, t.with_extension("md.bak"));
                println!("your edited {} was saved as {}.bak before the update", t.display(), t.display());
            }
            changes.push(format!("command: {name} updated"));
        }
        if !same {
            std::fs::copy(&f, &t).map_err(|e| e.to_string())?;
        }
        marker.set_hash(&key, &hash_of(&f).unwrap_or_default());
    }
    // the rules block: Claude Code loads .claude/rules/ as project memory (it is what makes Sonnet reach for aix)
    let rsrc = share.join("rules/aix.md");
    if rsrc.is_file() {
        let t = claude.join("rules").join("aix.md");
        let rec = marker.hash("rules/aix.md");
        if t.is_file() && rec.as_ref().is_some_and(|r| hash_of(&t).as_deref() != Some(r.as_str())) {
            println!("kept your edited {}", t.display());
        } else if std::fs::read(&rsrc).ok() != std::fs::read(&t).ok() {
            changes.push(format!("rules: aix.md {}", if t.is_file() { "updated" } else { "installed" }));
            std::fs::create_dir_all(claude.join("rules")).map_err(|e| e.to_string())?;
            std::fs::copy(&rsrc, &t).map_err(|e| e.to_string())?;
            marker.set_hash("rules/aix.md", &hash_of(&t).unwrap_or_default());
        } else {
            marker.set_hash("rules/aix.md", &hash_of(&t).unwrap_or_default());
        }
    }
    if changes.is_empty() {
        println!("skill + /brief /impact /bugs + rules already current in {}", claude.display());
    } else {
        println!("{}\nskill + /brief /impact /bugs + rules refreshed -> {}", changes.join("\n"), claude.display());
    }
    Ok(())
}

/// The skill, commands and rules file, removed only while unmodified (what aix copied, or what this release ships).
fn remove_skill(repo: &Path, share: Option<&Path>, marker: &Marker) {
    let claude = repo.join(".claude");
    let unmodified = |p: &Path, rel: &str, shipped: Option<PathBuf>| {
        let ch = hash_of(p);
        ch.is_some() && (shipped.and_then(|s| hash_of(&s)) == ch || marker.hash(rel) == ch)
    };
    let skill = claude.join("skills").join("aix");
    if skill.is_dir() {
        let legacy = marker.hash("skills/aix").is_none() && std::fs::read_to_string(skill.join("SKILL.md")).is_ok_and(|t| t.contains("\nname: aix") || t.starts_with("name: aix"));
        if unmodified(&skill, "skills/aix", share.map(|s| s.join("skills/aix"))) || legacy {
            let _ = std::fs::remove_dir_all(&skill);
        } else {
            println!("kept {} (your modified copy)", skill.display());
        }
    }
    for c in ["brief", "impact", "bugs"] {
        let f = claude.join("commands").join(format!("{c}.md"));
        if !f.is_file() {
            continue;
        }
        let rel = format!("commands/{c}.md");
        let legacy = marker.hash(&rel).is_none() && std::fs::read_to_string(&f).is_ok_and(|t| t.to_lowercase().contains("aix"));
        if unmodified(&f, &rel, share.map(|s| s.join(&rel))) || legacy {
            let _ = std::fs::remove_file(&f);
        } else {
            println!("kept {} (your own or modified copy)", f.display());
        }
    }
    let f = claude.join("rules").join("aix.md");
    if f.is_file() {
        if unmodified(&f, "rules/aix.md", share.map(|s| s.join("rules/aix.md"))) {
            let _ = std::fs::remove_file(&f);
        } else {
            println!("kept {} (your modified copy)", f.display());
        }
    }
}

/// The post-commit hook file (shared by all worktrees of a clone): removed, or the pre-aix one put back, unless another
/// worktree still uses aix.
fn remove_git_hook(repo: &Path) {
    let Some(o) = std::process::Command::new("git").arg("-C").arg(repo).args(["rev-parse", "--git-path", "hooks"]).output().ok().filter(|o| o.status.success()) else { return };
    let rel = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let hooks = if Path::new(&rel).is_absolute() { PathBuf::from(&rel) } else { repo.join(&rel) };
    let hook = hooks.join("post-commit");
    if !std::fs::read_to_string(&hook).is_ok_and(|t| t.contains(">>> aix post-commit >>>")) {
        return;
    }
    let wt = std::process::Command::new("git").arg("-C").arg(repo).args(["worktree", "list", "--porcelain"]).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let others: Vec<&str> = wt
        .lines()
        .filter_map(|l| l.strip_prefix("worktree "))
        .filter(|w| !aix_core::sys::canonicalize(w).is_ok_and(|c| aix_core::sys::same_path(&c, repo)) && Path::new(w).join(".aix/initialized").exists())
        .collect();
    if !others.is_empty() {
        println!("left the aix post-commit hook in place: it is shared and these worktrees still use aix: {}", others.join(", "));
        return;
    }
    let pre = hooks.join("post-commit.pre-aix");
    let _ = if pre.exists() { std::fs::rename(&pre, &hook) } else { std::fs::remove_file(&hook) };
    println!("removed the aix post-commit hook");
}

/// Restarts the watcher a run stopped when the run ends early (an error), so the repo keeps the watcher it had.
struct WatchGuard<'a> {
    repo: &'a Path,
    db: Option<&'a Path>,
    stopped: bool,
    done: bool,
}
impl Drop for WatchGuard<'_> {
    fn drop(&mut self) {
        if self.stopped && !self.done {
            watch::spawn(self.repo, self.db);
        }
    }
}

/// The aix command lines below (card, privacy check): first `n` lines of their output.
fn show(repo: &Path, args: &[&str], n: usize) {
    let mut c = std::process::Command::new(crate::refresh::self_exe());
    c.arg("--repo").arg(repo).args(args);
    let (_, out) = refresh::output(c);
    for l in out.lines().take(n) {
        println!("{l}");
    }
}

/// `aix init [REPO] [--shared] [--mcp] [--no-git-hook] [--no-watch] [--allow-data | --no-allow-data] [--accept-ignore]
/// [--uninstall]`: the exit code.
pub fn run(arg: Option<&Path>, db: Option<&Path>, o: &Opts) -> i32 {
    let repo = match refresh::root_of(arg, "init", true) {
        Ok(r) => r,
        Err((c, m)) => {
            eprintln!("{m}{}", if m.contains("not its root") { "; nothing was changed. (a separate repo there needs its own git init first)" } else { "" });
            return c;
        }
    };
    println!("aix init: repo {}", repo.display());
    match install(&repo, db, o) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aix init: {e}");
            1
        }
    }
}

fn install(repo: &Path, db: Option<&Path>, o: &Opts) -> Res<i32> {
    let exe = aix_core::sys::slash(&refresh::self_exe());
    let dbp = aix_core::index::resolve_db(repo, db);
    let (lset, sset, mcpjson) = (repo.join(".claude").join("settings.local.json"), repo.join(".claude").join("settings.json"), repo.join(".mcp.json"));
    // .gitignore preflight: read-only, before anything is touched
    if !o.uninstall {
        if let Err(stop) = aix_core::ignorecheck::gate(repo, &dbp, false) {
            if !o.accept {
                println!("{}", aix_extract::redact::redact_block(&stop));
                println!("aix init: stopped before changing anything. Fix .gitignore (aix ignore-check --suggest), or re-run with --accept-ignore to index as is.");
                return Ok(3);
            }
        }
    }
    // preflight: which files get touched; each must parse and be writable BEFORE anything is stopped or moved
    let (t_l, t_s) = if o.uninstall {
        (Some(Action::Uninstall), Some(Action::Uninstall))
    } else {
        let (sl, ss) = (probe(&lset, false)?, probe(&sset, false)?);
        let shared = o.shared || ss == "legacy" && sl != "legacy";
        if shared && !o.shared {
            println!("note: an older aix-init wired .claude/settings.json (shared); updating it there");
        }
        let other = |st: &str| (st == "legacy").then_some(Action::Clean);
        if shared {
            probe(&sset, true)?;
            (other(sl), Some(Action::Install))
        } else {
            probe(&lset, true)?;
            (Some(Action::Install), other(ss))
        }
    };
    for (t, p) in [(t_l, &lset), (t_s, &sset)] {
        if t.is_some() && !writable(p) {
            return Err(format!("{} is not writable (permissions?); nothing was changed.", p.display()));
        }
    }
    if o.data.is_some() && !o.uninstall {
        load(&lset, true)?;
        if !writable(&lset) {
            return Err(format!("{} is not writable (permissions?); nothing was changed.", lset.display()));
        }
    }
    if (o.mcp || o.uninstall && mcpjson.exists()) && (mcp_load(&mcpjson).is_err() || !writable(&mcpjson)) {
        return Err(mcp_load(&mcpjson).err().unwrap_or_else(|| format!("{} is not writable (permissions?); nothing was changed.", mcpjson.display())));
    }
    if !o.uninstall && (std::fs::create_dir_all(repo.join(".claude")).is_err() || !writable(&repo.join(".claude/.probe"))) {
        return Err(format!("cannot create or write {} (permissions?); nothing was changed.", repo.join(".claude").display()));
    }
    // stop the watcher first: a second one must never start next to it; a fresh one is started at the end
    let mut guard = WatchGuard { repo, db, stopped: false, done: o.uninstall || o.no_watch };
    if !o.uninstall {
        for p in watch::stop(repo, &dbp) {
            println!("aix watch: stopped {p}");
            guard.stopped = true;
        }
        std::fs::create_dir_all(repo.join(".aix")).map_err(|e| e.to_string())?;
    }
    let marker = Marker(repo.join(".aix").join("created-files"));
    if let Some(t) = t_l {
        apply(&lset, t, &marker, &exe)?;
    }
    if let Some(t) = t_s {
        apply(&sset, t, &marker, &exe)?;
    }
    if let (Some(on), false) = (o.data, o.uninstall) {
        apply_data(&lset, on, &marker)?;
        config_allow_data(&repo.join(".aix").join("config.toml"), on);
    }
    let share = share_dir();
    if o.uninstall {
        remove_skill(repo, share.as_deref(), &marker);
        remove_git_hook(repo);
        if mcpjson.exists() {
            mcp_apply(&mcpjson, false, &marker, &exe)?;
        }
        // stop only THIS repo's watcher, and drop this index's lock and pid files
        watch::stop(repo, &dbp);
        if let Some(ld) = refresh::lock_dir() {
            let key = aix_core::logs::sha_key(&dbp);
            for n in ["embed.lock", "log.lock", "refresh.lock", "watch.lock", "watch.pid", "watch.logs.pid"] {
                let _ = std::fs::remove_file(ld.join(format!("{key}.{n}")));
            }
        }
        let _ = std::fs::remove_dir_all(repo.join(".aix"));
        for d in ["commands", "skills", "rules", ""] {
            let _ = std::fs::remove_dir(repo.join(".claude").join(d));
        }
        println!("aix removed from {}", repo.display());
        return Ok(0);
    }
    match share.as_deref().filter(|s| s.join("skills/aix").is_dir()) {
        Some(s) => copy_skill(repo, s, &marker)?,
        None => println!("note: skill files not found in {} (re-run the install script)", share.map(|s| s.display().to_string()).unwrap_or_else(|| "~/.local/share/aix/claude-code".into())),
    }
    if o.mcp {
        mcp_apply(&mcpjson, true, &marker, &exe)?;
    }
    if !o.no_git_hook {
        crate::hooks::install_git_hook(repo, db, true).map_err(|e| e.to_string())?;
    }
    // marker: SessionStart may refresh the index and start a watcher here
    let _ = std::fs::write(repo.join(".aix").join("initialized"), b"");
    for f in ["initialized", "created-files"] {
        let _ = aix_core::sys::chmod(&repo.join(".aix").join(f), 0o600);
    }
    if o.accept {
        aix_core::ignorecheck::cli(repo, db, &["--accept".to_string()], false);
    }
    println!("building the index...");
    let r = refresh::run(Some(repo), db, &refresh::Opts { full: false, embed: 30.0, summaries: 0.0, backfill: false, wait: 120.0, strict: true, accept_ignore: false });
    if r != 0 {
        return Ok(r);
    }
    if !o.no_watch && watch::spawn(repo, db) {
        guard.done = true;
        println!("auto-refresh watcher started");
    }
    let _ = aix_core::sys::owner_only_dir(&repo.join(".aix"));
    println!();
    show(repo, &["--no-refresh", "card"], 12);
    println!("privacy check:");
    show(repo, &["--no-refresh", "privacy-check"], 12);
    println!();
    println!("done. Start Claude Code in {}; try: aix brief <a route or menu label>   (undo: aix init --uninstall)", repo.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allow list is aix-init.sh's (each rule as a Bash rule, plus `aix refresh`): the two cannot drift apart.
    #[test]
    fn allow_rules_match_the_script() {
        let sh = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-init.sh")).unwrap();
        let block = &sh[sh.find("QUERIES = [").unwrap()..sh.find("DATA_RULES").unwrap()];
        let queries = &block[..block.find(']').unwrap()];
        let q = regex::Regex::new(r#""([^"]+)""#).unwrap();
        let mut script: BTreeSet<String> = q.captures_iter(queries).map(|m| format!("Bash(aix {}:*)", &m[1])).collect();
        let rules = regex::Regex::new(r#""(Bash\([^"]+\))""#).unwrap();
        // the literal rules after the list (not the f-string template that expands it)
        script.extend(rules.captures_iter(&block[block.find(']').unwrap()..]).map(|m| m[1].to_string()).filter(|r| !r.contains('{')));
        let ours: BTreeSet<String> = allow_rules().into_iter().filter(|r| r.starts_with("Bash(")).collect();
        assert_eq!(ours.difference(&script).cloned().collect::<Vec<_>>(), vec!["Bash(aix refresh:*)".to_string()]);
        assert!(script.is_subset(&ours), "{:?}", script.difference(&ours).collect::<Vec<_>>());
        let data = &sh[sh.find("DATA_RULES = [").unwrap()..];
        let data: BTreeSet<String> = rules.captures_iter(&data[..data.find(']').unwrap()]).map(|m| m[1].to_string()).collect();
        assert_eq!(data, data_rules().into_iter().filter(|r| r.starts_with("Bash(")).collect());
    }

    #[test]
    fn our_hooks_in_every_spelling() {
        assert!(ours(&json!({"command": "C:/Users/x/.cargo/bin/aix.exe", "args": ["hook", "pretool"]})));
        assert!(ours(&json!({"command": "/Users/x/.cargo/bin/aix", "args": ["card"]})));
        assert!(ours(&json!({"command": "'/Users/x/.cargo/bin/aix-hook-pretool'"})));
        assert!(ours(&json!({"command": "C:/Users/x/.cargo/bin/aix.exe hook prompt"})));
        assert!(!ours(&json!({"command": "/opt/tools/lint.sh"})));
        assert!(!ours(&json!({"command": "/Users/x/tools/check.sh"})));
    }
}
