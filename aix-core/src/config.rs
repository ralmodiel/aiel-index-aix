//! Configuration: `<repo>/.aix/config.toml`, then `~/.config/aix/config.toml`, then the local AI
//! harness routing file `~/.config/local-llm/backends.json` (roles "embed" and "chat") for endpoints.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct Endpoint {
    /// Base URL, e.g. `http://127.0.0.1:8092` (the client appends `/v1/...`).
    pub url: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// OpenAI-compatible embeddings endpoint. None = keyword search only.
    pub embed: Option<Endpoint>,
    /// OpenAI-compatible chat endpoints in priority order (summaries, `ask --answer`).
    pub chat: Vec<Endpoint>,
    pub embed_query_prefix: String,
    pub embed_doc_prefix: String,
    pub embed_batch: usize,
    /// Seconds of embedding work `update` may do.
    pub embed_deadline_secs: f64,
    /// Seconds of embedding work a query may do before answering.
    pub query_embed_deadline_secs: f64,
    /// Extra path regexes to exclude from the index.
    pub exclude: Vec<String>,
    /// Query-time default exclusions (kinds or globs, e.g. ["docs", "**/*.snap"]): they only narrow answers (never widen
    /// what is indexed or readable), so a repo-local config may set them. `--no-default-excludes` turns them off.
    pub default_excludes: Vec<String>,
    /// Answers with more rows than this (after a truncation) get the count breakdown and narrowing hints.
    pub count_first_over: usize,
    pub max_file_bytes: u64,
    /// `aix code` / `cat` / `head` / `tail` / `sed -n`: a requested range is shown whole up to this many lines; a
    /// longer one prints its first 3/5, an outline of the rest and the exact continuation (`--max N`, `--full`).
    pub code_cap: usize,
    /// Default per-call output budget in tokens (0 = off), as `--max-tokens N` (4 bytes a token, whole rows only, a
    /// footer names the exact command for the rest). `AIX_MAX_TOKENS` overrides; a typed `--max-tokens` wins.
    pub max_tokens: usize,
    /// Built-in seeded regex patterns (mined from what scripts and Claude search with) are materialized.
    pub seed_patterns: bool,
    /// Also index files git does not track yet (default off: a fresh credentials file must never be indexed
    /// before it is committed).
    pub index_untracked: bool,
    /// Repo-relative globs of gitignored files to index anyway (scratch notes, scripts): text types only, 256 KB a file,
    /// at most 5000 files, secret names refused, no symlinks, never inside node_modules/.git/target/dist/build or a
    /// nested checkout.
    pub include: Vec<String>,
    /// Folders outside the repo whose scripts `aix script` lists by name and usage line (opt-in; `AIX_SCRIPT_DIRS` adds
    /// more, colon separated). Never indexed; the privacy deny list applies.
    pub script_dirs: Vec<String>,
    /// `[redact]`: extra secret rules and hashed false-positive allow-list entries for this repo (the built-in
    /// families cannot be switched off), `ip = true` to redact IP addresses.
    pub redact: aix_extract::redact::RedactConfig,
    /// Your weekly model allocation in tokens (0 = unknown): `stats --savings` then shows the tokens saved as a share of it.
    /// `AIX_WEEKLY_TOKENS` overrides.
    pub weekly_tokens: u64,
    /// Name of that allocation for the output, e.g. "Max 20x" (`AIX_PLAN` overrides).
    pub plan: String,
    /// When the weekly allocation resets, e.g. "Sun 16:00" (local time; `AIX_WEEK_START` overrides): `stats --savings`
    /// then measures from the most recent such moment instead of from the first recorded query.
    pub week_start: String,
    /// Where the settings came from (for `stats`).
    #[serde(skip)]
    pub source: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            embed: None,
            chat: vec![],
            embed_query_prefix: "Instruct: Given a question about a software project's features, pages, bugs, tests or code, retrieve the index entries that answer it\nQuery: ".into(),
            embed_doc_prefix: String::new(),
            embed_batch: 32,
            weekly_tokens: 0,
            plan: String::new(),
            week_start: String::new(),
            embed_deadline_secs: 20.0,
            query_embed_deadline_secs: 0.0,
            exclude: vec![],
            default_excludes: vec![],
            count_first_over: 60,
            max_file_bytes: 1_500_000,
            code_cap: 200,
            max_tokens: 0,
            seed_patterns: true,
            index_untracked: false,
            include: vec![],
            script_dirs: vec![],
            redact: Default::default(),
            source: "defaults".into(),
        }
    }
}

/// Read the environment variable `AIX_<name>`.
pub fn env_var(name: &str) -> Option<String> {
    std::env::var(format!("AIX_{name}")).ok()
}

fn home() -> Option<PathBuf> {
    crate::sys::home()
}

impl Config {
    /// Load config for a repo. `db_dir` is the directory holding index.db (may differ from the repo).
    pub fn load(repo: &Path, db_dir: &Path) -> Config {
        let mut cands = vec![db_dir.join("config.toml"), repo.join(".aix/config.toml")];
        if let Some(h) = home() {
            cands.push(h.join(".config/aix/config.toml"));
        }
        let mut cfg = Config::default();
        for c in cands {
            if let Ok(t) = std::fs::read_to_string(&c) {
                match toml::from_str::<Config>(&t) {
                    Ok(mut x) => {
                        x.source = c.display().to_string();
                        // A cloned repo must not choose where document text is sent: endpoint settings in a
                        // config that lives inside the repo are ignored.
                        if is_repo_local(&c, repo) && (x.embed.is_some() || !x.chat.is_empty()) {
                            eprintln!("aix: ignoring embed/chat endpoints in {} (repo-local config)", c.display());
                            x.embed = None;
                            x.chat.clear();
                        }
                        cfg = x;
                        break;
                    }
                    Err(e) => {
                        // `"C:\Users\x"` is a TOML escape error (`\U`, `\x`): say how to write a Windows path
                        let m = e.to_string();
                        let hint = if t.contains(":\\") && (m.contains("escape") || m.contains("unicode")) {
                            " (a Windows path in a \"...\" string needs doubled backslashes: write 'C:\\x' in single quotes, or C:/x)"
                        } else {
                            ""
                        };
                        eprintln!("aix: ignoring {}: {m}{hint}", c.display())
                    }
                }
            }
        }
        // the plan is the user's, not the repo's: when the config in use does not set it, take it from the user config
        if cfg.weekly_tokens == 0 {
            if let Some(h) = home() {
                if let Some(x) = std::fs::read_to_string(h.join(".config/aix/config.toml")).ok().and_then(|t| toml::from_str::<Config>(&t).ok()) {
                    cfg.weekly_tokens = x.weekly_tokens;
                    if cfg.plan.is_empty() {
                        cfg.plan = x.plan;
                    }
                    if cfg.week_start.is_empty() {
                        cfg.week_start = x.week_start;
                    }
                }
            }
        }
        if let Some(n) = env_var("MAX_TOKENS").and_then(|v| v.trim().parse::<usize>().ok()) {
            cfg.max_tokens = n;
        }
        if let Some(p) = env_var("PLAN") {
            cfg.plan = p;
        }
        if let Some(w) = env_var("WEEK_START") {
            cfg.week_start = w;
        }
        if cfg.embed.is_none() || cfg.chat.is_empty() {
            if let Some(h) = home() {
                let bj = h.join(".config/local-llm/backends.json");
                if let Some((embed, chat)) = read_backends(&bj) {
                    if cfg.embed.is_none() {
                        cfg.embed = embed;
                    }
                    if cfg.chat.is_empty() {
                        cfg.chat = chat;
                    }
                    cfg.source = format!("{} + {}", cfg.source, bj.display());
                }
            }
        }
        if let Some(w) = env_var("WEEKLY_TOKENS").and_then(|v| v.trim().replace('_', "").parse::<u64>().ok()) {
            cfg.weekly_tokens = w;
        }
        if let Some(u) = env_var("EMBED_URL") {
            cfg.embed =
                if u.is_empty() { None } else { Some(Endpoint { url: u, model: "local".into(), name: "env".into() }) };
        }
        // Document text only ever goes to a model on this machine.
        if let Some(e) = &cfg.embed {
            if let Err(m) = check_loopback(&e.url) {
                eprintln!("aix: embed endpoint refused: {m}");
                cfg.embed = None;
            }
        }
        aix_extract::masks::install(repo);
        for w in aix_extract::redact::configure(&cfg.redact) {
            eprintln!("aix: {w}");
        }
        cfg.chat.retain(|e| match check_loopback(&e.url) {
            Ok(()) => true,
            Err(m) => {
                eprintln!("aix: chat endpoint refused: {m}");
                false
            }
        });
        cfg
    }
}

fn is_repo_local(cfg_path: &Path, repo: &Path) -> bool {
    let p = crate::sys::canonicalize(&cfg_path).unwrap_or_else(|_| cfg_path.to_path_buf());
    let r = crate::sys::canonicalize(&repo).unwrap_or_else(|_| repo.to_path_buf());
    p.starts_with(r)
}

/// Only loopback hosts (127.0.0.0/8, ::1, localhost) are acceptable endpoints.
pub fn check_loopback(url: &str) -> Result<(), String> {
    let rest = url.trim().strip_prefix("http://").or_else(|| url.trim().strip_prefix("https://")).ok_or_else(|| format!("{url}: only http(s) URLs on this machine are allowed"))?;
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    if auth.contains('@') {
        return Err(format!("{url}: credentials in the URL are not allowed"));
    }
    let host = if let Some(h) = auth.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else {
        auth.rsplit_once(':').map(|x| x.0).unwrap_or(auth)
    };
    let ok = host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || host.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a.is_loopback());
    if ok {
        Ok(())
    } else {
        Err(format!("{url}: host '{host}' is not loopback (127.0.0.1, ::1, localhost); aix sends text only to a local model"))
    }
}

/// Parse the local-llm harness routing file: first backend of role "embed", all of role "chat".
pub fn read_backends(path: &Path) -> Option<(Option<Endpoint>, Vec<Endpoint>)> {
    let t = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&t).ok()?;
    let list = |role: &str| -> Vec<Endpoint> {
        v.get(role)
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|e| serde_json::from_value::<Endpoint>(e.clone()).ok()).collect())
            .unwrap_or_default()
    };
    Some((list("embed").into_iter().next(), list("chat")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backends_json() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("b.json");
        std::fs::write(&p, r#"{"embed":[{"name":"e","url":"http://x:1","model":"m"}],"chat":[{"name":"c","url":"http://y:2","model":"q","tags":["fast"]}]}"#).unwrap();
        let (e, c) = read_backends(&p).unwrap();
        assert_eq!(e.unwrap().url, "http://x:1");
        assert_eq!(c[0].model, "q");
    }
    #[test]
    fn loopback_only() {
        for u in ["http://127.0.0.1:8092", "http://localhost:1/v1", "http://[::1]:9", "http://127.5.5.5", "https://LOCALHOST"] {
            assert!(check_loopback(u).is_ok(), "{u}");
        }
        for u in ["http://evil.example:80", "http://10.0.0.5:8092", "http://127.0.0.1.evil.com", "http://localhost@evil.com/", "ftp://127.0.0.1", "http://0.0.0.0:1", "http://[::ffff:8.8.8.8]"] {
            assert!(check_loopback(u).is_err(), "{u}");
        }
    }
    #[test]
    fn repo_local_endpoints_ignored_and_remote_refused() {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("r");
        std::fs::create_dir_all(repo.join(".aix")).unwrap();
        std::fs::write(repo.join(".aix/config.toml"), "[embed]\nurl = \"http://127.0.0.1:1\"\n[[chat]]\nurl = \"http://127.0.0.1:2\"\n").unwrap();
        let c = Config::load(&repo, &repo.join(".aix"));
        assert!(c.embed.as_ref().is_none_or(|e| e.url != "http://127.0.0.1:1"), "{c:?}");
        assert!(c.chat.iter().all(|e| e.url != "http://127.0.0.1:2"), "{c:?}");
        // a config outside the repo with a remote host is refused
        let ext = d.path().join("ext");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(ext.join("config.toml"), "[embed]\nurl = \"http://evil.example:1\"\n").unwrap();
        let repo2 = d.path().join("r2");
        std::fs::create_dir_all(&repo2).unwrap();
        let c = Config::load(&repo2, &ext);
        assert!(c.embed.is_none());
    }
    #[test]
    fn toml_config() {
        let c: Config =
            toml::from_str("exclude = [\"^vendor/\"]\n[embed]\nurl = \"http://e\"\nmodel = \"m\"\n").unwrap();
        assert_eq!(c.embed.unwrap().url, "http://e");
        assert_eq!(c.embed_batch, 32);
    }
}
