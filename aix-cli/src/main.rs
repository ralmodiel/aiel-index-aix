//! `aix`: project knowledge index for Claude Code on big repos (CLI + stdio MCP server).

mod hookans;
mod hooklog;
mod hooks;
mod hooksh;
mod init;
mod mask_cmd;
mod preanswer;
mod refresh;
mod sets_cmd;
mod watch;
#[cfg(feature = "mcp")]
mod mcp;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use aix_core::{find_repo, semantic, summaries, Index, Opts};

#[derive(Parser)]
#[command(name = "aix", about = "Project knowledge index for Claude Code on big repos", long_about = None)]
struct Cli {
    /// Repo root (default: the git toplevel of the current directory)
    #[arg(long, global = true)]
    repo: Option<PathBuf>,
    /// Index file (default: <repo>/.aix/index.db)
    #[arg(long, global = true, env = "AIX_DB")]
    db: Option<PathBuf>,
    /// Max hits per section
    #[arg(long, global = true, default_value_t = 20)]
    limit: usize,
    /// JSON output ({lines, hits} or the aix/v1 envelope): compact, no empty or null fields
    #[arg(long, global = true)]
    json: bool,
    /// with --json: indented, every field (for humans)
    #[arg(long, global = true)]
    pretty: bool,
    /// one JSON answer per line and a final {"summary":{n,truncated,excluded}} line (streaming tools)
    #[arg(long, global = true)]
    jsonl: bool,
    /// Skip the staleness check before a query
    #[arg(long, global = true)]
    no_refresh: bool,
    /// Machine rows only (path:line:text, path, path:N, N<TAB>key); a cut answer ends with one `…` line
    #[arg(long, global = true)]
    bare: bool,
    /// Only `path:line` per hit (implies --bare): where, when the location is all you need
    #[arg(long, global = true)]
    locs: bool,
    /// At most N rows, with one footer naming the exact next command
    #[arg(long, global = true)]
    head: Option<usize>,
    /// Clip each text column to N characters (0 = no clip; --bare defaults to 200)
    #[arg(long, global = true)]
    width: Option<usize>,
    /// Token budget for the whole answer (4 bytes a token): whole rows only, a footer names the rest (0 = off)
    #[arg(long, global = true)]
    max_tokens: Option<usize>,
    /// The index generation a continuation footer printed (`--page N --gen G`): a later page says when it changed
    #[arg(long, global = true, hide = true)]
    gen: Option<String>,
    /// Build even though `aix ignore-check` has findings, and record that the user accepted them (.aix/config)
    #[arg(long, global = true)]
    accept_ignore: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Index or refresh (incremental unless --full); optionally embed and summarise under deadlines
    Update {
        #[arg(long)]
        full: bool,
        /// Seconds of embedding work after the update (default 0 = none; `aix embed` fills them)
        #[arg(long)]
        embed_deadline: Option<f64>,
        /// Also write one-line local-LLM summaries (files, features, bug clusters)
        #[arg(long)]
        summaries: bool,
        #[arg(long, default_value_t = 60.0)]
        summaries_deadline: f64,
        #[arg(long)]
        quiet: bool,
        /// Memory budget (e.g. 2G, 800M; env AIX_MAX_MEMORY): caps workers and SQLite's cache, and resolves the code
        /// graph in batches when the whole graph would not fit. Default: half of the available memory
        #[arg(long)]
        max_memory: Option<String>,
        /// Progress lines on stderr while a long update runs (env AIX_PROGRESS=1)
        #[arg(long)]
        progress: bool,
    },
    /// Embed pending entries (resumable) until the deadline
    Embed {
        #[arg(long, default_value_t = 120.0)]
        deadline: f64,
    },
    /// Local-LLM one-line summaries (resumable; labelled summary_source=local-llm)
    Summarize {
        #[arg(long, default_value_t = 120.0)]
        deadline: f64,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Serve the index over stdio MCP
    Mcp,
    /// 10-line project card (SessionStart hook)
    Card,
    /// Hook helpers: `pretool` reads a PreToolUse event on stdin (nudge, or deny with the exact answer);
    /// `classify [FILE] [--summary]` labels every tool call of a transcript with the same rules (aix|miss|silent|other)
    Hook {
        event: String,
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Set aix up for this repo in one command: Claude Code hooks, allow rules, skill, git hook, index, watcher
    /// (scripts/aix-init.sh in Rust; --uninstall takes back what it added)
    Init {
        /// The repo root (default: the current directory)
        #[arg(value_name = "REPO")]
        dir: Option<PathBuf>,
        /// Write .claude/settings.json (shared with the team) instead of settings.local.json (yours only)
        #[arg(long)]
        shared: bool,
        /// Also register the MCP server in .mcp.json
        #[arg(long)]
        mcp: bool,
        #[arg(long)]
        no_git_hook: bool,
        #[arg(long)]
        no_watch: bool,
        /// Let Claude store and delete data sets without asking (put, sets rm)
        #[arg(long, conflicts_with = "no_allow_data")]
        allow_data: bool,
        #[arg(long)]
        no_allow_data: bool,
        /// Same as --accept-ignore: index as is despite .gitignore findings
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        uninstall: bool,
    },
    /// Locked, logged, low-priority index update for hooks, the watcher and cron (scripts/aix-refresh.sh in Rust)
    Refresh {
        #[arg(value_name = "REPO")]
        dir: Option<PathBuf>,
        /// Re-extract every file
        #[arg(long)]
        full: bool,
        /// Then embed pending entries for up to SECS seconds
        #[arg(long, value_name = "SECS", default_value_t = 0.0)]
        embed: f64,
        /// Then write local-LLM summaries for up to SECS seconds
        #[arg(long, value_name = "SECS", default_value_t = 0.0)]
        summaries: f64,
        /// Embed in 300 s chunks until nothing is pending
        #[arg(long)]
        backfill: bool,
        /// Wait this long for another refresh's update to finish, then skip
        #[arg(long, value_name = "SECS", default_value_t = 120.0)]
        wait: f64,
        /// Exit non-zero on failure (default: always 0, so hooks never fail a commit or a session)
        #[arg(long)]
        strict: bool,
    },
    /// Auto-refresh: refresh the index once edits go quiet (scripts/aix-watch.sh in Rust; one watcher per index)
    Watch {
        #[arg(value_name = "REPO")]
        dir: Option<PathBuf>,
        /// Fixed quiet time in seconds (default: adaptive)
        #[arg(long, value_name = "SECS")]
        idle: Option<f64>,
        /// Seconds between polls while nothing is pending (default 2; 5 on slow storage)
        #[arg(long, value_name = "SECS")]
        poll: Option<f64>,
        /// Exit after this many seconds without a change (0 = never)
        #[arg(long, value_name = "SECS", default_value_t = 14400.0)]
        exit_after: f64,
        /// Seconds of embedding per refresh
        #[arg(long, value_name = "SECS", default_value_t = 30.0)]
        embed: f64,
        /// While idle, check the embedding backlog every SECS seconds (0 = never)
        #[arg(long, value_name = "SECS", default_value_t = 60.0)]
        backlog: f64,
        #[arg(long, default_value = "auto", value_parser = ["auto", "fast", "slow"])]
        storage: String,
        /// Print the detected storage class and why, then exit
        #[arg(long)]
        storage_check: bool,
        /// Refresh if anything changed since the last refresh, then exit (for cron)
        #[arg(long)]
        once: bool,
        /// Stop this repo's watcher and exit
        #[arg(long)]
        stop: bool,
    },
    /// Install a post-commit git hook (chains any existing hook) that runs `aix update`
    InstallGitHook {
        /// Install into --repo even when it is not the repository of the current directory
        #[arg(long)]
        force: bool,
    },
    /// Everything before editing a route, page or file
    ///
    /// Compact by default (about 40 lines); `--full` gives every call, lead and commit
    Brief {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// What the current diff touches (routes, e2e, scripts, quoted UI strings)
    Impact {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Who calls a symbol (code graph)
    Callers {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// What a symbol calls (code graph)
    Callees {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Cross-layer trace: screen -> client fn -> endpoint -> handler -> service -> table (or --up)
    Trace {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// A feature end to end: resolved route, trace, related docs, findings and e2e scenarios
    Explain {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Members of a file with line ranges and facts: outline <file> [words]
    Outline {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Smallest re-check for a change: routes x roles to UI-audit and the e2e scenarios to run. `scope [rev|A..B]`
    /// is the working tree against rev (commits since + uncommitted); `scope --commit <sha>` is exactly that commit
    Scope {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Past findings and fix commits for a route, file or topic
    Bugs {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// How to test a route or topic
    Qa {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Feature catalogue lookup (or a role's menu)
    Feature {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Where a UI string lives and which tests quote it
    Text {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Registered logs: `logs add|list|suggest|rm|prune|errors|grep|show|tail|watch ...` (redacted, templated, linked to code)
    Logs {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Pasted blocks and prompt-named files: `paste list|show|grep|errors|frames|add|rm|suggest ...`
    Paste {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Alias of `paste` for attached files (ids default to file:N)
    File {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Block until the index, a log, a paste or an attached file is indexed (exit 0 ready, 2 timeout, 1 failed)
    Wait {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Scan what aix holds for privacy incidents; `--fix` purges/chmods/unwatches, exit 1 while a HIGH one remains
    PrivacyCheck {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Read-only .gitignore preflight (exit 0 clean, 1 findings, 2 error); --suggest prints lines to append
    IgnoreCheck {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Snapshot files outside the index (redacted) as file:<id>
    Attach {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Backend endpoint with roles, client wrapper and callers
    Endpoint {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Symbol definitions and uses
    Symbol {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Existing scripts for a task
    Script {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Checklist items: [open|done|all] [decision|found|blocker] [file.md] [words]
    Tasks {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Commits touching a file and findings naming it
    History {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Keyword search (bm25)
    Find {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        kind: Option<String>,
    },
    /// Hybrid search (bm25 + embeddings)
    Ask {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
        /// features|bugs|code|docs|qa
        #[arg(long)]
        kind: Option<String>,
        /// Add a short cited answer from the local chat model
        #[arg(long)]
        answer: bool,
    },
    /// Route card
    Route {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Bug-pattern leads: role gaps, client calls with no backend, fix hot spots (route, label or all)
    Hints {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Database table columns from the JPA entity, plus SQL touching it
    Table {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Source of one function/method/class (symbol, Class.method, file:line or file:A-B), numbered
    ///
    /// Capped at 60 lines (`--max N` changes the cap, `--full` lifts it); the last line names the next ranges
    Code {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Whole files (a big one: first part, outline, continuation): cat [-n] FILE[:A-B]...|- [--raw|--bare]
    Cat {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// First lines of files, GNU semantics: head [-n N|-N|-n -K] FILE...|- [--raw|--bare]
    Head {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Last lines of files, GNU semantics: tail [-n N|-N|-n +K] FILE...|- [--raw|--bare]
    Tail {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// sed print forms (-n 'A,Bp' | 'Np' | '/re/,/re2/p' ...); s/// and /re/d print a diff preview, never written
    Sed {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Bounded, redacted diff: diff A B | diff FILE (vs HEAD) | diff REV[..REV] [-- PATH...] [--stat|--name-only]
    Diff {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Read-before-edit check: how often the exact text occurs in a file: anchor FILE 'text'...
    Anchor {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Named materialized regex patterns: patterns [list | check <regex> | add <name> <regex> | rm|pin|unpin <name>]
    Patterns { args: Vec<String> },
    /// Which command answers a task: howto <what you want to do>
    Howto { args: Vec<String> },
    /// Regex search over indexed files: grep <regex> [-i] [-w] [-F] [-x] [-e <regex>]... [-l] [-c] [-A|-B|-C <n>] [-g <glob>]... [-t <lang>] [--in <path part>] [--scripts] [--and RE] [--not RE] [--body|--member] [<path>|@set]
    Grep {
        /// The regex (quote it) and grep/rg-style flags: -i -w -F -x -e -l -c -A/-B/-C N -g/--glob GLOB (repeatable, !negates)
        /// -t/--type LANG, and a trailing path; use `--` before a regex that starts with '-'. GNU: -v -o -m N -L -q -h
        /// --include/--exclude=GLOB --exclude-dir. aix's own: --and RE (the same line must also match RE; repeatable),
        /// --not RE (the line must not match RE), --not-in PART (skip paths containing PART), --body / --member (each
        /// hit's enclosing method or class once), --count-by match|file|dir[:N]|ext, --total, --bare, --width N.
        /// On data sets (@name): -f @set (patterns are the set's lines; with -F -x: rows equal to one of them, -v the
        /// rest: a set difference)
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
        /// Only files whose path contains this
        #[arg(long = "in")]
        within: Option<String>,
        /// Only the repo's scripts
        #[arg(long)]
        scripts: bool,
    },
    /// Read-only SQL: sql "SELECT ..." [--bare] [--head N] [--offset N]
    ///
    /// Caps: at most 500 rows and 64 KB per answer (a larger --limit is clamped; page with --offset), and each
    /// value is clipped to 200 characters even with --width 0 (select substr(col, 201) for the rest).
    Sql {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Index schema
    Schema,
    /// The indexed files, as ls / find / wc -l / test -f: files [GLOB|DIR|RE] [--lines] [--count] [--group-by dir|ext] [--changed [REV]] [-name G -type f|d -maxdepth N ...]
    Files {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// One level of the indexed tree, like ls (same flags as files)
    Ls {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Count rows read from `-` (wc -l), or group them: count by file|dir[:N]|ext|kind|match|field N|line
    Count {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Remove repeated rows read from `-` (order kept, first wins): dedup [line|text|file|member|dir[:N]|field N|NAME|match] [-c] [--sort count] [--norm]
    Dedup {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Bounded, redacted view of text on stdin: filter [-i] [--grep RE] [--not RE] [--head N] [--tail N] [--between A B] -; records of a data set: filter --where 'FIELD=V' (also != > >= < <=) @set
    Filter {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// In-call pipe or sequence: pipe 'grep X | count by dir', pipe 'brief /x ; callers Y' (also: aix 'grep X | head 5').
    /// Row stages: count [by file|dir[:N]|ext|kind|match|field N|NAME|level|template|item], filter [-i] [--grep RE] [-v RE]
    /// (filter --where F=V @set as the first stage), dedup [KEY] [-c], sort [-r -n -u -f -t C -k N[,M]], uniq [-c], head|tail [-n N], cut -d C -f LIST,
    /// wc -l, grep [-v -c -o -i -w -F] RE, sed -n A,Bp, put NAME (last stage). File/symbol stages, once per row: code,
    /// outline, brief, history, bugs, qa, callers, callees, impact, trace, symbol, explain, grep RE -. --json/--jsonl
    /// go before the quotes (aix --jsonl 'a ; b': one answer per command); a trailing 2>&1 is ignored
    Pipe {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Several commands in one call, one argument each: batch 'brief /x' 'callers Y'
    Batch {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Table sizes; --savings for the savings meter
    Stats {
        #[arg(long)]
        savings: bool,
        /// with --savings: the % of your weekly allocation used so far this week (e.g. 28%), to show what the week would have cost without aix
        #[arg(long, requires = "savings", value_name = "PCT")]
        currentweek: Option<String>,
        /// PreToolUse hook decisions by intent (nudged / answered / silent / aix) from .aix/hook-events.jsonl
        #[arg(long)]
        hooks: bool,
        /// with --hooks: only events since YYYY-MM-DD or 30m / 12h / 7d
        #[arg(long)]
        since: Option<String>,
    },
    /// stdin -> redacted stdout; stderr names every rule that changed each line and the allow-list hash that keeps a
    /// false positive readable (`--hash STRING` prints the entry for one string)
    RedactTest {
        #[arg(long)]
        hash: Option<String>,
    },
    /// Keep a value or pattern out of everything aix shows or stores: `mask add '<regex>' [--hint label] [--name N]
    /// [--scope repo|global]`, `mask add --literal '<text>' [--icase]` (6+ chars, slow hash only), `mask list`,
    /// `mask rm <name> [--purge]`, `mask test ['<text>']`
    Mask {
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<String>,
    },
}

/// `ask "<question>" --kind code`: the free-text argument takes hyphen values, so flags written after the question
/// land in it; pull `--kind X`, `--kind=X` and `--answer` back out.
fn trailing_flags(args: Vec<String>, mut kind: Option<String>, mut answer: bool) -> (Vec<String>, Option<String>, bool) {
    let mut out = vec![];
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--kind" {
            match it.next() {
                Some(v) => kind = Some(v),
                None => out.push(a),
            }
        } else if let Some(v) = a.strip_prefix("--kind=") {
            kind = Some(v.to_string());
        } else if a == "--answer" {
            answer = true;
        } else {
            out.push(a);
        }
    }
    (out, kind, answer)
}

fn main() {
    // before any SQLite connection: a damaged index must fail the command, never shrink its answer
    aix_core::index::watch_db_damage();
    // `aix ... | head` must end quietly, never with a "Broken pipe" panic and never killed by SIGPIPE (a status of 141
    // under `set -o pipefail`): SIGPIPE stays ignored (the Rust default), the answer is written with errors ignored,
    // and any other print that hits a closed pipe ends the process with the status it already had.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.payload().downcast_ref::<String>().map(String::as_str).or_else(|| info.payload().downcast_ref::<&str>().copied()).unwrap_or("");
        if msg.contains("failed printing to std") || msg.contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    if let Err(e) = real_main() {
        // an error can echo a bad argument or a path that holds a secret
        use std::io::Write;
        let mut m = format!("aix: {e:#}");
        if cfg!(windows) && m.contains("unable to open database file") {
            m.push_str(" (Windows: an index path over 260 characters, its -journal and -wal names included, opens only where long paths are enabled (LongPathsEnabled=1); else keep the index on a short path: --db C:\\aix\\<name>.db)");
        }
        let _ = writeln!(std::io::stderr(), "{}", aix_extract::redact::redact_line(&m));
        std::process::exit(2);
    }
}

/// Write to stdout, ignoring a closed pipe (`aix ... | head`).
fn out_line(s: &str) {
    use std::io::Write;
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(s.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}

/// `aix 0.1.0 (git <sha>, revision <extractor revision>)`: tells an old installed binary from a new one.
fn version_line() -> String {
    format!("{} (git {}, revision {})", env!("CARGO_PKG_VERSION"), env!("AIX_GIT_SHA"), aix_extract::REVISION)
}

/// Where `scripts/install.sh` recorded the clone it installed from (one line: its path).
fn source_clone() -> Option<String> {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| aix_core::sys::home().map(|h| h.join(".local/share")))?;
    let p = std::fs::read_to_string(base.join("aix/src-path")).ok()?;
    let p = p.trim();
    (!p.is_empty()).then(|| p.to_string())
}

/// On an unknown flag or command: say whether this binary is older than the clone it was installed from (a cheap
/// `git rev-parse`, then `git diff --quiet` over the crates: a docs-only commit does not make it older), else just
/// which build this is.
fn stale_hint() -> String {
    let built = env!("AIX_GIT_SHA");
    let sha = built.trim_end_matches("-dirty");
    if let Some(src) = source_clone() {
        let git = |args: &[&str]| std::process::Command::new("git").arg("-C").arg(&src).args(args).output().ok();
        let head = git(&["rev-parse", "--short", "HEAD"]).filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        if let Some(h) = head.filter(|h| !h.is_empty() && built != "unknown" && !h.starts_with(sha) && !sha.starts_with(h.as_str())) {
            // exit 0: nothing that goes into the binary changed since it was built (a sha the clone lacks: 128, newer)
            let code = git(&["diff", "--quiet", sha, "HEAD", "--", "aix-cli", "aix-core", "aix-extract", "Cargo.toml", "Cargo.lock"]);
            if code.is_none_or(|o| o.status.code() != Some(0)) {
                // Windows: install.sh is bash; the hooks and PATH use the binary cargo installs (--force: an aix.exe
                // copied there by hand is not cargo's, and cargo refuses to overwrite it)
                let how = if cfg!(windows) { format!("cargo install --locked --force --path {src}/aix-cli") } else { format!("{src}/scripts/install.sh") };
                return format!("note: this aix is built from {built}, but {src} is at {h}: the flag may be newer than the installed binary; re-run {how}");
            }
        }
    }
    format!("note: this is aix {}", version_line())
}

/// The flags every query command accepts (typed after the arguments; the clap `[ARGS]...` hides them).
const QUERY_FLAGS_HELP: &str = "Flags typed with the arguments (say what you do NOT need):
  --exclude KINDS|GLOBS   pre-filter (docs,tests,scripts,generated,fixtures,migrations,vendor,data or globs); -x is the short form
  --only KINDS|GLOBS      positive counterpart of --exclude
  --hide KINDS|GLOBS      post-filter after ranking (the answer keeps a one-line tally)
  --skip SECTIONS         leave sections out; --fields SECTIONS keeps only these; --order SECTIONS sets their order
  --conf exact,resolved   call-graph confidences to keep (drops name-only rows)
  --plan | --count        broad question? only the breakdown and ready-to-run narrowed commands
  --exists                one line: yes (first file:line) or no (exit status 1)
  --group-by KEY [--having count>N]   one row per group instead of rows
  --page N [--per-page N] | --offset K   stable paging of the full answer
  --sort relevance,path,recency,conf,fanin,size   row order
  --no-default-excludes   ignore the repo's default excludes
  --full | --max N        code/brief size cap";

const LOGS_FLAGS_HELP: &str = "Flags: --level L / --since T / --until T / --before T / --last N, --name N (a registered log or paste:N), --template ID, --context N, -n N, --lines A-B,
  --exclude / --only / --exists / --count / --group-by / --page, --format F, --follow (-f), --allow-dotfile (home dot-folders), --dry-run, --keep-ips, --expires D.
  Blocking: `logs await` / `aix wait` stop on --idle S, --until-match RE, --for S, --unqueried, --max-lines N, --stop-mb N, --timeout S.
  Subcommands that change what is indexed (add rm prune watch unwatch mark alert) run in a terminal only; the MCP tool is read-only.";

fn with_flag_help(cmd: clap::Command) -> clap::Command {
    let mut cmd = cmd;
    for n in [
        "brief", "impact", "callers", "callees", "trace", "explain", "outline", "scope", "bugs", "qa", "feature", "text", "endpoint", "symbol", "script", "tasks", "history", "find", "ask",
        "route", "hints", "table", "code", "grep", "cat", "head", "tail", "sed", "diff", "anchor",
    ] {
        cmd = cmd.mut_subcommand(n, |s| s.after_long_help(QUERY_FLAGS_HELP));
    }
    for n in ["logs", "paste", "file", "attach", "wait"] {
        cmd = cmd.mut_subcommand(n, |s| s.after_long_help(LOGS_FLAGS_HELP));
    }
    // grep: `-h` is GNU's --no-filename (also after the global --bare/--width, which clap reads first); help is --help
    cmd = cmd.mut_subcommand("grep", |s| s.disable_help_flag(true).arg(clap::Arg::new("help").long("help").action(clap::ArgAction::Help).help("Print help")));
    cmd
}

fn parse_cli() -> Cli {
    let version: &'static str = Box::leak(version_line().into_boxed_str());
    // `aix`, not argv[0]'s `aix.exe` (Windows), in usage lines and errors
    let cmd = with_flag_help(Cli::command().version(version).bin_name("aix"));
    match cmd.try_get_matches_from(pipe_argv(aix_core::sys::args())) {
        Ok(m) => Cli::from_arg_matches(&m).unwrap_or_else(|e| e.exit()),
        Err(e) => {
            use clap::error::ErrorKind;
            let unknown = matches!(e.kind(), ErrorKind::UnknownArgument | ErrorKind::InvalidSubcommand);
            if e.use_stderr() {
                // clap echoes the offending argument: it may be a secret
                use std::io::Write;
                let mut err = std::io::stderr();
                let _ = write!(err, "{}", aix_extract::redact::redact_block(&e.render().to_string()));
                // shell tools that are not subcommands: the aix line that answers them
                let first = match e.get(clap::error::ContextKind::InvalidSubcommand) {
                    Some(clap::error::ContextValue::String(v)) => Some(v.clone()),
                    _ => None,
                };
                let tip = match first.as_deref() {
                    Some("wc") => Some("aix: `wc -l F` is `aix files F --lines` (or `aix 'grep X | wc -l'` as a pipe stage)"),
                    Some("find") => Some("aix: `find DIR -name GLOB` is `aix files DIR -name GLOB`"),
                    Some("rg") => Some("aix: `rg PATTERN` is `aix grep PATTERN`"),
                    Some("stat") => Some("aix: `stat F` is `aix files F --size --lines`"),
                    _ => None,
                };
                if let Some(t) = tip.filter(|_| unknown) {
                    let _ = writeln!(err, "{t}");
                } else if unknown {
                    let _ = writeln!(err, "{}", stale_hint());
                }
                std::process::exit(e.exit_code());
            }
            e.exit()
        }
    }
}

/// logs/paste/attach: exact argv, and the write subcommands (add, rm, prune, watch ...) are allowed because this is the CLI
/// (the MCP tool never sets AIX_LOGS_CLI).
fn write_cmd(name: &'static str, args: Vec<String>, mut o: Opts) -> (&'static str, Vec<String>, Opts) {
    std::env::set_var("AIX_LOGS_CLI", "1");
    o.argv = Some(args.clone());
    (name, args, o)
}

/// The read commands get their exact argv (a sed script or an anchor with spaces stays one argument).
fn read_cmd(name: &'static str, args: Vec<String>, mut o: Opts) -> (&'static str, Vec<String>, Opts) {
    o.argv = Some(args.clone());
    (name, args, o)
}

/// A command whose argv must not be re-split (pipes, find patterns).
fn exact(name: &'static str, args: Vec<String>, mut o: Opts) -> (&'static str, Vec<String>, Opts) {
    o.argv = Some(args.clone());
    (name, args, o)
}

/// `aix 'grep X | count by dir'` / `aix 'brief /x ; code a.rs:1-9'`: a first word holding a space (not a
/// subcommand) is a pipe.
fn pipe_argv(mut argv: Vec<String>) -> Vec<String> {
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if matches!(a, "--repo" | "--db" | "--limit" | "--head" | "--width") {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if a.contains(char::is_whitespace) || a.starts_with('@') {
            argv.insert(i, "pipe".to_string());
        } else if aix_core::opts::QUERY_CMDS.contains(&a) {
            // `aix text -- -w`: the `--` reaches the query command (clap would drop it), which reads the words
            // after it as query words
            if let Some(k) = argv[i + 1..].iter().position(|x| x == "--") {
                argv.insert(i + 1 + k, "--".to_string());
            }
        }
        break;
    }
    argv
}

/// The query commands' argument list, if `cmd` has one.
fn query_args(cmd: &mut Cmd) -> Option<&mut Vec<String>> {
    match cmd {
        Cmd::Brief { args } | Cmd::Impact { args } | Cmd::Callers { args } | Cmd::Callees { args } | Cmd::Trace { args } | Cmd::Explain { args } | Cmd::Outline { args }
        | Cmd::Scope { args } | Cmd::Bugs { args } | Cmd::Qa { args } | Cmd::Feature { args } | Cmd::Text { args } | Cmd::Endpoint { args } | Cmd::Symbol { args }
        | Cmd::Script { args } | Cmd::Tasks { args } | Cmd::History { args } | Cmd::Find { args, .. } | Cmd::Ask { args, .. } | Cmd::Route { args } | Cmd::Hints { args }
        | Cmd::Table { args } | Cmd::Code { args } | Cmd::Grep { args, .. } | Cmd::Files { args } | Cmd::Ls { args } | Cmd::Count { args } | Cmd::Dedup { args } | Cmd::Filter { args }
        | Cmd::Pipe { args } | Cmd::Batch { args } | Cmd::Cat { args } | Cmd::Head { args } | Cmd::Tail { args } | Cmd::Sed { args } | Cmd::Diff { args }
        | Cmd::Anchor { args } => Some(args),
        _ => None,
    }
}

fn real_main() -> Result<()> {
    // data sets: `aix put`, `aix sets`, and any command naming an existing @set (sets_cmd.rs)
    if let Some(code) = sets_cmd::intercept() {
        std::process::exit(code);
    }
    let mut cli = parse_cli();
    aix_extract::warm::prewarm();
    // clap swallows the first `--`; grep needs it ("a regex starting with '-' goes after --")
    if let Cmd::Grep { args, .. } = &mut cli.cmd {
        let raw: Vec<String> = std::env::args().skip(1).collect();
        if let Some(g) = raw.iter().position(|a| a == "grep") {
            if let Some(k) = raw[g + 1..].iter().position(|a| a == "--") {
                let after = raw.len() - (g + 1 + k) - 1;
                // clap keeps the `--` once a hyphen value came before it (`grep -n -- x`): never add a second one
                if after <= args.len() && !args.iter().any(|a| a == "--") {
                    let at = args.len() - after;
                    args.insert(at, "--".to_string());
                }
            }
        }
    }
    // ... and so do code/cat/sed/diff (`diff REV -- path`, `code -- -weird-name`)
    let read_name = match &cli.cmd {
        Cmd::Code { .. } => Some("code"),
        Cmd::Cat { .. } => Some("cat"),
        Cmd::Head { .. } => Some("head"),
        Cmd::Tail { .. } => Some("tail"),
        Cmd::Sed { .. } => Some("sed"),
        Cmd::Diff { .. } => Some("diff"),
        Cmd::Anchor { .. } => Some("anchor"),
        _ => None,
    };
    if let (Some(name), Some(args)) = (read_name, query_args(&mut cli.cmd)) {
        let raw: Vec<String> = std::env::args().skip(1).collect();
        if let Some(g) = raw.iter().position(|a| a == name) {
            if let Some(k) = raw[g + 1..].iter().position(|a| a == "--") {
                let after = raw.len() - (g + 1 + k) - 1;
                if after <= args.len() && !args.iter().any(|a| a == "--") {
                    let at = args.len() - after;
                    args.insert(at, "--".to_string());
                }
            }
        }
    }
    // the global output flags are accepted after the pattern too (`aix grep foo --json`); after a `--` they are text
    let mut moved = (false, false, false, false);
    let mut repo_arg: Option<PathBuf> = None;
    if let Some(args) = query_args(&mut cli.cmd) {
        let stop = args.iter().position(|a| a == "--").unwrap_or(args.len());
        let mut i = 0;
        while i < args.len().min(stop) {
            match args[i].as_str() {
                "--json" => moved.0 = true,
                "--jsonl" => moved.1 = true,
                "--pretty" => moved.2 = true,
                "--no-refresh" => moved.3 = true,
                "--repo" if i + 1 < args.len() => {
                    repo_arg = Some(PathBuf::from(args.remove(i + 1)));
                }
                a if a.starts_with("--repo=") => {
                    repo_arg = Some(PathBuf::from(&a["--repo=".len()..]));
                }
                _ => {
                    i += 1;
                    continue;
                }
            }
            args.remove(i);
        }
    }
    if repo_arg.is_some() {
        cli.repo = repo_arg;
    }
    cli.json |= moved.0;
    cli.jsonl |= moved.1;
    cli.pretty |= moved.2;
    cli.no_refresh |= moved.3;
    // Windows: `--repo /c/x` (Git Bash's spelling, typed in PowerShell) is C:/x, not \c\x on the current drive
    if let Some(r) = cli.repo.as_ref().map(|r| r.to_string_lossy().into_owned()).filter(|r| cfg!(windows) && matches!(r.as_bytes(), [b'/', d] | [b'/', d, b'/', ..] if d.is_ascii_alphabetic())) {
        cli.repo = Some(PathBuf::from(hooksh::os_path(&r)));
    }
    let cwd = std::env::current_dir()?;
    let repo = cli.repo.clone().unwrap_or_else(|| find_repo(&cwd));
    // paths typed relative to a subdirectory (`cd frontend/src; aix grep x pages`)
    if let (Ok(c), Ok(r)) = (aix_core::sys::canonicalize(&cwd), aix_core::sys::canonicalize(&repo)) {
        if let Ok(rel) = c.strip_prefix(&r) {
            aix_core::opts::set_cwd_rel(&aix_core::sys::slash(rel));
        }
    }
    // the repo lifecycle (bash scripts on Unix, these everywhere): no index is opened here
    let dir = |d: &Option<PathBuf>| d.clone().or_else(|| cli.repo.clone());
    match &cli.cmd {
        Cmd::Init { dir: d, shared, mcp, no_git_hook, no_watch, allow_data, no_allow_data, yes, uninstall } => {
            let o = init::Opts {
                shared: *shared,
                mcp: *mcp,
                no_git_hook: *no_git_hook,
                no_watch: *no_watch,
                data: if *allow_data { Some(true) } else if *no_allow_data { Some(false) } else { None },
                accept: *yes || cli.accept_ignore,
                uninstall: *uninstall,
            };
            std::process::exit(init::run(dir(d).as_deref(), cli.db.as_deref(), &o));
        }
        Cmd::Refresh { dir: d, full, embed, summaries, backfill, wait, strict } => {
            let o = refresh::Opts { full: *full, embed: *embed, summaries: *summaries, backfill: *backfill, wait: *wait, strict: *strict, accept_ignore: cli.accept_ignore };
            std::process::exit(refresh::run(dir(d).as_deref(), cli.db.as_deref(), &o));
        }
        Cmd::Watch { dir: d, idle, poll, exit_after, embed, backlog, storage, storage_check, once, stop } => {
            let o = watch::Opts { idle: *idle, poll: *poll, exit_after: *exit_after, embed: *embed, backlog: *backlog, storage: storage.clone(), storage_check: *storage_check, once: *once, stop: *stop };
            std::process::exit(watch::run(dir(d).as_deref(), cli.db.as_deref(), &o));
        }
        _ => {}
    }
    // hooks must never fail loudly or slow a session down
    if let Cmd::Hook { event, args } = &cli.cmd {
        let code = hooks::hook(&repo, cli.db.as_deref(), event, args);
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    if let Cmd::Stats { hooks: true, since, .. } = &cli.cmd {
        let db = aix_core::index::resolve_db(&repo, cli.db.as_deref());
        out_line(&hooklog::stats(&db, since.as_deref()));
        return Ok(());
    }
    if let Cmd::Mask { args } = &cli.cmd {
        return mask_cmd::run(&repo, cli.db.as_deref(), args);
    }
    if let Cmd::RedactTest { hash } = &cli.cmd {
        let _ = aix_core::config::Config::load(&repo, &repo.join(".aix")); // installs the repo's [redact] settings
        return Ok(aix_extract::redact::redact_test(hash.as_deref())?);
    }
    if let Cmd::InstallGitHook { force } = &cli.cmd {
        return hooks::install_git_hook(&repo, cli.db.as_deref(), *force);
    }
    if matches!(&cli.cmd, Cmd::Paste { args } if args.first().is_some_and(|a| a == "ingest-stdin")) {
        aix_core::logq::prefetch_stdin();
    }
    if let Cmd::IgnoreCheck { args } = &cli.cmd {
        // before Index::open: a read-only check never creates .aix
        std::process::exit(aix_core::ignorecheck::cli(&repo, cli.db.as_deref(), args, cli.json));
    }
    let builds = |unbuilt: bool| match &cli.cmd {
        Cmd::Update { full, .. } => *full || unbuilt,
        Cmd::Card | Cmd::Mcp | Cmd::Sql { .. } | Cmd::Schema => false,
        _ => unbuilt && !cli.no_refresh,
    };
    // no index yet: the gate runs before Index::open, so a refused first build leaves no database (or WAL) behind
    let r = aix_core::sys::canonicalize(&repo).unwrap_or_else(|_| repo.clone());
    let db_path = cli.db.as_deref().map(Path::to_path_buf).unwrap_or_else(|| aix_core::index::default_db(&r));
    if !db_path.exists() && builds(true) && !cli.accept_ignore {
        if let Err(stop) = aix_core::ignorecheck::gate(&r, &db_path, false) {
            out_line(&aix_extract::redact::redact_block(&stop));
            std::process::exit(2);
        }
        // a clone or worktree of an indexed checkout starts from the parent's index: the update below then re-reads
        // only what differs (seconds, not a full build)
        if let Some(s) = aix_core::index::seed(&r, &db_path) {
            eprintln!(
                "aix: first index of this checkout copied from {} ({} ms); refreshing what differs",
                aix_core::logs::display_path(&s.parent.to_string_lossy()),
                s.ms
            );
        }
    }
    let mut ix = Index::open(&repo, cli.db.as_deref())?;
    // the first build (and a full rebuild) waits for the user's .gitignore decision: exit 2 with the STOP block
    let unbuilt = ix.meta("built").is_none();
    let building = builds(unbuilt);
    if building || cli.accept_ignore {
        if let Err(stop) = aix_core::ignorecheck::gate(&ix.repo, &ix.db_path, cli.accept_ignore) {
            out_line(&aix_extract::redact::redact_block(&stop));
            std::process::exit(2);
        }
    }
    let limit = cli.limit;
    let no_refresh = cli.no_refresh;
    let opts = |kind: Option<String>, answer: bool, savings: bool| Opts { limit, kind, answer, savings, current_week_pct: None, no_refresh, argv: None, x: Default::default() };
    let (cmd, args, o): (&str, Vec<String>, Opts) = match cli.cmd {
        Cmd::Update { full, embed_deadline, summaries: sums, summaries_deadline, quiet, max_memory, progress } => {
            if let Some(m) = max_memory {
                if aix_core::par::parse_mb(&m).is_none() {
                    anyhow::bail!("--max-memory {m}: give MB or a size like 800M / 2G");
                }
                // SAFETY: set before the update starts any thread that reads the environment
                unsafe { std::env::set_var("AIX_MAX_MEMORY", &m) };
            }
            if progress {
                // SAFETY: as above
                unsafe { std::env::set_var("AIX_PROGRESS", "1") };
            }
            let s = ix.update(full)?;
            if !quiet {
                if s.is_noop() && !full {
                    println!("index is current (the watcher/hook keeps it fresh) — no update needed");
                } else {
                    println!("{}", s.line());
                }
            }
            // a manual update never blocks on embedding unless asked (`--embed-deadline SECS`, or `aix embed`)
            let dl = embed_deadline.unwrap_or(0.0);
            if dl > 0.0 && ix.cfg.embed.is_some() {
                let r = semantic::embed_pending(&ix, Duration::from_secs_f64(dl))?;
                if !quiet || r.error.is_some() {
                    println!(
                        "embeddings: {} new, {} pending{}",
                        r.embedded,
                        r.pending,
                        r.error.map(|e| format!(" ({e}; keyword search still works)")).unwrap_or_default()
                    );
                }
            }
            if sums {
                let r = summaries::summarize(&ix, Duration::from_secs_f64(summaries_deadline), 500)?;
                println!(
                    "summaries (local-llm): {} files, {} features, {} bug clusters, {} files pending{}",
                    r.files,
                    r.features,
                    r.bug_clusters,
                    r.pending_files,
                    r.note.map(|n| format!(" ({n})")).unwrap_or_default()
                );
            }
            return Ok(());
        }
        Cmd::Embed { deadline } => {
            ix.update(false)?;
            let r = semantic::embed_pending(&ix, Duration::from_secs_f64(deadline))?;
            println!(
                "embeddings: {} new, {} pending{}",
                r.embedded,
                r.pending,
                r.error.map(|e| format!(" ({e})")).unwrap_or_default()
            );
            return Ok(());
        }
        Cmd::Summarize { deadline, max } => {
            ix.update(false)?;
            let r = summaries::summarize(&ix, Duration::from_secs_f64(deadline), max)?;
            println!(
                "summaries (local-llm): {} files, {} features, {} bug clusters, {} failed, {} files pending{}",
                r.files,
                r.features,
                r.bug_clusters,
                r.failed,
                r.pending_files,
                r.note.map(|n| format!(" ({n})")).unwrap_or_default()
            );
            return Ok(());
        }
        #[cfg(feature = "mcp")]
        Cmd::Mcp => {
            let _ = ix.update(false);
            return mcp::serve(ix);
        }
        #[cfg(not(feature = "mcp"))]
        Cmd::Mcp => anyhow::bail!("this aix was built without the `mcp` feature (cargo install --path aix-cli --features mcp)"),
        Cmd::Card => {
            let text = aix_extract::redact::redact_block(&hooks::card(&mut ix));
            if cli.json || cli.jsonl {
                let lines: Vec<&str> = text.lines().collect();
                let v = serde_json::json!({"cmd": "card", "card": text, "lines": lines});
                println!("{}", if cli.pretty { serde_json::to_string_pretty(&v)? } else { v.to_string() });
            } else {
                println!("{text}");
            }
            return Ok(());
        }
        Cmd::Hook { .. } | Cmd::InstallGitHook { .. } | Cmd::RedactTest { .. } | Cmd::Mask { .. } | Cmd::IgnoreCheck { .. } | Cmd::Init { .. } | Cmd::Refresh { .. } | Cmd::Watch { .. } => {
            unreachable!()
        }
        Cmd::Brief { args } => ("brief", args, opts(None, false, false)),
        Cmd::Impact { args } => ("impact", args, opts(None, false, false)),
        Cmd::Callers { args } => ("callers", args, opts(None, false, false)),
        Cmd::Callees { args } => ("callees", args, opts(None, false, false)),
        Cmd::Outline { args } => ("outline", args, opts(None, false, false)),
        Cmd::Trace { args } => ("trace", args, opts(None, false, false)),
        Cmd::Explain { args } => ("explain", args, opts(None, false, false)),
        Cmd::Scope { args } => ("scope", args, opts(None, false, false)),
        Cmd::Bugs { args } => ("bugs", args, opts(None, false, false)),
        Cmd::Qa { args } => ("qa", args, opts(None, false, false)),
        Cmd::Feature { args } => ("feature", args, opts(None, false, false)),
        Cmd::Text { args } => ("text", args, opts(None, false, false)),
        Cmd::Endpoint { args } => ("endpoint", args, opts(None, false, false)),
        Cmd::Symbol { args } => ("symbol", args, opts(None, false, false)),
        Cmd::Script { args } => ("script", args, opts(None, false, false)),
        Cmd::Tasks { args } => ("tasks", args, opts(None, false, false)),
        Cmd::History { args } => ("history", args, opts(None, false, false)),
        Cmd::Find { args, kind } => {
            let (args, kind, _) = trailing_flags(args, kind, false);
            ("find", args, opts(kind, false, false))
        }
        Cmd::Ask { args, kind, answer } => {
            let (args, kind, answer) = trailing_flags(args, kind, answer);
            ("ask", args, opts(kind, answer, false))
        }
        Cmd::Route { args } => ("route", args, opts(None, false, false)),
        Cmd::Hints { args } => ("hints", args, opts(None, false, false)),
        Cmd::Table { args } => ("table", args, opts(None, false, false)),
        Cmd::Code { args } => read_cmd("code", args, opts(None, false, false)),
        Cmd::Cat { args } => read_cmd("cat", args, opts(None, false, false)),
        Cmd::Head { args } => read_cmd("head", args, opts(None, false, false)),
        Cmd::Tail { args } => read_cmd("tail", args, opts(None, false, false)),
        Cmd::Sed { args } => read_cmd("sed", args, opts(None, false, false)),
        Cmd::Diff { args } => read_cmd("diff", args, opts(None, false, false)),
        Cmd::Anchor { args } => read_cmd("anchor", args, opts(None, false, false)),
        Cmd::Patterns { args } => ("patterns", args, opts(None, false, false)),
        Cmd::Howto { args } => ("howto", args, opts(None, false, false)),
        Cmd::Grep { mut args, within, scripts } => {
            if let Some(w) = within {
                args.extend(["--in".to_string(), w]);
            }
            if scripts {
                args.push("--scripts".into());
            }
            // the argv goes through untouched: a pattern with spaces, quotes or tabs stays byte-exact
            let mut o = opts(None, false, false);
            o.argv = Some(args.clone());
            ("grep", args, o)
        }
        Cmd::Logs { args } => write_cmd("logs", args, opts(None, false, false)),
        Cmd::Paste { args } => write_cmd("paste", args, opts(None, false, false)),
        Cmd::File { args } => write_cmd("file", args, opts(None, false, false)),
        Cmd::Attach { args } => write_cmd("attach", args, opts(None, false, false)),
        Cmd::Wait { args } => write_cmd("wait", args, opts(None, false, false)),
        Cmd::PrivacyCheck { args } => write_cmd("privacy-check", args, opts(None, false, false)),
        Cmd::Sql { args } => ("sql", args, opts(None, false, false)),
        Cmd::Schema => ("schema", vec![], opts(None, false, false)),
        Cmd::Stats { savings, currentweek, .. } => {
            let mut o = opts(None, false, savings);
            if let Some(c) = currentweek {
                match c.trim().trim_end_matches('%').trim().parse::<f64>() {
                    Ok(p) if (0.0..=100.0).contains(&p) => o.current_week_pct = Some(p),
                    _ => {
                        eprintln!("aix: --currentweek takes a percentage between 0 and 100, e.g. 28%");
                        std::process::exit(2);
                    }
                }
            }
            ("stats", vec![], o)
        }
        // exact argv: a pipe stage or a find pattern keeps its spaces and quotes
        Cmd::Files { args } => exact("files", args, opts(None, false, false)),
        Cmd::Ls { args } => exact("ls", args, opts(None, false, false)),
        Cmd::Count { args } => exact("count", args, opts(None, false, false)),
        Cmd::Dedup { args } => exact("dedup", args, opts(None, false, false)),
        Cmd::Filter { args } => exact("filter", args, opts(None, false, false)),
        Cmd::Pipe { args } => exact("pipe", args, opts(None, false, false)),
        Cmd::Batch { args } => exact("batch", args, opts(None, false, false)),
    };
    // --json/--jsonl/--pretty after the subcommand (`aix logs errors --json`) count like the global ones
    let (mut o, mut args) = (o, args);
    let (mut t_json, mut t_jsonl, mut t_pretty) = (false, false, false);
    if matches!(cmd, "logs" | "paste" | "file" | "attach" | "wait" | "privacy-check") {
        args.retain(|a| match a.as_str() {
            "--json" => !std::mem::replace(&mut t_json, true),
            "--jsonl" => !std::mem::replace(&mut t_jsonl, true),
            "--pretty" => !std::mem::replace(&mut t_pretty, true),
            _ => true,
        });
        if o.argv.is_some() {
            o.argv = Some(args.clone());
        }
    }
    // global output options travel with the arguments (the core reads them for every command, CLI and MCP alike)
    let mut front: Vec<String> = vec![];
    if cli.bare {
        front.push("--bare".into());
    }
    if cli.locs {
        front.push("--locs".into());
    }
    if let Some(n) = cli.head {
        front.extend(["--head".to_string(), n.to_string()]);
    }
    if let Some(n) = cli.width {
        front.extend(["--width".to_string(), n.to_string()]);
    }
    if let Some(n) = cli.max_tokens {
        front.extend(["--max-tokens".to_string(), n.to_string()]);
    }
    if let Some(g) = &cli.gen {
        front.extend(["--gen".to_string(), g.clone()]);
    }
    if !front.is_empty() {
        front.extend(args);
        args = front;
        if o.argv.is_some() {
            o.argv = Some(args.clone());
        }
    }
    // `-` reads the process stdin (the MCP server never does: its stdin is the protocol)
    aix_core::rows::allow_process_stdin();
    // a flag value with spaces (`-x 'my dir/**'`) keeps its quotes through the join
    let joined_arg = aix_core::cli_join(cmd, &args);
    if let Some(e) = aix_core::logq::query_arg_error(cmd, &joined_arg) {
        eprintln!("{e}");
        std::process::exit(2);
    }
    if cli.json || cli.jsonl || t_json || t_jsonl {
        aix_core::query::set_full_roles(true); // machine output: role lists whole
    }
    let out = aix_core::run(&mut ix, cmd, &joined_arg, &o)?;
    for n in &out.stderr {
        eprintln!("{}", aix_extract::redact::redact_line(n));
    }
    if cli.json || cli.jsonl || t_json || t_jsonl {
        out_line(&aix_core::render_json(&out, cli.pretty || t_pretty, cli.jsonl || t_jsonl));
    } else if !(out.lines.is_empty() && out.label.is_none() && out.exists.is_some()) {
        // `grep -q`: nothing at all, as GNU grep (the exit status is the answer); an empty answer (`aix sed -n '/x/p' F
        // --bare` that selects nothing) prints nothing, as the shell tool does
        let t = out.text();
        if !t.is_empty() {
            out_line(&t);
        }
        // bare rows of a data set: the data label goes to stderr (stdout stays the rows alone)
        if out.label.is_none() && !out.error && args.iter().any(|a| a == "--bare") && args.iter().any(|a| a.starts_with('@') && aix_core::setq::is_set_arg(&ix, a)) {
            eprintln!("{}", aix_core::sets::LABEL);
        }
    }
    if matches!(cmd, "logs" | "paste" | "file" | "attach" | "wait" | "privacy-check") {
        let code = aix_core::logq::exit_code();
        // a refusal (an unknown paste id, no logs registered) is "none", never success
        let code = if code == 0 && out.error { out.exit_code.unwrap_or(1) } else { code };
        if code != 0 {
            std::process::exit(code); // logs await / wait: 2 = timeout, 1 = failed
        }
        return Ok(());
    }
    // 0 found, 1 none / no match / path not found, 2 usage or error (a parse / regex / flag error is not "no match")
    let status = aix_core::opts::exit_status(cmd, &out);
    if status != 0 {
        std::process::exit(status);
    }
    Ok(())
}
