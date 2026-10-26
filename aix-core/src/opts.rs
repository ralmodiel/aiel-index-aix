//! Options in any position and paths in any spelling (FIX-6A).
//!
//! `aix callers main --limit 3`, `aix tasks open --limit 3`, `aix code main --count`: the documented flags are read
//! wherever they stand, never folded into the symbol; on the single-argument commands an unknown `--flag` is an error
//! naming the supported ones. Paths: `./x`, `x\y`, `x//y`, `x/`, a bare basename and paths relative to a
//! subdirectory working directory all mean the repo-relative indexed path.

use std::sync::Mutex;

use crate::index::Index;

/// Query commands that read `--limit N`, `--max N`, `--full` (and `--repo X` on the CLI) in any position.
pub const FLAG_CMDS: &[&str] = &[
    "brief", "callers", "callees", "trace", "explain", "outline", "bugs", "qa", "feature", "text", "endpoint", "symbol", "script", "tasks", "history", "find", "ask", "route", "hints",
    "table", "code", "grep",
];

/// Single-argument commands: an unknown `--flag` is a usage error (exit 2), never part of the symbol.
pub const STRICT: &[&str] = &["callers", "callees", "symbol", "route", "endpoint", "trace", "explain", "table", "hints", "tasks", "history", "outline", "brief", "code"];

/// Flags the exclusion / paging / output layers read later (see `excl::take_flags`) or that are no-ops here.
const PASSTHROUGH: &[&str] = &[
    "--exclude", "--only", "--hide", "--skip", "--fields", "--order", "--sort", "--conf", "--no-default-excludes", "--plan", "--exists", "--group-by", "--having", "--page", "--per-page", "--offset", "--json",
    "--jsonl", "--pretty", "--no-refresh", "--all", "--up", "--body", "--sites", "--depth",
];

pub const SUPPORTED: &str = "--limit N, --max N, --full, --count, --exists, --plan, --exclude/--only/--hide KINDS|GLOBS (-x), --skip/--fields/--order SECTIONS, --conf, --sort, --group-by KEY [--having COND], --page N [--per-page N], --offset K, --json, --jsonl, --pretty, --no-refresh, --no-default-excludes, --repo DIR (CLI)";

/// Free-text query commands: a word starting with `-` that no layer reads is an error (exit 2), never a query word;
/// `--` ends the options (the words after it are query words, the `--` itself is dropped).
pub const QUERY_CMDS: &[&str] = &["text", "ask", "find", "qa", "feature", "bugs", "script"];

const QUERY_FLAGS: &[&str] = &["--limit", "--max", "--full", "--count", "--kind", "--answer", "--exclude", "-x"];

/// `ask --kind`: the kinds it ranks by.
pub const ASK_KINDS: &[&str] = &["features", "bugs", "code", "docs", "qa"];

/// The argument of a free-text query command with its flags checked (see [`QUERY_CMDS`]).
pub fn query_flags(cmd: &str, arg: &str, kind: Option<&str>) -> Result<String, String> {
    if !QUERY_CMDS.contains(&cmd) {
        return Ok(arg.to_string());
    }
    if cmd == "ask" {
        if let Some(k) = kind.filter(|k| !ASK_KINDS.contains(k)) {
            return Err(format!("ask: unknown --kind {k} (kinds: {}; `code` ranks methods and other code)", ASK_KINDS.join(", ")));
        }
    }
    if cmd == "find" {
        if let Some(k) = kind.filter(|k| k.is_empty()) {
            return Err(format!("find: --kind needs a value ({k:?})"));
        }
    }
    let words: Vec<&str> = arg.split_whitespace().collect();
    let mut prev = "";
    let mut ended = false;
    let mut dd = None;
    for (i, w) in words.iter().enumerate() {
        if ended {
            break;
        }
        if *w == "--" {
            ended = true;
            dd = Some(i);
            continue;
        }
        let name = w.split_once('=').map_or(*w, |(n, _)| n);
        let value_of_prev = matches!(prev, "-x" | "--exclude" | "--only" | "--hide" | "--skip" | "--fields" | "--order" | "--sort" | "--conf" | "--having" | "--group-by" | "--limit" | "--max" | "--page" | "--per-page" | "--offset" | "--kind" | "--depth");
        let flaglike = (name.starts_with("--") && name.len() > 2) || (name.len() > 1 && name.starts_with('-') && name[1..].chars().all(|c| c.is_ascii_alphabetic()));
        if flaglike && !value_of_prev && !QUERY_FLAGS.contains(&name) && !PASSTHROUGH.contains(&name) {
            return Err(format!("{cmd}: unknown option {} (a query word starting with - goes after `--`: aix {cmd} -- {w}). Supported: {SUPPORTED}", name.chars().take(40).collect::<String>()));
        }
        prev = name;
    }
    Ok(match dd {
        Some(i) => words.iter().enumerate().filter(|(k, _)| *k != i).map(|(_, w)| *w).collect::<Vec<_>>().join(" "),
        None => arg.to_string(),
    })
}

/// What [`take_common`] pulled out of the argument string.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Common {
    pub arg: String,
    pub limit: Option<usize>,
    pub max: Option<usize>,
    pub full: bool,
    /// `--count` on a command whose exclusion layer does not read it (`code`)
    pub count: bool,
}

fn num(flag: &str, v: Option<&str>) -> Result<usize, String> {
    v.and_then(|v| v.trim().parse::<usize>().ok()).ok_or_else(|| format!("{flag} needs a non-negative number"))
}

/// Read `--limit N|--limit=N`, `--max N|--max=N`, `--full` and `--count` (code) out of a query's argument string
/// wherever they stand. `code` and `brief` keep `--max` / `--full` (their own size cap reads them later). On the
/// STRICT commands any other `--flag` is an error naming what is supported. The string is returned untouched when
/// nothing was taken (spacing preserved).
pub fn take_common(cmd: &str, arg: &str) -> Result<Common, String> {
    let mut c = Common { arg: arg.to_string(), ..Default::default() };
    // impact reads them too (`impact Class.method --limit 5`), but keeps its own exit statuses
    if !(FLAG_CMDS.contains(&cmd) || cmd == "impact") || !arg.contains("--") {
        return Ok(c);
    }
    let size_cmd = matches!(cmd, "code" | "brief");
    let strict = STRICT.contains(&cmd);
    let words: Vec<&str> = arg.split_whitespace().collect();
    let mut keep: Vec<&str> = vec![];
    let mut i = 0;
    let mut taken = false;
    while i < words.len() {
        let w = words[i];
        let (name, inline) = match w.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v)),
            _ => (w, None),
        };
        match name {
            "--limit" | "--max" if !(size_cmd && name == "--max") => {
                let (v, used) = match inline {
                    Some(v) => (Some(v), 1),
                    None => (words.get(i + 1).copied(), 2),
                };
                let n = num(name, v)?;
                c.limit = Some(n);
                taken = true;
                i += used;
            }
            "--max" => {
                // code / brief: the size cap (read by take_size_flags); only validated here
                if inline.is_none() {
                    num(name, words.get(i + 1).copied())?;
                    keep.push(w);
                    keep.push(words[i + 1]);
                    i += 2;
                } else {
                    num(name, inline)?;
                    keep.push(w);
                    i += 1;
                }
            }
            "--full" => {
                if size_cmd {
                    keep.push(w);
                } else {
                    c.full = true;
                    taken = true;
                }
                i += 1;
            }
            "--count" if cmd == "code" => {
                c.count = true;
                taken = true;
                i += 1;
            }
            "--repo" => {
                return Err(format!("{cmd}: --repo is a CLI option (aix --repo DIR {cmd} ...); it is not available here"));
            }
            "--limit" | "--count" => {
                keep.push(w);
                i += 1;
            }
            "--untested" | "--write" if cmd == "endpoint" => {
                keep.push(w);
                i += 1;
            }
            // endpoint's own grouping and filters (read by query::endpoint)
            "--count-by" | "--role" | "--method" if cmd == "endpoint" => {
                keep.push(w);
                if inline.is_none() {
                    keep.extend(words.get(i + 1).copied());
                    i += 1;
                }
                i += 1;
            }
            n if n.starts_with("--") && n.len() > 2 && strict && !PASSTHROUGH.contains(&n) => {
                return Err(format!("{cmd}: unknown option {}. Supported: {SUPPORTED}. Options may stand before or after the query; a symbol never starts with --", n.chars().take(40).collect::<String>()));
            }
            _ => {
                keep.push(w);
                i += 1;
            }
        }
    }
    if taken || keep.len() != words.len() {
        c.arg = keep.join(" ");
    }
    Ok(c)
}

/// grep's token list: `--limit N`, `--max N`, `--full` before any `--` (grep keeps its own `--count` = -c).
/// Returns (tokens, limit, full).
pub fn take_grep(toks: &[String]) -> Result<(Vec<String>, Option<usize>, bool), String> {
    let stop = toks.iter().position(|t| t == "--").unwrap_or(toks.len());
    let (mut out, mut limit, mut full) = (Vec::with_capacity(toks.len()), None, false);
    let mut i = 0;
    while i < toks.len() {
        if i >= stop {
            out.push(toks[i].clone());
            i += 1;
            continue;
        }
        let t = toks[i].as_str();
        let (name, inline) = match t.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v)),
            _ => (t, None),
        };
        match name {
            "--limit" | "--max" => {
                let (v, used) = match inline {
                    Some(v) => (Some(v), 1),
                    None => (toks.get(i + 1).map(String::as_str), 2),
                };
                limit = Some(num(name, v).map_err(|e| format!("grep: {e}"))?);
                i += used;
            }
            "--full" => {
                full = true;
                i += 1;
            }
            _ => {
                out.push(toks[i].clone());
                i += 1;
            }
        }
    }
    Ok((out, limit, full))
}

// ── paths ──

static CWD_REL: Mutex<String> = Mutex::new(String::new());

/// The working directory relative to the repo root ("" at the root): a path that is not found from the root is tried
/// below it (`cd frontend/src; aix grep x pages`).
pub fn set_cwd_rel(rel: &str) {
    if let Ok(mut g) = CWD_REL.lock() {
        *g = rel.trim_matches('/').to_string();
    }
}

pub fn cwd_rel() -> String {
    CWD_REL.lock().map(|g| g.clone()).unwrap_or_default()
}

/// `./a//b\c/` -> `a/b/c`.
pub fn clean_path(p: &str) -> String {
    let mut s = p.replace('\\', "/");
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while let Some(r) = s.strip_prefix("./") {
        s = r.to_string();
    }
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

/// Does an indexed file or directory carry this repo-relative path?
pub fn path_exists(ix: &Index, p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    let dir = format!("{p}/");
    ix.conn
        .query_row("SELECT 1 FROM files WHERE path=?1 OR substr(path,1,?2)=?3 LIMIT 1", rusqlite::params![p, dir.chars().count() as i64, dir], |_| Ok(()))
        .is_ok()
}

/// Is `p` exactly an indexed file (not a directory)?
pub fn path_is_file(ix: &Index, p: &str) -> bool {
    ix.conn.query_row("SELECT 1 FROM files WHERE path=?1", [p], |_| Ok(())).is_ok()
}

/// The indexed path a user's spelling means, if any: cleaned, then below the working subdirectory.
pub fn resolve_path(ix: &Index, p: &str) -> Option<String> {
    let c = clean_path(p);
    if c.is_empty() || c == "." {
        // `.` in a subdirectory is that directory (as grep and ls read it); at the root it names no single path
        let rel = cwd_rel();
        return (!rel.is_empty() && p.starts_with('.') && path_exists(ix, &rel)).then_some(rel);
    }
    if path_exists(ix, &c) {
        return Some(c);
    }
    let rel = cwd_rel();
    if !rel.is_empty() {
        let joined = clean_path(&format!("{rel}/{c}"));
        if path_exists(ix, &joined) {
            return Some(joined);
        }
        // `../main`, `a/../b` from a subdirectory: resolved lexically, never above the repo root
        if c.contains("..") {
            if let Some(j) = lexical(&joined).filter(|j| !j.is_empty() && path_exists(ix, j)) {
                return Some(j);
            }
        }
    }
    if c.contains("..") {
        if let Some(j) = lexical(&c).filter(|j| !j.is_empty() && path_exists(ix, j)) {
            return Some(j);
        }
    }
    // Windows opens a path typed in another case (`readme.md` is README.md): the indexed spelling
    if cfg!(windows) {
        let joined = (!rel.is_empty()).then(|| clean_path(&format!("{rel}/{c}")));
        return case_of(ix, &c).or_else(|| case_of(ix, joined.as_deref()?));
    }
    None
}

/// The indexed file or directory `p` names when case is ignored, in the index's spelling (ASCII case only).
// ponytail: a scan of `files` per word (no NOCASE index); misses are remembered per process, as the rows of a stream
// ask for the same word thousands of times. A NOCASE index on files(path) if typed paths ever get slow.
fn case_of(ix: &Index, p: &str) -> Option<String> {
    use std::collections::HashSet;
    static MISS: std::sync::LazyLock<Mutex<HashSet<String>>> = std::sync::LazyLock::new(Default::default);
    // never a Windows file name: a data set (`@t`), a `file:line`, words with spaces
    if p.starts_with('@') || p.contains([':', ' ', '\t', '*', '?', '"', '<', '>', '|']) || MISS.lock().is_ok_and(|m| m.contains(p)) {
        return None;
    }
    let n = p.chars().count() as i64;
    let hit = ix
        .conn
        .prepare_cached("SELECT substr(path,1,?2) FROM files WHERE path=?1 COLLATE NOCASE OR substr(path,1,?2+1)=?3 COLLATE NOCASE LIMIT 1")
        .and_then(|mut st| st.query_row(rusqlite::params![p, n, format!("{p}/")], |r| r.get(0)))
        .ok();
    if hit.is_none() {
        if let Ok(mut m) = MISS.lock() {
            if m.len() > 50_000 {
                m.clear();
            }
            m.insert(p.to_string());
        }
    }
    hit
}

/// `a/./b/../c` -> `a/c`; None when `..` climbs above the start.
fn lexical(p: &str) -> Option<String> {
    let mut v: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                v.pop()?;
            }
            s => v.push(s),
        }
    }
    Some(v.join("/"))
}

/// The one indexed file whose name is this bare basename (`App.tsx`), when exactly one is.
pub fn unique_basename(ix: &Index, name: &str) -> Option<String> {
    if name.contains('/') || !name.contains('.') || name.starts_with('.') {
        return None;
    }
    let mut st = ix.conn.prepare_cached("SELECT path FROM files WHERE path LIKE '%/' || ?1 ESCAPE '\\' LIMIT 2").ok()?;
    let esc = name.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    let v: Vec<String> = st.query_map([&esc], |r| r.get::<_, String>(0)).ok()?.flatten().collect();
    (v.len() == 1).then(|| v[0].clone())
}

/// Does a word look like a path (not a plain word)?
pub fn path_shaped(w: &str) -> bool {
    w.contains('/') || w.contains('\\') || w.starts_with("./") || w.starts_with("../")
}

/// Commands whose words may name files: spell-normalise every word that resolves to an indexed path.
pub const PATH_CMDS: &[&str] = &["outline", "history", "code", "brief", "route", "bugs", "qa", "table", "trace", "explain", "callers", "callees", "symbol", "tasks", "script", "text"];
/// ... and these also resolve a bare basename that names exactly one indexed file.
const BASENAME_CMDS: &[&str] = &["outline", "history", "code", "brief"];

/// Rewrite `./x`, `x\y`, `x//y`, `x/`, subdirectory-relative and (for a few commands) bare-basename words to the
/// repo-relative indexed path. A `:A-B` / `:line` suffix is kept. Words that match nothing are left alone.
pub fn normalize_paths(ix: &Index, cmd: &str, arg: &str) -> String {
    if !PATH_CMDS.contains(&cmd) || arg.trim().is_empty() {
        return arg.to_string();
    }
    let mut changed = false;
    let words: Vec<String> = arg
        .split_whitespace()
        .map(|w| {
            if w.starts_with('-') || w.starts_with('\'') || w.starts_with('"') {
                return w.to_string();
            }
            let (p, suf) = match w.rsplit_once(':') {
                Some((p, s)) if !p.is_empty() && s.chars().next().is_some_and(|c| c.is_ascii_digit()) && s.chars().all(|c| c.is_ascii_digit() || c == '-') => (p, format!(":{s}")),
                _ => (w, String::new()),
            };
            let fixed = if path_shaped(p) || p.ends_with('/') {
                resolve_path(ix, p).filter(|r| r != p)
            } else if BASENAME_CMDS.contains(&cmd) && !path_exists(ix, p) {
                resolve_path(ix, p).filter(|r| r != p).or_else(|| unique_basename(ix, p))
            } else {
                None
            };
            match fixed {
                Some(f) => {
                    changed = true;
                    format!("{f}{suf}")
                }
                None => w.to_string(),
            }
        })
        .collect();
    if changed {
        words.join(" ")
    } else {
        arg.to_string()
    }
}

/// A `hints` row: `  /route | lead` (never a footer such as `  next: aix ...`).
pub fn is_hint_row(l: &str) -> bool {
    l.starts_with("  ") && l.contains(" | ") && !l.trim_start().starts_with("next:")
}

/// `hints` rows (`  /route | lead`) as plan rows: the route stands where a file would.
pub fn hint_rows(lines: &[String]) -> Vec<crate::plan::Row> {
    lines
        .iter()
        .filter(|l| is_hint_row(l))
        .map(|l| crate::plan::Row { path: l.trim_start().split(" | ").next().unwrap_or("").to_string(), n: 1, bytes: l.len() + 1, conf: None })
        .collect()
}

// ── howto: a curated task -> exact command table (first), keyword ranking after ──

/// (every group needs one of its phrases in the question, the commands to run)
type Curated = (&'static [&'static [&'static str]], &'static str);

const HOWTO: &[Curated] = &[
    (&[&["script"]], "aix script <words>   (existing scripts for a task, with usage)"),
    (&[&["history", "git log", "commits touching", "commits that touch", "commits touch", "touched", "touching", "commits for", "commits of", "commits to", "who changed", "last changed", "blame", "log of", "changed over time", "commits changed", "which commits", "commits changing", "changes to"]], "aix history <file|Class.method>   (commits touching it, fixes flagged, findings naming it)"),
    (&[&["who calls", "callers", "what calls", "used by", "who uses", "who references", "is called", "usages of", "uses of"]], "aix callers <Symbol|Class.method>   (add --conf exact,resolved to drop name-only rows)"),
    (&[&["what does", "callees", "calls what", "which functions does", "dependencies of"], &["call", "callees", "depend", "use"]], "aix callees <Symbol|Class.method>"),
    (&[&["whole file", "entire file", "full file", "complete file", "the file contents", "file contents", "file content", "read a file", "read the file", "read file", "open a file", "open the file", "view a file", "cat a file", "all of a file"]], "aix code <file> --full   (the whole file, numbered; --max N sets the cap)"),
    (&[&["lines", "line range", "__range__"], &["read", "show", "print", "view", "see", "get", "sed", "display", "extract", "range", "__range__"]], "aix code <file>:A-B   (lines A to B, numbered)"),
    (&[&["open task", "open tasks", "tasks", "todo", "to-do", "checklist", "blocker", "unfinished", "backlog", "open items", "outstanding", "decisions"]], "aix tasks open [decision|found|blocker] [words]"),
    (&[&["config", "property", "properties", "setting", "settings", "env var", "environment variable", "yml", "yaml", ".env", "option", "feature flag"], &["find", "where", "which", "locate", "search", "look", "defined", "value", "key", "set"]], "aix grep '<property.key>'   /   aix text \"<label>\"   (a UI label for it)"),
    (&[&["file named", "files named", "by name", "file name", "filename", "find file", "find files", "locate file", "files called", "file called", "files matching", "which file", "path of", "where is the file"]], "aix find <name>   /   aix grep -l '<name-regex>' [<dir>]"),
    (&[&["outline", "methods of", "members of", "methods in", "list methods", "list functions", "functions in", "structure of", "what is in", "what's in", "classes in", "list the members"]], "aix outline <file> [words]   (members with line ranges and facts)"),
    (&[&["body of", "source of", "implementation of", "code of", "read the method", "read method", "read function", "show method", "show function", "definition of", "method body", "function body", "show the code"]], "aix code <Class.method|symbol>   (its source, numbered)"),
    (&[&["test", "tests", "e2e", "qa", "cover"], &["how", "which", "what", "scenario", "cover", "run"]], "aix qa <route|topic>   /   aix scope [rev]   (which checks to rerun)"),
    (&[&["diff", "before commit", "before i commit", "my change", "my changes", "uncommitted", "changed files", "blast radius", "what breaks"]], "aix impact [rev|Symbol]   (what the change touches)"),
    (&[&["ui string", "label", "button text", "toast", "message text", "user-facing", "wording"]], "aix text \"<ui string>\"   (where it lives and which tests quote it)"),
    (&[&["endpoint", "endpoints"], &["no test", "without test", "untested", "no script", "not covered", "uncovered", "no spec", "without a test", "lack a test", "have no test"], &["endpoint", "endpoints"]], "aix endpoint <path> --untested   (no script or spec names it; --role R, --method M, --write narrow the list)"),
    (&[&["endpoint", "rest api", "http route", "api route", "handler for", "controller"]], "aix endpoint <[METHOD] /path|name>   (roles, client wrapper, callers)"),
    (&[&["two patterns", "both patterns", "two regex", "both words", "two words", "match two", "match both", "and also matches", "lines that match a and b"]], "aix grep '<re>' --and '<re2>' [path]   (the same line matches both; --not '<re>' drops lines, --body: one hit per enclosing method)"),
    (&[&["pipe stage", "pipe stages", "stages", "sort", "uniq", "cut -", "wc -l", "count by"], &["pipe", "rows", "output", "result", "stage", "list"]], "aix '<command> | count by dir | sort -rn | head -n 5'   (row stages: count, filter, dedup, sort, uniq, head, tail, cut, wc -l, grep, sed -n, put; aix pipe --help)"),
    (&[&["difference", "not in the other", "missing from", "but not in", "minus", "compare two lists", "diff two", "set difference"], &["list", "lists", "set", "sets", "rows", "lines", "files", "@"]], "aix grep -v -F -x -f @b @a   (rows of @a that are not lines of @b; store each first: aix put a FILE)"),
    (&[&["filter records", "where field", "field equals", "records where", "filter by field", "rows where"]], "aix filter --where 'FIELD=V' @set   (also != > >= < <=; aix sets show NAME --fields lists the fields)"),
    (&[&["live database", "live data", "rows in the database", "count rows in", "production data", "database rows", "in the db right now"]], "aix reads the code, docs and history, not live data: for rows use the repo's own DB script (aix script psql | aix script sql)"),
    (&[&["table", "column", "columns", "schema of", "migration", "entity"], &["table", "column", "columns", "schema", "migration", "entity", "database", "db"]], "aix table <db table|Entity>[.column]"),
    (&[&["index"], &["how big", "size of", "up to date", "stale", "fresh", "what is in", "what's in", "status", "how many"]], "aix stats   (what the index holds, how fresh it is)"),
    (&[&["files", "lines", "line count"], &["list all", "list the", "list files", "files under", "files in", "how many", "lines of", "count", "largest", "biggest", "sizes", "wc"]], "aix files [DIR|GLOB] [--lines] [--count] [--sort lines|size]   (ls / find / wc -l over the indexed files)"),
    (&[&["per directory", "per dir", "by directory", "by dir", "per folder", "per file", "by file"], &["count", "how many", "usages", "occurrences", "matches"]], "aix 'grep <re> | count by dir:2'   (dir:N sets the depth; count by file / ext / match)"),
    (&[&["log"], &["summarize", "summary", "errors in", "digest", "what went wrong", "group"]], "aix logs errors --since 15m   (a registered log)   /   cmd 2>&1 | aix put app - --pattern auto  then  aix count by template @app"),
    (&[&["by meaning", "semantic", "similar to", "conceptually", "in plain words", "natural language", "fuzzy"]], "aix ask \"<question>\" --kind code   (ranked by meaning and words)"),
    (&[&["bug", "bugs", "regression", "broke", "broken before", "past findings", "past fixes"]], "aix bugs <route|file|topic>"),
    (&[&["save a list", "save the list", "save results", "save output", "save the output", "reuse", "data set", "dataset", "keep the output", "store the output", "store results", "query a log", "query the output", "test report", "git log", "search it later", "output and search", "save the"]], "cmd 2>&1 | aix put <name> -   /   aix '<aix command> --bare | put <name>'   then aix grep RE @<name>, aix count by template @<name>"),
];

fn range_marked(q: &str) -> String {
    static R: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"\d+\s*(-|to|\.\.)\s*\d+").unwrap());
    if R.is_match(q) { format!("{q} __range__") } else { q.to_string() }
}

/// The curated commands that answer a task described in words, best match first (all groups must hit).
pub fn howto_curated(question: &str) -> Vec<&'static str> {
    let q = range_marked(&question.to_lowercase());
    let mut hit: Vec<(usize, usize, &'static str)> = HOWTO
        .iter()
        .enumerate()
        .filter(|(_, (groups, _))| groups.iter().all(|g| g.iter().any(|p| q.contains(p))))
        .map(|(i, (groups, cmd))| (groups.len(), i, *cmd))
        .collect();
    // a more specific entry (more groups) first, then the table order
    hit.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    hit.into_iter().map(|h| h.2).collect()
}

// ── exit status ──

static NONE_LINE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)^(==\s.*(:\s*none\b|:\s*0 rows\b|\b0 (matching lines|matches|commits)\b)|==\s*no\s|no\s|none\b|path not found|\(?0 (rows|matches)\b)").unwrap()
});

/// Does the answer say "nothing found"? Its first informative line is a none line and no row follows.
pub fn looks_none(out: &crate::Out) -> bool {
    if !out.hits.is_empty() {
        return false;
    }
    let info: Vec<&String> = out.lines.iter().filter(|l| !l.starts_with('(') && !l.trim().is_empty()).collect();
    match info.first() {
        None => true,
        Some(f) => NONE_LINE.is_match(f) && !info.iter().skip(1).any(|l| crate::plan::is_row(l)),
    }
}

/// The process status of an answer: 0 found, 1 none / no match, 2 usage or error.
pub fn exit_status(cmd: &str, out: &crate::Out) -> i32 {
    if out.error || out.exit_code == Some(2) || out.lines.first().is_some_and(|l| l.starts_with("usage: aix ")) {
        2
    } else if let Some(c) = out.exit_code {
        c
    } else if let Some(found) = out.exists {
        if found { 0 } else { 1 }
    } else if FLAG_CMDS.contains(&cmd) && looks_none(out) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_anywhere() {
        let c = take_common("callers", "main --limit 3").unwrap();
        assert_eq!((c.arg.as_str(), c.limit), ("main", Some(3)));
        let c = take_common("tasks", "open --max=4").unwrap();
        assert_eq!((c.arg.as_str(), c.limit), ("open", Some(4)));
        let c = take_common("code", "main --count").unwrap();
        assert!(c.count && c.arg == "main");
        let c = take_common("code", "a.rs --max 7").unwrap();
        assert_eq!((c.arg.as_str(), c.limit), ("a.rs --max 7", None));
        assert!(take_common("callers", "main --bogus").unwrap_err().contains("Supported"));
        assert!(take_common("callers", "main --limit x").is_err());
        assert_eq!(take_common("find", "a --bogus").unwrap().arg, "a --bogus");
        assert_eq!(take_common("callers", "main --exists").unwrap().arg, "main --exists");
    }

    #[test]
    fn grep_flags_stop_at_double_dash() {
        let t: Vec<String> = ["foo", "--limit", "3", "--full", "--", "--limit"].iter().map(|s| s.to_string()).collect();
        let (r, l, f) = take_grep(&t).unwrap();
        assert_eq!((r, l, f), (vec!["foo".to_string(), "--".into(), "--limit".into()], Some(3), true));
    }

    #[test]
    fn spellings() {
        assert_eq!(clean_path("./a//b\\c/"), "a/b/c");
    }
}

#[cfg(test)]
mod howto_tests {
    #[test]
    fn task_phrasings_reach_their_command_first() {
        for (q, cmd) in [
            ("which commits changed OwnerController", "aix history"),
            ("how many lines of java are there", "aix files"),
            ("count usages of @GetMapping per directory", "count by dir"),
            ("summarize this server log", "aix logs errors"),
            ("search by meaning for code that validates pets", "aix ask"),
            ("is the index up to date", "aix stats"),
        ] {
            let first = super::howto_curated(q).first().copied().unwrap_or("");
            assert!(first.contains(cmd), "{q} -> {first}");
        }
    }
}
