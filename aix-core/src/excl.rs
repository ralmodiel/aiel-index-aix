//! One exclusion vocabulary for every query command (CLI flags and MCP arguments alike), so a caller can say what it
//! does NOT need and pay no tokens for it.
//!
//!   -x / --exclude <kinds|globs>   PRE: rows are dropped in SQL before ranking and `--limit` (slots go to what is wanted)
//!   --only <kinds|globs>           PRE: the positive counterpart
//!   --conf exact,resolved          PRE: drop name-only / heuristic call-graph rows
//!   --hide <kinds|globs|sections>  POST: applied after ranking and limiting; the output keeps a one-line tally
//!   --skip <sections> / --fields   sections of a multi-section command (brief, trace, explain, table, callers)
//!   --order <sections>             section order of a multi-section command (the byte cap is spent in that order)
//!   --sort relevance,path,recency,conf,fanin,size   row order (comma list = tie-breaks)
//!
//! File kinds come from the index's file classification (`files.class`, see [`file_class`]). Defaults come from
//! `default_excludes` in config.toml and `AIX_EXCLUDE`; they only ever narrow answers, never widen what is indexed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

/// (token, class): the kind vocabulary (plural and singular spellings).
pub const KINDS: &[(&str, &str)] = &[
    ("source", "source"),
    ("sources", "source"),
    ("test", "test"),
    ("tests", "test"),
    ("script", "script"),
    ("scripts", "script"),
    ("doc", "doc"),
    ("docs", "doc"),
    ("data", "data"),
    ("migration", "migration"),
    ("migrations", "migration"),
    ("generated", "generated"),
    ("fixture", "fixture"),
    ("fixtures", "fixture"),
    ("vendor", "vendor"),
];

/// Plural spelling used in suggestions.
pub fn kind_word(class: &str) -> &'static str {
    match class {
        "test" => "tests",
        "script" => "scripts",
        "doc" => "docs",
        "migration" => "migrations",
        "fixture" => "fixtures",
        "generated" => "generated",
        "vendor" => "vendor",
        "data" => "data",
        _ => "source",
    }
}

fn kind_of(tok: &str) -> Option<&'static str> {
    KINDS.iter().find(|k| k.0 == tok.to_ascii_lowercase()).map(|k| k.1)
}

/// Coarse class of a file for exclusion: source / test / script / doc / data / migration / generated / fixture / vendor.
/// A pure function of the path, memoized per thread: the PRE filter (`aix_drop`) asks it for every row a query reads,
/// and the same few thousand paths come back again and again.
pub fn file_class(p: &str) -> &'static str {
    thread_local! {
        static MEMO: std::cell::RefCell<std::collections::HashMap<String, &'static str>> = Default::default();
    }
    MEMO.with(|m| {
        if let Some(c) = m.borrow().get(p) {
            return *c;
        }
        let c = file_class_of(p);
        let mut m = m.borrow_mut();
        if m.len() >= 65_536 {
            m.clear();
        }
        m.insert(p.to_string(), c);
        c
    })
}

fn file_class_of(p: &str) -> &'static str {
    static VENDOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)(vendor|third_party|node_modules|bower_components)/").unwrap());
    static GEN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(^|/)(generated|__generated__|gen|build|dist|target|out)/|\.(min\.(js|css)|pb\.go|snap)$|\.generated\.\w+$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock)$").unwrap()
    });
    static MIG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)db/(migration|tenant)/.*\.sql$|(^|/)migrations?/").unwrap());
    static FIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)(fixtures?|testdata|__fixtures__|__mocks__|__snapshots__|mocks?)/").unwrap());
    static TEST: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(test|spec)\.[jt]sx?$|(^|/)__tests__/|(^|/)src/test/|(^|/)tests?/|(Test|Tests|IT)\.(java|kt)$|_test\.(go|py|rs)$|(^|/)test_[^/]*\.py$|^e2e/specs/").unwrap()
    });
    static SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)(scripts|bin|tools)/|^e2e/[^/]*\.(mjs|sh|js)$|\.(sh|bash)$|(^|/)Makefile$").unwrap());
    static DOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(md|mdx|rst|adoc)$|^docs?/").unwrap());
    static DATA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(json|csv|ya?ml|toml|xml|properties|conf|txt|sql|svg|ini)$").unwrap());
    if VENDOR.is_match(p) {
        "vendor"
    } else if GEN.is_match(p) {
        "generated"
    } else if MIG.is_match(p) {
        "migration"
    } else if FIX.is_match(p) {
        "fixture"
    } else if TEST.is_match(p) {
        "test"
    } else if SCRIPT.is_match(p) {
        "script"
    } else if DOC.is_match(p) {
        "doc"
    } else if DATA.is_match(p) {
        "data"
    } else {
        "source"
    }
}

/// gitignore-ish glob to an anchored regex: `**/` any dirs, `**` anything, `*` within a segment, `?` one char; a glob
/// without `/` matches a file or directory name at any depth; a trailing `/` means the whole directory.
fn glob_re(g: &str) -> Option<Regex> {
    let mut g = g.trim().to_string();
    if g.is_empty() {
        return None;
    }
    let anywhere = !g.contains('/');
    let dir = g.ends_with('/');
    if dir {
        g.pop();
    }
    let mut re = String::new();
    let cs: Vec<char> = g.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '*' if cs.get(i + 1) == Some(&'*') => {
                if cs.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    let src = if anywhere || dir {
        // a bare name: the file, or a directory of that name, anywhere
        format!("(?:^|/){re}(?:/.*)?$")
    } else {
        // `docs/**` also names the directory itself; a path without wildcards also names everything under it
        format!("^{re}(?:/.*)?$")
    };
    Regex::new(&src).ok()
}

#[derive(Default, Clone, Debug)]
pub struct Spec {
    pub tokens: Vec<String>,
    kinds: BTreeSet<&'static str>,
    globs: Vec<Regex>,
}

impl Spec {
    pub fn parse(list: &str) -> Spec {
        let mut s = Spec::default();
        s.add(list);
        s
    }
    pub fn add(&mut self, list: &str) {
        for t in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if let Some(k) = kind_of(t) {
                self.kinds.insert(k);
                self.tokens.push(t.to_string());
            } else if let Some(r) = glob_re(t) {
                self.globs.push(r);
                self.tokens.push(t.to_string());
            }
        }
    }
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.globs.is_empty()
    }
    pub fn matches(&self, p: &str) -> bool {
        !self.is_empty() && (self.kinds.contains(file_class(p)) || self.globs.iter().any(|g| g.is_match(p)))
    }
    pub fn has_kind(&self, class: &str) -> bool {
        self.kinds.contains(class)
    }
}

/// The raw flags as typed (CLI text, MCP arguments).
#[derive(Default, Clone, Debug)]
pub struct ExclArgs {
    pub exclude: Vec<String>,
    pub only: Vec<String>,
    pub hide: Vec<String>,
    pub skip: Vec<String>,
    pub fields: Vec<String>,
    pub order: Vec<String>,
    pub sort: Vec<String>,
    pub conf: Vec<String>,
    pub no_default: bool,
    /// --count / --plan: breakdown only
    pub plan: bool,
    /// --exists: one-line yes/no
    pub exists: bool,
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub offset: Option<usize>,
    pub group_by: Option<String>,
    pub having: Option<String>,
}

impl ExclArgs {
    pub fn is_empty(&self) -> bool {
        self.exclude.is_empty()
            && self.only.is_empty()
            && self.hide.is_empty()
            && self.skip.is_empty()
            && self.fields.is_empty()
            && self.order.is_empty()
            && self.sort.is_empty()
            && self.conf.is_empty()
        && !self.plan
        && !self.exists
        && self.page.is_none()
        && self.per_page.is_none()
        && self.offset.is_none()
        && self.group_by.is_none()
        && self.having.is_none()
    }
    pub fn merge(&mut self, o: &ExclArgs) {
        self.exclude.extend(o.exclude.iter().cloned());
        self.only.extend(o.only.iter().cloned());
        self.hide.extend(o.hide.iter().cloned());
        self.skip.extend(o.skip.iter().cloned());
        self.fields.extend(o.fields.iter().cloned());
        self.order.extend(o.order.iter().cloned());
        self.sort.extend(o.sort.iter().cloned());
        self.conf.extend(o.conf.iter().cloned());
        self.no_default |= o.no_default;
        self.plan |= o.plan;
        self.exists |= o.exists;
        self.page = self.page.or(o.page);
        self.per_page = self.per_page.or(o.per_page);
        self.offset = self.offset.or(o.offset);
        self.group_by = self.group_by.clone().or(o.group_by.clone());
        self.having = self.having.clone().or(o.having.clone());
    }
}

fn split_list(v: &str) -> impl Iterator<Item = String> + '_ {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Pull the exclusion flags out of an argument token list. `grep` keeps its own `-x` (whole-line match) unless the next
/// word is plainly an exclusion list (kinds, or a glob) AND another word remains to be the pattern.
pub fn take_flags(toks: &[String], grep: bool) -> (Vec<String>, ExclArgs) {
    let mut a = ExclArgs::default();
    let mut rest = vec![];
    let mut i = 0;
    let specish = |v: &str| {
        !v.is_empty() && v.split(',').all(|p| kind_of(p.trim()).is_some() || p.contains('*') || p.contains('/'))
    };
    while i < toks.len() {
        // grep: everything after `--` is the pattern and paths, verbatim (`grep -- -x`)
        if grep && toks[i] == "--" {
            rest.extend(toks[i..].iter().cloned());
            break;
        }
        let t = toks[i].as_str();
        let (name, inline) = match t.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (t, None),
        };
        let kind = match name {
            "-x" | "--exclude" => Some(0),
            "--only" => Some(1),
            "--hide" => Some(2),
            "--skip" => Some(3),
            "--fields" => Some(4),
            "--order" => Some(5),
            "--sort" => Some(6),
            "--conf" => Some(7),
            _ => None,
        };
        match name {
            "--no-default-excludes" => {
                a.no_default = true;
                i += 1;
                continue;
            }
            "--plan" | "--exists" => {
                if name == "--plan" {
                    a.plan = true;
                } else {
                    a.exists = true;
                }
                i += 1;
                continue;
            }
            // grep's own `--count` (per-file counts) keeps its meaning; use --plan there
            "--count" if !grep => {
                a.plan = true;
                i += 1;
                continue;
            }
            "--group-by" => {
                if let Some(v) = inline.clone().or_else(|| toks.get(i + 1).cloned()) {
                    a.group_by = Some(v.to_ascii_lowercase());
                    i += if inline.is_some() { 1 } else { 2 };
                    continue;
                }
            }
            "--having" => {
                // one quoted token, or the grammar's own words (`count>5 and share>0.1`)
                let mut parts: Vec<String> = vec![];
                let mut j = i + 1;
                if let Some(v) = &inline {
                    parts.push(v.clone());
                    j = i + 1;
                } else if let Some(v) = toks.get(j) {
                    parts.push(v.clone());
                    j += 1;
                }
                static HV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(and|or|between|count|share|[<>=!]+|[<>=!]*\d+(\.\d+)?|(count|share)[<>=!]+\d+(\.\d+)?)$").unwrap());
                while let Some(t) = toks.get(j).filter(|t| HV.is_match(t)) {
                    parts.push(t.clone());
                    j += 1;
                }
                if !parts.is_empty() {
                    a.having = Some(parts.join(" "));
                    i = j;
                    continue;
                }
            }
            "--page" | "--per-page" | "--offset" => {
                let v = inline.clone().or_else(|| toks.get(i + 1).cloned());
                if let Some(n) = v.as_deref().and_then(|v| v.parse::<usize>().ok()) {
                    match name {
                        "--page" => a.page = Some(n.max(1)),
                        "--per-page" => a.per_page = Some(n.max(1)),
                        _ => a.offset = Some(n),
                    }
                    i += if inline.is_some() { 1 } else { 2 };
                    continue;
                }
            }
            _ => {}
        }
        let Some(k) = kind else {
            rest.push(toks[i].clone());
            i += 1;
            continue;
        };
        let (val, used) = match inline {
            Some(v) => (Some(v), 1),
            None => (toks.get(i + 1).cloned(), 2),
        };
        let Some(val) = val else {
            rest.push(toks[i].clone());
            i += 1;
            continue;
        };
        // grep's GNU `--exclude=GLOB` (a file-name glob such as `*.min.js`, not a kind list or a path glob) is grep's own
        if grep && name == "--exclude" && !val.contains('/') && !val.split(',').all(|p| kind_of(p.trim()).is_some()) {
            rest.push(toks[i].clone());
            if used == 2 {
                rest.push(val);
            }
            i += used;
            continue;
        }
        if grep && name == "-x" {
            // another positional word must remain to be the pattern (`grep re -x docs`, `grep -x docs re`)
            // words that are a flag's value (`--width 0`, `-m 2`, `-A 3`) are not patterns
            const VALUED: &[&str] = &["--width", "--head", "--limit", "--max", "-m", "-A", "-B", "-C", "-e", "-g", "-t", "--group", "--count-by", "--and", "--not", "--not-in", "--in", "--glob", "--type", "--include", "--exclude-dir", "--max-count"];
            let positional = |v: &[String], from: usize| v.iter().enumerate().skip(from).filter(|(j, r)| !r.starts_with('-') && !(*j > 0 && VALUED.contains(&v[j - 1].as_str()))).count();
            let others = positional(&rest, 0) + positional(toks, i + 2);
            if !specish(&val) || others < 1 {
                // grep -x: the whole line must match. A word after it that is not a pattern flag is probably meant as an exclusion
                if !val.starts_with('-') && !specish(&val) && others >= 1 {
                    flag_note(format!("(grep -x is the whole-line flag, so '{val}' is read as a search word; to exclude files use --exclude <kinds|globs>, e.g. --exclude tests,docs)"));
                }
                rest.push(toks[i].clone());
                i += 1;
                continue;
            }
        }
        let dst = match k {
            0 => &mut a.exclude,
            1 => &mut a.only,
            2 => &mut a.hide,
            3 => &mut a.skip,
            4 => &mut a.fields,
            5 => &mut a.order,
            6 => &mut a.sort,
            _ => &mut a.conf,
        };
        dst.extend(split_list(&val));
        i += used;
    }
    (rest, a)
}

/// Whitespace-token form of [`take_flags`] for the commands that take one argument string. Untouched when no flag is
/// present (spacing preserved).
pub fn take_arg_flags(arg: &str) -> (String, ExclArgs) {
    let toks = split_flag_values(arg);
    let (rest, a) = take_flags(&toks, false);
    if rest.len() == toks.len() && a.is_empty() && !a.no_default {
        return (arg.to_string(), a);
    }
    (rest.join(" "), a)
}

thread_local! {
    static NOTES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}
fn flag_note(s: String) {
    NOTES.with(|n| n.borrow_mut().push(s));
}
/// Hints raised while reading flags since the last call (a grep `-x` that is not an exclusion list...).
pub fn take_flag_notes() -> Vec<String> {
    NOTES.with(|n| std::mem::take(&mut *n.borrow_mut()))
}

/// Whitespace tokens, except that the value of an exclusion flag may be quoted (`-x 'my dir/**'`): its spaces are kept.
fn split_flag_values(arg: &str) -> Vec<String> {
    const VALUE_FLAGS: &[&str] = &["-x", "--exclude", "--only", "--hide", "--skip", "--fields", "--order", "--sort", "--conf", "--having", "--group-by"];
    let words: Vec<&str> = arg.split_whitespace().collect();
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        let after_flag = out.last().is_some_and(|p: &String| VALUE_FLAGS.contains(&p.as_str()));
        let q = w.chars().next().filter(|c| (*c == '\'' || *c == '"') && after_flag);
        if let Some(q) = q {
            let mut parts = vec![w.trim_start_matches(q)];
            let mut closed = w.len() > 1 && w.ends_with(q);
            let mut j = i;
            while !closed && j + 1 < words.len() {
                j += 1;
                parts.push(words[j]);
                closed = words[j].ends_with(q);
            }
            if closed {
                let mut v = parts.join(" ");
                v.pop(); // the closing quote
                out.push(v);
                i = j + 1;
                continue;
            }
        }
        out.push(w.to_string());
        i += 1;
    }
    out
}

/// Check the values of the ranking and filtering flags: one line naming what is accepted, or None.
pub fn validate(cmd: &str, a: &ExclArgs) -> Option<String> {
    const SORTS: &[&str] = &["relevance", "path", "recency", "conf", "fanin", "size", "count", "count:asc", "key"];
    for s in &a.sort {
        if !SORTS.contains(&s.to_ascii_lowercase().as_str()) {
            return Some(format!("(--sort {s}: unknown key; use relevance, path, recency, conf, fanin, size; with --group-by also count, count:asc, key)"));
        }
    }
    for c in &a.conf {
        if !matches!(c.to_ascii_lowercase().as_str(), "exact" | "resolved" | "heuristic" | "name" | "name-only" | "nameonly") {
            return Some(format!("(--conf {c}: unknown confidence; use exact, resolved, heuristic, name)"));
        }
    }
    let secs = sections_of(cmd);
    for o in &a.order {
        let ol = o.to_ascii_lowercase().replace('_', "-");
        if secs.is_empty() || !matches!(cmd, "brief" | "trace" | "explain" | "table") {
            return Some(format!("(--order {o}: {cmd} has no sections to order; --order applies to brief, trace, explain, table)"));
        }
        if !secs.contains(&ol.as_str()) {
            return Some(format!("(--order {o}: unknown section for {cmd}; sections: {})", secs.join(",")));
        }
    }
    None
}

/// Sections each multi-section command can skip, hide, order or select with `--fields`.
pub fn sections_of(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "brief" => &["menu", "api", "roles", "e2e", "scripts", "bugs", "fixes", "decisions", "hints"],
        "trace" | "explain" => &["ui", "endpoint", "service", "tables", "state", "docs", "findings", "e2e"],
        "table" => &["columns", "constraints", "migrations", "readers", "writers", "endpoints"],
        "callers" => &["name-only", "tests"],
        _ => &[],
    }
}

/// The resolved criteria of one query.
#[derive(Default, Clone, Debug)]
pub struct Excl {
    pub x: Spec,
    pub only: Spec,
    pub defaults: Spec,
    pub hide: Spec,
    pub hide_sections: BTreeSet<String>,
    pub skip: BTreeSet<String>,
    pub order: Vec<String>,
    pub sort: Vec<String>,
    pub group: Option<String>,
    pub having: Option<String>,
    /// allowed call-graph confidences (empty: all)
    pub conf: Vec<String>,
    /// notes for the caller (unknown section names...)
    pub notes: Vec<String>,
}

impl Excl {
    /// `defaults`: config / env default excludes (ignored with `--no-default-excludes`).
    pub fn build(cmd: &str, a: &ExclArgs, defaults: &[String]) -> Excl {
        let mut e = Excl::default();
        for x in &a.exclude {
            e.x.add(x);
        }
        for x in &a.only {
            e.only.add(x);
        }
        if !a.no_default {
            for d in defaults {
                e.defaults.add(d);
            }
            // test fixtures are sample projects, not facts about this one: the project-fact commands leave them out
            if matches!(cmd, "tasks" | "feature" | "endpoint" | "hints") && a.only.is_empty() && !e.defaults.kinds.contains("fixture") {
                e.defaults.add("fixtures");
            }
        }
        let secs = sections_of(cmd);
        for h in &a.hide {
            let hl = h.to_ascii_lowercase();
            if secs.contains(&hl.as_str()) {
                e.hide_sections.insert(hl.clone());
            }
            e.hide.add(h);
        }
        let mut skip: BTreeSet<String> = BTreeSet::new();
        for s in &a.skip {
            let sl = s.to_ascii_lowercase().replace('_', "-");
            let sl = if sl == "name" || sl == "nameonly" { "name-only".to_string() } else { sl };
            if secs.contains(&sl.as_str()) {
                skip.insert(sl);
            } else if secs.is_empty() {
                e.notes.push(format!("(--skip {s}: {cmd} has no sections; use -x <kinds|globs>)"));
            } else {
                e.notes.push(format!("(--skip {s}: unknown section for {cmd}; sections: {})", secs.join(",")));
            }
        }
        if !a.fields.is_empty() {
            let want: BTreeSet<String> = a.fields.iter().map(|f| f.to_ascii_lowercase()).collect();
            for s in secs {
                if !want.contains(*s) {
                    skip.insert(s.to_string());
                }
            }
            for w in &want {
                if !secs.contains(&w.as_str()) {
                    e.notes.push(format!("(--fields {w}: unknown section for {cmd}; sections: {})", secs.join(",")));
                }
            }
        }
        // callers: `--skip tests` is the tests kind, `--skip name-only` is --conf exact,resolved
        if cmd == "callers" {
            if skip.remove("tests") {
                e.x.add("tests");
            }
            if skip.remove("name-only") {
                e.conf = vec!["exact".into(), "resolved".into(), "heuristic".into()];
            }
        }
        e.skip = skip;
        for c in &a.conf {
            let c = c.to_ascii_lowercase();
            let c = if c == "name-only" || c == "nameonly" { "name".to_string() } else { c };
            if !e.conf.contains(&c) {
                e.conf.push(c);
            }
        }
        if a.conf.iter().any(|c| c.eq_ignore_ascii_case("exact")) && !a.conf.iter().any(|c| c.eq_ignore_ascii_case("heuristic")) {
            e.conf.retain(|c| c != "heuristic");
        }
        e.group = a.group_by.clone();
        e.having = a.having.clone();
        e.order = a.order.iter().map(|s| s.to_ascii_lowercase()).collect();
        e.sort = a.sort.iter().map(|s| s.to_ascii_lowercase()).filter(|s| s != "relevance").collect();
        e
    }

    /// Dropped by a PRE criterion (exclusion, defaults, or outside `--only`).
    pub fn drops(&self, p: &str) -> bool {
        if p.is_empty() {
            return false;
        }
        self.x.matches(p) || self.defaults.matches(p) || (!self.only.is_empty() && !self.only.matches(p))
    }
    pub fn default_drops(&self, p: &str) -> bool {
        !p.is_empty() && self.defaults.matches(p)
    }
    /// A PRE criterion that needs the SQL layer (paths or confidence).
    pub fn pre_active(&self) -> bool {
        !self.x.is_empty() || !self.only.is_empty() || !self.defaults.is_empty() || !self.conf.is_empty()
    }
    pub fn path_active(&self) -> bool {
        !self.x.is_empty() || !self.only.is_empty() || !self.defaults.is_empty()
    }
    /// Anything that can change the answer (all of it needs the comparison run for the tally).
    pub fn active(&self) -> bool {
        self.pre_active() || !self.skip.is_empty() || !self.hide.is_empty() || !self.hide_sections.is_empty()
    }
    pub fn sort_has(&self, k: &str) -> bool {
        self.sort.iter().any(|s| s == k)
    }
    pub fn criteria(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        let mut put = |k: &str, v: Vec<String>| {
            if !v.is_empty() {
                m.insert(k.into(), serde_json::json!(v));
            }
        };
        put("exclude", self.x.tokens.clone());
        put("only", self.only.tokens.clone());
        put("defaults", self.defaults.tokens.clone());
        put("hide", self.hide.tokens.clone());
        put("skip", self.skip.iter().cloned().collect());
        put("conf", self.conf.clone());
        put("order", self.order.clone());
        put("sort", self.sort.clone());
        put("group_by", self.group.iter().cloned().collect());
        put("having", self.having.iter().cloned().collect());
        serde_json::Value::Object(m)
    }
}

/// Defaults from the environment (`AIX_EXCLUDE`, comma or space separated) and the config file.
pub fn default_list(cfg: &[String]) -> Vec<String> {
    let mut v: Vec<String> = cfg.to_vec();
    if let Some(e) = crate::config::env_var("EXCLUDE") {
        v.extend(e.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string));
    }
    v
}

// ───────────────────────────── sections ─────────────────────────────

/// Section tag of every output line of a multi-section command (None: not part of any skippable section).
pub fn section_tags(cmd: &str, lines: &[String]) -> Vec<Option<&'static str>> {
    let mut out = Vec::with_capacity(lines.len());
    let mut in_eq = false; // inside a "== ..." block (brief): its indented rows belong to it
    let mut cur: Option<&'static str> = None; // block opened by a "== ..." header (brief / explain) or a "  label" (brief)
    for l in lines {
        let t = l.trim_start();
        let indent = l.len() - t.len();
        let tag: Option<&'static str> = match cmd {
            "brief" => {
                if l.starts_with("== ") {
                    in_eq = true;
                    cur = if l.starts_with("== scripts") {
                        Some("scripts")
                    } else if l.starts_with("== past findings") || l.starts_with("== bugs") {
                        Some("bugs")
                    } else if l.starts_with("== recent fix commits") || l.starts_with("== fix commits") {
                        Some("fixes")
                    } else if l.starts_with("== open DECISION") {
                        Some("decisions")
                    } else {
                        None
                    };
                    cur
                } else if in_eq && indent >= 1 {
                    cur
                } else if indent == 2 {
                    cur = if t.starts_with("roles:") {
                        Some("roles")
                    } else if t.starts_with("menu:") {
                        Some("menu")
                    } else if t.starts_with("api (") || t.starts_with("api:") {
                        Some("api")
                    } else if t.starts_with("hints (") {
                        Some("hints")
                    } else if t.starts_with("e2e (") || t.starts_with("e2e:") {
                        Some("e2e")
                    } else if t.starts_with("scripts (") {
                        Some("scripts")
                    } else if cur.is_some() && !l.starts_with("route ") && l.starts_with("  ") && false {
                        cur
                    } else {
                        None
                    };
                    cur
                } else if indent >= 3 {
                    cur
                } else {
                    cur = None;
                    in_eq = false;
                    None
                }
            }
            "trace" | "explain" => {
                if l.starts_with("== ") {
                    cur = if l.starts_with("== docs") {
                        Some("docs")
                    } else if l.starts_with("== findings") {
                        Some("findings")
                    } else if l.starts_with("== e2e") {
                        Some("e2e")
                    } else {
                        None
                    };
                    cur
                } else if l.starts_with('(') {
                    cur = None;
                    None
                } else if cur.is_some() {
                    cur
                } else {
                    match t.split_whitespace().next().unwrap_or("") {
                        "route" | "menu" | "member" | "client" | "screen" | "page" | "component" => Some("ui"),
                        "endpoint" | "handler" => Some("endpoint"),
                        "call" => Some("service"),
                        "table" => Some("tables"),
                        "state" => Some("state"),
                        _ => None,
                    }
                }
            }
            "table" => {
                if t.starts_with("-- ") {
                    cur = if t.starts_with("-- columns") {
                        Some("columns")
                    } else if t.starts_with("-- constraints") {
                        Some("constraints")
                    } else if t.starts_with("-- migration") {
                        Some("migrations")
                    } else if t.starts_with("-- writers") {
                        Some("writers")
                    } else if t.starts_with("-- readers") {
                        Some("readers")
                    } else if t.starts_with("-- endpoints") {
                        Some("endpoints")
                    } else {
                        None
                    };
                    cur
                } else if l.starts_with("==") || l.starts_with('(') {
                    cur = None;
                    None
                } else {
                    cur
                }
            }
            _ => None,
        };
        out.push(tag);
    }
    out
}

/// Drop the lines of the skipped sections.
pub fn apply_skip(cmd: &str, lines: &mut Vec<String>, skip: &BTreeSet<String>) {
    if skip.is_empty() || !matches!(cmd, "brief" | "trace" | "explain" | "table") {
        return;
    }
    let tags = section_tags(cmd, lines);
    let mut i = 0;
    lines.retain(|_| {
        let keep = tags[i].is_none_or(|t| !skip.contains(t));
        i += 1;
        keep
    });
}

/// Reorder the section blocks of brief / explain / table (stable; unnamed text keeps its place): sections named in
/// `order` come first, in that order, right after the leading unsectioned lines.
pub fn apply_order(cmd: &str, lines: &mut Vec<String>, order: &[String]) {
    if order.is_empty() || !matches!(cmd, "brief" | "explain" | "table") {
        return;
    }
    // blocks: a run of lines with the same tag; the first run of untagged lines (the header) stays on top
    let tags = section_tags(cmd, lines);
    let mut blocks: Vec<(Option<&'static str>, Vec<String>)> = vec![];
    for (l, t) in lines.iter().zip(tags) {
        match blocks.last_mut() {
            Some(b) if b.0 == t => b.1.push(l.clone()),
            _ => blocks.push((t, vec![l.clone()])),
        }
    }
    let rank = |t: Option<&'static str>| t.and_then(|t| order.iter().position(|o| o == t)).unwrap_or(usize::MAX);
    let head = blocks.iter().take_while(|b| b.0.is_none()).count();
    let tail = &mut blocks[head..];
    if tail.is_empty() {
        return;
    }
    tail.sort_by_key(|b| rank(b.0)); // stable: unnamed blocks keep their relative order after the named ones
    *lines = blocks.into_iter().flat_map(|b| b.1).collect();
}

// ───────────────────────────── line classification ─────────────────────────────

static PATH_IN_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s(\[])((?:[\w@.\-\[\]]+/)*[\w@.\-\[\]]+\.(?:tsx?|jsx?|mjs|cjs|java|kt|py|sh|md|mdx|json|sql|ya?ml|html|css|scss|go|rs|toml|xml|properties|txt|csv|conf))(?::\d+|-\d+-|\b)").unwrap()
});

/// A row that opens with `path:N` (any extension, or an extensionless name under a directory or a well-known build file):
/// the shape every aix row has, whatever the language (`a.rb:1:`, `b.cs:3-5 ...`, `src/gradlew:2:`).
static ROW_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*((?:[\w@.\-\[\]+~]+/)*(?:[\w@\-\[\]+~][\w@.\-\[\]+~]*\.[A-Za-z][\w+\-]{0,15}|\.[A-Za-z][\w.\-]{0,30})|(?:[\w@.\-\[\]+~]+/)+[\w@\-\[\]+~][\w@.\-+~]*|Makefile|Dockerfile|Gemfile|Rakefile|Jenkinsfile|Vagrantfile|Procfile|gradlew|mvnw|LICENSE|Containerfile|Justfile|justfile|BUILD|WORKSPACE)(?::\d+(?:-\d+)?(?:[: ]|$)|-\d+- |\s*$)").unwrap()
});

/// The file a result line is about: the first path-like token.
pub fn line_path(l: &str) -> Option<&str> {
    PATH_IN_LINE.captures(l).and_then(|c| c.get(1)).map(|m| m.as_str()).or_else(|| ROW_PATH.captures(l).and_then(|c| c.get(1)).map(|m| m.as_str()))
}

#[derive(Default, Debug, Clone)]
pub struct Share {
    pub lines: usize,
    pub bytes: usize,
}

/// (per-class share, total lines, total bytes) of the result lines.
pub fn composition(lines: &[String]) -> (BTreeMap<&'static str, Share>, usize, usize) {
    let mut m: BTreeMap<&'static str, Share> = BTreeMap::new();
    let (mut tl, mut tb) = (0, 0);
    for l in lines {
        tl += 1;
        tb += l.len() + 1;
        if let Some(p) = line_path(l) {
            let s = m.entry(file_class(p)).or_default();
            s.lines += 1;
            s.bytes += l.len() + 1;
        }
    }
    (m, tl, tb)
}

/// Pick the kinds worth excluding from a composition: not `source`, each at least 8% of the bytes, at most three,
/// worth suggesting only when together they are at least 30%. Returns (kinds, share of bytes 0..1).
pub fn pick_kinds(comp: &BTreeMap<&'static str, Share>, total_bytes: usize, min_total: f64, excluded: &dyn Fn(&str) -> bool) -> Option<(Vec<&'static str>, f64)> {
    if total_bytes == 0 {
        return None;
    }
    let mut c: Vec<(&'static str, usize)> = comp.iter().filter(|(k, _)| **k != "source" && !excluded(k)).map(|(k, s)| (*k, s.bytes)).collect();
    c.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let picked: Vec<(&'static str, usize)> = c.into_iter().filter(|x| x.1 as f64 / total_bytes as f64 >= 0.08).take(3).collect();
    let sum: usize = picked.iter().map(|x| x.1).sum();
    let share = sum as f64 / total_bytes as f64;
    (share >= min_total).then(|| (picked.iter().map(|x| kind_word(x.0)).collect(), share))
}

pub fn kinds_phrase(kinds: &[&str]) -> String {
    match kinds {
        [a] => a.to_string(),
        [a, b] => format!("{a} and {b}"),
        [a, b, c] => format!("{a}, {b} and {c}"),
        _ => kinds.join(", "),
    }
}

/// Footer suggestions computed from the answer's own composition: file kinds (all commands) and, for the
/// multi-section commands, sections. `ex` is what is already in force (nothing is suggested twice).
pub fn suggest(cmd: &str, lines: &[String], ex: &Excl, truncated: bool) -> Option<String> {
    if matches!(cmd, "grep" | "code" | "sql" | "schema" | "stats" | "howto" | "patterns") {
        return None;
    }
    let (comp, tl, tb) = composition(lines);
    // only large answers deserve a hint
    if tl < 15 || tb < 1800 {
        return None;
    }
    let mut parts: Vec<String> = vec![];
    if let Some((k, share)) = pick_kinds(&comp, tb, 0.30, &|c| ex.x.has_kind(c) || ex.defaults.has_kind(c)) {
        parts.push(format!("{:.0}% of this answer is in {}: add -x {}", share * 100.0, kinds_phrase(&k), k.join(",")));
    }
    let secs = sections_of(cmd);
    if !secs.is_empty() && matches!(cmd, "brief" | "trace" | "explain" | "table") {
        let tags = section_tags(cmd, lines);
        let mut by: BTreeMap<&str, usize> = BTreeMap::new();
        for (l, t) in lines.iter().zip(&tags) {
            if let Some(t) = t {
                *by.entry(*t).or_default() += l.len() + 1;
            }
        }
        let mut v: Vec<(&str, usize)> = by.into_iter().filter(|(t, _)| !ex.skip.contains(*t)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let picked: Vec<(&str, usize)> = v.into_iter().filter(|x| x.1 as f64 / tb as f64 >= 0.2).take(2).collect();
        if !picked.is_empty() {
            let share = picked.iter().map(|x| x.1).sum::<usize>() as f64 / tb as f64;
            let names: Vec<&str> = picked.iter().map(|x| x.0).collect();
            let what = if names.len() == 1 { format!("the {} section is", names[0]) } else { format!("the {} sections are", names.join(" and ")) };
            parts.push(format!("{what} {:.0}% of this {cmd}: add --skip {}", share * 100.0, names.join(",")));
        }
    }
    if cmd == "callers" || cmd == "callees" || cmd == "impact" {
        let n = lines.iter().filter(|l| l.contains("(name)") || l.contains("(heuristic)")).count();
        if n * 4 >= tl && ex.conf.is_empty() {
            parts.push(format!("{n} of {tl} rows are name-only/heuristic: add --conf exact,resolved"));
        }
    }
    if truncated && matches!(cmd, "brief" | "explain" | "table") && parts.is_empty() {
        parts.push("cut at the size cap: put what you need first with --order <sections> or select with --fields".into());
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("({})", parts.join("; ")))
}

/// `--hide` (post): drop result lines of hidden kinds / globs / sections after ranking and limiting; returns the tally.
pub fn apply_hide(cmd: &str, lines: &mut Vec<String>, ex: &Excl) -> BTreeMap<String, usize> {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    if ex.hide.is_empty() && ex.hide_sections.is_empty() {
        return tally;
    }
    let tags = section_tags(cmd, lines);
    let mut i = 0;
    lines.retain(|l| {
        let tag = tags[i];
        i += 1;
        if let Some(t) = tag.filter(|t| ex.hide_sections.contains(*t)) {
            *tally.entry(format!("section {t}")).or_default() += 1;
            return false;
        }
        // headers ("== ...") and notes are never hidden by path
        if l.starts_with("==") || l.starts_with('(') {
            return true;
        }
        if let Some(p) = line_path(l).filter(|p| ex.hide.matches(p)) {
            *tally.entry(file_class(p).to_string()).or_default() += 1;
            return false;
        }
        true
    });
    tally
}

pub fn tally_line(tally: &BTreeMap<String, usize>) -> Option<String> {
    if tally.is_empty() {
        return None;
    }
    let total: usize = tally.values().sum();
    let mut v: Vec<(&String, &usize)> = tally.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let parts: Vec<String> = v.iter().map(|(k, n)| format!("{} {n}", kind_label(k))).collect();
    Some(format!("(hid {total} lines: {})", parts.join(", ")))
}

fn kind_label(k: &str) -> String {
    if k.starts_with("section ") {
        k.to_string()
    } else {
        kind_word(k).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(file_class("docs/a.md"), "doc");
        assert_eq!(file_class("src/a.test.ts"), "test");
        assert_eq!(file_class("e2e/specs/x.json"), "test");
        assert_eq!(file_class("scripts/run.sh"), "script");
        assert_eq!(file_class("db/migration/V1__a.sql"), "migration");
        assert_eq!(file_class("src/generated/api.ts"), "generated");
        assert_eq!(file_class("x/node_modules/a/b.js"), "vendor");
        assert_eq!(file_class("src/__fixtures__/a.json"), "fixture");
        assert_eq!(file_class("config/app.yml"), "data");
        assert_eq!(file_class("src/App.tsx"), "source");
        assert_eq!(file_class("src/main/java/a/FooTest.java"), "test");
    }

    #[test]
    fn globs_and_kinds() {
        let s = Spec::parse("docs/**,**/*.test.ts,e2e,tests");
        assert!(s.matches("docs/a/b.md") && s.matches("src/a.test.ts") && s.matches("e2e/run.mjs"));
        assert!(s.matches("src/test/A.java") && !s.matches("src/App.tsx"));
        assert!(Spec::parse("*.snap").matches("a/b/x.snap"));
        assert!(Spec::parse("src/lib").matches("src/lib/a.ts") && !Spec::parse("src/lib").matches("src/libx/a.ts"));
        assert!(Spec::parse("").is_empty());
    }

    #[test]
    fn flags() {
        let t = |s: &str| s.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        let (rest, a) = take_flags(&t("Foo.bar -x tests,docs --skip bugs --conf=exact,resolved --no-default-excludes"), false);
        assert_eq!(rest, vec!["Foo.bar"]);
        assert_eq!(a.exclude, vec!["tests", "docs"]);
        assert_eq!(a.skip, vec!["bugs"]);
        assert_eq!(a.conf, vec!["exact", "resolved"]);
        assert!(a.no_default);
        // grep keeps -x (whole line) unless the next word is an exclusion list and a pattern remains
        let (rest, a) = take_flags(&t("-x foo"), true);
        assert_eq!(rest, vec!["-x", "foo"]);
        assert!(a.exclude.is_empty());
        let (rest, a) = take_flags(&t("re -x tests,docs"), true);
        assert_eq!(rest, vec!["re"]);
        assert_eq!(a.exclude, vec!["tests", "docs"]);
        let (rest, _) = take_flags(&t("-x docs"), true);
        assert_eq!(rest, vec!["-x", "docs"]);
    }

    #[test]
    fn quoted_flag_values_keep_their_spaces_and_bad_values_are_named() {
        let (rest, a) = take_arg_flags("Cancel order -x 'my dir/**,docs' --sort path");
        assert_eq!(rest, "Cancel order");
        assert_eq!(a.exclude, vec!["my dir/**", "docs"]);
        assert!(validate("text", &a).is_none());
        let bad = ExclArgs { sort: vec!["bogus".into()], ..Default::default() };
        assert!(validate("callers", &bad).unwrap().contains("--sort bogus"));
        let bad = ExclArgs { order: vec!["nope".into()], ..Default::default() };
        assert!(validate("brief", &bad).unwrap().contains("unknown section"));
        assert!(validate("grep", &bad).unwrap().contains("no sections"));
        let bad = ExclArgs { conf: vec!["maybe".into()], ..Default::default() };
        assert!(validate("callers", &bad).is_some());
        // grep -x with a word that is no exclusion list: kept as grep's flag, with a hint
        let t: Vec<String> = "pat -x bogus".split(' ').map(str::to_string).collect();
        let (rest, _) = take_flags(&t, true);
        assert_eq!(rest, vec!["pat", "-x", "bogus"]);
        assert!(take_flag_notes().iter().any(|n| n.contains("--exclude")));
    }

    #[test]
    fn sections() {
        let l: Vec<String> = [
            "route /a -> A src/A.tsx",
            "  roles: x",
            "  api (2 calls):",
            "    foo GET /x -> X.java:1",
            "  e2e (1): s",
            "== past findings (hybrid search)",
            "  docs/a.md:3  bad",
            "== recent fix commits",
            "  abc fix",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut v = l.clone();
        apply_skip("brief", &mut v, &["bugs".to_string(), "api".to_string()].into_iter().collect());
        assert_eq!(v.len(), 5, "{v:?}");
        assert!(!v.iter().any(|x| x.contains("docs/a.md") || x.contains("foo GET")));
        let mut v = l.clone();
        apply_order("brief", &mut v, &["fixes".to_string(), "bugs".to_string()]);
        assert_eq!(v[1], "== recent fix commits", "{v:?}");
        assert_eq!(v[3], "== past findings (hybrid search)", "{v:?}");
        assert_eq!(v[0], l[0]);
    }

    #[test]
    fn hide_tally() {
        let mut lines: Vec<String> = ["== hits", "  src/a.ts:1: x", "  docs/b.md:2: x", "  src/a.test.ts:3: y"].iter().map(|s| s.to_string()).collect();
        let a = ExclArgs { hide: vec!["tests,docs".into()], ..Default::default() };
        let ex = Excl::build("grep", &a, &[]);
        let t = apply_hide("grep", &mut lines, &ex);
        assert_eq!(lines.len(), 2);
        assert_eq!(tally_line(&t).unwrap(), "(hid 2 lines: docs 1, tests 1)");
    }
}
