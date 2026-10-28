//! `aix grep` with GNU grep's flags: the engine for everything beyond the plain ranked search in `query::grep`.
//!
//! Accepted (GNU semantics, proven by differential tests against GNU grep): -i/-y -w -x -F -E -G -e RE... -v -o -m N
//! -c -l -L -q -s -h -H -n -r -R -I -a, -A/-B/-C N and -NUM (context up to 30, a note when capped),
//! --include/--exclude/--exclude-dir GLOB, several paths / files / unexpanded globs, `-` (row input), `--` and
//! combined short flags. aix's own: --and RE / --not RE (line must / must not also match), --not-in PART,
//! --body / --member (each hit's enclosing member once), --group N (-o prints capture group N),
//! --count-by match|file|dir[:N]|ext, --total, --within (with `-`: only lines inside the input rows' ranges),
//! --bare (`path:line:text`), --width N (clip text, default 200, 0 = never).
//! Anything else exits 2 naming the shell command to use. The pattern dialect is ERE / Rust regex (as `grep -E`
//! and `rg`); GNU BRE escapes (`a\|b`, `\(x\)\+`) are translated and announced, back-references are refused.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use regex::Regex;

use crate::index::Index;
use crate::query::{path_rank, Out};

/// Context lines per side are capped here (a note says so).
pub const MAX_CONTEXT: usize = 30;
/// Default clip of a printed text column.
pub const DEFAULT_WIDTH: usize = 200;

/// Clip a text column to `n` characters, then `…` marks the cut (as outfmt::clip_line); 0 = never. Whitespace is kept.
pub fn clipw(s: &str, n: usize) -> String {
    if n == 0 || s.chars().count() <= n {
        return s.to_string();
    }
    let mut o: String = s.chars().take(n).collect();
    o.push('…');
    o
}

#[derive(Default, Debug, Clone)]
pub struct Gx {
    /// trailing path words that name no indexed file (GNU: "No such file", exit 2, the other paths still searched)
    pub missing: Vec<String>,
    pub pats: Vec<String>,
    pub icase: bool,
    pub word: bool,
    pub line: bool,
    pub fixed: bool,
    pub ere: bool,
    pub invert: bool,
    pub only: bool,
    pub max_count: Option<usize>,
    pub count: bool,
    pub files_only: bool,
    pub files_without: bool,
    pub quiet: bool,
    pub no_filename: bool,
    pub after: usize,
    pub before: usize,
    pub ctx_asked: usize,
    pub globs: Vec<String>,
    /// GNU --include / --exclude in command-line order: (is include, glob)
    pub incl: Vec<(bool, String)>,
    pub excl_dir: Vec<String>,
    pub within: String,
    pub scripts: bool,
    pub and_res: Vec<String>,
    pub not_res: Vec<String>,
    pub not_in: Vec<String>,
    pub body: bool,
    pub member: bool,
    pub group: Option<usize>,
    pub count_by: Option<String>,
    pub total: bool,
    pub bare: bool,
    pub width: Option<usize>,
    pub head: Option<usize>,
    pub stdin: bool,
    pub ranges_only: bool,
    /// trailing words that name paths (indexed files or dirs) and unexpanded path globs
    pub paths: Vec<String>,
    pub path_globs: Vec<String>,
    pub bre_from: Vec<(String, String)>,
    /// a word the caller typed that needs the GNU engine (a flag the plain search does not have)
    pub gnu: bool,
    pub notes: Vec<String>,
    /// a GNU-only short flag was typed (`-n`, `-rn`): a GNU-style call
    pub short_flags: bool,
}

/// Does the pattern have an ERE-only operator (`|`, `+`, `?`, `(`) that is not escaped?
fn unescaped_ere(p: &str) -> bool {
    let mut esc = false;
    let mut in_class = false;
    for c in p.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            '[' => in_class = true,
            ']' => in_class = false,
            '|' | '+' | '?' | '(' if !in_class => return true,
            _ => {}
        }
    }
    false
}

fn refuse(flag: &str, why: &str) -> String {
    format!("grep: unsupported flag {flag}{why}: run the shell command instead (`grep {flag} ...` or `rg ...`). Supported: {}", crate::query::GREP_FLAGS)
}

thread_local! {
    static EXACT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The words came as exact argv (CLI, a pipe stage): every word after the pattern is a path, as GNU grep reads them.
/// Without it (an MCP or hook string `grep foo bar`) plain words after the pattern join it as a phrase.
pub fn set_exact_argv(on: bool) -> bool {
    EXACT.with(|c| c.replace(on))
}

/// `.`, `./`, `..` back to the root, the repo's absolute path: the whole repo.
pub(crate) fn is_root_word(ix: &Index, w: &str) -> bool {
    let c = crate::opts::clean_path(w);
    if (c.is_empty() || c == ".") && w.starts_with('.') && !w.starts_with("..") {
        return true;
    }
    let root = crate::sys::canonicalize(&ix.repo).unwrap_or_else(|_| ix.repo.clone());
    let p = std::path::Path::new(w);
    let abs = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().map(|c| c.join(p)).unwrap_or_else(|_| p.to_path_buf()) };
    crate::sys::canonicalize(&abs).is_ok_and(|c| c == root)
}

/// A word that can only mean a file (`nosuch.ts`, `src/x`), never a phrase word.
fn file_shaped(w: &str) -> bool {
    static F: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"^[\w@+\-.]*[\w@+\-]\.[A-Za-z][A-Za-z0-9]{0,9}$").unwrap());
    crate::opts::path_shaped(w) || F.is_match(w)
}

/// Parse grep's argument list. Err = a usage message (exit status 2; a leading \u{1} marks "path not found", status 1).
/// `gnu == false`: the plain ranked search (`query::grep`) answers it unchanged.
pub fn parse(ix: &Index, args: &[String]) -> Result<Gx, String> {
    let mut g = Gx::default();
    let mut rest: Vec<String> = vec![];
    let mut epats: Vec<String> = vec![];
    let mut literal = false;
    let mut it = args.iter().map(String::as_str);
    let num = |name: &str, v: &str| v.trim().parse::<usize>().map_err(|_| format!("grep: {name} needs a number, got '{}'", aix_extract::text::clip(v, 20)));
    let unq = |s: &str| s.trim_matches(|c| c == '\'' || c == '"').to_string();
    let ctx = |g: &mut Gx, which: char, n: usize| {
        g.ctx_asked = g.ctx_asked.max(n);
        let m = n.min(MAX_CONTEXT);
        if which != 'B' {
            g.after = m;
        }
        if which != 'A' {
            g.before = m;
        }
    };
    while let Some(w) = it.next() {
        if literal || !w.starts_with('-') || w == "-" {
            rest.push(w.to_string());
            continue;
        }
        if w == "--" {
            literal = true;
            continue;
        }
        if let Some(long) = w.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            let value = |it: &mut dyn Iterator<Item = &str>| -> Result<String, String> {
                inline.clone().or_else(|| it.next().map(str::to_string)).ok_or_else(|| format!("grep: --{name} needs a value"))
            };
            match name {
                "in" => g.within = value(&mut it)?,
                "scripts" => g.scripts = true,
                "ignore-case" => g.icase = true,
                "no-ignore-case" => g.icase = false,
                "word-regexp" => g.word = true,
                "line-regexp" => g.line = true,
                "fixed-strings" => g.fixed = true,
                "extended-regexp" => g.ere = true,
                "basic-regexp" => g.ere = false,
                "files-with-matches" => g.files_only = true,
                "count" => {} // aix's own --count (count first: a breakdown and narrower commands, lib.rs plan), not GNU -c
                "line-number" | "recursive" | "dereference-recursive" | "no-heading" | "with-filename" | "no-messages" | "text" | "line-buffered" | "initial-tab" if inline.is_none() => {
                    if name == "initial-tab" {
                        return Err(refuse("--initial-tab", ""));
                    }
                }
                "no-filename" => {
                    g.no_filename = true;
                    g.gnu = true;
                }
                "invert-match" => (g.invert, g.gnu) = (true, true),
                "only-matching" => (g.only, g.gnu) = (true, true),
                "files-without-match" => (g.files_without, g.gnu) = (true, true),
                "quiet" | "silent" => (g.quiet, g.gnu) = (true, true),
                "max-count" => {
                    g.max_count = Some(num("--max-count", &value(&mut it)?)?);
                    g.gnu = true;
                }
                "regexp" => epats.push(value(&mut it)?),
                "glob" => g.globs.push(unq(&value(&mut it)?)),
                "type" => {
                    let v = unq(&value(&mut it)?);
                    let gs = crate::query::type_globs(&v).ok_or_else(|| format!("grep: unknown --type '{v}'"))?;
                    g.globs.extend(gs.iter().map(|s| s.to_string()));
                }
                "include" | "exclude" => {
                    g.incl.push((name == "include", unq(&value(&mut it)?)));
                    g.gnu = true;
                }
                "exclude-dir" => {
                    g.excl_dir.push(unq(&value(&mut it)?).trim_end_matches('/').to_string());
                    g.gnu = true;
                }
                "after-context" | "before-context" | "context" => {
                    let n = num(&format!("--{name}"), &value(&mut it)?)?;
                    ctx(&mut g, if name == "after-context" { 'A' } else if name == "before-context" { 'B' } else { 'C' }, n);
                }
                "color" | "colour" => {}
                "binary-files" => {
                    let v = value(&mut it)?;
                    if !matches!(v.as_str(), "without-match" | "text") {
                        return Err(refuse(&format!("--binary-files={v}"), " (indexed files are text)"));
                    }
                }
                "and" | "not" => {
                    let v = value(&mut it)?;
                    if name == "and" { g.and_res.push(v) } else { g.not_res.push(v) }
                    g.gnu = true;
                }
                "not-in" => {
                    g.not_in.push(value(&mut it)?);
                    g.gnu = true;
                }
                "body" => (g.body, g.gnu) = (true, true),
                "member" => (g.member, g.gnu) = (true, true),
                "group" => {
                    g.group = Some(num("--group", &value(&mut it)?)?);
                    g.gnu = true;
                }
                "count-by" => {
                    let v = value(&mut it)?.to_ascii_lowercase();
                    let k = v.split(':').next().unwrap_or("");
                    if !matches!(k, "match" | "file" | "dir" | "ext") || (k != "dir" && v.contains(':')) || (k == "dir" && v.split(':').nth(1).is_some_and(|d| d.parse::<usize>().is_err())) {
                        return Err(format!("grep: --count-by takes match, file, dir[:N] or ext (got '{v}')"));
                    }
                    g.count_by = Some(v);
                    g.gnu = true;
                }
                "total" => (g.total, g.gnu) = (true, true),
                "within" => (g.ranges_only, g.gnu) = (true, true),
                "bare" => (g.bare, g.gnu) = (true, true),
                "width" => {
                    g.width = Some(num("--width", &value(&mut it)?)?);
                    g.gnu = true;
                }
                "head" => {
                    g.head = Some(num("--head", &value(&mut it)?)?.max(1));
                    g.gnu = true;
                }
                "perl-regexp" => return Err(refuse("--perl-regexp", " (no look-around / back-references in the linear-time engine)")),
                _ => return Err(refuse(&format!("--{name}"), "")),
            }
            continue;
        }
        // short flags, clustered (`-rnI`, `-in`); a value flag takes the rest of the word or the next word
        let cs: Vec<char> = w[1..].chars().collect();
        // `-5`: GNU's -C 5
        if cs.iter().all(|c| c.is_ascii_digit()) {
            ctx(&mut g, 'C', num("-NUM", &w[1..])?);
            continue;
        }
        // GNU-style call: a flag that is a no-op here because aix always does it (-n -r -H -s -I ...)
        g.short_flags |= cs.iter().any(|c| matches!(c, 'n' | 'r' | 'R' | 'H' | 's' | 'I' | 'a'));
        let mut k = 0;
        while k < cs.len() {
            let c = cs[k];
            match c {
                'i' | 'y' => g.icase = true,
                'w' => g.word = true,
                'x' => g.line = true,
                'F' => g.fixed = true,
                'E' => g.ere = true,
                'G' => g.ere = false,
                'l' => g.files_only = true,
                'c' => g.count = true,
                'n' | 'r' | 'R' | 'H' | 's' | 'I' | 'a' => {}
                'h' => (g.no_filename, g.gnu) = (true, true),
                'v' => (g.invert, g.gnu) = (true, true),
                'o' => (g.only, g.gnu) = (true, true),
                'L' => (g.files_without, g.gnu) = (true, true),
                'q' => (g.quiet, g.gnu) = (true, true),
                'e' | 'g' | 't' | 'A' | 'B' | 'C' | 'm' => {
                    let tail: String = cs[k + 1..].iter().collect();
                    let v = if !tail.is_empty() { tail } else { it.next().map(str::to_string).ok_or_else(|| format!("grep: -{c} needs a value"))? };
                    match c {
                        'e' => epats.push(v),
                        'g' => g.globs.push(unq(&v)),
                        't' => {
                            let gs = crate::query::type_globs(&unq(&v)).ok_or_else(|| format!("grep: unknown -t {}", unq(&v)))?;
                            g.globs.extend(gs.iter().map(|s| s.to_string()));
                        }
                        'm' => {
                            g.max_count = Some(num("-m", &v)?);
                            g.gnu = true;
                        }
                        _ => {
                            let n = num(&format!("-{c}"), &v)?;
                            ctx(&mut g, c, n);
                        }
                    }
                    break;
                }
                'P' => return Err(refuse("-P", " (no look-around / back-references in the linear-time engine)")),
                'f' => return Err(refuse("-f FILE", " (patterns from a file)")),
                'z' | 'Z' | 'U' | 'b' | 'u' | 'T' | 'd' | 'D' | 'V' => return Err(refuse(&format!("-{c}"), "")),
                _ => return Err(refuse(&format!("-{c}"), "")),
            }
            k += 1;
        }
    }
    if g.ctx_asked > MAX_CONTEXT {
        g.notes.push(format!("(context capped at {MAX_CONTEXT} lines per side, {} asked: for a longer range use aix code FILE:A-B)", g.ctx_asked));
    }
    // the pattern: -e values, else the first word
    if epats.is_empty() {
        if rest.is_empty() {
            return Err("usage: aix grep <regex> [GNU grep flags] [path|glob|-]...".to_string());
        }
        // `grep --and A path`: --and adds a regex to the main one, it is not the main one (the path would be searched for)
        if (!g.and_res.is_empty() || !g.not_res.is_empty()) && rest.len() == 1 && crate::opts::resolve_path(ix, &rest[0]).is_some() {
            return Err(format!("grep: --and/--not add a condition to the main regex, and none was given ('{}' is a path): aix grep <regex> --and <regex2> [path]", rest[0]));
        }
        g.pats.push(rest.remove(0));
    } else {
        g.pats = epats;
    }
    // every trailing word that names an indexed path, `-` (row input) or an unexpanded path glob is a path
    let mut keep: Vec<String> = vec![];
    while let Some(last) = rest.pop() {
        if last == "-" {
            g.stdin = true;
            g.gnu = true;
            continue;
        }
        if let Some(p) = crate::opts::resolve_path(ix, &last) {
            g.paths.insert(0, p);
            continue;
        }
        if is_root_word(ix, &last) {
            continue; // `.`, `./`, the repo's own path, a `..` that comes back to the root: the whole repo
        }
        if last.contains(['*', '?', '[']) && (last.contains('/') || last.contains('.')) {
            g.path_globs.insert(0, crate::opts::clean_path(&last));
            g.gnu = true;
            continue;
        }
        // a path word that names nothing indexed: GNU's "No such file" (the other paths are still searched)
        let exact = EXACT.with(|c| c.get());
        if (exact || file_shaped(&last)) && !last.contains(char::is_whitespace) {
            g.missing.insert(0, last);
            continue;
        }
        keep.insert(0, last);
        break;
    }
    if !g.missing.is_empty() {
        if g.paths.is_empty() && g.path_globs.is_empty() && !g.stdin {
            // nothing left to search: not a "no match"
            return Err(format!("\u{1}{}", crate::query::path_miss(ix, &g.missing[0])));
        }
        g.gnu = true;
    }
    // a word between the pattern and the paths
    let mut words: Vec<String> = rest;
    words.extend(keep);
    if let Some(cand) = words.last() {
        let c = crate::opts::clean_path(cand);
        let on_disk = !c.is_empty() && ix.repo.join(&c).exists();
        if crate::opts::path_shaped(cand) || on_disk {
            return Err(format!("\u{1}{}", crate::query::path_miss(ix, cand)));
        }
        // `grep foo bar` from a hook or MCP string means the phrase "foo bar" (as the plain search reads it)
        if g.pats.len() == 1 {
            let p = format!("{} {}", g.pats[0], words.join(" "));
            g.pats[0] = p;
        } else {
            return Err(format!("\u{1}path not found: {cand}"));
        }
    }
    if g.ranges_only && !g.stdin {
        return Err("grep: --within limits the search to the ranges of row input; give `-` and pipe rows in (e.g. aix callers X | aix grep RE - --within)".to_string());
    }
    if g.only && (g.after + g.before > 0) {
        return Err("grep: -o with -A/-B/-C is not supported (GNU prints only `--` separators there); drop the context flags".to_string());
    }
    if g.group.is_some() && !g.only && g.count_by.as_deref() != Some("match") {
        return Err("grep: --group N picks the capture group that -o (or --count-by match) prints; add -o".to_string());
    }
    if g.files_only && g.files_without {
        return Err("grep: -l and -L together list nothing useful; pick one".to_string());
    }
    // several paths, globs, -c/-l (exact totals), a context wider than the plain search shows: this engine
    if g.count || g.files_only || !g.incl.is_empty() {
        g.gnu = true;
    }
    // the global output options (outfmt.rs took them out of the words wherever they stood): OR'ed with grep's own
    let f = crate::outfmt::current();
    if f.bare {
        (g.bare, g.gnu) = (true, true);
    }
    if g.width.is_none() {
        g.width = f.width;
    }
    if g.head.is_none() && g.gnu {
        // this engine caps --head itself (lib.rs pages only the plain ranked search)
        g.head = f.head;
    }
    // GNU-style call (short flags) without -E/-F: an unescaped | + ? ( is read as ERE here, literally by GNU BRE
    if g.short_flags && !g.ere && !g.fixed && g.pats.iter().any(|p| unescaped_ere(p)) {
        g.notes.push("(note: without -E, an unescaped | + ? ( is read as ERE here (GNU grep's BRE reads it literally); escape it, or add -E to say ERE)".to_string());
    }
    Ok(g)
}

/// Regex source for one pattern (BRE translated unless -E/-F), and the translation note.
fn pat_src(p: &str, g: &Gx, notes: &mut Vec<(String, String)>) -> String {
    if g.fixed {
        return regex::escape(p);
    }
    if !g.ere {
        // a GNU-style call (short flags) reads a lone `\(x\)` group as GNU does too
        let gnu_group = || (g.gnu && p.contains("\\(") && p.matches("\\(").count() == p.matches("\\)").count()).then(|| crate::query::bre_unescape(p));
        if let Some(t) = crate::query::bre_to_ere(p).or_else(gnu_group) {
            notes.push((p.to_string(), t.clone()));
            return t;
        }
    }
    p.to_string()
}

// crlf: `$` before a CR too, as on the lines grep prints (the whole-file prefilter sees a CRLF file's raw text)
fn build(src: &str, icase: bool, from_bre: bool) -> Result<Regex, String> {
    crate::query::grep_regex(src, icase, true, from_bre)
}

/// GNU fnmatch for --include/--exclude/--exclude-dir: `*` `?` `[...]` and `\x`; matched against a base name.
pub fn fnmatch(glob: &str, name: &str) -> bool {
    let mut re = String::from("^");
    let cs: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '\\' if i + 1 < cs.len() => {
                i += 1;
                re.push_str(&regex::escape(&cs[i].to_string()));
            }
            '[' => {
                // a bracket expression up to the closing `]` (a `]` right after `[` or `[!` is literal)
                let mut j = i + 1;
                if j < cs.len() && (cs[j] == '!' || cs[j] == '^') {
                    j += 1;
                }
                if j < cs.len() && cs[j] == ']' {
                    j += 1;
                }
                while j < cs.len() && cs[j] != ']' {
                    j += 1;
                }
                if j >= cs.len() {
                    re.push_str(r"\[");
                } else {
                    let body: String = cs[i + 1..j].iter().collect();
                    let body = if let Some(b) = body.strip_prefix('!') { format!("^{b}") } else { body };
                    re.push('[');
                    re.push_str(&body.replace('\\', r"\\").replace('[', r"\[").replace("\\[:", "[:"));
                    re.push(']');
                    i = j;
                }
            }
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    Regex::new(&re).is_ok_and(|r| r.is_match(name))
}

/// A path glob typed as a trailing word (`src/*.ts`, unexpanded by a shell or sent from MCP): `*`/`?` stay inside one
/// path segment, `**` crosses them.
fn path_glob(g: &str) -> Option<Regex> {
    let mut re = String::from("^");
    let cs: Vec<char> = g.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '*' if cs.get(i + 1) == Some(&'*') => {
                re.push_str(".*");
                i += 1;
                if cs.get(i + 1) == Some(&'/') {
                    i += 1;
                    re.push_str("/?");
                }
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push_str("(?:/.*)?$");
    Regex::new(&re).ok()
}

/// Is this file in the GNU --include/--exclude/--exclude-dir set? (last matching option wins; with none matching a
/// file is included unless the first such option is --include)
fn gnu_selected(g: &Gx, path: &str) -> bool {
    let (dir, base) = path.rsplit_once('/').map_or(("", path), |(d, b)| (d, b));
    if !g.excl_dir.is_empty() && !dir.is_empty() && dir.split('/').any(|seg| g.excl_dir.iter().any(|x| fnmatch(x, seg) || (x.contains('/') && path.starts_with(&format!("{x}/"))))) {
        return false;
    }
    if g.incl.is_empty() {
        return true;
    }
    match g.incl.iter().rev().find(|(_, gl)| fnmatch(gl, base)) {
        Some((inc, _)) => *inc,
        None => !g.incl[0].0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum K {
    Sel,
    Ctx,
}

struct FileRes {
    file: String,
    /// selected lines (after -m)
    n: usize,
    /// printed lines: (line number 1-based, text, kind)
    lines: Vec<(usize, String, K)>,
    /// -o / --count-by match: (line, matched text)
    frags: Vec<(usize, String)>,
    /// selected lines printed with part of them redacted
    masked: usize,
}

/// The engine. Returns false when the plain ranked search should answer instead.
pub fn grep(ix: &Index, args: &[String], budget_ms: u128, out: &mut Out) -> bool {
    let mut g = match parse(ix, args) {
        Ok(g) => g,
        Err(e) => {
            if let Some(p) = e.strip_prefix('\u{1}') {
                out.emit(p.to_string());
                out.exit_code = Some(1);
            } else {
                out.fail_usage(e);
            }
            return true;
        }
    };
    // a context wider than the plain search's own cap, or an explicit width: still the plain search's job unless a
    // GNU-only flag is present
    if !g.gnu {
        for n in &g.notes {
            out.emit(n.clone());
        }
        return false;
    }
    let width = g.width.unwrap_or(DEFAULT_WIDTH);
    // the matchers
    let mut bre = vec![];
    let srcs: Vec<String> = g.pats.iter().flat_map(|p| if g.fixed { p.split('\n').map(str::to_string).collect::<Vec<_>>() } else { vec![p.clone()] }).map(|p| pat_src(&p, &g, &mut bre)).collect();
    let alt = if srcs.len() == 1 { srcs[0].clone() } else { srcs.iter().map(|s| format!("(?:{s})")).collect::<Vec<_>>().join("|") };
    // -w: GNU's rule (the match is preceded and followed by a non-word character or the line edge), not `\b`:
    // `-w '-x'` matches " -x " where `\b-x\b` does not. Group 1 is the word itself.
    let (src, shift) = if g.line {
        (format!("^(?:{alt})$"), 0)
    } else if g.word {
        (format!(r"(?:^|[^\w])((?:{alt}))(?:[^\w]|$)"), 1)
    } else {
        (alt, 0)
    };
    let re = match build(&src, g.icase, !bre.is_empty()) {
        Ok(r) => r,
        Err(e) => {
            out.fail_usage(e);
            return true;
        }
    };
    let mk = |v: &[String], bre: &mut Vec<(String, String)>| -> Result<Vec<Regex>, String> {
        v.iter().map(|p| { let n = bre.len(); let src = pat_src(p, &g, bre); build(&src, g.icase, bre.len() > n) }).collect()
    };
    let (and_res, not_res) = match (mk(&g.and_res, &mut bre), mk(&g.not_res, &mut bre)) {
        (Ok(a), Ok(n)) => (a, n),
        (Err(e), _) | (_, Err(e)) => {
            out.fail_usage(e);
            return true;
        }
    };
    let want_group = g.group.unwrap_or(0) + if g.group.is_some() { shift } else { 0 };
    if g.group.is_some() && want_group >= re.captures_len() {
        out.fail_usage(format!("grep: --group {}: the pattern has {} capture group(s)", g.group.unwrap_or(0), re.captures_len() - 1 - shift));
        return true;
    }
    g.bre_from = bre;
    // row input
    let mut ranges: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    let mut row_files: Option<(HashSet<String>, Vec<String>)> = None;
    if g.stdin {
        // the shared row parser (rows.rs): rows injected by an in-call pipe, else the CLI's stdin
        let input = match crate::rows::parse_stdin(Some(ix)) {
            Ok(r) => r,
            Err(e) => {
                out.fail_usage(format!("grep -: {e}"));
                return true;
            }
        };
        // (file, start, end, point): a hit names a line (`--within` widens it to the enclosing member), a range its
        // lines, a file or a per-file count the whole file; a directory ends with `/`
        let mut rows: Vec<(String, usize, usize, bool)> = vec![];
        for (r, _) in input.iter() {
            match r {
                crate::rows::Row::Hit { path, line, .. } => rows.push((path.clone(), *line, *line, true)),
                crate::rows::Row::Range { path, a, b } => rows.push((path.clone(), *a, (*b).max(*a), false)),
                crate::rows::Row::File { path } => rows.push((path.clone(), 0, 0, false)),
                crate::rows::Row::Count { .. } => {
                    if let Some(p) = r.path() {
                        rows.push((p.to_string(), 0, 0, false));
                    }
                }
                crate::rows::Row::Text { .. } => {}
            }
        }
        let ignored = input.len() - rows.len();
        if rows.is_empty() {
            out.emit(format!("== no rows in the input name an indexed file ({ignored} lines ignored): nothing to search"));
            out.exit_code = Some(1);
            return true;
        }
        let (mut fs, mut ds) = (HashSet::new(), vec![]);
        for (file, start, end, point) in &rows {
            let file = file.trim_end_matches('/');
            if ix.conn.query_row("SELECT 1 FROM files WHERE path=?", [file], |_| Ok(())).is_ok() {
                fs.insert(file.to_string());
                if g.ranges_only {
                    let (a, b) = if *start == 0 {
                        (1, usize::MAX)
                    } else if *point {
                        enclosing(ix, file, *start).map(|m| (m.0, m.1)).unwrap_or((*start, *end))
                    } else {
                        (*start, *end)
                    };
                    ranges.entry(file.to_string()).or_default().push((a, b));
                }
            } else {
                ds.push(format!("{file}/"));
            }
        }
        if !g.bare {
            if ignored > 0 {
                out.emit(format!("(row input: {} rows, {ignored} lines ignored)", rows.len()));
            }
            if let Some(n) = crate::rows::input_note(&input, false) {
                out.emit(n);
            }
        }
        row_files = Some((fs, ds));
    }
    // scope
    let sql = if g.scripts {
        "SELECT f.path FROM files f JOIN scripts s ON s.file = f.path WHERE aix_drop(f.path)=0 ORDER BY f.path"
    } else {
        "SELECT path FROM files WHERE aix_drop(path)=0 ORDER BY path"
    };
    let globs = if g.globs.is_empty() {
        None
    } else {
        let mut b = ignore::overrides::OverrideBuilder::new("/");
        for x in &g.globs {
            if let Err(e) = b.add(x) {
                out.fail_usage(format!("bad glob '{}': {}", aix_extract::text::clip(x, 40), e.to_string().lines().next().unwrap_or("")));
                return true;
            }
        }
        b.build().ok()
    };
    let pglobs: Vec<Regex> = g.path_globs.iter().filter_map(|x| path_glob(x)).collect();
    let dirps: Vec<String> = g.paths.iter().map(|p| format!("{p}/")).collect();
    let in_scope = |p: &str| {
        (g.within.is_empty() || p.contains(&g.within))
            && !g.not_in.iter().any(|x| p.contains(x.as_str()))
            && ((g.paths.is_empty() && pglobs.is_empty()) || g.paths.iter().zip(&dirps).any(|(x, d)| p == x || p.starts_with(d.as_str())) || pglobs.iter().any(|r| r.is_match(p)))
            && globs.as_ref().is_none_or(|gl| !gl.matched(std::path::Path::new(p), false).is_ignore())
            && gnu_selected(&g, p)
            && row_files.as_ref().is_none_or(|(fs, ds)| fs.contains(p) || ds.iter().any(|d| p.starts_with(d.as_str())))
    };
    let files: Vec<String> = crate::query::rows(&ix.conn, sql, &[]).into_iter().map(|r| r[0].clone()).filter(|p| in_scope(p)).collect();
    let repo = ix.repo.clone();
    let max_bytes = ix.cfg.max_file_bytes;
    let t0 = std::time::Instant::now();
    let done = std::sync::atomic::AtomicUsize::new(0);
    let timed_out = std::sync::atomic::AtomicBool::new(false);
    let need_all = g.invert || g.files_without || (g.count && !g.paths.is_empty());
    let frag_mode = g.only || g.count_by.as_deref() == Some("match");
    let (before, after) = if g.count || g.files_only || g.files_without || g.quiet || g.count_by.is_some() || g.total || g.member { (0, 0) } else { (g.before, g.after) };
    // matches count only outside redacted spans (`raw`: the file's line, `red`: what is printed)
    let vis = |r: &Regex, raw: &str, red: &str| aix_extract::text::visible_match(r, raw, red);
    let selects = |l: &str, red: &str| -> bool {
        (vis(&re, l, red) != g.invert) && and_res.iter().all(|r| vis(r, l, red)) && !not_res.iter().any(|r| vis(r, l, red))
    };
    let frags_of = |l: &str| -> Vec<String> {
        let mut v = vec![];
        let mut pos = 0;
        while pos <= l.len() {
            let Some(c) = re.captures_at(l, pos) else { break };
            // the match itself (with -w: the word, not the edge characters around it)
            let w = c.get(shift).unwrap_or_else(|| c.get(0).unwrap());
            let m = if g.group.is_some() { c.get(want_group) } else { Some(w) };
            if let Some(m) = m.filter(|m| !m.as_str().is_empty()) {
                v.push(m.as_str().to_string());
            }
            let mut next = w.end();
            if next <= pos || w.start() == w.end() {
                next = pos.max(w.start()) + 1;
                while next < l.len() && !l.is_char_boundary(next) {
                    next += 1;
                }
            }
            pos = next;
        }
        v
    };
    use rayon::prelude::*;
    let mut res: Vec<FileRes> = files
        .par_iter()
        .filter_map(|f| {
            if budget_ms == 0 || t0.elapsed().as_millis() > budget_ms {
                timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            let t = crate::query::read_for_grep(&repo, f, max_bytes)?;
            done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if !need_all && !re.is_match(&t) {
                return None;
            }
            // select on the file's own text, print the redacted line (a masked token is still found, a mask label
            // never matches; what is printed is never a secret)
            let (raw, lines) = aix_extract::text::select_and_show(&t);
            let at = |k: usize| -> &str { if raw.is_empty() { lines[k].as_str() } else { raw[k] } };
            let rg = ranges.get(f.as_str());
            let in_rg = |k: usize| rg.is_none_or(|v| v.iter().any(|(a, b)| k + 1 >= *a && k < *b));
            let mut sel: Vec<usize> = vec![];
            for k in 0..lines.len() {
                if g.max_count.is_some_and(|m| sel.len() >= m) {
                    break;
                }
                if in_rg(k) && selects(at(k), &lines[k]) {
                    sel.push(k);
                }
            }
            let masked = sel.iter().filter(|&&k| at(k) != lines[k]).count();
            let mut fr = FileRes { file: f.clone(), n: sel.len(), lines: vec![], frags: vec![], masked };
            if frag_mode && !g.invert {
                for &k in &sel {
                    // a match inside a redacted span is not a match (no oracle): only visible fragments count
                    for m in frags_of(at(k)) {
                        if at(k) == lines[k] || aix_extract::text::visible_text(&m, &lines[k]) {
                            fr.frags.push((k + 1, aix_extract::text::shown_fragment(at(k), &lines[k], &m)));
                        }
                    }
                }
            }
            if !(g.count || g.files_only || g.files_without || g.quiet || g.total || g.only) {
                let mut show: BTreeMap<usize, K> = BTreeMap::new();
                for &k in &sel {
                    for c in k.saturating_sub(before)..k {
                        show.entry(c).or_insert(K::Ctx);
                    }
                    show.insert(k, K::Sel);
                    // after -m's last line GNU prints the trailing context even when it holds matching lines
                    let stop = (k + after).min(lines.len().saturating_sub(1));
                    for c in k + 1..=stop {
                        show.entry(c).or_insert(K::Ctx);
                    }
                }
                fr.lines = show.into_iter().map(|(k, kind)| (k + 1, lines[k].clone(), kind)).collect();
            }
            let keep = if g.files_without { sel.is_empty() } else { !sel.is_empty() || g.count && explicit_file(&g, f) };
            keep.then_some(fr)
        })
        .collect();
    // --bare keeps the plain order (source first), so `--bare --head N` is the same rows as plain/json
    if g.count_by.is_some() {
        res.sort_by(|a, b| a.file.cmp(&b.file));
    } else {
        res.sort_by(|a, b| path_rank(&a.file).cmp(&path_rank(&b.file)).then_with(|| a.file.cmp(&b.file)));
    }
    let total: usize = res.iter().map(|r| r.n).sum();
    let nfiles = res.iter().filter(|r| r.n > 0).count();
    let scanned = done.load(std::sync::atomic::Ordering::Relaxed);
    let partial = timed_out.load(std::sync::atomic::Ordering::Relaxed);
    let ms = t0.elapsed().as_millis();
    out.weights = Some(res.iter().filter(|r| r.n > 0).map(|r| (r.file.clone(), r.n)).collect());
    // GNU's status: 0 when a line was selected (with -L too, as GNU grep 3.5+), 1 when none
    let gnu_found = total > 0 || (g.files_without && files.len() > res.len());
    out.exit_code = Some(if gnu_found { 0 } else { 1 });
    if !g.missing.is_empty() {
        // GNU: the files that exist are searched, each missing one is an error, the status is 2
        for m in &g.missing {
            let line = format!("grep: {m}: no such indexed file or directory");
            if g.bare {
                out.stderr.push(line);
            } else {
                out.emit(format!("== {line}"));
            }
        }
        out.exit_code = Some(2);
    }
    out.bare = g.bare;
    let partial_line = || {
        format!("== partial: scanned {scanned} of {} files in {ms} ms (budget {budget_ms} ms): the answer below is incomplete; narrow it (a path, --in, -g) or run rg", files.len())
    };
    if partial {
        // a budget-cut scan is never a complete answer: every output form says so, and "nothing found" in it is not
        // a "no match" (exit 2)
        out.truncated = true;
        if g.bare || g.quiet {
            out.stderr.push(partial_line());
        }
        if !gnu_found {
            out.exit_code = Some(2);
        }
    }
    if g.quiet {
        out.exists = Some(gnu_found);
        out.bare = true; // nothing around the (empty) answer
        return true;
    }
    let full = out.limit >= crate::FULL_ROWS;
    let user_cap = if out.limit == 20 { None } else { Some(out.limit) };
    let cap = g.head.or(user_cap);
    let fname = |f: &str| if g.no_filename { String::new() } else { format!("{f}:") };
    let mut notes = g.notes.clone();
    // wanted files the index could not hold (too big, unusable name) inside this search: named in every output form
    let skipped: Vec<(String, String)> = ix
        .meta("skipped")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('\t'))
        .filter(|(_, p)| in_scope(p) && (!g.scripts || p.starts_with("scripts/")))
        .map(|(why, p)| (why.to_string(), p.to_string()))
        .collect();
    if !skipped.is_empty() {
        let mut why: Vec<&str> = skipped.iter().map(|s| s.0.as_str()).collect();
        why.sort();
        why.dedup();
        let names: Vec<&str> = skipped.iter().take(5).map(|s| s.1.as_str()).collect();
        let more = if skipped.len() > 5 { format!(" and {} more", skipped.len() - 5) } else { String::new() };
        notes.push(format!("({} file{} in scope not searched ({}): {}{more}; rg covers {})", skipped.len(), if skipped.len() == 1 { "" } else { "s" }, why.join("/"), names.join(", "), if skipped.len() == 1 { "it" } else { "them" }));
    }
    if !g.stdin && !g.quiet {
        if let Some(n) = crate::query::unsupported_note(ix, &|p: &str| in_scope(p) && (!g.scripts || p.starts_with("scripts/"))) {
            notes.push(n);
        }
    }
    let masked: usize = res.iter().map(|r| r.masked).sum();
    if masked > 0 && !g.files_without {
        notes.push(format!("({masked} matching line{} shown with part of {} redacted (***): the match is in the file, never use them as edit anchors)", if masked == 1 { "" } else { "s" }, if masked == 1 { "it" } else { "them" }));
    }
    if files.is_empty() && (!g.globs.is_empty() || !g.path_globs.is_empty()) {
        // nothing was searched: the scope itself matched no file (not "no match in it")
        let gl: Vec<String> = g.globs.iter().chain(&g.path_globs).map(|x| crate::shell_quote(x)).collect();
        notes.push(format!("== the scope matched no indexed file (glob {}): check it with aix files <glob> [dir]", gl.join(" ")));
    }
    if g.bare {
        // the rows stay clean; what explains an empty or odd answer goes to stderr
        out.stderr.extend(notes.iter().cloned());
    }
    if !g.bare {
        for n in &notes {
            out.emit(n.clone());
        }
        for (from, to) in &g.bre_from {
            out.emit(format!("(read as GNU grep BRE: {} -> {}; add -E to match the backslashes literally)", aix_extract::text::clip(from, 60), aix_extract::text::clip(to, 60)));
        }
        if partial {
            out.emit(partial_line());
        }
    }
    // ── aggregates ──
    if g.total || g.count_by.is_some() {
        let mut groups: BTreeMap<String, usize> = BTreeMap::new();
        match g.count_by.as_deref() {
            Some("match") => {
                for r in &res {
                    for (_, m) in &r.frags {
                        *groups.entry(m.clone()).or_default() += 1;
                    }
                }
            }
            Some(k) => {
                let (key, depth) = crate::group::split_key(k);
                for r in res.iter().filter(|r| r.n > 0) {
                    let kk = if key == "ext" {
                        crate::walk::ext_lower(&r.file).to_string()
                    } else {
                        crate::group::file_key(&r.file, &key, depth)
                    };
                    *groups.entry(if kk.is_empty() { "(none)".into() } else { kk }).or_default() += r.n;
                }
            }
            None => {}
        }
        let mut gv: Vec<(String, usize)> = groups.into_iter().collect();
        gv.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if g.total {
            if g.bare {
                out.emit(total.to_string());
            } else {
                out.emit(format!("== total: {total} matching lines in {nfiles} files ({scanned} indexed files searched, {ms} ms)"));
            }
        }
        if g.count_by.is_some() {
            let gtotal: usize = gv.iter().map(|x| x.1).sum();
            let show = if full { usize::MAX } else { cap.unwrap_or(if g.bare { crate::MAX_ROWS } else { 50 }) };
            for (k, n) in gv.iter().take(show) {
                out.emit(if g.bare { format!("{n}\t{k}") } else { format!("{n:>6}  {k}") });
            }
            if gv.len() > show {
                out.truncated = true;
                out.emit(format!("(total {gtotal} in {} groups; {show} shown: {} more groups not shown, add --head {})", gv.len(), gv.len() - show, gv.len()));
            } else if !g.bare {
                out.emit(format!("(total {gtotal} in {} groups by {})", gv.len(), g.count_by.as_deref().unwrap_or("")));
            }
        }
        return true;
    }
    // ── file lists and counts: exact, never "too broad" ──
    if g.files_only || g.files_without || g.count {
        let list: Vec<&FileRes> = res.iter().collect();
        if !g.bare {
            let what = if g.files_without { format!("{} files without a match ({} searched)", list.len(), scanned) } else { format!("{total} matching lines in {nfiles} files ({scanned} indexed files searched, {ms} ms)") };
            out.emit(format!("== {what}"));
        }
        let show = if full { usize::MAX } else { cap.unwrap_or(if g.bare { crate::MAX_ROWS } else { 100 }) };
        for r in list.iter().take(show) {
            let row = if g.count {
                if g.bare { format!("{}{}", fname(&r.file), r.n) } else { format!("  {}: {}", r.file, r.n) }
            } else if g.bare {
                r.file.clone()
            } else {
                format!("  {}", r.file)
            };
            out.emit(row);
            out.hit("grep", &r.file, 0, "");
        }
        if list.len() > show {
            out.truncated = true;
            out.emit(format!("== {} more files not shown (exact list: add --head {} or page with --page 2 --per-page {show})", list.len() - show, list.len()));
        }
        if !g.bare && !gnu_found && !g.files_without {
            out.lines.push("== no match in the indexed files (untracked, gitignored, secret and oversized files are not indexed: `rg` covers those)".to_string());
        }
        return true;
    }
    if !g.bare {
        let what = if g.invert { "selected (non-matching) lines" } else { "matching lines" };
        out.emit(format!("== {total} {what} in {nfiles} files ({scanned} indexed files searched, {ms} ms)"));
    }
    // ── --member / --body: each hit's enclosing member once ──
    if g.member || g.body {
        let mut shown = 0usize;
        let limit = if full { usize::MAX } else { cap.unwrap_or(if g.member { 50 } else { 8 }) };
        let mut groups_n = 0usize;
        'files: for r in &res {
            let mut seen: BTreeSet<(usize, usize)> = BTreeSet::new();
            let sel: Vec<usize> = r.lines.iter().filter(|x| x.2 == K::Sel).map(|x| x.0).collect();
            for &ln in &sel {
                let m = enclosing(ix, &r.file, ln);
                let (a, b, label) = m.clone().unwrap_or((ln, ln, "(top level)".to_string()));
                if !seen.insert((a, b)) {
                    continue;
                }
                groups_n += 1;
                if shown >= limit {
                    continue;
                }
                shown += 1;
                let hits: Vec<usize> = sel.iter().copied().filter(|x| *x >= a && *x <= b).collect();
                if g.member {
                    out.emit(if g.bare { format!("{}:{a}-{b}\t{label}\t{}", r.file, hits.len()) } else { format!("  {}:{a}-{b} {label} ({} hits)", r.file, hits.len()) });
                    out.hit("grep", &r.file, a as i64, &label);
                    continue;
                }
                let Some(t) = crate::query::read_for_grep(&ix.repo, &r.file, ix.cfg.max_file_bytes) else { continue 'files };
                let lines = aix_extract::text::select_and_show(&t).1;
                let body_cap = if full { usize::MAX } else { 80 };
                if !g.bare {
                    out.emit(format!("== {}:{a}-{b} {label} ({} hits)", r.file, hits.len()));
                }
                for k in a..=b.min(a + body_cap - 1).min(lines.len()) {
                    let tx = clipw(&lines[k - 1], width);
                    let hit = hits.contains(&k);
                    out.emit(match (g.bare, hit) {
                        (true, true) => format!("{}{k}:{tx}", fname(&r.file)),
                        (true, false) => format!("{}{k}-{tx}", if g.no_filename { String::new() } else { format!("{}-", r.file) }),
                        (false, true) => format!("  {}:{k}: {tx}", r.file),
                        (false, false) => format!("  {}-{k}- {tx}", r.file),
                    });
                    if hit {
                        out.hit("grep", &r.file, k as i64, &tx);
                    }
                }
                if b + 1 - a > body_cap {
                    out.emit(format!("  … {} more lines: aix code {}:{}-{b}", b + 1 - a - body_cap, r.file, a + body_cap));
                }
            }
        }
        if groups_n > shown {
            out.truncated = true;
            out.emit(format!("== {} more members not shown: add --head {groups_n}", groups_n - shown));
        }
        return true;
    }
    // ── rows ──
    let row_cap = if full { usize::MAX } else { cap.unwrap_or(if g.bare { crate::MAX_ROWS } else { 20 }) };
    let line_budget = if full { usize::MAX } else if g.bare { crate::MAX_ROWS.max(row_cap) } else { 150.max(row_cap) };
    let byte_budget = if full || cap.is_some() { usize::MAX } else { 60 * 1024 }; // an explicit --head N: N rows, whatever their size
    let (mut rows_out, mut lines_out, mut bytes) = (0usize, 0usize, 0usize);
    let mut cut_rows = 0usize;
    let mut prev: Option<(String, usize)> = None;
    let total_rows: usize = if g.only { res.iter().map(|r| r.frags.len()).sum() } else { total };
    for r in &res {
        if g.only {
            for (ln, m) in &r.frags {
                if rows_out >= row_cap || bytes > byte_budget {
                    cut_rows += 1;
                    continue;
                }
                let tx = clipw(m, width);
                let l = if g.bare { format!("{}{ln}:{tx}", fname(&r.file)) } else { format!("  {}:{ln}: {tx}", r.file) };
                bytes += l.len() + 1;
                out.emit(l);
                out.hit("grep", &r.file, *ln as i64, &tx);
                rows_out += 1;
            }
            continue;
        }
        for (ln, text, kind) in &r.lines {
            if rows_out >= row_cap || lines_out >= line_budget || bytes > byte_budget {
                if *kind == K::Sel {
                    cut_rows += 1;
                }
                continue;
            }
            if let Some((pf, pl)) = &prev {
                if (before + after > 0) && (pf != &r.file || *ln > pl + 1) {
                    out.emit(if g.bare { "--".to_string() } else { "  --".to_string() });
                }
            }
            prev = Some((r.file.clone(), *ln));
            let tx = clipw(text, width);
            let l = match (g.bare, kind) {
                (true, K::Sel) => format!("{}{ln}:{tx}", fname(&r.file)),
                (true, K::Ctx) => format!("{}{ln}-{tx}", if g.no_filename { String::new() } else { format!("{}-", r.file) }),
                (false, K::Sel) => format!("  {}:{ln}: {tx}", r.file),
                (false, K::Ctx) => format!("  {}-{ln}- {tx}", r.file),
            };
            bytes += l.len() + 1;
            out.emit(l);
            lines_out += 1;
            if *kind == K::Sel {
                out.hit("grep", &r.file, *ln as i64, &tx);
                rows_out += 1;
            }
        }
    }
    if cut_rows > 0 {
        out.truncated = true;
        let per = rows_out.max(1);
        out.emit(if g.bare {
            // the one continuation-footer style of --bare (outfmt.rs)
            format!("\u{2026} {cut_rows} more matching lines not shown ({total_rows} in all): everything with --head {total_rows}")
        } else {
            format!("== {cut_rows} more matching lines not shown ({total_rows} in all): next page with --page 2 --per-page {per}, or everything with --head {total_rows}")
        });
    }
    if !gnu_found && !g.bare {
        out.emit("== no match in the indexed files (untracked, gitignored, secret and oversized files are not indexed: `rg` covers those)");
    }
    true
}

/// Was `f` named as a file on the command line (GNU -c prints `f:0` for those)?
fn explicit_file(g: &Gx, f: &str) -> bool {
    g.paths.iter().any(|p| p == f)
}

/// The innermost member (not a field) whose span holds `line`: (start, end, "kind name").
pub fn enclosing(ix: &Index, file: &str, line: usize) -> Option<(usize, usize, String)> {
    let l = line as i64;
    ix.conn
        .query_row(
            "SELECT line, end_line, kind, COALESCE(NULLIF(qname,''), name) FROM members WHERE file=?1 AND line<=?2 AND end_line>=?2 AND kind<>'field'
             ORDER BY (kind IN ('class','interface','enum','record','struct','impl','trait','module')), line DESC LIMIT 1",
            rusqlite::params![file, l],
            |r| Ok((r.get::<_, i64>(0)? as usize, r.get::<_, i64>(1)? as usize, format!("{} {}", r.get::<_, String>(2)?, r.get::<_, String>(3)?))),
        )
        .ok()
}
