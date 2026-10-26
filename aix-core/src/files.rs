//! `aix files` (alias `aix ls`): the indexed files, as ls / find / wc -l / test -f would list them.
//!
//! `files [GLOB|DIR|RE|FILE ...] [--name RE] [--ext x,y] [--lines] [--size] [--count] [--group-by dir[:N]|ext]
//!        [--changed [REV]] [--members] [--exists] [--sort path|lines|size] [--limit N] [--page N] [-]`
//! - a positional GLOB uses gitignore rules (`*.ts` at any depth, `src/*.rs` anchored, `**` crosses dirs); a RE (it
//!   has `\ ^ $ ( | + {` or `.*`) is a regex over the path; a DIR lists the files below it (ls: one level); a FILE is
//!   that file; any other word is a smart-case substring of the path. The answer says how each word was read.
//! - find(1) primaries with GNU semantics: `-name/-iname/-path/-ipath GLOB` (fnmatch: `*` matches `/` and a leading
//!   dot), `-type f|d`, `-maxdepth/-mindepth N`, `-newer FILE`, `-not`/`!` before one primary, `-a`/`-and`, `-print`.
//!   Positionals are then start points as in find (`.` = the repo or the working subdirectory). Anything else
//!   (`-o`, parentheses, `-prune`, `-exec`, `-delete`, `-regex`, `-size`, `-mtime` ...) exits 2 naming the find command.
//! - Only indexed files are listed (directories are derived from them): gitignored, secret, binary and oversized
//!   files are not, and the answer says so with the shell command that lists them.
//! - `--changed [REV]`: files changed vs HEAD (or REV), untracked included (git status / git diff --name-only);
//!   `--members`: the members (functions, classes) whose lines the diff touches.
//! - `-` restricts the listing to the files named by the input rows (`aix scope | aix files --changed --lines -`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use regex::Regex;

use crate::index::Index;
use crate::pipe::Answer;
use crate::rows::{Meta, Row};

/// GNU fnmatch(3) with flags 0 (find -name / -path): `*` and `?` match any character including `/` and a leading
/// dot, `[...]` / `[!...]` / `[^...]` with ranges and POSIX classes, `\` escapes. `fold` = -iname / -ipath.
pub fn fnmatch(pat: &str, s: &str, fold: bool) -> bool {
    let p: Vec<char> = if fold { pat.to_lowercase().chars().collect() } else { pat.chars().collect() };
    let t: Vec<char> = if fold { s.to_lowercase().chars().collect() } else { s.chars().collect() };
    fn class(p: &[char], mut i: usize, c: char) -> Option<(bool, usize)> {
        // p[i] is just after '['; returns (matched, index after ']')
        let neg = matches!(p.get(i), Some('!') | Some('^'));
        if neg {
            i += 1;
        }
        let mut hit = false;
        let mut first = true;
        loop {
            let ch = *p.get(i)?;
            if ch == ']' && !first {
                return Some((hit != neg, i + 1));
            }
            first = false;
            if ch == '[' && p.get(i + 1) == Some(&':') {
                let rest: String = p[i + 2..].iter().collect();
                if let Some(end) = rest.find(":]") {
                    let name = &rest[..end];
                    let ok = match name {
                        "alpha" => c.is_alphabetic(),
                        "digit" => c.is_ascii_digit(),
                        "alnum" => c.is_alphanumeric(),
                        "upper" => c.is_uppercase(),
                        "lower" => c.is_lowercase(),
                        "space" => c.is_whitespace(),
                        "punct" => c.is_ascii_punctuation(),
                        "xdigit" => c.is_ascii_hexdigit(),
                        _ => return None,
                    };
                    hit |= ok;
                    i += 2 + name.chars().count() + 2;
                    continue;
                }
            }
            let lo = if ch == '\\' {
                i += 1;
                *p.get(i)?
            } else {
                ch
            };
            if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|x| *x != ']') {
                let hi = *p.get(i + 2)?;
                hit |= lo <= c && c <= hi;
                i += 3;
            } else {
                hit |= lo == c;
                i += 1;
            }
        }
    }
    fn go(p: &[char], t: &[char]) -> bool {
        let (mut pi, mut ti) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while ti < t.len() {
            let step = match p.get(pi) {
                Some('*') => {
                    star = Some((pi, ti));
                    pi += 1;
                    continue;
                }
                Some('?') => Some(pi + 1),
                Some('[') => match class(p, pi + 1, t[ti]) {
                    Some((true, next)) => Some(next),
                    Some((false, _)) => None,
                    None => (t[ti] == '[').then_some(pi + 1), // an unclosed '[' is literal
                },
                Some('\\') if pi + 1 < p.len() => (p[pi + 1] == t[ti]).then_some(pi + 2),
                Some(c) => (*c == t[ti]).then_some(pi + 1),
                None => None,
            };
            match step {
                Some(n) => {
                    pi = n;
                    ti += 1;
                }
                None => match star {
                    Some((sp, st)) => {
                        pi = sp + 1;
                        ti = st + 1;
                        star = Some((sp, st + 1));
                    }
                    None => return false,
                },
            }
        }
        while p.get(pi) == Some(&'*') {
            pi += 1;
        }
        pi == p.len()
    }
    go(&p, &t)
}

#[derive(Debug, Clone)]
enum Prim {
    Name(String, bool),
    Path(String, bool),
    Type(char),
    Newer(Option<SystemTime>),
}

#[derive(Debug, Clone)]
struct Test {
    not: bool,
    p: Prim,
}

#[derive(Debug, Default)]
struct Args {
    pos: Vec<String>,
    tests: Vec<Test>,
    find_mode: bool,
    maxdepth: Option<usize>,
    mindepth: Option<usize>,
    name_re: Option<Regex>,
    exts: Vec<String>,
    lines: bool,
    size: bool,
    count: bool,
    group: Option<(String, usize)>,
    changed: Option<String>,
    members: bool,
    exists: bool,
    sort: String,
    dash: bool,
    /// ls -a / -A: names starting with a dot too
    all: bool,
    limit: Option<usize>,
    page: Option<usize>,
    offset: Option<usize>,
}

struct Ent {
    path: String,
    dir: bool,
    lines: i64,
    bytes: i64,
}

fn usage_err(a: &mut Answer, msg: String) {
    a.fail(msg);
}

fn parse(ix: &Index, toks: &[String], ls: bool) -> Result<Args, String> {
    let mut a = Args { sort: "path".into(), ..Default::default() };
    let mut i = 0;
    let mut not = false;
    let num = |v: Option<&String>, f: &str| v.and_then(|v| v.parse::<usize>().ok()).ok_or_else(|| format!("files: {f} needs a number"));
    let refuse = |t: &str| {
        let shell = toks.iter().map(|x| crate::shell_quote(x)).collect::<Vec<_>>().join(" ");
        format!("files: {t} is not supported (only -name -iname -path -ipath -type f|d -maxdepth -mindepth -newer -not/! -a -print); run it with find: find {shell}")
    };
    while i < toks.len() {
        let t = toks[i].as_str();
        let v = toks.get(i + 1);
        let mut used = 1;
        match t {
            "-a" | "-A" if ls => a.all = true,
            "-1" if ls => {}
            "-" => a.dash = true,
            "-name" | "-iname" | "-path" | "-ipath" | "-wholename" | "-iwholename" => {
                let g = v.ok_or_else(|| format!("files: {t} needs a pattern"))?.clone();
                let fold = t.starts_with("-i");
                let p = if t.contains("name") && !t.contains("whole") { Prim::Name(g, fold) } else { Prim::Path(g, fold) };
                a.tests.push(Test { not, p });
                not = false;
                a.find_mode = true;
                used = 2;
            }
            "-type" => {
                let k = v.ok_or("files: -type needs f or d")?;
                if k != "f" && k != "d" {
                    return Err(refuse(&format!("-type {k}")));
                }
                a.tests.push(Test { not, p: Prim::Type(k.chars().next().unwrap_or('f')) });
                not = false;
                a.find_mode = true;
                used = 2;
            }
            "-newer" => {
                let f = v.ok_or("files: -newer needs a file")?;
                let p = crate::rows::norm(f, Some(ix));
                let m = std::fs::metadata(ix.repo.join(&p)).and_then(|m| m.modified()).map_err(|_| format!("files: -newer: '{f}': No such file or directory"))?;
                a.tests.push(Test { not, p: Prim::Newer(Some(m)) });
                not = false;
                a.find_mode = true;
                used = 2;
            }
            "-maxdepth" => {
                a.maxdepth = Some(num(v, t)?);
                a.find_mode = true;
                used = 2;
            }
            "-mindepth" => {
                a.mindepth = Some(num(v, t)?);
                a.find_mode = true;
                used = 2;
            }
            "-not" | "!" => {
                not = !not;
                a.find_mode = true;
            }
            "-a" | "-and" | "-print" => a.find_mode = true,
            "--name" => {
                let r = v.ok_or("files: --name needs a regex")?;
                a.name_re = Some(Regex::new(r).map_err(|e| format!("files: --name: {e}"))?);
                used = 2;
            }
            "--ext" => {
                let e = v.ok_or("files: --ext needs a list (ts,tsx)")?;
                a.exts.extend(e.split(',').map(|x| x.trim().trim_start_matches('.').to_ascii_lowercase()).filter(|x| !x.is_empty()));
                used = 2;
            }
            "--lines" | "-l" => a.lines = true,
            "--size" => a.size = true,
            "--count" | "-c" => a.count = true,
            "--members" => a.members = true,
            "--exists" | "-q" => a.exists = true,
            "--group-by" | "--by" => {
                let g = v.ok_or("files: --group-by needs dir[:N] or ext")?;
                let (k, d) = crate::group::split_key(g);
                if !matches!(k.as_str(), "dir" | "ext" | "kind" | "lang") {
                    return Err(format!("files: --group-by {g}: keys are dir[:N], ext, kind"));
                }
                a.group = Some((if k == "lang" { "ext".into() } else { k }, d));
                used = 2;
            }
            "--sort" => {
                let s = v.ok_or("files: --sort needs path, lines or size")?;
                if !matches!(s.as_str(), "path" | "lines" | "size") {
                    return Err(format!("files: --sort {s}: path, lines or size"));
                }
                a.sort = s.clone();
                used = 2;
            }
            "--changed" => {
                a.changed = Some("HEAD".into());
                if let Some(r) = v.filter(|r| !r.starts_with('-') && ix.rev_exists(r) && crate::opts::resolve_path(ix, r).is_none()) {
                    a.changed = Some(r.clone());
                    used = 2;
                }
            }
            "--limit" | "--per-page" => {
                a.limit = Some(num(v, t)?.max(1));
                used = 2;
            }
            "--page" => {
                a.page = Some(num(v, t)?.max(1));
                used = 2;
            }
            "--offset" => {
                a.offset = Some(num(v, t)?);
                used = 2;
            }
            "--full" | "--all" => a.limit = Some(crate::FULL_ROWS),
            _ if t.starts_with("--") => return Err(format!("files: unknown option {t} (see aix files --help: --name --ext --lines --size --count --group-by --changed --members --exists --sort)")),
            _ if t.starts_with('-') && t.len() > 1 || t == "(" || t == ")" => return Err(refuse(t)),
            _ => a.pos.push(t.to_string()),
        }
        i += used;
    }
    if not {
        return Err("files: -not / ! must stand before a primary".into());
    }
    if ls && !a.find_mode && a.maxdepth.is_none() {
        a.maxdepth = Some(1);
    }
    Ok(a)
}

/// What a positional word is.
enum Sel {
    Dir(String),
    File(String),
    Glob(ignore::gitignore::Gitignore),
    Re(Regex),
    Sub(String, bool),
}

fn classify(ix: &Index, w: &str) -> Result<Sel, String> {
    static REISH: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"[\\^$()|+{]|\.\*").unwrap());
    if w == "." || w == "./" {
        return Ok(Sel::Dir(cwd()));
    }
    if let Some(p) = crate::opts::resolve_path(ix, w) {
        let is_file: bool = ix.conn.query_row("SELECT 1 FROM files WHERE path=?1", [&p], |_| Ok(())).is_ok();
        return Ok(if is_file { Sel::File(p) } else { Sel::Dir(p) });
    }
    // shell brace alternation in a glob (`*.{yaml,yml}`, `src/{a,b}/*.ts`): one glob per alternative, any matches
    static BRACE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"\{[^{}]*,[^{}]*\}").unwrap());
    if BRACE.is_match(w) && !w.contains(['(', '|', '^', '$', '\\']) {
        let alts = expand_braces(w);
        let mut b = ignore::gitignore::GitignoreBuilder::new(&ix.repo);
        for a in &alts {
            b.add_line(None, a).map_err(|e| format!("files: glob '{a}': {e}"))?;
        }
        return b.build().map(|g| Sel::Glob(g)).map_err(|e| format!("files: glob '{w}': {e}"));
    }
    // `*.test.*`, `src/**/*.spec.*`: a `*` that does not follow a `.` is a glob star, so the `.*` at the end is the
    // glob's "any extension" (a regex reads `src/.*Test` / `.*\.java$`)
    let bytes = w.as_bytes();
    let glob_star = (0..bytes.len()).any(|i| bytes[i] == b'*' && (i == 0 || !matches!(bytes[i - 1], b'.' | b')' | b']')));
    let only_dot_star = !w.contains(['\\', '^', '$', '(', ')', '|', '+', '{']);
    if REISH.is_match(w) && !(glob_star && only_dot_star) {
        return Regex::new(w).map(|r| Sel::Re(r)).map_err(|e| format!("files: '{w}' read as a regex: {e}"));
    }
    if w.contains(['*', '?', '[']) {
        let mut b = ignore::gitignore::GitignoreBuilder::new(&ix.repo);
        b.add_line(None, w).map_err(|e| format!("files: glob '{w}': {e}"))?;
        return b.build().map(|g| Sel::Glob(g)).map_err(|e| format!("files: glob '{w}': {e}"));
    }
    if let Some(p) = crate::opts::resolve_path(ix, w) {
        let is_file: bool = ix.conn.query_row("SELECT 1 FROM files WHERE path=?1", [&p], |_| Ok(())).is_ok();
        return Ok(if is_file { Sel::File(p) } else { Sel::Dir(p) });
    }
    if crate::opts::path_shaped(w) || (!w.contains(['*', '?']) && ix.repo.join(crate::opts::clean_path(w)).exists()) {
        return Ok(Sel::File(crate::opts::clean_path(w))); // reported as not found below
    }
    let fold = !w.chars().any(|c| c.is_uppercase());
    Ok(Sel::Sub(w.to_string(), fold))
}

/// `a{b,c}d{e,f}` -> abde, abdf, acde, acdf (at most 64 alternatives).
fn expand_braces(w: &str) -> Vec<String> {
    let Some(open) = w.find('{') else { return vec![w.to_string()] };
    let Some(close) = w[open..].find('}').map(|c| open + c) else { return vec![w.to_string()] };
    let (pre, body, post) = (&w[..open], &w[open + 1..close], &w[close + 1..]);
    if !body.contains(',') {
        return expand_braces(post).into_iter().map(|p| format!("{pre}{{{body}}}{p}")).take(64).collect();
    }
    let mut out = vec![];
    for alt in body.split(',') {
        for rest in expand_braces(post) {
            out.push(format!("{pre}{alt}{rest}"));
            if out.len() >= 64 {
                return out;
            }
        }
    }
    out
}

fn cwd() -> String {
    crate::opts::cwd_rel()
}

fn all_files(ix: &Index) -> Vec<Ent> {
    let mut st = match ix.conn.prepare("SELECT path, lines, bytes FROM files ORDER BY path") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    st.query_map([], |r| Ok(Ent { path: r.get(0)?, dir: false, lines: r.get::<_, Option<i64>>(1)?.unwrap_or(0), bytes: r.get::<_, Option<i64>>(2)?.unwrap_or(0) }))
        .map(|m| m.flatten().collect())
        .unwrap_or_default()
}

/// `wc -l`: the number of newlines (a last line without one is not counted), from the index's line count and the
/// file's last byte.
fn wc_lines(ix: &Index, e: &Ent) -> i64 {
    use std::io::{Read, Seek, SeekFrom};
    if e.bytes == 0 {
        return 0;
    }
    let ends_nl = std::fs::File::open(ix.repo.join(&e.path))
        .and_then(|mut f| {
            f.seek(SeekFrom::End(-1))?;
            let mut b = [0u8; 1];
            f.read_exact(&mut b)?;
            Ok(b[0] == b'\n')
        })
        .unwrap_or(true);
    if ends_nl { e.lines } else { (e.lines - 1).max(0) }
}

fn under(p: &str, dir: &str) -> bool {
    dir.is_empty() || p.len() > dir.len() && p.starts_with(dir) && p.as_bytes()[dir.len()] == b'/'
}

fn depth_below(p: &str, dir: &str) -> usize {
    if p == dir {
        return 0;
    }
    let rel = if dir.is_empty() { p } else { &p[dir.len() + 1..] };
    rel.split('/').count()
}

pub fn run(ix: &Index, cmd: &str, toks: &[String], per_page: Option<usize>) -> Answer {
    let ls = cmd == "ls";
    let mut ans = Answer::new(cmd, toks);
    // the shared filters (`-x tests`, `--only src`) next to the find-style tests
    let (mut rest, mut xt): (Vec<String>, Vec<String>) = (vec![], vec![]);
    let mut i = 0;
    while i < toks.len() {
        if matches!(toks[i].as_str(), "-x" | "--exclude" | "--only") && i + 1 < toks.len() {
            xt.extend([toks[i].clone(), toks[i + 1].clone()]);
            i += 2;
        } else {
            rest.push(toks[i].clone());
            i += 1;
        }
    }
    let shared = (!xt.is_empty()).then(|| crate::excl::Excl::build(cmd, &crate::excl::take_flags(&xt, false).1, &[]));
    let toks: &[String] = &rest;
    let a = match parse(ix, toks, ls) {
        Ok(a) => a,
        Err(e) => {
            usage_err(&mut ans, e);
            return ans;
        }
    };
    let mut ents = all_files(ix);
    let all_paths: BTreeSet<String> = ents.iter().map(|e| e.path.clone()).collect();
    let keep = |p: &str| shared.as_ref().is_none_or(|x| !x.drops(p));
    ents.retain(|e| keep(&e.path));
    let indexed = ents.len();
    let mut want_in: Option<BTreeSet<String>> = None;
    let mut notes: Vec<String> = vec![];
    let mut read_as: Vec<String> = vec![];
    // `-`: only the files the input rows name
    if a.dash {
        match crate::rows::parse_stdin(Some(ix)) {
            Ok(r) => {
                let want: BTreeSet<String> = r.rows.iter().filter_map(|x| x.path().map(|p| p.trim_end_matches('/').to_string())).collect();
                if let Some(n) = crate::rows::input_note(&r, true) {
                    notes.push(n);
                }
                if want.is_empty() && a.changed.is_some() {
                    // `aix scope | aix files --changed -`: rows that name no file restrict nothing
                    notes.push("(the input named no file: all changed files are listed)".into());
                } else {
                    ents.retain(|e| want.contains(&e.path));
                    want_in = Some(want);
                }
                if let Some(p) = r.partial.clone() {
                    ans.rows.partial = Some(p);
                }
            }
            Err(e) => {
                ans.fail(format!("files: {e}"));
                return ans;
            }
        }
    }
    // --changed: the diff's files (deleted ones are listed as such: they are no longer indexed)
    let mut deleted: Vec<String> = vec![];
    let mut unindexed: Vec<String> = vec![];
    if let Some(rev) = &a.changed {
        if let Some(bad) = ix.unknown_rev(rev) {
            ans.fail(format!("files: unknown revision {bad}"));
            return ans;
        }
        let ch: BTreeSet<String> = ix.changed_files(rev).into_iter().collect();
        let ch: BTreeSet<String> = ch.into_iter().filter(|p| want_in.as_ref().is_none_or(|w| w.contains(p))).collect();
        deleted = ch.iter().filter(|p| !all_paths.contains(*p) && !ix.repo.join(p).exists()).cloned().collect();
        unindexed = ch.iter().filter(|p| !all_paths.contains(*p) && ix.repo.join(p).is_file()).cloned().collect();
        ents.retain(|e| ch.contains(&e.path));
        read_as.push(format!("changed vs {rev}"));
    }
    ans.notes.append(&mut notes);
    // `@set` / `@set/item`: the items (paths) its rows name, from the set store
    if !a.pos.is_empty() && a.pos.iter().all(|w| crate::rows::is_set_ref(w)) {
        let mut items: BTreeMap<String, usize> = BTreeMap::new();
        for w in &a.pos {
            match crate::rows::set_rows(ix, w) {
                Some(Ok(r)) => {
                    for row in &r.rows {
                        let k = row.path().map(str::to_string).unwrap_or_else(|| w.clone());
                        *items.entry(k).or_default() += 1;
                    }
                }
                Some(Err(e)) => {
                    ans.fail(format!("files: {e}"));
                    return ans;
                }
                None => {
                    ans.out_line(format!("path not found: {w} (no such data set; aix put <name> - stores one)"));
                    ans.exit = Some(1);
                    return ans;
                }
            }
        }
        for (k, n) in &items {
            ans.rows.push(Row::Count { key: k.clone(), n: *n as u64 }, Meta { kind: "rows".into(), text: String::new(), ..Default::default() });
        }
        ans.head = vec![format!("== {} items in {} (rows each)", items.len(), a.pos.join(", "))];
        ans.finish_listing(per_page.or(a.limit), a.page, a.offset, 100);
        return ans;
    }
    let mut sels: Vec<Sel> = vec![];
    for w in &a.pos {
        match classify(ix, w) {
            Ok(s) => sels.push(s),
            Err(e) => {
                ans.fail(e);
                return ans;
            }
        }
    }
    // a named file or dir that is not indexed: not found (exit 1), with what is on disk
    for (s, w) in sels.iter().zip(&a.pos) {
        if let Sel::File(p) = s {
            if !ents.iter().any(|e| &e.path == p) && !a.dash && a.changed.is_none() {
                let on_disk = ix.repo.join(p).exists();
                let why = if !on_disk { String::new() } else { crate::query::not_indexed_why(ix, p) };
                ans.out_line(format!("{} {w}{why}", if a.find_mode { "find: no such indexed file or directory:" } else { "path not found:" }));
                ans.exit = Some(1);
                return ans;
            }
        }
    }
    let mut entries: Vec<(Ent, String)> = vec![]; // (entry, the path as find would print it)
    if a.find_mode || ls {
        // start points: the positionals (dirs or files), else `.`
        let starts: Vec<(String, String)> = if a.pos.is_empty() {
            vec![(cwd(), ".".to_string())]
        } else {
            let mut v = vec![];
            for (s, w) in sels.iter().zip(&a.pos) {
                // echoed as typed (as find does), but with aix's `/` (Windows: `aix-core\src` lists aix-core/src/x)
                let w = &crate::sys::slash(std::path::Path::new(w));
                match s {
                    Sel::Dir(d) => v.push((d.clone(), w.clone())),
                    Sel::File(f) => v.push((f.clone(), w.clone())),
                    _ if ls => {
                        ans.fail(format!("ls: '{w}' is a pattern: aix files '{w}' lists the matching files"));
                        return ans;
                    }
                    _ => {
                        ans.fail(format!("files: with find primaries the words are start points (dirs or files), '{w}' is neither; for a pattern use -name '{w}' or -path"));
                        return ans;
                    }
                }
            }
            v
        };
        let dirs: BTreeSet<String> = {
            let mut d = BTreeSet::new();
            for e in &ents {
                let mut p = e.path.as_str();
                while let Some((parent, _)) = p.rsplit_once('/') {
                    if !d.insert(parent.to_string()) {
                        break;
                    }
                    p = parent;
                }
            }
            d
        };
        for (s, typed) in &starts {
            let printed = |rel: &str| -> String {
                if rel.is_empty() {
                    typed.clone()
                } else if typed.ends_with('/') {
                    format!("{typed}{rel}")
                } else {
                    format!("{typed}/{rel}")
                }
            };
            let rel_of = |p: &str| -> String { if s.is_empty() { p.to_string() } else { p.get(s.len() + 1..).unwrap_or("").to_string() } };
            let start_is_dir = s.is_empty() || dirs.contains(s);
            if start_is_dir {
                entries.push((Ent { path: if s.is_empty() { ".".into() } else { s.clone() }, dir: true, lines: 0, bytes: 0 }, printed("")));
            }
            for d in dirs.iter().filter(|d| under(d, s)) {
                entries.push((Ent { path: d.clone(), dir: true, lines: 0, bytes: 0 }, printed(&rel_of(d))));
            }
            for e in ents.iter().filter(|e| under(&e.path, s) || &e.path == s) {
                entries.push((Ent { path: e.path.clone(), dir: false, lines: e.lines, bytes: e.bytes }, if &e.path == s { typed.clone() } else { printed(&rel_of(&e.path)) }));
            }
        }
        // depth, then the primaries (all ANDed, each possibly negated)
        let start_of = |printed: &str| -> usize {
            // depth = components after the start point as typed
            starts.iter().filter(|(_, t)| printed == t || printed.starts_with(t.as_str())).map(|(_, t)| t.len()).max().unwrap_or(0)
        };
        entries.retain(|(e, pr)| {
            let tlen = start_of(pr);
            let rel = pr[tlen..].trim_start_matches('/');
            let depth = if rel.is_empty() { 0 } else { rel.split('/').count() };
            if a.maxdepth.is_some_and(|m| depth > m) || a.mindepth.is_some_and(|m| depth < m) {
                return false;
            }
            let base = if pr.len() > 1 { pr.trim_end_matches('/').rsplit('/').next().unwrap_or(pr) } else { pr.as_str() };
            a.tests.iter().all(|t| {
                let ok = match &t.p {
                    Prim::Name(g, fold) => fnmatch(g, base, *fold),
                    Prim::Path(g, fold) => fnmatch(g, pr, *fold),
                    Prim::Type(c) => (*c == 'd') == e.dir,
                    Prim::Newer(m) => {
                        let mine = std::fs::metadata(ix.repo.join(if e.path == "." { "" } else { &e.path })).and_then(|m| m.modified()).ok();
                        matches!((mine, m), (Some(x), Some(y)) if x > *y)
                    }
                };
                ok != t.not
            })
        });
        if ls {
            // ls: a dir start lists its children, not itself
            entries.retain(|(e, pr)| !(e.dir && starts.iter().any(|(s, t)| (pr == t) && (e.path == *s || e.path == "." && s.is_empty()))));
        }
        if ls && !a.all {
            // ls hides names starting with a dot unless -a / -A
            entries.retain(|(e, _)| !e.path.rsplit('/').next().unwrap_or("").starts_with('.'));
        }
        let mut seen = BTreeSet::new();
        entries.retain(|(e, _)| seen.insert((e.path.clone(), e.dir)));
        if a.find_mode {
            read_as.push("find(1) primaries (GNU fnmatch: * matches / and a leading dot)".into());
        }
    } else {
        for (s, w) in sels.iter().zip(&a.pos) {
            read_as.push(match s {
                Sel::Dir(d) => format!("'{w}' = dir {}", if d.is_empty() { "." } else { d }),
                Sel::File(_) => format!("'{w}' = file"),
                Sel::Glob(..) => format!("'{w}' = glob (gitignore rules)"),
                Sel::Re(..) => format!("'{w}' = regex over the path"),
                Sel::Sub(_, f) => format!("'{w}' = substring of the path{}", if *f { ", any case" } else { "" }),
            });
        }
        for e in ents {
            let keep = sels.is_empty()
                || sels.iter().any(|s| match s {
                    Sel::Dir(d) => under(&e.path, d),
                    Sel::File(f) => &e.path == f,
                    Sel::Glob(g) => g.matched_path_or_any_parents(&e.path, false).is_ignore(),
                    Sel::Re(r) => r.is_match(&e.path),
                    Sel::Sub(w, fold) => {
                        if *fold {
                            e.path.to_lowercase().contains(&w.to_lowercase())
                        } else {
                            e.path.contains(w.as_str())
                        }
                    }
                });
            if keep {
                let p = e.path.clone();
                entries.push((e, p));
            }
        }
    }
    // --name / --ext (files only)
    if let Some(r) = &a.name_re {
        entries.retain(|(e, _)| r.is_match(e.path.rsplit('/').next().unwrap_or(&e.path)));
        read_as.push(format!("--name {}", r.as_str()));
    }
    if !a.exts.is_empty() {
        entries.retain(|(e, _)| !e.dir && e.path.rsplit_once('.').is_some_and(|(_, x)| a.exts.contains(&x.to_ascii_lowercase())));
        read_as.push(format!("--ext {}", a.exts.join(",")));
    }
    let nfiles = entries.iter().filter(|(e, _)| !e.dir).count();
    let ndirs = entries.len() - nfiles;
    let what = if ndirs > 0 && nfiles > 0 { format!("{nfiles} files, {ndirs} dirs") } else if ndirs > 0 { format!("{ndirs} dirs") } else { format!("{nfiles} files") };
    let mut gi = "indexed files only (gitignored, secret, binary, oversized are not listed: `git ls-files -o` / `find` show them)".to_string();
    // tracked files of types aix does not index, under what was listed: named (an `ls` is not the whole directory)
    let roots: Vec<String> = sels.iter().filter_map(|s| match s { Sel::Dir(d) => Some(d.clone()), _ => None }).collect();
    let whole = sels.is_empty();
    let in_roots = |p: &str| whole || roots.iter().any(|d| d.is_empty() || p.starts_with(&format!("{}/", d.trim_end_matches('/'))));
    let direct = |p: &str| ls && !a.find_mode && (if whole { !p.contains('/') } else { roots.iter().any(|d| p.strip_prefix(&format!("{}/", d.trim_end_matches('/'))).is_some_and(|r| !r.contains('/'))) });
    if let Some(n) = crate::query::unsupported_note(ix, &|p: &str| if ls && !a.find_mode { direct(p) } else { in_roots(p) }) {
        gi = format!("{gi}; {}", n.trim_start_matches('(').trim_end_matches(')'));
    }
    // --exists (test -f / -e)
    if a.exists {
        match entries.first() {
            Some((_, p)) => ans.out_line(format!("yes (first: {p})")),
            None => ans.out_line("no".to_string()),
        }
        ans.exit = Some(if entries.is_empty() { 1 } else { 0 });
        ans.exists = Some(!entries.is_empty());
        return ans;
    }
    let lines_of = |e: &Ent| if a.lines || a.group.is_some() || a.sort == "lines" { wc_lines(ix, e) } else { e.lines };
    // --members: the members the diff touches
    if a.members {
        let rev = a.changed.clone().unwrap_or_else(|| "HEAD".into());
        let mut n = 0;
        for (e, _) in entries.iter().filter(|(e, _)| !e.dir) {
            let ranges = crate::query::changed_ranges(ix, None, &rev, &e.path);
            let syms = crate::query::rows(&ix.conn, "SELECT line, end_line, kind, CASE WHEN container<>'' THEN container||'.'||name ELSE name END FROM symbols WHERE file=?1 ORDER BY line", &[&e.path]);
            let new_file = ranges.is_none();
            for s in syms {
                let (a1, b1): (usize, usize) = (s[0].parse().unwrap_or(0), s[1].parse().unwrap_or(0));
                let touched = match &ranges {
                    Some(r) => r.iter().any(|(x, y)| (*x as usize) <= b1 && (*y as usize) >= a1),
                    None => true,
                };
                if touched && matches!(s[2].as_str(), "function" | "method" | "class" | "interface" | "struct" | "enum" | "trait" | "impl" | "type" | "const" | "fn" | "component") {
                    ans.rows.push(Row::Range { path: e.path.clone(), a: a1, b: b1 }, Meta { kind: "member".into(), text: format!("{} {}{}", s[2], s[3], if new_file { " (new file)" } else { "" }), ..Default::default() });
                    n += 1;
                }
            }
        }
        ans.head = vec![format!("== members touched vs {rev}: {n} in {nfiles} changed files")];
        ans.finish_listing(per_page.or(a.limit), a.page, a.offset, 200);
        if n == 0 {
            ans.exit = Some(1);
        }
        return ans;
    }
    // --group-by dir[:N] | ext | kind (with --lines: the lines per group, wc -l totals)
    if let Some((k, d)) = &a.group {
        let mut g: BTreeMap<String, i64> = BTreeMap::new();
        for (e, _) in entries.iter().filter(|(e, _)| !e.dir) {
            *g.entry(crate::group::file_key(&e.path, k, *d)).or_default() += if a.lines { lines_of(e) } else { 1 };
        }
        let mut v: Vec<(String, i64)> = g.into_iter().collect();
        v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
        let total: i64 = v.iter().map(|x| x.1).sum();
        for (key, n) in &v {
            ans.rows.push(Row::Count { key: key.clone(), n: *n as u64 }, Meta { kind: "group".into(), text: String::new(), ..Default::default() });
        }
        let gk = if *d > 1 { format!("{k}:{d}") } else { k.clone() };
        ans.head = vec![format!("== {} {} in {} groups by {gk} ({})", total, if a.lines { "lines" } else { "files" }, v.len(), read_as.join("; ")).replace(" ()", "")];
        ans.notes.push(format!("({gi})"));
        ans.finish_listing(per_page.or(a.limit), a.page, a.offset, 100);
        if v.is_empty() {
            ans.exit = Some(1);
        }
        return ans;
    }
    // --count (ls | wc -l, find | wc -l)
    if a.count {
        let n = entries.len();
        ans.out_line(format!("{n} ({what}{}{})", if read_as.is_empty() { String::new() } else { format!("; {}", read_as.join("; ")) }, if a.lines { String::new() } else { String::new() }));
        ans.bare_lines = Some(vec![n.to_string()]);
        ans.notes.push(format!("({gi})"));
        ans.exit = Some(if n == 0 { 1 } else { 0 });
        return ans;
    }
    // the listing
    match a.sort.as_str() {
        "lines" => entries.sort_by(|x, y| lines_of(&y.0).cmp(&lines_of(&x.0)).then(x.1.cmp(&y.1))),
        // `--lines --sort size`: the size shown is the line count, so that is the order
        "size" if a.lines && !a.size => entries.sort_by(|x, y| lines_of(&y.0).cmp(&lines_of(&x.0)).then(x.1.cmp(&y.1))),
        "size" => entries.sort_by(|x, y| y.0.bytes.cmp(&x.0.bytes).then(x.1.cmp(&y.1))),
        _ => entries.sort_by(|x, y| x.1.cmp(&y.1)),
    }
    let mut total_lines = 0i64;
    for (e, pr) in &entries {
        let shown = if a.find_mode || ls { pr.strip_prefix("./").filter(|s| !s.is_empty()).unwrap_or(pr).to_string() } else { pr.clone() };
        if e.dir {
            let n = if ls { format!("{}/", shown.trim_end_matches('/')) } else { shown.clone() };
            ans.rows.push(Row::File { path: if ls { n } else { shown } }, Meta { kind: "dir".into(), text: String::new(), ..Default::default() });
        } else if a.lines {
            let n = lines_of(e);
            total_lines += n;
            ans.rows.push(Row::Count { key: shown, n: n as u64 }, Meta { kind: "lines".into(), text: if a.size { format!("{} bytes", e.bytes) } else { String::new() }, ..Default::default() });
        } else if a.size {
            ans.rows.push(Row::Count { key: shown, n: e.bytes as u64 }, Meta { kind: "bytes".into(), text: String::new(), ..Default::default() });
        } else {
            ans.rows.push(Row::File { path: shown }, Meta { kind: "file".into(), text: String::new(), ..Default::default() });
        }
    }
    for p in deleted.iter().filter(|p| keep(p)) {
        ans.rows.push(Row::File { path: p.clone() }, Meta { kind: "deleted".into(), text: "(deleted)".into(), ..Default::default() });
    }
    for p in unindexed.iter().filter(|p| keep(p)).filter(|p| sels.is_empty() || sels.iter().any(|s| matches!(s, Sel::Glob(g) if g.matched_path_or_any_parents(p, false).is_ignore()) || matches!(s, Sel::Dir(d) if under(p, d)))) {
        ans.rows.push(Row::File { path: p.clone() }, Meta { kind: "unindexed".into(), text: "(untracked, not indexed)".into(), ..Default::default() });
    }
    let read = if read_as.is_empty() { String::new() } else { format!(" ({})", read_as.join("; ")) };
    ans.head = vec![format!("== {what}{}{read} of {indexed} indexed", if a.lines { format!(", {total_lines} lines") } else { String::new() })];
    if !deleted.is_empty() {
        ans.head[0].push_str(&format!(", {} deleted", deleted.len()));
    }
    if a.lines && nfiles > 1 {
        ans.notes.push(format!("({total_lines} total, wc -l counting: newlines)"));
    }
    ans.notes.push(format!("({gi})"));
    if a.find_mode && entries.is_empty() && a.tests.iter().any(|t| matches!(&t.p, Prim::Path(g, _) if !g.starts_with(['*', '.', '/']) )) {
        ans.notes.push("(find -path matches the whole path as find prints it: from `.` that is ./src/...; try -path './src/*' or '*/src/*')".into());
    }
    ans.finish_listing(per_page.or(a.limit), a.page, a.offset, 100);
    if ans.rows.is_empty() {
        ans.exit = Some(1);
    }
    let _ = depth_below;
    ans
}

#[cfg(test)]
mod tests {
    use super::fnmatch;

    #[test]
    fn fnmatch_is_gnu_flags_0() {
        assert!(fnmatch("*.rs", ".hidden.rs", false));
        assert!(fnmatch("*/x/*", "./src/x/a.rs", false));
        assert!(fnmatch("a?c", "a/c", false));
        assert!(fnmatch("[!a]b", "cb", false) && !fnmatch("[!a]b", "ab", false));
        assert!(fnmatch("[]a]", "]", false));
        assert!(fnmatch("[a-c]x", "bx", false));
        assert!(fnmatch("[[:digit:]]*", "9z", false));
        assert!(fnmatch("\\*", "*", false) && !fnmatch("\\*", "a", false));
        assert!(fnmatch("*.RS", "a.rs", true) && !fnmatch("*.RS", "a.rs", false));
        assert!(!fnmatch("*.rs", "a.rsx", false));
        assert!(fnmatch("[a", "[a", false));
    }
}
