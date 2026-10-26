//! Count first, then page or narrow: `--count` / `--plan` (breakdown only), `--page` / `--per-page` / `--offset`
//! (stable pages over the full result), the automatic count-first block on large answers, and `--sort`.
//! Everything is computed from the index answer itself (the same query without the row limit); nothing reads the repo.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::excl::{self, file_class, kind_word, line_path, Excl};
use crate::index::Index;

/// A result row: a line that names a file (headers "== ..." and notes "(...)" are not rows).
pub fn is_row(l: &str) -> bool {
    !l.starts_with("==") && !l.starts_with('(') && !is_ctx(l) && !is_def(l) && !is_detail(l) && line_path(l).is_some()
}

/// The definition line a callers/callees/impact answer opens with (`path:17-22 defined: method ...`): context, not a row.
pub fn is_def(l: &str) -> bool {
    static DEF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*[^\s:][^:]*:\d+-\d+ defined: ").unwrap());
    l.contains(" defined: ") && DEF.is_match(l)
}

/// A line of an endpoint card under its row (`  roles: ...`, `  client ...`): a page keeps it with its row.
pub fn is_detail(l: &str) -> bool {
    ["  roles: ", "  profile: ", "  client ", "  direct uses: ", "  scripts/specs: "].iter().any(|p| l.starts_with(p))
}

/// A grep context line (`  path-12- text`) or a `  --` separator: it belongs to the row before it, it is not a row.
pub fn is_ctx(l: &str) -> bool {
    static CTX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+(--$|\S+-\d+- )").unwrap());
    CTX.is_match(l)
}

pub fn tokens(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

pub fn fmt_tok(t: usize) -> String {
    if t >= 1000 {
        format!("~{:.1}k tokens", t as f64 / 1000.0)
    } else {
        format!("~{} tokens", t.max(1))
    }
}

/// One weighted row of the full answer (grep rows carry their true matching-line count).
#[derive(Clone, Debug)]
pub struct Row {
    pub path: String,
    pub n: usize,
    pub bytes: usize,
    pub conf: Option<&'static str>,
}

static CONF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\((exact|resolved|heuristic|name)\)").unwrap());

pub fn rows_from_lines(lines: &[String]) -> Vec<Row> {
    lines
        .iter()
        .filter(|l| is_row(l))
        .map(|l| Row {
            path: line_path(l).unwrap_or("").to_string(),
            n: 1,
            bytes: l.len() + 1,
            conf: CONF.captures(l).and_then(|c| c.get(1)).map(|m| match m.as_str() {
                "exact" => "exact",
                "resolved" => "resolved",
                "heuristic" => "heuristic",
                _ => "name",
            }),
        })
        .collect()
}

/// Directory grouping of the rows: first segment(s), deepened while one group holds more than 80% (at most 4 levels).
fn dir_groups(rows: &[Row]) -> Vec<(String, usize)> {
    let total: usize = rows.iter().map(|r| r.n).sum();
    let mut depth = 1;
    loop {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for r in rows {
            let segs: Vec<&str> = r.path.split('/').collect();
            let d = depth.min(segs.len().saturating_sub(1));
            let key = if d == 0 { ".".to_string() } else { segs[..d].join("/") };
            *m.entry(key).or_default() += r.n;
        }
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        if depth >= 4 || v.len() > 1 && (v[0].1 as f64) <= 0.8 * total as f64 || v.is_empty() {
            return v;
        }
        // one dominant group: look one level deeper unless it is the only possibility
        if v.len() == 1 && rows.iter().all(|r| r.path.split('/').count() <= depth + 1) {
            return v;
        }
        depth += 1;
    }
}

pub struct PlanCtx<'a> {
    pub cmd: &'a str,
    /// the command line to repeat (without the narrowing flags being suggested): `aix <cmd> <args>`
    pub cmdline: &'a str,
    pub per_page: usize,
    pub ex: &'a Excl,
    pub auto: bool,
    /// the rows below are the first ones read, not all of them (the totals are lower bounds)
    pub capped: bool,
    /// lines of the full answer (for sections and the byte estimate)
    pub lines: &'a [String],
    pub rows: &'a [Row],
}

/// The count breakdown plus 2-3 ready-to-run next commands.
pub fn report(c: &PlanCtx) -> Vec<String> {
    let total: usize = c.rows.iter().map(|r| r.n).sum();
    let tb_rows: usize = c.rows.iter().map(|r| r.n * r.bytes).sum();
    let tb = tb_rows.max(c.lines.iter().map(|l| l.len() + 1).sum());
    let mut out = vec![];
    let plus = if c.capped { "+" } else { "" };
    out.push(format!(
        "== count {}: {total}{plus} rows, {}{plus} in full{}{}",
        c.cmd,
        fmt_tok(tokens(tb)),
        if c.auto { " (answer is longer than this page; --all for everything)" } else { "" },
        if c.capped { " (capped: only the first rows were read, so the breakdown below covers those, not all; narrow with --only/-x)" } else { "" }
    ));
    // kinds
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for r in c.rows {
        *kinds.entry(file_class(&r.path)).or_default() += r.n;
    }
    let mut kv: Vec<(&str, usize)> = kinds.into_iter().collect();
    kv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if !kv.is_empty() {
        out.push(format!("  kinds: {}", kv.iter().map(|(k, n)| format!("{} {n}", if *k == "source" { "source" } else { kind_word(k) })).collect::<Vec<_>>().join(", ")));
    }
    let dg = dir_groups(c.rows);
    if dg.len() > 1 {
        out.push(format!("  dirs: {}", dg.iter().take(5).map(|(d, n)| format!("{d} {n}")).collect::<Vec<_>>().join(", ")));
    }
    // sections (multi-section commands)
    if !excl::sections_of(c.cmd).is_empty() && matches!(c.cmd, "brief" | "trace" | "explain" | "table") {
        let tags = excl::section_tags(c.cmd, c.lines);
        let mut by: BTreeMap<&str, usize> = BTreeMap::new();
        for (l, t) in c.lines.iter().zip(&tags) {
            if let Some(t) = t {
                *by.entry(*t).or_default() += l.len() + 1;
            }
        }
        let mut sv: Vec<(&str, usize)> = by.into_iter().collect();
        sv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        if !sv.is_empty() {
            out.push(format!("  sections: {}", sv.iter().take(6).map(|(t, b)| format!("{t} {}", fmt_tok(tokens(*b)).replace(" tokens", "t"))).collect::<Vec<_>>().join(", ")));
        }
    }
    // confidence (call graph)
    if matches!(c.cmd, "callers" | "callees" | "impact") {
        let mut cf: BTreeMap<&str, usize> = BTreeMap::new();
        for r in c.rows {
            if let Some(k) = r.conf {
                *cf.entry(k).or_default() += r.n;
            }
        }
        if !cf.is_empty() {
            out.push(format!("  conf: {}", ["exact", "resolved", "heuristic", "name"].iter().filter_map(|k| cf.get(k).map(|n| format!("{k} {n}"))).collect::<Vec<_>>().join(", ")));
        }
    }
    // next commands
    let mut next: Vec<String> = vec![];
    let est = |pred: &dyn Fn(&Row) -> bool| -> (usize, usize) {
        let kept: Vec<&Row> = c.rows.iter().filter(|r| pred(r)).collect();
        (kept.iter().map(|r| r.n).sum(), kept.iter().map(|r| r.n * r.bytes).sum())
    };
    let kind_comp: BTreeMap<&'static str, excl::Share> = {
        let mut m: BTreeMap<&'static str, excl::Share> = BTreeMap::new();
        for r in c.rows {
            let s = m.entry(file_class(&r.path)).or_default();
            s.lines += r.n;
            s.bytes += r.n * r.bytes;
        }
        m
    };
    if let Some((k, _)) = excl::pick_kinds(&kind_comp, tb_rows.max(1), 0.15, &|x| c.ex.x.has_kind(x) || c.ex.defaults.has_kind(x)) {
        let set: Vec<&str> = k.clone();
        let (n, b) = est(&|r| !set.contains(&kind_word(file_class(&r.path))));
        let share = 100 - (n * 100 / total.max(1)).min(100);
        // grep's own -x means "whole line": the long form cannot be misread
        let flag = if c.cmd == "grep" { "--exclude" } else { "-x" };
        next.push(format!("aix {} {flag} {}  # {share}% of the rows are {}: ~{n} rows, {}", c.cmdline, k.join(","), excl::kinds_phrase(&k), fmt_tok(tokens(b))));
    }
    if matches!(c.cmd, "callers" | "callees" | "impact") && c.ex.conf.is_empty() {
        let (n, b) = est(&|r| !matches!(r.conf, Some("name") | Some("heuristic")));
        if n < total {
            next.push(format!("aix {} --conf exact,resolved  # {} name-only rows dropped: ~{n} rows, {}", c.cmdline, total - n, fmt_tok(tokens(b))));
        }
    }
    if matches!(c.cmd, "brief" | "trace" | "explain" | "table") {
        let tags = excl::section_tags(c.cmd, c.lines);
        let mut by: BTreeMap<&str, usize> = BTreeMap::new();
        for (l, t) in c.lines.iter().zip(&tags) {
            if let Some(t) = t.filter(|t| !c.ex.skip.contains(*t)) {
                *by.entry(t).or_default() += l.len() + 1;
            }
        }
        let mut sv: Vec<(&str, usize)> = by.into_iter().filter(|x| x.1 as f64 >= 0.2 * tb as f64).collect();
        sv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        if let Some((t, b)) = sv.first() {
            next.push(format!("aix {} --skip {t}  # the {t} section is {}% of this answer: {} left", c.cmdline, b * 100 / tb.max(1), fmt_tok(tokens(tb - b))));
        }
    }
    if next.is_empty() && dg.len() > 1 {
        let real: Vec<&(String, usize)> = dg.iter().filter(|d| !d.0.starts_with('.')).take(3).collect();
        if real.len() > 1 {
            let top: Vec<String> = real.iter().map(|(d, n)| format!("{d} {n} row{}", if *n == 1 { "" } else { "s" })).collect();
            next.push(format!("aix {} --only '{}/**'  # or narrow to one directory: {}", c.cmdline, real[0].0, top.join(", ")));
        }
    }
    if total > c.per_page && !matches!(c.cmd, "brief" | "trace" | "explain" | "table" | "outline") {
        next.push(format!("aix {} --page 2  # rows {}-{} of {total}{plus}", c.cmdline, c.per_page + 1, (2 * c.per_page).min(total)));
    }
    for (i, n) in next.into_iter().take(3).enumerate() {
        out.push(if i == 0 { format!("  next: {n}") } else { format!("        {n}") });
    }
    out
}

/// A stable page of the full answer: the leading header lines, then rows `[start, start+per)` with the "== ..." header
/// that introduced them. Returns (lines, total rows).
pub fn paginate(lines: &[String], start: usize, per: usize) -> (Vec<String>, usize) {
    paginate_by(lines, start, per, &|l| is_row(l))
}

/// `paginate` with the command's own notion of a row (`hints`: `  /route | lead` lines).
pub fn paginate_by(lines: &[String], start: usize, per: usize, is_row: &dyn Fn(&str) -> bool) -> (Vec<String>, usize) {
    let per = per.min(usize::MAX / 4);
    let total = lines.iter().filter(|l| is_row(l)).count();
    let mut out: Vec<String> = vec![];
    let mut seen = 0usize;
    let mut pending: Vec<&String> = vec![];
    let mut lead = true;
    let mut last_in = false; // the last row was kept: its context lines follow it
    for l in lines {
        if is_def(l) {
            if start == 0 {
                // the definition is shown once, with the first page, under the header that introduces it
                if lead {
                    out.extend(pending.drain(..).filter(|p| p.starts_with("==")).cloned());
                }
                out.push(l.clone());
            }
            continue;
        }
        if is_ctx(l) || is_detail(l) {
            if last_in {
                out.push(l.clone());
            }
            continue;
        }
        if is_row(l) {
            last_in = seen >= start && seen < start.saturating_add(per);
            if lead {
                // headers before the first row open every page
                out.extend(pending.drain(..).filter(|p| p.starts_with("==")).cloned());
                lead = false;
            }
            if seen >= start && seen < start.saturating_add(per) {
                out.extend(pending.drain(..).filter(|p| p.starts_with("==")).cloned());
                out.push(l.clone());
            } else {
                pending.clear();
            }
            seen += 1;
        } else if l.starts_with("==") {
            // a new section header replaces a header that had no row in the page
            if pending.last().is_some_and(|p| p.starts_with("==")) && !lead {
                pending.pop();
            }
            pending.push(l);
        } else if lead {
            pending.push(l);
        }
    }
    // lead block when there were no rows at all
    if lead {
        out.extend(pending.into_iter().cloned());
    }
    // the title lines of page > 1 would repeat verbatim: dedupe the leading "== " title that is also a section header
    let mut seen_hdr = std::collections::HashSet::new();
    out.retain(|l| !l.starts_with("==") || seen_hdr.insert(l.clone()));
    (out, total)
}

// ───────────────────────────── --sort ─────────────────────────────

fn conf_rank(c: Option<&str>) -> i64 {
    match c {
        Some("exact") => 0,
        Some("resolved") => 1,
        Some("heuristic") => 2,
        Some(_) => 3,
        None => 4,
    }
}

pub fn path_line(l: &str) -> (String, i64) {
    let p = line_path(l).unwrap_or("").to_string();
    let n = l.find(&format!("{p}:")).map(|i| l[i + p.len() + 1..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>()).and_then(|s| s.parse().ok()).unwrap_or(0);
    (p, n)
}

/// Reorder the rows of each contiguous block (stable, ties broken by path:line) by the `--sort` keys:
/// path, recency (git last touch, newest first), conf, fanin (most called first), size (smallest file first).
/// Applies to single-line listings; multi-section commands use `--order`.
pub fn sort_rows(ix: &Index, cmd: &str, lines: &mut [String], keys: &[String]) {
    if keys.is_empty() || matches!(cmd, "brief" | "trace" | "explain" | "table" | "outline" | "code" | "grep") {
        return;
    }
    let c = &ix.conn;
    let mut cache: std::collections::HashMap<String, (String, i64)> = Default::default();
    let mut meta = |p: &str| -> (String, i64) {
        cache
            .entry(p.to_string())
            .or_insert_with(|| {
                c.query_row("SELECT COALESCE(commit_date,''), COALESCE(bytes,0) FROM files WHERE path=?", [p], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap_or_default()
            })
            .clone()
    };
    let fanin = |p: &str, line: i64| -> i64 {
        c.query_row(
            "SELECT COALESCE((SELECT n FROM sym_fanin s WHERE s.file=?1 AND s.line=(SELECT m.line FROM members m WHERE m.file=?1 AND m.line<=?2 AND m.end_line>=?2 ORDER BY m.line DESC LIMIT 1)), 0)",
            rusqlite::params![p, line],
            |r| r.get(0),
        )
        .unwrap_or(0)
    };
    let mut i = 0;
    while i < lines.len() {
        if !is_row(&lines[i]) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < lines.len() && is_row(&lines[j]) {
            j += 1;
        }
        type SortKey = (Vec<(i64, String)>, (String, i64), usize);
        let mut blk: Vec<SortKey> = vec![];
        for (k, l) in lines[i..j].iter().enumerate() {
            let (p, n) = path_line(l);
            let m = meta(&p);
            let conf = CONF.captures(l).and_then(|x| x.get(1)).map(|x| x.as_str().to_string());
            let mut kv = vec![];
            for key in keys {
                kv.push(match key.as_str() {
                    "path" => (0, p.clone()),
                    // newest first: invert by sorting the date descending through a negated lexical key
                    "recency" => (0, m.0.chars().map(|ch| char::from_u32(0x7e - (ch as u32).min(0x7e)).unwrap_or('~')).collect()),
                    "conf" => (conf_rank(conf.as_deref()), String::new()),
                    "fanin" => (-fanin(&p, n), String::new()),
                    "size" => (m.1, String::new()),
                    _ => (0, String::new()),
                });
            }
            blk.push((kv, (p, n), k));
        }
        blk.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        let old: Vec<String> = lines[i..j].to_vec();
        for (k, b) in blk.iter().enumerate() {
            lines[i + k] = old[b.2].clone();
        }
        i = j;
    }
}

/// The footer-less `aix ...` flags as typed, for next-command suggestions.
pub fn flags_string(a: &excl::ExclArgs) -> String {
    let mut s = String::new();
    let mut put = |f: &str, v: &[String]| {
        if !v.is_empty() {
            s.push_str(&format!(" {f} {}", crate::shell_quote(&v.join(","))));
        }
    };
    put("--exclude", &a.exclude);
    put("--only", &a.only);
    put("--hide", &a.hide);
    put("--skip", &a.skip);
    put("--fields", &a.fields);
    put("--order", &a.order);
    put("--sort", &a.sort);
    put("--conf", &a.conf);
    if a.no_default {
        s.push_str(" --no-default-excludes");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn pages_union_to_the_full_set() {
        let lines = l(&["== callers of X: 5", "a/x.ts:1 f (exact)", "a/x.ts:2 g (exact)", "== more", "b/y.ts:3 h (name)", "b/y.ts:4 i (name)", "c/z.ts:5 j (exact)", "(+0 more)"]);
        let mut all: Vec<String> = vec![];
        for p in 0..3 {
            let (pg, total) = paginate(&lines, p * 2, 2);
            assert_eq!(total, 5);
            all.extend(pg.into_iter().filter(|x| is_row(x)));
        }
        let want: Vec<String> = lines.iter().filter(|x| is_row(x)).cloned().collect();
        assert_eq!(all, want);
        let (p2, _) = paginate(&lines, 2, 2);
        assert_eq!(p2[0], "== callers of X: 5");
        assert!(p2.contains(&"== more".to_string()));
    }

    #[test]
    fn report_has_next_commands() {
        let mut lines = vec!["== callers of X".to_string()];
        for i in 0..40 {
            lines.push(format!("src/a{i}.ts:{i} f (exact)"));
        }
        for i in 0..30 {
            lines.push(format!("docs/d{i}.md:{i} text about it here (name)"));
        }
        let rows = rows_from_lines(&lines);
        let ex = Excl::default();
        let r = report(&PlanCtx { cmd: "callers", cmdline: "callers X", per_page: 20, ex: &ex, auto: false, capped: false, lines: &lines, rows: &rows });
        let t = r.join("\n");
        assert!(t.contains("70 rows") && t.contains("kinds: source 40, docs 30"), "{t}");
        assert!(t.contains("-x docs") && t.contains("--conf exact,resolved") && t.contains("--page 2"), "{t}");
    }

    #[test]
    fn rows_of_any_language_and_defined_in_text_are_rows() {
        for r in ["  a.rb:1: e = 1", "  b.cs:1: e = 1", "src/x.swift:3:let a", "lib/m.lua:2-4 f (exact)", "  a.rb", "  src/b.cs", "src/gradlew:2: x", "Makefile:4: all:", ".gitignore:1: target", "  d.py:1: x = 1 # defined in cfg", "c.py:1:x = 1 defined: here"] {
            assert!(is_row(r), "{r}");
        }
        assert!(is_def("src/a.rs:7-9 defined: function fn x()") && !is_row("src/a.rs:7-9 defined: function fn x()"));
        for n in ["== x", "(note)", "12:00:01 ERROR boom", "10.0.0.1:80 GET /", "   (A.m is inherited: defined in B)"] {
            assert!(!is_row(n), "{n}");
        }
    }
}
