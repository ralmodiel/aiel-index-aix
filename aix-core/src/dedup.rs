//! Deduplication: the `dedup` pipe stage and the global `--dedup[=KEY]` option.
//!
//! - Order-preserving and global: the first occurrence of each key is kept (unlike `uniq`, which stays GNU-exact and
//!   adjacent-only). Footer: `(N duplicates removed (by KEY))`.
//! - KEY: `line` (default: the whole row as printed), `text` (the row text without `path:line:`), `file`, `member`
//!   (the enclosing function/class, from the index), `dir[:N]`, `field N` (1-based whitespace field) / `field NAME`
//!   (a named field of a data-set row, `NAME=value` or a JSON key), `match` (the part grep's pattern matched).
//! - `-c` / `--count`: each kept row is prefixed with its occurrence count (`N<TAB>row` bare), in first-appearance
//!   order; `--sort count` sorts by count, descending.
//! - `--norm`: rows that differ only in variable parts (numbers, hex ids, UUIDs, ISO / epoch timestamps, IPs, quoted
//!   strings) are one shape: `N×  <shape> (first A, last B)`. The text is redacted before it is normalised.
//! - In a `;` sequence or a batch, a file range an earlier section printed in full is replaced by
//!   `(F:A-B shown above in == aix <cmd>)` unless `--no-dedup` (sections() below).

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::index::Index;
use crate::rows::{Meta, Row, Rows};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Line,
    Text,
    File,
    Member,
    Dir(Option<usize>),
    Field(String),
    Match,
}

impl Key {
    /// `line`, `text`, `file`, `member`, `dir`, `dir:N`, `field N`, `field:N`, `field NAME`, `match`.
    pub fn parse(s: &str) -> Result<Key, String> {
        let s = s.trim();
        let (k, v) = match s.split_once([':', ' ', '=']) {
            Some((k, v)) => (k, Some(v.trim())),
            None => (s, None),
        };
        Ok(match (k, v) {
            ("line" | "", None) => Key::Line,
            ("text", None) => Key::Text,
            ("file", None) => Key::File,
            ("member", None) => Key::Member,
            ("match", None) => Key::Match,
            ("dir", None) => Key::Dir(None),
            ("dir", Some(n)) => Key::Dir(Some(n.parse::<usize>().ok().filter(|n| *n > 0).ok_or_else(|| format!("dir:N takes a positive depth (got '{n}')"))?)),
            ("field", Some(f)) if !f.is_empty() => Key::Field(f.to_string()),
            // data-set keys (the same names as count): a row's level, its template (shape), its item
            ("level" | "template" | "item", None) => Key::Field(k.to_string()),
            _ => return Err(format!("unknown key '{s}': line, text, file, member, dir[:N], field N|NAME or match")),
        })
    }
    pub fn name(&self) -> String {
        match self {
            Key::Line => "line".into(),
            Key::Text => "text".into(),
            Key::File => "file".into(),
            Key::Member => "member".into(),
            Key::Match => "match".into(),
            Key::Dir(None) => "dir".into(),
            Key::Dir(Some(n)) => format!("dir:{n}"),
            Key::Field(f) => format!("field {f}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub key: Key,
    pub count: bool,
    pub sort_count: bool,
    pub norm: bool,
}

impl Spec {
    /// The `dedup` stage's words: `[KEY] [-c|--count] [--sort count] [--norm] [-]`.
    pub fn parse(args: &[String]) -> Result<Spec, String> {
        let mut sp = Spec { key: Key::Line, count: false, sort_count: false, norm: false };
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            match a {
                "-" => {}
                "-c" | "--count" => sp.count = true,
                "--norm" => sp.norm = true,
                "--sort" => {
                    match args.get(i + 1).map(String::as_str) {
                        Some("count") => sp.sort_count = true,
                        Some("first") => sp.sort_count = false,
                        v => return Err(format!("dedup: --sort takes count or first (got {})", v.unwrap_or("nothing"))),
                    }
                    i += 1;
                }
                "field" | "dir" => {
                    // `field 2`, `field level`, `dir 2`
                    match args.get(i + 1).filter(|v| !v.starts_with('-')) {
                        Some(v) => {
                            sp.key = Key::parse(&format!("{a} {v}"))?;
                            i += 1;
                        }
                        None if a == "dir" => sp.key = Key::Dir(None),
                        None => return Err("dedup: field takes a number or a name (field 2, field level)".into()),
                    }
                }
                _ if a.starts_with("--key=") => sp.key = Key::parse(&a[6..])?,
                _ if a.starts_with('-') => return Err(format!("dedup: unknown option {a} (dedup [KEY] [-c] [--sort count] [--norm]; KEY: line, text, file, member, dir[:N], field N|NAME, match)")),
                _ => sp.key = Key::parse(a).map_err(|e| format!("dedup: {e}"))?,
            }
            i += 1;
        }
        Ok(sp)
    }
}

/// The text of a row without its location.
fn text_of(r: &Row, m: &Meta) -> String {
    match r {
        Row::Hit { text, .. } => text.clone(),
        Row::Range { .. } => m.text.clone(),
        Row::File { path } => path.clone(),
        Row::Count { key, .. } => key.clone(),
        Row::Text { line } => line.clone(),
    }
}

/// A named field: the data-set row's own (Meta.fields), else `NAME=value` / `"NAME": value` in the text.
pub fn field_named(r: &Row, m: &Meta, name: &str) -> Option<String> {
    if let Some((_, v)) = m.fields.iter().find(|(k, _)| k == name) {
        return Some(v.clone());
    }
    let t = text_of(r, m);
    if t.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t.trim()) {
            if let Some(x) = v.get(name) {
                return Some(x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()));
            }
        }
    }
    let re = Regex::new(&format!(r#"(?:^|[\s,;{{(])"?{}"?\s*[=:]\s*("[^"]*"|'[^']*'|[^\s,;)}}]+)"#, regex::escape(name))).ok()?;
    re.captures(&t).map(|c| c[1].trim_matches(|c| c == '"' || c == '\'').to_string())
}

static LEVEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|SEVERE|FATAL|CRITICAL)\b").unwrap());

/// A named key of a row, the same in count, dedup and --where: the row's own fields (a data-set record), the record
/// of the set row it cites, then `level` (the log level in the text), `template` (the normalised shape), `item` (the
/// set item), else `NAME=value` / a JSON key in the text.
pub fn named(ix: Option<&Index>, r: &Row, m: &Meta, name: &str) -> Option<String> {
    let look = |fs: &[(String, String)]| fs.iter().find(|(k, _)| k == name || k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
    if let Some(v) = look(&m.fields) {
        return Some(v);
    }
    if let (Some(ix), Some(p), Some(l)) = (ix, r.path(), r.line()) {
        if crate::rows::is_set_ref(p) {
            if let Some(v) = crate::rows::set_fields(ix, p, l).and_then(|fs| look(&fs)) {
                return Some(v);
            }
        }
    }
    if name != "template" && name != "item" {
        if let Some(v) = field_named(r, m, name) {
            return Some(v);
        }
    }
    match name {
        "level" => {
            let t = text_of(r, m);
            return LEVEL.captures(&t).map(|c| c[1].to_ascii_uppercase().replace("WARNING", "WARN"));
        }
        "template" => return Some(normalize(&text_of(r, m))),
        "item" => return r.path().map(|p| p.split_once('/').map(|x| x.1).unwrap_or(p).to_string()),
        _ => {}
    }
    field_named(r, m, name)
}

/// The innermost member around a row's line (else its file and line).
fn member_of(ix: Option<&Index>, r: &Row) -> String {
    let (Some(p), Some(l)) = (r.path(), r.line()) else {
        return r.path().map(str::to_string).unwrap_or_default();
    };
    if let Some(ix) = ix {
        let q = crate::query::rows(
            &ix.conn,
            "SELECT line, end_line, COALESCE(NULLIF(qname,''), name) FROM members WHERE file=?1 AND line<=?2 AND end_line>=?2 AND kind NOT IN ('field','property','const','variable') ORDER BY end_line-line LIMIT 1",
            &[&p, &(l as i64)],
        );
        if let Some(x) = q.first() {
            return format!("{p}:{}-{} {}", x[0], x[1], x[2]);
        }
    }
    format!("{p}:{l}")
}

/// The key of one row.
pub fn key_of(ix: Option<&Index>, r: &Row, m: &Meta, key: &Key, pattern: Option<&Regex>) -> String {
    match key {
        Key::Line => r.render(m),
        Key::Text => text_of(r, m),
        Key::File => r.path().map(|p| p.trim_end_matches('/').to_string()).unwrap_or_else(|| r.render(m)),
        Key::Member => member_of(ix, r),
        Key::Dir(depth) => {
            let p = r.path().unwrap_or("");
            let d = p.trim_end_matches('/').rsplit_once('/').map(|x| x.0).unwrap_or(".");
            match depth {
                Some(n) => d.split('/').take(*n).collect::<Vec<_>>().join("/"),
                None => d.to_string(),
            }
        }
        Key::Field(f) => match f.parse::<usize>() {
            // as count by field N: the text's N-th blank-separated field (awk)
            Ok(n) if n > 0 => text_of(r, m).split_whitespace().nth(n - 1).unwrap_or("").to_string(),
            _ => named(ix, r, m, f).unwrap_or_default(),
        },
        Key::Match => {
            let t = text_of(r, m);
            match pattern.and_then(|re| re.find(&t)) {
                Some(x) => x.as_str().to_string(),
                None => t,
            }
        }
    }
}

static NORM: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r#""(?:[^"\\]|\\.)*""#, "<STR>"),
        (r"'(?:[^'\\]|\\.)*'", "<STR>"),
        (r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<UUID>"),
        (r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?", "<TS>"),
        (r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b", "<TS>"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "<IP>"),
        (r"(?i)\b(?:[0-9a-f]{1,4}:){4,7}[0-9a-f]{1,4}\b", "<IP>"),
        (r"\b1\d{9}(?:\d{3})?\b", "<TS>"),
        (r"(?i)\b0x[0-9a-f]+\b", "<HEX>"),
        (r"(?i)\b[0-9a-f]{8,}\b", "<HEX>"),
        (r"\d+(?:\.\d+)?", "<N>"),
    ]
    .into_iter()
    .map(|(p, r)| (Regex::new(p).unwrap(), r))
    .collect()
});

/// The shape of a line: its variable parts as placeholders (`<N>`, `<HEX>`, `<UUID>`, `<TS>`, `<IP>`, `<STR>`).
pub fn normalize(s: &str) -> String {
    let mut t = aix_extract::redact::redact_line(s);
    for (re, rep) in NORM.iter() {
        // a long hex run is an id when it has a digit (a word like `deadbeefs` stays)
        if re.as_str() == r"(?i)\b[0-9a-f]{8,}\b" {
            t = re.replace_all(&t, |c: &regex::Captures| if c[0].bytes().any(|b| b.is_ascii_digit()) { rep.to_string() } else { c[0].to_string() }).into_owned();
        } else {
            t = re.replace_all(&t, *rep).into_owned();
        }
    }
    t
}

/// Where a row is, for a `--norm` example: `path:line`, else the input line number.
fn loc(r: &Row, i: usize) -> String {
    match (r.path(), r.line()) {
        (Some(p), Some(l)) => format!("{p}:{l}"),
        (Some(p), None) => p.to_string(),
        _ => format!("line {}", i + 1),
    }
}

/// Apply a spec to rows: (the rows kept or the count rows, how many were removed).
pub fn apply(ix: Option<&Index>, rows: &Rows, sp: &Spec, pattern: Option<&Regex>) -> (Rows, usize) {
    let mut order: Vec<String> = vec![];
    let mut idx: HashMap<String, (usize, usize, usize)> = HashMap::new(); // key -> (first row, last row, count)
    for (i, (r, m)) in rows.iter().enumerate() {
        let mut k = key_of(ix, r, m, &sp.key, pattern);
        if sp.norm {
            k = normalize(&k);
        }
        match idx.get_mut(&k) {
            Some(e) => {
                e.1 = i;
                e.2 += 1;
            }
            None => {
                idx.insert(k.clone(), (i, i, 1));
                order.push(k);
            }
        }
    }
    let removed = rows.len() - order.len();
    let mut out = Rows { partial: rows.partial.clone(), unknown: rows.unknown, redacted: rows.redacted, truncated: rows.truncated, bytes: rows.bytes, ..Default::default() };
    if sp.sort_count {
        // stable: equal counts keep their first-appearance order
        order.sort_by(|a, b| idx[b].2.cmp(&idx[a].2));
    }
    for k in order {
        let (first, last, n) = idx[&k];
        let (r, m) = (&rows.rows[first], &rows.meta[first]);
        if sp.norm {
            let (a, b) = (loc(r, first), loc(&rows.rows[last], last));
            let ex = if n == 1 {
                format!("({a})")
            } else {
                // the last example names only the line when it is in the same file
                let b = match (a.rsplit_once(':'), b.rsplit_once(':')) {
                    (Some((pa, _)), Some((pb, lb))) if pa == pb && !pa.starts_with("line") => format!(":{lb}"),
                    _ => b,
                };
                format!("(first {a}, last {b})")
            };
            out.push(Row::Count { key: format!("{k} {ex}"), n: n as u64 }, Meta { kind: "norm".into(), ..Default::default() });
        } else if sp.count {
            out.push(Row::Count { key: r.render(m), n: n as u64 }, Meta { kind: "group".into(), ..Default::default() });
        } else {
            out.push(r.clone(), m.clone());
        }
    }
    (out, removed)
}

/// The footer line.
pub fn footer(removed: usize, sp: &Spec) -> String {
    format!("({removed} duplicate{} removed (by {}{}))", if removed == 1 { "" } else { "s" }, sp.key.name(), if sp.norm { ", normalised" } else { "" })
}

/// The global `--dedup[=KEY]` on a command's printed answer: repeated row lines are dropped (headers, notes and
/// footers stay); the bare rows follow.
pub fn apply_lines(ix: Option<&Index>, lines: &mut Vec<String>, bare: Option<&mut Vec<String>>, sp: &Spec) -> usize {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut keep: Vec<String> = vec![];
    let mut removed = 0;
    let keyed = |l: &str| -> Option<String> {
        let rs = crate::rows::parse_text(l, ix);
        let (r, m) = rs.iter().next()?;
        let mut k = key_of(ix, r, m, &sp.key, None);
        if sp.norm {
            k = normalize(&k);
        }
        Some(k)
    };
    let mut gone: Vec<bool> = Vec::with_capacity(lines.len());
    for l in lines.iter() {
        let mut g = false;
        if crate::outfmt::is_row_line(l) && !l.starts_with("==") {
            if let Some(k) = keyed(l) {
                let e = seen.entry(k).or_insert(0);
                *e += 1;
                if *e > 1 {
                    removed += 1;
                    g = true;
                }
            }
        }
        gone.push(g);
    }
    let all: Vec<String> = std::mem::take(lines);
    keep.extend(drop_orphan_context(all, gone));
    *lines = keep;
    if let Some(b) = bare {
        let mut seen2: HashMap<String, ()> = HashMap::new();
        let gone: Vec<bool> = b
            .iter()
            .map(|l| {
                if l.starts_with('\u{2026}') || l.starts_with("==") {
                    return false;
                }
                match keyed(l) {
                    Some(k) => seen2.insert(k, ()).is_some(),
                    None => false,
                }
            })
            .collect();
        let all = std::mem::take(b);
        *b = drop_orphan_context(all, gone);
    }
    if removed > 0 {
        let f = footer(removed, sp);
        // bare output: the one footer style (`…`)
        lines.push(if crate::outfmt::current().bare { format!("\u{2026} {}", f.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(&f)) } else { f });
    }
    removed
}

static MATCH_ROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\S+?:\d+:").unwrap());
static CTX_ROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\S+?-\d+-").unwrap());

/// grep -A/-B/-C output after dedup: a context group (between `--` lines) whose matching rows were all removed
/// goes with them (its context lines and one separator), so no context is left without its match.
fn drop_orphan_context(lines: Vec<String>, gone: Vec<bool>) -> Vec<String> {
    let is_sep = |l: &str| l.trim() == "--";
    if !lines.iter().any(|l| is_sep(l)) && !lines.iter().any(|l| CTX_ROW.is_match(l) && !MATCH_ROW.is_match(l)) {
        return lines.into_iter().zip(gone).filter(|(_, g)| !g).map(|(l, _)| l).collect();
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        if is_sep(&lines[i]) || !(MATCH_ROW.is_match(&lines[i]) || CTX_ROW.is_match(&lines[i])) {
            if !gone[i] {
                out.push(lines[i].clone());
            }
            i += 1;
            continue;
        }
        // one group: consecutive match/context rows
        let mut j = i;
        while j < lines.len() && !is_sep(&lines[j]) && (MATCH_ROW.is_match(&lines[j]) || CTX_ROW.is_match(&lines[j])) {
            j += 1;
        }
        let matches: Vec<usize> = (i..j).filter(|k| MATCH_ROW.is_match(&lines[*k])).collect();
        let orphan = !matches.is_empty() && matches.iter().all(|k| gone[*k]);
        if orphan {
            // drop the group and the separator after it (or the one before it when it ends the output)
            if j < lines.len() && is_sep(&lines[j]) {
                j += 1;
            } else if out.last().is_some_and(|l| is_sep(l)) {
                out.pop();
            }
        } else {
            out.extend((i..j).filter(|k| !gone[*k]).map(|k| lines[k].clone()));
        }
        i = j;
    }
    out
}

static BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^== (?:[\w-]+ )+?(?P<p>[\w@.+\-/]+):(?P<a>\d+)-(?P<b>\d+) \((?P<n>\d+) lines?\)(?: \(.*\))?$").unwrap());

/// Cross-section dedupe of a `;` sequence / batch: a code block (`== <kind> F:A-B (N lines)` and its numbered lines)
/// whose range an earlier section printed in full is replaced by one line naming that section.
pub fn sections(lines: &mut Vec<String>) -> usize {
    // (path, a, b, section text, section number): an identical command later in the sequence is another section
    let mut shown: Vec<(String, usize, usize, String, usize)> = vec![];
    let mut section = String::new();
    let mut sec_no = 0usize;
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut replaced = 0;
    let mut i = 0;
    while i < lines.len() {
        let l = &lines[i];
        if let Some(c) = l.strip_prefix("== aix ") {
            section = c.to_string();
            sec_no += 1;
            out.push(l.clone());
            i += 1;
            continue;
        }
        if let Some(c) = BLOCK.captures(l) {
            let (p, a, b) = (c["p"].to_string(), c["a"].parse::<usize>().unwrap_or(0), c["b"].parse::<usize>().unwrap_or(0));
            // the block's numbered lines
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().split(' ').next().is_some_and(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_digit())) {
                j += 1;
            }
            let full = j - i - 1 == b + 1 - a;
            if let Some(prev) = shown.iter().find(|s| s.0 == p && s.1 <= a && b <= s.2 && s.4 != sec_no) {
                out.push(format!("({p}:{a}-{b} shown above in == aix {})", prev.3));
                replaced += 1;
                i = j;
                continue;
            }
            if full {
                shown.push((p, a, b, section.clone(), sec_no));
            }
        }
        out.push(l.clone());
        i += 1;
    }
    *lines = out;
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(lines: &[&str]) -> Rows {
        crate::rows::parse_text(&lines.join("\n"), None)
    }

    #[test]
    fn keeps_first_occurrence_in_order() {
        let r = rows(&["b", "a", "b", "c", "a"]);
        let (o, n) = apply(None, &r, &Spec::parse(&[]).unwrap(), None);
        assert_eq!((o.bare_lines(), n), (vec!["b".to_string(), "a".into(), "c".into()], 2));
        let sp = Spec::parse(&["-c".into(), "--sort".into(), "count".into()]).unwrap();
        let (o, _) = apply(None, &r, &sp, None);
        assert_eq!(o.bare_lines(), vec!["2\tb".to_string(), "2\ta".into(), "1\tc".into()]);
    }

    #[test]
    fn norm_collapses_variable_parts() {
        assert_eq!(normalize("ERROR timeout after 500ms on 10.0.0.12:8080 id=3f2a9c1be0d4"), "ERROR timeout after <N>ms on <IP> id=<HEX>");
        assert_eq!(normalize("at 2026-10-24T10:00:01Z user \"bob\" uuid 123e4567-e89b-12d3-a456-426614174000"), "at <TS> user <STR> uuid <UUID>");
        let r = rows(&["ERROR timeout after 500ms on 10.0.0.1", "ok", "ERROR timeout after 20ms on 10.0.0.9"]);
        let sp = Spec::parse(&["--norm".into()]).unwrap();
        let (o, n) = apply(None, &r, &sp, None);
        assert_eq!(n, 1);
        assert_eq!(o.bare_lines()[0], "2\tERROR timeout after <N>ms on <IP> (first line 1, last line 3)");
    }

    #[test]
    fn keys() {
        assert_eq!(Key::parse("dir:2").unwrap(), Key::Dir(Some(2)));
        assert!(Key::parse("bogus").is_err());
        let r = rows(&["src/a/x.rs:1:foo level=warn", "src/a/y.rs:2:foo level=warn", "src/b/z.rs:3:bar level=error"]);
        let (o, _) = apply(None, &r, &Spec::parse(&["field".into(), "level".into()]).unwrap(), None);
        assert_eq!(o.len(), 2);
        let (o, _) = apply(None, &r, &Spec::parse(&["text".into()]).unwrap(), None);
        assert_eq!(o.len(), 2);
        let (o, _) = apply(None, &r, &Spec::parse(&["dir".into()]).unwrap(), None);
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn sections_replace_ranges_shown_above() {
        let mut l: Vec<String> = ["== aix code a.rs:1-2", "== lines a.rs:1-2 (2 lines)", "1 x", "2 y", "== aix code a.rs:2-2", "== lines a.rs:2-2 (1 line)", "2 y"].iter().map(|s| s.to_string()).collect();
        assert_eq!(sections(&mut l), 1);
        assert_eq!(l.last().unwrap(), "(a.rs:2-2 shown above in == aix code a.rs:1-2)");
        // the same command twice: the second is named, not printed again
        let mut l: Vec<String> = ["== aix code a.rs:1-2", "== lines a.rs:1-2 (2 lines)", "1 x", "2 y", "== aix code a.rs:1-2", "== lines a.rs:1-2 (2 lines)", "1 x", "2 y"].iter().map(|s| s.to_string()).collect();
        assert_eq!(sections(&mut l), 1);
        assert_eq!(l.last().unwrap(), "(a.rs:1-2 shown above in == aix code a.rs:1-2)");
    }
}
