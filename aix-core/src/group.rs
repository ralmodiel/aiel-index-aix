//! `--group-by <key>` / `--having '<expr>'`: the shape of an answer instead of its rows. The answer's rows are keyed,
//! loaded into a temp table and compiled to `GROUP BY ... HAVING ...` with bound parameters (a whitelist grammar, never
//! concatenated SQL).

use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;
use rusqlite::types::Value as Sql;

use crate::excl::{file_class, line_path};
use crate::index::Index;

pub const HAVING_HELP: &str = "(--having: count>N, count>=N, count=N, count<N, count between A and B, share>0.1, joined with and/or)";

/// Keys per command family.
pub fn keys_for(cmd: &str) -> &'static str {
    match cmd {
        "callers" | "callees" | "impact" => "file, dir[:N], kind, lang, caller-class, callee, conf",
        "grep" => "file, dir[:N], kind, lang, match",
        "brief" | "trace" | "explain" | "endpoint" | "qa" | "impact_" => "file, dir[:N], kind, lang, endpoint, method, role, table, op",
        "table" => "file, dir[:N], kind, lang, table, op",
        "history" | "bugs" => "month, is_fix, file, dir[:N], kind",
        _ => "file, dir[:N], kind, lang",
    }
}

fn supported(cmd: &str, key: &str) -> bool {
    match key {
        "file" | "dir" | "kind" | "lang" => true,
        "caller-class" | "callee" | "conf" => matches!(cmd, "callers" | "callees" | "impact"),
        "endpoint" | "method" | "role" => matches!(cmd, "brief" | "trace" | "explain" | "endpoint" | "qa" | "impact" | "scope" | "symbol"),
        "table" | "op" => matches!(cmd, "table" | "trace" | "explain" | "brief"),
        "month" | "is_fix" => matches!(cmd, "history" | "bugs" | "tasks" | "brief"),
        "match" => cmd == "grep",
        _ => false,
    }
}

/// `dir:2` -> ("dir", 2).
pub fn split_key(k: &str) -> (String, usize) {
    match k.split_once(':') {
        Some((a, n)) => (a.to_ascii_lowercase(), n.parse().unwrap_or(1).max(1)),
        None => (k.to_ascii_lowercase(), 1),
    }
}

pub fn check_key(cmd: &str, k: &str) -> Result<(), String> {
    let (key, _) = split_key(k);
    if !supported(cmd, &key) {
        return Err(format!("(--group-by {k}: not available for {cmd}; keys: {})", keys_for(cmd)));
    }
    if let Some((_, d)) = k.split_once(':') {
        match (key.as_str(), d.parse::<usize>()) {
            ("dir", Ok(n)) if n >= 1 => {}
            ("match", Ok(_)) => {}
            ("dir", _) => return Err(format!("(--group-by {k}: the depth must be a number from 1, e.g. dir:2)")),
            ("match", _) => return Err(format!("(--group-by {k}: the group must be a number, e.g. match:1; match alone groups by the whole match)")),
            _ => return Err(format!("(--group-by {k}: only dir takes a depth (dir:N) and match a group (match:N))")),
        }
    }
    Ok(())
}

/// `match` -> 0 (the whole match), `match:2` -> 2 (capture group 2).
pub fn match_group(k: &str) -> usize {
    k.split_once(':').and_then(|x| x.1.parse().ok()).unwrap_or(0)
}

/// One `count|share <op> <number>` term (or `between A and B`) of the grammar, with the connector before it.
#[derive(Debug, Clone)]
pub struct Term {
    pub or_before: bool,
    pub share: bool,
    pub op: String,
    pub a: f64,
    pub b: f64,
}

/// The `--having` grammar as terms (shared by `grep` and `logs`: one grammar, one error text).
pub fn parse_terms(src: &str) -> Result<Vec<Term>, String> {
    static TOK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\s*(count|share|between|and|or|>=|<=|!=|<>|=|>|<|\d+(?:\.\d+)?)").unwrap());
    let mut toks: Vec<String> = vec![];
    let mut pos = 0;
    let src = src.trim();
    while pos < src.len() {
        let Some(m) = TOK.find_at(src, pos).filter(|m| m.start() == pos) else { return Err(HAVING_HELP.into()) };
        toks.push(m.as_str().trim().to_ascii_lowercase());
        pos = m.end();
    }
    if toks.is_empty() {
        return Err(HAVING_HELP.into());
    }
    let num = |s: &str| s.parse::<f64>().ok();
    let mut terms: Vec<Term> = vec![];
    let (mut i, mut or_before) = (0, false);
    let mut expect_term = true;
    while i < toks.len() {
        if expect_term {
            let share = match toks[i].as_str() {
                "count" => false,
                "share" => true,
                _ => return Err(HAVING_HELP.into()),
            };
            let op = toks.get(i + 1).map(String::as_str).unwrap_or("");
            if op == "between" {
                let (a, and, b) = (toks.get(i + 2).and_then(|t| num(t)), toks.get(i + 3).map(String::as_str), toks.get(i + 4).and_then(|t| num(t)));
                let (Some(a), Some("and"), Some(b)) = (a, and, b) else { return Err(HAVING_HELP.into()) };
                terms.push(Term { or_before, share, op: "between".into(), a, b });
                i += 5;
            } else if matches!(op, ">" | ">=" | "<" | "<=" | "=" | "!=" | "<>") {
                let Some(v) = toks.get(i + 2).and_then(|t| num(t)) else { return Err(HAVING_HELP.into()) };
                terms.push(Term { or_before, share, op: op.into(), a: v, b: 0.0 });
                i += 3;
            } else {
                return Err(HAVING_HELP.into());
            }
            expect_term = false;
        } else {
            match toks[i].as_str() {
                "and" => or_before = false,
                "or" => or_before = true,
                _ => return Err(HAVING_HELP.into()),
            }
            i += 1;
            expect_term = true;
        }
    }
    if expect_term {
        return Err(HAVING_HELP.into());
    }
    Ok(terms)
}

/// Does a group of weight `n` (out of `total`) pass? AND binds tighter than OR, as in the SQL form.
pub fn having_keep(terms: &[Term], n: f64, total: f64) -> bool {
    let mut any = false;
    let mut all = true;
    for (i, t) in terms.iter().enumerate() {
        if t.or_before && i > 0 {
            any |= all;
            all = true;
        }
        let v = if t.share { n / total.max(1.0) } else { n };
        let ok = match t.op.as_str() {
            "between" => v >= t.a && v <= t.b,
            ">" => v > t.a,
            ">=" => v >= t.a,
            "<" => v < t.a,
            "<=" => v <= t.a,
            "=" => (v - t.a).abs() < 1e-9,
            _ => (v - t.a).abs() >= 1e-9,
        };
        all &= ok;
    }
    any | all
}

pub fn dir_key(path: &str, depth: usize) -> String {
    let segs: Vec<&str> = path.split('/').collect();
    let d = depth.min(segs.len().saturating_sub(1));
    if d == 0 {
        ".".into()
    } else {
        segs[..d].join("/")
    }
}

/// `dir` with no depth: the first depth at which the paths fall into more than one directory (every path under
/// `src/` at depth 1 is one useless group), at most 8.
pub fn auto_dir_depth(paths: &[String]) -> usize {
    let mut d = 1;
    while d < 8 {
        let keys: std::collections::HashSet<String> = paths.iter().map(|p| dir_key(p, d)).collect();
        let deeper: std::collections::HashSet<String> = paths.iter().map(|p| dir_key(p, d + 1)).collect();
        if keys.len() > 1 || deeper == keys {
            break;
        }
        d += 1;
    }
    d
}

pub fn file_key(path: &str, key: &str, depth: usize) -> String {
    match key {
        "file" => path.to_string(),
        "dir" => dir_key(path, depth),
        "kind" => crate::excl::kind_word(file_class(path)).to_string(), // the -x / --only spelling: docs, scripts, tests
        _ => path.rsplit_once('.').map(|x| x.1.to_ascii_lowercase()).unwrap_or_else(|| "none".into()),
    }
}

static TOKEN_AFTER_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\S+?:\d+(?:-\d+)?\s+(\S+)").unwrap());
static CONF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\((exact|resolved|heuristic|name)\)").unwrap());
static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(GET|POST|PUT|PATCH|DELETE) (/[^\s)]*)").unwrap());
static ROLES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"roles ([A-Za-z_][\w,+]*)|\[([a-z_][a-z_,+0-9]*)\]").unwrap());
static TABLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*table\s+(\w+)\s+\((read|write)\)").unwrap());
static MONTH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\d{4}-\d{2})-\d{2}\b").unwrap());
static FIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bfix").unwrap());

/// The group keys of one result line (empty: the line is not a row for this key).
pub fn line_keys(cmd: &str, key: &str, depth: usize, l: &str) -> Vec<String> {
    if l.starts_with("==") || l.starts_with('(') || l.contains(" defined: ") {
        return vec![];
    }
    match key {
        "file" | "dir" | "kind" | "lang" => line_path(l).map(|p| vec![file_key(p, key, depth)]).unwrap_or_default(),
        "caller-class" | "callee" => {
            if line_path(l).is_none() {
                return vec![];
            }
            let Some(t) = TOKEN_AFTER_PATH.captures(l).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()) else { return vec![] };
            if key == "callee" {
                return vec![t];
            }
            vec![t.rsplit_once('.').map(|x| x.0.to_string()).unwrap_or(t)]
        }
        "conf" => CONF.captures(l).and_then(|c| c.get(1)).map(|m| vec![m.as_str().to_string()]).unwrap_or_default(),
        "endpoint" => ENDPOINT.captures(l).map(|c| vec![format!("{} {}", &c[1], &c[2])]).unwrap_or_default(),
        "method" => ENDPOINT.captures(l).map(|c| vec![c[1].to_string()]).unwrap_or_default(),
        "role" => {
            let mut v = vec![];
            if let Some(c) = ROLES.captures(l) {
                let s = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()).unwrap_or("");
                v.extend(s.split(',').filter(|r| !r.is_empty() && !r.starts_with('+')).map(str::to_string));
            }
            v
        }
        "table" => TABLE.captures(l).map(|c| vec![c[1].to_string()]).unwrap_or_default(),
        "op" => TABLE.captures(l).map(|c| vec![if &c[2] == "write" { "w".into() } else { "r".into() }]).unwrap_or_default(),
        "month" => MONTH.captures(l).map(|c| vec![c[1].to_string()]).unwrap_or_default(),
        "is_fix" => {
            if MONTH.is_match(l) {
                vec![if FIX.is_match(l) { "fix".into() } else { "other".into() }]
            } else {
                vec![]
            }
        }
        _ => {
            let _ = cmd;
            vec![]
        }
    }
}

/// Compile the HAVING mini-grammar: `count>N | count>=N | count=N | count<N | count<=N | count between A and B | share>F`,
/// joined by `and` / `or`. Returns SQL over the aggregate `SUM(n)` with `?` placeholders, and the bound values.
pub fn parse_having(src: &str) -> Result<(String, Vec<Sql>), String> {
    let terms = parse_terms(src)?;
    let mut sql = String::new();
    let mut params: Vec<Sql> = vec![];
    for (i, t) in terms.iter().enumerate() {
        if i > 0 {
            sql.push_str(if t.or_before { " OR " } else { " AND " });
        }
        let agg = if t.share { "(SUM(n) * 1.0 / (SELECT SUM(n) FROM temp.aix_g))" } else { "SUM(n)" };
        if t.op == "between" {
            sql.push_str(&format!("({agg} BETWEEN ? AND ?)"));
            params.push(Sql::Real(t.a));
            params.push(Sql::Real(t.b));
        } else {
            sql.push_str(&format!("({agg} {} ?)", t.op));
            params.push(Sql::Real(t.a));
        }
    }
    Ok((sql, params))
}

/// GROUP BY over weighted keys. `sort`: "count" (desc), "count:asc" or "key". Returns (groups after HAVING, total weight).
pub fn grouped(ix: &Index, items: &[(String, i64)], having: Option<&str>, sort: &str) -> Result<(Vec<(String, i64)>, i64), String> {
    let c = &ix.conn;
    c.execute_batch("CREATE TEMP TABLE IF NOT EXISTS aix_g(k TEXT, n INT); DELETE FROM temp.aix_g;").map_err(|e| e.to_string())?;
    {
        let mut st = c.prepare("INSERT INTO temp.aix_g VALUES(?, ?)").map_err(|e| e.to_string())?;
        for (k, n) in items {
            st.execute(rusqlite::params![k, n]).map_err(|e| e.to_string())?;
        }
    }
    let total: i64 = c.query_row("SELECT COALESCE(SUM(n),0) FROM temp.aix_g", [], |r| r.get(0)).unwrap_or(0);
    let (hv, params) = match having {
        Some(h) => {
            let (s, p) = parse_having(h)?;
            (format!(" HAVING {s}"), p)
        }
        None => (String::new(), vec![]),
    };
    let order = match sort {
        "count:asc" => "ORDER BY SUM(n) ASC, k ASC",
        "key" => "ORDER BY k ASC",
        _ => "ORDER BY SUM(n) DESC, k ASC",
    };
    let sql = format!("SELECT k, SUM(n) FROM temp.aix_g GROUP BY k{hv} {order}");
    let mut st = c.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = st
        .query_map(rusqlite::params_from_iter(params.iter()), |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();
    let _ = c.execute_batch("DELETE FROM temp.aix_g;");
    Ok((rows, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn having_grammar() {
        let (s, p) = parse_having("count>5 and share>0.1").unwrap();
        assert_eq!(s, "(SUM(n) > ?) AND ((SUM(n) * 1.0 / (SELECT SUM(n) FROM temp.aix_g)) > ?)");
        assert_eq!(p.len(), 2);
        let (s, p) = parse_having("count between 2 and 9 or count=1").unwrap();
        assert!(s.contains("BETWEEN ? AND ?") && s.contains(" OR ") && p.len() == 3, "{s}");
        for bad in ["", "count", "count>", "count>5 and", "1=1; drop table files", "count > 'x'", "sum>3"] {
            assert!(parse_having(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn having_in_memory_matches_the_sql_grammar() {
        let t = parse_terms("count>5 and share>0.1").unwrap();
        assert!(having_keep(&t, 6.0, 20.0) && !having_keep(&t, 6.0, 100.0) && !having_keep(&t, 5.0, 20.0));
        let t = parse_terms("count between 2 and 9 or count=1").unwrap();
        assert!(having_keep(&t, 1.0, 9.0) && having_keep(&t, 4.0, 9.0) && !having_keep(&t, 12.0, 20.0));
        assert!(parse_terms("count>5; drop").is_err());
    }

    #[test]
    fn group_keys_are_checked() {
        assert!(check_key("grep", "dir:2").is_ok() && check_key("grep", "match:1").is_ok() && check_key("grep", "match").is_ok());
        for bad in ["dir:0", "dir:x", "match:x", "kind:2", "bogus"] {
            assert!(check_key("grep", bad).is_err(), "{bad}");
        }
        assert_eq!(match_group("match"), 0);
        assert_eq!(match_group("match:2"), 2);
        assert_eq!(file_key("docs/a.md", "kind", 1), "docs");
    }

    #[test]
    fn keys() {
        assert_eq!(line_keys("callers", "caller-class", 1, "a/B.java:10 UserResource.save (exact)"), vec!["UserResource"]);
        assert_eq!(line_keys("grep", "dir", 2, "  frontend/src/pages/A.tsx:3: x"), vec!["frontend/src"]);
        assert_eq!(line_keys("brief", "endpoint", 1, "    foo GET /a/b -> X.java:4 [teacher,admin,+2]"), vec!["GET /a/b"]);
        assert_eq!(line_keys("brief", "role", 1, "    foo GET /a/b -> X.java:4 [teacher,admin,+2]"), vec!["teacher", "admin"]);
        assert_eq!(line_keys("trace", "table", 1, "        table    users (write) a/User.java:1"), vec!["users"]);
        assert_eq!(line_keys("history", "month", 1, "  2cf548da 2026-10-23 Fix thing"), vec!["2026-10"]);
    }
}
