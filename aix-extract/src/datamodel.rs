//! Data model extractor: ORM entities and their columns, schema migrations, foreign keys and raw data-access facts.
//!
//! Stacks (auto-detected per file, no configuration): JPA / Hibernate / Panache and Spring Data (tree-sitter on files
//! that declare an entity or a repository), SQLAlchemy and Django models, Prisma / TypeORM / Drizzle (table level),
//! Flyway / Prisma / plain SQL migrations (full DDL reader), Liquibase (XML and formatted SQL), Alembic, Rails and
//! Django migrations (name level). SQL strings found in Java / Python / TypeScript code become table-level access facts.
//! Everything here is per file; entity -> table resolution and the enclosing member are joined in aix-core.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Node;

use crate::model::*;
use crate::sqlparse::{looks_like_sql, parse_ddl, safe_default, table_ops, Ctx};
use crate::text::Lines;
use crate::ts_util::*;
use crate::Extractor;

pub struct DataModel;

impl Extractor for DataModel {
    fn name(&self) -> &'static str {
        "datamodel"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        matches!(ext_of(path), "java" | "py" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "sql" | "prisma" | "xml" | "yaml" | "yml" | "rb" | "php" | "cs" | "go")
            && !crate::is_test_path(path)
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            match f.ext() {
                "java" => java_file(f, &mut rows),
                "py" => python(f, &mut rows),
                "ts" | "tsx" | "js" | "jsx" | "mjs" => typescript(f, &mut rows),
                "sql" => sql_file(f, &mut rows),
                "prisma" => prisma(f, &mut rows),
                "xml" => liquibase_xml(f, &mut rows),
                "yaml" | "yml" => liquibase_yaml(f, &mut rows),
                "rb" => rails(f, &mut rows),
                "cs" => efcore(f, &mut rows),
                "go" => go_file(f, &mut rows),
                "php" => {
                    laravel(f, &mut rows);
                    if !f.path.contains("migrations/") {
                        eloquent(f, &mut rows);
                    }
                }
                _ => {}
            }
        }
        rows
    }
}

// ───────────────────────────── helpers ─────────────────────────────

/// camelCase / PascalCase -> snake_case (Hibernate's CamelCaseToUnderscores: acronyms stay together).
pub fn snake(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut o = String::new();
    for (i, &c) in cs.iter().enumerate() {
        if c.is_uppercase() {
            let prev = i.checked_sub(1).map(|p| cs[p]);
            let next = cs.get(i + 1).copied();
            let after_lower = prev.is_some_and(|p| p.is_lowercase() || p.is_ascii_digit());
            let acronym_end = prev.is_some_and(|p| p.is_uppercase()) && next.is_some_and(|n| n.is_lowercase());
            if i > 0 && (after_lower || acronym_end) {
                o.push('_');
            }
            o.extend(c.to_lowercase());
        } else {
            o.push(c);
        }
    }
    o
}

fn anno_name(t: &str) -> String {
    let t = t.trim().trim_start_matches('@');
    let head = t.split('(').next().unwrap_or("").trim();
    head.rsplit('.').next().unwrap_or("").to_string()
}

fn key_pos(t: &str, key: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = t[from..].find(key) {
        let at = from + i;
        let before_ok = at == 0 || !t.as_bytes()[at - 1].is_ascii_alphanumeric() && t.as_bytes()[at - 1] != b'_';
        let rest = t[at + key.len()..].trim_start();
        if before_ok && ((rest.starts_with('=') && !rest.starts_with("==")) || (rest.starts_with(':') && !rest.starts_with("::"))) {
            return Some(at + key.len() + (t[at + key.len()..].len() - rest.len()) + 1);
        }
        from = at + key.len();
    }
    None
}

fn arg_str(t: &str, key: &str) -> Option<String> {
    let p = key_pos(t, key)?;
    let r = t[p..].trim_start();
    let q = r.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let end = r[1..].find(q)?;
    Some(r[1..1 + end].to_string())
}

fn arg_bool(t: &str, key: &str) -> Option<bool> {
    let p = key_pos(t, key)?;
    let r = t[p..].trim_start();
    if r.starts_with("true") || r.starts_with("True") {
        Some(true)
    } else if r.starts_with("false") || r.starts_with("False") {
        Some(false)
    } else {
        None
    }
}

fn arg_num(t: &str, key: &str) -> Option<u32> {
    let p = key_pos(t, key)?;
    let r = t[p..].trim_start();
    let d: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
    d.parse().ok()
}

/// Text inside the balanced parentheses opening at `open` (index of '('), skipping string literals; and the index
/// after the closing paren.
pub fn balanced(text: &str, open: usize) -> Option<(&str, usize)> {
    let b = text.as_bytes();
    if b.get(open) != Some(&b'(') {
        return None;
    }
    let (mut depth, mut i) = (0i32, open);
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&text[open + 1..i], i + 1));
                }
            }
            q @ (b'"' | b'\'' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn str_lits(s: &str) -> Vec<String> {
    static R: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["']([^"'\n]*)["']"#).unwrap());
    R.captures_iter(s).map(|c| c[1].to_string()).collect()
}

/// Top-level comma split of an argument list (strings and nesting respected).
fn split_args(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let (mut depth, mut start, mut i) = (0i32, 0, 0);
    let mut out = vec![];
    while i < b.len() {
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            q @ (b'"' | b'\'' | b'`') => {
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b',' if depth == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < s.len() && !s[start..].trim().is_empty() {
        out.push(s[start..].trim().to_string());
    }
    out
}

fn clip(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n {
        s
    } else {
        let mut o: String = s.chars().take(n).collect();
        o.push('~');
        o
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Lang {
    Java,
    Py,
    Ts,
    /// Go: `//` and `/* */` comments, "..." and raw `...` strings (as TS)
    Go,
}

/// String literals of a source file: (offset of the literal, content). Adjacent literals joined by `+` (Java, TS)
/// or only whitespace (Python implicit concatenation) become one. Comments are skipped.
fn string_literals(text: &str, lang: Lang) -> Vec<(usize, String)> {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut out: Vec<(usize, String, usize)> = vec![]; // offset, content, end
    while i < n {
        let c = b[i];
        match c {
            b'/' if lang != Lang::Py && i + 1 < n && b[i + 1] == b'/' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if lang != Lang::Py && i + 1 < n && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < n && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'#' if lang == Lang::Py => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'"' | b'\'' | b'`' => {
                let q = c;
                let start = i;
                let triple = i + 2 < n && b[i + 1] == q && b[i + 2] == q && q != b'`';
                if lang == Lang::Java && q == b'\'' {
                    // char literal
                    i += 1;
                    while i < n && b[i] != b'\'' {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                    continue;
                }
                if triple {
                    i += 3;
                    let s = i;
                    while i + 2 < n && !(b[i] == q && b[i + 1] == q && b[i + 2] == q) {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    let e = i.min(n);
                    out.push((start, text[s..e].to_string(), (e + 3).min(n)));
                    i = (e + 3).min(n);
                } else {
                    i += 1;
                    let s = i;
                    while i < n && b[i] != q && !(b[i] == b'\n' && q != b'`') {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    let e = i.min(n);
                    out.push((start, text[s..e].to_string(), (e + 1).min(n)));
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    // join neighbours
    let mut res: Vec<(usize, String)> = vec![];
    let mut k = 0;
    while k < out.len() {
        let (off, mut s, mut end) = out[k].clone();
        while k + 1 < out.len() {
            let gap = &text[end.min(n)..out[k + 1].0.min(n)];
            let g = gap.trim();
            let join = g == "+" || (lang == Lang::Py && g.is_empty()) || (lang == Lang::Py && g == "\\");
            if !join {
                break;
            }
            k += 1;
            s.push_str(&out[k].1);
            end = out[k].2;
        }
        res.push((off, s));
        k += 1;
    }
    res
}

static SQL_FN_CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:from|join|select|call|perform|,)\s+(?:[a-z_]\w*\.)?([a-z_]\w*)\s*\(").unwrap());
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{[^}]*\}|\{[A-Za-z_][\w.]*\}|%s|%\([^)]*\)s").unwrap());

/// SQL / JPQL statements in string literals -> table-level access facts.
fn sql_strings(f: &SourceFile, lang: Lang, rows: &mut Rows) {
    let t = &f.text;
    if !(t.contains("select") || t.contains("SELECT") || t.contains("insert") || t.contains("INSERT") || t.contains("update")
        || t.contains("UPDATE") || t.contains("delete") || t.contains("DELETE") || t.contains("from ") || t.contains("MERGE"))
    {
        return;
    }
        let fn_probe = |clean: &str, line: u32, rows: &mut Rows| {
            // a call of a SQL function (`FROM fn_x(...)`, `SELECT fn_x(...)`): resolved against the migrations' functions
            const BUILTIN: &[&str] = &["cast", "count", "sum", "min", "max", "avg", "coalesce", "extract", "lower", "upper", "round", "exists", "in", "values", "any", "all", "now", "date_trunc", "unnest", "nullif", "concat", "trim", "length", "array_agg", "string_agg", "row_number", "rank", "over", "filter", "distinct", "not", "and", "or", "using", "on", "where", "set", "as"];
            for m in SQL_FN_CALL.captures_iter(clean) {
                let n = m[1].to_lowercase();
                if !BUILTIN.contains(&n.as_str()) {
                    rows.data_raw.push(DataRaw { file: f.path.clone(), line: line as _, kind: "fncall".into(), target: n, op: String::new(), via: "sqlfn".into(), extra: String::new() });
                }
            }
        };
    let lt = Lines::new(t);
    for (off, lit) in string_literals(t, lang) {
        if lit.len() < 12 || lit.len() > 20_000 {
            continue;
        }
        let lit = lit.replace("\\n", " ").replace("\\t", " ");
        let clean = PLACEHOLDER.replace_all(&lit, " _x_ ").to_string();
        let line = lt.at(off);
        fn_probe(&clean, line as u32, rows);
        if !looks_like_sql(&clean) {
            continue;
        }
        let ctx_start = off.saturating_sub(90);
        let before = t.get(ctx_start..off).unwrap_or("");
        let after = t.get(off..(off + lit.len() + 120).min(t.len())).unwrap_or("");
        let native = before.contains("NativeQuery") || before.contains("nativeQuery") || after.contains("nativeQuery = true")
            || after.contains("nativeQuery=true");
        let hql = !native
            && (before.contains("createQuery") || before.contains("@Query") || before.contains("@NamedQuery") || before.contains("createNamedQuery")
                || clean.trim_start().to_lowercase().starts_with("from "));
        for (name, op) in table_ops(&clean, hql) {
            if name.starts_with("_x_") || name.len() < 2 {
                continue;
            }
            rows.data_raw.push(DataRaw {
                file: f.path.clone(),
                line,
                kind: if hql { "jpql" } else { "table" }.into(),
                target: name,
                op: op.to_string(),
                via: if hql { "jpql" } else { "native" }.into(),
                extra: String::new(),
            });
        }
    }
}


// ───────────────────────────── state literals ─────────────────────────────

/// A column / field that names a lifecycle state: `status`, `unlock_status`, `orderState`, `stage`, `phase`.
fn is_state_col(name: &str) -> bool {
    let n = name.rsplit('.').next().unwrap_or(name).to_lowercase().replace('_', "");
    n.ends_with("status") || n.ends_with("state") || n == "stage" || n == "phase"
}

fn state_value_ok(v: &str) -> bool {
    let v = v.trim();
    v.len() >= 2 && v.len() <= 40 && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '))
}

static ST_CMP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b([A-Za-z_][\w.]*)\s*(=|<>|!=)\s*'([^']{1,60})'").unwrap());
static ST_IN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b([A-Za-z_][\w.]*)\s+(?:not\s+)?in\s*\(\s*((?:'[^']*'\s*,?\s*)+)\)").unwrap());
static ST_FROM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:from|join|update|into)\s+([A-Za-z_][\w.]*)(?:\s+(?:as\s+)?([A-Za-z_]\w*))?").unwrap());
static ST_QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"'([^']*)'").unwrap());
static ST_WHERE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bwhere\b").unwrap());
// code around a string literal (text before it / after it on the same line)
static ST_SET_BEFORE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:^|[^=!<>])\b([\w.]*(?:status|state))\s*=\s*$|\.set(\w*(?:Status|State))\(\s*$").unwrap());
static ST_TEST_BEFORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([\w.]*(?:status|state))\s*(?:===?|!==?)\s*$|\b(\w*(?:status|state))(?:\(\))?\s*\.equals(?:IgnoreCase)?\(\s*$|\bequals\(\s*[\w.()]*?\b(\w*(?:status|state))(?:\(\))?\s*,\s*$").unwrap()
});
static ST_TEST_AFTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*\.equals(?:IgnoreCase)?\(\s*[\w.()]*?\b(\w*(?:status|state))(?:\(\))?\s*\)|^\s*(?:===?|!==?)\s*[\w.]*?\b(\w*(?:status|state))\b").unwrap());

/// Lifecycle-state literals: an UPDATE / `Entity.update("status = 'x' ... where status = 'y'")` fragment that sets a state
/// column to a literal (with the states it is guarded by), a SQL / JPQL / Panache predicate that tests one
/// (`status = 'x'`, `status in ('a','b')`), and code that assigns or compares a state field with a literal
/// (`r.status = "x"`, `"x".equals(r.status)`, `status === 'x'`). Rows are `kind = state`: target = column / field,
/// op = set | test, extra = the value (set rows: `value|guard1,guard2`). Tables are joined in the core.
fn state_literals(f: &SourceFile, lang: Lang, rows: &mut Rows) {
    let t = &f.text;
    let lo = t.to_lowercase();
    if !(lo.contains("status") || lo.contains("state")) {
        return;
    }
    let lt = Lines::new(t);
    // via = "state" or "state:<table or entity named by the literal's alias for this column>"
    let mut push = |off: usize, col: &str, op: &str, val: String, hint: &str| {
        let via = if hint.is_empty() { "state".to_string() } else { format!("state:{hint}") };
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(off), kind: "state".into(), target: col.rsplit('.').next().unwrap_or(col).to_string(), op: op.into(), via, extra: val });
    };
    for (off, lit) in string_literals(t, lang) {
        let lit = lit.replace("\\n", " ").replace("\\t", " ").replace('\n', " ");
        let before_all = t.get(off.saturating_sub(120)..off).unwrap_or("");
        let before_line = before_all.rsplit('\n').next().unwrap_or("");
        // 1. a query / update fragment: the literal itself holds `col = 'x'` comparisons
        if lit.contains('\'') && lit.len() >= 8 {
            let is_update = lit.trim_start().to_lowercase().starts_with("update ") || {
                let b = before_all.to_lowercase();
                b.rsplit('\n').take(3).any(|l| l.contains("update(") || l.contains("executeupdate") || l.contains("updateall"))
            };
            // alias -> table / entity named in FROM / JOIN / UPDATE of this literal
            let mut aliases: Vec<(String, String)> = vec![];
            for c in ST_FROM.captures_iter(&lit) {
                let name = c[1].rsplit('.').next().unwrap_or(&c[1]).to_string();
                let al = c.get(2).map(|m| m.as_str().to_string()).filter(|a| !matches!(a.to_lowercase().as_str(), "where" | "set" | "on" | "inner" | "left" | "right" | "outer" | "cross" | "join" | "order" | "group" | "having" | "limit" | "values" | "using" | "and" | "or" | "select"));
                aliases.push((al.unwrap_or_else(|| name.clone()), name));
            }
            let hint_for = |qcol: &str| -> String {
                match qcol.rsplit_once('.') {
                    Some((q, _)) => aliases.iter().find(|a| a.0.eq_ignore_ascii_case(q) || a.1.eq_ignore_ascii_case(q)).map(|a| a.1.clone()).unwrap_or_default(),
                    None if aliases.len() == 1 => aliases[0].1.clone(),
                    None => String::new(),
                }
            };
            let (head, tail) = match ST_WHERE.find(&lit) {
                Some(m) => (&lit[..m.start()], &lit[m.end()..]),
                None => (if is_update { lit.as_str() } else { "" }, if is_update { "" } else { lit.as_str() }),
            };
            let mut guards: Vec<(String, String)> = vec![]; // (col, value) of the where part
            for c in ST_CMP.captures_iter(tail) {
                if is_state_col(&c[1]) && state_value_ok(&c[3]) {
                    guards.push((c[1].rsplit('.').next().unwrap_or(&c[1]).to_string(), c[3].to_string()));
                    push(off, &c[1], "test", c[3].to_string(), &hint_for(&c[1]));
                }
            }
            for c in ST_IN.captures_iter(tail) {
                if is_state_col(&c[1]) {
                    for q in ST_QUOTED.captures_iter(&c[2]) {
                        if state_value_ok(&q[1]) {
                            guards.push((c[1].rsplit('.').next().unwrap_or(&c[1]).to_string(), q[1].to_string()));
                            push(off, &c[1], "test", q[1].to_string(), &hint_for(&c[1]));
                        }
                    }
                }
            }
            if is_update {
                for c in ST_CMP.captures_iter(head) {
                    if &c[2] == "=" && is_state_col(&c[1]) && state_value_ok(&c[3]) {
                        let col = c[1].rsplit('.').next().unwrap_or(&c[1]).to_string();
                        let from: Vec<&str> = guards.iter().filter(|g| g.0 == col).map(|g| g.1.as_str()).collect();
                        push(off, &c[1], "set", format!("{}|{}", &c[3], from.join(",")), &hint_for(&c[1]));
                    }
                }
            }
            continue;
        }
        // 2. a bare literal compared with / assigned to a state field in code
        if !state_value_ok(&lit) {
            continue;
        }
        let end = off + lit.len() + 2;
        let after = t.get(end.min(t.len())..(end + 90).min(t.len())).unwrap_or("");
        let after = after.split('\n').next().unwrap_or("");
        if let Some(c) = ST_SET_BEFORE.captures(before_line) {
            let col = c.get(1).or(c.get(2)).map(|m| m.as_str()).unwrap_or("");
            let col = if col.chars().next().is_some_and(|ch| ch.is_uppercase()) { col.to_lowercase() } else { col.to_string() };
            push(off, &col, "set", format!("{}|", lit.trim()), "");
        } else if let Some(c) = ST_TEST_BEFORE.captures(before_line).or_else(|| ST_TEST_AFTER.captures(after)) {
            let col = c.iter().skip(1).flatten().next().map(|m| m.as_str()).unwrap_or("");
            push(off, col, "test", lit.trim().to_string(), "");
        }
    }
}

// ───────────────────────────── Java ─────────────────────────────

static REPO_GEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([A-Za-z]*Repository[A-Za-z]*)\s*<\s*([A-Z]\w*)").unwrap());

fn tsimple(ty: &str) -> String {
    // List<Foo> / Set<Foo> / Foo[] / Foo<Bar> -> the innermost capitalised simple name
    let inner = ty.rsplit(['<', ',']).next().unwrap_or(ty);
    let inner = inner.trim().trim_end_matches(['>', ']', '[', ' ']);
    inner.rsplit('.').next().unwrap_or(inner).to_string()
}

fn is_primitive(ty: &str) -> bool {
    matches!(ty, "int" | "long" | "boolean" | "double" | "float" | "short" | "byte")
}

fn java_file(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let wants_tree = t.contains("@Entity") || t.contains("@MappedSuperclass") || t.contains("@Embeddable") || t.contains("Repository<");
    if wants_tree {
        if let Some(tree) = parse(&java(), t) {
            for n in named_children(tree.root_node()) {
                java_type(f, n, rows);
            }
        }
    }
    sql_strings(f, Lang::Java, rows);
    state_literals(f, Lang::Java, rows);
}

fn mod_info(decl: Node, src: &str) -> (Vec<String>, bool, bool) {
    let mut annos = vec![];
    let (mut is_static, mut transient) = (false, false);
    if let Some(m) = named_children(decl).into_iter().find(|c| c.kind() == "modifiers") {
        for c in children(m) {
            match c.kind() {
                "marker_annotation" | "annotation" => annos.push(squash(text(c, src))),
                _ => match text(c, src) {
                    "static" => is_static = true,
                    "transient" => transient = true,
                    _ => {}
                },
            }
        }
    }
    (annos, is_static, transient)
}

fn java_type(f: &SourceFile, n: Node, rows: &mut Rows) {
    let src = &f.text;
    if !matches!(n.kind(), "class_declaration" | "interface_declaration" | "record_declaration") {
        return;
    }
    let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else { return };
    let (annos, _, _) = mod_info(n, src);
    let has = |a: &str| annos.iter().any(|x| anno_name(x) == a);
    // supers (names only) and repository generics
    let mut supers = vec![];
    for c in named_children(n) {
        if matches!(c.kind(), "superclass" | "super_interfaces" | "extends_interfaces") {
            let ct = squash(text(c, src));
            for cap in REPO_GEN.captures_iter(&ct) {
                rows.data_raw.push(DataRaw {
                    file: f.path.clone(),
                    line: line(n),
                    kind: "repo".into(),
                    target: name.clone(),
                    op: String::new(),
                    via: "repo".into(),
                    extra: cap[2].to_string(),
                });
            }
            walk(c, |x| match x.kind() {
                "type_arguments" => false,
                "type_identifier" => {
                    supers.push(text(x, src).to_string());
                    false
                }
                "scoped_type_identifier" => {
                    supers.push(text(x, src).rsplit('.').next().unwrap_or("").to_string());
                    false
                }
                _ => true,
            });
        }
    }
    let kind = if has("Entity") {
        Some("entity")
    } else if has("MappedSuperclass") {
        Some("mapped-superclass")
    } else if has("Embeddable") {
        Some("embeddable")
    } else {
        None
    };
    if let Some(kind) = kind {
        let table_anno = annos.iter().find(|a| anno_name(a) == "Table");
        let mut table = table_anno.and_then(|a| arg_str(a, "name")).unwrap_or_else(|| snake(&name));
        if table.contains('.') {
            table = table.rsplit('.').next().unwrap_or("").to_string();
        }
        let panache = supers.iter().any(|s| s.starts_with("Panache"));
        rows.entities.push(EntityDef {
            file: f.path.clone(),
            line: line(n),
            end_line: end_line(n),
            name: name.clone(),
            table: if kind == "entity" { table.trim_matches('"').to_lowercase() } else { String::new() },
            orm: if panache { "panache" } else { "jpa" }.into(),
            supers: supers.clone(),
            kind: kind.into(),
        });
        if supers.iter().any(|s| s == "PanacheEntity") {
            rows.entity_fields.push(EntityField {
                file: f.path.clone(),
                line: line(n),
                entity: name.clone(),
                field: "id".into(),
                column: "id".into(),
                ty: "Long".into(),
                nullable: false,
                transient: false,
                pk: true,
                rel: String::new(),
                flags: "PanacheEntity".into(),
            });
        }
        if let Some(body) = n.child_by_field_name("body") {
            for it in named_children(body) {
                if it.kind() == "field_declaration" {
                    java_field(f, &name, it, rows);
                }
            }
        }
    }
    if let Some(body) = n.child_by_field_name("body") {
        for it in named_children(body) {
            java_type(f, it, rows);
        }
    }
}

fn java_field(f: &SourceFile, entity: &str, fd: Node, rows: &mut Rows) {
    let src = &f.text;
    let (annos, is_static, jtransient) = mod_info(fd, src);
    if is_static {
        return;
    }
    let Some(tn) = fd.child_by_field_name("type") else { return };
    let ty = squash(text(tn, src));
    let target = tsimple(&ty);
    let find = |a: &str| annos.iter().find(|x| anno_name(x) == a);
    let transient = jtransient || find("Transient").is_some();
    for d in named_children(fd).into_iter().filter(|d| d.kind() == "variable_declarator") {
        let Some(field) = d.child_by_field_name("name").map(|x| text(x, src).to_string()) else { continue };
        let col_anno = find("Column");
        let join_anno = find("JoinColumn");
        let pk = find("Id").is_some() || find("EmbeddedId").is_some();
        let m2o = find("ManyToOne").or_else(|| find("OneToOne"));
        let inverse = find("OneToMany").is_some()
            || find("ManyToMany").is_some()
            || find("ElementCollection").is_some()
            || m2o.is_some_and(|a| a.contains("mappedBy"));
        let embedded = find("Embedded").is_some() || find("EmbeddedId").is_some();
        let mut flags = vec![];
        let mut rel = String::new();
        let column = if transient {
            String::new()
        } else if inverse {
            rel = target.clone();
            flags.push(if find("OneToMany").is_some() { "1:N".to_string() } else { "inverse".to_string() });
            String::new()
        } else if embedded && find("EmbeddedId").is_none() {
            rel = target.clone();
            flags.push("embedded".into());
            String::new()
        } else if m2o.is_some() {
            rel = target.clone();
            join_anno.and_then(|a| arg_str(a, "name")).unwrap_or_else(|| format!("{}_id", snake(&field)))
        } else {
            col_anno.and_then(|a| arg_str(a, "name")).unwrap_or_else(|| snake(&field)).trim_matches('"').to_lowercase()
        };
        let mut nullable = !(pk || is_primitive(&ty));
        if col_anno.and_then(|a| arg_bool(a, "nullable")) == Some(false) || join_anno.and_then(|a| arg_bool(a, "nullable")) == Some(false) {
            nullable = false;
        }
        if m2o.and_then(|a| arg_bool(a, "optional")) == Some(false) {
            nullable = false;
        }
        if find("NotNull").is_some() || find("NotBlank").is_some() || find("NotEmpty").is_some() {
            nullable = false;
            flags.push("validated".into());
        }
        if let Some(a) = col_anno {
            if arg_bool(a, "unique") == Some(true) {
                flags.push("unique".into());
            }
            if let Some(n) = arg_num(a, "length") {
                flags.push(format!("len {n}"));
            }
            if let Some(def) = arg_str(a, "columnDefinition") {
                flags.push(format!("def {}", clip(&def, 30)));
            }
        }
        if find("Lob").is_some() {
            flags.push("lob".into());
        }
        if find("Enumerated").is_some() {
            flags.push("enum".into());
        }
        if find("Version").is_some() {
            flags.push("version".into());
        }
        if find("GeneratedValue").is_some() {
            flags.push("generated".into());
        }
        let ln = line(fd);
        if !rel.is_empty() && !column.is_empty() {
            rows.fks.push(Fk {
                file: f.path.clone(),
                line: ln,
                from_table: format!("entity:{entity}"),
                from_col: column.clone(),
                to_table: format!("entity:{rel}"),
                to_col: String::new(),
                src: "entity".into(),
            });
        }
        rows.entity_fields.push(EntityField {
            file: f.path.clone(),
            line: ln,
            entity: entity.to_string(),
            field,
            column,
            ty: clip(&ty, 40),
            nullable,
            transient,
            pk,
            rel,
            flags: flags.join(", "),
        });
    }
}

// ───────────────────────────── SQL files / migrations ─────────────────────────────

static FLYWAY_V: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[VvUu](\d[\d_.]*)__").unwrap());

/// (version, tool) when `path` is a schema migration file.
fn migration_ctx(path: &str, ext: &str) -> Option<(String, String)> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if ext == "sql" {
        if let Some(c) = FLYWAY_V.captures(name) {
            return Some((c[1].replace('_', "."), "flyway".into()));
        }
        if name.starts_with("R__") {
            return Some(("R".into(), "flyway".into()));
        }
    }
    let lower = path.to_lowercase();
    let in_mig = lower.split('/').any(|d| {
        d.contains("migrat") || d == "db" || d == "flyway" || d == "liquibase" || d == "changelog" || d == "changelogs" || d.contains("schema") || d == "sql"
    });
    if !in_mig {
        return None;
    }
    let parent = path.rsplit('/').nth(1).unwrap_or("");
    let digits = |s: &str| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
    let pd = digits(parent);
    if ext == "sql" && name == "migration.sql" && pd.len() >= 8 {
        return Some((pd, "prisma".into()));
    }
    let nd = digits(name);
    if !nd.is_empty() {
        return Some((nd, "sql".into()));
    }
    Some((name.trim_end_matches(".sql").to_string(), "sql".into()))
}

fn sql_file(f: &SourceFile, rows: &mut Rows) {
    if f.text.starts_with("--liquibase formatted sql") {
        return liquibase_sql(f, rows);
    }
    let Some((version, tool)) = migration_ctx(&f.path, "sql") else { return };
    let (m, fk) = parse_ddl(&Ctx { file: &f.path, version: &version, tool: &tool }, &f.text);
    rows.migrations.extend(m);
    rows.fks.extend(fk);
}

fn liquibase_sql(f: &SourceFile, rows: &mut Rows) {
    let lt = Lines::new(&f.text);
    let mut sets: Vec<(u32, String)> = vec![];
    for (i, l) in f.text.lines().enumerate() {
        if let Some(rest) = l.trim().strip_prefix("--changeset") {
            let id = rest.trim().split_whitespace().next().unwrap_or("").to_string();
            sets.push((i as u32 + 1, id.rsplit(':').next().unwrap_or("").to_string()));
        }
    }
    let _ = lt;
    let (mut m, fk) = parse_ddl(&Ctx { file: &f.path, version: "", tool: "liquibase" }, &f.text);
    for x in &mut m {
        x.version = sets.iter().rev().find(|s| s.0 <= x.line).map(|s| s.1.clone()).unwrap_or_default();
    }
    rows.migrations.extend(m);
    rows.fks.extend(fk);
}

fn liquibase_xml(f: &SourceFile, rows: &mut Rows) {
    if !f.text.contains("databaseChangeLog") {
        return;
    }
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)<(/?)(\w+)((?:\s+[\w:.-]+\s*=\s*"[^"]*")*)\s*(/?)>"#).unwrap());
    static ATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([\w:.-]+)\s*=\s*"([^"]*)""#).unwrap());
    let lt = Lines::new(&f.text);
    let mut cs = String::new();
    let mut ctx: Option<(String, &'static str)> = None;
    let mut index_ctx: Option<(String, String, String)> = None; // table, name, cols so far
    let mk = |rows: &mut Rows, off: usize, cs: &str, t: &str, op: &str, obj: &str, col: &str, d: String| {
        rows.migrations.push(Migration {
            file: f.path.clone(),
            line: lt.at(off),
            version: cs.to_string(),
            tool: "liquibase".into(),
            table: t.to_lowercase(),
            op: op.into(),
            obj: obj.into(),
            column: col.to_lowercase(),
            detail: d,
        });
    };
    for c in TAG.captures_iter(&f.text) {
        let close = &c[1] == "/";
        let tag = &c[2];
        let off = c.get(0).unwrap().start();
        let at: std::collections::HashMap<String, String> = ATTR.captures_iter(&c[3]).map(|a| (a[1].to_string(), a[2].to_string())).collect();
        let g = |k: &str| at.get(k).cloned().unwrap_or_default();
        if close {
            match tag {
                "createTable" | "addColumn" => ctx = None,
                "createIndex" => {
                    if let Some((t, n, cols)) = index_ctx.take() {
                        mk(rows, off, &cs, &t, "create", "index", &cols, format!("index {n}({cols})"));
                    }
                }
                _ => {}
            }
            continue;
        }
        match tag {
            "changeSet" => cs = g("id"),
            "createTable" => {
                mk(rows, off, &cs, &g("tableName"), "create", "table", "", "create table".into());
                ctx = Some((g("tableName"), "create"));
            }
            "addColumn" => ctx = Some((g("tableName"), "add")),
            "column" => {
                if let Some((t, op)) = &ctx {
                    let mut d = g("type");
                    for k in ["defaultValue", "defaultValueNumeric", "defaultValueBoolean", "defaultValueComputed", "defaultValueDate"] {
                        let v = g(k);
                        if !v.is_empty() {
                            let raw = if k == "defaultValue" { format!("'{}'", v.replace('\'', "''")) } else { v };
                            d.push_str(&format!(" default {}", safe_default(&g("name"), &raw)));
                            break;
                        }
                    }
                    mk(rows, off, &cs, t, op, "column", &g("name"), d);
                } else if let Some((_, _, cols)) = &mut index_ctx {
                    if !cols.is_empty() {
                        cols.push(',');
                    }
                    cols.push_str(&g("name"));
                }
            }
            "constraints" => {
                if let Some((t, _)) = &ctx {
                    let col = rows.migrations.last().map(|m| m.column.clone()).unwrap_or_default();
                    // <constraints nullable="false"/> and primaryKey show on the column itself
                    if g("nullable") == "false" || g("primaryKey") == "true" {
                        if let Some(m) = rows.migrations.iter_mut().rev().find(|m| m.obj == "column" && m.column == col) {
                            if !m.detail.contains(" not null") && !m.detail.contains("default") {
                                m.detail.push_str(" not null");
                            } else if !m.detail.contains(" not null") {
                                m.detail = m.detail.replacen(" default", " not null default", 1);
                            }
                        }
                    }
                    if g("primaryKey") == "true" {
                        mk(rows, off, &cs, t, "create", "constraint", &col, format!("primary key({col})"));
                    }
                    if g("unique") == "true" {
                        mk(rows, off, &cs, t, "create", "constraint", &col, format!("unique({col})"));
                    }
                    let rt = if g("referencedTableName").is_empty() { g("references").split('(').next().unwrap_or("").to_string() } else { g("referencedTableName") };
                    if !rt.is_empty() {
                        let rc = g("referencedColumnNames");
                        rows.fks.push(Fk {
                            file: f.path.clone(),
                            line: lt.at(off),
                            from_table: t.to_lowercase(),
                            from_col: col.clone(),
                            to_table: rt.to_lowercase(),
                            to_col: rc.to_lowercase(),
                            src: "migration".into(),
                        });
                    }
                }
            }
            "dropTable" => mk(rows, off, &cs, &g("tableName"), "drop", "table", "", "drop table".into()),
            "dropColumn" => mk(rows, off, &cs, &g("tableName"), "drop", "column", &g("columnName"), "drop column".into()),
            "renameColumn" => mk(rows, off, &cs, &g("tableName"), "alter", "column", &g("oldColumnName"), format!("rename to {}", g("newColumnName"))),
            "renameTable" => mk(rows, off, &cs, &g("oldTableName"), "alter", "table", "", format!("rename to {}", g("newTableName"))),
            "modifyDataType" => mk(rows, off, &cs, &g("tableName"), "alter", "column", &g("columnName"), format!("type {}", g("newDataType"))),
            "addNotNullConstraint" => mk(rows, off, &cs, &g("tableName"), "alter", "column", &g("columnName"), "set not null".into()),
            "addUniqueConstraint" => mk(rows, off, &cs, &g("tableName"), "add", "constraint", &g("columnNames"), format!("unique({})", g("columnNames"))),
            "addPrimaryKey" => mk(rows, off, &cs, &g("tableName"), "add", "constraint", &g("columnNames"), format!("primary key({})", g("columnNames"))),
            "addForeignKeyConstraint" => {
                mk(
                    rows,
                    off,
                    &cs,
                    &g("baseTableName"),
                    "add",
                    "constraint",
                    &g("baseColumnNames"),
                    format!("fk({}) -> {}({})", g("baseColumnNames"), g("referencedTableName"), g("referencedColumnNames")),
                );
                rows.fks.push(Fk {
                    file: f.path.clone(),
                    line: lt.at(off),
                    from_table: g("baseTableName").to_lowercase(),
                    from_col: g("baseColumnNames").to_lowercase(),
                    to_table: g("referencedTableName").to_lowercase(),
                    to_col: g("referencedColumnNames").to_lowercase(),
                    src: "migration".into(),
                });
            }
            "createIndex" => {
                index_ctx = Some((g("tableName"), g("indexName"), String::new()));
            }
            "insert" | "loadData" => mk(rows, off, &cs, &g("tableName"), "add", "data", "", "insert rows".into()),
            _ => {}
        }
    }
    // <sql> bodies
    static SQLB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<sql[^>]*>(.*?)</sql>").unwrap());
    for c in SQLB.captures_iter(&f.text) {
        let off = c.get(1).unwrap().start();
        let body = c[1].replace("<![CDATA[", "").replace("]]>", "");
        let (m, fk) = parse_ddl(&Ctx { file: &f.path, version: "", tool: "liquibase" }, &body);
        let base = lt.at(off);
        for mut x in m {
            x.line += base - 1;
            x.version = rows.migrations.iter().rev().find(|y| y.line <= base && !y.version.is_empty()).map(|y| y.version.clone()).unwrap_or_default();
            rows.migrations.push(x);
        }
        for mut x in fk {
            x.line += base - 1;
            rows.fks.push(x);
        }
    }
}

fn liquibase_yaml(f: &SourceFile, rows: &mut Rows) {
    if !f.text.contains("databaseChangeLog") {
        return;
    }
    let mut cs = String::new();
    let mut table = String::new();
    let mut op = "";
    let mut obj = "";
    let mig = |rows: &mut Rows, line: usize, cs: &str, t: &str, op: &str, obj: &str, col: &str, d: &str| {
        rows.migrations.push(Migration {
            file: f.path.clone(),
            line: line as u32,
            version: cs.to_string(),
            tool: "liquibase".into(),
            table: t.to_lowercase(),
            op: op.into(),
            obj: obj.into(),
            column: col.to_lowercase(),
            detail: d.to_string(),
        });
    };
    let mut pending_col: Option<(usize, String)> = None;
    for (i, l) in f.text.lines().enumerate() {
        let t = l.trim().trim_start_matches("- ").trim();
        let kv = |k: &str| t.strip_prefix(k).map(|v| v.trim().trim_matches(['"', '\'']).to_string());
        if let Some(v) = kv("id:") {
            if !t.starts_with("id: ") || cs.is_empty() || true {
                cs = v;
            }
        } else if t.starts_with("createTable:") {
            op = "create";
            obj = "table";
            table.clear();
        } else if t.starts_with("addColumn:") {
            op = "add";
            obj = "column";
            table.clear();
        } else if let Some(v) = kv("tableName:") {
            table = v;
            if obj == "table" && op == "create" {
                mig(rows, i + 1, &cs, &table, "create", "table", "", "create table");
            }
        } else if let Some(v) = kv("name:") {
            if !table.is_empty() && (obj == "column" || obj == "table") && op != "" {
                pending_col = Some((i + 1, v));
            }
        } else if let Some(v) = kv("type:") {
            if let Some((ln, name)) = pending_col.take() {
                mig(rows, ln, &cs, &table, op, "column", &name, &v);
            }
        } else if t.starts_with("dropTable:") {
            op = "";
        }
    }
}

// ───────────────────────────── Laravel ─────────────────────────────

/// `database/migrations/*.php`: `Schema::create('t', function (Blueprint $table) { $table->string('c'); ... })`,
/// `Schema::table` (add / `dropColumn` / `renameColumn`), `Schema::drop[IfExists]`. `down()` is not replayed.
fn laravel(f: &SourceFile, rows: &mut Rows) {
    if !f.path.contains("migrations/") {
        return;
    }
    let name = f.name();
    let version: String = name.chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    static SCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"Schema::(create|table|drop|dropIfExists)\(\s*['"](\w+)['"]"#).unwrap());
    static COL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\$\w+->(\w+)\(\s*(?:['"](\w+)['"])?(?:\s*,\s*['"](\w+)['"])?"#).unwrap());
    let mk = |rows: &mut Rows, line: usize, t: &str, op: &str, obj: &str, col: &str, d: String| {
        rows.migrations.push(Migration {
            file: f.path.clone(),
            line: line as u32,
            version: version.clone(),
            tool: "laravel".into(),
            table: t.to_lowercase(),
            op: op.into(),
            obj: obj.into(),
            column: col.to_lowercase(),
            detail: d,
        });
    };
    let mut table = String::new();
    let mut creating = false;
    let mut in_down = false;
    for (i, l) in f.text.lines().enumerate() {
        let t = l.trim();
        let ln = i + 1;
        if t.contains("function down(") {
            in_down = true;
        } else if t.contains("function up(") {
            in_down = false;
        }
        if in_down {
            continue;
        }
        if let Some(c) = SCH.captures(t) {
            table = c[2].to_string();
            match &c[1] {
                "create" => {
                    creating = true;
                    mk(rows, ln, &table, "create", "table", "", "create table".into());
                }
                "table" => creating = false,
                _ => {
                    mk(rows, ln, &table, "drop", "table", "", "drop table".into());
                    table.clear();
                }
            }
            continue;
        }
        if table.is_empty() {
            continue;
        }
        for c in COL.captures_iter(t) {
            let ty = &c[1];
            let col = c.get(2).map(|m| m.as_str()).unwrap_or("");
            let op = if creating { "create" } else { "add" };
            match ty {
                "id" | "increments" | "bigIncrements" => mk(rows, ln, &table, op, "column", if col.is_empty() { "id" } else { col }, ty.into()),
                "timestamps" | "timestampsTz" | "nullableTimestamps" => {
                    mk(rows, ln, &table, op, "column", "created_at", "timestamp".into());
                    mk(rows, ln, &table, op, "column", "updated_at", "timestamp".into());
                }
                "softDeletes" => mk(rows, ln, &table, op, "column", "deleted_at", "timestamp".into()),
                "rememberToken" => mk(rows, ln, &table, op, "column", "remember_token", "string".into()),
                "dropColumn" if !col.is_empty() => mk(rows, ln, &table, "drop", "column", col, "drop column".into()),
                "renameColumn" if !col.is_empty() => {
                    if let Some(to) = c.get(3) {
                        mk(rows, ln, &table, "alter", "column", col, format!("rename to {}", to.as_str()));
                    }
                }
                "index" | "unique" | "primary" | "foreign" | "dropIndex" | "dropUnique" | "dropForeign" | "on" | "references" | "nullable" | "default" | "change" | "after" | "comment" | "constrained" | "cascadeOnDelete" | "onDelete" | "unsigned" => {}
                _ if !col.is_empty() => mk(rows, ln, &table, op, "column", col, ty.into()),
                _ => {}
            }
        }
        if t.starts_with("});") {
            table.clear();
        }
    }
}

// ───────────────────────────── Rails ─────────────────────────────

fn rails(f: &SourceFile, rows: &mut Rows) {
    // db/schema.rb (the schema dump) is read like one migration that creates every table as it stands; the engine
    // orders it after the migrations and `table` prefers it over replaying them
    let dump = f.path == "db/schema.rb" || f.path.ends_with("/db/schema.rb");
    if !f.path.contains("db/migrate/") && !dump {
        active_record(f, rows);
        return;
    }
    let name = f.name();
    let version: String = if dump { "schema".into() } else { name.chars().take_while(|c| c.is_ascii_digit()).collect() };
    let tool = if dump { "rails-schema" } else { "rails" };
    let mut table = String::new();
    let mk = |rows: &mut Rows, line: usize, t: &str, op: &str, obj: &str, col: &str, d: String| {
        rows.migrations.push(Migration {
            file: f.path.clone(),
            line: line as u32,
            version: version.clone(),
            tool: tool.into(),
            table: t.to_lowercase(),
            op: op.into(),
            obj: obj.into(),
            column: col.to_lowercase(),
            detail: d,
        });
    };
    static SYM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[:"'](\w+)["']?"#).unwrap());
    let sym = |s: &str| -> String { SYM.captures(s.trim()).map(|c| c[1].to_string()).unwrap_or_default() };
    // the block variable of `create_table :x do |t|` (any name); `def down` / `def self.down` undoes the change and
    // is not replayed (its add_column re-adds what `up` removed)
    static BVAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bdo\s*\|\s*(\w+)").unwrap());
    let mut bvar = "t".to_string();
    let mut skip_to: Option<usize> = None;
    for (i, l) in f.text.lines().enumerate() {
        let t = l.trim();
        let ln = i + 1;
        let indent = l.len() - l.trim_start().len();
        if let Some(d) = skip_to {
            if t == "end" && indent <= d {
                skip_to = None;
            }
            continue;
        }
        if t == "def down" || t == "def self.down" || t.starts_with("def down ") || t.starts_with("def self.down ") {
            skip_to = Some(indent);
            continue;
        }
        let col_line = t.strip_prefix(bvar.as_str()).and_then(|r| r.strip_prefix('.'));
        if let Some(r) = t.strip_prefix("create_table ") {
            table = sym(r);
            bvar = BVAR.captures(r).map(|c| c[1].to_string()).unwrap_or_else(|| "t".into());
            mk(rows, ln, &table, "create", "table", "", "create table".into());
        } else if t == "end" || t.starts_with("end ") {
            // table block may end; columns outside a create_table block use explicit table names
        } else if let Some(r) = col_line {
            if table.is_empty() {
                continue;
            }
            let (ty, rest) = r.split_once(|c: char| c == ' ' || c == '(').unwrap_or((r, ""));
            if ty == "timestamps" {
                mk(rows, ln, &table, "create", "column", "created_at", "datetime".into());
                mk(rows, ln, &table, "create", "column", "updated_at", "datetime".into());
            } else if ty == "references" || ty == "belongs_to" {
                let c = format!("{}_id", sym(rest));
                mk(rows, ln, &table, "create", "column", &c, "references".into());
                if rest.contains("foreign_key") {
                    rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: table.clone(), from_col: c, to_table: format!("{}s", sym(rest)), to_col: "id".into(), src: "migration".into() });
                }
            } else if ty == "index" {
                mk(rows, ln, &table, "create", "index", &sym(rest), clip(rest, 40));
            } else {
                let c = sym(rest);
                if !c.is_empty() {
                    let nn = if rest.contains("null: false") { " not null" } else { "" };
                    mk(rows, ln, &table, "create", "column", &c, format!("{ty}{nn}"));
                }
            }
        } else if let Some(r) = t.strip_prefix("add_column ") {
            let a = split_args(r);
            if a.len() >= 3 {
                mk(rows, ln, &sym(&a[0]), "add", "column", &sym(&a[1]), sym(&a[2]));
            }
        } else if let Some(r) = t.strip_prefix("remove_column ") {
            let a = split_args(r);
            if a.len() >= 2 {
                mk(rows, ln, &sym(&a[0]), "drop", "column", &sym(&a[1]), "drop column".into());
            }
        } else if let Some(r) = t.strip_prefix("change_column ") {
            let a = split_args(r);
            if a.len() >= 3 {
                mk(rows, ln, &sym(&a[0]), "alter", "column", &sym(&a[1]), format!("type {}", sym(&a[2])));
            }
        } else if let Some(r) = t.strip_prefix("rename_column ") {
            let a = split_args(r);
            if a.len() >= 3 {
                mk(rows, ln, &sym(&a[0]), "alter", "column", &sym(&a[1]), format!("rename to {}", sym(&a[2])));
            }
        } else if let Some(r) = t.strip_prefix("drop_table ") {
            mk(rows, ln, &sym(r), "drop", "table", "", "drop table".into());
        } else if let Some(r) = t.strip_prefix("add_index ") {
            let a = split_args(r);
            if a.len() >= 2 {
                let cols = str_lits(&a[1]).join(",");
                let cols = if cols.is_empty() { sym(&a[1]) } else { cols };
                let cols = if a[1].trim().starts_with('[') { a[1].trim_matches(['[', ']']).replace([':', ' '], "") } else { cols };
                mk(rows, ln, &sym(&a[0]), "create", "index", &cols, format!("index({cols})"));
            }
        } else if let Some(r) = t.strip_prefix("add_reference ") {
            let a = split_args(r);
            if a.len() >= 2 {
                let c = format!("{}_id", sym(&a[1]));
                mk(rows, ln, &sym(&a[0]), "add", "column", &c, "references".into());
                if r.contains("foreign_key") {
                    rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: sym(&a[0]), from_col: c, to_table: format!("{}s", sym(&a[1])), to_col: "id".into(), src: "migration".into() });
                }
            }
        } else if let Some(r) = t.strip_prefix("add_foreign_key ") {
            let a = split_args(r);
            if a.len() >= 2 {
                rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: sym(&a[0]), from_col: format!("{}_id", sym(&a[1]).trim_end_matches('s')), to_table: sym(&a[1]), to_col: "id".into(), src: "migration".into() });
                mk(rows, ln, &sym(&a[0]), "add", "constraint", "", format!("fk -> {}", sym(&a[1])));
            }
        }
    }
}

/// English plural of a snake_case name, the common ActiveRecord / Eloquent inflections (`category` -> `categories`,
/// `address` -> `addresses`, `person` -> `people`).
pub fn plural(s: &str) -> String {
    let (head, last) = s.rsplit_once('_').map(|(h, l)| (format!("{h}_"), l)).unwrap_or((String::new(), s));
    let irregular = [("person", "people"), ("man", "men"), ("woman", "women"), ("child", "children"), ("mouse", "mice"), ("datum", "data")];
    if let Some((_, p)) = irregular.iter().find(|(a, _)| *a == last) {
        return format!("{head}{p}");
    }
    if ["data", "metadata", "information", "equipment", "news", "series", "species"].contains(&last) {
        return s.to_string();
    }
    let b = last.as_bytes();
    let p = if last.ends_with("sis") {
        format!("{}ses", &last[..last.len() - 3])
    } else if last.ends_with('y') && b.len() > 1 && !b"aeiou".contains(&b[b.len() - 2]) {
        format!("{}ies", &last[..last.len() - 1])
    } else if ["s", "x", "z", "ch", "sh"].iter().any(|e| last.ends_with(e)) {
        format!("{last}es")
    } else {
        format!("{last}s")
    };
    format!("{head}{p}")
}

/// ActiveRecord: model classes (`class Rubygem < ApplicationRecord`, `self.table_name = "x"`) and the class-level
/// query / write calls on them (`Rubygem.where`, `Version.find_by`, `User.create!`, `scope ... { where(...) }` inside the
/// model). Instance calls (`@user.save`) are left out: the receiver's model is unknown here.
fn active_record(f: &SourceFile, rows: &mut Rows) {
    static CLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^([ \t]*)class\s+(?:\w+::)*([A-Z]\w*)\s*<\s*((?:::)?[A-Z][\w:]*)").unwrap());
    static TNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"self\.table_name\s*=\s*["':](\w+)"#).unwrap());
    static CALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:^|[^\w:.@$])((?:[A-Z]\w*::)*[A-Z]\w*)\.(where|find_by!?|find|find_each|find_in_batches|find_sole_by|all|first|last|take|exists\?|count|pluck|order|joins|left_joins|includes|preload|eager_load|select|limit|sum|maximum|minimum|ids|group|distinct|lock|create!?|insert!?|insert_all!?|upsert|upsert_all|update_all|delete_all|destroy_all|delete_by|destroy_by|find_or_create_by!?|create_or_find_by!?|find_or_initialize_by|update!?|increment_counter|decrement_counter|update_counters|new)\b").unwrap()
    });
    static BARE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[\s({;|])(where|find_by!?|joins|includes|order|pluck|exists\?|update_all|delete_all|insert_all!?|upsert_all)\(").unwrap());
    static CHAIN_W: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(update_all|delete_all|destroy_all|insert_all!?|upsert_all|touch_all|update_counters|find_or_create_by!?|create!?)\b").unwrap());
    let t = &f.text;
    let lt = Lines::new(t);
    let lines: Vec<&str> = t.lines().collect();
    // model classes: (name, first line, last line); the superclass is an ActiveRecord base or an abstract model
    let mut models: Vec<(String, usize, usize)> = vec![];
    for c in CLS.captures_iter(t) {
        let sup = c[3].trim_start_matches("::");
        let ar = sup == "ApplicationRecord" || sup == "ActiveRecord::Base" || sup.ends_with("Record") || sup.ends_with("::Base") && sup.starts_with("ActiveRecord");
        if !ar {
            continue;
        }
        let name = c[2].to_string();
        let indent = c[1].len();
        let start = lt.at(c.get(0).unwrap().start()) as usize;
        let mut end = lines.len();
        for (k, l) in lines.iter().enumerate().skip(start) {
            let tl = l.trim_start();
            if (tl == "end" || tl.starts_with("end ") || tl.starts_with("end#")) && l.len() - tl.len() == indent {
                end = k + 1;
                break;
            }
        }
        let body = lines[start.saturating_sub(1)..end.min(lines.len())].join("\n");
        if body.contains("self.abstract_class = true") {
            continue;
        }
        let table = TNAME.captures(&body).map(|m| m[1].to_lowercase()).unwrap_or_else(|| plural(&snake(&name)));
        rows.entities.push(EntityDef { file: f.path.clone(), line: start as u32, end_line: end as u32, name: name.clone(), table, orm: "activerecord".into(), supers: vec![sup.to_string()], kind: "entity".into() });
        models.push((name, start, end));
    }
    let writes = |m: &str| {
        matches!(m.trim_end_matches('!'), "create" | "insert" | "insert_all" | "upsert" | "upsert_all" | "update_all" | "delete_all" | "destroy_all" | "delete_by" | "destroy_by" | "find_or_create_by" | "create_or_find_by" | "update" | "increment_counter" | "decrement_counter" | "update_counters")
    };
    // Minitest / RSpec files and fixtures set data up; they are not the app's readers and writers
    let p = f.path.as_str();
    if p.starts_with("test/") || p.contains("/test/") || p.starts_with("spec/") || p.contains("/spec/") || p.ends_with("_test.rb") {
        return;
    }
    let mut push = |line: u32, entity: &str, op: &str| {
        rows.data_raw.push(DataRaw { file: f.path.clone(), line, kind: "entity".into(), target: entity.to_string(), op: op.into(), via: "orm".into(), extra: "activerecord".into() });
    };
    for (k, l) in lines.iter().enumerate() {
        let code = l.split(" #").next().unwrap_or(l);
        if code.trim_start().starts_with('#') {
            continue;
        }
        for c in CALL.captures_iter(code) {
            if &c[2] == "new" {
                continue; // an object in memory, not a query
            }
            let ent = c[1].rsplit("::").next().unwrap_or(&c[1]);
            // `Version.where(..).update_all(..)`: the chain ends in a write
            let chained = CHAIN_W.is_match(&code[c.get(0).unwrap().end()..]);
            push(k as u32 + 1, ent, if writes(&c[2]) || chained { "w" } else { "r" });
        }
        // a bare query inside a model's own class body (`scope :live, -> { where(...) }`, `def self.x; where(..)`)
        if let Some((name, _, _)) = models.iter().find(|(_, a, b)| *a < k + 1 && k < *b) {
            for c in BARE.captures_iter(code) {
                push(k as u32 + 1, name, if writes(&c[1]) { "w" } else { "r" });
            }
        }
    }
}

/// Laravel Eloquent: model classes (`class Song extends Model`, `protected $table = 'x'`) and static calls on them
/// (`Song::query()`, `Song::where(..)`, `User::create(..)`; a chain that ends in `->update(` / `->delete(` within the
/// statement is a write), and `DB::table('x')` query-builder access.
fn eloquent(f: &SourceFile, rows: &mut Rows) {
    static CLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*(?:(?:abstract|final)\s+)?class\s+([A-Z]\w*)\s+extends\s+\\?(?:[\w\\]*\\)?(Model|Authenticatable|Pivot|MorphPivot)\b").unwrap());
    static TNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"protected\s+(?:\?string\s+|string\s+)?\$table\s*=\s*['"](\w+)['"]"#).unwrap());
    static CALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:^|[^\w\\$>:])\\?(?:[A-Z]\w*\\)*([A-Z]\w*)::(query|where\w*|find|findOrFail|findMany|first\w*|all|count|exists|pluck|latest|oldest|orderBy\w*|select|with|has|whereHas|paginate|chunk|cursor|lazy|create|forceCreate|firstOrCreate|updateOrCreate|insert\w*|upsert|destroy|truncate|increment|decrement)\(").unwrap()
    });
    static DBT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\bDB::table\(\s*['"](\w+)['"]\s*\)"#).unwrap());
    static CHAIN_W: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"->(update|delete|forceDelete|insert\w*|upsert|increment|decrement|updateOrInsert|truncate)\(").unwrap());
    let t = &f.text;
    let lt = Lines::new(t);
    if let Some(c) = CLS.captures(t) {
        let name = c[1].to_string();
        let table = TNAME.captures(t).map(|m| m[1].to_lowercase()).unwrap_or_else(|| plural(&snake(&name)));
        let start = lt.at(c.get(0).unwrap().start());
        rows.entities.push(EntityDef { file: f.path.clone(), line: start, end_line: lt.at(t.len().saturating_sub(1)), name, table, orm: "eloquent".into(), supers: vec![c[2].to_string()], kind: "entity".into() });
    }
    if !(t.contains("::") && (t.contains("::query(") || CALL.is_match(t) || t.contains("DB::table("))) {
        return;
    }
    // the statement after a match: up to its `;` (a fluent chain spans lines)
    let stmt_w = |from: usize| -> bool {
        let end = t[from..].find([';', '{']).map(|e| from + e).unwrap_or(t.len());
        CHAIN_W.is_match(&t[from..end])
    };
    for c in CALL.captures_iter(t) {
        let m = c.get(0).unwrap();
        let w = matches!(&c[2], "create" | "forceCreate" | "firstOrCreate" | "updateOrCreate" | "upsert" | "destroy" | "truncate" | "increment" | "decrement") || c[2].starts_with("insert") || stmt_w(m.end());
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(m.start() + 1), kind: "entity".into(), target: c[1].to_string(), op: if w { "w" } else { "r" }.into(), via: "orm".into(), extra: "eloquent".into() });
    }
    for c in DBT.captures_iter(t) {
        let m = c.get(0).unwrap();
        let w = stmt_w(m.end());
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(m.start()), kind: "table".into(), target: c[1].to_lowercase(), op: if w { "w" } else { "r" }.into(), via: "native".into(), extra: String::new() });
    }
}

/// EF Core: entities from `DbSet<Order> Orders` (table = the property name), `builder.ToTable("x")` in an
/// `IEntityTypeConfiguration<T>` and `[Table("x")]`; schema from `migrationBuilder` migrations (CreateTable /
/// AddColumn / DropColumn / RenameColumn / DropTable, `Down` skipped, Designer / snapshot files skipped); access through
/// a DbSet property (`_db.Orders.Where(..)`, `.Set<Order>()`) or a generic repository field / parameter
/// (`IRepository<Basket> _basketRepository` -> `_basketRepository.AddAsync(..)`).
fn efcore(f: &SourceFile, rows: &mut Rows) {
    static DBSET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bDbSet<\s*([A-Z]\w*)\s*>\??\s+([A-Z]\w*)\s*(?:\{|=>)").unwrap());
    static CFG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"IEntityTypeConfiguration<\s*([A-Z]\w*)\s*>").unwrap());
    static TOTABLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\.ToTable\(\s*"(\w+)""#).unwrap());
    static TATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\[Table\(\s*"(\w+)"[^\]]*\]\s*(?:\[[^\]]*\]\s*)*(?:public\s+|internal\s+)?(?:sealed\s+|partial\s+|abstract\s+)*class\s+([A-Z]\w*)"#).unwrap());
    static REPOVAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:I?\w*Repository(?:Base)?)<\s*([A-Z]\w*)\s*>\s+(\w+)\s*[;,)=]").unwrap());
    static MEMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\s*\.\s*(?:Set<\s*([A-Z]\w*)\s*>\(\)|([A-Z]\w*))\s*\.\s*([A-Z]\w*)\b").unwrap());
    static W: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(Add|AddAsync|AddRange|AddRangeAsync|Remove|RemoveRange|Update|UpdateRange|Attach|ExecuteUpdate\w*|ExecuteDelete\w*|UpdateAsync|DeleteAsync|DeleteRangeAsync|UpdateRangeAsync)\b").unwrap());
    let t = &f.text;
    let lt = Lines::new(t);
    let p = f.path.as_str();
    if p.contains("/Migrations/") {
        if !p.ends_with(".Designer.cs") && !p.ends_with("ModelSnapshot.cs") && t.contains("migrationBuilder.") {
            ef_migration(f, rows);
        }
        return;
    }
    let ent = |rows: &mut Rows, off: usize, name: &str, table: &str, orm: &str| {
        rows.entities.push(EntityDef { file: f.path.clone(), line: lt.at(off), end_line: lt.at(off), name: name.to_string(), table: table.to_lowercase(), orm: orm.into(), supers: vec![], kind: "entity".into() });
    };
    for c in DBSET.captures_iter(t) {
        let m = c.get(0).unwrap();
        ent(rows, m.start(), &c[1], &c[2], "efcore");
        // the property is how code reaches the set: `_db.Orders` resolves like a repository of Order
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(m.start()), kind: "repo".into(), target: c[2].to_string(), op: String::new(), via: "repo".into(), extra: c[1].to_string() });
    }
    if let (Some(c), Some(tt)) = (CFG.captures(t), TOTABLE.captures(t)) {
        ent(rows, tt.get(0).unwrap().start(), &c[1], &tt[1], "efcore-table");
    }
    for c in TATTR.captures_iter(t) {
        ent(rows, c.get(0).unwrap().start(), &c[2], &c[1], "efcore-table");
    }
    // generic repositories declared in this file: variable -> entity
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for c in REPOVAR.captures_iter(t) {
        vars.insert(c[2].to_string(), c[1].to_string());
    }
    for c in MEMBER.captures_iter(t) {
        let m = c.get(0).unwrap();
        let (recv, set_ty, prop, method) = (&c[1], c.get(2).map(|x| x.as_str()), c.get(3).map(|x| x.as_str()), &c[4]);
        let target = if let Some(ty) = set_ty {
            ty.to_string()
        } else if let Some(e) = vars.get(recv).filter(|_| prop.is_some()) {
            // `_repo.ListAsync(spec)`: the "prop" slot holds the method name here
            let meth = prop.unwrap();
            let w = W.is_match(&format!(".{meth}")) || meth.starts_with("Save");
            rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(m.start()), kind: "entity".into(), target: e.clone(), op: if w { "w" } else { "r" }.into(), via: "orm".into(), extra: "efcore".into() });
            continue;
        } else if (recv.to_lowercase().contains("context") && !recv.to_lowercase().ends_with("httpcontext")) || recv.trim_start_matches('_') == "db" || recv.trim_start_matches('_') == "dbContext" {
            prop.unwrap_or_default().to_string()
        } else {
            continue;
        };
        // the rest of the statement (a chain may span lines; `if (..AnyAsync())` ends at its block)
        let end = t[m.start()..].find([';', '{']).map(|e| m.start() + e).unwrap_or(t.len());
        let w = W.is_match(&format!(".{method}")) || W.is_match(&t[m.start()..end]);
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(m.start()), kind: "entity".into(), target, op: if w { "w" } else { "r" }.into(), via: "orm".into(), extra: "efcore".into() });
    }
    // `_repo.Method(` lines the MEMBER pattern above cannot see (`_repo.ListAsync(spec)` has no second `.`)
    static RCALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\.([A-Z]\w*)\s*\(").unwrap());
    if !vars.is_empty() {
        for c in RCALL.captures_iter(t) {
            let Some(e) = vars.get(&c[1]) else { continue };
            let m = c.get(0).unwrap();
            let line = lt.at(m.start());
            if rows.data_raw.iter().rev().take(4).any(|r| r.line == line && r.target == *e && r.file == f.path) {
                continue;
            }
            let meth = &c[2];
            let w = W.is_match(&format!(".{meth}")) || meth.starts_with("Save");
            rows.data_raw.push(DataRaw { file: f.path.clone(), line, kind: "entity".into(), target: e.clone(), op: if w { "w" } else { "r" }.into(), via: "orm".into(), extra: "efcore".into() });
        }
    }
}

fn ef_migration(f: &SourceFile, rows: &mut Rows) {
    static OP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"migrationBuilder\s*\.\s*(\w+)\s*(?:<[^>(]*>)?\s*\(").unwrap());
    static COL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\w+)\s*=\s*table\.Column<([^>]+)>\(([^)]*)\)").unwrap());
    let t = &f.text;
    let lt = Lines::new(t);
    let name = f.name();
    let version: String = name.chars().take_while(|c| c.is_ascii_digit()).collect();
    // `Down` undoes `Up`: never replayed
    let down = t.find("void Down(").unwrap_or(t.len());
    let mk = |rows: &mut Rows, off: usize, tbl: &str, op: &str, obj: &str, col: &str, d: String| {
        rows.migrations.push(Migration { file: f.path.clone(), line: lt.at(off), version: version.clone(), tool: "efcore".into(), table: tbl.to_lowercase(), op: op.into(), obj: obj.into(), column: col.to_lowercase(), detail: d });
    };
    for c in OP.captures_iter(t) {
        let m = c.get(0).unwrap();
        if m.start() > down {
            break;
        }
        let Some((args, _)) = balanced(t, m.end() - 1) else { continue };
        let tbl = |k: &str| arg_str(args, k).unwrap_or_default();
        match &c[1] {
            "CreateTable" => {
                let table = tbl("name");
                if table.is_empty() {
                    continue;
                }
                mk(rows, m.start(), &table, "create", "table", "", "create table".into());
                let base = m.end();
                for cc in COL.captures_iter(args) {
                    let off = base + cc.get(0).unwrap().start();
                    let nn = if cc[3].contains("nullable: false") { " not null" } else { "" };
                    mk(rows, off, &table, "create", "column", &cc[1], format!("{}{nn}", arg_str(&cc[3], "type").unwrap_or_else(|| cc[2].to_string())));
                }
            }
            "DropTable" => mk(rows, m.start(), &tbl("name"), "drop", "table", "", "drop table".into()),
            "AddColumn" => mk(rows, m.start(), &tbl("table"), "add", "column", &tbl("name"), arg_str(args, "type").unwrap_or_default()),
            "DropColumn" => mk(rows, m.start(), &tbl("table"), "drop", "column", &tbl("name"), "drop column".into()),
            "RenameColumn" => mk(rows, m.start(), &tbl("table"), "alter", "column", &tbl("name"), format!("rename to {}", tbl("newName").to_lowercase())),
            "AlterColumn" => mk(rows, m.start(), &tbl("table"), "alter", "column", &tbl("name"), format!("type {}", arg_str(args, "type").unwrap_or_default())),
            "RenameTable" => mk(rows, m.start(), &tbl("name"), "alter", "table", "", format!("rename to {}", tbl("newName").to_lowercase())),
            _ => {}
        }
    }
}

/// Go: SQL in string literals (database/sql, sqlx, pgx: `db.QueryContext(ctx, "SELECT ... FROM t")`), and GORM
/// (files importing gorm): models (structs embedding `gorm.Model` or carrying `gorm:` tags; `TableName()` overrides the
/// snake_case plural) and calls whose model is known from the argument (`db.Create(&user)`, `db.Model(&User{})`,
/// `db.Find(&users)` with `var users []User` in the function).
fn go_file(f: &SourceFile, rows: &mut Rows) {
    sql_strings(f, Lang::Go, rows);
    let t = &f.text;
    if !(t.contains("gorm.io/gorm") || t.contains("jinzhu/gorm")) {
        return;
    }
    static STRUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^type\s+([A-Z]\w*)\s+struct\s*\{").unwrap());
    static TNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)func\s*\(\s*\w*\s*\*?([A-Z]\w*)\s*\)\s*TableName\(\)\s*string\s*\{\s*return\s+"(\w+)""#).unwrap());
    static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(Create|CreateInBatches|Save|Updates?|UpdateColumns?|Delete|Find|First|Last|Take|Count|Pluck|Scan|FirstOrCreate|FirstOrInit|Model)\(\s*(?:ctx\s*,\s*)?(&?)\s*(\[\])?\s*(?:\w+\.)?(\w+)\s*(\{)?").unwrap());
    static VAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\s*(?::=\s*&?|\s+)\[?\]?\*?(?:\w+\.)?([A-Z]\w*)\s*[{\n;)]").unwrap());
    static FUNC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^func\b").unwrap());
    let lt = Lines::new(t);
    let names: std::collections::HashMap<String, String> = TNAME.captures_iter(t).map(|c| (c[1].to_string(), c[2].to_string())).collect();
    for c in STRUCT.captures_iter(t) {
        let m = c.get(0).unwrap();
        let body_end = t[m.end()..].find("\n}").map(|e| m.end() + e).unwrap_or(t.len());
        let body = &t[m.end()..body_end];
        if !(body.contains("gorm.Model") || body.contains("gorm:\"")) {
            continue;
        }
        let name = c[1].to_string();
        let table = names.get(&name).cloned().unwrap_or_else(|| plural(&snake(&name)));
        rows.entities.push(EntityDef { file: f.path.clone(), line: lt.at(m.start()), end_line: lt.at(body_end), name, table, orm: "gorm".into(), supers: vec![], kind: "entity".into() });
    }
    // per function: variable -> model type, then the calls
    let starts: Vec<usize> = FUNC.find_iter(t).map(|m| m.start()).chain(std::iter::once(t.len())).collect();
    for win in starts.windows(2) {
        let (base, body) = (win[0], &t[win[0]..win[1]]);
        let vars: std::collections::HashMap<String, String> = VAR.captures_iter(body).map(|c| (c[1].to_string(), c[2].to_string())).collect();
        for c in CALL.captures_iter(body) {
            let m = c.get(0).unwrap();
            let arg = &c[4];
            let ty = if c.get(5).is_some() || arg.chars().next().is_some_and(|x| x.is_ascii_uppercase()) {
                arg.to_string()
            } else if let Some(ty) = vars.get(arg) {
                ty.clone()
            } else {
                continue;
            };
            let end = body[m.end()..].find('\n').map(|e| m.end() + e).unwrap_or(body.len());
            let meth = &c[1];
            let write = |x: &str| matches!(x, "Create" | "CreateInBatches" | "Save" | "Update" | "Updates" | "UpdateColumn" | "UpdateColumns" | "Delete" | "FirstOrCreate");
            let w = write(meth) || (meth == "Model" && CALL.captures_iter(&body[m.end()..end]).any(|x| write(&x[1])) || body[m.end()..end].contains(".Update"));
            rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(base + m.start()), kind: "entity".into(), target: ty, op: if w { "w" } else { "r" }.into(), via: "orm".into(), extra: "gorm".into() });
        }
    }
}

// ───────────────────────────── Python ─────────────────────────────

fn python(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let p = f.path.as_str();
    if (p.contains("/versions/") || p.contains("alembic")) && t.contains("down_revision") {
        alembic(f, rows);
    } else if p.contains("/migrations/") && t.contains("migrations.Migration") {
        django_migration(f, rows);
    } else {
        if t.contains("__tablename__") || t.contains("mapped_column(") || t.contains("Column(") || t.contains("models.") {
            python_models(f, rows);
        }
        if t.contains("table=True") {
            sqlmodel(f, rows);
        }
        python_tables(f, rows);
        python_access(f, rows);
    }
    sql_strings(f, Lang::Py, rows);
    state_literals(f, Lang::Py, rows);
}

static PY_CLASS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:").unwrap());
static PY_FIELD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+(\w+)\s*(?::\s*([^=]+?))?\s*=\s*(?:[\w.]*\.)?(Column|mapped_column|relationship|\w+Field|ForeignKey|OneToOneField|ManyToManyField|\w+Key)\s*\(").unwrap());

fn python_models(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let lines: Vec<&str> = t.lines().collect();
    let offs: Vec<usize> = {
        let mut o = vec![0];
        o.extend(t.match_indices('\n').map(|(i, _)| i + 1));
        o
    };
    struct Cls {
        name: String,
        line: usize,
        bases: String,
        start: usize,
        end: usize,
    }
    let mut classes: Vec<Cls> = vec![];
    for (i, l) in lines.iter().enumerate() {
        if let Some(c) = PY_CLASS.captures(l) {
            if let Some(last) = classes.last_mut() {
                last.end = i;
            }
            classes.push(Cls { name: c[1].to_string(), line: i + 1, bases: c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(), start: i, end: lines.len() });
        } else if !l.is_empty() && !l.starts_with(' ') && !l.starts_with('\t') && !l.starts_with('#') && !l.starts_with(')') {
            if let Some(last) = classes.last_mut() {
                if last.end == lines.len() {
                    last.end = i;
                }
            }
        }
    }
    let app = {
        let parts: Vec<&str> = f.path.split('/').collect();
        let n = parts.len();
        if n >= 3 && parts[n - 2] == "models" { parts[n - 3] } else if n >= 2 { parts[n - 2] } else { "" }.to_string()
    };
    for c in classes {
        let body = &lines[c.start + 1..c.end.min(lines.len())];
        let btxt = body.join("\n");
        if c.bases.contains("table=True") {
            continue; // SQLModel: sqlmodel() reads it
        }
        let django = c.bases.contains("models.Model") || (c.bases.split(',').any(|b| b.trim() == "Model") && t.contains("django"));
        // a real table name / column definition, not a mere use of `cls.__tablename__` in a mixin method
        static TBLNAME: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"(?m)^\s+__tablename__\s*(?::\s*[\w\[\]., ]+)?=\s*["']([\w.$-]+)["']"#).unwrap());
        let defined_tbl = TBLNAME.captures(&btxt).map(|m| m[1].to_string());
        let has_cols = body.iter().any(|l| PY_FIELD.is_match(l) && !l.contains("ForeignKey(") || l.contains("mapped_column(") || l.contains("Column("));
        let sqla = !django && (defined_tbl.is_some() || has_cols) && !c.bases.is_empty();
        if !django && !sqla {
            continue;
        }
        let supers: Vec<String> = c.bases.split(',').map(|b| b.trim().rsplit('.').next().unwrap_or("").split('[').next().unwrap_or("").to_string()).filter(|b| !b.is_empty()).collect();
        let abstract_ = btxt.contains("abstract = True") || btxt.contains("__abstract__ = True");
        let table = if django {
            arg_str(&btxt, "db_table").unwrap_or_else(|| format!("{}_{}", app, c.name.to_lowercase()))
        } else {
            // Flask-SQLAlchemy names the table after the class (CamelCase -> snake_case) when `__tablename__` is absent
            let flask_model = supers.iter().any(|s| s == "Model") && c.bases.split(',').any(|b| b.trim().ends_with("db.Model") || b.trim() == "Model");
            defined_tbl.clone().unwrap_or_else(|| if flask_model && has_cols && !abstract_ { snake(&c.name) } else { String::new() })
        };
        if table.is_empty() && !abstract_ && sqla && !supers.iter().any(|s| s != "Base") {
            // SQLAlchemy without a table name: a mixin / base
        }
        rows.entities.push(EntityDef {
            file: f.path.clone(),
            line: c.line as u32,
            end_line: c.end.max(c.start + 1) as u32,
            name: c.name.clone(),
            table: if abstract_ { String::new() } else { table.to_lowercase() },
            orm: if django { "django" } else { "sqlalchemy" }.into(),
            supers,
            kind: if abstract_ || table.is_empty() { "mapped-superclass" } else { "entity" }.into(),
        });
        let mut has_pk = false;
        let mut first = true;
        for (k, l) in body.iter().enumerate() {
            static BARE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+(\w+)\s*:\s*((?:\w+\.)?Mapped\[.+\])\s*(?:#.*)?$").unwrap());
            let ln = c.start + 2 + k;
            let (field, ann, kind, args) = if let Some(m) = PY_FIELD.captures(l) {
                let (field, ann, kind) = (m[1].to_string(), m.get(2).map(|x| x.as_str().trim().to_string()).unwrap_or_default(), m[3].to_string());
                // the call's argument text (may continue on following lines)
                let open = offs[ln - 1] + l.find(&format!("{kind}(")).unwrap_or(0) + kind.len();
                let args = balanced(t, open).map(|x| x.0.to_string()).unwrap_or_default();
                (field, ann, kind, args)
            } else if let Some(m) = BARE.captures(l).filter(|_| sqla) {
                // SQLAlchemy 2.0: a bare `x: Mapped[T]` is a column (`Mapped[Other]` without a call is a relationship)
                let ann = m[2].to_string();
                let inner = ann.split_once('[').map(|x| x.1.trim_end_matches(']')).unwrap_or("");
                let scalar = ["int", "str", "bool", "float", "datetime", "date", "time", "Decimal", "bytes", "UUID", "dict", "list", "Optional[", "None", "Any", "Enum"].iter().any(|s| inner.contains(s));
                if !scalar {
                    continue;
                }
                (m[1].to_string(), ann, "mapped_column".to_string(), String::new())
            } else {
                continue;
            };
            let a = split_args(&args);
            let pos: Vec<&String> = a.iter().filter(|x| !x.contains('=') || x.starts_with("sa.") || x.contains('(')).collect();
            let mut pk = arg_bool(&args, "primary_key") == Some(true);
            let mut nullable = if django { arg_bool(&args, "null") == Some(true) } else { arg_bool(&args, "nullable") != Some(false) };
            if django && kind == "AutoField" || kind == "BigAutoField" {
                pk = pk || true;
            }
            if sqla && pk {
                nullable = false;
            }
            if sqla && !ann.is_empty() && !ann.contains("None") && !ann.contains("Optional") && arg_bool(&args, "nullable").is_none() && kind == "mapped_column" {
                nullable = false;
            }
            has_pk |= pk;
            let mut flags = vec![];
            if arg_bool(&args, "unique") == Some(true) {
                flags.push("unique".to_string());
            }
            // an ORM default, redacted for credential-named columns like a SQL one
            if let Some(p) = ["server_default", "default"].iter().find_map(|k| key_pos(&args, k).map(|p| (k, p))) {
                let raw = split_args(&args[p.1..]).into_iter().next().unwrap_or_default();
                let raw = raw.trim();
                if !raw.is_empty() {
                    let colname = if django { arg_str(&args, "db_column").unwrap_or_else(|| field.clone()) } else { field.clone() };
                    flags.push(format!("default {}", crate::sqlparse::safe_default(&colname, raw)));
                }
            }
            if first {
                first = false;
            }
            let (mut column, mut rel, mut ty) = (String::new(), String::new(), String::new());
            let is_rel = matches!(kind.as_str(), "relationship" | "ManyToManyField" | "ForeignKey" | "OneToOneField");
            if kind == "relationship" || kind == "ManyToManyField" {
                rel = pos.first().map(|s| s.trim_matches(['"', '\'']).rsplit('.').next().unwrap_or("").to_string()).unwrap_or_default();
                // typed relationship without a positional target: `posts: so.WriteOnlyMapped['Post'] = so.relationship(back_populates=..)`
                if rel.is_empty() && kind == "relationship" {
                    rel = ann.rsplit('[').next().unwrap_or("").trim_matches([']', '"', '\'', ' ']).rsplit('.').next().unwrap_or("").to_string();
                }
                flags.push(if kind == "relationship" { "relationship".to_string() } else { "m2m".to_string() });
            } else if django && is_rel {
                rel = pos.first().map(|s| s.trim_matches(['"', '\'']).rsplit('.').next().unwrap_or("").to_string()).unwrap_or_default();
                column = arg_str(&args, "db_column").unwrap_or_else(|| format!("{field}_id"));
                ty = "fk".into();
            } else if django {
                column = arg_str(&args, "db_column").unwrap_or_else(|| field.clone());
                ty = kind.clone();
                if let Some(n) = arg_num(&args, "max_length") {
                    ty = format!("{kind}(max_length={n})");
                }
            } else {
                // SQLAlchemy Column('name', Type, ForeignKey('t.id'))
                let mut tys = pos.iter().filter(|s| !s.starts_with('"') && !s.starts_with('\'') && !s.starts_with("ForeignKey") && !s.starts_with("sa.ForeignKey"));
                ty = tys.next().map(|s| s.to_string()).unwrap_or_else(|| ann.clone());
                column = pos.first().filter(|s| s.starts_with('"') || s.starts_with('\'')).map(|s| s.trim_matches(['"', '\'']).to_string()).or_else(|| arg_str(&args, "name")).unwrap_or_else(|| field.clone());
                if let Some(fk) = args.find("ForeignKey(") {
                    if let Some((inner, _)) = balanced(&args, fk + "ForeignKey".len()).filter(|(i, _)| i.contains('"') || i.contains('\'')) {
                        let target = str_lits(inner).first().cloned().unwrap_or_default();
                        let (tt, tc) = target.rsplit_once('.').unwrap_or((target.as_str(), "id"));
                        rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: format!("entity:{}", c.name), from_col: column.to_lowercase(), to_table: tt.to_lowercase(), to_col: tc.to_lowercase(), src: "entity".into() });
                        rel = format!("table:{}", tt.to_lowercase());
                    }
                }
                // `sa.ForeignKey(User.id)`: the target is a model attribute, not a "table.col" string
                if rel.is_empty() && args.contains("ForeignKey(") {
                    static FKA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"ForeignKey\(\s*(\w+)\.(\w+)\s*[,)]").unwrap());
                    if let Some(m) = FKA.captures(&args) {
                        rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: format!("entity:{}", c.name), from_col: column.to_lowercase(), to_table: format!("entity:{}", &m[1]), to_col: m[2].to_lowercase(), src: "entity".into() });
                        rel = format!("entity:{}", &m[1]);
                    }
                }

            }
            if django && is_rel && !matches!(kind.as_str(), "ManyToManyField") && !rel.is_empty() {
                rows.fks.push(Fk { file: f.path.clone(), line: ln as u32, from_table: format!("entity:{}", c.name), from_col: column.to_lowercase(), to_table: format!("entity:{rel}"), to_col: String::new(), src: "entity".into() });
            }
            rows.entity_fields.push(EntityField {
                file: f.path.clone(),
                line: ln as u32,
                entity: c.name.clone(),
                field,
                column: column.to_lowercase(),
                ty: clip(&ty, 40),
                nullable,
                transient: false,
                pk,
                rel,
                flags: flags.join(", "),
            });
        }
        if django && !has_pk && !abstract_ {
            rows.entity_fields.push(EntityField {
                file: f.path.clone(),
                line: c.line as u32,
                entity: c.name.clone(),
                field: "id".into(),
                column: "id".into(),
                ty: "AutoField".into(),
                nullable: false,
                transient: false,
                pk: true,
                rel: String::new(),
                flags: "implicit".into(),
            });
        }
    }
}

/// `followers = sa.Table('followers', db.metadata, sa.Column('a', sa.Integer, sa.ForeignKey('user.id'), primary_key=True), ...)`:
/// a table without a model class (association tables).
fn python_tables(f: &SourceFile, rows: &mut Rows) {
    static TBL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^(\w+)\s*(?::[^=\n]+)?=\s*(?:\w+\.)?Table\(\s*['"](\w+)['"]"#).unwrap());
    let t = &f.text;
    if !t.contains("Table(") {
        return;
    }
    let lt = Lines::new(t);
    for m in TBL.captures_iter(t) {
        let whole = m.get(0).unwrap();
        let open = whole.start() + whole.as_str().find("Table(").unwrap() + 5;
        let Some((args, end)) = balanced(t, open) else { continue };
        let (name, table) = (m[1].to_string(), m[2].to_lowercase());
        let line = lt.at(whole.start());
        rows.entities.push(EntityDef { file: f.path.clone(), line, end_line: lt.at(end), name: name.clone(), table, orm: "sqlalchemy".into(), supers: vec![], kind: "entity".into() });
        for a in split_args(args) {
            let Some(p) = a.find("Column(") else { continue };
            let Some((inner, _)) = balanced(&a, p + 6) else { continue };
            let ca = split_args(inner);
            let col = ca.first().map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
            if col.is_empty() || col.contains('(') {
                continue;
            }
            let ty = ca.get(1).cloned().unwrap_or_default();
            let pk = arg_bool(inner, "primary_key") == Some(true);
            let mut rel = String::new();
            if let Some(fk) = inner.find("ForeignKey(") {
                if let Some((fi, _)) = balanced(inner, fk + "ForeignKey".len()) {
                    let target = str_lits(fi).first().cloned().unwrap_or_default();
                    if let Some((tt, tc)) = target.rsplit_once('.') {
                        rows.fks.push(Fk { file: f.path.clone(), line, from_table: format!("entity:{name}"), from_col: col.to_lowercase(), to_table: tt.to_lowercase(), to_col: tc.to_lowercase(), src: "entity".into() });
                        rel = format!("table:{}", tt.to_lowercase());
                    }
                }
            }
            rows.entity_fields.push(EntityField { file: f.path.clone(), line, entity: name.clone(), field: col.clone(), column: col.to_lowercase(), ty: clip(&ty, 40), nullable: !pk && arg_bool(inner, "nullable") != Some(false), transient: false, pk, rel, flags: String::new() });
        }
    }
}

/// SQLModel: `class Item(ItemBase, table=True)` is a table (`__tablename__`, else the class name in lower case);
/// its columns are its annotated fields and those of the (non-table) base classes it inherits in this file, which are
/// emitted as mapped superclasses. `Relationship(...)` fields are relations, not columns.
fn sqlmodel(f: &SourceFile, rows: &mut Rows) {
    static FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s+(\w+)\s*:\s*([^=#]+?)\s*(?:=\s*(.*))?$").unwrap());
    static TBLNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s+__tablename__\s*(?::[^=]+)?=\s*["'](\w+)["']"#).unwrap());
    let lines: Vec<&str> = f.text.lines().collect();
    // (name, bases, first line index, end index)
    let mut classes: Vec<(String, String, usize, usize)> = vec![];
    for (i, l) in lines.iter().enumerate() {
        if let Some(c) = PY_CLASS.captures(l) {
            classes.push((c[1].to_string(), c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(), i, lines.len()));
        } else if !l.trim().is_empty() && !l.starts_with([' ', '\t', '#', ')']) {
            if let Some(last) = classes.last_mut().filter(|x| x.3 == lines.len()) {
                last.3 = i;
            }
        }
    }
    let base_names = |b: &str| -> Vec<String> { b.split(',').map(|x| x.trim()).filter(|x| !x.contains('=') && !x.is_empty() && *x != "SQLModel").map(|x| x.rsplit('.').next().unwrap_or(x).to_string()).collect() };
    // base classes some table class inherits (transitively, within the file)
    let mut needed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stack: Vec<String> = classes.iter().filter(|c| c.1.contains("table=True")).flat_map(|c| base_names(&c.1)).collect();
    while let Some(n) = stack.pop() {
        if needed.insert(n.clone()) {
            if let Some(c) = classes.iter().find(|c| c.0 == n) {
                stack.extend(base_names(&c.1));
            }
        }
    }
    for (name, bases, start, end) in &classes {
        let table_cls = bases.contains("table=True");
        if !table_cls && !needed.contains(name) {
            continue;
        }
        let body = &lines[start + 1..(*end).min(lines.len())];
        let table = if table_cls { body.iter().find_map(|l| TBLNAME.captures(l).map(|m| m[1].to_lowercase())).unwrap_or_else(|| name.to_lowercase()) } else { String::new() };
        rows.entities.push(EntityDef {
            file: f.path.clone(),
            line: *start as u32 + 1,
            end_line: (*end).max(start + 1) as u32,
            name: name.clone(),
            table,
            orm: "sqlmodel".into(),
            supers: base_names(bases),
            kind: if table_cls { "entity" } else { "mapped-superclass" }.into(),
        });
        for (k, l) in body.iter().enumerate() {
            let Some(m) = FIELD.captures(l) else { continue };
            let (field, ann, val) = (m[1].to_string(), m[2].trim().to_string(), m.get(3).map(|x| x.as_str()).unwrap_or(""));
            if field.starts_with("__") || field == "model_config" || ann.starts_with("ClassVar") {
                continue;
            }
            let rel = val.trim_start().starts_with("Relationship(");
            let args = val.trim_start().strip_prefix("Field(").and_then(|r| r.rsplit_once(')')).map(|x| x.0).unwrap_or("");
            let mut flags = vec![];
            if arg_bool(args, "unique") == Some(true) {
                flags.push("unique".to_string());
            }
            if rel {
                flags.push("relationship".to_string());
            }
            let target = if rel { ann.trim_start_matches("list[").trim_end_matches(']').split('|').next().unwrap_or("").trim().trim_matches(['"', '\'']).to_string() } else { String::new() };
            if let Some(fk) = arg_str(args, "foreign_key") {
                let (tt, tc) = fk.rsplit_once('.').unwrap_or((fk.as_str(), "id"));
                rows.fks.push(Fk { file: f.path.clone(), line: (start + 2 + k) as u32, from_table: format!("entity:{name}"), from_col: field.to_lowercase(), to_table: tt.to_lowercase(), to_col: tc.to_lowercase(), src: "entity".into() });
            }
            rows.entity_fields.push(EntityField {
                file: f.path.clone(),
                line: (start + 2 + k) as u32,
                entity: name.clone(),
                field: field.clone(),
                column: if rel { String::new() } else { field.to_lowercase() },
                ty: clip(&ann, 40),
                nullable: ann.contains("None") || ann.contains("Optional"),
                transient: false,
                pk: arg_bool(args, "primary_key") == Some(true),
                rel: target,
                flags: flags.join(", "),
            });
        }
    }
}

fn python_access(f: &SourceFile, rows: &mut Rows) {
    static OBJ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Z]\w*)\.objects(?:\.\w+\([^()\n]*\))*\.(\w+)\(").unwrap());
    static SA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(query|select|insert|update|delete)\(\s*([A-Z]\w*)\b").unwrap());
    static FQ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Z]\w*)\.query\.(\w+)\(").unwrap());
    static ADD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(add|add_all|merge|bulk_save_objects)\(\s*([A-Z]\w*)\(").unwrap());
    let t = &f.text;
    if !(t.contains(".objects") || t.contains("query(") || t.contains("select(") || t.contains(".query.") || t.contains(".add(") || t.contains("session.") || t.contains("insert(") || t.contains("update(") || t.contains("delete(")) {
        return;
    }
    let lt = Lines::new(t);
    let mut push = |off: usize, entity: &str, op: &str| {
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(off), kind: "entity".into(), target: entity.to_string(), op: op.into(), via: "orm".into(), extra: String::new() });
    };
    for c in OBJ.captures_iter(t) {
        let w = matches!(&c[2], "create" | "bulk_create" | "update" | "bulk_update" | "delete" | "get_or_create" | "update_or_create" | "save");
        push(c.get(0).unwrap().start(), &c[1], if w { "w" } else { "r" });
    }
    for c in SA.captures_iter(t) {
        let w = matches!(&c[1], "insert" | "update" | "delete");
        push(c.get(0).unwrap().start(), &c[2], if w { "w" } else { "r" });
    }
    for c in FQ.captures_iter(t) {
        push(c.get(0).unwrap().start(), &c[1], "r");
    }
    for c in ADD.captures_iter(t) {
        push(c.get(0).unwrap().start(), &c[2], "w");
    }
    // `session.get(User, id)`; `session.add(db_user)` / `.delete(obj)` / `.merge(obj)` where the variable's class is
    // known in the same function (a `name: Model` parameter, `name = Model(..)` / `Model.model_validate(..)`)
    static GET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bsession\.get\(\s*([A-Z]\w*)\s*,").unwrap());
    for c in GET.captures_iter(t) {
        push(c.get(0).unwrap().start(), &c[1], "r");
    }
    static DEF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:async\s+)?def\s+\w+\s*\(").unwrap());
    static PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\s*:\s*([A-Z]\w*)\s*(?:\|\s*None\s*)?[,)=]").unwrap());
    static ASSIGN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(\w+)\s*(?::\s*[\w|. \[\]]+)?=\s*(?:await\s+)?(?:\w+\.get\(\s*)?([A-Z]\w*)(?:\.model_validate\(|\.from_orm\(|\(|\s*,)").unwrap());
    static OBJW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:session|db|db_session)\.(add|delete|merge)\(\s*(\w+)\s*\)").unwrap());
    if OBJW.is_match(t) {
        let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut off = 0usize;
        let mut in_sig = false;
        for l in t.split_inclusive('\n') {
            if DEF.is_match(l) {
                vars.clear();
                in_sig = true;
            }
            if in_sig {
                for c in PARAM.captures_iter(l) {
                    vars.insert(c[1].to_string(), c[2].to_string());
                }
                if l.trim_end().ends_with(':') {
                    in_sig = false;
                }
            } else if let Some(c) = ASSIGN.captures(l) {
                vars.insert(c[1].to_string(), c[2].to_string());
            }
            for c in OBJW.captures_iter(l) {
                if let Some(ty) = vars.get(&c[2]) {
                    push(off + c.get(0).unwrap().start(), ty, "w");
                }
            }
            off += l.len();
        }
    }
}

fn alembic(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    static REV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*revision\s*(?::[^=]+)?=\s*['"]([^'"]+)['"]"#).unwrap());
    static DOWN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*down_revision\s*(?::[^=]+)?=\s*['"]?([\w-]+)['"]?"#).unwrap());
    let rev = REV.captures(t).map(|c| c[1].to_string()).unwrap_or_default();
    let down = DOWN.captures(t).map(|c| c[1].to_string()).filter(|d| d != "None").unwrap_or_default();
    let lt = Lines::new(t);
    let mk = |rows: &mut Rows, off: usize, tb: &str, op: &str, obj: &str, col: &str, d: String| {
        rows.migrations.push(Migration { file: f.path.clone(), line: lt.at(off), version: rev.clone(), tool: "alembic".into(), table: tb.to_lowercase(), op: op.into(), obj: obj.into(), column: col.to_lowercase(), detail: d });
    };
    mk(rows, 0, "", "create", "revision", "", format!("down={down}"));
    let up_start = t.find("def upgrade").unwrap_or(0);
    let up_end = t.find("def downgrade").filter(|e| *e > up_start).unwrap_or(t.len());
    let up = &t[up_start..up_end];
    static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bop\.(\w+)\(").unwrap());
    // every operation as (name, offset, argument text, arguments laid out like the plain `op.*` call)
    let mut items: Vec<(String, usize, String, Vec<String>)> = vec![];
    for c in CALL.captures_iter(up) {
        let m = c.get(0).unwrap();
        let open = up_start + m.end() - 1;
        let Some((args, _)) = balanced(t, open) else { continue };
        items.push((c[1].to_string(), up_start + m.start(), args.to_string(), split_args(args)));
    }
    // `with op.batch_alter_table('t') as batch_op: batch_op.add_column(...)` (SQLite-friendly autogenerate output)
    static BATCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^([ \t]*)with\s+op\.batch_alter_table\(").unwrap());
    for b in BATCH.captures_iter(up) {
        let whole = b.get(0).unwrap();
        let open = up_start + whole.end() - 1;
        let Some((bargs, close)) = balanced(t, open) else { continue };
        let tb = split_args(bargs).first().map(|x| x.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
        let rest = &t[close + 1..];
        let alias = rest.trim_start().strip_prefix("as").map(|r| r.trim_start().chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>()).unwrap_or_default();
        if alias.is_empty() || tb.is_empty() {
            continue;
        }
        let indent = b[1].len();
        // block = the following lines indented deeper than the `with`
        let body_start = close + 1 + rest.find('\n').map(|i| i + 1).unwrap_or(rest.len());
        let mut body_end = body_start;
        for l in t[body_start.min(t.len())..].split_inclusive('\n') {
            let ind = l.len() - l.trim_start().len();
            if !l.trim().is_empty() && ind <= indent {
                break;
            }
            body_end += l.len();
        }
        let blk = &t[body_start.min(t.len())..body_end.min(t.len())];
        let re = Regex::new(&format!(r"\b{}\.(\w+)\(", regex::escape(&alias))).unwrap();
        for c in re.captures_iter(blk) {
            let m = c.get(0).unwrap();
            let o = body_start + m.end() - 1;
            let Some((args, _)) = balanced(t, o) else { continue };
            let a = split_args(args);
            let tq = tb.clone();
            let mut lay: Vec<String> = vec![tq.clone()];
            match &c[1] {
                "add_column" | "drop_column" | "alter_column" => lay.extend(a.iter().cloned()),
                // batch_op.create_index(name, cols) -> op.create_index(name, table, cols)
                "create_index" | "create_unique_constraint" | "create_primary_key" => {
                    lay = vec![a.first().cloned().unwrap_or_default(), tq];
                    lay.extend(a.iter().skip(1).cloned());
                }
                // batch_op.create_foreign_key(name, referent, local, remote) -> op.create_foreign_key(name, source, referent, local, remote)
                "create_foreign_key" => {
                    lay = vec![a.first().cloned().unwrap_or_default(), tq];
                    lay.extend(a.iter().skip(1).cloned());
                }
                _ => continue,
            }
            items.push((c[1].to_string(), body_start + m.start(), args.to_string(), lay));
        }
    }
    items.sort_by_key(|x| x.1);
    for (opname, off, args_s, a) in items {
        let args = args_s.as_str();
        let s0 = a.first().map(|x| x.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
        // `op.f('ix_user_email')` is an index name wrapped in the naming-convention helper
        let s0 = if s0.contains(".f(") { str_lits(&s0).into_iter().next().unwrap_or(s0) } else { s0 };
        let col_of = |x: &str| -> (String, String) {
            // sa.Column('name', sa.String(50), ...)
            let inner = x.find("Column(").and_then(|p| balanced(x, p + 6).map(|b| b.0.to_string())).unwrap_or_default();
            let ca = split_args(&inner);
            let name = ca.first().map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
            let ty = ca.get(1).cloned().unwrap_or_default();
            let nn = if arg_bool(&inner, "nullable") == Some(false) { " not null" } else { "" };
            (name, format!("{}{}", ty.replace("sa.", ""), nn))
        };
        match opname.as_str() {
            "create_table" => {
                mk(rows, off, &s0, "create", "table", "", "create table".into());
                for x in a.iter().skip(1) {
                    if x.contains("Column(") {
                        let (n, d) = col_of(x);
                        mk(rows, off, &s0, "create", "column", &n, d);
                    } else if x.contains("ForeignKeyConstraint(") {
                        let strs = str_lits(x);
                        if let Some(ref_) = strs.iter().find(|s| s.contains('.')) {
                            let (tt, tc) = ref_.rsplit_once('.').unwrap();
                            let fc = strs.first().cloned().unwrap_or_default();
                            rows.fks.push(Fk { file: f.path.clone(), line: lt.at(off), from_table: s0.to_lowercase(), from_col: fc, to_table: tt.to_lowercase(), to_col: tc.to_lowercase(), src: "migration".into() });
                        }
                    }
                }
            }
            "add_column" => {
                let (n, d) = col_of(a.get(1).map(|s| s.as_str()).unwrap_or(""));
                mk(rows, off, &s0, "add", "column", &n, d);
                if let Some(x) = a.get(1) {
                    if let Some(p) = x.find("ForeignKey(") {
                        if let Some((inner, _)) = balanced(x, p + 10) {
                            let r = str_lits(inner).first().cloned().unwrap_or_default();
                            let (tt, tc) = r.rsplit_once('.').unwrap_or((r.as_str(), "id"));
                            rows.fks.push(Fk { file: f.path.clone(), line: lt.at(off), from_table: s0.to_lowercase(), from_col: n.to_lowercase(), to_table: tt.to_lowercase(), to_col: tc.to_lowercase(), src: "migration".into() });
                        }
                    }
                }
            }
            "drop_column" => mk(rows, off, &s0, "drop", "column", a.get(1).map(|s| s.trim_matches(['"', '\''])).unwrap_or(""), "drop column".into()),
            "alter_column" => {
                let rest = &a[2.min(a.len())..];
                // `new_column_name='id'` is a rename: the replay moves the column
                let detail = match rest.iter().find_map(|x| x.trim().strip_prefix("new_column_name").map(|v| v.trim_start().trim_start_matches('=').trim().trim_matches(['"', '\'']).to_string())) {
                    Some(to) if !to.is_empty() => format!("rename to {to}"),
                    _ => clip(&rest.join(", "), 60),
                };
                mk(rows, off, &s0, "alter", "column", a.get(1).map(|s| s.trim_matches(['"', '\''])).unwrap_or(""), detail)
            }
            "drop_table" => mk(rows, off, &s0, "drop", "table", "", "drop table".into()),
            "rename_table" => mk(rows, off, &s0, "alter", "table", "", format!("rename to {}", a.get(1).map(|s| s.trim_matches(['"', '\''])).unwrap_or(""))),
            "create_index" => {
                let tb = a.get(1).map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
                let cols = a.get(2).map(|s| str_lits(s).join(",")).unwrap_or_default();
                mk(rows, off, &tb, "create", "index", &cols, format!("index {s0}({cols})"));
            }
            "create_foreign_key" => {
                let (src, dst) = (a.get(1).map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default(), a.get(2).map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default());
                let (lc, rc) = (a.get(3).map(|s| str_lits(s).join(",")).unwrap_or_default(), a.get(4).map(|s| str_lits(s).join(",")).unwrap_or_default());
                mk(rows, off, &src, "add", "constraint", &lc, format!("fk({lc}) -> {dst}({rc})"));
                rows.fks.push(Fk { file: f.path.clone(), line: lt.at(off), from_table: src.to_lowercase(), from_col: lc.to_lowercase(), to_table: dst.to_lowercase(), to_col: rc.to_lowercase(), src: "migration".into() });
            }
            "create_unique_constraint" | "create_primary_key" => {
                let tb = a.get(1).map(|s| s.trim_matches(['"', '\'']).to_string()).unwrap_or_default();
                let cols = a.get(2).map(|s| str_lits(s).join(",")).unwrap_or_default();
                mk(rows, off, &tb, "add", "constraint", &cols, format!("{}({cols})", if opname == "create_primary_key" { "primary key" } else { "unique" }));
            }
            "execute" => {
                if let Some(sql) = str_lits(args).into_iter().find(|s| looks_like_sql(s) || s.to_uppercase().starts_with("ALTER") || s.to_uppercase().starts_with("CREATE")) {
                    let (m, fk) = parse_ddl(&Ctx { file: &f.path, version: &rev, tool: "alembic" }, &sql);
                    let base = lt.at(off);
                    for mut x in m {
                        x.line = base;
                        rows.migrations.push(x);
                    }
                    for mut x in fk {
                        x.line = base;
                        rows.fks.push(x);
                    }
                }
            }
            _ => {}
        }
    }
}

fn django_migration(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let name = f.name();
    let version: String = name.chars().take_while(|c| c.is_ascii_digit()).collect();
    let app = f.path.rsplit('/').nth(2).unwrap_or("").to_string();
    let lt = Lines::new(t);
    let tbl = |model: &str| format!("{}_{}", app, model.to_lowercase());
    static OP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"migrations\.(CreateModel|DeleteModel|AddField|RemoveField|AlterField|RenameField|RenameModel)\(").unwrap());
    for c in OP.captures_iter(t) {
        let m = c.get(0).unwrap();
        let open = m.end() - 1;
        let Some((args, _)) = balanced(t, open) else { continue };
        let ln = lt.at(m.start());
        let mut mk = |tb: &str, op: &str, obj: &str, col: &str, d: String| {
            rows.migrations.push(Migration { file: f.path.clone(), line: ln, version: version.clone(), tool: "django".into(), table: tb.to_lowercase(), op: op.into(), obj: obj.into(), column: col.to_lowercase(), detail: d });
        };
        match &c[1] {
            "CreateModel" => {
                let model = arg_str(args, "name").unwrap_or_default();
                mk(&tbl(&model), "create", "table", "", "create table".into());
                if let Some(p) = args.find("fields=[") {
                    let fields = &args[p + 7..];
                    static F: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\(\s*['"](\w+)['"]\s*,\s*(?:\w+\.)*(\w+)\("#).unwrap());
                    for fc in F.captures_iter(fields) {
                        let col = if matches!(&fc[2], "ForeignKey" | "OneToOneField") { format!("{}_id", &fc[1]) } else { fc[1].to_string() };
                        if &fc[2] != "ManyToManyField" {
                            mk(&tbl(&model), "create", "column", &col, fc[2].to_string());
                        }
                    }
                }
            }
            "DeleteModel" => mk(&tbl(&arg_str(args, "name").unwrap_or_default()), "drop", "table", "", "drop table".into()),
            "AddField" | "AlterField" | "RemoveField" | "RenameField" => {
                let model = arg_str(args, "model_name").unwrap_or_default();
                let fname = arg_str(args, "name").or_else(|| arg_str(args, "old_name")).unwrap_or_default();
                let fty = args.find("field=").map(|p| args[p + 6..].split('(').next().unwrap_or("").rsplit('.').next().unwrap_or("").to_string()).unwrap_or_default();
                let col = if matches!(fty.as_str(), "ForeignKey" | "OneToOneField") { format!("{fname}_id") } else { fname };
                let (op, d) = match &c[1] {
                    "AddField" => ("add", fty),
                    "AlterField" => ("alter", format!("type {fty}")),
                    "RemoveField" => ("drop", "drop column".to_string()),
                    _ => ("alter", format!("rename to {}", arg_str(args, "new_name").unwrap_or_default())),
                };
                mk(&tbl(&model), op, "column", &col, d);
            }
            _ => {}
        }
    }
}

// ───────────────────────────── TypeScript / JavaScript ORMs ─────────────────────────────

fn typescript(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    if t.contains("@Entity") {
        typeorm(f, rows);
    }
    if t.contains("pgTable(") || t.contains("mysqlTable(") || t.contains("sqliteTable(") {
        drizzle(f, rows);
    }
    ts_access(f, rows);
    sql_strings(f, Lang::Ts, rows);
    state_literals(f, Lang::Ts, rows);
}

fn typeorm(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let lt = Lines::new(t);
    let lines: Vec<&str> = t.lines().collect();
    static PROP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:(?:public|private|protected|readonly|declare)\s+)*(\w+)[!?]?\s*:\s*([^;=]+?)\s*(?:=[^;]*)?;?\s*$").unwrap());
    static CLASS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?").unwrap());
    let mut ent: Option<(String, String)> = None; // (entity decorator args, ...)
    let mut cur: Option<String> = None;
    let mut decos: Vec<(usize, String)> = vec![];
    let mut i = 0;
    let offs: Vec<usize> = {
        let mut o = vec![0];
        o.extend(t.match_indices('\n').map(|(i, _)| i + 1));
        o
    };
    while i < lines.len() {
        let l = lines[i];
        let tl = l.trim();
        if tl.starts_with('@') {
            // collect the whole decorator, possibly multi-line
            let open = l.find('(').map(|p| offs[i] + p);
            let text = match open.and_then(|o| balanced(t, o)) {
                Some((_, end)) => {
                    let s = &t[offs[i] + l.find('@').unwrap()..end];
                    let nl = t[..end].matches('\n').count();
                    i = nl;
                    s.to_string()
                }
                None => tl.to_string(),
            };
            if anno_name(&text) == "Entity" {
                ent = Some((text.clone(), String::new()));
            }
            decos.push((i + 1, text));
            i += 1;
            continue;
        }
        if let Some(c) = CLASS.captures(l) {
            let name = c[1].to_string();
            if let Some((e, _)) = ent.take() {
                let args = e.split_once('(').map(|x| x.1.trim_end_matches(')').to_string()).unwrap_or_default();
                let table = str_lits(&args).first().cloned().filter(|s| !s.is_empty()).or_else(|| arg_str(&args, "name")).unwrap_or_else(|| snake(&name));
                rows.entities.push(EntityDef {
                    file: f.path.clone(),
                    line: decos.first().map(|d| d.0).unwrap_or(i + 1) as u32,
                    end_line: lt.at(t.len()),
                    name: name.clone(),
                    table: table.to_lowercase(),
                    orm: "typeorm".into(),
                    supers: c.get(2).map(|m| vec![m.as_str().to_string()]).unwrap_or_default(),
                    kind: "entity".into(),
                });
                cur = Some(name);
            } else {
                cur = None;
            }
            decos.clear();
            i += 1;
            continue;
        }
        if let (Some(ent_name), Some(p)) = (&cur, PROP.captures(l)) {
            if !decos.is_empty() {
                let field = p[1].to_string();
                let ty = p[2].trim().to_string();
                let find = |a: &str| decos.iter().find(|d| anno_name(&d.1) == a).map(|d| d.1.clone());
                let col = find("Column");
                let pk = find("PrimaryGeneratedColumn").is_some() || find("PrimaryColumn").is_some();
                let rel = find("ManyToOne").or_else(|| find("OneToOne"));
                let inverse = find("OneToMany").is_some() || find("ManyToMany").is_some();
                let join = find("JoinColumn");
                let special = ["CreateDateColumn", "UpdateDateColumn", "DeleteDateColumn", "VersionColumn"].iter().any(|a| find(a).is_some());
                if col.is_some() || pk || rel.is_some() || inverse || special {
                    let first_line = decos.first().map(|d| d.0).unwrap_or(i + 1) as u32;
                    let cname = if inverse {
                        String::new()
                    } else if let Some(r) = &rel {
                        let _ = r;
                        join.as_ref().and_then(|j| arg_str(j, "name")).unwrap_or_else(|| format!("{field}Id"))
                    } else {
                        col.as_ref().and_then(|c| arg_str(c, "name")).unwrap_or_else(|| field.clone())
                    };
                    let nullable = !pk && col.as_ref().map(|c| arg_bool(c, "nullable") == Some(true)).unwrap_or(false) || rel.as_ref().is_some_and(|r| arg_bool(r, "nullable") == Some(true));
                    let relt = rel.as_ref().or(find("OneToMany").as_ref().or(find("ManyToMany").as_ref())).map(|r| {
                        // () => Target
                        r.split("=>").nth(1).map(|x| x.trim().split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string()).unwrap_or_default()
                    }).unwrap_or_default();
                    if !relt.is_empty() && !cname.is_empty() {
                        rows.fks.push(Fk { file: f.path.clone(), line: first_line, from_table: format!("entity:{ent_name}"), from_col: cname.to_lowercase(), to_table: format!("entity:{relt}"), to_col: String::new(), src: "entity".into() });
                    }
                    rows.entity_fields.push(EntityField {
                        file: f.path.clone(),
                        line: first_line,
                        entity: ent_name.clone(),
                        field,
                        column: cname.to_lowercase(),
                        ty: clip(&ty, 40),
                        nullable,
                        transient: false,
                        pk,
                        rel: relt,
                        flags: if inverse { "inverse".into() } else { String::new() },
                    });
                }
            }
            decos.clear();
            i += 1;
            continue;
        }
        if !tl.is_empty() && !tl.starts_with("//") && !tl.starts_with('*') && !tl.starts_with("/*") {
            decos.clear();
        }
        i += 1;
    }
}

fn drizzle(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    static TBL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:pg|mysql|sqlite)Table\(\s*['"]([^'"]+)['"]\s*,\s*\{"#).unwrap());
    static COL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s*(\w+)\s*:\s*(\w+)\(\s*(?:['"]([^'"]+)['"])?"#).unwrap());
    let lt = Lines::new(t);
    for c in TBL.captures_iter(t) {
        let m = c.get(0).unwrap();
        let open = m.end() - 1;
        // matching brace
        let b = t.as_bytes();
        let (mut d, mut e) = (0i32, open);
        while e < b.len() {
            match b[e] {
                b'{' => d += 1,
                b'}' => {
                    d -= 1;
                    if d == 0 {
                        break;
                    }
                }
                _ => {}
            }
            e += 1;
        }
        let ent = c[1].to_string();
        rows.entities.push(EntityDef { file: f.path.clone(), line: lt.at(m.start()), end_line: lt.at(e.min(t.len() - 1)), name: ent.clone(), table: c[2].to_lowercase(), orm: "drizzle".into(), supers: vec![], kind: "entity".into() });
        let body = &t[open + 1..e.min(t.len())];
        let base_line = lt.at(open);
        for (k, l) in body.lines().enumerate() {
            if let Some(cc) = COL.captures(l) {
                let ln = base_line + k as u32;
                let field = cc[1].to_string();
                let column = cc.get(3).map(|x| x.as_str().to_string()).unwrap_or_else(|| field.clone());
                let fk = l.find(".references(").and_then(|p| l[p..].split("=>").nth(1).map(|x| x.trim().to_string()));
                if let Some(r) = &fk {
                    let target = r.split('.').next().unwrap_or("").trim().to_string();
                    let tcol = r.split('.').nth(1).map(|x| x.split(|c: char| !c.is_alphanumeric() && c != '_').next().unwrap_or("").to_string()).unwrap_or_default();
                    rows.fks.push(Fk { file: f.path.clone(), line: ln, from_table: format!("entity:{ent}"), from_col: column.to_lowercase(), to_table: format!("entity:{target}"), to_col: tcol.to_lowercase(), src: "entity".into() });
                }
                rows.entity_fields.push(EntityField {
                    file: f.path.clone(),
                    line: ln,
                    entity: ent.clone(),
                    field,
                    column: column.to_lowercase(),
                    ty: cc[2].to_string(),
                    nullable: !(l.contains(".notNull()") || l.contains(".primaryKey()")),
                    transient: false,
                    pk: l.contains(".primaryKey()"),
                    rel: fk.map(|r| r.split('.').next().unwrap_or("").trim().to_string()).unwrap_or_default(),
                    flags: if l.contains(".unique()") { "unique".into() } else { String::new() },
                });
            }
        }
    }
}

fn prisma(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    let lines: Vec<&str> = t.lines().collect();
    let models: Vec<String> = lines.iter().filter_map(|l| l.trim().strip_prefix("model ").map(|r| r.split_whitespace().next().unwrap_or("").to_string())).collect();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if let Some(r) = l.strip_prefix("model ") {
            let name = r.split_whitespace().next().unwrap_or("").to_string();
            let start = i;
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim() != "}" {
                j += 1;
            }
            let body = &lines[start + 1..j];
            let table = body.iter().find_map(|b| b.trim().strip_prefix("@@map(").and_then(|x| str_lits(x).first().cloned())).unwrap_or_else(|| name.clone());
            // composite key: @@id([a, b])
            let composite: Vec<String> = body
                .iter()
                .find_map(|b| b.trim().strip_prefix("@@id(").map(|x| x.split(']').next().unwrap_or("").trim_start_matches('[').split(',').map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).collect()))
                .unwrap_or_default();
            rows.entities.push(EntityDef { file: f.path.clone(), line: start as u32 + 1, end_line: j as u32 + 1, name: name.clone(), table: table.to_lowercase(), orm: "prisma".into(), supers: vec![], kind: "entity".into() });
            for (k, b) in body.iter().enumerate() {
                let b = b.trim();
                if b.is_empty() || b.starts_with("//") || b.starts_with('@') {
                    continue;
                }
                let mut parts = b.split_whitespace();
                let (Some(field), Some(ty)) = (parts.next(), parts.next()) else { continue };
                let list = ty.ends_with("[]");
                let optional = ty.ends_with('?');
                let base = ty.trim_end_matches("[]").trim_end_matches('?');
                let is_model = models.iter().any(|m| m == base);
                let ln = start as u32 + 2 + k as u32;
                let mapped = b.find("@map(").and_then(|p| str_lits(&b[p..]).first().cloned());
                if is_model {
                    // relation field: FK columns come from @relation(fields: [..], references: [..])
                    if let Some(p) = b.find("@relation(") {
                        let seg = &b[p..];
                        let fields = seg.find("fields:").map(|q| seg[q + 7..].split(']').next().unwrap_or("").trim_matches([' ', '[']).replace(' ', "")).unwrap_or_default();
                        let refs = seg.find("references:").map(|q| seg[q + 11..].split(']').next().unwrap_or("").trim_matches([' ', '[']).replace(' ', "")).unwrap_or_default();
                        if !fields.is_empty() {
                            rows.fks.push(Fk { file: f.path.clone(), line: ln, from_table: format!("entity:{name}"), from_col: fields.to_lowercase(), to_table: format!("entity:{base}"), to_col: refs.to_lowercase(), src: "entity".into() });
                        }
                    }
                    rows.entity_fields.push(EntityField { file: f.path.clone(), line: ln, entity: name.clone(), field: field.to_string(), column: String::new(), ty: ty.to_string(), nullable: optional, transient: false, pk: false, rel: base.to_string(), flags: if list { "1:N".into() } else { "relation".into() } });
                } else {
                    rows.entity_fields.push(EntityField {
                        file: f.path.clone(),
                        line: ln,
                        entity: name.clone(),
                        field: field.to_string(),
                        column: mapped.unwrap_or_else(|| field.to_string()).to_lowercase(),
                        ty: ty.to_string(),
                        nullable: optional,
                        transient: false,
                        pk: b.contains("@id") || composite.iter().any(|c| c == field),
                        rel: String::new(),
                        flags: if b.contains("@unique") { "unique".into() } else { String::new() },
                    });
                }
            }
            i = j;
        }
        i += 1;
    }
}

fn ts_access(f: &SourceFile, rows: &mut Rows) {
    static PRISMA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\.(\w+)\.(findMany|findFirst|findUnique|findFirstOrThrow|findUniqueOrThrow|create|createMany|update|updateMany|upsert|delete|deleteMany|count|aggregate|groupBy)\(").unwrap());
    static DRIZ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(from|insert|update|delete|into|leftJoin|innerJoin|rightJoin|fullJoin)\(\s*([A-Za-z_]\w*)\s*[,)]").unwrap());
    static DRIZQ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.query\.(\w+)\.(find\w+)\(").unwrap());
    static GETREPO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"getRepository\(\s*([A-Z]\w*)\s*\)\s*\.(\w+)\(").unwrap());
    static MGR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:manager|em|entityManager|transactionalEntityManager)\.(save|insert|update|delete|remove|softRemove|upsert|find\w*|count\w*|exists\w*)\(\s*([A-Z]\w*)\b").unwrap());
    let t = &f.text;
    let lt = Lines::new(t);
    let wr = |m: &str| {
        m.starts_with("create") || m.starts_with("update") || m.starts_with("delete") || m.starts_with("upsert") || m.starts_with("save") || m.starts_with("insert") || m.starts_with("remove") || m.starts_with("softRemove")
    };
    let mut push = |off: usize, target: &str, op: &str, extra: &str| {
        rows.data_raw.push(DataRaw { file: f.path.clone(), line: lt.at(off), kind: "entity".into(), target: target.to_string(), op: op.into(), via: "orm".into(), extra: extra.into() });
    };
    if t.contains("prisma") || t.contains("Prisma") || t.contains("db.") {
        for c in PRISMA.captures_iter(t) {
            let recv = c[1].to_lowercase();
            if recv.contains("prisma") || recv == "db" || recv == "tx" || recv == "client" || recv == "this" || recv.contains("db") {
                push(c.get(0).unwrap().start(), &c[2], if wr(&c[3]) { "w" } else { "r" }, "prisma");
            }
        }
    }
    if t.contains("drizzle") || t.contains("db.") || t.contains("tx.") {
        for c in DRIZ.captures_iter(t) {
            push(c.get(0).unwrap().start(), &c[2], if matches!(&c[1], "from" | "leftJoin" | "innerJoin" | "rightJoin" | "fullJoin") { "r" } else { "w" }, "drizzle");
        }
        for c in DRIZQ.captures_iter(t) {
            push(c.get(0).unwrap().start(), &c[1], "r", "drizzle");
        }
    }
    if t.contains("getRepository") {
        for c in GETREPO.captures_iter(t) {
            push(c.get(0).unwrap().start(), &c[1], if wr(&c[2]) { "w" } else { "r" }, "typeorm");
        }
    }
    if t.contains("manager") || t.contains("entityManager") || t.contains("em.") {
        for c in MGR.captures_iter(t) {
            push(c.get(0).unwrap().start(), &c[2], if wr(&c[1]) { "w" } else { "r" }, "typeorm");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_names() {
        assert_eq!(snake("schoolRealmUserId"), "school_realm_user_id");
        assert_eq!(snake("FinalizationRecord"), "finalization_record");
        assert_eq!(snake("userID"), "user_id");
        assert_eq!(snake("URLValue"), "url_value");
    }

    #[test]
    fn literals_join() {
        let l = string_literals("String q = \"SELECT a \" + \"FROM t\"; // \"no\"\nx(\"b\");", Lang::Java);
        assert_eq!(l[0].1, "SELECT a FROM t");
        assert_eq!(l[1].1, "b");
    }

    #[test]
    fn migration_versions() {
        assert_eq!(migration_ctx("db/migration/V21__x.sql", "sql"), Some(("21".into(), "flyway".into())));
        assert_eq!(migration_ctx("db/migration/V1_2__x.sql", "sql"), Some(("1.2".into(), "flyway".into())));
        assert_eq!(migration_ctx("db/migration/R__fn.sql", "sql"), Some(("R".into(), "flyway".into())));
        assert_eq!(migration_ctx("prisma/migrations/20230101000000_init/migration.sql", "sql"), Some(("20230101000000".into(), "prisma".into())));
        assert_eq!(migration_ctx("scripts/seed.sql", "sql"), None);
    }
}
