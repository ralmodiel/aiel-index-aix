//! A small SQL tokenizer plus two consumers: a DDL reader for migrations (CREATE/ALTER/DROP TABLE, indexes,
//! constraints, foreign keys, views, functions, seed data) and a table/operation scanner for SQL strings found in
//! code (native queries, JPQL, JDBC). Dialect-tolerant (PostgreSQL, MySQL, SQLite, H2): it never fails, it just
//! skips what it does not understand.

use crate::model::{Fk, Migration};
use crate::text::Lines;

#[derive(Clone, Debug, PartialEq)]
pub enum Tk {
    /// bare identifier or keyword (original case)
    Word(String),
    /// "quoted" / `quoted` identifier
    Quoted(String),
    /// 'string' literal (content unused)
    Str,
    Num,
    /// $$ ... $$ body
    Body,
    P(char),
}

#[derive(Clone, Debug)]
pub struct Tok {
    pub tk: Tk,
    pub off: usize,
}

impl Tok {
    fn is(&self, kw: &str) -> bool {
        matches!(&self.tk, Tk::Word(w) if w.eq_ignore_ascii_case(kw))
    }
    fn name(&self) -> Option<String> {
        match &self.tk {
            Tk::Word(w) => Some(w.clone()),
            Tk::Quoted(w) => Some(w.clone()),
            _ => None,
        }
    }
    /// Identifier as shown for schema objects: a plain name as written, a quoted one that is case sensitive or has
    /// spaces / punctuation kept in double quotes.
    fn dname(&self) -> Option<String> {
        match &self.tk {
            Tk::Quoted(w) => {
                // plain identifiers (`"UserId"`) keep the old lower-case folding so entity columns still match;
                // names with spaces / punctuation keep their case and show quoted
                if !w.is_empty() && w.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    Some(w.clone())
                } else {
                    // control characters and newlines cannot appear in a printed name; long names are cut
                    let t: String = w.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
                    let t = if t.chars().count() > 60 { format!("{}~", t.chars().take(60).collect::<String>()) } else { t };
                    Some(format!("\"{}\"", t.replace('"', "\"\"")))
                }
            }
            _ => self.name(),
        }
    }

    fn p(&self, c: char) -> bool {
        self.tk == Tk::P(c)
    }
}

pub fn tokenize(text: &str) -> Vec<Tok> {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut out = vec![];
    while i < n {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'-' if i + 1 < n && b[i + 1] == b'-' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'#' if false => {}
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                // block comments nest in PostgreSQL
                i += 2;
                let mut depth = 1;
                while i + 1 < n && depth > 0 {
                    if b[i] == b'/' && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if depth > 0 {
                    i = n;
                }
            }
            b'\'' => {
                let off = i;
                i += 1;
                let esc = off > 0 && (b[off - 1] == b'E' || b[off - 1] == b'e');
                while i < n {
                    if esc && b[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if b[i] == b'\'' {
                        if i + 1 < n && b[i + 1] == b'\'' {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i = (i + 1).min(n);
                out.push(Tok { tk: Tk::Str, off });
            }
            b'"' | b'`' => {
                let off = i;
                let q = c;
                i += 1;
                let s = i;
                while i < n {
                    if b[i] == q {
                        if i + 1 < n && b[i + 1] == q {
                            i += 2; // "" inside a quoted identifier is a literal quote
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                let q1 = q as char;
                out.push(Tok { tk: Tk::Quoted(text[s..i.min(n)].replace(&format!("{q1}{q1}"), &q1.to_string())), off });
                i = (i + 1).min(n);
            }
            b'$' => {
                // $$ or $tag$ ... $tag$ ; a bare $1 parameter is a number
                let off = i;
                let mut j = i + 1;
                while j < n && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j < n && b[j] == b'$' && (j == i + 1 || !b[i + 1].is_ascii_digit()) {
                    let tag = &text[i..=j];
                    match text[j + 1..].find(tag) {
                        Some(k) => i = j + 1 + k + tag.len(),
                        None => i = n,
                    }
                    out.push(Tok { tk: Tk::Body, off });
                } else {
                    while j < n && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    i = j.max(i + 1);
                    out.push(Tok { tk: Tk::Num, off });
                }
            }
            c if c.is_ascii_digit() => {
                let off = i;
                while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                    i += 1;
                }
                out.push(Tok { tk: Tk::Num, off });
            }
            c if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 => {
                let off = i;
                while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$' || b[i] >= 0x80) {
                    i += 1;
                }
                out.push(Tok { tk: Tk::Word(text[off..i].to_string()), off });
            }
            _ => {
                let ch = text[i..].chars().next().unwrap_or(' ');
                out.push(Tok { tk: Tk::P(ch), off: i });
                i += ch.len_utf8();
            }
        }
    }
    out
}

/// Statements: token ranges split at top-level `;`.
fn statements(toks: &[Tok]) -> Vec<&[Tok]> {
    let mut out = vec![];
    let mut s = 0;
    for (i, t) in toks.iter().enumerate() {
        if t.p(';') {
            if i > s {
                out.push(&toks[s..i]);
            }
            s = i + 1;
        }
    }
    if s < toks.len() {
        out.push(&toks[s..]);
    }
    out
}

/// Split at depth-0 commas, honouring parentheses.
fn split_commas(toks: &[Tok]) -> Vec<&[Tok]> {
    let mut out = vec![];
    let (mut depth, mut s) = (0i32, 0);
    for (i, t) in toks.iter().enumerate() {
        match t.tk {
            Tk::P('(') => depth += 1,
            Tk::P(')') => depth -= 1,
            Tk::P(',') if depth == 0 => {
                out.push(&toks[s..i]);
                s = i + 1;
            }
            _ => {}
        }
    }
    if s < toks.len() {
        out.push(&toks[s..]);
    }
    out
}

fn upper(t: &Tok) -> String {
    match &t.tk {
        Tk::Word(w) => w.to_uppercase(),
        _ => String::new(),
    }
}

/// `a.b.c` -> "c" and the index after it.
fn qname(toks: &[Tok], mut i: usize) -> Option<(String, usize)> {
    let mut last = toks.get(i)?.dname()?;
    i += 1;
    while i + 1 < toks.len() && toks[i].p('.') {
        match toks[i + 1].dname() {
            Some(n) => last = n,
            None => break,
        }
        i += 2;
    }
    Some((last, i))
}

/// Names inside the first parenthesised group at or after `i`: ("a,b", index after the group).
fn paren_names(toks: &[Tok], mut i: usize) -> (String, usize) {
    while i < toks.len() && !toks[i].p('(') {
        if toks[i].p(',') || toks[i].p(';') {
            return (String::new(), i);
        }
        i += 1;
    }
    let mut depth = 0;
    let mut names = vec![];
    while i < toks.len() {
        match &toks[i].tk {
            Tk::P('(') => depth += 1,
            Tk::P(')') => {
                depth -= 1;
                if depth == 0 {
                    return (names.join(","), i + 1);
                }
            }
            t if depth == 1 => {
                if let Some(n) = toks[i].dname() {
                    // skip ASC/DESC/opclass noise: keep the first name of each comma group
                    let prev_comma_or_open = i > 0 && (toks[i - 1].p('(') || toks[i - 1].p(','));
                    if prev_comma_or_open {
                        names.push(n);
                    }
                }
                let _ = t;
            }
            _ => {}
        }
        i += 1;
    }
    (names.join(","), i)
}

/// Index key list at or after `i`: simple columns by name, expressions as their clipped raw text. Returns the list
/// ("a,lower(b)") and the index after the group.
fn index_cols(toks: &[Tok], mut i: usize, text: &str) -> (String, usize) {
    while i < toks.len() && !toks[i].p('(') {
        if toks[i].p(',') || toks[i].p(';') {
            return (String::new(), i);
        }
        i += 1;
    }
    if i >= toks.len() {
        return (String::new(), i);
    }
    let mut depth = 0;
    let mut close = toks.len();
    for (k, t) in toks.iter().enumerate().skip(i) {
        match t.tk {
            Tk::P('(') => depth += 1,
            Tk::P(')') => {
                depth -= 1;
                if depth == 0 {
                    close = k;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &toks[(i + 1).min(close)..close];
    let mut parts: Vec<String> = vec![];
    for el in split_commas(inner) {
        let Some(f) = el.first() else { continue };
        let call = el.get(1).is_some_and(|t| t.p('('));
        let prefix_len = call && el.get(2).is_some_and(|t| t.tk == Tk::Num);
        if let (Some(n), true) = (f.dname(), !call || prefix_len) {
            parts.push(n);
        } else {
            let e = tok_end(el, el.len() - 1, text);
            parts.push(clip(&text[f.off..e.max(f.off)], 60));
        }
    }
    (parts.join(","), (close + 1).min(toks.len()))
}

/// Raw text of the first parenthesised group at or after `i`, clipped (without the outer parentheses).
fn paren_text(toks: &[Tok], i: usize, text: &str, n: usize) -> String {
    let Some(open) = toks.iter().skip(i).position(|t| t.p('(')).map(|x| x + i) else { return String::new() };
    let mut depth = 0;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match t.tk {
            Tk::P('(') => depth += 1,
            Tk::P(')') => {
                depth -= 1;
                if depth == 0 {
                    if k == open + 1 {
                        return String::new();
                    }
                    let (s, e) = (toks[open + 1].off, tok_end(toks, k - 1, text));
                    return clip(&text[s..e.max(s)], n);
                }
            }
            _ => {}
        }
    }
    let s = toks.get(open + 1).map(|t| t.off).unwrap_or(0);
    clip(&text[s..text.len().max(s)], n)
}

const COL_STOP: &[&str] = &[
    "NOT", "NULL", "DEFAULT", "PRIMARY", "UNIQUE", "REFERENCES", "CHECK", "GENERATED", "CONSTRAINT", "COLLATE", "AUTO_INCREMENT",
    "AUTOINCREMENT", "COMMENT", "IDENTITY", "ON", "UNSIGNED",
];

fn type_text(toks: &[Tok], text: &str) -> (String, usize) {
    let mut i = 0;
    let mut depth = 0;
    while i < toks.len() {
        if depth == 0 && COL_STOP.contains(&upper(&toks[i]).as_str()) {
            break;
        }
        match toks[i].tk {
            Tk::P('(') => depth += 1,
            Tk::P(')') => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    let s = toks.first().map(|t| t.off).unwrap_or(0);
    let e = if i > 0 { tok_end(toks, i - 1, text) } else { s };
    (text[s.min(e)..e].split_whitespace().collect::<Vec<_>>().join(" "), i)
}

fn tok_end(toks: &[Tok], i: usize, text: &str) -> usize {
    let t = &toks[i];
    match &t.tk {
        Tk::Word(w) => t.off + w.len(),
        Tk::Quoted(_) => {
            let b = text.as_bytes();
            let q = b[t.off];
            let mut i = t.off + 1;
            while i < b.len() {
                if b[i] == q {
                    if i + 1 < b.len() && b[i + 1] == q {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            (i + 1).min(text.len())
        }
        Tk::P(c) => t.off + c.len_utf8(),
        Tk::Str => {
            let b = text.as_bytes();
            let mut i = t.off + 1;
            while i < b.len() {
                if b[i] == b'\'' {
                    if i + 1 < b.len() && b[i + 1] == b'\'' {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            (i + 1).min(text.len())
        }
        Tk::Num => {
            let b = text.as_bytes();
            let mut i = t.off;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'$') {
                i += 1;
            }
            i
        }
        Tk::Body => toks.get(i + 1).map(|n| n.off).unwrap_or(text.len()).min(text.len()),
    }
}

fn clip(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= n {
        s
    } else {
        let mut o: String = s.chars().take(n).collect();
        // never cut inside a quoted literal without closing it
        if o.matches('\'').count() % 2 == 1 {
            o.push('\'');
        }
        o.push('~');
        o
    }
}

/// Lower-case unless the name is a quoted identifier shown with its case.
fn lc(s: &str) -> String {
    if s.contains('"') {
        s.to_string()
    } else {
        s.to_lowercase()
    }
}

const CRED_WORDS: &[&str] = &["password", "passwd", "passcode", "secret", "token", "credential", "apikey", "privatekey", "passphrase", "bearer"];
const CRED_SEGS: &[&str] = &["pwd", "pass", "key", "salt", "hash", "otp", "pin", "pw", "cred", "creds", "seed", "cvv", "ssn", "mfa", "totp"];

/// Does a column name say it holds a credential (password, token, key, salt, hash, otp, pin ...)?
pub fn is_credential_name(col: &str) -> bool {
    // split camelCase and snake_case into lower-case segments
    let mut segs: Vec<String> = vec![];
    let mut cur = String::new();
    let mut prev_lower = false;
    for ch in col.chars() {
        if !ch.is_alphanumeric() {
            if !cur.is_empty() {
                segs.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if ch.is_uppercase() && prev_lower && !cur.is_empty() {
            segs.push(std::mem::take(&mut cur));
        }
        prev_lower = ch.is_lowercase();
        cur.extend(ch.to_lowercase());
    }
    if !cur.is_empty() {
        segs.push(cur);
    }
    let flat = col.to_lowercase().replace(['_', ' ', '-', '"'], "");
    CRED_WORDS.iter().any(|w| flat.contains(w)) || segs.iter().any(|s| CRED_SEGS.contains(&s.as_str()))
}

/// A column default fit to print. Credential-named columns never show their default (except null / booleans / now());
/// other columns show functions, numbers, booleans and short enum-like literals only.
pub fn safe_default(col: &str, raw: &str) -> String {
    let mut r = raw.trim();
    // strip a trailing ::cast (outside quotes)
    if let Some(p) = r.rfind("::") {
        if r[..p].matches('\'').count() % 2 == 0 {
            r = r[..p].trim();
        }
    }
    let l = r.to_lowercase();
    let cred = is_credential_name(col);
    let is_num = !l.is_empty() && l.trim_start_matches(['-', '+']).chars().all(|c| c.is_ascii_digit() || c == '.') && l.chars().any(|c| c.is_ascii_digit());
    let no_arg_fn = {
        let t = l.trim_end_matches("()");
        t != l && !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    };
    let time_fn = l.starts_with("current_") || l.starts_with("localtime") || l == "sysdate" || l == "getdate()" || l.starts_with("now(") || l.starts_with("statement_timestamp") || l.starts_with("transaction_timestamp");
    if l == "null" || l == "true" || l == "false" || time_fn {
        return clip(r, 30);
    }
    if cred {
        return if l == "''" || l == "0" || l == "1" { clip(r, 30) } else { "<redacted>".into() };
    }
    if no_arg_fn || is_num {
        return clip(r, 30);
    }
    if r.len() >= 2 && r.starts_with('\'') && r.ends_with('\'') && r[1..r.len() - 1].find('\'').is_none() {
        let inner = &r[1..r.len() - 1];
        let enum_like = inner.chars().count() <= 24
            && inner.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '.' | '-' | ':' | '/' | ','))
            && !inner.contains("://");
        // long digit+letter runs without spaces look like tokens or hashes
        let token_like = inner.len() >= 16 && !inner.contains(' ') && inner.chars().any(|c| c.is_ascii_digit()) && inner.chars().any(|c| c.is_ascii_alphabetic());
        return if enum_like && !token_like { r.to_string() } else { "<literal>".into() };
    }
    if l.starts_with("nextval(") && !r.contains(' ') {
        return clip(r, 40);
    }
    if r.contains('\'') || r.contains('"') || r.contains('$') {
        return "<expr>".into();
    }
    clip(r, 30)
}

pub struct Ctx<'a> {
    pub file: &'a str,
    pub version: &'a str,
    pub tool: &'a str,
}

struct Em<'a> {
    cx: &'a Ctx<'a>,
    lines: Lines,
    mig: Vec<Migration>,
    fks: Vec<Fk>,
}

impl Em<'_> {
    #[allow(clippy::too_many_arguments)]
    fn m(&mut self, off: usize, table: &str, op: &str, obj: &str, col: &str, detail: String) {
        self.mig.push(Migration {
            file: self.cx.file.to_string(),
            line: self.lines.at(off),
            version: self.cx.version.to_string(),
            tool: self.cx.tool.to_string(),
            table: lc(table),
            op: op.to_string(),
            obj: obj.to_string(),
            column: lc(col),
            detail,
        });
    }
    fn fk(&mut self, off: usize, from_t: &str, from_c: &str, to_t: &str, to_c: &str) {
        let (fc, tc): (Vec<&str>, Vec<&str>) = (from_c.split(',').collect(), to_c.split(',').collect());
        for (k, f) in fc.iter().enumerate() {
            self.fks.push(Fk {
                file: self.cx.file.to_string(),
                line: self.lines.at(off),
                from_table: lc(from_t),
                from_col: lc(f),
                to_table: lc(to_t),
                to_col: lc(tc.get(k).copied().unwrap_or("")),
                src: "migration".into(),
            });
        }
    }
}

/// Read the DDL of one SQL file (or SQL string) into migration rows and foreign keys. Line numbers are relative to
/// `text`, offset by `line_base` (0 for a whole file).
pub fn parse_ddl(cx: &Ctx, text: &str) -> (Vec<Migration>, Vec<Fk>) {
    let toks = tokenize(text);
    let mut em = Em { cx, lines: Lines::new(text), mig: vec![], fks: vec![] };
    for st in statements(&toks) {
        stmt(&mut em, st, text);
    }
    (em.mig, em.fks)
}

fn stmt(em: &mut Em, st: &[Tok], text: &str) {
    let Some(first) = st.first() else { return };
    let w0 = upper(first);
    let off0 = first.off;
    match w0.as_str() {
        "CREATE" => create(em, st, text),
        "ALTER" => alter(em, st, text),
        "DO" => {
            // DO $$ BEGIN ... END $$: DDL inside is conditional (IF NOT EXISTS ...); read the simple statements
            if let Some(b) = st.iter().find(|t| t.tk == Tk::Body) {
                do_block(em, b.off, text);
            }
        }
        "DROP" => {
            let mut i = 1;
            let kind = upper(st.get(i).unwrap_or(first));
            if kind == "TABLE" {
                i += 1;
                if st.get(i).is_some_and(|t| t.is("IF")) {
                    i += 2;
                }
                for part in split_commas(&st[i..]) {
                    if let Some((n, _)) = qname(part, 0) {
                        em.m(off0, &n, "drop", "table", "", "drop table".into());
                    }
                }
            } else if kind == "INDEX" {
                // DROP INDEX [CONCURRENTLY] [IF EXISTS] a, b: the table is found from the CREATE INDEX of that name
                i += 1;
                if st.get(i).is_some_and(|t| t.is("CONCURRENTLY")) {
                    i += 1;
                }
                if st.get(i).is_some_and(|t| t.is("IF")) {
                    i += 2;
                }
                for part in split_commas(&st[i..]) {
                    if let Some((n, _)) = qname(part, 0) {
                        em.m(off0, "", "drop", "index", "", format!("drop index {n}"));
                    }
                }
            } else if matches!(kind.as_str(), "VIEW" | "FUNCTION" | "TRIGGER" | "MATERIALIZED") {
                let mut k = i + 1;
                if kind == "MATERIALIZED" {
                    k += 1;
                }
                if st.get(k).is_some_and(|t| t.is("IF")) {
                    k += 2;
                }
                if let Some((n, _)) = qname(st, k) {
                    let obj = if kind == "MATERIALIZED" { "view" } else { &kind.to_lowercase() };
                    em.m(off0, &n, "drop", obj, "", format!("drop {obj}"));
                }
            }
        }
        "INSERT" => {
            if let Some(k) = st.iter().position(|t| t.is("INTO")) {
                if let Some((n, _)) = qname(st, k + 1) {
                    em.m(off0, &n, "add", "data", "", "insert rows".into());
                }
            }
        }
        "UPDATE" => {
            if let Some((n, _)) = qname(st, 1) {
                em.m(off0, &n, "alter", "data", "", "update rows".into());
            }
        }
        "DELETE" => {
            if let Some(k) = st.iter().position(|t| t.is("FROM")) {
                if let Some((n, _)) = qname(st, k + 1) {
                    em.m(off0, &n, "drop", "data", "", "delete rows".into());
                }
            }
        }
        "TRUNCATE" => {
            let k = if st.get(1).is_some_and(|t| t.is("TABLE")) { 2 } else { 1 };
            if let Some((n, _)) = qname(st, k) {
                em.m(off0, &n, "drop", "data", "", "truncate".into());
            }
        }
        "RENAME" => {
            // MySQL: RENAME TABLE a TO b
            if st.get(1).is_some_and(|t| t.is("TABLE")) {
                if let (Some((a, i)), true) = (qname(st, 2), true) {
                    if st.get(i).is_some_and(|t| t.is("TO")) {
                        if let Some((b, _)) = qname(st, i + 1) {
                            em.m(off0, &a, "alter", "table", "", format!("rename to {b}"));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// The body of a `DO $tag$ ... $tag$` block: CREATE / ALTER / DROP statements of tables and indexes found in it, marked
/// conditional (they usually sit behind an IF [NOT] EXISTS).
fn do_block(em: &mut Em, off: usize, text: &str) {
    let rest = &text[off..];
    let Some(tl) = rest[1..].find('$') else { return };
    let tag = &rest[..tl + 2];
    let bstart = off + tag.len();
    let bend = text[bstart..].find(tag).map(|k| bstart + k).unwrap_or(text.len());
    let mut toks = tokenize(&text[bstart..bend]);
    for t in &mut toks {
        t.off += bstart;
    }
    for st in statements(&toks) {
        let Some(k) = st.iter().enumerate().position(|(k, t)| {
            matches!(upper(t).as_str(), "CREATE" | "DROP" | "ALTER")
                && (k == 0 || st[k - 1].is("THEN") || st[k - 1].is("BEGIN") || st[k - 1].is("ELSE") || st[k - 1].is("LOOP"))
                && {
                    let mut j = k + 1;
                    while st.get(j).is_some_and(|x| x.is("OR") || x.is("REPLACE") || x.is("UNIQUE") || x.is("TEMP") || x.is("TEMPORARY") || x.is("UNLOGGED")) {
                        j += 1;
                    }
                    matches!(upper_at(st, j).as_str(), "TABLE" | "INDEX")
                }
        }) else {
            continue;
        };
        let n0 = em.mig.len();
        stmt(em, &st[k..], text);
        for m in &mut em.mig[n0..] {
            m.detail.push_str(" (conditional, in DO block)");
        }
    }
}

fn create(em: &mut Em, st: &[Tok], text: &str) {
    let off0 = st[0].off;
    let mut i = 1;
    let mut unique = false;
    let mut or_replace = false;
    while i < st.len() {
        let w = upper(&st[i]);
        match w.as_str() {
            "OR" => or_replace = true,
            "REPLACE" | "GLOBAL" | "LOCAL" | "TEMP" | "TEMPORARY" | "UNLOGGED" | "MATERIALIZED" | "RECURSIVE" | "CONCURRENTLY" | "VIRTUAL" => {}
            "UNIQUE" => unique = true,
            _ => break,
        }
        i += 1;
    }
    let _ = or_replace;
    let kind = upper(st.get(i).unwrap_or(&st[0]));
    i += 1;
    match kind.as_str() {
        "TABLE" => {
            if st.get(i).is_some_and(|t| t.is("IF")) {
                i += 3;
            }
            let Some((tbl, j)) = qname(st, i) else { return };
            em.m(off0, &tbl, "create", "table", "", "create table".into());
            // CREATE TABLE x (LIKE y) / AS SELECT: no column list to read
            if !st.get(j).is_some_and(|t| t.p('(')) {
                return;
            }
            let mut depth = 0;
            let mut end = j;
            for (k, t) in st.iter().enumerate().skip(j) {
                match t.tk {
                    Tk::P('(') => depth += 1,
                    Tk::P(')') => {
                        depth -= 1;
                        if depth == 0 {
                            end = k;
                            break;
                        }
                    }
                    _ => {}
                }
                end = k;
            }
            for el in split_commas(&st[j + 1..end]) {
                table_element(em, &tbl, el, text);
            }
        }
        "INDEX" => {
            if st.get(i).is_some_and(|t| t.is("CONCURRENTLY")) {
                i += 1;
            }
            if st.get(i).is_some_and(|t| t.is("IF")) {
                i += 3;
            }
            let name = if st.get(i).is_some_and(|t| t.is("ON")) { String::new() } else { qname(st, i).map(|x| x.0).unwrap_or_default() };
            let Some(k) = st.iter().position(|t| t.is("ON")) else { return };
            let k = if st.get(k + 1).is_some_and(|t| t.is("ONLY")) { k + 2 } else { k + 1 };
            let Some((tbl, j)) = qname(st, k) else { return };
            let (cols, after) = index_cols(st, j, text);
            // partial index: keep the predicate
            let pred = st.iter().skip(after).position(|t| t.is("WHERE")).map(|p| after + p);
            let wh = match pred {
                Some(p) if p + 1 < st.len() => {
                    let s0 = st[p + 1].off;
                    let e0 = tok_end(st, st.len() - 1, text);
                    format!(" where {}", clip(&text[s0..e0.max(s0)], 70))
                }
                _ => String::new(),
            };
            em.m(off0, &tbl, "create", "index", &cols, format!("{}index {name}({cols}){wh}", if unique { "unique " } else { "" }));
        }
        "VIEW" => {
            if st.get(i).is_some_and(|t| t.is("IF")) {
                i += 3;
            }
            if let Some((n, _)) = qname(st, i) {
                em.m(off0, &n, if or_replace { "alter" } else { "create" }, "view", "", "view".into());
            }
        }
        "FUNCTION" | "PROCEDURE" => {
            if let Some((n, _)) = qname(st, i) {
                // the tables the body reads / writes ride in the detail ("function r:a,b w:c"), so a query calling the
                // function can be traced to them
                let mut detail = "function".to_string();
                if let Some(b) = st.iter().find(|t| t.tk == Tk::Body) {
                    let rest = &text[b.off..];
                    let tag_end = rest[1..].find('$').map(|k| k + 2).unwrap_or(0);
                    let body = if tag_end > 0 { rest[tag_end..].find(&rest[..tag_end]).map(|e| &rest[tag_end..tag_end + e]).unwrap_or("") } else { "" };
                    let me = n.to_lowercase();
                    let (mut r, mut w): (Vec<String>, Vec<String>) = (vec![], vec![]);
                    for (t, op) in table_ops(body, false) {
                        let t = t.to_lowercase();
                        if t == me || t.starts_with("_x_") || t.len() < 2 {
                            continue;
                        }
                        let v = if op == 'w' { &mut w } else { &mut r };
                        if !v.contains(&t) {
                            v.push(t);
                        }
                    }
                    if !r.is_empty() {
                        detail.push_str(&format!(" r:{}", r.join(",")));
                    }
                    if !w.is_empty() {
                        detail.push_str(&format!(" w:{}", w.join(",")));
                    }
                }
                em.m(off0, &n, if or_replace { "alter" } else { "create" }, "function", "", detail);
            }
        }
        "TRIGGER" => {
            if let Some((n, _)) = qname(st, i) {
                if let Some(k) = st.iter().position(|t| t.is("ON")) {
                    if let Some((tbl, _)) = qname(st, k + 1) {
                        em.m(off0, &tbl, "create", "trigger", "", format!("trigger {n}"));
                    }
                }
            }
        }
        _ => {}
    }
}

fn table_element(em: &mut Em, tbl: &str, el: &[Tok], text: &str) {
    let Some(f) = el.first() else { return };
    let off = f.off;
    let w = upper(f);
    let mut k = 0;
    let mut cname = String::new();
    if w == "CONSTRAINT" {
        k = 2;
        cname = el.get(1).and_then(|t| t.dname()).unwrap_or_default();
    }
    let named = if cname.is_empty() { String::new() } else { format!(" constraint {cname}") };
    let kw = el.get(k).map(upper).unwrap_or_default();
    match kw.as_str() {
        "PRIMARY" => {
            let (cols, _) = paren_names(el, k);
            em.m(off, tbl, "create", "constraint", &cols, format!("primary key({cols}){named}"));
        }
        "UNIQUE" if el.get(k + 1).is_none_or(|t| t.p('(') || t.is("KEY") || t.is("INDEX") || t.name().is_some()) => {
            let mut j = k + 1;
            if el.get(j).is_some_and(|t| t.is("KEY") || t.is("INDEX")) {
                j += 1;
            }
            let mut nm = cname.clone();
            if nm.is_empty() && el.get(j).is_some_and(|t| !t.p('(')) {
                nm = el.get(j).and_then(|t| t.dname()).unwrap_or_default();
            }
            let (cols, _) = paren_names(el, k);
            em.m(off, tbl, "create", "constraint", &cols, format!("unique({cols}){}", if nm.is_empty() { String::new() } else { format!(" constraint {nm}") }));
        }
        "FOREIGN" => {
            let (cols, j) = paren_names(el, k);
            if let Some(r) = el.iter().skip(j).position(|t| t.is("REFERENCES")) {
                let r = j + r;
                if let Some((to, i2)) = qname(el, r + 1) {
                    let (rc, _) = paren_names(el, i2);
                    em.m(off, tbl, "create", "constraint", &cols, format!("fk({cols}) -> {to}({rc}){named}"));
                    em.fk(off, tbl, &cols, &to, &rc);
                }
            }
        }
        "CHECK" => {
            let ex = paren_text(el, k, text, 80);
            em.m(off, tbl, "create", "constraint", "", format!("check {ex}{named}").replace("check  ", "check "));
        }
        "KEY" | "INDEX" | "FULLTEXT" | "SPATIAL" | "LIKE" | "EXCLUDE" | "PERIOD" if keyword_is_constraint(el, k) => {
            // MySQL `KEY name (cols)` / `INDEX name (cols)` are plain indexes; the rest are not tracked
            let j = k + usize::from(matches!(kw.as_str(), "FULLTEXT" | "SPATIAL"));
            if matches!(upper_at(el, j).as_str(), "KEY" | "INDEX") || matches!(kw.as_str(), "KEY" | "INDEX") {
                let jn = j + 1;
                let nm = el.get(jn).filter(|t| !t.p('(')).and_then(|t| t.dname()).unwrap_or_default();
                let (cols, _) = index_cols(el, jn, text);
                if !cols.is_empty() {
                    let pre = if matches!(kw.as_str(), "FULLTEXT" | "SPATIAL") { format!("{} ", kw.to_lowercase()) } else { String::new() };
                    em.m(off, tbl, "create", "index", &cols, format!("{pre}index {nm}({cols})"));
                }
            }
        }
        _ => {
            // column
            let Some(name) = f.dname() else { return };
            let rest = &el[1..];
            let (ty, used) = type_text(rest, text);
            let tail = &rest[used.min(rest.len())..];
            let up: Vec<String> = tail.iter().map(upper).collect();
            let has = |a: &str, b: &str| up.windows(2).any(|w| w[0] == a && w[1] == b);
            let pk = has("PRIMARY", "KEY");
            let not_null = has("NOT", "NULL") || pk;
            let mut d = ty.clone();
            if not_null {
                d.push_str(" not null");
            }
            if pk {
                d.push_str(" pk");
            }
            if up.iter().any(|x| x == "UNIQUE") {
                d.push_str(" unique");
            }
            if let Some(p) = up.iter().position(|x| x == "DEFAULT") {
                let mut depth = 0;
                let mut e = p + 1;
                while e < tail.len() {
                    if depth == 0 && e > p + 1 && COL_STOP.contains(&up[e].as_str()) {
                        break;
                    }
                    match tail[e].tk {
                        Tk::P('(') => depth += 1,
                        Tk::P(')') => depth -= 1,
                        _ => {}
                    }
                    e += 1;
                }
                if e > p + 1 {
                    let raw = &text[tail[p + 1].off..tok_end(tail, e - 1, text)];
                    d.push_str(&format!(" default {}", safe_default(&name, raw)));
                }
            }
            em.m(off, tbl, "create", "column", &name, clip(&d, 120));
            if let Some(r) = up.iter().position(|x| x == "REFERENCES") {
                if let Some((to, i2)) = qname(tail, r + 1) {
                    let (rc, _) = if tail.get(i2).is_some_and(|t| t.p('(')) { paren_names(tail, i2) } else { (String::new(), i2) };
                    em.fk(off, tbl, &name, &to, &rc);
                }
            }
        }
    }
}

fn upper_at(el: &[Tok], i: usize) -> String {
    el.get(i).map(upper).unwrap_or_default()
}

/// Is a table element that starts with one of the bare words KEY / INDEX / FULLTEXT / SPATIAL / LIKE / EXCLUDE / PERIOD
/// really that constraint, rather than a column that happens to be called that (`period text`, `key varchar(20)`)?
fn keyword_is_constraint(el: &[Tok], k: usize) -> bool {
    const TYPES: &[&str] = &[
        "TEXT", "INT", "INTEGER", "BIGINT", "SMALLINT", "VARCHAR", "CHAR", "CHARACTER", "BOOLEAN", "BOOL", "DATE", "TIME", "TIMESTAMP", "TIMESTAMPTZ", "NUMERIC", "DECIMAL",
        "FLOAT", "DOUBLE", "REAL", "UUID", "JSON", "JSONB", "BLOB", "BYTEA", "SERIAL", "BIGSERIAL", "TINYINT", "MEDIUMINT", "DATETIME", "INTERVAL", "TSRANGE", "DATERANGE", "TSTZRANGE", "ENUM", "STRING", "NVARCHAR",
        "LONGTEXT", "MEDIUMTEXT", "BIT", "MONEY", "VARBINARY", "BINARY", "CITEXT", "INET", "XML",
    ];
    let kw = upper_at(el, k);
    let n1 = el.get(k + 1);
    match kw.as_str() {
        "KEY" | "INDEX" => match n1 {
            Some(t) if t.p('(') => el.get(k + 2).is_some_and(|x| x.tk != Tk::Num),
            Some(t) if t.name().is_some() && !TYPES.contains(&upper(t).as_str()) => el.get(k + 2).is_some_and(|x| x.p('(') || x.is("USING")),
            _ => false,
        },
        "FULLTEXT" | "SPATIAL" => n1.is_some_and(|t| t.is("KEY") || t.is("INDEX") || t.p('(')),
        "LIKE" => n1.is_some_and(|t| t.name().is_some() && !TYPES.contains(&upper(t).as_str())) && el.get(k + 2).is_none_or(|t| t.is("INCLUDING") || t.is("EXCLUDING")),
        "EXCLUDE" => n1.is_some_and(|t| t.is("USING") || t.p('(')),
        "PERIOD" => n1.is_some_and(|t| t.is("FOR")),
        _ => false,
    }
}

fn alter(em: &mut Em, st: &[Tok], text: &str) {
    let off0 = st[0].off;
    let kind = upper(st.get(1).unwrap_or(&st[0]));
    if kind != "TABLE" {
        return;
    }
    let mut i = 2;
    if st.get(i).is_some_and(|t| t.is("IF")) {
        i += 2;
    }
    if st.get(i).is_some_and(|t| t.is("ONLY")) {
        i += 1;
    }
    let Some((tbl, j)) = qname(st, i) else { return };
    for a in split_commas(&st[j..]) {
        action(em, &tbl, a, off0, text);
    }
}

fn action(em: &mut Em, tbl: &str, a: &[Tok], off0: usize, text: &str) {
    let Some(f) = a.first() else { return };
    let w = upper(f);
    let skip_if = |mut k: usize, words: &[&str]| -> usize {
        if a.get(k).is_some_and(|t| t.is(words[0])) {
            k += words.len();
        }
        k
    };
    match w.as_str() {
        "ADD" => {
            let mut k = 1;
            let nxt = a.get(k).map(upper).unwrap_or_default();
            let is_constraint = matches!(nxt.as_str(), "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "FOREIGN" | "CHECK" | "EXCLUDE")
                && !(nxt == "UNIQUE" && a.get(k + 1).is_some_and(|t| t.is("COLUMN")));
            if is_constraint {
                // reuse the CREATE TABLE element reader, then relabel as an add
                let n0 = em.mig.len();
                let f0 = em.fks.len();
                table_element(em, tbl, &a[k..], text);
                for m in &mut em.mig[n0..] {
                    m.op = "add".into();
                    m.line = em.lines.at(off0);
                }
                for x in &mut em.fks[f0..] {
                    x.line = em.lines.at(off0);
                }
                return;
            }
            if nxt == "COLUMN" {
                k += 1;
            }
            k = skip_if(k, &["IF", "NOT", "EXISTS"]);
            let n0 = em.mig.len();
            let f0 = em.fks.len();
            table_element(em, tbl, &a[k..], text);
            for m in &mut em.mig[n0..] {
                m.op = "add".into();
                m.line = em.lines.at(off0);
            }
            for x in &mut em.fks[f0..] {
                x.line = em.lines.at(off0);
            }
        }
        "DROP" => {
            let nxt = a.get(1).map(upper).unwrap_or_default();
            if nxt == "CONSTRAINT" {
                let k = skip_if(2, &["IF", "EXISTS"]);
                let n = a.get(k).and_then(|t| t.dname()).unwrap_or_default();
                em.m(off0, tbl, "drop", "constraint", "", format!("drop constraint {n}"));
            } else if nxt == "INDEX" || nxt == "KEY" {
                let n = a.get(2).and_then(|t| t.dname()).unwrap_or_default();
                em.m(off0, tbl, "drop", "index", "", format!("drop index {n}"));
            } else if nxt == "PRIMARY" || nxt == "FOREIGN" {
                let n = if nxt == "FOREIGN" { a.get(3).and_then(|t| t.dname()).unwrap_or_default() } else { String::new() };
                em.m(off0, tbl, "drop", "constraint", "", format!("drop {}{}", nxt.to_lowercase(), if n.is_empty() { String::new() } else { format!(" key {n}") }));
            } else {
                let mut k = 1;
                if nxt == "COLUMN" {
                    k += 1;
                }
                k = skip_if(k, &["IF", "EXISTS"]);
                if let Some(c) = a.get(k).and_then(|t| t.dname()) {
                    em.m(off0, tbl, "drop", "column", &c, "drop column".into());
                }
            }
        }
        "ALTER" | "MODIFY" | "CHANGE" => {
            let mut k = 1;
            if a.get(k).is_some_and(|t| t.is("COLUMN")) {
                k += 1;
            }
            let Some(c) = a.get(k).and_then(|t| t.dname()) else { return };
            let rest: Vec<String> = a[k + 1..].iter().map(upper).collect();
            let detail = if w != "ALTER" {
                let (ty, _) = type_text(&a[k + 1..], text);
                format!("{} {ty}", w.to_lowercase())
            } else if rest.windows(2).any(|x| x[0] == "SET" && x[1] == "DATA") || rest.first().is_some_and(|x| x == "TYPE") {
                let p = a.iter().position(|t| t.is("TYPE")).unwrap_or(k + 1);
                let (ty, _) = type_text(&a[(p + 1).min(a.len())..], text);
                format!("type {}", clip(&ty, 60))
            } else if rest.windows(2).any(|x| x[0] == "SET" && x[1] == "NOT") {
                "set not null".into()
            } else if rest.windows(2).any(|x| x[0] == "DROP" && x[1] == "NOT") {
                "drop not null".into()
            } else if rest.windows(2).any(|x| x[0] == "SET" && x[1] == "DEFAULT") {
                "set default".into()
            } else if rest.windows(2).any(|x| x[0] == "DROP" && x[1] == "DEFAULT") {
                "drop default".into()
            } else {
                clip(&rest.join(" ").to_lowercase(), 40)
            };
            em.m(off0, tbl, "alter", "column", &c, detail);
        }
        "RENAME" => {
            let nxt = a.get(1).map(upper).unwrap_or_default();
            if nxt == "COLUMN" {
                let from = a.get(2).and_then(|t| t.dname()).unwrap_or_default();
                let to = a.get(4).and_then(|t| t.dname()).unwrap_or_default();
                em.m(off0, tbl, "alter", "column", &from, format!("rename to {to}"));
            } else if nxt == "TO" {
                let to = a.get(2).and_then(|t| t.dname()).unwrap_or_default();
                em.m(off0, tbl, "alter", "table", "", format!("rename to {to}"));
            }
        }
        _ => {}
    }
}

/// Tables a SQL string reads / writes: (name as written without schema, 'r' | 'w'). `jpql`: identifiers are entity
/// names and `alias.path` joins are skipped.
pub fn table_ops(sql: &str, jpql: bool) -> Vec<(String, char)> {
    let toks = tokenize(sql);
    let mut ctes: Vec<String> = vec![];
    for (i, t) in toks.iter().enumerate() {
        if t.is("AS") && toks.get(i + 1).is_some_and(|x| x.p('(')) && i > 0 {
            if let Some(n) = toks[i - 1].name() {
                ctes.push(n.to_lowercase());
            } else if toks[i - 1].p(')') {
                // WITH x (a, b) AS (
                let mut d = 0;
                let mut j = i - 1;
                loop {
                    match toks[j].tk {
                        Tk::P(')') => d += 1,
                        Tk::P('(') => {
                            d -= 1;
                            if d == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    if j == 0 {
                        break;
                    }
                    j -= 1;
                }
                if j > 0 {
                    if let Some(n) = toks[j - 1].name() {
                        ctes.push(n.to_lowercase());
                    }
                }
            }
        }
    }
    const STOP: &[&str] = &[
        "WHERE", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "FULL", "ON", "GROUP", "ORDER", "LIMIT", "UNION", "USING", "SET",
        "HAVING", "WINDOW", "FETCH", "FOR", "OFFSET", "RETURNING", "NATURAL", "SELECT", "VALUES", "LATERAL", "EXCEPT", "INTERSECT", "AS",
        "ONLY", "WITH", "WHEN", "THEN", "ELSE", "END", "AND", "OR", "NOT", "IN", "IS", "NULL", "ALL", "DISTINCT", "TABLESAMPLE", "OF",
        "NOWAIT", "SKIP", "FROM", "INTO", "STRAIGHT_JOIN",
    ];
    let is_stop = |t: &Tok| {
        matches!(&t.tk, Tk::Word(w) if STOP.contains(&w.to_uppercase().as_str())
            // JPQL entity names are CamelCase (Order, Group): a keyword is all lower or all upper case
            && !(jpql && w.chars().next().is_some_and(|c| c.is_uppercase()) && *w != w.to_uppercase()))
    };
    let mut out: Vec<(String, char)> = vec![];
    let mut add = |name: String, schema: Option<String>, op: char| {
        let l = name.to_lowercase();
        if ctes.contains(&l) || name.is_empty() || name.contains('{') || name.contains('%') {
            return;
        }
        if let Some(s) = schema {
            let s = s.to_lowercase();
            if s == "information_schema" || s == "pg_catalog" || s == "sys" {
                return;
            }
        }
        let n = if jpql { name } else { l };
        if !out.iter().any(|(a, b)| *a == n && *b == op) {
            out.push((n, op));
        }
    };
    // one table reference at i: (name, schema, next index)
    let table_ref = |i: usize, allow_paren: bool| -> Option<(String, Option<String>, usize)> {
        let t = toks.get(i)?;
        if is_stop(t) && !t.is("ONLY") {
            return None;
        }
        let mut i = i;
        if t.is("ONLY") {
            i += 1;
        }
        let first = toks.get(i)?.name()?;
        let mut parts = vec![first];
        let mut j = i + 1;
        while toks.get(j).is_some_and(|x| x.p('.')) {
            match toks.get(j + 1).and_then(|x| x.name()) {
                Some(n) => parts.push(n),
                None => break,
            }
            j += 2;
        }
        if !allow_paren && toks.get(j).is_some_and(|x| x.p('(')) {
            return None; // function call
        }
        if jpql && parts.len() > 1 {
            return None; // alias.path join
        }
        let name = parts.pop()?;
        Some((name, parts.pop(), j))
    };
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        let prev = if i > 0 { Some(&toks[i - 1]) } else { None };
        if t.is("FROM") || t.is("JOIN") {
            let write = t.is("FROM") && prev.is_some_and(|p| p.is("DELETE"));
            let mut k = i + 1;
            while let Some((n, s, mut j)) = table_ref(k, false) {
                add(n, s, if write { 'w' } else { 'r' });
                // alias
                if toks.get(j).is_some_and(|x| x.is("AS")) {
                    j += 1;
                }
                if toks.get(j).is_some_and(|x| x.name().is_some() && !is_stop(x)) {
                    j += 1;
                }
                if t.is("FROM") && toks.get(j).is_some_and(|x| x.p(',')) {
                    k = j + 1;
                    continue;
                }
                break;
            }
        } else if t.is("INTO") && prev.is_some_and(|p| p.is("INSERT") || p.is("MERGE") || p.is("REPLACE")) {
            if let Some((n, s, _)) = table_ref(i + 1, true) {
                add(n, s, 'w');
            }
        } else if t.is("UPDATE") && !prev.is_some_and(|p| p.is("FOR") || p.is("DO")) {
            if let Some((n, s, j)) = table_ref(i + 1, false) {
                let nx = toks.get(j);
                let alias_set = toks.get(j + 1).is_some_and(|x| x.is("SET")) || toks.get(j + 2).is_some_and(|x| x.is("SET"));
                if nx.is_some_and(|x| x.is("SET")) || alias_set || jpql {
                    add(n, s, 'w');
                }
            }
        } else if t.is("TRUNCATE") {
            let k = if toks.get(i + 1).is_some_and(|x| x.is("TABLE")) { i + 2 } else { i + 1 };
            if let Some((n, s, _)) = table_ref(k, false) {
                add(n, s, 'w');
            }
        } else if t.is("DELETE") && !toks.get(i + 1).is_some_and(|x| x.is("FROM")) && jpql {
            if let Some((n, s, _)) = table_ref(i + 1, false) {
                add(n, s, 'w');
            }
        }
        i += 1;
    }
    out
}

/// Does a string literal look like a SQL / JPQL statement (not prose that starts with "update")?
pub fn looks_like_sql(s: &str) -> bool {
    let t = s.trim_start_matches(|c: char| c.is_whitespace() || c == '(');
    if t.len() < 12 {
        return false;
    }
    let l: String = t.chars().take(400).collect::<String>().to_lowercase();
    let words: Vec<&str> = l.split_whitespace().take(6).collect();
    let has = |w: &str| l.split(|c: char| !c.is_alphanumeric() && c != '_').any(|x| x == w);
    match words.first().copied().unwrap_or("") {
        "select" => has("from") && !l.starts_with("select an ") && !l.starts_with("select a "),
        "insert" => words.get(1) == Some(&"into") || words.get(1) == Some(&"ignore"),
        "update" => words.len() > 2 && has("set"),
        "delete" => words.get(1) == Some(&"from"),
        "with" => has("as") && has("select"),
        "merge" => words.get(1) == Some(&"into"),
        "truncate" => true,
        "from" => true, // HQL shorthand: "from Entity where ..."
        "replace" => words.get(1) == Some(&"into"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ddl(t: &str) -> (Vec<Migration>, Vec<Fk>) {
        parse_ddl(&Ctx { file: "V1__x.sql", version: "1", tool: "flyway" }, t)
    }

    #[test]
    fn create_alter_drop() {
        let (m, f) = ddl(
            "-- c\nCREATE TABLE public.orders (\n  id character varying(26) DEFAULT gen() NOT NULL,\n  user_id text REFERENCES users(id),\n  note text,\n  CONSTRAINT ok UNIQUE (user_id, note)\n);\n\
             ALTER TABLE ONLY public.orders\n  ADD CONSTRAINT fk1 FOREIGN KEY (note) REFERENCES public.notes(id);\n\
             ALTER TABLE orders ADD COLUMN IF NOT EXISTS total numeric(10,2) NOT NULL, DROP COLUMN note;\n\
             ALTER TABLE orders ALTER COLUMN total TYPE bigint;\nCREATE UNIQUE INDEX CONCURRENTLY i1 ON orders USING btree (user_id);\nDROP TABLE IF EXISTS tmp1, tmp2;\n\
             CREATE OR REPLACE FUNCTION f() RETURNS int AS $$ BEGIN; SELECT 1; END; $$ LANGUAGE sql;\nINSERT INTO orders VALUES (1);",
        );
        let find = |op: &str, obj: &str, col: &str| m.iter().find(|x| x.op == op && x.obj == obj && x.column == col).unwrap_or_else(|| panic!("{op} {obj} {col}: {m:#?}"));
        assert_eq!(find("create", "table", "").line, 2);
        let id = find("create", "column", "id");
        assert_eq!((id.line, id.detail.as_str()), (3, "character varying(26) not null default gen()"));
        assert_eq!(find("create", "column", "user_id").line, 4);
        assert_eq!(find("create", "constraint", "user_id,note").detail, "unique(user_id,note) constraint ok");
        let fk = find("add", "constraint", "note");
        assert_eq!((fk.line, fk.detail.as_str()), (8, "fk(note) -> notes(id) constraint fk1"));
        assert_eq!(find("add", "column", "total").line, 10);
        assert_eq!(find("drop", "column", "note").line, 10);
        assert_eq!(find("alter", "column", "total").detail, "type bigint");
        assert_eq!(find("create", "index", "user_id").detail, "unique index i1(user_id)");
        assert_eq!(m.iter().filter(|x| x.op == "drop" && x.obj == "table").count(), 2);
        // the function body (inside $$) is not parsed as statements
        assert_eq!(m.iter().filter(|x| x.obj == "function").count(), 1);
        assert!(m.iter().any(|x| x.obj == "data" && x.table == "orders"));
        assert!(f.iter().any(|x| x.from_table == "orders" && x.from_col == "user_id" && x.to_table == "users" && x.to_col == "id"));
        assert!(f.iter().any(|x| x.from_col == "note" && x.to_table == "notes" && x.line == 8));
    }

    #[test]
    fn credentials_keywords_indexes_do_blocks() {
        let (m, _) = ddl(
            "/* a /* nested */ still */ CREATE TABLE u (id int, api_key text DEFAULT 'sk-live-abcdef', status text DEFAULT 'ACTIVE', period text, key text,\n\
             note text DEFAULT 'a long free text default that is no enum', \"Mixed Case\" int, CONSTRAINT c1 CHECK (id > 0));\n\
             CREATE INDEX i1 ON u (lower(note), status);\nCREATE UNIQUE INDEX i2 ON u (id) WHERE id > 5;\n\
             DO $$ BEGIN IF NOT EXISTS (SELECT 1) THEN CREATE INDEX i3 ON u (status); END IF; DROP INDEX i1; END $$;",
        );
        let d = |c: &str| m.iter().find(|x| x.obj == "column" && x.column == c).unwrap_or_else(|| panic!("{c}: {m:#?}")).detail.clone();
        assert!(d("api_key").contains("<redacted>") && !d("api_key").contains("sk-live"));
        assert_eq!(d("status"), "text default 'ACTIVE'");
        assert!(d("note").contains("<literal>"));
        d("period");
        d("key");
        d("\"Mixed Case\"");
        assert!(m.iter().any(|x| x.obj == "index" && x.detail == "index i1(lower(note),status)"));
        assert!(m.iter().any(|x| x.obj == "index" && x.detail == "unique index i2(id) where id > 5"));
        assert!(m.iter().any(|x| x.obj == "index" && x.detail == "index i3(status) (conditional, in DO block)"));
        assert!(m.iter().any(|x| x.op == "drop" && x.obj == "index" && x.detail.starts_with("drop index i1")));
        assert!(m.iter().any(|x| x.detail == "check id > 0 constraint c1"));
    }

    #[test]
    fn ops_in_code_strings() {
        let o = table_ops("SELECT a.x FROM public.orders a, items i JOIN users u ON u.id=a.uid WHERE a.n IN (SELECT n FROM tags t)", false);
        let names: Vec<_> = o.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(names, vec!["orders", "items", "users", "tags"]);
        let o = table_ops("WITH x AS (SELECT * FROM src) INSERT INTO dst SELECT * FROM x; UPDATE t1 SET a=1; DELETE FROM t2 WHERE 1=1", false);
        assert!(o.contains(&("dst".to_string(), 'w')) && o.contains(&("src".to_string(), 'r')) && o.contains(&("t1".to_string(), 'w')) && o.contains(&("t2".to_string(), 'w')));
        assert!(!o.iter().any(|x| x.0 == "x"));
        let o = table_ops("INSERT INTO scores (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2", false);
        assert_eq!(o, vec![("scores".to_string(), 'w')]);
        let o = table_ops("select o from Order o join o.items i where o.id = :id", true);
        assert_eq!(o, vec![("Order".to_string(), 'r')]);
        assert!(looks_like_sql("SELECT id FROM users WHERE x=1"));
        assert!(!looks_like_sql("Update your profile to continue using the app"));
        assert!(looks_like_sql("UPDATE users SET a = 1"));
    }
}
