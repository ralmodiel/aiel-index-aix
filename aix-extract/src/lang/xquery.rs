//! XQuery / MarkLogic XQuery (`.xqy .xq .xqm .xql .xquery .xqe`): a hand-made lexical scanner (there is no maintained
//! tree-sitter grammar on crates.io). Comments `(: (: nested :) :)`, string literals with doubled quotes, string
//! constructors, pragmas and the text of direct XML constructors are skipped; enclosed expressions `{ … }` inside
//! constructors and attribute values are code again (`{{` / `}}` are literal braces).
//!
//! Rows: the module itself (a `module` member spanning the file; `module namespace p = "uri"` makes it a library
//! module), `declare function` (exact line range up to the closing `};`, arity in the signature, `%private` / `private`
//! as visibility, other `%annotations` kept) and `declare variable` (fields). Prefixed calls `p:f(a, b)` carry the
//! namespace URI the prefix is bound to in this file as the receiver type, so the resolver can tell same-named
//! functions of different modules apart and pick the overload by arity; `local:` calls stay in the file; named
//! function references `p:f#2` are uses; built-in prefixes (`fn`, `xs`, `xdmp`, `cts`, `map`, …) are library names.
//! `import module namespace p = "uri" at "a.xqy", "b.xqy";` gives one `import` ref per location (callee = URI,
//! receiver = location, receiver type = prefix). `xdmp:invoke("/m.xqy")` / `xdmp:spawn("/m.xqy")` with a literal
//! path are call edges to that module (receiver type `xqmod:<path>`); `xdmp:eval` text is not followed (a note says so).

use std::collections::HashMap;

use crate::codegraph::{Member, Ref};
use crate::model::*;

pub const EXTS: &[&str] = &["xqy", "xq", "xqm", "xql", "xquery", "xqe"];

/// Namespace of `local:` functions.
pub const LOCAL_NS: &str = "http://www.w3.org/2005/xquery-local-functions";
/// Receiver-type marker of a module invoked by path (`xdmp:invoke("/a.xqy")`).
pub const MOD_PREFIX: &str = "xqmod:";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum K {
    /// NCName or prefixed QName (`p:name`, `Q{uri}name`, `p:*`).
    Name,
    /// `$name` / `$p:name` (text without the `$`).
    Var,
    /// String literal (text = value, doubled quotes undone).
    Str,
    Num,
    /// A direct XML constructor (`<a>…</a>`, comment, CDATA, PI): one operand, its text is not code.
    Xml,
    /// Punctuation / operator (text = the characters).
    P,
}

#[derive(Clone, Debug)]
pub struct Tok {
    pub k: K,
    pub s: String,
    pub pos: usize,
    pub end: usize,
}

impl Tok {
    fn is_p(&self, p: &str) -> bool {
        self.k == K::P && self.s == p
    }
    fn is_name(&self, n: &str) -> bool {
        self.k == K::Name && self.s == n
    }
}

/// The code tokens of a file (comments, strings' contents and XML text are not code) and its line starts.
pub struct Lexed {
    pub toks: Vec<Tok>,
    starts: Vec<usize>,
}

impl Lexed {
    pub fn line(&self, pos: usize) -> u32 {
        self.starts.partition_point(|&s| s <= pos) as u32
    }
}

/// Keywords after which an operand (so a direct constructor `<a>`) may follow.
const OPERAND_KW: &[&str] = &[
    "return", "then", "else", "in", "satisfies", "and", "or", "div", "idiv", "mod", "to", "eq", "ne", "lt", "le", "gt", "ge", "is",
    "union", "intersect", "except", "at", "default", "case", "where", "by", "collation", "count", "allowing", "with", "into", "of",
    "insert", "node", "nodes", "replace", "value", "delete", "rename", "as", "after", "before", "first", "last", "modify", "copy",
];

/// Names that are followed by `(` without being a function call (keywords, kind tests, inline functions).
const NOT_CALLS: &[&str] = &[
    "if", "then", "else", "return", "typeswitch", "switch", "case", "default", "try", "catch", "in", "satisfies", "where", "and", "or",
    "to", "div", "idiv", "mod", "eq", "ne", "lt", "le", "gt", "ge", "is", "union", "intersect", "except", "instance", "of", "treat",
    "as", "castable", "cast", "at", "let", "for", "order", "by", "some", "every", "element", "attribute", "text", "node", "comment",
    "document", "document-node", "processing-instruction", "schema-element", "schema-attribute", "namespace-node", "item",
    "empty-sequence", "function", "map", "array", "ordered", "unordered", "validate", "namespace", "declare", "import", "module",
    "xquery", "variable", "ascending", "descending", "stable", "group", "while", "external", "binary", "object-node",
    "array-node", "number-node", "boolean-node", "null-node",
];

/// Sequence-type keywords: a `name(` after them is a type, not a call.
const TYPE_INTRO: &[&str] = &["as", "of"];

fn name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c >= 0x80
}
fn name_char(c: u8) -> bool {
    name_start(c) || c.is_ascii_digit() || c == b'-' || c == b'.'
}

const MAX_NEST: u32 = 400;

struct Lexer<'a> {
    b: &'a [u8],
    src: &'a str,
    i: usize,
    toks: Vec<Tok>,
}

impl<'a> Lexer<'a> {
    fn at(&self, s: &str) -> bool {
        self.b[self.i..].starts_with(s.as_bytes())
    }
    fn peek(&self, k: usize) -> u8 {
        *self.b.get(self.i + k).unwrap_or(&0)
    }
    fn push(&mut self, k: K, s: String, pos: usize) {
        self.toks.push(Tok { k, s, pos, end: self.i });
    }
    fn skip_to(&mut self, end: &str) {
        match self.src.get(self.i..).and_then(|r| r.find(end)) {
            Some(k) => self.i += k + end.len(),
            None => self.i = self.b.len(),
        }
    }
    /// `(: … :)` with nesting.
    fn comment(&mut self) {
        let mut d = 0i32;
        while self.i < self.b.len() {
            if self.at("(:") {
                d += 1;
                self.i += 2;
            } else if self.at(":)") {
                d -= 1;
                self.i += 2;
                if d == 0 {
                    return;
                }
            } else {
                self.i += 1;
            }
        }
    }
    fn ncname(&mut self) {
        while self.i < self.b.len() && name_char(self.b[self.i]) {
            self.i += 1;
        }
        // a name does not end with `.` (`$x.` is rare, `a.` before an operator is not)
        while self.i > 0 && self.b[self.i - 1] == b'.' && self.i < self.b.len() && !name_start(self.b[self.i]) {
            self.i -= 1;
        }
    }
    /// QName at `i` (a name start): `n`, `p:n`, `p:*`, `Q{uri}n`.
    fn qname(&mut self) -> String {
        let s = self.i;
        if self.at("Q{") {
            self.skip_to("}");
            self.ncname();
            return self.src[s..self.i].to_string();
        }
        self.ncname();
        if self.peek(0) == b':' && (name_start(self.peek(1)) || self.peek(1) == b'*') {
            self.i += 1;
            if self.peek(0) == b'*' {
                self.i += 1;
            } else {
                self.ncname();
            }
        }
        self.src[s..self.i].to_string()
    }
    fn string(&mut self) -> String {
        let q = self.b[self.i];
        self.i += 1;
        let s = self.i;
        let mut out = String::new();
        let mut from = s;
        while self.i < self.b.len() {
            if self.b[self.i] == q {
                if self.peek(1) == q {
                    out.push_str(&self.src[from..=self.i]);
                    self.i += 2;
                    from = self.i;
                    continue;
                }
                out.push_str(&self.src[from..self.i]);
                self.i += 1;
                return out;
            }
            self.i += 1;
        }
        out.push_str(&self.src[from..self.i]);
        out
    }
    /// Can a direct constructor start here (the previous token does not end an operand)?
    fn operand_expected(&self) -> bool {
        match self.toks.last() {
            None => true,
            Some(t) => match t.k {
                K::Var | K::Str | K::Num | K::Xml => false,
                K::P => !matches!(t.s.as_str(), ")" | "]" | "}" | "?" | "*" | "."),
                K::Name => OPERAND_KW.contains(&t.s.as_str()),
            },
        }
    }
    /// Expression tokens up to the end, or (enclosed) up to the `}` that closes the enclosed expression.
    fn expr(&mut self, enclosed: bool, lvl: u32) {
        let mut depth = 0i32;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            let pos = self.i;
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.i += 1,
                b'(' if self.peek(1) == b':' => self.comment(),
                b'(' if self.peek(1) == b'#' => self.skip_to("#)"),
                b'"' | b'\'' => {
                    let s = self.string();
                    self.push(K::Str, s, pos);
                }
                b'`' if self.at("``[") => {
                    // string constructor: text with `{ expr }` interpolations
                    self.i += 3;
                    while self.i < self.b.len() && !self.at("]``") {
                        if self.at("`{") && lvl < MAX_NEST {
                            self.i += 2;
                            self.expr(true, lvl + 1);
                            if self.peek(0) == b'`' {
                                self.i += 1;
                            }
                        } else {
                            self.i += 1;
                        }
                    }
                    self.i = (self.i + 3).min(self.b.len());
                    self.push(K::Str, String::new(), pos);
                }
                b'{' => {
                    depth += 1;
                    self.i += 1;
                    self.push(K::P, "{".into(), pos);
                }
                b'}' => {
                    self.i += 1;
                    if enclosed && depth == 0 {
                        return;
                    }
                    depth -= 1;
                    self.push(K::P, "}".into(), pos);
                }
                b'<' if lvl < MAX_NEST && self.operand_expected() && (name_start(self.peek(1)) || self.peek(1) == b'!' || self.peek(1) == b'?') => {
                    if self.xml(lvl + 1) {
                        self.push(K::Xml, String::new(), pos);
                    } else {
                        self.i = pos + 1;
                        self.push(K::P, "<".into(), pos);
                    }
                }
                b'$' => {
                    self.i += 1;
                    while matches!(self.peek(0), b' ' | b'\t' | b'\r' | b'\n') {
                        self.i += 1;
                    }
                    if name_start(self.peek(0)) {
                        let n = self.qname();
                        self.push(K::Var, n, pos);
                    } else {
                        self.push(K::P, "$".into(), pos);
                    }
                }
                c if name_start(c) => {
                    let n = self.qname();
                    self.push(K::Name, n, pos);
                }
                c if c.is_ascii_digit() || (c == b'.' && self.peek(1).is_ascii_digit()) => {
                    while self.i < self.b.len() && (self.b[self.i].is_ascii_alphanumeric() || self.b[self.i] == b'.') {
                        self.i += 1;
                    }
                    let n = self.src[pos..self.i].to_string();
                    self.push(K::Num, n, pos);
                }
                b'=' if self.peek(1) == b'>' => {
                    // arrow operator: `$x => f(a)` passes `$x` as the first argument
                    self.i += 2;
                    self.push(K::P, "=>".into(), pos);
                }
                b':' if matches!(self.peek(1), b'=' | b':') => {
                    self.i += 2;
                    let s = self.src[pos..self.i].to_string();
                    self.push(K::P, s, pos);
                }
                _ => {
                    // one character (UTF-8 safe)
                    let ch = self.src[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                    self.i += ch;
                    let s = self.src[pos..self.i].to_string();
                    self.push(K::P, s, pos);
                }
            }
        }
    }
    /// A direct constructor at `<`: element (with attributes and content), comment, CDATA or processing instruction.
    /// False (nothing consumed, no tokens kept) when what follows `<name` is not a start tag.
    fn xml(&mut self, lvl: u32) -> bool {
        if self.at("<!--") {
            self.skip_to("-->");
            return true;
        }
        if self.at("<![CDATA[") {
            self.skip_to("]]>");
            return true;
        }
        if self.at("<?") {
            self.skip_to("?>");
            return true;
        }
        if self.at("<!") {
            return false;
        }
        let (start, ntok) = (self.i, self.toks.len());
        self.i += 1;
        self.qname();
        // attributes
        loop {
            let ws0 = self.i;
            while matches!(self.peek(0), b' ' | b'\t' | b'\r' | b'\n') {
                self.i += 1;
            }
            if self.at("/>") {
                self.i += 2;
                return true;
            }
            if self.peek(0) == b'>' {
                self.i += 1;
                break;
            }
            if !name_start(self.peek(0)) || self.i == ws0 {
                // `<a` followed by something that is not an attribute: a comparison after all
                self.i = start;
                self.toks.truncate(ntok);
                return false;
            }
            self.qname();
            while matches!(self.peek(0), b' ' | b'\t' | b'\r' | b'\n') {
                self.i += 1;
            }
            if self.peek(0) != b'=' {
                self.i = start;
                self.toks.truncate(ntok);
                return false;
            }
            self.i += 1;
            while matches!(self.peek(0), b' ' | b'\t' | b'\r' | b'\n') {
                self.i += 1;
            }
            let q = self.peek(0);
            if q != b'"' && q != b'\'' {
                self.i = start;
                self.toks.truncate(ntok);
                return false;
            }
            self.i += 1;
            while self.i < self.b.len() {
                let c = self.b[self.i];
                if c == q {
                    if self.peek(1) == q {
                        self.i += 2;
                        continue;
                    }
                    self.i += 1;
                    break;
                }
                if c == b'{' {
                    if self.peek(1) == b'{' {
                        self.i += 2;
                    } else {
                        self.i += 1;
                        self.expr(true, lvl + 1);
                    }
                    continue;
                }
                if c == b'}' && self.peek(1) == b'}' {
                    self.i += 2;
                    continue;
                }
                self.i += 1;
            }
        }
        // content
        while self.i < self.b.len() {
            if self.at("</") {
                self.skip_to(">");
                return true;
            }
            if self.peek(0) == b'<' {
                if lvl >= MAX_NEST || !self.xml(lvl + 1) {
                    self.i += 1;
                }
                continue;
            }
            if self.at("{{") || self.at("}}") {
                self.i += 2;
                continue;
            }
            if self.peek(0) == b'{' {
                self.i += 1;
                self.expr(true, lvl + 1);
                continue;
            }
            self.i += 1;
        }
        true
    }
}

pub fn lex(text: &str) -> Lexed {
    let mut l = Lexer { b: text.as_bytes(), src: text, i: 0, toks: vec![] };
    l.expr(false, 0);
    let mut starts = vec![0usize];
    starts.extend(text.bytes().enumerate().filter(|(_, c)| *c == b'\n').map(|(i, _)| i + 1));
    Lexed { toks: l.toks, starts }
}

/// Index of the token closing the bracket opened at `open` (`(` / `{` / `[`), or the last token.
pub fn close_of(t: &[Tok], open: usize) -> usize {
    let mut d = 0i32;
    for (k, x) in t.iter().enumerate().skip(open) {
        if x.k == K::P {
            match x.s.as_str() {
                "(" | "{" | "[" => d += 1,
                ")" | "}" | "]" => {
                    d -= 1;
                    if d == 0 {
                        return k;
                    }
                }
                _ => {}
            }
        }
    }
    t.len().saturating_sub(1)
}

/// Argument count of the call whose `(` is at `open`.
fn argc(t: &[Tok], open: usize) -> i32 {
    let close = close_of(t, open);
    if close == open + 1 {
        return 0;
    }
    let mut d = 0i32;
    let mut n = 1;
    for x in &t[open..close] {
        if x.k == K::P {
            match x.s.as_str() {
                "(" | "{" | "[" => d += 1,
                ")" | "}" | "]" => d -= 1,
                "," if d == 1 => n += 1,
                _ => {}
            }
        }
    }
    n
}

/// Index of the `;` ending the prolog statement that starts at `i` (bracket depth 0), or the last token.
fn stmt_end(t: &[Tok], i: usize) -> usize {
    let mut d = 0i32;
    for (k, x) in t.iter().enumerate().skip(i) {
        if x.k == K::P {
            match x.s.as_str() {
                "(" | "{" | "[" => d += 1,
                ")" | "}" | "]" => d -= 1,
                ";" if d <= 0 => return k,
                _ => {}
            }
        }
    }
    t.len().saturating_sub(1)
}

pub struct Import {
    pub tok: usize,
    pub prefix: String,
    pub uri: String,
    pub ats: Vec<String>,
    pub schema: bool,
}

pub struct Func {
    /// `declare` token .. `;` token (inclusive).
    pub first: usize,
    pub last: usize,
    /// Body / initialiser token range (calls inside belong to this declaration).
    pub body: (usize, usize),
    pub prefix: String,
    pub local: String,
    pub uri: String,
    pub arity: usize,
    pub sig: String,
    pub annos: Vec<String>,
    pub private: bool,
    pub var: bool,
    pub ret: String,
}

/// The prolog and declarations of one file.
pub struct Module {
    pub lx: Lexed,
    /// Library module: (prefix, namespace URI, token).
    pub lib: Option<(String, String, usize)>,
    /// Prefix -> namespace URI bound in this file (module, imports, `declare namespace`).
    pub binds: HashMap<String, String>,
    pub default_fn: Option<String>,
    pub imports: Vec<Import>,
    pub decls: Vec<Func>,
    pub options: Vec<String>,
    /// Token ranges of prolog statements that are not code (imports, namespaces, options, version).
    pub skip: Vec<(usize, usize)>,
}

fn lits_after(t: &[Tok], mut j: usize, end: usize) -> Vec<String> {
    let mut v = vec![];
    while j <= end && j < t.len() {
        if t[j].k == K::Str {
            v.push(t[j].s.clone());
        }
        j += 1;
    }
    v
}

fn src_of(text: &str, t: &[Tok], a: usize, b: usize) -> String {
    if a >= t.len() || b < a {
        return String::new();
    }
    let s = &text[t[a].pos..t[b.min(t.len() - 1)].end];
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn parse(text: &str) -> Module {
    let lx = lex(text);
    let mut m = Module { lx, lib: None, binds: HashMap::new(), default_fn: None, imports: vec![], decls: vec![], options: vec![], skip: vec![] };
    m.binds.insert("local".into(), LOCAL_NS.into());
    let t = &m.lx.toks;
    let n = t.len();
    let mut i = 0usize;
    let mut stmt_start = true;
    let mut depth = 0i32;
    while i < n {
        let x = &t[i];
        if stmt_start && depth == 0 && x.k == K::Name {
            let end = stmt_end(t, i);
            let nx = |k: usize| t.get(i + k);
            match x.s.as_str() {
                "xquery" if nx(1).is_some_and(|y| y.is_name("version") || y.is_name("encoding")) => {
                    m.skip.push((i, end));
                    i = end + 1;
                    continue;
                }
                "module" if nx(1).is_some_and(|y| y.is_name("namespace")) => {
                    if let (Some(p), Some(u)) = (nx(2), nx(4)) {
                        if p.k == K::Name && u.k == K::Str {
                            m.lib = Some((p.s.clone(), u.s.clone(), i));
                            m.binds.insert(p.s.clone(), u.s.clone());
                        }
                    }
                    m.skip.push((i, end));
                    i = end + 1;
                    continue;
                }
                "import" if nx(1).is_some_and(|y| y.is_name("module") || y.is_name("schema")) => {
                    let schema = nx(1).is_some_and(|y| y.is_name("schema"));
                    let mut j = i + 2;
                    let mut prefix = String::new();
                    if t.get(j).is_some_and(|y| y.is_name("namespace")) && t.get(j + 2).is_some_and(|y| y.is_p("=")) {
                        prefix = t[j + 1].s.clone();
                        j += 3;
                    } else if t.get(j).is_some_and(|y| y.is_name("default")) {
                        // import schema default element namespace "uri"
                        while j < end && t[j].k != K::Str {
                            j += 1;
                        }
                    }
                    if let Some(u) = t.get(j).filter(|y| y.k == K::Str) {
                        let at = (j + 1..end).find(|&k| t[k].is_name("at"));
                        let ats = at.map(|a| lits_after(t, a + 1, end)).unwrap_or_default();
                        if !prefix.is_empty() {
                            m.binds.insert(prefix.clone(), u.s.clone());
                        }
                        m.imports.push(Import { tok: i, prefix, uri: u.s.clone(), ats, schema });
                    }
                    m.skip.push((i, end));
                    i = end + 1;
                    continue;
                }
                "declare" => {
                    let mut j = i + 1;
                    let mut annos = vec![];
                    let mut words = vec![];
                    let mut private = false;
                    while j < end {
                        if t[j].is_p("%") && t.get(j + 1).is_some_and(|y| y.k == K::Name) {
                            let an = t[j + 1].s.clone();
                            j += 2;
                            let mut a = an.clone();
                            if t.get(j).is_some_and(|y| y.is_p("(")) {
                                let c = close_of(t, j);
                                a = format!("{an}{}", src_of(text, t, j, c).replace(" (", "(").replace("( ", "(").replace(" )", ")"));
                                j = c + 1;
                            }
                            if an == "private" || an == "fn:private" {
                                private = true;
                            } else if an != "public" {
                                annos.push(a);
                            }
                            continue;
                        }
                        if t[j].k == K::Name && matches!(t[j].s.as_str(), "private" | "public" | "updating" | "sequential" | "simple" | "deterministic" | "nondeterministic") {
                            if t[j].s == "private" {
                                private = true;
                            } else if t[j].s != "public" {
                                words.push(t[j].s.clone());
                            }
                            j += 1;
                            continue;
                        }
                        break;
                    }
                    let kw = t.get(j).filter(|y| y.k == K::Name).map(|y| y.s.as_str()).unwrap_or("");
                    match kw {
                        "function" if t.get(j + 1).is_some_and(|y| y.k == K::Name) && t.get(j + 2).is_some_and(|y| y.is_p("(")) => {
                            let qn = t[j + 1].s.clone();
                            let open = j + 2;
                            let pclose = close_of(t, open);
                            let arity = (open + 1..pclose).filter(|&k| t[k].k == K::Var && (t[k - 1].is_p("(") || t[k - 1].is_p(","))).count();
                            // return type up to the body `{` / `external`
                            let mut k = pclose + 1;
                            let mut d = 0i32;
                            while k < n {
                                let y = &t[k];
                                if y.k == K::P {
                                    match y.s.as_str() {
                                        "(" | "[" => d += 1,
                                        ")" | "]" => d -= 1,
                                        "{" if d == 0 => break,
                                        ";" if d == 0 => break,
                                        _ => {}
                                    }
                                } else if d == 0 && y.is_name("external") {
                                    break;
                                }
                                k += 1;
                            }
                            let ret = if t.get(pclose + 1).is_some_and(|y| y.is_name("as")) && k > pclose + 2 { src_of(text, t, pclose + 2, k - 1) } else { String::new() };
                            let (body, last) = if t.get(k).is_some_and(|y| y.is_p("{")) {
                                let c = close_of(t, k);
                                let last = if t.get(c + 1).is_some_and(|y| y.is_p(";")) { c + 1 } else { c };
                                ((k + 1, c), last)
                            } else {
                                let e = stmt_end(t, k.min(n.saturating_sub(1)));
                                ((e, e), e)
                            };
                            let head = src_of(text, t, open, if k > open { k - 1 } else { open });
                            let sig = format!("declare {}function {qn}{head}", words.iter().map(|w| format!("{w} ")).collect::<String>());
                            let (prefix, local) = split_q(&qn);
                            m.decls.push(Func { first: i, last, body, prefix: prefix.into(), local: local.into(), uri: String::new(), arity, sig, annos, private, var: false, ret });
                            i = last + 1;
                            stmt_start = true;
                            continue;
                        }
                        "variable" if t.get(j + 1).is_some_and(|y| y.k == K::Var) => {
                            let qn = t[j + 1].s.clone();
                            let init = (j + 2..end).find(|&k| t[k].is_p(":="));
                            let ty = if t.get(j + 2).is_some_and(|y| y.is_name("as")) {
                                let stop = (j + 3..end).find(|&k| t[k].is_p(":=") || t[k].is_name("external")).unwrap_or(end);
                                if stop > j + 3 { src_of(text, t, j + 3, stop - 1) } else { String::new() }
                            } else {
                                String::new()
                            };
                            let ext = (j + 2..end).any(|k| t[k].is_name("external"));
                            let body = match init {
                                Some(a) => (a + 1, end),
                                None => (end, end),
                            };
                            let sig = format!(
                                "declare variable ${qn}{}{}",
                                if ty.is_empty() { String::new() } else { format!(" as {ty}") },
                                if ext { " external" } else { "" }
                            );
                            let (prefix, local) = split_q(&qn);
                            m.decls.push(Func { first: i, last: end, body, prefix: prefix.into(), local: local.into(), uri: String::new(), arity: 0, sig, annos, private, var: true, ret: ty });
                            i = end + 1;
                            stmt_start = true;
                            continue;
                        }
                        "namespace" => {
                            if let (Some(p), Some(eq), Some(u)) = (t.get(j + 1), t.get(j + 2), t.get(j + 3)) {
                                if p.k == K::Name && eq.is_p("=") && u.k == K::Str {
                                    m.binds.insert(p.s.clone(), u.s.clone());
                                }
                            }
                        }
                        "default" => {
                            if t.get(j + 1).is_some_and(|y| y.is_name("function")) && t.get(j + 2).is_some_and(|y| y.is_name("namespace")) {
                                if let Some(u) = t.get(j + 3).filter(|y| y.k == K::Str) {
                                    m.default_fn = Some(u.s.clone());
                                }
                            }
                        }
                        "option" => m.options.push(src_of(text, t, j + 1, end.saturating_sub(1))),
                        _ => {}
                    }
                    if !kw.is_empty() && !matches!(kw, "function" | "variable") {
                        m.skip.push((i, end));
                        i = end + 1;
                        continue;
                    }
                }
                _ => {}
            }
        }
        if x.k == K::P {
            match x.s.as_str() {
                "(" | "{" | "[" => depth += 1,
                ")" | "}" | "]" => depth -= 1,
                _ => {}
            }
        }
        stmt_start = x.is_p(";") && depth <= 0;
        i += 1;
    }
    let lib_uri = m.lib.as_ref().map(|l| l.1.clone());
    for d in m.decls.iter_mut() {
        d.uri = if d.prefix.is_empty() {
            if d.var { String::new() } else { m.default_fn.clone().or_else(|| lib_uri.clone()).unwrap_or_default() }
        } else {
            m.binds.get(&d.prefix).cloned().unwrap_or_default()
        };
    }
    m
}

pub fn split_q(q: &str) -> (&str, &str) {
    match q.split_once(':') {
        Some((p, l)) if !p.starts_with("Q{") => (p, l),
        _ => ("", q),
    }
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// One use found in code: call (with arity), named function reference `p:f#2`, prefixed variable, invoked module.
pub struct Use {
    pub tok: usize,
    pub prefix: String,
    pub local: String,
    /// call | ref | field | module | eval
    pub kind: &'static str,
    pub argc: i32,
}

/// Calls and other uses inside code token ranges (prolog statements and declaration heads excluded).
pub fn uses(m: &Module) -> Vec<Use> {
    let t = &m.lx.toks;
    let mut skip = vec![false; t.len()];
    for &(a, b) in &m.skip {
        for s in skip.iter_mut().take(b.min(t.len().saturating_sub(1)) + 1).skip(a) {
            *s = true;
        }
    }
    for d in &m.decls {
        // the declaration head (annotations, name, parameters, types) is not code
        let head_end = if d.body.0 > d.first { d.body.0 - 1 } else { d.last };
        for s in skip.iter_mut().take(head_end.min(t.len().saturating_sub(1)) + 1).skip(d.first) {
            *s = true;
        }
    }
    let mut out = vec![];
    for (i, x) in t.iter().enumerate() {
        if skip[i] {
            continue;
        }
        match x.k {
            K::Name => {
                let prev = if i > 0 { Some(&t[i - 1]) } else { None };
                // `%ann(`, `element(`-style kind tests after `as` / `instance of`, axis steps `child::x`
                if prev.is_some_and(|p| p.is_p("%") || (p.k == K::Name && TYPE_INTRO.contains(&p.s.as_str()))) {
                    continue;
                }
                let (prefix, local) = split_q(&x.s);
                if local == "*" || prefix == "*" {
                    continue;
                }
                let next = t.get(i + 1);
                if next.is_some_and(|y| y.is_p("(")) {
                    if prefix.is_empty() && NOT_CALLS.contains(&local) {
                        continue;
                    }
                    let argc = argc(t, i + 1) + i32::from(prev.is_some_and(|p| p.is_p("=>")));
                    // xdmp:invoke / xdmp:spawn with a literal module path; xdmp:eval text is not followed
                    let xdmp = prefix == "xdmp" && !m.binds.contains_key("xdmp") || m.binds.get(prefix).is_some_and(|u| u == "http://marklogic.com/xdmp");
                    if xdmp && matches!(local, "invoke" | "spawn" | "eval" | "javascript-eval") {
                        if let Some(a) = t.get(i + 2).filter(|y| y.k == K::Str && t.get(i + 3).is_some_and(|z| z.is_p(",") || z.is_p(")"))) {
                            if local == "invoke" || local == "spawn" {
                                if !a.s.is_empty() {
                                    out.push(Use { tok: i, prefix: a.s.clone(), local: base_name(&a.s).to_string(), kind: "module", argc: -1 });
                                }
                            } else {
                                out.push(Use { tok: i, prefix: String::new(), local: local.to_string(), kind: "eval", argc: -1 });
                            }
                        }
                    }
                    out.push(Use { tok: i, prefix: prefix.into(), local: local.into(), kind: "call", argc });
                } else if next.is_some_and(|y| y.is_p("#")) && t.get(i + 2).is_some_and(|y| y.k == K::Num) {
                    let n: i32 = t[i + 2].s.parse().unwrap_or(-1);
                    out.push(Use { tok: i, prefix: prefix.into(), local: local.into(), kind: "ref", argc: n });
                }
            }
            K::Var => {
                let (prefix, local) = split_q(&x.s);
                if !prefix.is_empty() && !prefix.starts_with("Q{") {
                    // a `for $p:x in` binding is a local, but prefixed locals are rare: a module variable use
                    out.push(Use { tok: i, prefix: prefix.into(), local: local.into(), kind: "field", argc: -1 });
                }
            }
            _ => {}
        }
    }
    out
}

/// Namespaces of built-in functions (bound explicitly by some modules): library names, never a module of the repo.
const BUILTIN_NS: &[&str] = &[
    "http://www.w3.org/2005/xpath-functions",
    "http://www.w3.org/2005/xpath-functions/math",
    "http://www.w3.org/2005/xpath-functions/map",
    "http://www.w3.org/2005/xpath-functions/array",
    "http://www.w3.org/2001/XMLSchema",
    "http://marklogic.com/xdmp",
    "http://marklogic.com/cts",
    "http://marklogic.com/xdmp/json",
    "http://marklogic.com/xdmp/map",
    "http://marklogic.com/xdmp/math",
    "http://marklogic.com/xdmp/spell",
    "http://marklogic.com/xdmp/security",
    "http://marklogic.com/semantics",
    "http://marklogic.com/geospatial",
];

/// Namespace URI a prefix means in this file ("" for built-in / unknown prefixes: library names).
pub fn ns_of(m: &Module, prefix: &str) -> String {
    let u = if prefix.is_empty() { m.default_fn.clone().unwrap_or_default() } else { m.binds.get(prefix).cloned().unwrap_or_default() };
    if BUILTIN_NS.contains(&u.as_str()) {
        return String::new();
    }
    u
}

pub fn file(f: &SourceFile, rows: &mut Rows) {
    let m = parse(&f.text);
    let t = &m.lx.toks;
    let nlines = f.text.lines().count().max(1) as u32;
    let base = base_name(&f.path).to_string();
    // the module: a member spanning the file (calls of a main module's body belong to it)
    let msig = match &m.lib {
        Some((p, u, _)) => format!("module namespace {p} = \"{u}\""),
        None => "main module".to_string(),
    };
    let mut mannos: Vec<String> = m.options.iter().map(|o| format!("option {o}")).collect();
    for im in &m.imports {
        mannos.push(format!(
            "import {}{}{}",
            if im.schema { "schema " } else { "module " },
            if im.prefix.is_empty() { String::new() } else { format!("{}=", im.prefix) },
            im.uri
        ));
    }
    mannos.truncate(24);
    rows.members.push(Member {
        file: f.path.clone(),
        line: 1,
        end_line: nlines,
        name: base.clone(),
        container: None,
        qname: base.clone(),
        kind: "module".into(),
        sig: msig,
        vis: "public".into(),
        annos: mannos,
        is_static: false,
        supers: vec![],
        ret: m.lib.as_ref().map(|l| l.1.clone()).unwrap_or_default(),
    });
    rows.symbols.push(Symbol { file: f.path.clone(), line: 1, end_line: nlines, name: base.clone(), kind: "module".into(), exported: true, container: None });
    for d in &m.decls {
        let line = m.lx.line(t[d.first].pos);
        let end = m.lx.line(t[d.last.min(t.len() - 1)].end.saturating_sub(1)).max(line);
        let qname = if d.prefix.is_empty() { d.local.clone() } else { format!("{}:{}", d.prefix, d.local) };
        rows.members.push(Member {
            file: f.path.clone(),
            line,
            end_line: end,
            name: d.local.clone(),
            container: if d.uri.is_empty() { None } else { Some(d.uri.clone()) },
            qname: qname.clone(),
            kind: if d.var { "field" } else { "function" }.into(),
            sig: d.sig.chars().take(300).collect(),
            vis: if d.private { "private" } else { "public" }.into(),
            annos: d.annos.clone(),
            is_static: false,
            supers: vec![],
            ret: d.ret.chars().take(80).collect(),
        });
        rows.symbols.push(Symbol {
            file: f.path.clone(),
            line,
            end_line: end,
            name: qname,
            kind: if d.var { "variable" } else { "function" }.into(),
            exported: !d.private,
            container: None,
        });
    }
    for im in &m.imports {
        let line = m.lx.line(t[im.tok].pos);
        let ats: Vec<String> = if im.ats.is_empty() { vec![String::new()] } else { im.ats.clone() };
        for at in ats {
            rows.refs.push(Ref {
                file: f.path.clone(),
                line,
                caller: String::new(),
                caller_line: 0,
                callee: im.uri.clone(),
                recv: at,
                recv_type: im.prefix.clone(),
                kind: "import".into(),
                conf: "exact".into(),
                argc: -1,
            });
        }
    }
    // owner of each token: the declaration whose body holds it, else the module
    let owner = |k: usize| -> (String, u32) {
        for d in &m.decls {
            if k >= d.body.0 && k <= d.body.1 && k >= d.first && k <= d.last {
                let q = if d.prefix.is_empty() { d.local.clone() } else { format!("{}:{}", d.prefix, d.local) };
                return (q, m.lx.line(t[d.first].pos));
            }
        }
        (base.clone(), 1)
    };
    for u in uses(&m) {
        let line = m.lx.line(t[u.tok].pos);
        let (caller, caller_line) = owner(u.tok);
        match u.kind {
            "module" => rows.refs.push(Ref {
                file: f.path.clone(),
                line,
                caller,
                caller_line,
                callee: u.local.clone(),
                recv: u.prefix.clone(),
                recv_type: format!("{MOD_PREFIX}{}", u.prefix),
                kind: "call".into(),
                conf: "exact".into(),
                argc: -1,
            }),
            "eval" => rows.notes.push(Note {
                file: f.path.clone(),
                line,
                kind: "xquery".into(),
                reference: format!("xdmp:{}", u.local),
                text: format!("xdmp:{} evaluates query text: the code it runs is not followed by the code graph", u.local),
            }),
            kind => {
                let rt = ns_of(&m, &u.prefix);
                // a library name (built-in prefix) keeps its prefix: `xdmp:invoke`, `map:get`
                let callee = if rt.is_empty() && !u.prefix.is_empty() { format!("{}:{}", u.prefix, u.local) } else { u.local.clone() };
                rows.refs.push(Ref {
                    file: f.path.clone(),
                    line,
                    caller,
                    caller_line,
                    callee,
                    recv: u.prefix.clone(),
                    conf: if rt.is_empty() { "name" } else { "exact" }.into(),
                    recv_type: rt,
                    kind: kind.into(),
                    argc: u.argc,
                });
            }
        }
    }
}

/// MarkLogic Server-Side JavaScript (`.sjs`, walked as JavaScript): `const lib = require("/lib/x.sjs")` and
/// `const { a, b: c } = require("/x.xqy")` are import bindings (`lib.f()` / `a()` then resolve into that module).
pub fn sjs_require(
    f: &SourceFile,
    decl: tree_sitter::Node,
    name: tree_sitter::Node,
    value: tree_sitter::Node,
    src: &str,
    imports: &mut HashMap<String, (String, String)>,
    rows: &mut Rows,
) {
    use crate::ts_util::*;
    if value.kind() != "call_expression" || value.child_by_field_name("function").is_none_or(|x| text(x, src) != "require") {
        return;
    }
    let Some(spec) = value.child_by_field_name("arguments").and_then(|a| named_children(a).first().copied()).and_then(|a| js_string(a, src)) else { return };
    let mut bound: Vec<(String, String)> = vec![];
    match name.kind() {
        "identifier" => bound.push((text(name, src).to_string(), "*".into())),
        "object_pattern" => {
            for p in named_children(name) {
                match p.kind() {
                    "shorthand_property_identifier_pattern" => bound.push((text(p, src).to_string(), text(p, src).to_string())),
                    "pair_pattern" => {
                        if let (Some(k), Some(v)) = (p.child_by_field_name("key"), p.child_by_field_name("value")) {
                            bound.push((text(v, src).to_string(), text(k, src).to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    for (local, orig) in bound {
        rows.refs.push(Ref {
            file: f.path.clone(),
            line: line(decl),
            caller: String::new(),
            caller_line: 0,
            callee: if orig == "*" { local.clone() } else { orig.clone() },
            recv: spec.clone(),
            recv_type: String::new(),
            kind: "import".into(),
            conf: "exact".into(),
            argc: -1,
        });
        imports.insert(local, (spec.clone(), orig));
    }
}
