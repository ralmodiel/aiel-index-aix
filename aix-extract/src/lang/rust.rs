//! Rust (2021 / 2024 editions: async fn in traits, let-else, let chains, `impl Trait`, GATs) on tree-sitter-rust.
//! `impl X` / `impl Trait for X` blocks put their functions in `X` (the trait becomes one of X's supers); receivers
//! are typed from `self`, parameters, struct fields, `let x: T`, `let x = T::new()` / `T { .. }`, and `Type::f()` paths.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Rust;

fn vis(n: Node, src: &str) -> String {
    match kid(n, &["visibility_modifier"]) {
        None => "private".into(),
        Some(v) => {
            let t = text(v, src);
            if t == "pub" {
                "public".into()
            } else if t.contains("crate") || t.contains("super") || t.contains("self") || t.contains("in ") {
                "package".into()
            } else {
                "public".into()
            }
        }
    }
}

/// Attributes directly above the item: (first node, texts).
fn attrs<'t>(n: Node<'t>, src: &str) -> (Node<'t>, Vec<String>) {
    let (mut first, mut out) = (n, vec![]);
    let mut p = n.prev_sibling();
    while let Some(x) = p {
        match x.kind() {
            "attribute_item" => {
                out.push(text(x, src).trim_start_matches("#[").trim_end_matches(']').to_string());
                first = x;
            }
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        p = x.prev_sibling();
    }
    out.reverse();
    (first, out)
}

fn flatten(n: Node, prefix: &str, src: &str, line: u32, out: &mut Vec<ImportRow>) {
    let join = |a: &str, b: &str| if a.is_empty() { b.to_string() } else { format!("{a}::{b}") };
    match n.kind() {
        "identifier" | "type_identifier" | "self" | "crate" => {
            let name = text(n, src);
            out.push(ImportRow { line, callee: name.to_string(), module: prefix.to_string(), local: name.to_string() });
        }
        "scoped_identifier" => {
            let path = fld(n, "path").map(|p| text(p, src)).unwrap_or("");
            let name = fld_text(n, "name", src);
            out.push(ImportRow { line, callee: name.to_string(), module: join(prefix, path), local: name.to_string() });
        }
        "use_as_clause" => {
            let (path, alias) = (fld(n, "path"), fld_text(n, "alias", src));
            if let Some(p) = path {
                let full = text(p, src);
                let (m, name) = full.rsplit_once("::").unwrap_or(("", full));
                out.push(ImportRow { line, callee: name.to_string(), module: if m.is_empty() { prefix.to_string() } else { join(prefix, m) }, local: alias.to_string() });
            }
        }
        "use_wildcard" => {
            let p = n.named_child(0).map(|p| text(p, src)).unwrap_or("");
            out.push(ImportRow { line, callee: "*".into(), module: join(prefix, p), local: "*".into() });
        }
        "scoped_use_list" => {
            let path = fld(n, "path").map(|p| text(p, src)).unwrap_or("");
            let pre = join(prefix, path);
            if let Some(l) = fld(n, "list") {
                for c in named_children(l) {
                    flatten(c, &pre, src, line, out);
                }
            }
        }
        "use_list" => {
            for c in named_children(n) {
                flatten(c, prefix, src, line, out);
            }
        }
        _ => {}
    }
}

fn sig_of(n: Node, name: &str, src: &str, ret: &str) -> String {
    // `fn name(params without self) -> ret`: the receiver is not an argument
    let params: Vec<String> = fld(n, "parameters")
        .map(|p| {
            named_children(p)
                .into_iter()
                .filter(|c| c.kind() != "self_parameter" && !c.kind().contains("comment"))
                .map(|c| squash(text(c, src)))
                .collect()
        })
        .unwrap_or_default();
    let r = if ret.is_empty() { String::new() } else { format!(" -> {ret}") };
    format!("fn {name}({}){r}", params.join(", "))
}

impl Lang for Rust {
    fn language(&self) -> Language {
        tree_sitter_rust::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "rust"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "struct_item" | "union_item" | "enum_item" | "trait_item" => {
                let name = fld_text(n, "name", src);
                let kind = match n.kind() {
                    "enum_item" => "enum",
                    "trait_item" => "interface",
                    _ => "class",
                };
                let (start, annos) = attrs(n, src);
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.start = start;
                d.annos = annos;
                d.vis = vis(n, src);
                d.sig = format!("{} {name}", n.kind().trim_end_matches("_item"));
                if let Some(b) = fld(n, "bounds") {
                    d.supers = named_children(b).into_iter().map(|t| simple_type(text(t, src))).filter(|s| !s.is_empty()).collect();
                }
                d.walk = fld(n, "body").map(|b| named_children(b)).unwrap_or_default();
                vec![d]
            }
            "impl_item" => {
                let ty = simple_type(fld_text(n, "type", src));
                let mut d = Decl::new(Role::Wrapper, ty, "class", n);
                if let Some(t) = fld(n, "trait") {
                    let s = simple_type(text(t, src));
                    if !s.is_empty() {
                        d.supers.push(s);
                    }
                }
                d.walk = fld(n, "body").map(|b| named_children(b)).unwrap_or_default();
                vec![d]
            }
            "mod_item" => {
                let mut d = Decl::new(Role::Wrapper, "", "class", n);
                d.walk = fld(n, "body").map(|b| named_children(b)).unwrap_or_default();
                vec![d]
            }
            "function_item" | "function_signature_item" => {
                let name = fld_text(n, "name", src);
                let (start, annos) = attrs(n, src);
                let mut d = Decl::new(Role::Func, name, "function", n);
                d.start = start;
                d.annos = annos;
                d.vis = vis(n, src);
                d.ret = fld(n, "return_type").map(|r| if text(r, src) == "Self" { "Self".to_string() } else { simple_type(text(r, src)) }).unwrap_or_default();
                d.sig = sig_of(n, name, src, &d.ret);
                let params = fld(n, "parameters");
                let has_self = params.is_some_and(|p| named_children(p).iter().any(|c| c.kind() == "self_parameter"));
                d.is_static = !has_self && n.parent().is_some_and(|p| p.kind() == "declaration_list" && p.parent().is_some_and(|g| matches!(g.kind(), "impl_item" | "trait_item")));
                if let Some(p) = params {
                    for c in named_children(p) {
                        if c.kind() == "parameter" {
                            if let Some(pat) = fld(c, "pattern") {
                                let nm = text(pat, src).trim_start_matches("mut ").to_string();
                                d.params.push((nm, fld_text(c, "type", src).to_string()));
                            }
                        }
                    }
                }
                d.walk = fld(n, "body").into_iter().collect();
                vec![d]
            }
            "field_declaration" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Field, name, "field", n);
                d.vis = vis(n, src);
                d.ret = simple_type(fld_text(n, "type", src));
                d.sig = squash(text(n, src));
                vec![d]
            }
            "const_item" | "static_item" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Field, name, "const", n);
                d.vis = vis(n, src);
                d.ret = simple_type(fld_text(n, "type", src));
                d.sig = squash(text(n, src)).chars().take(120).collect();
                d.walk = fld(n, "value").into_iter().collect();
                vec![d]
            }
            "type_item" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Field, name, "type", n);
                d.vis = vis(n, src);
                d.sig = squash(text(n, src)).chars().take(120).collect();
                vec![d]
            }
            "macro_definition" => {
                let name = fld_text(n, "name", src);
                let (start, annos) = attrs(n, src);
                let mut d = Decl::new(Role::Field, name, "macro", n);
                d.start = start;
                d.annos = annos;
                d.vis = if annos_export(&d.annos) { "public".into() } else { "private".into() };
                d.sig = format!("macro_rules! {name}");
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let mut f = fld(n, "function")?;
        if f.kind() == "generic_function" {
            f = fld(f, "function")?;
        }
        let args = fld(n, "arguments");
        let (callee, recv, st, kind) = match f.kind() {
            "identifier" => {
                let c = text(f, src);
                if matches!(c, "Some" | "Ok" | "Err" | "Box" | "Vec") {
                    return None;
                }
                (c.to_string(), None, None, if c.chars().next().is_some_and(|x| x.is_uppercase()) { "new" } else { "call" })
            }
            "field_expression" => (fld_text(f, "field", src).to_string(), fld(f, "value"), None, "call"),
            "scoped_identifier" => {
                let name = fld_text(f, "name", src).to_string();
                let path = fld(f, "path").map(|p| text(p, src)).unwrap_or("");
                let last = path.rsplit("::").next().unwrap_or("");
                if last.chars().next().is_some_and(|c| c.is_uppercase()) {
                    let t = simple_type(last);
                    (name, None, if t.is_empty() { Some(last.to_string()) } else { Some(t) }, "call")
                } else if matches!(last, "self" | "Self") {
                    (name, None, Some("Self".into()), "call")
                } else {
                    (name, None, None, "call")
                }
            }
            _ => return None,
        };
        Some(Call { callee, recv, static_type: st, kind, argc: argc(args, src), args: arg_nodes(args) })
    }

    fn hidden_calls(&self, n: Node, src: &str) -> Vec<HiddenCall> {
        if n.kind() != "macro_invocation" {
            return vec![];
        }
        let mut out = vec![];
        let name = n.child_by_field_name("macro").map(|m| text(m, src)).unwrap_or("");
        let last = name.rsplit("::").next().unwrap_or("");
        // a use of a user macro is a reference to it (std / well-known macros would only add noise)
        if !last.is_empty() && !STD_MACROS.contains(&last) {
            out.push(HiddenCall { line: line(n), callee: last.to_string(), recv: String::new(), static_type: None, value: false });
        }
        if let Some(tt) = kid(n, &["token_tree"]) {
            token_calls(tt, src, &mut out);
            // a user macro's bare identifier arguments may be functions it calls (`ext_impl!(T, "t", h, handler)`
            // expands to `handler(f, &mut rows)`): a `ref` each, kept only when it names a function of this file
            if !last.is_empty() && !STD_MACROS.contains(&last) {
                let kids = children(tt);
                let inner = kids.get(1..kids.len().saturating_sub(1)).unwrap_or(&[]);
                for arg in inner.split(|k| text(*k, src) == ",") {
                    if let [k] = arg {
                        let name = text(*k, src);
                        if k.kind() == "identifier" && name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') && !KEYWORDS.contains(&name) {
                            out.push(HiddenCall { line: line(*k), callee: name.to_string(), recv: String::new(), static_type: None, value: true });
                        }
                    }
                }
            }
        }
        out
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "use_declaration" {
            return vec![];
        }
        let mut out = vec![];
        if let Some(a) = fld(n, "argument") {
            flatten(a, "", src, line(n), &mut out);
        }
        out
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() != "let_declaration" {
            return vec![];
        }
        let Some(p) = fld(n, "pattern") else { return vec![] };
        let name = match p.kind() {
            "identifier" => text(p, src).to_string(),
            "mut_pattern" => p.named_child(0).map(|c| text(c, src).to_string()).unwrap_or_default(),
            _ => return vec![],
        };
        if let Some(t) = fld(n, "type") {
            return vec![(name, TypeSrc::Declared(text(t, src).to_string()))];
        }
        match fld(n, "value") {
            Some(v) => vec![(name, TypeSrc::Init(v))],
            None => vec![],
        }
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "self" => Expr::This,
            "field_expression" => match fld(n, "value") {
                Some(v) => Expr::Member(v, fld_text(n, "field", src).to_string()),
                None => Expr::Other,
            },
            "reference_expression" | "try_expression" | "await_expression" | "parenthesized_expression" => {
                n.named_child(0).map(|c| self.expr(c, src)).unwrap_or(Expr::Other)
            }
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        match n.kind() {
            "struct_expression" => {
                let t = fld(n, "name").map(|x| text(x, src)).unwrap_or("");
                simple_type(t)
            }
            "reference_expression" | "try_expression" | "await_expression" | "parenthesized_expression" => {
                n.named_child(0).map(|c| self.init_type(c, src)).unwrap_or_default()
            }
            "call_expression" => {
                let Some(f) = fld(n, "function") else { return String::new() };
                if f.kind() != "scoped_identifier" {
                    return String::new();
                }
                let name = fld_text(f, "name", src);
                let path = fld(f, "path").map(|p| text(p, src)).unwrap_or("");
                let last = path.rsplit("::").next().unwrap_or("");
                let ctor = ["new", "default", "from", "with", "create", "open", "connect", "build", "init", "load", "parse"]
                    .iter()
                    .any(|p| name == *p || name.starts_with(&format!("{p}_")));
                if !ctor {
                    return String::new();
                }
                if matches!(last, "Arc" | "Box" | "Rc" | "Mutex" | "RwLock" | "RefCell" | "Cell") {
                    return fld(n, "arguments").and_then(|a| a.named_child(0)).map(|a| self.init_type(a, src)).unwrap_or_default();
                }
                if last == "Self" {
                    return "Self".into();
                }
                if last.chars().next().is_some_and(|c| c.is_uppercase()) {
                    return simple_type(last);
                }
                String::new()
            }
            _ => String::new(),
        }
    }
}

const STD_MACROS: &[&str] = &[
    "println", "print", "eprintln", "eprint", "format", "write", "writeln", "vec", "panic", "assert", "assert_eq", "assert_ne",
    "debug_assert", "debug_assert_eq", "debug_assert_ne", "unreachable", "unimplemented", "todo", "matches", "dbg", "format_args",
    "include_str", "include_bytes", "include", "concat", "stringify", "env", "option_env", "cfg", "line", "file", "column",
    "module_path", "compile_error", "thread_local", "bail", "anyhow", "ensure", "params", "named_params", "json", "vec_deque",
    "info", "warn", "error", "debug", "trace", "tracing", "quote", "select", "join", "try_join", "pin", "ready", "test",
    "main", "lazy_static", "async_trait", "derive", "macro_rules", "static_assertions", "const_assert", "bitflags", "format_ident",
    "eyre", "tokio", "Ok", "try_", "r#try", "ptr",
];

const KEYWORDS: &[&str] = &[
    "if", "while", "for", "match", "loop", "fn", "return", "let", "in", "as", "move", "ref", "mut", "else", "break", "continue",
    "where", "impl", "dyn", "unsafe", "async", "await", "pub", "use", "mod", "struct", "enum", "trait", "type", "const", "static",
    "Some", "Ok", "Err", "None", "Box", "Vec", "Self", "self", "super", "crate",
];

/// Call-like token sequences in a macro's token tree: `f(..)`, `a::b(..)`, `x.m(..)`, recursively in nested groups.
fn token_calls(tt: Node, src: &str, out: &mut Vec<HiddenCall>) {
    let kids = children(tt);
    for (i, k) in kids.iter().enumerate() {
        match k.kind() {
            "token_tree" => token_calls(*k, src, out),
            "identifier" | "type_identifier" | "field_identifier" => {
                let Some(next) = kids.get(i + 1) else { continue };
                if next.kind() != "token_tree" || !text(*next, src).starts_with('(') {
                    continue;
                }
                let name = text(*k, src);
                if KEYWORDS.contains(&name) {
                    continue;
                }
                let prev = if i > 0 { Some(kids[i - 1]) } else { None };
                if prev.is_some_and(|p| matches!(p.kind(), "fn" | "struct" | "enum" | "trait" | "type") || text(p, src) == "fn") {
                    continue;
                }
                // `a::b::f(` : collect the path to the left
                let mut path: Vec<&str> = vec![];
                let mut j = i;
                while j >= 2 && text(kids[j - 1], src) == "::" && matches!(kids[j - 2].kind(), "identifier" | "type_identifier" | "self" | "crate" | "super") {
                    path.insert(0, text(kids[j - 2], src));
                    j -= 2;
                }
                let is_method = prev.is_some_and(|p| text(p, src) == ".");
                let (recv, st) = if path.is_empty() {
                    (String::new(), None)
                } else {
                    let l = *path.last().unwrap();
                    let st = if l.chars().next().is_some_and(|c| c.is_uppercase()) {
                        Some(simple_type(l)).filter(|t| !t.is_empty()).or_else(|| Some(l.to_string()))
                    } else if matches!(l, "self" | "Self") {
                        Some("Self".to_string())
                    } else {
                        None
                    };
                    // a lowercase module path (`util::f(`) carries no receiver, like the same call outside a macro
                    (if st.is_some() { path.join("::") } else { String::new() }, st)
                };
                if is_method && !path.is_empty() {
                    continue;
                }
                out.push(HiddenCall { line: line(*k), callee: name.to_string(), recv, static_type: st, value: false });
            }
            _ => {}
        }
    }
}

fn annos_export(a: &[String]) -> bool {
    a.iter().any(|x| x.contains("macro_export"))
}
