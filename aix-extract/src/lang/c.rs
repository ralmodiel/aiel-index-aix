//! C and C++ (C11 / C17, C++11 - 20: templates, namespaces, lambdas, out-of-class method definitions) on
//! tree-sitter-c / tree-sitter-cpp: symbol level. Structs / classes / enums / typedef'd structs, functions (a
//! `Class::method` definition belongs to `Class`), fields, macros, `#include`s, calls with `this`, `Class::f()`,
//! typed receivers and `new T`.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct C;
pub struct Cpp;

fn declarator_fn(n: Node) -> Option<Node> {
    // function_declarator under pointer / reference declarators
    let mut cur = n.child_by_field_name("declarator")?;
    loop {
        match cur.kind() {
            "function_declarator" => return Some(cur),
            "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" | "attributed_declarator" => {
                cur = cur.child_by_field_name("declarator").or_else(|| cur.named_child(0))?;
            }
            _ => return None,
        }
    }
}

/// (container, name) of a function declarator's name.
fn fn_name(fd: Node, src: &str) -> (Option<String>, String) {
    let d = fd.child_by_field_name("declarator");
    match d {
        Some(x) if x.kind() == "qualified_identifier" => {
            let scope = fld_text(x, "scope", src).rsplit("::").next().unwrap_or("").to_string();
            (Some(scope).filter(|s| !s.is_empty()), simple_name(fld_text(x, "name", src)))
        }
        Some(x) => (None, simple_name(text(x, src))),
        None => (None, String::new()),
    }
}

fn simple_name(s: &str) -> String {
    s.rsplit("::").next().unwrap_or(s).to_string()
}

fn declared_name<'a>(n: Node, src: &'a str) -> &'a str {
    let mut cur = n;
    loop {
        match cur.kind() {
            "identifier" | "field_identifier" | "type_identifier" => return text(cur, src),
            _ => match cur.child_by_field_name("declarator").or_else(|| cur.named_child(0)) {
                Some(c) => cur = c,
                None => return "",
            },
        }
    }
}

fn params(fd: Node, src: &str) -> Vec<(String, String)> {
    let Some(pl) = fd.child_by_field_name("parameters") else { return vec![] };
    named_children(pl)
        .into_iter()
        .filter(|p| p.kind() == "parameter_declaration")
        .filter_map(|p| {
            let d = p.child_by_field_name("declarator")?;
            Some((declared_name(d, src).to_string(), fld_text(p, "type", src).to_string()))
        })
        .collect()
}

/// Access (`public:` ...) in effect for a member: the closest `access_specifier` above it.
fn access(n: Node, src: &str, default: &str) -> String {
    let default = match n.parent().and_then(|p| p.parent()).map(|g| g.kind()) {
        Some("class_specifier") => "private",
        Some("struct_specifier") | Some("union_specifier") => "public",
        _ => default,
    };
    let mut s = n.prev_sibling();
    while let Some(x) = s {
        if x.kind() == "access_specifier" {
            return text(x, src).trim_end_matches(':').trim().to_string();
        }
        s = x.prev_sibling();
    }
    default.into()
}

fn static_fn(n: Node, src: &str) -> bool {
    children(n).iter().any(|c| c.kind() == "storage_class_specifier" && text(*c, src) == "static")
}

fn decls_for<'t>(n: Node<'t>, src: &str, cpp: bool) -> Vec<Decl<'t>> {
    match n.kind() {
        "namespace_definition" | "linkage_specification" | "template_declaration" => {
            let mut d = Decl::new(Role::Wrapper, "", "class", n);
            d.walk = children(n);
            vec![d]
        }
        "struct_specifier" | "class_specifier" | "union_specifier" | "enum_specifier" => {
            let Some(body) = n.child_by_field_name("body") else { return vec![] };
            let name = fld_text(n, "name", src);
            if name.is_empty() {
                return vec![];
            }
            let kind = if n.kind() == "enum_specifier" { "enum" } else { "class" };
            let mut d = Decl::new(Role::Type, simple_name(name), kind, n);
            d.sig = format!("{} {name}", n.kind().trim_end_matches("_specifier"));
            for b in children(n).into_iter().filter(|c| c.kind() == "base_class_clause") {
                for t in named_children(b).into_iter().filter(|c| c.kind() != "access_specifier") {
                    let s = simple_type(text(t, src));
                    if !s.is_empty() {
                        d.supers.push(s);
                    }
                }
            }
            d.walk = named_children(body);
            vec![d]
        }
        "type_definition" => {
            // typedef struct { ... } Name;
            let (Some(t), Some(dc)) = (n.child_by_field_name("type"), n.child_by_field_name("declarator")) else { return vec![] };
            if matches!(t.kind(), "struct_specifier" | "union_specifier" | "enum_specifier") && t.child_by_field_name("name").is_none() {
                if let Some(body) = t.child_by_field_name("body") {
                    let name = declared_name(dc, src);
                    let mut d = Decl::new(Role::Type, name, if t.kind() == "enum_specifier" { "enum" } else { "class" }, n);
                    d.sig = format!("typedef {name}");
                    d.walk = named_children(body);
                    return vec![d];
                }
            }
            vec![]
        }
        "function_definition" => {
            let Some(fd) = declarator_fn(n) else { return vec![] };
            let (cont, name) = fn_name(fd, src);
            if name.is_empty() {
                return vec![];
            }
            let mut d = Decl::new(Role::Func, name.clone(), "function", n);
            d.container = cont;
            d.is_static = static_fn(n, src);
            d.vis = if d.is_static && !cpp { "private".into() } else if cpp { access(n, src, "public") } else { "public".into() };
            let t = fld_text(n, "type", src);
            d.ret = simple_type(t);
            d.sig = format!("{t} {name}{}", fd.child_by_field_name("parameters").map(|p| squash(text(p, src))).unwrap_or_default());
            d.params = params(fd, src);
            d.walk = n.child_by_field_name("body").into_iter().collect();
            vec![d]
        }
        "field_declaration" if n.parent().is_some_and(|p| p.kind() == "field_declaration_list") => {
            let t = fld_text(n, "type", src);
            flds(n, "declarator")
                .into_iter()
                .filter_map(|dc| {
                    if let Some(fd) = (dc.kind() == "function_declarator").then_some(dc).or_else(|| declarator_fn(n)) {
                        // a method prototype
                        let (_, name) = fn_name(fd, src);
                        let mut d = Decl::new(Role::Func, name.clone(), "function", n);
                        d.vis = access(n, src, "private");
                        d.ret = simple_type(t);
                        d.sig = format!("{t} {name}{}", fd.child_by_field_name("parameters").map(|p| squash(text(p, src))).unwrap_or_default());
                        d.walk = vec![];
                        return Some(d);
                    }
                    let name = declared_name(dc, src);
                    if name.is_empty() {
                        return None;
                    }
                    let mut d = Decl::new(Role::Field, name, "field", n);
                    d.vis = access(n, src, "private");
                    d.is_static = static_fn(n, src);
                    d.ret = simple_type(t);
                    d.sig = squash(text(n, src)).chars().take(120).collect();
                    Some(d)
                })
                .collect()
        }
        "enumerator" => {
            let mut d = Decl::new(Role::Field, fld_text(n, "name", src), "const", n);
            d.sig = squash(text(n, src));
            vec![d]
        }
        "preproc_function_def" | "preproc_def" => {
            let name = fld_text(n, "name", src);
            let func = n.kind() == "preproc_function_def";
            let mut d = Decl::new(if func { Role::Func } else { Role::Field }, name, if func { "function" } else { "const" }, n);
            d.sig = if func { format!("#define {name}{}", fld_text(n, "parameters", src)) } else { format!("#define {name}") };
            d.walk = vec![];
            vec![d]
        }
        _ => vec![],
    }
}

fn call_for<'t>(n: Node<'t>, src: &str) -> Option<Call<'t>> {
    match n.kind() {
        "call_expression" => {
            let f = fld(n, "function")?;
            let args = fld(n, "arguments");
            let a = arg_nodes(args);
            let (callee, recv, st) = match f.kind() {
                "identifier" => (text(f, src).to_string(), None, None),
                "field_expression" => (fld_text(f, "field", src).to_string(), fld(f, "argument"), None),
                "qualified_identifier" => {
                    let scope = fld_text(f, "scope", src);
                    let last = scope.rsplit("::").next().unwrap_or("");
                    let first_upper = last.chars().next().is_some_and(|c| c.is_uppercase());
                    (simple_name(fld_text(f, "name", src)), None, if first_upper { Some(last.to_string()) } else { None })
                }
                "template_function" => (fld_text(f, "name", src).to_string(), None, None),
                _ => return None,
            };
            Some(Call { callee, recv, static_type: st, kind: "call", argc: a.len() as i32, args: a })
        }
        "new_expression" => {
            let t = fld(n, "type")?;
            let a = arg_nodes(fld(n, "arguments"));
            Some(Call { callee: simple_type(text(t, src)), recv: None, static_type: None, kind: "new", argc: a.len() as i32, args: a })
        }
        _ => None,
    }
}

fn imports_for(n: Node, src: &str) -> Vec<ImportRow> {
    if n.kind() != "preproc_include" {
        return vec![];
    }
    let p = fld_text(n, "path", src).trim_matches(['"', '<', '>']).to_string();
    let local = p.rsplit('/').next().unwrap_or("").to_string();
    vec![ImportRow { line: line(n), callee: "*".into(), module: p, local }]
}

fn locals_for<'t>(n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
    if n.kind() != "declaration" || n.parent().is_some_and(|p| matches!(p.kind(), "translation_unit" | "declaration_list" | "field_declaration_list")) {
        return vec![];
    }
    let Some(t) = fld(n, "type") else { return vec![] };
    if t.kind() == "placeholder_type_specifier" {
        return vec![];
    }
    flds(n, "declarator")
        .into_iter()
        .map(|d| {
            let nm = declared_name(d, src).to_string();
            (nm, TypeSrc::Declared(text(t, src).to_string()))
        })
        .collect()
}

fn expr_for<'t>(n: Node<'t>, src: &str) -> Expr<'t> {
    match n.kind() {
        "identifier" => Expr::Ident(text(n, src).to_string()),
        "this" => Expr::This,
        "field_expression" => match fld(n, "argument") {
            Some(a) => Expr::Member(a, fld_text(n, "field", src).to_string()),
            None => Expr::Other,
        },
        "pointer_expression" | "parenthesized_expression" => n.named_child(0).map(|c| expr_for(c, src)).unwrap_or(Expr::Other),
        _ => Expr::Other,
    }
}

impl Lang for C {
    fn language(&self) -> Language {
        tree_sitter_c::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "c"
    }
    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        decls_for(n, src, false)
    }
    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        call_for(n, src)
    }
    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        imports_for(n, src)
    }
    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        locals_for(n, src)
    }
    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        expr_for(n, src)
    }
    fn caps_are_types(&self) -> bool {
        false
    }
}

impl Lang for Cpp {
    fn language(&self) -> Language {
        tree_sitter_cpp::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "cpp"
    }
    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        decls_for(n, src, true)
    }
    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        call_for(n, src)
    }
    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        imports_for(n, src)
    }
    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        locals_for(n, src)
    }
    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        expr_for(n, src)
    }
    fn caps_are_types(&self) -> bool {
        false
    }
}
