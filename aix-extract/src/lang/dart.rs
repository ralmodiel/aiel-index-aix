//! Dart (2.x / 3.x: records, patterns, sealed / base classes, extension types, null safety) on tree-sitter-dart:
//! symbol level. Classes, mixins, enums, extensions, methods / getters / constructors, fields, imports, and calls with
//! `this`, static and typed receivers.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Dart;

fn annos(n: Node, src: &str) -> Vec<String> {
    children(n).into_iter().filter(|c| c.kind() == "annotation").map(|c| squash(text(c, src).trim_start_matches('@'))).collect()
}

fn type_names(n: Node, src: &str, out: &mut Vec<String>) {
    walk(n, |x| {
        if x.kind() == "type_identifier" {
            let s = simple_type(text(x, src));
            if !s.is_empty() {
                out.push(s);
            }
            return false;
        }
        true
    });
}

fn params(sig: Node, src: &str) -> (Vec<(String, String)>, String) {
    let Some(pl) = fld(sig, "parameters") else { return (vec![], String::new()) };
    let ps = named_children(pl)
        .into_iter()
        .filter(|p| p.kind() == "formal_parameter")
        .map(|p| (fld_text(p, "name", src).to_string(), kid(p, &["type"]).map(|t| text(t, src).to_string()).unwrap_or_default()))
        .collect();
    (ps, squash(text(pl, src)))
}

fn sig_decl<'t>(owner: Node<'t>, sig: Node<'t>, src: &str, body: Option<Node<'t>>) -> Option<Decl<'t>> {
    let (kind, role) = match sig.kind() {
        "function_signature" | "getter_signature" | "setter_signature" | "operator_signature" => ("function", Role::Func),
        "constructor_signature" | "factory_constructor_signature" | "redirecting_factory_constructor_signature" | "constant_constructor_signature" => ("ctor", Role::Func),
        _ => return None,
    };
    let names = flds(sig, "name");
    let name = names.last().map(|x| text(*x, src)).unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let mut d = Decl::new(role, name, kind, owner);
    d.annos = annos(owner, src);
    d.vis = if name.starts_with('_') { "private".into() } else { "public".into() };
    d.is_static = text(owner, src).trim_start().starts_with("static ") || kid(owner, &["static"]).is_some() || children(sig).iter().any(|c| c.kind() == "static");
    let (ps, ptxt) = params(sig, src);
    d.params = ps;
    d.ret = fld(sig, "return_type").map(|t| simple_type(text(t, src))).unwrap_or_default();
    d.sig = format!("{name}{}", if ptxt.is_empty() { String::new() } else { ptxt });
    d.walk = body.into_iter().collect();
    Some(d)
}

impl Lang for Dart {
    fn language(&self) -> Language {
        tree_sitter_dart::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "dart"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "class_declaration" | "mixin_declaration" | "enum_declaration" | "extension_declaration" | "extension_type_declaration" => {
                let name = fld_text(n, "name", src);
                let kind = match n.kind() {
                    "enum_declaration" => "enum",
                    "mixin_declaration" => "interface",
                    _ => "class",
                };
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.annos = annos(n, src);
                d.vis = if name.starts_with('_') { "private".into() } else { "public".into() };
                d.sig = format!("{kind} {name}");
                for k in ["superclass", "interfaces", "mixins"] {
                    if let Some(s) = fld(n, k) {
                        type_names(s, src, &mut d.supers);
                    }
                }
                d.walk = fld(n, "body").map(named_children).unwrap_or_default();
                vec![d]
            }
            "function_declaration" => {
                let Some(sig) = fld(n, "signature") else { return vec![] };
                sig_decl(n, sig, src, fld(n, "body")).into_iter().collect()
            }
            "method_declaration" => {
                let Some(sig) = fld(n, "signature").and_then(|s| named_children(s).into_iter().next()) else { return vec![] };
                sig_decl(n, sig, src, fld(n, "body")).into_iter().collect()
            }
            // class_member > declaration: fields, constructors, abstract methods
            "declaration" => {
                let kids = named_children(n);
                if let Some(s) = kids.iter().find(|c| c.kind().ends_with("signature")) {
                    let s = if s.kind() == "method_signature" { s.named_child(0).unwrap_or(*s) } else { *s };
                    return sig_decl(n, s, src, None).into_iter().collect();
                }
                let Some(list) = kids.iter().find(|c| matches!(c.kind(), "initialized_identifier_list" | "static_final_declaration_list" | "identifier_list")) else { return vec![] };
                let t = kid(n, &["type"]).map(|t| simple_type(text(t, src))).unwrap_or_default();
                named_children(*list)
                    .into_iter()
                    .map(|c| {
                        let nm = fld_text(c, "name", src);
                        let nm = if nm.is_empty() { text(c, src) } else { nm };
                        let mut d = Decl::new(Role::Field, nm, "field", n);
                        d.vis = if nm.starts_with('_') { "private".into() } else { "public".into() };
                        d.ret = t.clone();
                        d.sig = squash(text(n, src)).chars().take(120).collect();
                        d
                    })
                    .collect()
            }
            "enum_constant" => {
                let mut d = Decl::new(Role::Field, fld_text(n, "name", src), "const", n);
                d.sig = squash(text(n, src));
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let f = fld(n, "function")?;
        let a = arg_nodes(fld(n, "arguments"));
        match f.kind() {
            "identifier" => {
                let c = text(f, src);
                Some(Call { callee: c.to_string(), recv: None, static_type: None, kind: if c.chars().next().is_some_and(|x| x.is_uppercase()) { "new" } else { "call" }, argc: a.len() as i32, args: a })
            }
            "member_expression" => Some(Call { callee: fld_text(f, "property", src).to_string(), recv: fld(f, "object"), static_type: None, kind: "call", argc: a.len() as i32, args: a }),
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "import_specification" {
            return vec![];
        }
        let uri = fld(n, "uri").map(|u| text(u, src).trim_matches(['\'', '"']).to_string()).unwrap_or_default();
        let alias = fld(n, "alias").map(|a| text(a, src).to_string());
        let local = alias.unwrap_or_else(|| uri.rsplit('/').next().unwrap_or("").trim_end_matches(".dart").to_string());
        vec![ImportRow { line: line(n), callee: "*".into(), module: uri, local }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() != "initialized_variable_definition" {
            return vec![];
        }
        let name = fld_text(n, "name", src).to_string();
        if let Some(t) = kid(n, &["type"]).or_else(|| n.parent().and_then(|p| kid(p, &["type"]))) {
            return vec![(name, TypeSrc::Declared(text(t, src).to_string()))];
        }
        fld(n, "value").map(|v| vec![(name, TypeSrc::Init(v))]).unwrap_or_default()
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "this" => Expr::This,
            "member_expression" => match fld(n, "object") {
                Some(o) => Expr::Member(o, fld_text(n, "property", src).to_string()),
                None => Expr::Other,
            },
            "argument" | "named_argument" | "parenthesized_expression" => n.named_child(n.named_child_count().saturating_sub(1) as u32).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        if n.kind() == "call_expression" {
            if let Some(f) = fld(n, "function") {
                if f.kind() == "identifier" && text(f, src).chars().next().is_some_and(|c| c.is_uppercase()) {
                    return simple_type(text(f, src));
                }
            }
        }
        String::new()
    }
}
