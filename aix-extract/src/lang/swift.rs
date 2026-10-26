//! Swift (5.x: actors, async / throws, result builders, macros) on tree-sitter-swift: symbol level. Types, protocols,
//! extensions (members join the extended type), functions, initialisers, properties, enum cases; imports; calls with
//! `self`, static (`Type.f()`), typed property / parameter / `let x = T(..)` receivers.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Swift;

fn vis(n: Node, src: &str) -> String {
    if let Some(m) = kid(n, &["modifiers"]) {
        for c in named_children(m) {
            if c.kind() == "visibility_modifier" {
                return match text(c, src) {
                    "private" | "fileprivate" => "private",
                    "internal" => "package",
                    _ => "public",
                }
                .into();
            }
        }
    }
    "package".into()
}

fn is_static(n: Node, src: &str) -> bool {
    kid(n, &["modifiers"]).is_some_and(|m| named_children(m).iter().any(|c| matches!(text(*c, src), "static" | "class")))
}

fn type_of_annotation(n: Node, src: &str) -> String {
    kid(n, &["type_annotation"]).map(|t| simple_type(text(t, src).trim_start_matches(':'))).unwrap_or_default()
}

fn ident<'a>(n: Node, src: &'a str) -> &'a str {
    n.child_by_field_name("name")
        .filter(|c| c.kind() == "simple_identifier" || c.kind() == "type_identifier")
        .map(|c| text(c, src))
        .or_else(|| kid(n, &["simple_identifier"]).map(|c| text(c, src)))
        .unwrap_or("")
}

impl Lang for Swift {
    fn language(&self) -> Language {
        tree_sitter_swift::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "swift"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "class_declaration" | "protocol_declaration" => {
                let kw = children(n).into_iter().find(|c| matches!(c.kind(), "struct" | "class" | "enum" | "extension" | "actor" | "protocol")).map(|c| c.kind().to_string()).unwrap_or_default();
                let name_node = n.child_by_field_name("name");
                let name = name_node.map(|x| simple_type(text(x, src))).unwrap_or_default();
                let kind = if n.kind() == "protocol_declaration" { "interface" } else if kw == "enum" { "enum" } else { "class" };
                let role = if kw == "extension" { Role::Wrapper } else { Role::Type };
                let mut d = Decl::new(role, name.clone(), kind, n);
                d.vis = vis(n, src);
                d.sig = format!("{kw} {name}");
                for s in children(n).into_iter().filter(|c| c.kind() == "inheritance_specifier") {
                    let t = simple_type(text(s, src));
                    if !t.is_empty() {
                        d.supers.push(t);
                    }
                }
                d.walk = n.child_by_field_name("body").map(named_children).unwrap_or_default();
                vec![d]
            }
            "deinit_declaration" | "subscript_declaration" => {
                let name = if n.kind() == "deinit_declaration" { "deinit" } else { "subscript" };
                let mut d = Decl::new(Role::Func, name, if name == "deinit" { "ctor" } else { "function" }, n);
                d.vis = vis(n, src);
                let to = n.child_by_field_name("body").map(|b| b.start_byte()).unwrap_or(n.end_byte()).max(n.start_byte());
                d.sig = squash(src[n.start_byte()..to].trim_end_matches(['{', ' ', '\n']));
                d.walk = children(n).into_iter().filter(|c| matches!(c.kind(), "function_body" | "computed_property")).collect();
                vec![d]
            }
            "function_declaration" | "protocol_function_declaration" | "init_declaration" => {
                let init = n.kind() == "init_declaration";
                let name = if init { "init" } else { ident(n, src) };
                let mut d = Decl::new(Role::Func, name, if init { "ctor" } else { "function" }, n);
                d.vis = vis(n, src);
                d.is_static = is_static(n, src);
                let ps: Vec<Node> = children(n).into_iter().filter(|c| c.kind() == "parameter").collect();
                // keep the parameters' default values (they set the minimum argument count): text up to the body
                let from = n.child_by_field_name("name").map(|x| x.start_byte()).unwrap_or(n.start_byte());
                let to = n.child_by_field_name("body").map(|b| b.start_byte()).unwrap_or(n.end_byte()).max(from);
                d.sig = format!("func {}", squash(src[from..to].trim_end_matches(['{', ' ', '\n'])));
                for p in &ps {
                    let names = flds(*p, "name");
                    if let (Some(a), Some(t)) = (names.iter().find(|x| x.kind() == "simple_identifier"), names.iter().find(|x| x.kind() != "simple_identifier")) {
                        d.params.push((text(*a, src).to_string(), text(*t, src).to_string()));
                    }
                }
                d.ret = children(n)
                    .into_iter()
                    .filter(|c| matches!(c.kind(), "user_type" | "optional_type" | "array_type") && c.start_byte() > ps.last().map(|p| p.end_byte()).unwrap_or(0))
                    .map(|c| simple_type(text(c, src)))
                    .next()
                    .unwrap_or_default();
                d.walk = n.child_by_field_name("body").into_iter().collect();
                vec![d]
            }
            "property_declaration" => {
                if !n.parent().is_some_and(|p| p.kind() == "class_body" || p.kind() == "source_file" || p.kind() == "protocol_body") {
                    return vec![];
                }
                let name = n.child_by_field_name("name").and_then(|p| kid(p, &["simple_identifier"])).map(|x| text(x, src)).unwrap_or("");
                let mut d = Decl::new(Role::Field, name, "field", n);
                d.vis = vis(n, src);
                d.is_static = is_static(n, src);
                let t = type_of_annotation(n, src);
                d.ret = if t.is_empty() { n.child_by_field_name("value").map(|v| self.init_type(v, src)).unwrap_or_default() } else { t };
                d.sig = squash(text(n, src)).chars().take(120).collect();
                d.walk = n.child_by_field_name("value").into_iter().collect();
                vec![d]
            }
            "enum_entry" => flds(n, "name")
                .into_iter()
                .map(|x| {
                    let mut d = Decl::new(Role::Field, text(x, src), "const", n);
                    d.sig = text(x, src).to_string();
                    d
                })
                .collect(),
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let f = n.named_child(0)?;
        let suffix = kid(n, &["call_suffix"]);
        let va = suffix.and_then(|s| kid(s, &["value_arguments"]));
        let mut args: Vec<Node> = va.map(|v| named_children(v).into_iter().filter(|c| c.kind() == "value_argument").collect()).unwrap_or_default();
        let trailing = suffix.is_some_and(|s| kid(s, &["lambda_literal"]).is_some()) as i32;
        let count = args.len() as i32 + trailing;
        args.iter_mut().for_each(|a| *a = a.child_by_field_name("value").unwrap_or(*a));
        match f.kind() {
            "simple_identifier" => {
                let c = text(f, src);
                Some(Call { callee: c.to_string(), recv: None, static_type: None, kind: if c.chars().next().is_some_and(|x| x.is_uppercase()) { "new" } else { "call" }, argc: count, args })
            }
            "navigation_expression" => {
                let t = f.child_by_field_name("target")?;
                let s = f.child_by_field_name("suffix")?;
                let id = kid(s, &["simple_identifier"]).or_else(|| s.child_by_field_name("suffix"))?;
                Some(Call { callee: text(id, src).to_string(), recv: Some(t), static_type: None, kind: "call", argc: count, args })
            }
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "import_declaration" {
            return vec![];
        }
        let m = squash(text(n, src).trim_start_matches("import").trim());
        vec![ImportRow { line: line(n), callee: "*".into(), local: m.rsplit('.').next().unwrap_or("").to_string(), module: m }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() != "property_declaration" || n.parent().is_some_and(|p| p.kind() == "class_body") {
            return vec![];
        }
        let Some(nm) = n.child_by_field_name("name").and_then(|p| kid(p, &["simple_identifier"])) else { return vec![] };
        let t = type_of_annotation(n, src);
        if !t.is_empty() {
            return vec![(text(nm, src).to_string(), TypeSrc::Declared(t))];
        }
        match n.child_by_field_name("value") {
            Some(v) => vec![(text(nm, src).to_string(), TypeSrc::Init(v))],
            None => vec![],
        }
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "simple_identifier" => Expr::Ident(text(n, src).to_string()),
            "self_expression" => Expr::This,
            "navigation_expression" => {
                let (Some(t), Some(s)) = (n.child_by_field_name("target"), n.child_by_field_name("suffix")) else { return Expr::Other };
                match kid(s, &["simple_identifier"]).or_else(|| s.child_by_field_name("suffix")) {
                    Some(i) => Expr::Member(t, text(i, src).to_string()),
                    None => Expr::Other,
                }
            }
            "value_argument" => n.child_by_field_name("value").map(|v| self.expr(v, src)).unwrap_or(Expr::Other),
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        if n.kind() == "call_expression" {
            if let Some(f) = n.named_child(0) {
                if f.kind() == "simple_identifier" && text(f, src).chars().next().is_some_and(|c| c.is_uppercase()) {
                    return simple_type(text(f, src));
                }
            }
        }
        String::new()
    }
}
