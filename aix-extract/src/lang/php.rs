//! PHP (7.4 / 8.x: attributes, enums, readonly and promoted constructor properties, first-class callables, never /
//! union types) on tree-sitter-php. Variables keep their `$`; `$this->x->f()` is typed through declared property
//! types, `Type::f()` is a static call, `new T` a constructor call.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Php;

fn vis(n: Node, src: &str, default: &str) -> String {
    kid(n, &["visibility_modifier"]).map(|v| text(v, src).to_string()).unwrap_or_else(|| default.into())
}

fn annos(n: Node, src: &str) -> Vec<String> {
    let mut out = vec![];
    if let Some(al) = fld(n, "attributes").or_else(|| kid(n, &["attribute_list"])) {
        for g in named_children(al) {
            for a in named_children(g).into_iter().filter(|c| c.kind() == "attribute") {
                out.push(squash(text(a, src)));
            }
        }
    }
    out
}

fn ty(n: Option<Node>, src: &str) -> String {
    n.map(|t| simple_type(text(t, src).trim_start_matches('?').split('|').next().unwrap_or(""))).unwrap_or_default()
}

fn var(n: Option<Node>, src: &str) -> String {
    n.map(|v| text(v, src).to_string()).unwrap_or_default()
}

fn params(list: Option<Node>, src: &str) -> Vec<(String, String)> {
    let Some(l) = list else { return vec![] };
    named_children(l)
        .into_iter()
        .filter(|p| matches!(p.kind(), "simple_parameter" | "property_promotion_parameter" | "variadic_parameter"))
        .map(|p| (var(fld(p, "name"), src), fld_text(p, "type", src).to_string()))
        .collect()
}

impl Lang for Php {
    fn language(&self) -> Language {
        tree_sitter_php::LANGUAGE_PHP.into()
    }
    fn tag(&self) -> &'static str {
        "php"
    }
    fn caps_are_types(&self) -> bool {
        false
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "namespace_definition" => {
                let mut d = Decl::new(Role::Wrapper, "", "class", n);
                d.walk = fld(n, "body").map(named_children).unwrap_or_default();
                if d.walk.is_empty() {
                    // `namespace A;` form: the statements that follow are siblings and are visited by the parent
                    return vec![];
                }
                vec![d]
            }
            "class_declaration" | "interface_declaration" | "trait_declaration" | "enum_declaration" => {
                let name = fld_text(n, "name", src);
                let kind = match n.kind() {
                    "interface_declaration" => "interface",
                    "enum_declaration" => "enum",
                    _ => "class",
                };
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.annos = annos(n, src);
                d.sig = format!("{} {name}", n.kind().trim_end_matches("_declaration"));
                for c in children(n) {
                    if matches!(c.kind(), "base_clause" | "class_interface_clause") {
                        for t in named_children(c) {
                            let s = simple_type(text(t, src));
                            if !s.is_empty() {
                                d.supers.push(s);
                            }
                        }
                    }
                }
                let body = fld(n, "body");
                if let Some(b) = body {
                    // `use SomeTrait;` mixes a trait in
                    for u in named_children(b).into_iter().filter(|c| c.kind() == "use_declaration") {
                        for t in named_children(u).into_iter().filter(|c| matches!(c.kind(), "name" | "qualified_name")) {
                            let s = simple_type(text(t, src));
                            if !s.is_empty() {
                                d.supers.push(s);
                            }
                        }
                    }
                }
                d.walk = body.map(named_children).unwrap_or_default();
                vec![d]
            }
            "method_declaration" | "function_definition" => {
                let name = fld_text(n, "name", src);
                let m = n.kind() == "method_declaration";
                let body = fld(n, "body");
                let mut d = Decl::new(Role::Func, name, if name == "__construct" { "ctor" } else { "function" }, n);
                d.vis = if m { vis(n, src, "public") } else { "public".into() };
                d.annos = annos(n, src);
                d.is_static = kid(n, &["static_modifier"]).is_some();
                let pl = fld(n, "parameters");
                d.ret = ty(fld(n, "return_type"), src);
                d.sig = format!("function {name}{}", pl.map(|p| squash(text(p, src))).unwrap_or_default());
                d.params = params(pl, src);
                d.walk = body.into_iter().chain(pl).collect();
                let mut out = vec![];
                // promoted constructor parameters are properties
                if let Some(p) = pl {
                    for pp in named_children(p).into_iter().filter(|c| c.kind() == "property_promotion_parameter") {
                        let nm = var(fld(pp, "name"), src);
                        let mut f = Decl::new(Role::Field, nm.trim_start_matches('$'), "field", pp);
                        f.vis = vis(pp, src, "public");
                        f.ret = ty(fld(pp, "type"), src);
                        f.sig = squash(text(pp, src));
                        out.push(f);
                    }
                }
                out.insert(0, d);
                out
            }
            "property_declaration" => {
                let t = ty(fld(n, "type"), src);
                let is_static = kid(n, &["static_modifier"]).is_some();
                named_children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "property_element")
                    .map(|c| {
                        let nm = var(c.named_child(0), src);
                        let mut d = Decl::new(Role::Field, nm.trim_start_matches('$'), "field", n);
                        d.vis = vis(n, src, "public");
                        d.annos = annos(n, src);
                        d.is_static = is_static;
                        d.ret = t.clone();
                        d.sig = squash(text(n, src)).chars().take(120).collect();
                        d
                    })
                    .collect()
            }
            "const_declaration" => named_children(n)
                .into_iter()
                .filter(|c| c.kind() == "const_element")
                .map(|c| {
                    let mut d = Decl::new(Role::Field, c.named_child(0).map(|x| text(x, src)).unwrap_or(""), "const", n);
                    d.vis = vis(n, src, "public");
                    d.sig = squash(text(n, src)).chars().take(120).collect();
                    d
                })
                .collect(),
            "enum_case" => {
                let mut d = Decl::new(Role::Field, fld_text(n, "name", src), "const", n);
                d.sig = squash(text(n, src));
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        let args = fld(n, "arguments");
        let a = args.map(|a| named_children(a).into_iter().filter(|c| matches!(c.kind(), "argument" | "variadic_placeholder")).collect::<Vec<_>>()).unwrap_or_default();
        let argc = if text_has_spread(args, src) { -1 } else { a.len() as i32 };
        match n.kind() {
            "function_call_expression" => {
                let f = fld(n, "function")?;
                if !matches!(f.kind(), "name" | "qualified_name") {
                    return None;
                }
                let c = text(f, src).rsplit('\\').next().unwrap_or("").to_string();
                Some(Call { callee: c, recv: None, static_type: None, kind: "call", argc, args: a })
            }
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let nm = fld(n, "name")?;
                Some(Call { callee: text(nm, src).to_string(), recv: fld(n, "object"), static_type: None, kind: "call", argc, args: a })
            }
            "scoped_call_expression" => {
                let nm = fld(n, "name")?;
                let sc = fld(n, "scope")?;
                let st = match sc.kind() {
                    "relative_scope" => match text(sc, src) {
                        "self" | "static" => Some("Self".to_string()),
                        _ => None,
                    },
                    _ => Some(simple_type(text(sc, src))).filter(|s| !s.is_empty()),
                };
                Some(Call { callee: text(nm, src).to_string(), recv: None, static_type: st, kind: "call", argc, args: a })
            }
            "object_creation_expression" => {
                let c = kid(n, &["name", "qualified_name"])?;
                Some(Call { callee: simple_type(text(c, src)), recv: None, static_type: None, kind: "new", argc, args: a })
            }
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "namespace_use_clause" {
            return vec![];
        }
        let full = named_children(n).into_iter().find(|c| matches!(c.kind(), "qualified_name" | "name")).map(|c| text(c, src)).unwrap_or("");
        if full.is_empty() {
            return vec![];
        }
        let (m, name) = full.trim_start_matches('\\').rsplit_once('\\').unwrap_or(("", full));
        let alias = fld(n, "alias").map(|a| text(a, src).to_string());
        vec![ImportRow { line: line(n), callee: name.to_string(), module: m.to_string(), local: alias.unwrap_or(name.to_string()) }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if n.kind() == "assignment_expression" {
            if let (Some(l), Some(r)) = (fld(n, "left"), fld(n, "right")) {
                if l.kind() == "variable_name" {
                    return vec![(text(l, src).to_string(), TypeSrc::Init(r))];
                }
            }
        }
        vec![]
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "variable_name" => {
                let t = text(n, src);
                if t == "$this" {
                    Expr::This
                } else {
                    Expr::Ident(t.to_string())
                }
            }
            "member_access_expression" | "nullsafe_member_access_expression" => match fld(n, "object") {
                Some(o) => Expr::Member(o, fld_text(n, "name", src).to_string()),
                None => Expr::Other,
            },
            "argument" | "parenthesized_expression" => n.named_child(0).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        if n.kind() == "object_creation_expression" {
            return kid(n, &["name", "qualified_name"]).map(|c| simple_type(text(c, src))).unwrap_or_default();
        }
        String::new()
    }
}

fn text_has_spread(args: Option<Node>, src: &str) -> bool {
    args.is_some_and(|a| text(a, src).contains("..."))
}
