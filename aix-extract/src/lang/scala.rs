//! Scala (2.13 / 3: case classes, traits, objects, enums, givens, extension methods, braceless syntax) on
//! tree-sitter-scala: symbol level. Types, defs, vals, imports, calls with typed / `this` / object receivers, `new T`.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Scala;

fn vis(n: Node, src: &str) -> String {
    kid(n, &["modifiers"])
        .and_then(|m| named_children(m).into_iter().find(|c| c.kind() == "access_modifier"))
        .map(|c| if text(c, src).starts_with("private") { "private" } else { "protected" }.to_string())
        .unwrap_or_else(|| "public".into())
}

fn has_mod(n: Node, src: &str, w: &str) -> bool {
    kid(n, &["modifiers"]).is_some_and(|m| text(m, src).split_whitespace().any(|x| x == w))
}

fn params(list: Option<Node>, src: &str) -> Vec<(String, String)> {
    let Some(l) = list else { return vec![] };
    named_children(l).into_iter().filter(|p| matches!(p.kind(), "parameter" | "class_parameter")).map(|p| (fld_text(p, "name", src).to_string(), fld_text(p, "type", src).to_string())).collect()
}

impl Lang for Scala {
    fn language(&self) -> Language {
        tree_sitter_scala::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "scala"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "class_definition" | "trait_definition" | "object_definition" | "enum_definition" => {
                let name = fld_text(n, "name", src);
                let kind = match n.kind() {
                    "trait_definition" => "interface",
                    "enum_definition" => "enum",
                    "class_definition" if children(n).iter().any(|c| c.kind() == "case") || has_mod(n, src, "case") => "record",
                    _ => "class",
                };
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.vis = vis(n, src);
                let cp = fld(n, "class_parameters");
                d.sig = format!("{kind} {name}{}", cp.map(|p| squash(text(p, src))).unwrap_or_default());
                if let Some(e) = fld(n, "extend") {
                    d.supers = flds(e, "type").into_iter().map(|t| simple_type(text(t, src))).filter(|s| !s.is_empty() && s != "with").collect();
                }
                d.walk = fld(n, "body").map(named_children).unwrap_or_default();
                let mut out = vec![];
                if let Some(c) = cp {
                    for p in named_children(c).into_iter().filter(|p| p.kind() == "class_parameter") {
                        let t = squash(text(p, src));
                        {
                            let mut f = Decl::new(Role::Field, fld_text(p, "name", src), "field", p);
                            f.container = Some(name.to_string());
                            f.ret = simple_type(fld_text(p, "type", src));
                            if kind != "record" && !t.contains("val ") && !t.contains("var ") {
                                f.vis = "private".into();
                            }
                            f.sig = t;
                            out.push(f);
                        }
                    }
                }
                out.insert(0, d);
                out
            }
            "function_definition" | "function_declaration" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Func, name, "function", n);
                d.vis = vis(n, src);
                let pl = fld(n, "parameters");
                d.sig = format!("def {name}{}", pl.map(|p| squash(text(p, src))).unwrap_or_default());
                d.params = params(pl, src);
                d.ret = simple_type(fld_text(n, "return_type", src));
                d.walk = fld(n, "body").into_iter().collect();
                vec![d]
            }
            "val_definition" | "var_definition" | "val_declaration" | "var_declaration" => {
                if !n.parent().is_some_and(|p| matches!(p.kind(), "template_body" | "compilation_unit")) {
                    return vec![];
                }
                let p = fld(n, "pattern");
                let name = p.filter(|p| p.kind() == "identifier").map(|p| text(p, src)).unwrap_or("");
                if name.is_empty() {
                    return vec![];
                }
                let mut d = Decl::new(Role::Field, name, if n.parent().is_some_and(|p| p.kind() == "compilation_unit") { "const" } else { "field" }, n);
                d.vis = vis(n, src);
                let t = fld_text(n, "type", src);
                d.ret = if t.is_empty() { fld(n, "value").map(|v| self.init_type(v, src)).unwrap_or_default() } else { simple_type(t) };
                d.sig = squash(text(n, src)).chars().take(120).collect();
                d.walk = fld(n, "value").into_iter().collect();
                vec![d]
            }
            "simple_enum_case" => {
                let mut d = Decl::new(Role::Field, fld_text(n, "name", src), "const", n);
                d.sig = squash(text(n, src));
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        match n.kind() {
            "call_expression" => {
                let f = fld(n, "function")?;
                let args = fld(n, "arguments");
                let a = arg_nodes(args);
                let (callee, recv) = match f.kind() {
                    "identifier" => (text(f, src).to_string(), None),
                    "field_expression" => (fld_text(f, "field", src).to_string(), fld(f, "value")),
                    "generic_function" => (fld(f, "function").map(|x| text(x, src).to_string())?, None),
                    _ => return None,
                };
                Some(Call { callee, recv, static_type: None, kind: "call", argc: a.len() as i32, args: a })
            }
            "instance_expression" => {
                let t = kid(n, &["type_identifier", "generic_type", "stable_type_identifier"])?;
                let a = arg_nodes(fld(n, "arguments"));
                Some(Call { callee: simple_type(text(t, src)), recv: None, static_type: None, kind: "new", argc: a.len() as i32, args: a })
            }
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "import_declaration" {
            return vec![];
        }
        let path: Vec<String> = flds(n, "path").into_iter().filter(|p| p.is_named()).map(|p| text(p, src).to_string()).collect();
        let module = path.join(".");
        if let Some(sel) = kid(n, &["namespace_selectors"]) {
            return named_children(sel)
                .into_iter()
                .map(|s| match s.kind() {
                    "arrow_renamed_identifier" => ImportRow { line: line(n), callee: fld_text(s, "name", src).into(), module: module.clone(), local: fld_text(s, "alias", src).into() },
                    _ => ImportRow { line: line(n), callee: text(s, src).into(), module: module.clone(), local: text(s, src).into() },
                })
                .collect();
        }
        let (m, name) = module.rsplit_once('.').unwrap_or(("", &module));
        vec![ImportRow { line: line(n), callee: name.to_string(), module: m.to_string(), local: name.to_string() }]
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        if !matches!(n.kind(), "val_definition" | "var_definition") || n.parent().is_some_and(|p| matches!(p.kind(), "template_body" | "compilation_unit")) {
            return vec![];
        }
        let Some(p) = fld(n, "pattern").filter(|p| p.kind() == "identifier") else { return vec![] };
        if let Some(t) = fld(n, "type") {
            return vec![(text(p, src).to_string(), TypeSrc::Declared(text(t, src).to_string()))];
        }
        fld(n, "value").map(|v| vec![(text(p, src).to_string(), TypeSrc::Init(v))]).unwrap_or_default()
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" if text(n, src) == "this" => Expr::This,
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "field_expression" => match fld(n, "value") {
                Some(v) => Expr::Member(v, fld_text(n, "field", src).to_string()),
                None => Expr::Other,
            },
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        match n.kind() {
            "instance_expression" => kid(n, &["type_identifier", "generic_type"]).map(|t| simple_type(text(t, src))).unwrap_or_default(),
            "call_expression" => match fld(n, "function") {
                Some(f) if f.kind() == "identifier" && text(f, src).chars().next().is_some_and(|c| c.is_uppercase()) => simple_type(text(f, src)),
                _ => String::new(),
            },
            _ => String::new(),
        }
    }
}
