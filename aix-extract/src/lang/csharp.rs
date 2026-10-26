//! C# (10-12: file-scoped namespaces, records, record structs, primary constructors, required members, collection
//! expressions, global usings) on tree-sitter-c-sharp. Types come from declared types, `new T()`, `var x = new T()`,
//! `this`, primary-constructor parameters and fields; `Type.Method()` is a static call.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct CSharp;

fn mods(n: Node, src: &str) -> Vec<String> {
    children(n).into_iter().filter(|c| c.kind() == "modifier").map(|c| text(c, src).to_string()).collect()
}

fn vis(m: &[String], default: &str) -> String {
    let has = |w: &str| m.iter().any(|x| x == w);
    if has("private") {
        "private"
    } else if has("protected") {
        "protected"
    } else if has("internal") {
        "package"
    } else if has("public") {
        "public"
    } else {
        return default.into();
    }
    .into()
}

fn annos(n: Node, src: &str) -> Vec<String> {
    let mut out = vec![];
    for al in children(n).into_iter().filter(|c| c.kind() == "attribute_list") {
        for a in named_children(al).into_iter().filter(|c| c.kind() == "attribute") {
            out.push(squash(text(a, src)));
        }
    }
    out
}

fn tname(n: Option<Node>, src: &str) -> String {
    n.map(|t| simple_type(&text(t, src).replace("global::", ""))).unwrap_or_default()
}

fn params(list: Option<Node>, src: &str) -> Vec<(String, String)> {
    let Some(l) = list else { return vec![] };
    named_children(l)
        .into_iter()
        .filter(|p| p.kind() == "parameter")
        .map(|p| (fld_text(p, "name", src).to_string(), fld_text(p, "type", src).to_string()))
        .collect()
}

impl Lang for CSharp {
    fn language(&self) -> Language {
        tree_sitter_c_sharp::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "csharp"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        let in_iface = n.parent().and_then(|p| p.parent()).is_some_and(|g| g.kind() == "interface_declaration");
        match n.kind() {
            "namespace_declaration" => {
                let mut d = Decl::new(Role::Wrapper, "", "class", n);
                d.walk = fld(n, "body").map(named_children).unwrap_or_default();
                vec![d]
            }
            "class_declaration" | "struct_declaration" | "record_declaration" | "record_struct_declaration" | "interface_declaration"
            | "enum_declaration" => {
                let name = fld_text(n, "name", src);
                let kind = match n.kind() {
                    "interface_declaration" => "interface",
                    "enum_declaration" => "enum",
                    "record_declaration" | "record_struct_declaration" => "record",
                    _ => "class",
                };
                let m = mods(n, src);
                let mut d = Decl::new(Role::Type, name, kind, n);
                d.vis = vis(&m, "package");
                d.annos = annos(n, src);
                d.is_static = m.iter().any(|x| x == "static");
                let body = fld(n, "body");
                let pl = kid(n, &["parameter_list"]);
                d.sig = format!("{} {name}{}", n.kind().trim_end_matches("_declaration").replace('_', " "), pl.map(|p| squash(text(p, src))).unwrap_or_default());
                if let Some(b) = kid(n, &["base_list"]) {
                    d.supers = named_children(b)
                        .into_iter()
                        .filter(|c| !c.kind().contains("argument"))
                        .map(|c| simple_type(text(c, src).split('(').next().unwrap_or("")))
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                d.walk = body.map(named_children).unwrap_or_default();
                let mut out = vec![];
                // primary constructor parameters are visible as fields (record: public properties)
                if let Some(p) = pl {
                    for (nm, ty) in params(Some(p), src) {
                        let mut f = Decl::new(Role::Field, nm, "field", p);
                        f.container = Some(name.to_string());
                        f.ret = simple_type(&ty);
                        f.vis = if kind == "record" { "public".into() } else { "private".into() };
                        f.sig = format!("{ty} {}", f.name);
                        out.push(f);
                    }
                }
                out.insert(0, d);
                out
            }
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
                let ctor = n.kind() == "constructor_declaration";
                let name = fld_text(n, "name", src);
                let m = mods(n, src);
                let mut d = Decl::new(Role::Func, name, if ctor { "ctor" } else { "function" }, n);
                d.vis = vis(&m, if in_iface { "public" } else { "private" });
                d.annos = annos(n, src);
                d.is_static = m.iter().any(|x| x == "static");
                let pl = fld(n, "parameters");
                let rt = tname(fld(n, "returns").or_else(|| fld(n, "type")), src);
                d.ret = rt.clone();
                d.sig = format!("{}{name}{}", if rt.is_empty() { String::new() } else { format!("{rt} ") }, pl.map(|p| squash(text(p, src))).unwrap_or_default());
                d.params = params(pl, src);
                d.walk = fld(n, "body").into_iter().chain(kid(n, &["constructor_initializer"])).collect();
                vec![d]
            }
            "destructor_declaration" | "operator_declaration" | "conversion_operator_declaration" => {
                let m = mods(n, src);
                let name = if n.kind() == "destructor_declaration" {
                    format!("~{}", fld_text(n, "name", src))
                } else {
                    // `operator +` / `implicit operator int`: the text between the `operator` keyword and the parameters
                    let kw = children(n).into_iter().find(|c| c.kind() == "operator");
                    let to = fld(n, "parameters").map(|p| p.start_byte()).unwrap_or(n.end_byte());
                    let tail = kw.map(|k| src[k.end_byte()..to.max(k.end_byte())].trim().to_string()).unwrap_or_default();
                    let imp = children(n).into_iter().find(|c| matches!(text(*c, src), "implicit" | "explicit")).map(|c| text(c, src).to_string());
                    match (n.kind(), imp) {
                        ("conversion_operator_declaration", Some(i)) => format!("{i} operator {tail}"),
                        _ => format!("operator {tail}"),
                    }
                };
                let mut d = Decl::new(Role::Func, name.clone(), "function", n);
                d.vis = vis(&m, "private");
                d.annos = annos(n, src);
                d.is_static = n.kind() != "destructor_declaration";
                let pl = fld(n, "parameters");
                d.ret = tname(fld(n, "type"), src);
                d.sig = format!("{name}{}", pl.map(|p| squash(text(p, src))).unwrap_or_default());
                d.params = params(pl, src);
                d.walk = fld(n, "body").into_iter().collect();
                vec![d]
            }
            "property_declaration" => {
                let name = fld_text(n, "name", src);
                let m = mods(n, src);
                let mut d = Decl::new(Role::Field, name, "field", n);
                d.vis = vis(&m, if in_iface { "public" } else { "private" });
                d.annos = annos(n, src);
                d.is_static = m.iter().any(|x| x == "static");
                d.ret = tname(fld(n, "type"), src);
                d.sig = format!("{} {name}", fld_text(n, "type", src));
                d.walk = children(n).into_iter().filter(|c| matches!(c.kind(), "accessor_list" | "arrow_expression_clause")).collect();
                vec![d]
            }
            "field_declaration" => {
                let m = mods(n, src);
                let Some(vd) = kid(n, &["variable_declaration"]) else { return vec![] };
                let ty = tname(fld(vd, "type"), src);
                named_children(vd)
                    .into_iter()
                    .filter(|c| c.kind() == "variable_declarator")
                    .map(|c| {
                        let mut d = Decl::new(Role::Field, fld_text(c, "name", src), if m.iter().any(|x| x == "const") { "const" } else { "field" }, n);
                        d.vis = vis(&m, "private");
                        d.annos = annos(n, src);
                        d.is_static = m.iter().any(|x| x == "static");
                        d.ret = ty.clone();
                        d.sig = format!("{} {}", fld_text(vd, "type", src), d.name);
                        d.walk = named_children(c);
                        d
                    })
                    .collect()
            }
            "enum_member_declaration" => {
                let mut d = Decl::new(Role::Field, fld_text(n, "name", src), "const", n);
                d.sig = squash(text(n, src));
                vec![d]
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        match n.kind() {
            "invocation_expression" => {
                let f = fld(n, "function")?;
                let args = fld(n, "arguments");
                let (callee, recv) = match f.kind() {
                    "identifier" => (text(f, src).to_string(), None),
                    "generic_name" => (kid(f, &["identifier"]).map(|i| text(i, src).to_string())?, None),
                    "member_access_expression" | "conditional_access_expression" => {
                        let nm = fld(f, "name")?;
                        let callee = if nm.kind() == "generic_name" { kid(nm, &["identifier"]).map(|i| text(i, src))? } else { text(nm, src) };
                        (callee.to_string(), fld(f, "expression").or_else(|| f.child(0)))
                    }
                    _ => return None,
                };
                let a = args.map(|a| named_children(a).into_iter().filter(|c| c.kind() == "argument").collect::<Vec<_>>()).unwrap_or_default();
                Some(Call { callee, recv, static_type: None, kind: "call", argc: a.len() as i32, args: a })
            }
            "object_creation_expression" => {
                let t = fld(n, "type")?;
                let args = fld(n, "arguments");
                let a = args.map(|a| named_children(a).into_iter().filter(|c| c.kind() == "argument").collect::<Vec<_>>()).unwrap_or_default();
                Some(Call { callee: simple_type(text(t, src)), recv: None, static_type: None, kind: "new", argc: a.len() as i32, args: a })
            }
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "using_directive" {
            return vec![];
        }
        let alias = fld(n, "name").map(|a| text(a, src).to_string());
        let target = named_children(n).into_iter().rev().find(|c| matches!(c.kind(), "identifier" | "qualified_name" | "alias_qualified_name" | "generic_name"));
        let Some(t) = target else { return vec![] };
        let full = text(t, src);
        match alias {
            Some(a) => {
                let (m, name) = full.rsplit_once('.').unwrap_or(("", full));
                vec![ImportRow { line: line(n), callee: name.to_string(), module: m.to_string(), local: a }]
            }
            None => vec![ImportRow { line: line(n), callee: "*".into(), module: full.to_string(), local: "*".into() }],
        }
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        match n.kind() {
            "variable_declaration" if n.parent().is_some_and(|p| matches!(p.kind(), "local_declaration_statement" | "for_statement" | "using_statement" | "using_declaration")) => {
                let ty = fld(n, "type");
                let implicit = ty.is_none_or(|t| t.kind() == "implicit_type");
                named_children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "variable_declarator")
                    .filter_map(|c| {
                        let nm = fld_text(c, "name", src).to_string();
                        if !implicit {
                            return Some((nm, TypeSrc::Declared(text(ty.unwrap(), src).to_string())));
                        }
                        named_children(c).into_iter().find(|x| x.kind() != "identifier").map(|e| (nm, TypeSrc::Init(e)))
                    })
                    .collect()
            }
            "declaration_expression" | "catch_declaration" => vec![],
            _ => vec![],
        }
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "this_expression" => Expr::This,
            "member_access_expression" => {
                let obj = fld(n, "expression").or_else(|| n.child(0));
                match obj {
                    Some(o) if o.kind() == "this" || text(o, src) == "this" => Expr::Member(o, fld_text(n, "name", src).to_string()),
                    Some(o) => Expr::Member(o, fld_text(n, "name", src).to_string()),
                    None => Expr::Other,
                }
            }
            "this" => Expr::This,
            "argument" | "parenthesized_expression" | "await_expression" | "cast_expression" => {
                n.named_child(n.named_child_count().saturating_sub(1) as u32).map(|c| self.expr(c, src)).unwrap_or(Expr::Other)
            }
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        match n.kind() {
            "object_creation_expression" => fld(n, "type").map(|t| simple_type(text(t, src))).unwrap_or_default(),
            "await_expression" | "parenthesized_expression" => n.named_child(0).map(|c| self.init_type(c, src)).unwrap_or_default(),
            "equals_value_clause" => n.named_child(0).map(|c| self.init_type(c, src)).unwrap_or_default(),
            "cast_expression" | "as_expression" => fld(n, "type").map(|t| simple_type(text(t, src))).unwrap_or_default(),
            _ => String::new(),
        }
    }
}
