//! Go (1.18-1.23: generics, range-over-int, range-over-func) on tree-sitter-go. Receiver types come from method
//! receivers, parameters, struct fields (embedded types become supers), `x := &T{}`, `var x T`, `x := y.(*T)` and
//! `x := NewT()` (recorded as `ret:NewT` for the resolver to look up the declared result type).

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Go;

fn is_builtin_call(n: &str) -> bool {
    matches!(
        n,
        "append" | "len" | "cap" | "make" | "new" | "copy" | "delete" | "panic" | "recover" | "print" | "println" | "close"
            | "string" | "int" | "int8" | "int16" | "int32" | "int64" | "uint" | "uint8" | "uint16" | "uint32" | "uint64"
            | "float32" | "float64" | "byte" | "rune" | "bool" | "complex" | "real" | "imag" | "min" | "max" | "clear"
    )
}

fn params_of<'t>(list: Option<Node<'t>>, src: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let Some(list) = list else { return out };
    for p in named_children(list) {
        if !matches!(p.kind(), "parameter_declaration" | "variadic_parameter_declaration") {
            continue;
        }
        let ty = fld_text(p, "type", src).to_string();
        for nm in flds(p, "name") {
            out.push((text(nm, src).to_string(), ty.clone()));
        }
    }
    out
}

fn first_result(r: Option<Node>, src: &str) -> String {
    match r {
        None => String::new(),
        Some(r) if r.kind() == "parameter_list" => {
            named_children(r).first().map(|p| simple_type(fld_text(*p, "type", src))).unwrap_or_default()
        }
        Some(r) => simple_type(text(r, src)),
    }
}

impl Lang for Go {
    fn language(&self) -> Language {
        tree_sitter_go::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "go"
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        let vis = |name: &str| if caps_first(name) { "public" } else { "private" };
        match n.kind() {
            "type_spec" | "type_alias" => {
                let name = fld_text(n, "name", src);
                let ty = fld(n, "type");
                let (kind, role) = match ty.map(|t| t.kind()) {
                    Some("struct_type") => ("class", Role::Type),
                    Some("interface_type") => ("interface", Role::Type),
                    _ => ("type", Role::Field),
                };
                let mut d = Decl::new(role, name, kind, n);
                d.vis = vis(name).into();
                d.sig = format!("type {name} {}", ty.map(|t| t.kind().trim_end_matches("_type")).unwrap_or(""));
                if matches!(d.role, Role::Type) {
                    let body = ty.unwrap();
                    d.walk = children(body).into_iter().flat_map(|c| if c.kind() == "field_declaration_list" { children(c) } else { vec![c] }).collect();
                    // embedded types promote their members: they act as supers
                    for c in &d.walk {
                        if c.kind() == "field_declaration" && fld(*c, "name").is_none() {
                            let t = simple_type(fld_text(*c, "type", src));
                            if !t.is_empty() {
                                d.supers.push(t);
                            }
                        }
                        if c.kind() == "type_elem" || c.kind() == "struct_elem" {
                            let t = simple_type(text(*c, src));
                            if !t.is_empty() && kind == "interface" {
                                d.supers.push(t);
                            }
                        }
                    }
                    d.walk.retain(|c| !matches!(c.kind(), "{" | "}"));
                    // an interface lists its method names in the signature: the resolver matches implementations
                    // (Go types implement an interface implicitly, by having its methods)
                    if kind == "interface" {
                        let ms: Vec<&str> = d.walk.iter().filter(|c| c.kind() == "method_elem").map(|c| fld_text(*c, "name", src)).collect();
                        if !ms.is_empty() {
                            d.sig = format!("type {name} interface {{ {} }}", ms.join("; "));
                        }
                    }
                    if d.walk.is_empty() {
                        d.walk = vec![body];
                    }
                } else {
                    d.walk = vec![];
                    d.ret = String::new();
                    d.hidden = true;
                }
                vec![d]
            }
            "field_declaration" => {
                let ty = fld_text(n, "type", src);
                flds(n, "name")
                    .into_iter()
                    .map(|nm| {
                        let name = text(nm, src);
                        let mut d = Decl::new(Role::Field, name, "field", n);
                        d.vis = vis(name).into();
                        d.ret = simple_type(ty);
                        d.ty_raw = ty.to_string();
                        d.hidden = true;
                        d.sig = format!("{name} {ty}");
                        d
                    })
                    .collect()
            }
            "method_elem" => {
                let name = fld_text(n, "name", src);
                let mut d = Decl::new(Role::Func, name, "method", n);
                d.vis = vis(name).into();
                d.sig = format!("{name}{}", fld_text(n, "parameters", src));
                d.ret = first_result(fld(n, "result"), src);
                d.walk = vec![];
                vec![d]
            }
            "function_declaration" | "method_declaration" => {
                let name = fld_text(n, "name", src);
                let method = n.kind() == "method_declaration";
                let mut d = Decl::new(Role::Func, name, if method { "method" } else { "function" }, n);
                d.vis = vis(name).into();
                let body = fld(n, "body");
                d.sig = header(n, body, src);
                d.ret = first_result(fld(n, "result"), src);
                d.params = params_of(fld(n, "parameters"), src);
                if method {
                    if let Some(r) = fld(n, "receiver") {
                        if let Some(p) = named_children(r).first() {
                            let t = simple_type(fld_text(*p, "type", src));
                            if !t.is_empty() {
                                d.container = Some(t);
                            }
                            if let Some(nm) = fld(*p, "name") {
                                d.this_var = Some(text(nm, src).to_string());
                            }
                        }
                    }
                }
                d.walk = body.into_iter().chain(fld(n, "parameters")).collect();
                vec![d]
            }
            // package-level constants and variables (not the ones inside a function)
            "const_spec" | "var_spec" => {
                let top = n.parent().is_some_and(|p| p.kind() == "source_file" || p.parent().is_some_and(|g| g.kind() == "source_file") || p.kind().ends_with("_spec_list") && p.parent().and_then(|g| g.parent()).is_some_and(|g| g.kind() == "source_file"));
                if !top {
                    return vec![];
                }
                let ty = fld_text(n, "type", src);
                flds(n, "name")
                    .into_iter()
                    .map(|nm| {
                        let name = text(nm, src);
                        let mut d = Decl::new(Role::Field, name, "const", n);
                        d.vis = vis(name).into();
                        d.ret = simple_type(ty);
                        d.ty_raw = ty.to_string();
                        d.hidden = true;
                        d.sig = header(n, None, src);
                        d.walk = fld(n, "value").into_iter().collect();
                        d
                    })
                    .collect()
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "call_expression" {
            return None;
        }
        let mut f = fld(n, "function")?;
        // NewStack[int](): an index expression over the function name
        while matches!(f.kind(), "index_expression" | "parenthesized_expression" | "type_instantiation_expression") {
            f = fld(f, "operand").or_else(|| f.named_child(0))?;
        }
        let args = fld(n, "arguments");
        let (callee, recv) = match f.kind() {
            "identifier" => (text(f, src).to_string(), None),
            "selector_expression" => (fld_text(f, "field", src).to_string(), fld(f, "operand")),
            _ => return None,
        };
        if recv.is_none() && is_builtin_call(&callee) {
            return None;
        }
        Some(Call { callee, recv, static_type: None, kind: "call", argc: argc(args, src), args: arg_nodes(args) })
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "import_spec" {
            return vec![];
        }
        let path = fld_text(n, "path", src).trim_matches(['"', '`']).to_string();
        if path.is_empty() {
            return vec![];
        }
        let mut last = path.rsplit('/').next().unwrap_or("").to_string();
        if last.len() > 1 && last.starts_with('v') && last[1..].chars().all(|c| c.is_ascii_digit()) {
            last = path.rsplit('/').nth(1).unwrap_or("").to_string(); // .../chi/v5 -> chi
        }
        let alias = fld(n, "name").map(|a| text(a, src).to_string()).unwrap_or(last);
        if alias == "_" || alias == "." {
            return vec![];
        }
        vec![ImportRow { line: line(n), callee: "*".into(), module: path, local: alias }]
    }

    fn closure_params(&self, n: Node, src: &str) -> Option<Vec<(String, String)>> {
        (n.kind() == "func_literal").then(|| params_of(fld(n, "parameters"), src))
    }

    fn locals<'t>(&self, n: Node<'t>, src: &str) -> Vec<(String, TypeSrc<'t>)> {
        match n.kind() {
            "short_var_declaration" | "assignment_statement" => {
                let (Some(l), Some(r)) = (fld(n, "left"), fld(n, "right")) else { return vec![] };
                if n.kind() == "assignment_statement" && fld_text(n, "operator", src) != "=" {
                    return vec![];
                }
                let (ls, rs) = (named_children(l), named_children(r));
                if ls.len() == rs.len() {
                    ls.into_iter()
                        .zip(rs)
                        .filter(|(a, _)| a.kind() == "identifier")
                        .map(|(a, b)| (text(a, src).to_string(), TypeSrc::Init(b)))
                        .collect()
                } else if rs.len() == 1 && !ls.is_empty() && ls[0].kind() == "identifier" {
                    vec![(text(ls[0], src).to_string(), TypeSrc::Init(rs[0]))]
                } else {
                    vec![]
                }
            }
            "var_spec" => {
                let names: Vec<String> = flds(n, "name").into_iter().map(|x| text(x, src).to_string()).collect();
                if let Some(t) = fld(n, "type") {
                    names.into_iter().map(|nm| (nm, TypeSrc::Declared(text(t, src).to_string()))).collect()
                } else if let Some(v) = fld(n, "value") {
                    let vs = named_children(v);
                    names.into_iter().zip(vs).map(|(nm, e)| (nm, TypeSrc::Init(e))).collect()
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" | "type_identifier" => Expr::Ident(text(n, src).to_string()),
            "selector_expression" => match fld(n, "operand") {
                Some(o) => Expr::Member(o, fld_text(n, "field", src).to_string()),
                None => Expr::Other,
            },
            "parenthesized_expression" => n.named_child(0).map(|c| self.expr(c, src)).unwrap_or(Expr::Other),
            "unary_expression" if text(n, src).starts_with('&') => {
                fld(n, "operand").map(|c| self.expr(c, src)).unwrap_or(Expr::Other)
            }
            _ => Expr::Other,
        }
    }

    fn init_type(&self, n: Node, src: &str) -> String {
        match n.kind() {
            "unary_expression" => fld(n, "operand").map(|o| self.init_type(o, src)).unwrap_or_default(),
            "parenthesized_expression" => n.named_child(0).map(|o| self.init_type(o, src)).unwrap_or_default(),
            "composite_literal" => {
                fld(n, "type").map(|t| text(t, src).to_string()).unwrap_or_default()
            }
            "type_assertion_expression" => fld_text(n, "type", src).to_string(),
            "call_expression" => {
                let Some(mut f) = fld(n, "function") else { return String::new() };
                while matches!(f.kind(), "index_expression" | "parenthesized_expression") {
                    match fld(f, "operand").or_else(|| f.named_child(0)) {
                        Some(x) => f = x,
                        None => return String::new(),
                    }
                }
                let name = match f.kind() {
                    "identifier" => text(f, src),
                    // pkg.NewT(): only when the operand is a plain package name
                    "selector_expression" if fld(f, "operand").is_some_and(|o| o.kind() == "identifier") => fld_text(f, "field", src),
                    _ => return String::new(),
                };
                if name == "new" {
                    return fld(n, "arguments").and_then(|a| a.named_child(0)).map(|t| text(t, src).to_string()).unwrap_or_default();
                }
                if is_builtin_call(name) {
                    return String::new();
                }
                format!("ret:{name}")
            }
            _ => String::new(),
        }
    }
}

fn caps_first(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_uppercase())
}
