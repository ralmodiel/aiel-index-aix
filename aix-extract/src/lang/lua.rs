//! Lua (5.1 - 5.4, LuaJIT) on tree-sitter-lua: symbol level. `function M.f` / `function M:m` / `M.f = function`
//! become members of the table `M`; `require` is an import; calls with `self`, `M.f()` and `obj:m()` receivers.

use tree_sitter::{Language, Node};

use super::engine::*;
use super::*;
use crate::ts_util::*;

pub struct Lua;

fn params(n: Node, src: &str) -> (Vec<(String, String)>, String) {
    let Some(p) = fld(n, "parameters") else { return (vec![], "()".into()) };
    let names: Vec<String> = named_children(p).into_iter().map(|x| text(x, src).to_string()).collect();
    (names.iter().map(|x| (x.clone(), String::new())).collect(), format!("({})", names.join(", ")))
}

impl Lang for Lua {
    fn language(&self) -> Language {
        tree_sitter_lua::LANGUAGE.into()
    }
    fn tag(&self) -> &'static str {
        "lua"
    }
    fn caps_are_types(&self) -> bool {
        false
    }
    fn synthesize_containers(&self) -> bool {
        true
    }

    fn decls<'t>(&self, n: Node<'t>, src: &str) -> Vec<Decl<'t>> {
        match n.kind() {
            "function_declaration" => {
                let nm = fld(n, "name");
                let (cont, name, stat) = match nm {
                    Some(x) if x.kind() == "dot_index_expression" => (Some(fld_text(x, "table", src).to_string()), fld_text(x, "field", src).to_string(), true),
                    Some(x) if x.kind() == "method_index_expression" => (Some(fld_text(x, "table", src).to_string()), fld_text(x, "method", src).to_string(), false),
                    Some(x) => (None, text(x, src).to_string(), false),
                    None => return vec![],
                };
                let local = text(n, src).starts_with("local ") || n.parent().is_some_and(|p| p.kind() == "local_declaration") || children(n).iter().any(|c| c.kind() == "local");
                let mut d = Decl::new(Role::Func, name.clone(), "function", n);
                d.container = cont;
                d.is_static = stat && d.container.is_some();
                d.vis = if local { "private".into() } else { "public".into() };
                if let Some(p) = n.parent().filter(|p| p.kind() == "local_declaration") {
                    d.start = p;
                }
                let (ps, ptxt) = params(n, src);
                d.params = ps;
                d.sig = format!("function {name}{ptxt}");
                d.walk = fld(n, "body").into_iter().collect();
                vec![d]
            }
            // M.f = function(...) ... end
            "assignment_statement" => {
                let (Some(vl), Some(el)) = (kid(n, &["variable_list"]), kid(n, &["expression_list"])) else { return vec![] };
                let (vars, vals) = (named_children(vl), named_children(el));
                let mut out = vec![];
                for (v, e) in vars.iter().zip(vals.iter()) {
                    // `x = x or function() end`: the function on the right of an `or`
                    let e = if e.kind() == "binary_expression" && fld(*e, "right").is_some_and(|r| r.kind() == "function_definition") && text(*e, src).contains(" or ") {
                        fld(*e, "right").unwrap()
                    } else {
                        *e
                    };
                    if e.kind() == "function_definition" && matches!(v.kind(), "dot_index_expression" | "identifier") {
                        let (cont, name, stat) = if v.kind() == "identifier" {
                            (None, text(*v, src).to_string(), false)
                        } else {
                            (Some(fld_text(*v, "table", src).to_string()), fld_text(*v, "field", src).to_string(), true)
                        };
                        let mut d = Decl::new(Role::Func, name, "function", n);
                        d.container = cont;
                        d.is_static = stat;
                        let (ps, ptxt) = params(e, src);
                        d.params = ps;
                        d.sig = format!("function {}{ptxt}", d.name);
                        d.walk = fld(e, "body").into_iter().collect();
                        out.push(d);
                    }
                }
                out
            }
            _ => vec![],
        }
    }

    fn call<'t>(&self, n: Node<'t>, src: &str) -> Option<Call<'t>> {
        if n.kind() != "function_call" {
            return None;
        }
        let f = fld(n, "name")?;
        let args = fld(n, "arguments");
        let a = args.map(|a| named_children(a).into_iter().filter(|c| !c.kind().contains("comment")).collect::<Vec<_>>()).unwrap_or_default();
        let argc = a.len() as i32;
        match f.kind() {
            "identifier" => {
                let c = text(f, src);
                if matches!(c, "require" | "setmetatable" | "pairs" | "ipairs" | "print" | "type" | "tostring" | "tonumber" | "pcall" | "error" | "assert" | "select" | "next" | "rawget" | "rawset") {
                    return None;
                }
                Some(Call { callee: c.to_string(), recv: None, static_type: None, kind: "call", argc, args: a })
            }
            "dot_index_expression" => Some(Call { callee: fld_text(f, "field", src).to_string(), recv: fld(f, "table"), static_type: None, kind: "call", argc, args: a }),
            "method_index_expression" => Some(Call { callee: fld_text(f, "method", src).to_string(), recv: fld(f, "table"), static_type: None, kind: "call", argc, args: a }),
            _ => None,
        }
    }

    fn imports(&self, n: Node, src: &str) -> Vec<ImportRow> {
        if n.kind() != "function_call" || fld_text(n, "name", src) != "require" {
            return vec![];
        }
        let Some(s) = fld(n, "arguments").and_then(|a| named_children(a).into_iter().next()) else { return vec![] };
        let module = text(s, src).trim_matches(['"', '\'', '(', ')']).trim_start_matches("[[").trim_end_matches("]]").to_string();
        // `local json = require("json")` binds `json`
        let mut local = module.rsplit(['.', '/']).next().unwrap_or("").to_string();
        let mut p = n.parent();
        while let Some(x) = p {
            if x.kind() == "assignment_statement" {
                if let Some(v) = kid(x, &["variable_list"]).and_then(|v| v.named_child(0)) {
                    local = text(v, src).to_string();
                }
                break;
            }
            if matches!(x.kind(), "block" | "chunk") {
                break;
            }
            p = x.parent();
        }
        vec![ImportRow { line: line(n), callee: "*".into(), module, local }]
    }

    fn expr<'t>(&self, n: Node<'t>, src: &str) -> Expr<'t> {
        match n.kind() {
            "identifier" if text(n, src) == "self" => Expr::This,
            "identifier" => Expr::Ident(text(n, src).to_string()),
            "dot_index_expression" => match fld(n, "table") {
                Some(t) => Expr::Member(t, fld_text(n, "field", src).to_string()),
                None => Expr::Other,
            },
            _ => Expr::Other,
        }
    }
}
