//! Spring MVC: `@RequestMapping` on the class, `@Get/Post/Put/Delete/PatchMapping` and `@RequestMapping(method=)` on
//! methods, `value`/`path` arrays, and `@PreAuthorize` / `@Secured` / `@RolesAllowed` as roles.

use std::collections::HashMap;

use tree_sitter::Node;

use super::*;
use crate::ts_util::*;

ext_impl!(Spring, "spring", |p| ext_of(p) == "java", extract_file);

fn extract_file(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    if !(t.contains("Mapping") && (t.contains("Controller") || t.contains("RequestMapping"))) {
        return;
    }
    let Some(tree) = parse(&java(), t) else { return };
    let root = tree.root_node();
    let mut consts: HashMap<String, String> = HashMap::new();
    walk(root, |n| {
        if n.kind() == "field_declaration" {
            for d in named_children(n) {
                if d.kind() == "variable_declarator" {
                    if let (Some(nm), Some(v)) = (d.child_by_field_name("name"), d.child_by_field_name("value")) {
                        if let Some(s) = java_string(v, t) {
                            consts.insert(text(nm, t).to_string(), s);
                        }
                    }
                }
            }
        }
        true
    });
    for n in named_children(root) {
        class(n, f, &consts, rows);
    }
}

struct Anno<'a> {
    name: String,
    args: Vec<(String, Node<'a>)>,
}

fn annos<'a>(decl: Node<'a>, src: &str) -> Vec<Anno<'a>> {
    let mut out = vec![];
    let Some(mods) = named_children(decl).into_iter().find(|c| c.kind() == "modifiers") else { return out };
    for m in children(mods) {
        if !matches!(m.kind(), "marker_annotation" | "annotation") {
            continue;
        }
        let name = m.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
        let name = name.rsplit('.').next().unwrap_or(name).to_string();
        let mut args = vec![];
        if let Some(a) = m.child_by_field_name("arguments") {
            for c in named_children(a) {
                if c.kind() == "element_value_pair" {
                    if let (Some(k), Some(v)) = (c.child_by_field_name("key"), c.child_by_field_name("value")) {
                        args.push((text(k, src).to_string(), v));
                    }
                } else {
                    args.push(("value".into(), c));
                }
            }
        }
        out.push(Anno { name, args });
    }
    out
}

/// All string values an annotation argument can denote: literals, concatenations, array initialisers, constants.
fn strings(n: Node, src: &str, consts: &HashMap<String, String>) -> Vec<String> {
    match n.kind() {
        "string_literal" => java_string(n, src).into_iter().collect(),
        "element_value_array_initializer" => {
            named_children(n).into_iter().flat_map(|c| strings(c, src, consts)).collect()
        }
        "binary_expression" => {
            let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) else {
                return vec![];
            };
            let (ls, rs) = (strings(l, src, consts), strings(r, src, consts));
            let mut out = vec![];
            for a in &ls {
                for b in &rs {
                    out.push(format!("{a}{b}"));
                }
            }
            out
        }
        "identifier" | "field_access" => {
            let t = text(n, src);
            let k = t.rsplit('.').next().unwrap_or(t);
            consts.get(k).cloned().into_iter().collect()
        }
        "parenthesized_expression" => n.named_child(0).map(|c| strings(c, src, consts)).unwrap_or_default(),
        _ => vec![],
    }
}

fn arg<'a>(a: &Anno<'a>, keys: &[&str]) -> Option<Node<'a>> {
    a.args.iter().find(|(k, _)| keys.contains(&k.as_str())).map(|(_, v)| *v)
}

/// Quoted role names inside a SpEL expression: `hasRole('ADMIN')`, `hasAnyRole('A','B')`, `hasAuthority("x")`.
fn spel_roles(expr: &str) -> Vec<String> {
    let mut out = vec![];
    if expr.contains("permitAll") {
        return vec!["public".into()];
    }
    if expr.contains("denyAll") {
        return vec!["!deny".into()];
    }
    for key in ["hasRole", "hasAnyRole", "hasAuthority", "hasAnyAuthority"] {
        let mut rest = expr;
        while let Some(i) = rest.find(key) {
            let after = &rest[i + key.len()..];
            let Some(open) = after.find('(') else { break };
            let Some(close) = after[open..].find(')') else { break };
            for part in after[open + 1..open + close].split(',') {
                let r = part.trim().trim_matches(['\'', '"']);
                if !r.is_empty() {
                    out.push(r.trim_start_matches("ROLE_").to_string());
                }
            }
            rest = &after[open + close..];
        }
    }
    if out.is_empty() && (expr.contains("isAuthenticated") || expr.contains("authenticated")) {
        out.push("authenticated".into());
    }
    out
}

fn roles_of(list: &[Anno], src: &str, consts: &HashMap<String, String>) -> Option<Vec<String>> {
    for a in list {
        match a.name.as_str() {
            "PreAuthorize" | "PostAuthorize" => {
                let e: Vec<String> = a.args.iter().flat_map(|(_, v)| strings(*v, src, consts)).collect();
                let r: Vec<String> = e.iter().flat_map(|x| spel_roles(x)).collect();
                return Some(if r.is_empty() {
                    vec![format!("expr:{}", e.join(" ").chars().take(60).collect::<String>())]
                } else {
                    r
                });
            }
            "Secured" | "RolesAllowed" => {
                let r: Vec<String> = a
                    .args
                    .iter()
                    .flat_map(|(_, v)| strings(*v, src, consts))
                    .map(|x| x.trim_start_matches("ROLE_").to_string())
                    .collect();
                return Some(r);
            }
            "PermitAll" | "AnonymousAllowed" => return Some(vec!["public".into()]),
            "DenyAll" => return Some(vec!["!deny".into()]),
            _ => {}
        }
    }
    None
}

fn methods_of(a: &Anno, src: &str) -> Vec<String> {
    match a.name.as_str() {
        "GetMapping" => vec!["GET".into()],
        "PostMapping" => vec!["POST".into()],
        "PutMapping" => vec!["PUT".into()],
        "DeleteMapping" => vec!["DELETE".into()],
        "PatchMapping" => vec!["PATCH".into()],
        "RequestMapping" => {
            let Some(m) = arg(a, &["method"]) else { return vec![] };
            let mut out = vec![];
            walk(m, |c| {
                if matches!(c.kind(), "identifier") {
                    let t = text(c, src);
                    if matches!(t, "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS") {
                        out.push(t.to_string());
                    }
                }
                true
            });
            out
        }
        _ => vec![],
    }
}

fn is_mapping(name: &str) -> bool {
    matches!(name, "GetMapping" | "PostMapping" | "PutMapping" | "DeleteMapping" | "PatchMapping" | "RequestMapping")
}

fn class(n: Node, f: &SourceFile, consts: &HashMap<String, String>, rows: &mut Rows) {
    if !matches!(n.kind(), "class_declaration" | "interface_declaration") {
        return;
    }
    let src = &f.text;
    let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else { return };
    let ca = annos(n, src);
    if ca.iter().any(|a| a.name == "FeignClient" || a.name == "HttpExchange") {
        return;
    }
    let prefixes: Vec<String> = ca
        .iter()
        .find(|a| a.name == "RequestMapping")
        .and_then(|a| arg(a, &["value", "path"]).map(|v| strings(v, src, consts)))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec![String::new()]);
    let class_roles = roles_of(&ca, src, consts);
    let Some(body) = n.child_by_field_name("body") else { return };
    for m in named_children(body) {
        match m.kind() {
            "method_declaration" => {
                let ma = annos(m, src);
                let Some(map) = ma.iter().find(|a| is_mapping(&a.name)) else { continue };
                let Some(hname) = m.child_by_field_name("name").map(|x| text(x, src).to_string()) else { continue };
                let mut methods = methods_of(map, src);
                if methods.is_empty() {
                    methods = vec!["ANY".into()];
                }
                let paths: Vec<String> = arg(map, &["value", "path"])
                    .map(|v| strings(v, src, consts))
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| vec![String::new()]);
                let roles = roles_of(&ma, src, consts).or_else(|| class_roles.clone()).unwrap_or_default();
                for pre in &prefixes {
                    for p in &paths {
                        for me in &methods {
                            push_ep(
                                rows,
                                Ep {
                                    file: &f.path,
                                    line: line(m),
                                    method: me,
                                    path: &join(pre, p),
                                    class: &name,
                                    handler: &hname,
                                    roles: roles.clone(),
                                },
                            );
                        }
                    }
                }
            }
            "class_declaration" => class(m, f, consts, rows),
            _ => {}
        }
    }
}
