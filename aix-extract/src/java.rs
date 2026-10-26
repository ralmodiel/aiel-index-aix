//! Java: classes/interfaces/enums/records and public methods; JAX-RS endpoints with `@RolesAllowed`;
//! `static final String` constants (role names).

use std::path::Path;

use tree_sitter::Node;

use crate::model::*;
use crate::ts_util::*;
use crate::Extractor;

pub struct Java;

const HTTP: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

impl Extractor for Java {
    fn name(&self) -> &'static str {
        "java"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "java"
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let Some(tree) = parse(&java(), &f.text) else {
                continue;
            };
            let root = tree.root_node();
            for n in named_children(root) {
                type_decl(n, &f.text, f, None, &mut rows);
            }
        }
        rows
    }
}

struct Annos {
    private: bool,
    names: Vec<String>,
    path: Option<String>,
    roles: Option<Vec<String>>,
    public: bool,
    static_final: bool,
}

fn annos(decl: Node, src: &str) -> Annos {
    let mut a = Annos { private: false, names: vec![], path: None, roles: None, public: false, static_final: false };
    let Some(mods) = named_children(decl).into_iter().find(|c| c.kind() == "modifiers") else {
        return a;
    };
    let mut stat = false;
    let mut fin = false;
    for m in children(mods) {
        match m.kind() {
            "marker_annotation" | "annotation" => {
                let name = m.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
                let name = name.rsplit('.').next().unwrap_or(name).to_string();
                let args = m.child_by_field_name("arguments");
                match name.as_str() {
                    "Path" => a.path = args.and_then(|x| first_string(x, src)),
                    "RolesAllowed" => a.roles = Some(args.map(|x| role_list(x, src)).unwrap_or_default()),
                    "PermitAll" | "AnonymousAllowed" => a.roles = Some(vec!["public".into()]),
                    "DenyAll" => a.roles = Some(vec!["!deny".into()]),
                    "Authenticated" => a.roles = Some(vec!["authenticated".into()]),
                    _ => {}
                }
                a.names.push(name);
            }
            _ => match text(m, src) {
                "public" => a.public = true,
                "private" => a.private = true,
                "static" => stat = true,
                "final" => fin = true,
                _ => {}
            },
        }
    }
    a.static_final = stat && fin;
    a
}

fn first_string(n: Node, src: &str) -> Option<String> {
    let mut out = None;
    walk(n, |c| {
        if out.is_none() {
            if let Some(s) = java_string(c, src) {
                out = Some(s);
            }
        }
        out.is_none()
    });
    out
}

/// Role list from `@RolesAllowed({"a", Roles.B})`: literals as-is, references as `@Roles.B`.
fn role_list(n: Node, src: &str) -> Vec<String> {
    let mut out = vec![];
    walk(n, |c| match c.kind() {
        "string_literal" => {
            if let Some(s) = java_string(c, src) {
                out.push(s);
            }
            false
        }
        "field_access" | "identifier" => {
            out.push(format!("@{}", text(c, src)));
            false
        }
        _ => true,
    });
    out
}

fn join_path(a: &str, b: &str) -> String {
    let mut s = format!("/{}/{}", a.trim_matches('/'), b.trim_matches('/'));
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    if s.len() > 1 {
        s = s.trim_end_matches('/').to_string();
    }
    s
}

fn type_decl(n: Node, src: &str, f: &SourceFile, outer: Option<&str>, rows: &mut Rows) {
    let kind = match n.kind() {
        "class_declaration" => "class",
        "interface_declaration" => "interface",
        "enum_declaration" => "enum",
        "record_declaration" => "record",
        "annotation_type_declaration" => "interface",
        _ => return,
    };
    let Some(name) = n.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
        return;
    };
    let ca = annos(n, src);
    rows.symbols.push(Symbol {
        file: f.path.clone(),
        line: line(n),
        end_line: end_line(n),
        name: name.clone(),
        kind: kind.into(),
        // types are part of the module surface unless private (nested records/DTOs included)
        exported: !ca.private,
        container: outer.map(str::to_string),
    });
    let Some(body) = n.child_by_field_name("body") else {
        return;
    };
    let class_path = ca.path.clone();
    for m in named_children(body) {
        match m.kind() {
            "method_declaration" => {
                let ma = annos(m, src);
                let Some(mname) = m.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                    continue;
                };
                if ma.public || kind == "interface" {
                    rows.symbols.push(Symbol {
                        file: f.path.clone(),
                        line: line(m),
                        end_line: end_line(m),
                        name: mname.clone(),
                        kind: "method".into(),
                        exported: true,
                        container: Some(name.clone()),
                    });
                }
                let verb = ma.names.iter().find(|x| HTTP.contains(&x.as_str()));
                if let Some(verb) = verb {
                    if class_path.is_some() || ma.path.is_some() {
                        let path = join_path(class_path.as_deref().unwrap_or(""), ma.path.as_deref().unwrap_or(""));
                        let roles = ma.roles.clone().or_else(|| ca.roles.clone()).unwrap_or_default();
                        rows.endpoints.push(Endpoint {
                            file: f.path.clone(),
                            line: line(m),
                            method: verb.clone(),
                            norm_path: norm_path(&path),
                            path,
                            class: name.clone(),
                            handler: mname,
                            roles,
                        });
                    }
                }
            }
            "field_declaration" => {
                let fa = annos(m, src);
                let ty = m.child_by_field_name("type").map(|t| text(t, src)).unwrap_or("");
                if fa.static_final && ty == "String" {
                    for d in named_children(m) {
                        if d.kind() != "variable_declarator" {
                            continue;
                        }
                        let (Some(dn), Some(v)) = (d.child_by_field_name("name"), d.child_by_field_name("value"))
                        else {
                            continue;
                        };
                        if let Some(s) = java_string(v, src) {
                            rows.consts.push(Const {
                                file: f.path.clone(),
                                line: line(d),
                                name: format!("{}.{}", name, text(dn, src)),
                                values: vec![s],
                            });
                        }
                    }
                }
            }
            _ => type_decl(m, src, f, Some(&name), rows),
        }
    }
}
