//! Python defs/classes and Bash functions.

use std::path::Path;

use tree_sitter::Node;

use crate::model::*;
use crate::ts_util::*;
use crate::Extractor;

pub struct Python;
pub struct Bash;

pub fn is_shell(f: &SourceFile) -> bool {
    matches!(f.ext(), "sh" | "bash" | "zsh")
        || (f.ext().is_empty()
            && (f.text.starts_with("#!/bin/bash")
                || f.text.starts_with("#!/usr/bin/env bash")
                || f.text.starts_with("#!/bin/sh")))
}

impl Extractor for Python {
    fn name(&self) -> &'static str {
        "python"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "py"
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let Some(tree) = parse(&python(), &f.text) else {
                continue;
            };
            py_block(tree.root_node(), &f.text, f, None, &mut rows);
        }
        rows
    }
}

fn py_block(n: Node, src: &str, f: &SourceFile, class: Option<&str>, rows: &mut Rows) {
    for c in named_children(n) {
        let d = if c.kind() == "decorated_definition" { c.child_by_field_name("definition").unwrap_or(c) } else { c };
        match d.kind() {
            "function_definition" | "class_definition" => {
                let Some(name) = d.child_by_field_name("name").map(|x| text(x, src).to_string()) else {
                    continue;
                };
                let is_class = d.kind() == "class_definition";
                rows.symbols.push(Symbol {
                    file: f.path.clone(),
                    line: line(d),
                    end_line: end_line(d),
                    exported: !name.starts_with('_'),
                    kind: if is_class {
                        "class"
                    } else if class.is_some() {
                        "method"
                    } else {
                        "function"
                    }
                    .into(),
                    container: class.map(str::to_string),
                    name: name.clone(),
                });
                if is_class {
                    if let Some(b) = d.child_by_field_name("body") {
                        py_block(b, src, f, Some(&name), rows);
                    }
                }
            }
            _ => {}
        }
    }
}

impl Extractor for Bash {
    fn name(&self) -> &'static str {
        "bash"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        matches!(ext_of(path), "sh" | "bash" | "zsh" | "")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files.iter().filter(|f| is_shell(f)) {
            let Some(tree) = parse(&bash(), &f.text) else {
                continue;
            };
            walk(tree.root_node(), |n| {
                if n.kind() == "function_definition" {
                    if let Some(nm) = n.child_by_field_name("name") {
                        rows.symbols.push(Symbol {
                            file: f.path.clone(),
                            line: line(n),
                            end_line: end_line(n),
                            name: text(nm, &f.text).to_string(),
                            kind: "function".into(),
                            exported: true,
                            container: None,
                        });
                    }
                    return false;
                }
                true
            });
        }
        rows
    }
}
