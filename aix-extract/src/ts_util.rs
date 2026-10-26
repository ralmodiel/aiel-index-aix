//! Small tree-sitter helpers shared by the language extractors.

use tree_sitter::{Language, Node, Parser, Tree};

/// Syntax trees deeper than this are not walked: the extractors recurse over children, and a generated or hostile
/// file (`1+1+...` 5000 terms, `[[[[`, `f(f(f(`) would overflow the stack and abort the whole indexing run.
pub const MAX_DEPTH: usize = 500;

thread_local! {
    static TOO_DEEP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// True (once) if a `parse` on this thread refused a tree for being deeper than [`MAX_DEPTH`].
pub fn take_too_deep() -> bool {
    TOO_DEEP.with(|c| c.replace(false))
}

/// Like [`take_too_deep`] without clearing the flag.
pub fn peek_too_deep() -> bool {
    TOO_DEEP.with(|c| c.get())
}

/// Depth of the deepest node, computed iteratively (no recursion), stopping early past `limit`.
pub fn depth_exceeds(root: Node, limit: usize) -> bool {
    let mut cur = root.walk();
    let mut depth = 0usize;
    loop {
        if cur.goto_first_child() {
            depth += 1;
            if depth > limit {
                return true;
            }
            continue;
        }
        loop {
            if cur.goto_next_sibling() {
                break;
            }
            if !cur.goto_parent() {
                return false;
            }
            depth -= 1;
        }
    }
}

/// Parse `text`; None when the grammar cannot be loaded or the tree is deeper than [`MAX_DEPTH`] (see `take_too_deep`).
pub fn parse(lang: &Language, text: &str) -> Option<Tree> {
    let mut p = Parser::new();
    p.set_language(lang).ok()?;
    let t = p.parse(text, None)?;
    if depth_exceeds(t.root_node(), MAX_DEPTH) {
        TOO_DEEP.with(|c| c.set(true));
        return None;
    }
    Some(t)
}

pub fn tsx() -> Language {
    tree_sitter_typescript::LANGUAGE_TSX.into()
}
pub fn typescript() -> Language {
    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
}
pub fn java() -> Language {
    tree_sitter_java::LANGUAGE.into()
}
pub fn python() -> Language {
    tree_sitter_python::LANGUAGE.into()
}
pub fn bash() -> Language {
    tree_sitter_bash::LANGUAGE.into()
}

pub fn text<'a>(n: Node, src: &'a str) -> &'a str {
    &src[n.byte_range()]
}

/// 1-based line of a node's start.
pub fn line(n: Node) -> u32 {
    n.start_position().row as u32 + 1
}
pub fn end_line(n: Node) -> u32 {
    n.end_position().row as u32 + 1
}

pub fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.children(&mut c).collect()
}
pub fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// Pre-order walk of every node under `root`, calling `f`. `f` returns false to skip a subtree.
pub fn walk<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>) -> bool) {
    let mut cur = root.walk();
    let mut descend = true;
    loop {
        if descend {
            let n = cur.node();
            if f(n) && cur.goto_first_child() {
                continue;
            }
        }
        if cur.goto_next_sibling() {
            descend = true;
            continue;
        }
        if !cur.goto_parent() {
            return;
        }
        descend = false;
    }
}

/// Value of a JS/TS string-ish literal: 'x', "x", `x` (template text kept with ${...} as written).
pub fn js_string(n: Node, src: &str) -> Option<String> {
    match n.kind() {
        "string" | "template_string" => {
            let t = text(n, src);
            if t.len() >= 2 {
                Some(unescape_js(&t[1..t.len() - 1]))
            } else {
                None
            }
        }
        "parenthesized_expression" => n.named_child(0).and_then(|c| js_string(c, src)),
        _ => None,
    }
}

fn unescape_js(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n') => out.push(' '),
                Some('t') => out.push(' '),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Java string literal value.
pub fn java_string(n: Node, src: &str) -> Option<String> {
    if n.kind() == "string_literal" {
        let t = text(n, src);
        if t.starts_with("\"\"\"") {
            return Some(t.trim_matches('"').trim().to_string());
        }
        return Some(t.trim_matches('"').to_string());
    }
    None
}

/// Collapse internal whitespace.
pub fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
