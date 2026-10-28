//! TypeScript / TSX: symbols, UI strings, imports, imported-object calls, HTTP client calls and string
//! constants (role lists).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tree_sitter::Node;

use crate::model::*;
use crate::ts_util::*;
use crate::Extractor;

pub struct TypeScript;

pub fn is_ts(path: &str) -> bool {
    matches!(ext_of(path), "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs")
}

impl Extractor for TypeScript {
    fn name(&self) -> &'static str {
        "typescript"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        is_ts(path) && !path.ends_with(".d.ts") && !path.contains(".min.")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            extract_file(f, &mut rows);
        }
        rows
    }
}

/// Props whose string values are user-facing.
const UI_PROPS: &[&str] = &[
    "title",
    "placeholder",
    "aria-label",
    "label",
    "alt",
    "tooltip",
    "description",
    "helperText",
    "emptyMessage",
    "confirmText",
    "confirmLabel",
    "subtitle",
    "hint",
];
/// Object keys inside toast/confirm calls whose string values are user-facing.
const MSG_KEYS: &[&str] =
    &["title", "message", "description", "body", "text", "confirmText", "confirmLabel", "cancelText"];
const HTTP: &[&str] = &["get", "post", "put", "delete", "patch", "head"];

pub fn lang_for(path: &str) -> tree_sitter::Language {
    match ext_of(path) {
        "tsx" | "jsx" | "js" | "mjs" => tsx(),
        _ => typescript(),
    }
}

pub fn extract_file(f: &SourceFile, rows: &mut Rows) {
    let src = f.text.as_str();
    let Some(tree) = parse(&lang_for(&f.path), src) else {
        return;
    };
    let root = tree.root_node();
    let jsx = matches!(f.ext(), "tsx" | "jsx");
    let api_prefix =
        if src.contains("baseURL") && (src.contains("'/api'") || src.contains("\"/api\"")) { "/api" } else { "" };

    // Pass 1: top-level declarations -> symbols, consts, imports.
    let consts = collect_consts(root, src);
    for (name, (line, raw)) in &consts {
        let values = resolve(raw, &consts, 0);
        rows.consts.push(Const { file: f.path.clone(), line: *line, name: name.clone(), values });
    }
    let mut imported: HashSet<String> = HashSet::new();
    for top in named_children(root) {
        let (decl, exported) = if top.kind() == "export_statement" {
            match top.child_by_field_name("declaration") {
                Some(d) => (d, true),
                None => continue,
            }
        } else {
            (top, false)
        };
        if top.kind() == "import_statement" {
            imports_of(top, src, f, rows, &mut imported);
            continue;
        }
        symbols_of(decl, exported, src, f, jsx, rows, &mut imported);
    }

    // Test files: quoted literals are what a rename would break.
    if crate::is_test_path(&f.path) {
        test_literals(root, f, rows);
        if crate::scripts::is_script(f) {
            return;
        }
    }

    // Pass 2: whole-tree walk for strings, calls, http calls.
    walk(root, |n| {
        match n.kind() {
            "jsx_text" if jsx => {
                let raw = text(n, src);
                let t = squash(raw);
                if is_wordy(&t) {
                    push_ui(rows, f, n, t, "jsx".into(), root, src);
                    // the node starts after the previous element (often the line before): cite the line the text is on
                    let lead = raw.len() - raw.trim_start().len();
                    let nl = raw[..lead].matches('\n').count();
                    if let Some(u) = rows.ui_strings.last_mut() {
                        u.line += nl as u32;
                    }
                }
            }
            // `{cond ? 'A' : 'B'}` / `{x && 'Text'}` as element children are visible text too
            "jsx_expression" if jsx && n.parent().is_some_and(|p| p.kind() == "jsx_element") => {
                if let Some(e) = n.named_child(0) {
                    ui_from_arg(e, src, f, rows, "jsx", root);
                }
            }
            "jsx_attribute" if jsx => {
                let kids = named_children(n);
                if let (Some(k), Some(v)) = (kids.first(), kids.get(1)) {
                    let prop = text(*k, src);
                    if UI_PROPS.contains(&prop) {
                        match v.kind() {
                            "string" => ui_from_arg(*v, src, f, rows, &format!("prop:{prop}"), root),
                            // `title={busy ? 'Saving…' : 'Save'}` too
                            "jsx_expression" => {
                                if let Some(e) = v.named_child(0) {
                                    ui_from_arg(e, src, f, rows, &format!("prop:{prop}"), root);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "call_expression" => call_of(n, src, f, rows, &imported, api_prefix, root),
            "string" | "template_string" => {
                if let Some(s) = js_string(n, src) {
                    if s.starts_with("/api/") && !in_http_call(n, src) {
                        rows.api_calls.push(ApiCall {
                            file: f.path.clone(),
                            line: line(n),
                            object: None,
                            name: None,
                            method: String::new(),
                            norm_path: norm_path(&s),
                            path: s,
                        });
                    }
                }
            }
            _ => {}
        }
        true
    });

    // Other user-facing literals (labels in config arrays, `const label = '...'`), with the prototype's filters.
    if f.path.contains("/src/") && !f.path.ends_with("lib/api.ts") {
        let have: HashSet<(u32, String)> =
            rows.ui_strings.iter().filter(|u| u.file == f.path).map(|u| (u.line, u.text.clone())).collect();
        walk(root, |n| {
            if n.kind() == "import_statement"
                || n.kind() == "export_statement" && n.child_by_field_name("source").is_some()
            {
                return false;
            }
            if n.kind() == "jsx_attribute" {
                let prop = n.named_child(0).map(|k| text(k, src)).unwrap_or("");
                return !(prop == "className" || prop == "class" || prop == "style" || UI_PROPS.contains(&prop));
            }
            if n.kind() == "template_string" {
                // `{ text: `${n} of ${m} learners need attention` }`: a template as an object property value
                if let Some(t) = js_string(n, src).map(|s| squash(&s)) {
                    if pair_value_is_copy(n, src, &template_static(n, src)) && !have.contains(&(line(n), t.clone())) {
                        // `{ Coverage: `${a} of ${b} learners graded` }`: a capitalised key is the row's shown label
                        if let Some(k) = label_key(n, src) {
                            push_ui(rows, f, n, k, "literal".into(), root, src);
                        }
                        push_ui(rows, f, n, t, "literal".into(), root, src);
                    }
                }
                return true;
            }
            if n.kind() != "string" {
                return true;
            }
            if let Some(s) = js_string(n, src) {
                let s = squash(&s);
                let copy = if is_literal_text(&s) { !literal_skip_context(n, src) } else { pair_value_is_copy(n, src, &s) };
                if copy && !have.contains(&(line(n), s.clone())) {
                    push_ui(rows, f, n, s, "literal".into(), root, src);
                }
            }
            false
        });
    }
}

static NON_UI_KEYS: &[&str] = &[
    "className",
    "class",
    "icon",
    "variant",
    "size",
    "type",
    "key",
    "id",
    "href",
    "to",
    "path",
    "color",
    "method",
    "url",
    "name",
    "role",
    "status",
    "kind",
    "format",
    "mode",
    "align",
    "value",
];

/// Prototype filter for literal strings: looks like words a user reads, not code.
fn is_literal_text(s: &str) -> bool {
    let first = s.chars().next().unwrap_or(' ');
    if !(first.is_ascii_uppercase() || first.is_ascii_digit() || "“\"'(".contains(first)) {
        return false;
    }
    if !s.as_bytes().windows(2).any(|w| w[0].is_ascii_alphabetic() && w[1].is_ascii_alphabetic()) || s.len() > 300 {
        return false;
    }
    if s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
        return false;
    }
    let low = s.to_ascii_lowercase();
    if low.starts_with("http") || s.starts_with('/') || s.starts_with('.') || s.starts_with('#') {
        return false;
    }
    if [".tsx", ".ts", ".png", ".svg", ".json"].iter().any(|e| low.ends_with(e)) && !s.contains(' ') {
        return false;
    }
    if ["px)", "rem)", "rgb(", "rgba(", "var("].iter().any(|e| low.contains(e)) {
        return false;
    }
    // CamelCase identifiers (component names, enum values)
    let mut cs = s.chars();
    let camel = cs.next().is_some_and(|c| c.is_ascii_uppercase())
        && !s.contains(' ')
        && s.chars().skip(1).any(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase());
    if camel {
        return false;
    }
    s.contains(' ') || s.chars().count() >= 3
}

/// Object keys whose (template or lowercase) string values are user-facing copy.
const COPY_KEYS: &[&str] = &[
    "text", "label", "title", "subtitle", "message", "description", "body", "hint", "tooltip", "placeholder",
    "caption", "heading", "header", "summary", "detail", "details", "reason", "note", "error", "warning",
    "helperText", "helpText", "emptyText", "emptyMessage", "confirmText", "confirmLabel", "cancelText",
];
/// Short function words: a value containing one reads as a sentence, not a class list, id or enum value.
const FUNCTION_WORDS: &[&str] = &[
    "a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "is", "are", "was", "be", "been", "has", "have",
    "no", "not", "with", "at", "by", "from", "this", "that", "your", "will", "can", "cannot", "need", "needs",
];

/// Static text of a template literal, `${...}` parts replaced by a space.
fn template_static(n: Node, src: &str) -> String {
    let (start, end) = (n.start_byte() + 1, n.end_byte().saturating_sub(1));
    let mut out = String::new();
    let mut at = start;
    for c in named_children(n) {
        if c.kind() == "template_substitution" {
            out.push_str(src.get(at..c.start_byte()).unwrap_or(""));
            out.push(' ');
            at = c.end_byte();
        }
    }
    out.push_str(src.get(at..end.max(at)).unwrap_or(""));
    squash(&out)
}

/// A string/template that is the value of an object-literal property and reads as copy: the key is a
/// copy key (`text:`, `label:`, `message:` ...) and the static text has a word, or, under any key that is not
/// code-ish (`className`, `id`, `url`, ...), the static text is a sentence of 2+ words with a function word
/// ("of", "the", "no", ...) and no code characters. Keeps `tone: 'warn'`, ids, URLs, class lists out.
fn pair_value_is_copy(n: Node, src: &str, stat: &str) -> bool {
    let Some(p) = n.parent().filter(|p| p.kind() == "pair") else { return false };
    if p.child_by_field_name("value").is_none_or(|v| v.id() != n.id()) {
        return false;
    }
    let key = p.child_by_field_name("key").map(|k| text(k, src).trim_matches(['"', '\'']).to_string()).unwrap_or_default();
    // search keywords/synonyms are matched, not shown; a route-keyed map (`'/grades': '...'`) is the same
    let hidden = ["keywords", "keyword", "words", "synonyms", "aliases", "tags", "terms", "search"].contains(&key.as_str()) || key.starts_with('/');
    if hidden || NON_UI_KEYS.contains(&key.as_str()) || stat.len() > 600 {
        return false;
    }
    let low = stat.to_ascii_lowercase();
    if low.starts_with("http") || stat.starts_with('/') || stat.starts_with('.') || stat.starts_with('#') {
        return false;
    }
    if ["=", ";", "{", "}", "<", ">", "://", "px", "var(", "rgb("].iter().any(|c| low.contains(c)) {
        return false;
    }
    let words: Vec<&str> = stat
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| ",.:;!?()'\"“”".contains(c)))
        .filter(|w| w.chars().count() >= 1 && w.chars().all(|c| c.is_alphabetic() || c == '\''))
        .collect();
    if COPY_KEYS.contains(&key.as_str()) {
        return words.iter().any(|w| w.chars().count() >= 2);
    }
    // a class list (`p-2 hover:underline`) has tokens like `p-2`, `hover:x`
    let codeish = stat.split_whitespace().any(|w| {
        let w = w.trim_end_matches([',', '.', ':', '!', '?', ')']);
        w.contains(':') || w.contains('-') && w.chars().any(|c| c.is_ascii_digit())
    });
    let alpha = words.iter().filter(|w| w.chars().count() >= 2).count();
    !codeish && alpha >= 2 && words.iter().any(|w| FUNCTION_WORDS.contains(&w.to_ascii_lowercase().as_str()))
}

/// The key of `{ Coverage: <copy> }` when it reads as a shown label: capitalised words, not an ALL_CAPS const.
fn label_key(n: Node, src: &str) -> Option<String> {
    let k = n.parent()?.child_by_field_name("key")?;
    let k = text(k, src).trim_matches(['"', '\'']);
    let ok = k.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && k.chars().any(|c| c.is_ascii_lowercase())
        && k.chars().all(|c| c.is_alphabetic() || c == ' ');
    ok.then(|| k.to_string())
}

/// Literal positions that are code, not copy: object keys/ids, comparisons, switch cases, type positions.
fn literal_skip_context(n: Node, src: &str) -> bool {
    let Some(p) = n.parent() else { return false };
    match p.kind() {
        "pair" => {
            let is_key = p.child_by_field_name("key").is_some_and(|k| k.id() == n.id());
            let key = p
                .child_by_field_name("key")
                .map(|k| text(k, src).trim_matches(['"', '\'']).to_string())
                .unwrap_or_default();
            // `{ name: 'Reports & Analysis', items: [...] }`: a multi-word capitalised name is a shown label
            let shown_name = key == "name" && text(n, src).contains(' ');
            is_key || NON_UI_KEYS.contains(&key.as_str()) && !shown_name
        }
        "binary_expression" => {
            let op = p.child_by_field_name("operator").map(|o| text(o, src)).unwrap_or("");
            matches!(op, "===" | "!==" | "==" | "!=" | "in")
        }
        "switch_case" | "literal_type" | "subscript_expression" | "property_identifier" | "computed_property_name" => {
            true
        }
        "arguments" => {
            let callee = p.parent().and_then(|c| c.child_by_field_name("function")).map(|f| text(f, src)).unwrap_or("");
            let last = callee.rsplit('.').next().unwrap_or(callee);
            matches!(
                last,
                "require"
                    | "import"
                    | "get"
                    | "post"
                    | "put"
                    | "delete"
                    | "patch"
                    | "getItem"
                    | "setItem"
                    | "removeItem"
                    | "querySelector"
                    | "addEventListener"
                    | "includes"
                    | "startsWith"
                    | "endsWith"
                    | "split"
                    | "replace"
                    | "join"
                    | "has"
                    | "set"
                    | "t"
                    | "useState"
                    | "classNames"
                    | "clsx"
                    | "cn"
            )
        }
        _ => false,
    }
}

fn test_literals(root: Node, f: &SourceFile, rows: &mut Rows) {
    let src = f.text.as_str();
    let mut seen = HashSet::new();
    walk(root, |n| {
        if matches!(n.kind(), "string" | "template_string") {
            if let Some(s) = js_string(n, src) {
                let s = squash(&s);
                let letters3 = s.as_bytes().windows(3).any(|w| w.iter().all(|c| c.is_ascii_alphabetic()));
                let pathy = s.starts_with('.')
                    || s.starts_with('/')
                    || s.starts_with("http")
                    || s.starts_with("node:")
                    || s.split_whitespace().count() == 1 && s.contains('/');
                if letters3 && !pathy && s.len() <= 300 && seen.insert((line(n), s.clone())) {
                    rows.ui_strings.push(UiString {
                        file: f.path.clone(),
                        line: line(n),
                        text: s,
                        kind: "test".into(),
                        component: None,
                    });
                }
            }
            return false;
        }
        true
    });
}

fn is_wordy(s: &str) -> bool {
    s.chars().filter(|c| c.is_alphabetic()).count() >= 2 && s.len() <= 600
}

fn push_ui(rows: &mut Rows, f: &SourceFile, n: Node, t: String, kind: String, root: Node, src: &str) {
    rows.ui_strings.push(UiString {
        file: f.path.clone(),
        line: line(n),
        text: t,
        kind,
        component: enclosing_top_name(n, root, src),
    });
}

/// Name of the top-level declaration containing `n`.
fn enclosing_top_name(n: Node, root: Node, src: &str) -> Option<String> {
    let mut cur = n;
    while let Some(p) = cur.parent() {
        if p.id() == root.id() {
            break;
        }
        cur = p;
    }
    let decl = if cur.kind() == "export_statement" { cur.child_by_field_name("declaration")? } else { cur };
    match decl.kind() {
        "function_declaration" | "class_declaration" | "generator_function_declaration" => {
            decl.child_by_field_name("name").map(|x| text(x, src).to_string())
        }
        "lexical_declaration" | "variable_declaration" => {
            decl.named_child(0).and_then(|d| d.child_by_field_name("name")).map(|x| text(x, src).to_string())
        }
        _ => None,
    }
}

/// True when the literal is the first argument of an `x.get(...)`-style call or `fetch(...)`, which
/// `call_of` already records with its method.
fn in_http_call(n: Node, src: &str) -> bool {
    let Some(args) = n.parent().filter(|a| a.kind() == "arguments") else {
        return false;
    };
    if args.named_child(0).map(|a| a.id()) != Some(n.id()) {
        return false;
    }
    let Some(func) = args.parent().and_then(|c| c.child_by_field_name("function")) else {
        return false;
    };
    match func.kind() {
        "member_expression" => {
            func.child_by_field_name("object").is_some_and(|o| o.kind() == "identifier")
                && func.child_by_field_name("property").is_some_and(|p| HTTP.contains(&text(p, src)))
        }
        "identifier" => text(func, src) == "fetch",
        _ => false,
    }
}

fn imports_of(n: Node, src: &str, f: &SourceFile, rows: &mut Rows, imported: &mut HashSet<String>) {
    let Some(source) = n.child_by_field_name("source").and_then(|s| js_string(s, src)) else {
        return;
    };
    let ln = line(n);
    walk(n, |c| {
        let name = match c.kind() {
            "import_specifier" => {
                c.child_by_field_name("alias").or_else(|| c.child_by_field_name("name")).map(|x| text(x, src))
            }
            "import_clause" => c.named_child(0).filter(|x| x.kind() == "identifier").map(|x| text(x, src)),
            "namespace_import" => c.named_child(0).map(|x| text(x, src)),
            _ => None,
        };
        if let Some(name) = name {
            if source.starts_with('.') || source.starts_with('@') || source.starts_with('~') {
                imported.insert(name.to_string());
            }
            rows.imports.push(Import {
                file: f.path.clone(),
                line: ln,
                name: name.to_string(),
                source: source.clone(),
            });
        }
        true
    });
}

#[allow(clippy::too_many_arguments)]
fn symbols_of(
    decl: Node,
    exported: bool,
    src: &str,
    f: &SourceFile,
    jsx: bool,
    rows: &mut Rows,
    imported: &mut HashSet<String>,
) {
    let mut sym = |name: &str, kind: &str, n: Node, container: Option<String>| {
        rows.symbols.push(Symbol {
            file: f.path.clone(),
            line: line(n),
            end_line: end_line(n),
            name: name.to_string(),
            kind: kind.to_string(),
            exported,
            container,
        });
    };
    let fn_kind = |name: &str| {
        if jsx && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            "component"
        } else {
            "function"
        }
    };
    match decl.kind() {
        "function_declaration" | "generator_function_declaration" | "function_signature" => {
            if let Some(nm) = decl.child_by_field_name("name") {
                let name = text(nm, src);
                sym(name, fn_kind(name), decl, None);
            }
        }
        // `namespace X { export function f() {} }` / `declare module "x" { .. }`: the namespace, then its declarations
        // `declare module "x" { .. }` / `declare function f(): void;`
        "ambient_declaration" | "expression_statement" => {
            for d in named_children(decl) {
                symbols_of(d, exported, src, f, jsx, rows, imported);
            }
        }
        "internal_module" | "module" => {
            if let Some(nm) = decl.child_by_field_name("name") {
                sym(text(nm, src).trim_matches(['"', '\'']), "namespace", decl, None);
            }
            if let Some(body) = decl.child_by_field_name("body") {
                for top in named_children(body) {
                    let (d, exp) = if top.kind() == "export_statement" {
                        match top.child_by_field_name("declaration") {
                            Some(d) => (d, true),
                            None => continue,
                        }
                    } else {
                        (top, exported)
                    };
                    symbols_of(d, exp, src, f, jsx, rows, imported);
                }
            }
        }
        "class_declaration" | "abstract_class_declaration" => {
            if let Some(nm) = decl.child_by_field_name("name") {
                let cname = text(nm, src).to_string();
                sym(&cname, "class", decl, None);
                if let Some(body) = decl.child_by_field_name("body") {
                    for m in named_children(body) {
                        if matches!(m.kind(), "method_definition" | "abstract_method_signature" | "method_signature") {
                            let acc = children(m).iter().any(|c| text(*c, src) == "private");
                            if let (Some(mn), false) = (m.child_by_field_name("name"), acc) {
                                sym(text(mn, src), "method", m, Some(cname.clone()));
                            }
                        }
                    }
                }
            }
        }
        "interface_declaration" | "type_alias_declaration" | "enum_declaration" => {
            if let Some(nm) = decl.child_by_field_name("name") {
                let kind = match decl.kind() {
                    "interface_declaration" => "interface",
                    "enum_declaration" => "enum",
                    _ => "type",
                };
                sym(text(nm, src), kind, decl, None);
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            for d in named_children(decl) {
                if d.kind() != "variable_declarator" {
                    continue;
                }
                let Some(nm) = d.child_by_field_name("name") else {
                    continue;
                };
                let name = text(nm, src);
                let val = d.child_by_field_name("value");
                // `const X = lazy(() => import('./pages/X'))` counts as an import of X.
                if let Some(v) = val {
                    if let Some(spec) = dynamic_import(v, src) {
                        imported.insert(name.to_string());
                        rows.imports.push(Import {
                            file: f.path.clone(),
                            line: line(d),
                            name: name.to_string(),
                            source: spec,
                        });
                        continue;
                    }
                }
                let is_fn = val.is_some_and(|v| {
                    matches!(v.kind(), "arrow_function" | "function_expression" | "function")
                        || (v.kind() == "call_expression"
                            && ["memo", "forwardRef", "React.memo", "React.forwardRef", "lazy"]
                                .contains(&v.child_by_field_name("function").map(|x| text(x, src)).unwrap_or("")))
                });
                if is_fn {
                    sym(name, fn_kind(name), d, None);
                } else if exported {
                    sym(name, "const", d, None);
                }
            }
        }
        _ => {}
    }
}

fn dynamic_import(v: Node, src: &str) -> Option<String> {
    let mut found = None;
    walk(v, |c| {
        if found.is_some() {
            return false;
        }
        if c.kind() == "call_expression" {
            if let Some(func) = c.child_by_field_name("function") {
                if func.kind() == "import" || text(func, src) == "import" {
                    found = c
                        .child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .and_then(|s| js_string(s, src));
                }
            }
        }
        true
    });
    found
}

fn call_of(n: Node, src: &str, f: &SourceFile, rows: &mut Rows, imported: &HashSet<String>, prefix: &str, root: Node) {
    let Some(func) = n.child_by_field_name("function") else {
        return;
    };
    let args = n.child_by_field_name("arguments");
    let ftext = text(func, src);
    // toast / confirm messages
    let last = ftext.rsplit('.').next().unwrap_or(ftext);
    let lower = last.to_ascii_lowercase();
    let kind = if lower.contains("toast")
        || (ftext.contains("toast") && ["success", "error", "info", "warning", "warn"].contains(&last))
    {
        Some("toast")
    } else if lower.contains("confirm") || lower == "alert" || lower == "prompt" {
        Some("confirm")
    } else if lower == "notify" || lower == "shownotification" {
        Some("toast")
    } else {
        None
    };
    if let (Some(kind), Some(args)) = (kind, args) {
        for a in named_children(args) {
            ui_from_arg(a, src, f, rows, kind, root);
        }
    }
    if func.kind() == "member_expression" {
        let obj = func.child_by_field_name("object");
        let prop = func.child_by_field_name("property").map(|p| text(p, src)).unwrap_or("");
        if let Some(obj) = obj {
            let otext = text(obj, src);
            // HTTP client call: api.get('/x', ...)
            if obj.kind() == "identifier" && HTTP.contains(&prop) && !is_server_route(otext, args, src) {
                if let Some(path) = args.and_then(|a| a.named_child(0)).and_then(|s| client_path(s, src)) {
                    if path.starts_with('/') {
                        let full = if !prefix.is_empty() && !path.starts_with(prefix) {
                            format!("{prefix}{path}")
                        } else {
                            path.clone()
                        };
                        let (object, name) = client_slot(n, src);
                        rows.api_calls.push(ApiCall {
                            file: f.path.clone(),
                            line: line(n),
                            object,
                            name,
                            method: prop.to_ascii_uppercase(),
                            norm_path: norm_path(&full),
                            path,
                        });
                        return;
                    }
                }
            }
            if obj.kind() == "identifier" && imported.contains(otext) {
                rows.calls.push(Call {
                    file: f.path.clone(),
                    line: line(n),
                    object: otext.to_string(),
                    member: prop.to_string(),
                });
            }
        }
    } else if ftext == "fetch" {
        if let Some(path) = args.and_then(|a| a.named_child(0)).and_then(|s| client_path(s, src)) {
            if path.starts_with('/') {
                let full = if !prefix.is_empty() && !path.starts_with(prefix) { format!("{prefix}{path}") } else { path.clone() };
                rows.api_calls.push(ApiCall {
                    file: f.path.clone(),
                    line: line(n),
                    object: None,
                    name: None,
                    method: fetch_method(args, src),
                    norm_path: norm_path(&full),
                    path,
                });
            }
        }
    }
}

/// `app.get('/x', handler)` / `router.post('/x', auth, async (req, res) => ...)`: a server route, not a client call.
/// A handler is a function, or (for the usual server receiver names) any identifier/member passed after the path.
fn is_server_route(obj: &str, args: Option<Node>, src: &str) -> bool {
    let Some(args) = args else { return false };
    let a = named_children(args);
    if a.len() < 2 {
        return false;
    }
    let func = |k: &str| matches!(k, "arrow_function" | "function_expression" | "function" | "generator_function");
    if a[1..].iter().any(|x| func(x.kind())) {
        return !matches!(obj, "axios" | "http" | "client" | "request" | "got" | "ky");
    }
    let _ = src;
    let server = matches!(obj, "app" | "router" | "server" | "routes" | "route" | "fastify" | "r" | "api_router" | "apiRouter");
    server && a[1..].iter().all(|x| matches!(x.kind(), "identifier" | "member_expression" | "call_expression" | "array"))
}

/// The path of an HTTP call's first argument: a string, a template (`${BASE}/x`), or `BASE + '/x'`; an absolute URL
/// loses its origin.
fn client_path(a: Node, src: &str) -> Option<String> {
    let mut s = match a.kind() {
        "binary_expression" if text(a, src).contains('+') => {
            let r = a.child_by_field_name("right")?;
            js_string(r, src)?
        }
        _ => js_string(a, src)?,
    };
    if let Some(rest) = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")) {
        s = rest.find('/').map(|i| rest[i..].to_string()).unwrap_or_default();
    } else if s.starts_with("${") {
        // `${BASE}/x`, `${API_URL}/x` (the placeholder is the origin/prefix)
        if let Some(i) = s.find('}') {
            s = s[i + 1..].to_string();
        }
    }
    if s.starts_with("//") {
        return None;
    }
    Some(s)
}

/// `fetch(url, { method: 'POST' })` -> POST; no options -> GET; a computed method -> "" (unknown).
fn fetch_method(args: Option<Node>, src: &str) -> String {
    let Some(opts) = args.and_then(|a| a.named_child(1)) else { return "GET".into() };
    if opts.kind() != "object" {
        return "".into();
    }
    for p in named_children(opts) {
        if p.kind() == "pair" {
            let key = p.child_by_field_name("key").map(|k| text(k, src).trim_matches(['"', '\'']).to_string());
            if key.as_deref() == Some("method") {
                return match p.child_by_field_name("value").and_then(|v| js_string(v, src)) {
                    Some(m) => m.to_ascii_uppercase(),
                    None => "".into(),
                };
            }
        } else if p.kind() != "comment" {
            // `...spread` options may carry a method
            return "".into();
        }
    }
    "GET".into()
}

fn ui_from_arg(a: Node, src: &str, f: &SourceFile, rows: &mut Rows, kind: &str, root: Node) {
    if let Some(s) = js_string(a, src) {
        let s = squash(&s);
        if is_wordy(&s) {
            push_ui(rows, f, a, s, kind.into(), root, src);
        }
    } else if a.kind() == "object" {
        for p in named_children(a) {
            if p.kind() == "pair" {
                let key = p.child_by_field_name("key").map(|k| text(k, src).trim_matches(['"', '\'']).to_string());
                if key.is_some_and(|k| MSG_KEYS.contains(&k.as_str())) {
                    if let Some(v) = p.child_by_field_name("value") {
                        ui_from_arg(v, src, f, rows, kind, root);
                    }
                }
            }
        }
    } else if a.kind() == "ternary_expression" {
        for c in named_children(a).into_iter().skip(1) {
            ui_from_arg(c, src, f, rows, kind, root);
        }
    } else if a.kind() == "parenthesized_expression"
        || a.kind() == "binary_expression" && a.child_by_field_name("operator").is_some_and(|o| matches!(o.kind(), "&&" | "||" | "??"))
    {
        // `(cond ? 'A' : 'B')`, `x && 'Text'`, `a || 'Fallback'`
        for c in named_children(a) {
            ui_from_arg(c, src, f, rows, kind, root);
        }
    }
}

/// For `export const xApi = { list: (...) => api.get(...) }`: ("xApi", "list").
fn client_slot(n: Node, src: &str) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut object = None;
    let mut cur = n;
    while let Some(p) = cur.parent() {
        match p.kind() {
            "pair" if name.is_none() => {
                name = p.child_by_field_name("key").map(|k| text(k, src).trim_matches(['"', '\'']).to_string());
            }
            "method_definition" if name.is_none() => {
                name = p.child_by_field_name("name").map(|k| text(k, src).to_string());
            }
            "variable_declarator" => {
                object = p
                    .child_by_field_name("name")
                    .filter(|k| k.kind() == "identifier")
                    .map(|k| text(k, src).to_string());
                if name.is_none() {
                    name = object.take();
                }
                break;
            }
            "function_declaration" => {
                if name.is_none() {
                    name = p.child_by_field_name("name").map(|k| text(k, src).to_string());
                }
                break;
            }
            _ => {}
        }
        cur = p;
    }
    (object, name)
}

/// Raw value of a const: list of elements, each `S:literal`, `R:NAME` (reference / spread).
type RawConst = Vec<String>;

fn collect_consts(root: Node, src: &str) -> HashMap<String, (u32, RawConst)> {
    let mut out = HashMap::new();
    for top in named_children(root) {
        let decl = if top.kind() == "export_statement" {
            match top.child_by_field_name("declaration") {
                Some(d) => d,
                None => continue,
            }
        } else {
            top
        };
        if decl.kind() != "lexical_declaration" {
            continue;
        }
        for d in named_children(decl) {
            let (Some(nm), Some(v)) = (d.child_by_field_name("name"), d.child_by_field_name("value")) else {
                continue;
            };
            let v = strip_as(v);
            if let Some(raw) = raw_value(v, src) {
                out.insert(text(nm, src).to_string(), (line(d), raw));
            }
        }
    }
    out
}

fn strip_as(mut v: Node) -> Node {
    while matches!(v.kind(), "as_expression" | "satisfies_expression" | "parenthesized_expression") {
        match v.named_child(0) {
            Some(c) => v = c,
            None => break,
        }
    }
    v
}

fn raw_value(v: Node, src: &str) -> Option<RawConst> {
    match v.kind() {
        "string" => js_string(v, src).map(|s| vec![format!("S:{s}")]),
        "array" => {
            let mut out = vec![];
            for e in named_children(v) {
                let e = strip_as(e);
                match e.kind() {
                    "string" => out.push(format!("S:{}", js_string(e, src)?)),
                    "spread_element" => out.push(format!("R:{}", text(e.named_child(0)?, src))),
                    "identifier" | "member_expression" => out.push(format!("R:{}", text(e, src))),
                    "comment" => {}
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

fn resolve(raw: &RawConst, all: &HashMap<String, (u32, RawConst)>, depth: u8) -> Vec<String> {
    let mut out = vec![];
    for r in raw {
        if let Some(s) = r.strip_prefix("S:") {
            out.push(s.to_string());
        } else if let Some(name) = r.strip_prefix("R:") {
            match all.get(name) {
                Some((_, inner)) if depth < 8 => out.extend(resolve(inner, all, depth + 1)),
                _ => out.push(format!("@{name}")),
            }
        }
    }
    let mut seen = HashSet::new();
    out.retain(|x| seen.insert(x.clone()));
    out
}

/// Resolve a role expression node (array literal, identifier or member) with the file's local consts.
pub fn role_values(n: Node, src: &str, consts: &HashMap<String, (u32, Vec<String>)>) -> Vec<String> {
    let n = strip_as(n);
    let raw = match n.kind() {
        "identifier" | "member_expression" => vec![format!("R:{}", text(n, src))],
        _ => raw_value(n, src).unwrap_or_default(),
    };
    resolve(&raw, consts, 0)
}

/// Public access to the file-local const table (for the router extractor).
pub fn local_consts(root: Node, src: &str) -> HashMap<String, (u32, Vec<String>)> {
    collect_consts(root, src)
}
