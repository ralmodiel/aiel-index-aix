//! Vue / Svelte single-file components: every `<script>` block goes through the TypeScript extractors with its lines
//! kept in place (the block is padded with the lines above it), so member and string line numbers are the file's own.

use std::sync::LazyLock;

use regex::Regex;

use tree_sitter::Node;

use crate::codegraph::{Member, Ref};
use crate::model::*;
use crate::ts_util::*;

static SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<script\b([^>]*)>(.*?)</script\s*>").unwrap());

/// Script blocks of a component: (line offset of the block's first line, code).
pub fn script_blocks(text: &str) -> Vec<(usize, String)> {
    SCRIPT
        .captures_iter(text)
        .filter(|c| !c[1].contains("type=\"application/json\"") && !c[1].contains("type=\"text/template\""))
        .map(|c| {
            let m = c.get(2).unwrap();
            (text[..m.start()].matches('\n').count(), m.as_str().to_string())
        })
        .collect()
}

/// A SourceFile for one block: same path, code preceded by blank lines so line numbers match the component.
pub fn block_file(f: &SourceFile, off: usize, code: &str) -> SourceFile {
    SourceFile::new(f.path.clone(), format!("{}{}", "\n".repeat(off), code))
}

/// Component name: the file's stem.
fn comp_name(f: &SourceFile) -> String {
    let base = f.path.rsplit('/').next().unwrap_or(&f.path);
    base.split('.').next().unwrap_or(base).to_string()
}

fn member(f: &SourceFile, comp: &str, name: &str, kind: &str, line: u32, end_line: u32, sig: String) -> Member {
    Member {
        file: f.path.clone(),
        line,
        end_line: end_line.max(line),
        name: name.to_string(),
        container: Some(comp.to_string()),
        qname: format!("{comp}.{name}"),
        kind: kind.into(),
        sig,
        vis: "public".into(),
        annos: vec![],
        is_static: false,
        supers: vec![],
        ret: String::new(),
    }
}

fn key_text(n: Node, src: &str) -> String {
    text(n, src).trim_matches(['"', '\'']).to_string()
}

/// Options-API members (`methods: {}` / `computed: {}` of the default export) and Svelte `$:` statements of one block.
fn pseudo_members(bf: &SourceFile, comp: &str, svelte: bool) -> Vec<Member> {
    let src = bf.text.as_str();
    let Some(tree) = parse(&typescript(), src) else { return vec![] };
    let root = tree.root_node();
    let mut out = vec![];
    for top in named_children(root) {
        if svelte && top.kind() == "labeled_statement" && top.child_by_field_name("label").is_some_and(|l| text(l, src) == "$") {
            let body = named_children(top).into_iter().find(|c| c.kind() != "statement_identifier");
            let first: String = body.map(|b| text(b, src)).unwrap_or("").chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$' || *c == '.').collect();
            let first = if first.is_empty() { format!("L{}", line(top)) } else { first };
            let nm = format!("$: {first}");
            let sig = format!("$: {}", squash(text(top, src).trim_start_matches('$').trim_start_matches(':')).chars().take(80).collect::<String>());
            out.push(member(bf, comp, &nm, "function", line(top), end_line(top), sig));
            continue;
        }
        if top.kind() != "export_statement" || !children(top).iter().any(|c| text(*c, src) == "default") {
            continue;
        }
        let Some(mut obj) = top.child_by_field_name("value") else { continue };
        // defineComponent({ .. }) / Vue.extend({ .. })
        if obj.kind() == "call_expression" {
            if let Some(a) = obj.child_by_field_name("arguments").and_then(|a| named_children(a).into_iter().find(|c| c.kind() == "object")) {
                obj = a;
            }
        }
        if obj.kind() != "object" {
            continue;
        }
        for pair in named_children(obj) {
            if pair.kind() != "pair" {
                continue;
            }
            let (Some(k), Some(v)) = (pair.child_by_field_name("key"), pair.child_by_field_name("value")) else { continue };
            let section = key_text(k, src);
            if !matches!(section.as_str(), "methods" | "computed") || v.kind() != "object" {
                continue;
            }
            for m in named_children(v) {
                let name = match m.kind() {
                    "method_definition" => m.child_by_field_name("name").map(|n| key_text(n, src)),
                    "pair" => m.child_by_field_name("key").map(|n| key_text(n, src)),
                    _ => None,
                };
                let Some(name) = name.filter(|n| !n.is_empty()) else { continue };
                out.push(member(bf, comp, &name, "method", line(m), end_line(m), format!("{section} {name}()")));
            }
        }
    }
    out
}

/// Names a template may use: callee candidates found in an expression (`f(x)`, `a.b(c)`, a bare `onClick`).
fn template_refs(expr: &str) -> Vec<(String, bool)> {
    static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([A-Za-z_$][\w$]*)\s*\(").unwrap());
    static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*([A-Za-z_$][\w$]*)\s*$").unwrap());
    let mut out = vec![];
    if let Some(c) = IDENT.captures(expr) {
        out.push((c[1].to_string(), false));
        return out;
    }
    for c in CALL.captures_iter(expr) {
        let m = c.get(1).unwrap();
        // a member call (`list.map(`) belongs to the object, not to the component's own functions
        if expr[..m.start()].trim_end().ends_with('.') {
            continue;
        }
        if matches!(m.as_str(), "if" | "for" | "while" | "function" | "return" | "typeof") {
            continue;
        }
        out.push((m.as_str().to_string(), true));
    }
    out
}

/// Template expressions of a component with the file line of each: Vue directives / mustaches, Svelte `{expr}`.
fn template_exprs(text: &str, vue: bool) -> Vec<(u32, String)> {
    static VUE_ATTR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?:^|[\s<])(?:@[\w.:-]+|:[\w.:-]+|v-[\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());
    static MUSTACHE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)\{\{(.*?)\}\}").unwrap());
    static SV_ATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:^|[\s<])[\w:.|-]+\s*=\s*\{([^{}]*)\}"#).unwrap());
    static SV_EXPR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{[#:/@]?(?:if|each|await|key|html|const)?\s*([^{}]*)\}").unwrap());
    // markup only: script and style blocks blanked (newlines kept)
    let blank = |t: &str| -> String {
        static BLOCK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<(script|style)\b[^>]*>.*?</(script|style)\s*>").unwrap());
        BLOCK.replace_all(t, |c: &regex::Captures| c[0].chars().map(|ch| if ch == '\n' { '\n' } else { ' ' }).collect::<String>()).into_owned()
    };
    let t = blank(text);
    let line_of = |off: usize| t[..off].matches('\n').count() as u32 + 1;
    let mut out = vec![];
    if vue {
        for c in VUE_ATTR.captures_iter(&t) {
            let g = c.get(1).or_else(|| c.get(2)).unwrap();
            out.push((line_of(g.start()), g.as_str().to_string()));
        }
        for c in MUSTACHE.captures_iter(&t) {
            let g = c.get(1).unwrap();
            out.push((line_of(g.start()), g.as_str().to_string()));
        }
    } else {
        for c in SV_ATTR.captures_iter(&t) {
            let g = c.get(1).unwrap();
            out.push((line_of(g.start()), g.as_str().to_string()));
        }
        for c in SV_EXPR.captures_iter(&t) {
            let g = c.get(1).unwrap();
            if !g.as_str().trim().is_empty() {
                out.push((line_of(g.start()), g.as_str().to_string()));
            }
        }
    }
    out
}

/// Code-graph rows for a component (members and refs of its script blocks, Options-API members, template uses).
pub fn file(f: &SourceFile, rows: &mut Rows) {
    let vue = f.ext() == "vue";
    let comp = comp_name(f);
    let first_member = rows.members.len();
    let first_ref = rows.refs.len();
    let mut pseudo: Vec<Member> = vec![];
    for (off, code) in script_blocks(&f.text) {
        let bf = block_file(f, off, &code);
        crate::codegraph::ts_file(&bf, rows);
        pseudo.extend(pseudo_members(&bf, &comp, !vue));
    }
    // refs written inside a pseudo member (no enclosing declaration) belong to it, not to the file
    for r in rows.refs[first_ref..].iter_mut() {
        if r.caller.is_empty() && r.kind != "import" {
            if let Some(m) = pseudo.iter().filter(|m| m.line <= r.line && r.line <= m.end_line).min_by_key(|m| m.end_line - m.line) {
                r.caller = m.qname.clone();
                r.caller_line = m.line;
            }
        }
    }
    // template: expressions are uses by the component; only names the script defines or imports are worth an edge
    let mut known: std::collections::HashSet<String> = rows.members[first_member..].iter().map(|m| m.name.clone()).collect();
    known.extend(pseudo.iter().map(|m| m.name.clone()));
    known.extend(rows.refs[first_ref..].iter().filter(|r| r.kind == "import").map(|r| r.callee.clone()));
    let exprs = template_exprs(&f.text, vue);
    let tline = exprs.iter().map(|e| e.0).min();
    if let Some(tl) = tline {
        let tend = exprs.iter().map(|e| e.0).max().unwrap_or(tl);
        let tm = member(f, &comp, "template", "method", tl, tend, "template".into());
        let mut any = false;
        for (ln, e) in exprs {
            for (name, is_call) in template_refs(&e) {
                if !known.contains(&name) {
                    continue;
                }
                any = true;
                rows.refs.push(Ref {
                    file: f.path.clone(),
                    line: ln,
                    caller: tm.qname.clone(),
                    caller_line: tm.line,
                    callee: name,
                    recv: String::new(),
                    recv_type: String::new(),
                    kind: if is_call { "call" } else { "ref" }.into(),
                    conf: "name".into(),
                    argc: -1,
                });
            }
        }
        if any {
            pseudo.push(tm);
        }
    }
    rows.members.extend(pseudo);
}
