//! MarkLogic routes: REST API resource extensions (a module declaring `…/rest-api/resource/NAME` with `get` / `put` /
//! `post` / `delete` functions, or `services/NAME.sjs` exporting `GET` / `PUT` / `POST` / `DELETE`) are endpoints
//! `METHOD /v1/resources/NAME`; REST transforms (`…/rest-api/transform/NAME`) get a note. The declarative URL rewriter
//! (`rewriter.xml`: `<match-path matches|prefix|any-of>` … `<dispatch>` / `<set-path>`), `<request uri endpoint>`
//! routes of the App Services REST library, and an XQuery URL rewriter (`xdmp:get-request-url()` with a literal
//! `replace(…, "^/x", "/m.xqy")` or `if (matches|starts-with(…, "/x")) then "/m.xqy"`) are endpoints whose handler
//! is the module path, when the pattern and the module are literals.

use std::sync::LazyLock;

use regex::Regex;

use super::{push_ep, Ep};
use crate::lang::xquery::{self, Tok, K};
use crate::model::*;

fn is_xq(p: &str) -> bool {
    xquery::EXTS.contains(&ext_of(p))
}

fn is_rewriter_xml(p: &str) -> bool {
    let n = p.rsplit('/').next().unwrap_or(p).to_ascii_lowercase();
    n.ends_with(".xml") && n.contains("rewriter")
}

super::ext_impl!(MarkLogic, "marklogic", |p| is_xq(p) || is_rewriter_xml(p) || ext_of(p) == "sjs", file);

const RESOURCE: &str = "http://marklogic.com/rest-api/resource/";
const TRANSFORM: &str = "http://marklogic.com/rest-api/transform/";

fn is_module_path(s: &str) -> bool {
    let p = s.split('?').next().unwrap_or(s);
    xquery::EXTS.iter().chain(["sjs"].iter()).any(|e| p.ends_with(&format!(".{e}")))
}

/// A URL regex as a route path: `^/app/(\w+)$` -> `/app/{}`; anything else regex-like stays as written.
pub fn regex_path(re: &str) -> String {
    let mut s = re.trim().trim_start_matches('^').trim_end_matches('$').to_string();
    // capture groups -> one placeholder
    let mut out = String::new();
    let mut depth = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    if depth == 0 {
                        if matches!(n, '.' | '/' | '-' | '?' | '+' | '*') {
                            out.push(n);
                        } else {
                            out.push('\\');
                            out.push(n);
                        }
                    }
                }
            }
            '(' => {
                if depth == 0 {
                    out.push_str("{}");
                }
                depth += 1;
            }
            ')' => depth -= 1,
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    s = out.replace("/?", "/").replace(".*", "{}");
    s.trim_end_matches('?').to_string()
}

fn ep(rows: &mut Rows, f: &SourceFile, line: u32, method: &str, path: &str, class: &str, handler: &str) {
    if path.is_empty() {
        return;
    }
    push_ep(rows, Ep { file: &f.path, line, method, path, class, handler, roles: vec![] });
}

fn file(f: &SourceFile, rows: &mut Rows) {
    if is_rewriter_xml(&f.path) {
        rewriter_xml(f, rows);
    } else if ext_of(&f.path) == "sjs" {
        sjs_resource(f, rows);
    } else {
        xqy(f, rows);
    }
}

fn line_at(text: &str, pos: usize) -> u32 {
    text[..pos.min(text.len())].matches('\n').count() as u32 + 1
}

fn xqy(f: &SourceFile, rows: &mut Rows) {
    let m = xquery::parse(&f.text);
    let t = &m.lx.toks;
    if let Some((_, uri, tok)) = &m.lib {
        if let Some(name) = uri.strip_prefix(RESOURCE).filter(|n| !n.is_empty()) {
            for d in m.decls.iter().filter(|d| !d.var) {
                let meth = d.local.to_ascii_lowercase();
                if matches!(meth.as_str(), "get" | "put" | "post" | "delete") {
                    let q = format!("{}:{}", d.prefix, d.local);
                    ep(rows, f, m.lx.line(t[d.first].pos), &meth, &format!("/v1/resources/{name}"), name, &q);
                }
            }
        } else if let Some(name) = uri.strip_prefix(TRANSFORM).filter(|n| !n.is_empty()) {
            rows.notes.push(Note {
                file: f.path.clone(),
                line: m.lx.line(t[*tok].pos),
                kind: "marklogic".into(),
                reference: format!("transform:{name}"),
                text: format!("MarkLogic REST transform '{name}': applied with ?transform={name} on /v1/documents, /v1/search and other REST calls"),
            });
        }
    }
    request_routes(f, rows);
    if f.text.contains("get-request-url") || f.text.contains("get-request-path") {
        url_rewriter(f, &m, rows);
    }
}

/// `<request uri="^/x$" endpoint="/x.xqy">` (App Services REST library, Roxy): literal uri and endpoint only.
fn request_routes(f: &SourceFile, rows: &mut Rows) {
    static REQ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<(?:\w+:)?request\s+uri\s*=\s*"([^"{]*)"\s+endpoint\s*=\s*"([^"{]*)""#).unwrap());
    static METH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<(?:\w+:)?http\s+method\s*=\s*"(\w+)""#).unwrap());
    for c in REQ.captures_iter(&f.text) {
        let (all, uri, endpoint) = (c.get(0).unwrap(), &c[1], &c[2]);
        if !is_module_path(endpoint) {
            continue;
        }
        // methods: `<http method="GET"/>` children up to the end of this request element
        let rest = &f.text[all.end()..];
        let head_end = rest.find('>').unwrap_or(rest.len());
        let body = if rest[..head_end].ends_with('/') { "" } else { &rest[..rest.find("request>").unwrap_or(rest.len())] };
        let mut methods: Vec<String> = METH.captures_iter(body).map(|m| m[1].to_string()).collect();
        if methods.is_empty() {
            methods.push("ANY".into());
        }
        let line = line_at(&f.text, all.start());
        for me in methods {
            ep(rows, f, line, &me, &regex_path(uri), "request", endpoint.split('?').next().unwrap_or(endpoint));
        }
    }
}

/// XQuery URL rewriter: `replace($url, "^/x/(.*)", "/m.xqy?id=$1")` and `if (matches($url, "^/x")) then "/m.xqy"`.
fn url_rewriter(f: &SourceFile, m: &xquery::Module, rows: &mut Rows) {
    let t: &[Tok] = &m.lx.toks;
    for i in 0..t.len() {
        let x = &t[i];
        if x.k != K::Name {
            continue;
        }
        let local = xquery::split_q(&x.s).1;
        if local == "replace" && t.get(i + 1).is_some_and(|y| y.k == K::P && y.s == "(") {
            let close = xquery::close_of(t, i + 1);
            let strs: Vec<&Tok> = t[i + 2..close].iter().filter(|y| y.k == K::Str).collect();
            if strs.len() >= 2 && is_module_path(&strs[1].s) {
                let target = strs[1].s.split('?').next().unwrap_or("");
                ep(rows, f, m.lx.line(strs[0].pos), "ANY", &regex_path(&strs[0].s), "url-rewriter", target);
            }
        }
        if local == "then" {
            let Some(target) = t.get(i + 1).filter(|y| y.k == K::Str && is_module_path(&y.s)) else { continue };
            // the condition: the `if (` … `)` right before `then`
            if i == 0 || !(t[i - 1].k == K::P && t[i - 1].s == ")") {
                continue;
            }
            let Some(open) = open_of(t, i - 1) else { continue };
            if !(open > 0 && t[open - 1].k == K::Name && t[open - 1].s == "if") {
                continue;
            }
            if let Some(lit) = t[open..i].iter().find(|y| y.k == K::Str && (y.s.starts_with('/') || y.s.starts_with('^'))) {
                let tg = target.s.split('?').next().unwrap_or("");
                ep(rows, f, m.lx.line(lit.pos), "ANY", &regex_path(&lit.s), "url-rewriter", tg);
            }
        }
    }
}

/// The `(` matching the `)` at `close`.
fn open_of(t: &[Tok], close: usize) -> Option<usize> {
    let mut d = 0i32;
    for k in (0..=close).rev() {
        if t[k].k == K::P {
            match t[k].s.as_str() {
                ")" | "]" | "}" => d += 1,
                "(" | "[" | "{" => {
                    d -= 1;
                    if d == 0 {
                        return (t[k].s == "(").then_some(k);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// `services/NAME.sjs` exporting `GET` / `PUT` / `POST` / `DELETE`: a REST resource extension.
fn sjs_resource(f: &SourceFile, rows: &mut Rows) {
    static EXP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^[ \t]*(?:module\.)?exports\.(GET|PUT|POST|DELETE)\s*=").unwrap());
    let in_services = f.path.starts_with("services/") || f.path.contains("/services/");
    if !in_services {
        return;
    }
    let name = f.path.rsplit('/').next().unwrap_or(&f.path).trim_end_matches(".sjs").to_string();
    for c in EXP.captures_iter(&f.text) {
        let g = c.get(0).unwrap();
        ep(rows, f, line_at(&f.text, g.start()), &c[1], &format!("/v1/resources/{name}"), &name, &c[1]);
    }
}

/// Declarative rewriter: one endpoint per `<dispatch>` with the innermost path matcher and method matcher around it.
fn rewriter_xml(f: &SourceFile, rows: &mut Rows) {
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)<!--.*?-->|<(/?)(?:[\w.-]+:)?([\w.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(/?)>"#).unwrap());
    static ATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());
    // open elements: (name, attributes, path set inside)
    let mut stack: Vec<(String, Vec<(String, String)>, Option<String>)> = vec![];
    let mut last_end = 0usize;
    let mut open_text: Option<(String, usize)> = None;
    for c in TAG.captures_iter(&f.text) {
        let g = c.get(0).unwrap();
        if g.as_str().starts_with("<!--") {
            continue;
        }
        let close = !c[1].is_empty();
        let name = c[2].to_string();
        let selfclose = !c[4].is_empty();
        let text_before = f.text[last_end..g.start()].trim().to_string();
        last_end = g.end();
        if close {
            if let Some((n, at)) = open_text.take() {
                if n == name {
                    handle(f, rows, &mut stack, &name, &text_before, at);
                }
            }
            if let Some(k) = stack.iter().rposition(|s| s.0 == name) {
                stack.truncate(k);
            }
            continue;
        }
        let attrs: Vec<(String, String)> = ATTR
            .captures_iter(&c[3])
            .map(|a| (a[1].rsplit(':').next().unwrap_or(&a[1]).to_string(), a.get(2).or(a.get(3)).map(|x| x.as_str().to_string()).unwrap_or_default()))
            .collect();
        if selfclose {
            if name == "dispatch" {
                handle(f, rows, &mut stack, &name, "", g.start());
            }
            continue;
        }
        if name == "dispatch" || name == "set-path" {
            open_text = Some((name.clone(), g.start()));
        }
        stack.push((name, attrs, None));
    }

    fn handle(f: &SourceFile, rows: &mut Rows, stack: &mut [(String, Vec<(String, String)>, Option<String>)], name: &str, text: &str, at: usize) {
        let line = line_at(&f.text, at);
        if name == "set-path" {
            // remembered on the innermost enclosing element, read by a later `<dispatch/>`
            if let Some(top) = stack.iter_mut().rev().find(|s| s.0 != "set-path") {
                top.2 = Some(text.to_string());
            }
            return;
        }
        let target = if text.is_empty() { stack.iter().rev().find_map(|s| s.2.clone()).unwrap_or_default() } else { text.to_string() };
        let target = target.split('?').next().unwrap_or("").trim().to_string();
        if target.is_empty() || target.contains('$') && !is_module_path(&target) {
            return;
        }
        let attr = |s: &(String, Vec<(String, String)>, Option<String>), k: &str| s.1.iter().find(|a| a.0 == k).map(|a| a.1.clone());
        let mut paths: Vec<String> = vec![];
        if let Some(mp) = stack.iter().rev().find(|s| s.0 == "match-path") {
            if let Some(r) = attr(mp, "matches") {
                paths.push(regex_path(&r));
            } else if let Some(p) = attr(mp, "prefix") {
                paths.push(p);
            } else if let Some(a) = attr(mp, "any-of") {
                paths.extend(a.split_whitespace().map(str::to_string));
            }
        }
        if paths.is_empty() {
            return;
        }
        let methods: Vec<String> = stack
            .iter()
            .rev()
            .find(|s| s.0 == "match-method")
            .and_then(|s| attr(s, "any-of"))
            .map(|a| a.split_whitespace().map(str::to_string).collect())
            .unwrap_or_else(|| vec!["ANY".to_string()]);
        for p in &paths {
            for me in &methods {
                ep(rows, f, line, me, p, "rewriter", &target);
            }
        }
    }
}
