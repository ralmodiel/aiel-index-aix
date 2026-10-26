//! Scripts: path, header comment and usage lines, so "is there already a script for X" is one lookup.

use std::path::Path;

use std::sync::LazyLock;

use regex::Regex;

use crate::model::*;
use crate::pybash::is_shell;
use crate::text::{redact, Lines};
use crate::Extractor;

static FLAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:^|[^\w-])(--[a-z][\w-]{1,30})").unwrap());
/// A string literal that ends in `/api` (e.g. `"http://localhost:8080/api" + p`): the file's other path
/// literals are relative to the API base.
static API_BASE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"/api/?['"`]"#).unwrap());
/// A relative API path: `/orders/items/{}/lines` once placeholders are folded.
static REL_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/[a-z][\w-]*(?:/[\w%{}$.:-]+)*/?").unwrap());
static API_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/api/[\w/{}$.:%-]*").unwrap());
/// `"POST", ` just before a literal: the literal is the path of an HTTP call (`call("POST", f"/x/{id}")`)
static METHOD_BEFORE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*[fFrRbB]?$"#).unwrap());

/// One path-shaped string literal: where its text starts, the text with every `{...}` / `${...}` placeholder
/// (f-string expressions with subscripts and quotes, `r['id']`) folded to `{x}`, whether a `+` follows it (a
/// concatenated id: `"/x/" + id`) and whether an HTTP method literal precedes it.
struct PathLit {
    at: usize,
    text: String,
    plus: bool,
    after_method: bool,
}

fn path_literals(t: &str) -> Vec<PathLit> {
    let b = t.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 1 < b.len() {
        let q = b[i];
        if !matches!(q, b'"' | b'\'' | b'`') || b[i + 1] != b'/' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut depth = 0usize;
        let mut text = String::new();
        let mut closed = false;
        while j < b.len() && j - i < 400 {
            let c = b[j];
            if c == b'\n' && q != b'`' {
                break;
            }
            if depth == 0 && c == q {
                closed = true;
                break;
            }
            if c == b'{' {
                if depth == 0 {
                    text.push_str("{x");
                }
                depth += 1;
            } else if c == b'}' && depth > 0 {
                depth -= 1;
                if depth == 0 {
                    text.push('}');
                }
            } else if depth == 0 {
                let ch_len = t[j..].chars().next().map_or(1, char::len_utf8);
                text.push_str(&t[j..j + ch_len]);
                j += ch_len;
                continue;
            }
            j += 1;
        }
        if !closed {
            i += 1;
            continue;
        }
        let rest = t[j + 1..].trim_start_matches([' ', '\t']);
        let mut k = i.saturating_sub(24);
        while !t.is_char_boundary(k) {
            k += 1;
        }
        let before = t[k..i].trim_end_matches([' ', '\t']);
        out.push(PathLit { at: i + 1, text, plus: rest.starts_with('+'), after_method: METHOD_BEFORE.is_match(before) });
        i = j + 1;
    }
    out
}

/// `/api/...` literals in a file as script refs; when the file builds URLs from an `/api` base, its relative path
/// literals (`"/fees/%s/payments"`) count too, prefixed with `/api`; a relative literal right after an HTTP method
/// literal (`call("POST", f"/x/{id}/unlock")`, the helper adding the base) counts as both `/x/...` and `/api/x/...`.
/// A literal ending in `/` that is concatenated (`"/x/" + id`) ends in a placeholder.
pub fn api_refs(f: &SourceFile, rows: &mut Rows) {
    let lt = Lines::new(&f.text);
    let mut seen = std::collections::HashSet::new();
    let mut push = |line: u32, norm: String| {
        if seen.insert((line, norm.clone())) {
            rows.script_refs.push(ScriptRef { file: f.path.clone(), line, norm_path: norm });
        }
    };
    let base = API_BASE.is_match(&f.text);
    for l in path_literals(&f.text) {
        let tail = |p: &str| if l.plus && p.ends_with('/') { format!("{p}{{x}}") } else { p.to_string() };
        if let Some(m) = API_PATH.find(&l.text) {
            push(lt.at(l.at), norm_path(&tail(m.as_str())));
            continue;
        }
        if l.text.starts_with("/api") {
            continue;
        }
        let Some(m) = REL_PATH.find(&l.text) else { continue };
        // a literal path must be the whole literal up to its query string (not a prose line that starts with /)
        if !l.text[m.end()..].is_empty() && !l.text[m.end()..].starts_with('?') {
            continue;
        }
        let p = tail(m.as_str());
        if base || l.after_method {
            push(lt.at(l.at), norm_path(&format!("/api{p}")));
        }
        if l.after_method && !base {
            push(lt.at(l.at), norm_path(&p));
        }
    }
}

fn kind_of(path: &str) -> &'static str {
    if path.contains("/regress/") {
        "regress"
    } else if path.starts_with("e2e/") && !path[4..].contains('/') && path.ends_with(".mjs") {
        "audit"
    } else if path.contains("/check-") {
        "check"
    } else if path.starts_with("e2e/") {
        "e2e"
    } else {
        "script"
    }
}

pub struct Scripts;

const SCRIPT_DIRS: &[&str] = &["scripts", "script", "bin", "tools", "hack", "ci", ".github"];

pub fn is_script(f: &SourceFile) -> bool {
    if is_shell(f) || f.text.starts_with("#!") {
        return true;
    }
    let in_dir = f.path.split('/').rev().skip(1).any(|seg| SCRIPT_DIRS.contains(&seg));
    let e2e_top = f.path.starts_with("e2e/") && matches!(f.ext(), "mjs" | "sh" | "js");
    (in_dir || e2e_top) && matches!(f.ext(), "py" | "mjs" | "js" | "cjs" | "ts" | "rb" | "pl" | "ps1" | "sh")
}

impl Extractor for Scripts {
    fn name(&self) -> &'static str {
        "scripts"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        matches!(ext_of(path), "sh" | "bash" | "zsh" | "" | "py" | "mjs" | "js" | "cjs" | "ts" | "rb" | "pl" | "ps1")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files.iter().filter(|f| is_script(f)) {
            let (header, usage) = header_and_usage(&f.text);
            let mut flags: Vec<String> = vec![];
            for c in FLAG.captures_iter(&f.text) {
                let x = c[1].to_string();
                if !flags.contains(&x) && flags.len() < 20 {
                    flags.push(x);
                }
            }
            rows.scripts.push(Script {
                file: f.path.clone(),
                kind: kind_of(&f.path).into(),
                header: redact(&header),
                usage: redact(&usage),
                flags: flags.join(" "),
            });
            api_refs(f, &mut rows);
        }
        rows
    }
}

pub fn header_and_usage(text: &str) -> (String, String) {
    let mut header = vec![];
    let mut in_block = false;
    let mut in_doc: Option<&str> = None;
    for (i, raw) in text.lines().enumerate() {
        let l = raw.trim();
        if i == 0 && l.starts_with("#!") {
            continue;
        }
        if header.len() >= 15 {
            break;
        }
        if let Some(q) = in_doc {
            let done = l.contains(q);
            let t = l.replace(q, "");
            if !t.trim().is_empty() {
                header.push(t.trim().to_string());
            }
            if done {
                break;
            }
            continue;
        }
        if in_block {
            let done = l.contains("*/");
            let t = l.trim_start_matches('*').replace("*/", "");
            if !t.trim().is_empty() {
                header.push(t.trim().to_string());
            }
            if done {
                in_block = false;
                if !header.is_empty() {
                    break;
                }
            }
            continue;
        }
        if l.is_empty() {
            if header.is_empty() {
                continue;
            }
            break;
        }
        if l.starts_with("set -")
            || l.starts_with("'use strict'")
            || l.starts_with("# -*-")
            || l.starts_with("# shellcheck")
        {
            continue;
        }
        if let Some(c) = l.strip_prefix('#').or_else(|| l.strip_prefix("//")) {
            let c = c.trim_start_matches(['#', '/', '-', '=']).trim();
            if !c.is_empty() {
                header.push(c.to_string());
            }
            continue;
        }
        if l.starts_with("/*") {
            in_block = true;
            let t = l.trim_start_matches("/*").trim_start_matches('*').replace("*/", "");
            if !t.trim().is_empty() {
                header.push(t.trim().to_string());
            }
            if l.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if l.starts_with("\"\"\"") || l.starts_with("'''") || l.starts_with("r\"\"\"") {
            let q = if l.contains("\"\"\"") { "\"\"\"" } else { "'''" };
            let rest = l.trim_start_matches('r').trim_start_matches(q);
            if rest.contains(q) {
                header.push(rest.replace(q, "").trim().to_string());
                break;
            }
            if !rest.trim().is_empty() {
                header.push(rest.trim().to_string());
            }
            in_doc = Some(q);
            continue;
        }
        if l.starts_with("import ") || l.starts_with("from ") || l.starts_with("const ") || l.starts_with("require(") {
            if header.is_empty() {
                continue;
            }
            break;
        }
        break;
    }
    let mut usage = vec![];
    for l in text.lines().take(200) {
        let t = l.trim().trim_start_matches(['#', '/', '*', ' ']).trim();
        let lower = t.to_ascii_lowercase();
        if (lower.starts_with("usage:") || lower.contains("usage: ") || lower.starts_with("example:"))
            && usage.len() < 5
        {
            let t = t.trim_matches(['"', '\'', '`', ';', ')', '(']).trim();
            let t = t.trim_start_matches("echo ").trim_matches(['"', '\'']);
            if !usage.iter().any(|u: &String| u == t) {
                usage.push(t.to_string());
            }
        }
    }
    (header.join(" | ").chars().take(1200).collect(), usage.join(" | "))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bash_header() {
        let (h, u) =
            header_and_usage("#!/bin/bash\n# Gate: build + test.\n# Usage: gate.sh [--fast]\nset -e\necho hi\n");
        assert_eq!(h, "Gate: build + test. | Usage: gate.sh [--fast]");
        assert_eq!(u, "Usage: gate.sh [--fast]");
    }
    #[test]
    fn py_docstring() {
        let (h, _) = header_and_usage("#!/usr/bin/env python3\n\"\"\"Count rows.\n\nMore.\n\"\"\"\nimport os\n");
        assert_eq!(h, "Count rows. | More.");
    }
    #[test]
    fn relative_api_paths_behind_an_api_base() {
        let py = "BASE = \"http://localhost:8080/api\"\n\
                  call(T, \"POST\", \"/fees/assessments/%s/payments\" % aid)\n\
                  call(T, \"DELETE\", f\"/fees/assessments/{aid}/payments/{pid}?reason=x\")\n\
                  open(\"/tmp/out.txt\")\n";
        let mut rows = Rows::default();
        api_refs(&SourceFile::new("scripts/regress/d38-money.py", py), &mut rows);
        let norms: Vec<_> = rows.script_refs.iter().map(|r| r.norm_path.as_str()).collect();
        assert!(norms.contains(&"/api/fees/assessments/{}/payments"), "{norms:?}");
        assert!(norms.contains(&"/api/fees/assessments/{}/payments/{}"), "{norms:?}");
        // no API base: relative literals are ignored
        let mut rows = Rows::default();
        api_refs(&SourceFile::new("scripts/x.py", "open(\"/fees/a\")\n"), &mut rows);
        assert!(rows.script_refs.is_empty());
    }
    #[test]
    fn subscripts_printf_method_position_and_concatenation() {
        let py = "call(\"POST\", f\"/api/orders/{r['id']}/approve\", {}, A)\n\
                  call(A, \"POST\", \"/api/orders/%s/request-review\" % ids[4])\n\
                  call(\"POST\", f\"/orders/{oid}/cancel\", {\"reason\": \"x\"})\n\
                  call(\"DELETE\", \"/api/orders/discounts/\" + did)\n\
                  print(\"/not/a/call\")\n";
        let mut rows = Rows::default();
        api_refs(&SourceFile::new("scripts/check-orders.py", py), &mut rows);
        let norms: Vec<(u32, &str)> = rows.script_refs.iter().map(|r| (r.line, r.norm_path.as_str())).collect();
        assert!(norms.contains(&(1, "/api/orders/{}/approve")), "{norms:?}");
        assert!(norms.contains(&(2, "/api/orders/{}/request-review")), "{norms:?}");
        assert!(norms.contains(&(3, "/api/orders/{}/cancel")) && norms.contains(&(3, "/orders/{}/cancel")), "{norms:?}");
        assert!(norms.contains(&(4, "/api/orders/discounts/{}")), "{norms:?}");
        assert!(!norms.iter().any(|(l, _)| *l == 5), "{norms:?}");
        // the old cut-offs are gone
        assert!(!norms.contains(&(1, "/api/orders/{}")) && !norms.contains(&(2, "/api/orders")), "{norms:?}");
    }
}
