//! Next.js: `app/**/route.ts` handlers (`export GET/POST...`), `pages/api/**`, and page routes
//! (`app/**/page.tsx`, `pages/**`) as frontend routes.

use std::path::Path;

use regex::Regex;

use super::*;
use crate::Extractor;

pub struct NextRoutes;

const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

fn js_ext(p: &str) -> bool {
    matches!(ext_of(p), "ts" | "tsx" | "js" | "jsx" | "mjs")
}

/// URL path for a file below `app/` or `pages/`: route groups `(g)`, parallel slots `@s` and `index` vanish.
fn url_of(path: &str) -> Option<(bool, String)> {
    let parts: Vec<&str> = path.split('/').collect();
    let (i, is_app) = parts
        .iter()
        .position(|p| *p == "app")
        .map(|i| (i, true))
        .or_else(|| parts.iter().position(|p| *p == "pages").map(|i| (i, false)))?;
    let rest = &parts[i + 1..];
    let mut segs: Vec<String> = vec![];
    for (k, s) in rest.iter().enumerate() {
        let last = k == rest.len() - 1;
        if last {
            let stem = s.rsplit_once('.').map(|x| x.0).unwrap_or(s);
            let stem = stem.trim_end_matches(".page");
            if is_app {
                continue; // page / route / layout file name itself
            }
            if stem != "index" {
                segs.push(stem.to_string());
            }
        } else if (s.starts_with('(') && s.ends_with(')')) || s.starts_with('@') {
            continue;
        } else {
            segs.push(s.to_string());
        }
    }
    Some((is_app, param_syntax(&format!("/{}", segs.join("/")))))
}

fn is_next_app(repo: &Path, file: &str) -> bool {
    let mut dir = Path::new(file).parent();
    while let Some(d) = dir {
        if let Ok(t) = std::fs::read_to_string(repo.join(d).join("package.json")) {
            return t.contains("\"next\"");
        }
        dir = d.parent();
        if d.as_os_str().is_empty() {
            break;
        }
    }
    false
}

impl Extractor for NextRoutes {
    fn name(&self) -> &'static str {
        "nextjs"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        js_ext(path)
            && (path.starts_with("app/")
                || path.starts_with("pages/")
                || path.contains("/app/")
                || path.contains("/pages/"))
    }
    fn extract(&self, repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let Some((is_app, url)) = url_of(&f.path) else { continue };
            let stem = f.name().rsplit_once('.').map(|x| x.0).unwrap_or(f.name());
            let stem = stem.trim_end_matches(".page");
            if is_app && !matches!(stem, "route" | "page") {
                continue;
            }
            if !is_next_app(repo, &f.path) {
                continue;
            }
            if is_app && stem == "route" {
                app_route(f, &url, &mut rows);
            } else if !is_app && url.starts_with("/api") {
                if matches!(f.name().rsplit_once('.').map(|x| x.0), Some("_app" | "_document")) {
                    continue;
                }
                pages_api(f, &url, &mut rows);
            } else if !is_app && f.name().starts_with('_') {
                continue;
            } else {
                page(f, &url, &mut rows);
            }
        }
        rows
    }
}

fn line_at(t: &str, off: usize) -> u32 {
    t[..off.min(t.len())].bytes().filter(|b| *b == b'\n').count() as u32 + 1
}

fn app_route(f: &SourceFile, url: &str, rows: &mut Rows) {
    let t = &f.text;
    let decl =
        Regex::new(r"export\s+(?:async\s+)?(?:function\s+|const\s+|let\s+)(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
            .unwrap();
    let list = Regex::new(r"export\s*\{([^}]*)\}").unwrap();
    let mut seen: Vec<String> = vec![];
    for c in decl.captures_iter(t) {
        let m = c[1].to_string();
        if seen.contains(&m) {
            continue;
        }
        push_ep(
            rows,
            Ep {
                file: &f.path,
                line: line_at(t, c.get(0).unwrap().start()),
                method: &m,
                path: url,
                class: "",
                handler: &m,
                roles: auth_hint(t),
            },
        );
        seen.push(m);
    }
    for c in list.captures_iter(t) {
        for name in c[1].split(',') {
            let name = name.split_whitespace().last().unwrap_or("");
            if METHODS.contains(&name) && !seen.iter().any(|s| s == name) {
                push_ep(
                    rows,
                    Ep {
                        file: &f.path,
                        line: line_at(t, c.get(0).unwrap().start()),
                        method: name,
                        path: url,
                        class: "",
                        handler: name,
                        roles: auth_hint(t),
                    },
                );
                seen.push(name.to_string());
            }
        }
    }
}

/// Session/auth helper calls inside a handler file: a hint, not a role.
fn auth_hint(t: &str) -> Vec<String> {
    for (needle, name) in [
        ("getServerSession", "getServerSession"),
        ("auth()", "auth"),
        ("getSession", "getSession"),
        ("currentUser", "currentUser"),
        ("getToken(", "getToken"),
        ("supabase.auth.getUser", "supabase.auth.getUser"),
        ("withAuth", "withAuth"),
    ] {
        if t.contains(needle) {
            return vec![format!("auth:{name}")];
        }
    }
    vec![]
}

fn pages_api(f: &SourceFile, url: &str, rows: &mut Rows) {
    let t = &f.text;
    let Some(m) = Regex::new(r"export\s+default\s+(?:async\s+)?(?:function\s+(\w+)|(\w+))?").unwrap().captures(t)
    else {
        return;
    };
    let handler = m
        .get(1)
        .or(m.get(2))
        .map(|x| x.as_str().to_string())
        .filter(|s| s != "async" && s != "function")
        .unwrap_or_else(|| "handler".into());
    let l = line_at(t, m.get(0).unwrap().start());
    let mut methods: Vec<String> = vec![];
    for c in Regex::new(r#"req(?:uest)?\.method\s*(?:===|==|!==)\s*['"](GET|POST|PUT|DELETE|PATCH)['"]|case\s+['"](GET|POST|PUT|DELETE|PATCH)['"]"#).unwrap().captures_iter(t) {
        let x = c.get(1).or(c.get(2)).unwrap().as_str().to_string();
        if !methods.contains(&x) {
            methods.push(x);
        }
    }
    if methods.is_empty() {
        methods.push("ANY".into());
    }
    for me in methods {
        push_ep(
            rows,
            Ep { file: &f.path, line: l, method: &me, path: url, class: "", handler: &handler, roles: auth_hint(t) },
        );
    }
}

fn page(f: &SourceFile, url: &str, rows: &mut Rows) {
    let t = &f.text;
    let m =
        Regex::new(r"export\s+default\s+(?:async\s+)?(?:function\s+(\w+)|class\s+(\w+)|(\w+))").unwrap().captures(t);
    let (comp, l) = match &m {
        Some(c) => (
            c.get(1)
                .or(c.get(2))
                .or(c.get(3))
                .map(|x| x.as_str().to_string())
                .filter(|s| s != "async" && s != "function")
                .unwrap_or_else(|| "Page".into()),
            line_at(t, c.get(0).unwrap().start()),
        ),
        None => return,
    };
    rows.routes.push(Route {
        file: f.path.clone(),
        line: l,
        path: url.to_string(),
        component: Some(comp),
        roles: vec![],
        role_expr: String::new(),
        feature: String::new(),
        redirect: String::new(),
    });
}
