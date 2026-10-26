//! Frontend route tables written as objects: React Router (`createBrowserRouter([{ path, element, children }])`,
//! `useRoutes`) and Vue Router (`createRouter({ routes: [{ path, component, children }] })`).
//! JSX `<Route>` tables stay with `router.rs`; file-based routes (Next.js) with `next.rs`.

use tree_sitter::Node;

use super::*;
use crate::ts_util::*;
use crate::typescript::lang_for;

ext_impl!(
    FrontendRoutes,
    "route-objects",
    |p| matches!(ext_of(p), "ts" | "tsx" | "js" | "jsx" | "mjs" | "mts"),
    extract_file
);

const GATE: &[&str] = &[
    "createBrowserRouter",
    "createHashRouter",
    "createMemoryRouter",
    "useRoutes",
    "RouteObject",
    "createRouter",
    "vue-router",
    "RouteRecordRaw",
    "VueRouter",
    "createWebHistory",
];
const COMP_KEYS: &[&str] = &["element", "Component", "component", "lazy", "children", "redirect", "index"];

fn key_of<'a>(p: Node, src: &'a str) -> Option<&'a str> {
    p.child_by_field_name("key").map(|k| text(k, src).trim_matches(['"', '\'']))
}

fn pairs<'a>(obj: Node<'a>) -> Vec<Node<'a>> {
    named_children(obj).into_iter().filter(|c| c.kind() == "pair").collect()
}

fn get<'a>(obj: Node<'a>, src: &str, key: &str) -> Option<Node<'a>> {
    pairs(obj).into_iter().find(|p| key_of(*p, src) == Some(key)).and_then(|p| p.child_by_field_name("value"))
}

fn is_route_obj(obj: Node, src: &str) -> bool {
    obj.kind() == "object" && {
        let keys: Vec<&str> = pairs(obj).into_iter().filter_map(|p| key_of(p, src)).collect();
        (keys.contains(&"path") || keys.contains(&"index")) && keys.iter().any(|k| COMP_KEYS.contains(k))
    }
}

/// Component name from `element: <Users />`, `Component: Users`, `component: Users`, `lazy/component: () => import('./Users')`.
fn component(obj: Node, src: &str) -> (Option<String>, String) {
    if let Some(e) = get(obj, src, "element") {
        let mut found = None;
        let mut redirect = String::new();
        walk(e, |n| {
            if matches!(n.kind(), "jsx_self_closing_element" | "jsx_opening_element") && found.is_none() {
                let nm = n.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
                if nm == "Navigate" || nm == "Redirect" {
                    walk(n, |a| {
                        if a.kind() == "jsx_attribute" && text(a, src).starts_with("to=") {
                            redirect = text(a, src)[3..].trim_matches(['"', '\'', '{', '}']).to_string();
                        }
                        true
                    });
                    found = Some(String::new());
                } else if !matches!(
                    nm.as_str(),
                    "Suspense"
                        | "React.Suspense"
                        | "Fragment"
                        | "RequireAuth"
                        | "ProtectedRoute"
                        | "PrivateRoute"
                        | "AuthGuard"
                        | "RoleGuard"
                        | "ErrorBoundary"
                ) {
                    found = Some(nm);
                }
            }
            true
        });
        return (found.filter(|s| !s.is_empty()), redirect);
    }
    for k in ["Component", "component", "lazy"] {
        if let Some(v) = get(obj, src, k) {
            if v.kind() == "identifier" {
                return (Some(text(v, src).to_string()), String::new());
            }
            let mut spec = None;
            walk(v, |n| {
                if n.kind() == "call_expression"
                    && n.child_by_field_name("function").map(|f| text(f, src)) == Some("import")
                {
                    spec = n
                        .child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .and_then(|a| js_string(a, src));
                }
                spec.is_none()
            });
            if let Some(s) = spec {
                let stem = s.rsplit('/').next().unwrap_or(&s);
                let stem = stem.split('.').next().unwrap_or(stem);
                let stem = if stem == "index" { s.rsplit('/').nth(1).unwrap_or(stem) } else { stem };
                return (Some(stem.to_string()), String::new());
            }
        }
    }
    let r = get(obj, src, "redirect").and_then(|v| js_string(v, src)).unwrap_or_default();
    (None, r)
}

fn roles_of(obj: Node, src: &str) -> Vec<String> {
    let mut out = vec![];
    for k in ["meta", "handle"] {
        if let Some(m) = get(obj, src, k) {
            for kk in ["roles", "role", "permissions"] {
                if let Some(r) = get(m, src, kk) {
                    walk(r, |n| {
                        if let Some(s) = js_string(n, src) {
                            out.push(s);
                        }
                        true
                    });
                }
            }
        }
    }
    out
}

/// Path pieces of an object and its ancestors (outermost first).
fn full_path(obj: Node, src: &str) -> String {
    let mut parts: Vec<String> = vec![];
    let mut cur = Some(obj);
    let mut guard = 0;
    while let Some(o) = cur {
        guard += 1;
        if guard > 20 {
            break;
        }
        if let Some(p) = get(o, src, "path").and_then(|v| js_string(v, src)) {
            parts.push(p.clone());
            if p.starts_with('/') {
                break;
            }
        }
        // object -> array -> pair(children) -> object
        cur = o
            .parent()
            .and_then(|a| a.parent())
            .and_then(|p| p.parent())
            .filter(|x| x.kind() == "object" && is_route_obj(*x, src));
        if let Some(c) = cur {
            if o.parent().map(|a| a.kind()) != Some("array") || c.kind() != "object" {
                cur = None;
            }
        }
    }
    parts.reverse();
    let mut path = String::new();
    for p in parts {
        path = if p.starts_with('/') { p } else { join(&path, &p) };
    }
    if path.is_empty() {
        "/".into()
    } else {
        join("", &param_syntax(&path))
    }
}

fn extract_file(f: &SourceFile, rows: &mut Rows) {
    if !GATE.iter().any(|g| f.text.contains(g)) || !f.text.contains("path") {
        return;
    }
    let Some(tree) = parse(&lang_for(&f.path), &f.text) else { return };
    let src = &f.text;
    walk(tree.root_node(), |n| {
        if is_route_obj(n, src) && n.parent().map(|p| p.kind()) == Some("array") {
            let (comp, redirect) = component(n, src);
            let redirect = if redirect.is_empty() {
                get(n, src, "redirect").and_then(|v| js_string(v, src)).unwrap_or_default()
            } else {
                redirect
            };
            // a pure layout wrapper still counts as a route when it has a component
            if comp.is_some() || !redirect.is_empty() {
                rows.routes.push(Route {
                    file: f.path.clone(),
                    line: line(n),
                    path: full_path(n, src),
                    component: comp,
                    roles: roles_of(n, src),
                    role_expr: String::new(),
                    feature: String::new(),
                    redirect,
                });
            }
        }
        true
    });
}
