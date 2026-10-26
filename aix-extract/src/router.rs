//! React Router `<Route>` tables (with nested paths and role guards) and navigation menus
//! (`{ name, href, roles }` objects in Sidebar / nav / menu files).

use std::collections::HashMap;
use std::path::Path;

use tree_sitter::Node;

use crate::model::*;
use crate::ts_util::*;
use crate::typescript::{lang_for, local_consts, role_values};
use crate::Extractor;

pub struct ReactRouter;

/// JSX wrappers that are not the page component.
const WRAPPERS: &[&str] = &[
    "Route",
    "ProtectedRoute",
    "RequireAuth",
    "RequireRole",
    "Suspense",
    "ErrorBoundary",
    "ShellBoundary",
    "LazyBoundary",
    "React.Suspense",
    "Fragment",
    "React.Fragment",
    "RoleGuard",
    "Guard",
    "AuthGuard",
];
const ROLE_PROPS: &[&str] = &["requiredRoles", "roles", "allowedRoles", "anyRole", "role"];

fn is_menu_file(path: &str) -> bool {
    let n = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    n.contains("sidebar") || n.contains("navigation") || n.contains("menu") || n.starts_with("nav")
}

impl Extractor for ReactRouter {
    fn name(&self) -> &'static str {
        "react-router"
    }
    fn detect(&self, repo: &Path) -> bool {
        crate::package_json_mentions(repo, "react-router")
    }
    fn handles(&self, path: &str) -> bool {
        matches!(ext_of(path), "tsx" | "jsx" | "ts" | "js")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let has_routes = f.text.contains("<Route");
            let menu = is_menu_file(&f.path) && (f.text.contains("href:") || f.text.contains("path:"));
            if !has_routes && !menu {
                continue;
            }
            let Some(tree) = parse(&lang_for(&f.path), &f.text) else {
                continue;
            };
            let root = tree.root_node();
            let consts = local_consts(root, &f.text);
            if has_routes {
                routes(root, f, &consts, &mut rows);
            }
            if menu {
                menus(root, f, &consts, &mut rows);
            }
        }
        rows
    }
}

fn tag_name<'a>(n: Node, src: &'a str) -> Option<&'a str> {
    let open = match n.kind() {
        "jsx_element" => n.child_by_field_name("open_tag")?,
        "jsx_self_closing_element" => n,
        _ => return None,
    };
    open.child_by_field_name("name").map(|x| text(x, src))
}

fn attrs<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let open = if n.kind() == "jsx_element" { n.child_by_field_name("open_tag") } else { Some(n) };
    open.map(|o| named_children(o).into_iter().filter(|a| a.kind() == "jsx_attribute").collect()).unwrap_or_default()
}

fn attr<'t>(n: Node<'t>, name: &str, src: &str) -> Option<Option<Node<'t>>> {
    for a in attrs(n) {
        let kids = named_children(a);
        if kids.first().map(|k| text(*k, src)) == Some(name) {
            let v = kids.get(1).map(|v| if v.kind() == "jsx_expression" { v.named_child(0).unwrap_or(*v) } else { *v });
            return Some(v);
        }
    }
    None
}

fn route_path(n: Node, src: &str) -> Option<String> {
    if attr(n, "index", src).is_some() {
        return Some(String::new());
    }
    attr(n, "path", src).flatten().and_then(|v| js_string(v, src))
}

fn join(parent: &str, child: &str) -> String {
    if child.starts_with('/') {
        return child.to_string();
    }
    let p = parent.trim_end_matches('/');
    if child.is_empty() {
        return if p.is_empty() { "/".into() } else { p.to_string() };
    }
    format!("{p}/{child}")
}

fn routes(root: Node, f: &SourceFile, consts: &HashMap<String, (u32, Vec<String>)>, rows: &mut Rows) {
    let src = f.text.as_str();
    walk(root, |n| {
        if tag_name(n, src) != Some("Route") {
            return true;
        }
        let Some(own) = route_path(n, src) else {
            return true;
        };
        // full path from enclosing <Route path> ancestors
        let mut parts = vec![own];
        let mut cur = n;
        while let Some(p) = cur.parent() {
            if tag_name(p, src) == Some("Route") {
                if let Some(pp) = route_path(p, src) {
                    parts.push(pp);
                }
            }
            cur = p;
        }
        let mut full = String::from("/");
        for p in parts.iter().rev() {
            full = join(&full, p);
        }
        let mut component = None;
        let mut roles = vec![];
        let mut role_expr = String::new();
        let mut feature = String::new();
        let mut redirect = String::new();
        if let Some(Some(el)) = attr(n, "element", src) {
            walk(el, |c| {
                // props of wrappers (e.g. `<Suspense fallback={<Spinner/>}>`) are not the page
                if c.kind() == "jsx_attribute" {
                    return false;
                }
                if let Some(t) = tag_name(c, src) {
                    if t == "Navigate" {
                        if let Some(Some(to)) = attr(c, "to", src) {
                            redirect = js_string(to, src).unwrap_or_default();
                        }
                    }
                    if component.is_none() && !WRAPPERS.contains(&t) && t != "Navigate" {
                        component = Some(t.to_string());
                    }
                    for rp in ROLE_PROPS {
                        if let Some(Some(v)) = attr(c, rp, src) {
                            if role_expr.is_empty() {
                                role_expr = squash(text(v, src));
                            }
                            roles.extend(role_values(v, src, consts));
                        }
                    }
                    if let Some(Some(v)) = attr(c, "requiredFeature", src) {
                        feature = js_string(v, src).unwrap_or_default();
                    }
                }
                true
            });
        }
        rows.routes.push(Route {
            file: f.path.clone(),
            line: line(n),
            path: full,
            component,
            roles,
            role_expr,
            feature,
            redirect,
        });
        true
    });
}

fn pair_value<'t>(obj: Node<'t>, keys: &[&str], src: &str) -> Option<Node<'t>> {
    for p in named_children(obj) {
        if p.kind() == "pair" {
            if let Some(k) = p.child_by_field_name("key") {
                if keys.contains(&text(k, src).trim_matches(['"', '\''])) {
                    return p.child_by_field_name("value");
                }
            }
        }
    }
    None
}

/// Roles named by the checks in a condition: `has('a', B)`, `hasAnyRole(x, ['a','b'])`, `roles.includes('a')`.
fn guard_roles(cond: Node, src: &str, consts: &HashMap<String, (u32, Vec<String>)>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    walk(cond, |x| {
        if x.kind() == "call_expression" {
            let fname = x.child_by_field_name("function").map(|f| text(f, src).rsplit('.').next().unwrap_or("").to_string()).unwrap_or_default();
            if matches!(fname.as_str(), "has" | "hasRole" | "hasAnyRole" | "hasNavRole" | "includes" | "some") {
                if let Some(args) = x.child_by_field_name("arguments") {
                    for a in named_children(args) {
                        match js_string(a, src) {
                            Some(v) => out.push(v),
                            None => out.extend(role_values(a, src, consts)),
                        }
                    }
                }
            }
        }
        true
    });
    // plain role names, or a constant that resolves later across files (`@DATA_MANAGER`)
    out.retain(|r| {
        let b = r.strip_prefix('@');
        match b {
            Some(n) => !n.is_empty() && n.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
            None => !r.is_empty() && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') && r.chars().next().is_some_and(|c| c.is_ascii_lowercase()),
        }
    });
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert(r.clone()));
    out
}

/// Roles of a menu item with no `roles` key, from the code around it: the `if (has(..))` conditions it sits in, else (an
/// exported helper that builds a nav for one kind of account) every role the helper checks.
fn guarded_roles(n: Node, src: &str, consts: &HashMap<String, (u32, Vec<String>)>) -> Vec<String> {
    let mut r: Vec<String> = vec![];
    let mut func: Option<Node> = None;
    let mut cur = n;
    while let Some(p) = cur.parent() {
        if p.kind() == "if_statement" {
            if let Some(c) = p.child_by_field_name("condition") {
                r.extend(guard_roles(c, src, consts));
            }
        }
        if func.is_none() && p.kind() == "function_declaration" {
            func = Some(p);
        }
        cur = p;
    }
    if r.is_empty() {
        if let Some(f) = func.filter(|f| end_line(*f).saturating_sub(line(*f)) < 80) {
            walk(f, |x| {
                if x.kind() == "if_statement" {
                    if let Some(c) = x.child_by_field_name("condition") {
                        r.extend(guard_roles(c, src, consts));
                    }
                }
                true
            });
        }
    }
    let mut seen = std::collections::HashSet::new();
    r.retain(|x| seen.insert(x.clone()));
    r
}

fn menus(root: Node, f: &SourceFile, consts: &HashMap<String, (u32, Vec<String>)>, rows: &mut Rows) {
    let src = f.text.as_str();
    walk(root, |n| {
        if n.kind() != "object" {
            return true;
        }
        let label = pair_value(n, &["name", "label", "title"], src).and_then(|v| js_string(v, src));
        let href = pair_value(n, &["href", "path", "to"], src).and_then(|v| js_string(v, src));
        let (Some(label), Some(href)) = (label, href) else {
            return true;
        };
        if !href.starts_with('/') {
            return true;
        }
        let mut roles = pair_value(n, &["roles"], src).map(|v| role_values(v, src, consts)).unwrap_or_default();
        if roles.is_empty() {
            roles = guarded_roles(n, src, consts);
        }
        let sval = |k: &str| pair_value(n, &[k], src).and_then(|v| js_string(v, src)).unwrap_or_default();
        let mut tabs = vec![];
        if let Some(arr) = pair_value(n, &["tabs"], src) {
            for t in named_children(arr).into_iter().filter(|t| t.kind() == "object") {
                let tt = pair_value(t, &["title", "label", "name"], src).and_then(|v| js_string(v, src));
                let tk = pair_value(t, &["key", "id"], src).and_then(|v| js_string(v, src));
                if let (Some(tt), Some(tk)) = (tt, tk) {
                    tabs.push(format!("{tt}={tk}"));
                }
            }
        }
        // exported nav array that holds this item
        let mut nav = String::new();
        let mut up = n;
        while let Some(p) = up.parent() {
            if p.kind() == "variable_declarator" {
                nav = p.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
            }
            up = p;
        }
        // enclosing group: an object with a title/name and an items/children array containing us
        let mut group = None;
        let mut group_roles = vec![];
        let mut cur = n;
        while let Some(p) = cur.parent() {
            if p.kind() == "object" && pair_value(p, &["items", "children"], src).is_some() {
                group = pair_value(p, &["title", "name", "label"], src).and_then(|v| js_string(v, src));
                group_roles = pair_value(p, &["roles"], src).map(|v| role_values(v, src, consts)).unwrap_or_default();
                break;
            }
            cur = p;
        }
        rows.menu.push(MenuItem {
            file: f.path.clone(),
            line: line(n),
            nav,
            label,
            path: href,
            group,
            keywords: sval("keywords"),
            tooltip: sval("tooltip"),
            tabs,
            roles,
            group_roles,
        });
        true
    });
}
