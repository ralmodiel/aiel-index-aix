//! Python web frameworks: FastAPI (`@app.get`, `APIRouter(prefix=)`, `include_router`, `Depends` auth hints),
//! Flask (`@app.route(methods=)`, blueprints with `url_prefix`, `add_url_rule`) and Django (`urls.py`
//! `path()/re_path()/include()`, DRF routers, class and function views).

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Node;

use super::*;
use crate::ts_util::*;

ext_impl!(PyWeb, "pyweb", |p| ext_of(p) == "py", extract_file);

fn py_str(n: Node, src: &str) -> Option<String> {
    if n.kind() != "string" {
        return None;
    }
    let t = text(n, src);
    let t = t.trim_start_matches(|c: char| "rRbBuUfF".contains(c));
    for q in ["\"\"\"", "'''", "\"", "'"] {
        if t.starts_with(q) && t.ends_with(q) && t.len() >= 2 * q.len() {
            return Some(t[q.len()..t.len() - q.len()].to_string());
        }
    }
    None
}

/// A prefix argument: a string literal, or a reference to a constant resolved later (`$NAME`).
fn prefix_arg(v: Node, src: &str) -> Option<String> {
    match v.kind() {
        "string" => py_str(v, src),
        "identifier" | "attribute" => Some(format!("${}", text(v, src).rsplit('.').next().unwrap_or(""))),
        _ => None,
    }
}

fn py_strs(n: Node, src: &str) -> Vec<String> {
    match n.kind() {
        "string" => py_str(n, src).into_iter().collect(),
        "list" | "tuple" | "set" | "parenthesized_expression" => {
            named_children(n).into_iter().flat_map(|c| py_strs(c, src)).collect()
        }
        "concatenated_string" => vec![named_children(n).into_iter().filter_map(|c| py_str(c, src)).collect::<String>()],
        _ => vec![],
    }
}

struct Args<'a> {
    pos: Vec<Node<'a>>,
    kw: HashMap<String, Node<'a>>,
}

fn args_of<'a>(call: Node<'a>, src: &str) -> Args<'a> {
    let mut a = Args { pos: vec![], kw: HashMap::new() };
    if let Some(l) = call.child_by_field_name("arguments") {
        for c in named_children(l) {
            if c.kind() == "keyword_argument" {
                if let (Some(k), Some(v)) = (c.child_by_field_name("name"), c.child_by_field_name("value")) {
                    a.kw.insert(text(k, src).to_string(), v);
                }
            } else if c.kind() != "comment" {
                a.pos.push(c);
            }
        }
    }
    a
}

fn authish(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    [
        "auth",
        "login",
        "jwt",
        "token",
        "permission",
        "role",
        "admin",
        "current_user",
        "superuser",
        "session",
        "guard",
        "require",
        "protect",
        "current",
        "verify",
        "oauth",
        "bearer",
        "apikey",
        "api_key",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// `Depends(get_current_user)` / `Security(...)` names that look like auth.
fn depends_hints(t: &str) -> Vec<String> {
    let re = Regex::new(r"(?:Depends|Security)\(\s*([\w.]+)").unwrap();
    let mut out = vec![];
    for c in re.captures_iter(t) {
        let n = c[1].rsplit('.').next().unwrap_or("").to_string();
        if authish(&n) && !out.contains(&format!("auth:{n}")) {
            out.push(format!("auth:{n}"));
        }
    }
    out
}

#[derive(Default, Clone)]
struct Scope {
    prefix: String,
    kind: &'static str, // fastapi | flask | bp | router(drf)
    roles: Vec<String>,
    /// a mounted sub-router (APIRouter / Blueprint), not the app itself
    sub: bool,
    /// dependencies we could not classify were declared on it
    unk: bool,
}

struct Cx<'a> {
    f: &'a SourceFile,
    scopes: HashMap<String, Scope>,
    /// local name -> (module (dots kept), imported name; "" for `import x`)
    imports: HashMap<String, (String, String)>,
}

fn extract_file(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    consts(f, rows);
    let web = [
        "fastapi",
        "FastAPI",
        "APIRouter",
        "flask",
        "Flask",
        "Blueprint",
        "urlpatterns",
        "rest_framework",
        "django",
        "quart",
        "Quart",
    ]
    .iter()
    .any(|m| t.contains(m));
    // routers imported from another module (`from app.api import bp`) leave no framework name in this file
    static DECO: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?m)^\s*@\w+\.(?:route|get|post|put|delete|patch)\(\s*[rf]?['"]/"#).unwrap());
    if !web && !DECO.is_match(t) {
        return;
    }
    let Some(tree) = parse(&python(), t) else { return };
    let root = tree.root_node();
    let mut cx = Cx { f, scopes: HashMap::new(), imports: HashMap::new() };
    cx.decls(root);
    let aliases = dep_aliases(root, f, rows);
    cx.routes(root, rows, &aliases);
    cx.mounts(root, rows);
    if t.contains("urlpatterns") || t.contains("register(") {
        cx.django(root, rows);
    }
    views(root, f, rows);
}

/// `NAME = "/api/v1"` / `NAME: str = "/api/v1"` (module or class level): path-like string constants, for `prefix=settings.NAME`.
fn consts(f: &SourceFile, rows: &mut Rows) {
    if !f.text.contains("= \"/") && !f.text.contains("= '/") {
        return;
    }
    let re = Regex::new(r#"(?m)^[ \t]*([A-Z][A-Z0-9_]*)\s*(?::\s*[\w\[\], .]+)?=\s*["'](/[^"'\n]*)["']"#).unwrap();
    for c in re.captures_iter(&f.text) {
        let l = f.text[..c.get(0).unwrap().start()].matches('\n').count() as u32 + 1;
        rows.consts.push(Const {
            file: f.path.clone(),
            line: l,
            name: c[1].to_string(),
            values: vec![c[2].to_string()],
        });
    }
}

fn dotted(n: Node, src: &str) -> String {
    text(n, src).split_whitespace().collect()
}

impl<'a> Cx<'a> {
    fn src(&self) -> &'a str {
        &self.f.text
    }

    fn decls(&mut self, root: Node) {
        let src = self.src();
        walk(root, |n| {
            match n.kind() {
                "import_from_statement" => {
                    let module = n.child_by_field_name("module_name").map(|m| dotted(m, src)).unwrap_or_default();
                    for c in named_children(n) {
                        if Some(c) == n.child_by_field_name("module_name") {
                            continue;
                        }
                        match c.kind() {
                            "dotted_name" => {
                                let nm = dotted(c, src);
                                self.imports.insert(nm.clone(), (module.clone(), nm));
                            }
                            "aliased_import" => {
                                let nm = c.child_by_field_name("name").map(|x| dotted(x, src)).unwrap_or_default();
                                let al = c
                                    .child_by_field_name("alias")
                                    .map(|x| dotted(x, src))
                                    .unwrap_or_else(|| nm.clone());
                                self.imports.insert(al, (module.clone(), nm));
                            }
                            _ => {}
                        }
                    }
                    return false;
                }
                "import_statement" => {
                    for c in named_children(n) {
                        match c.kind() {
                            "dotted_name" => {
                                let nm = dotted(c, src);
                                self.imports.insert(
                                    nm.rsplit('.').next().unwrap_or("").to_string(),
                                    (nm.clone(), String::new()),
                                );
                            }
                            "aliased_import" => {
                                let nm = c.child_by_field_name("name").map(|x| dotted(x, src)).unwrap_or_default();
                                let al = c.child_by_field_name("alias").map(|x| dotted(x, src)).unwrap_or_default();
                                self.imports.insert(al, (nm, String::new()));
                            }
                            _ => {}
                        }
                    }
                    return false;
                }
                "assignment" => {
                    if let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) {
                        if l.kind() == "identifier" && r.kind() == "call" {
                            let fname = r.child_by_field_name("function").map(|x| text(x, src)).unwrap_or("");
                            let last = fname.rsplit('.').next().unwrap_or("");
                            let kind = match last {
                                "FastAPI" => "fastapi",
                                "APIRouter" => "fastapi",
                                "Flask" | "Quart" => "flask",
                                "Blueprint" => "bp",
                                "DefaultRouter" | "SimpleRouter" | "ExtendedSimpleRouter" => "drf",
                                _ => "",
                            };
                            if !kind.is_empty() {
                                let a = args_of(r, src);
                                let prefix =
                                    a.kw.get("prefix")
                                        .or(a.kw.get("url_prefix"))
                                        .and_then(|v| prefix_arg(*v, src))
                                        .unwrap_or_default();
                                let roles = depends_hints(text(r, src));
                                let unk = roles.is_empty() && text(r, src).contains("dependencies");
                                let sub = !matches!(last, "FastAPI" | "Flask" | "Quart" | "DefaultRouter" | "SimpleRouter" | "ExtendedSimpleRouter");
                                self.scopes.insert(text(l, src).to_string(), Scope { prefix, kind, roles, sub, unk });
                            }
                        }
                    }
                }
                _ => {}
            }
            true
        });
    }

    /// A Flask / FastAPI route with no auth decorator or dependency is served to everyone, unless something in this
    /// file adds auth around it (`before_request`, `dependencies=`, middleware).
    fn public_default(&self, sc: &Scope) -> bool {
        if sc.unk || !matches!(sc.kind, "fastapi" | "flask" | "bp") {
            return false;
        }
        let t = &self.f.text;
        ![
            "before_request",
            "before_app_request",
            "before_app_first_request",
            "add_middleware",
            "AuthenticationMiddleware",
            "dependencies=",
            "login_required = ",
            "WWW-Authenticate",
        ]
        .iter()
        .any(|k| t.contains(k))
    }

    fn decorator_roles(&self, deco_nodes: &[Node]) -> Vec<String> {
        let src = self.src();
        let mut roles = vec![];
        for d in deco_nodes {
            let e = d.named_child(0);
            let Some(e) = e else { continue };
            let (name, args): (String, Vec<String>) = match e.kind() {
                "call" => {
                    let fname = e.child_by_field_name("function").map(|x| text(x, src)).unwrap_or("").to_string();
                    let a = args_of(e, src);
                    (fname, a.pos.iter().flat_map(|p| py_strs(*p, src)).collect())
                }
                _ => (text(e, src).to_string(), vec![]),
            };
            let last = name.rsplit('.').next().unwrap_or("").to_string();
            if matches!(
                last.as_str(),
                "route"
                    | "get"
                    | "post"
                    | "put"
                    | "delete"
                    | "patch"
                    | "head"
                    | "options"
                    | "api_route"
                    | "websocket"
                    | "api_view"
                    | "require_http_methods"
                    | "action"
                    | "cache"
                    | "cached"
                    | "doc"
                    | "response"
                    | "expect"
                    | "marshal_with"
                    | "errorhandler"
                    | "before_request"
            ) {
                continue;
            }
            if authish(&last) {
                if args.is_empty() {
                    roles.push(format!("auth:{last}"));
                } else {
                    roles.extend(args);
                }
            }
        }
        roles
    }

    fn routes(&mut self, root: Node, rows: &mut Rows, aliases: &HashMap<String, Vec<String>>) {
        let src = self.src();
        let mut defs: Vec<Node> = vec![];
        walk(root, |n| {
            if n.kind() == "decorated_definition" {
                defs.push(n);
            }
            true
        });
        for d in defs {
            let Some(def) = d.child_by_field_name("definition") else { continue };
            if def.kind() != "function_definition" {
                continue;
            }
            let hname = def.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
            let decos: Vec<Node> = named_children(d).into_iter().filter(|c| c.kind() == "decorator").collect();
            let params = def.child_by_field_name("parameters").map(|p| text(p, src)).unwrap_or("");
            for deco in &decos {
                let Some(call) = deco.named_child(0) else { continue };
                if call.kind() != "call" {
                    continue;
                }
                let Some(func) = call.child_by_field_name("function") else { continue };
                if func.kind() != "attribute" {
                    continue;
                }
                let (Some(obj), Some(attr)) =
                    (func.child_by_field_name("object"), func.child_by_field_name("attribute"))
                else {
                    continue;
                };
                let attr = text(attr, src);
                let scope_name = text(obj, src).to_string();
                let (sc, scope_name) = match self.scopes.get(&scope_name).cloned() {
                    Some(sc) => (sc, scope_name),
                    // `from app.main import bp`: the router lives in another module
                    None => match self.imports.get(&scope_name) {
                        Some((m, orig)) if !m.is_empty() && !orig.is_empty() && obj.kind() == "identifier" => {
                            (Scope { kind: "flask", sub: true, ..Default::default() }, format!("@{m}|{orig}"))
                        }
                        _ => continue,
                    },
                };
                let a = args_of(call, src);
                let path = a
                    .pos
                    .first()
                    .and_then(|p| py_str(*p, src))
                    .or_else(|| a.kw.get("rule").or(a.kw.get("path")).and_then(|v| py_str(*v, src)));
                let Some(path) = path else { continue };
                let methods: Vec<String> = if HTTP_LOWER.contains(&attr) {
                    vec![attr.to_ascii_uppercase()]
                } else if attr == "route" || attr == "api_route" {
                    let m = a.kw.get("methods").map(|v| py_strs(*v, src)).unwrap_or_default();
                    if m.is_empty() {
                        vec!["GET".into()]
                    } else {
                        m.into_iter().map(|x| x.to_ascii_uppercase()).collect()
                    }
                } else {
                    continue;
                };
                let mut roles = sc.roles.clone();
                roles.extend(depends_hints(text(call, src)));
                roles.extend(depends_hints(params));
                roles.extend(self.decorator_roles(&decos));
                // `user: CurrentUser` where `CurrentUser = Annotated[User, Depends(get_current_user)]`: this file's
                // alias is read here; an imported one is left as `dep:<module>|<name>` for the cross-file pass
                let mut deps: Vec<String> = vec![];
                for t in param_type_names(def, src) {
                    if let Some(fs) = aliases.get(&t) {
                        roles.extend(fs.iter().map(|f| format!("auth:{f}")));
                    } else if let Some((m, orig)) = self.imports.get(&t) {
                        if !m.is_empty() {
                            deps.push(format!("dep:{m}|{}", if orig.is_empty() { &t } else { orig }));
                        }
                    }
                }
                roles.dedup();
                if roles.is_empty() && self.public_default(&sc) {
                    roles.push("public".into());
                }
                for d in deps {
                    if !roles.contains(&d) {
                        roles.insert(0, d);
                    }
                }
                let full = join(&sc.prefix, &param_syntax(&path));
                for me in methods {
                    push_scoped_ex(
                        rows,
                        &scope_name,
                        Ep {
                            file: &self.f.path,
                            line: line(*deco),
                            method: &me,
                            path: &full,
                            class: "",
                            handler: &hname,
                            roles: roles.clone(),
                        },
                        sc.sub,
                    );
                }
            }
        }
        // app.add_url_rule('/p', view_func=fn, methods=[...])
        let mut calls: Vec<Node> = vec![];
        walk(root, |n| {
            if n.kind() == "call" {
                calls.push(n);
            }
            true
        });
        for c in calls {
            let Some(func) = c.child_by_field_name("function") else { continue };
            if func.kind() != "attribute" {
                continue;
            }
            let (Some(obj), Some(attr)) = (func.child_by_field_name("object"), func.child_by_field_name("attribute"))
            else {
                continue;
            };
            if text(attr, src) != "add_url_rule" {
                continue;
            }
            let scope_name = text(obj, src).to_string();
            let Some(sc) = self.scopes.get(&scope_name).cloned() else { continue };
            let a = args_of(c, src);
            let Some(path) = a.pos.first().and_then(|p| py_str(*p, src)) else { continue };
            let view = a.kw.get("view_func").or(a.pos.get(2)).map(|v| text(*v, src).to_string()).unwrap_or_default();
            let methods =
                a.kw.get("methods")
                    .map(|v| py_strs(*v, src))
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| vec!["GET".into()]);
            for me in methods {
                let mut roles = sc.roles.clone();
                if roles.is_empty() && self.public_default(&sc) {
                    roles.push("public".into());
                }
                push_scoped_ex(
                    rows,
                    &scope_name,
                    Ep {
                        file: &self.f.path,
                        line: line(c),
                        method: &me,
                        path: &join(&sc.prefix, &param_syntax(&path)),
                        class: "",
                        handler: view.rsplit('.').next().unwrap_or(""),
                        roles,
                    },
                    sc.sub,
                );
            }
        }
    }

    /// (module, attribute) of a router expression: `items.router`, `router`, `api_router`.
    fn child_ref(&self, e: Node) -> Option<(String, String)> {
        let src = self.src();
        match e.kind() {
            "identifier" => {
                let nm = text(e, src);
                match self.imports.get(nm) {
                    Some((m, orig)) if !m.is_empty() => Some((m.clone(), orig.clone())),
                    _ => Some((String::new(), nm.to_string())),
                }
            }
            "attribute" => {
                let o = text(e.child_by_field_name("object")?, src);
                let a = text(e.child_by_field_name("attribute")?, src);
                match self.imports.get(o) {
                    // `from app.api import items` -> module app.api.items
                    Some((m, orig)) if !orig.is_empty() => {
                        Some((format!("{}{}{}", m, if m.ends_with('.') { "" } else { "." }, orig), a.to_string()))
                    }
                    Some((m, _)) => Some((m.clone(), a.to_string())),
                    None => None,
                }
            }
            _ => None,
        }
    }

    fn mounts(&mut self, root: Node, rows: &mut Rows) {
        let src = self.src();
        let mut calls: Vec<Node> = vec![];
        walk(root, |n| {
            if n.kind() == "call" {
                calls.push(n);
            }
            true
        });
        for c in calls {
            let Some(func) = c.child_by_field_name("function") else { continue };
            if func.kind() != "attribute" {
                continue;
            }
            let (Some(obj), Some(attr)) = (func.child_by_field_name("object"), func.child_by_field_name("attribute"))
            else {
                continue;
            };
            let attr = text(attr, src);
            if !matches!(attr, "include_router" | "register_blueprint") {
                continue;
            }
            let parent = text(obj, src);
            let a = args_of(c, src);
            let prefix =
                a.kw.get("prefix").or(a.kw.get("url_prefix")).and_then(|v| prefix_arg(*v, src)).unwrap_or_default();
            let Some(first) = a.pos.first() else { continue };
            // the child's own prefix is already part of its endpoints' local paths
            if let Some((m, name)) = self.child_ref(*first) {
                let mut roles = depends_hints(&a.kw.get("dependencies").map(|v| text(*v, src)).unwrap_or("").to_string());
                let dep = a.kw.contains_key("dependencies");
                let mut mw = dep && roles.is_empty();
                if let Some(ps) = self.scopes.get(parent) {
                    roles.extend(ps.roles.iter().cloned());
                    mw |= ps.unk;
                }
                push_mount_ex(rows, &self.f.path, line(c), "py", parent, &prefix, &name, &m, &roles, mw);
            }
        }
    }

    fn django(&mut self, root: Node, rows: &mut Rows) {
        let src = self.src();
        let f = self.f;
        // lists assigned to urlpatterns-like variables, `urlpatterns += [...]`, and router.register calls
        let mut lists: Vec<(String, Node)> = vec![];
        walk(root, |n| {
            if n.kind() == "assignment" || n.kind() == "augmented_assignment" {
                if let (Some(l), Some(r)) = (n.child_by_field_name("left"), n.child_by_field_name("right")) {
                    if l.kind() == "identifier" && matches!(r.kind(), "list" | "tuple") {
                        let nm = text(l, src).to_string();
                        if nm == "urlpatterns"
                            || nm.ends_with("urlpatterns")
                            || nm.ends_with("_urls")
                            || nm.ends_with("urls")
                        {
                            lists.push((nm, r));
                        }
                    }
                }
            }
            true
        });
        for (scope, list) in lists {
            for item in named_children(list) {
                if item.kind() != "call" {
                    continue;
                }
                let fname = item.child_by_field_name("function").map(|x| text(x, src)).unwrap_or("");
                if !matches!(fname, "path" | "re_path" | "url") {
                    continue;
                }
                let a = args_of(item, src);
                let (Some(p0), Some(view)) = (a.pos.first(), a.pos.get(1)) else { continue };
                let Some(pat) = py_str(*p0, src) else { continue };
                let local = if fname == "path" { param_syntax(&pat) } else { regex_path(&pat) };
                let line_no = line(item);
                if view.kind() == "call" {
                    let vf = view.child_by_field_name("function").map(|x| text(x, src)).unwrap_or("");
                    if vf == "include" {
                        let va = args_of(*view, src);
                        let Some(arg0) = va.pos.first() else { continue };
                        let target = match arg0.kind() {
                            "string" => py_str(*arg0, src).map(|m| (m, "urlpatterns".to_string())),
                            "tuple" => named_children(*arg0)
                                .first()
                                .and_then(|s| py_str(*s, src))
                                .map(|m| (m, "urlpatterns".to_string())),
                            "attribute" => {
                                // include(router.urls) / include(module.urls)
                                let o = arg0.child_by_field_name("object").map(|x| text(x, src)).unwrap_or("");
                                match self.imports.get(o) {
                                    Some((m, orig)) if !m.is_empty() && !orig.is_empty() => {
                                        // `from . import api` (module) vs `from .api import router` (object)
                                        Some((m.clone(), o.to_string()))
                                    }
                                    _ => Some((String::new(), o.to_string())),
                                }
                            }
                            "identifier" => {
                                let nm = text(*arg0, src);
                                match self.imports.get(nm) {
                                    Some((m, orig)) => Some((m.clone(), orig.clone())),
                                    None => Some((String::new(), nm.to_string())),
                                }
                            }
                            _ => None,
                        };
                        if let Some((m, child)) = target {
                            push_mount(rows, &f.path, line_no, "dj", &scope, &local, &child, &m);
                        }
                    } else if vf.ends_with("as_view") {
                        let cls = vf.trim_end_matches(".as_view").rsplit('.').next().unwrap_or("");
                        push_scoped(
                            rows,
                            &scope,
                            Ep {
                                file: &f.path,
                                line: line_no,
                                method: "ANY",
                                path: &local,
                                class: "",
                                handler: cls,
                                roles: vec![],
                            },
                        );
                    }
                } else {
                    let vt = text(*view, src);
                    if vt.ends_with(".urls") || vt.ends_with("urls") && vt.contains('.') {
                        continue;
                    }
                    let (class, handler) = vt
                        .rsplit_once('.')
                        .map(|(a, b)| (a.rsplit('.').next().unwrap_or(a).to_string(), b.to_string()))
                        .unwrap_or((String::new(), vt.to_string()));
                    push_scoped(
                        rows,
                        &scope,
                        Ep {
                            file: &f.path,
                            line: line_no,
                            method: "ANY",
                            path: &local,
                            class: &class,
                            handler: &handler,
                            roles: vec![],
                        },
                    );
                }
            }
        }
        // DRF routers: router.register(r'users', UserViewSet)
        let mut calls: Vec<Node> = vec![];
        walk(root, |n| {
            if n.kind() == "call" {
                calls.push(n);
            }
            true
        });
        for c in calls {
            let Some(func) = c.child_by_field_name("function") else { continue };
            if func.kind() != "attribute" {
                continue;
            }
            let (Some(obj), Some(attr)) = (func.child_by_field_name("object"), func.child_by_field_name("attribute"))
            else {
                continue;
            };
            if text(attr, src) != "register" || self.scopes.get(text(obj, src)).map(|s| s.kind) != Some("drf") {
                continue;
            }
            let a = args_of(c, src);
            let (Some(p0), Some(v)) = (a.pos.first(), a.pos.get(1)) else { continue };
            let Some(pre) = py_str(*p0, src) else { continue };
            let cls = text(*v, src).rsplit('.').next().unwrap_or("").to_string();
            let scope = text(obj, src).to_string();
            let base = join("", pre.trim_matches('^').trim_end_matches('$'));
            for p in [base.clone(), format!("{base}/{{pk}}")] {
                push_scoped(
                    rows,
                    &scope,
                    Ep {
                        file: &f.path,
                        line: line(c),
                        method: "ANY",
                        path: &p,
                        class: "",
                        handler: &cls,
                        roles: vec![],
                    },
                );
            }
        }
    }
}

/// Django `re_path` regex to a plain path: `^users/(?P<pk>\d+)/$` -> `users/{pk}`.
fn regex_path(p: &str) -> String {
    let p = p.trim_start_matches('^').trim_end_matches('$');
    let named = Regex::new(r"\(\?P<(\w+)>[^)]*\)").unwrap().replace_all(p, "{$1}").to_string();
    let rest = Regex::new(r"\([^)]*\)").unwrap().replace_all(&named, "{}").to_string();
    rest.replace("\\.", ".").replace('?', "")
}

/// Class-based and function views: the HTTP methods each serves (for Django `as_view()` / router targets).
static VIEW_METHODS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['"](GET|POST|PUT|PATCH|DELETE)['"]"#).unwrap());

fn views(root: Node, f: &SourceFile, rows: &mut Rows) {
    let src = &f.text;
    if !(src.contains("View") || src.contains("api_view") || src.contains("require_")) {
        return;
    }
    walk(root, |n| {
        let (def, decos) = if n.kind() == "decorated_definition" {
            (
                n.child_by_field_name("definition"),
                named_children(n).into_iter().filter(|c| c.kind() == "decorator").collect::<Vec<_>>(),
            )
        } else {
            (None, vec![])
        };
        if let Some(def) = def {
            if def.kind() == "function_definition" {
                let name = def.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
                let mut methods: Vec<String> = vec![];
                for d in &decos {
                    let t = text(*d, src);
                    if t.contains("api_view") || t.contains("require_http_methods") {
                        for m in VIEW_METHODS.captures_iter(t) {
                            methods.push(m[1].to_string());
                        }
                    }
                    for (k, v) in [("require_GET", "GET"), ("require_POST", "POST"), ("require_safe", "GET")] {
                        if t.contains(k) {
                            methods.push(v.into());
                        }
                    }
                }
                if !methods.is_empty() {
                    methods.dedup();
                    push_view(rows, &f.path, line(n), &name, &methods);
                }
            }
        }
        if n.kind() == "class_definition" {
            let name = n.child_by_field_name("name").map(|x| text(x, src).to_string()).unwrap_or_default();
            let bases = n.child_by_field_name("superclasses").map(|b| text(b, src)).unwrap_or("");
            if !(bases.contains("View") || bases.contains("Mixin") || bases.contains("Generic")) {
                return true;
            }
            let mut methods: Vec<String> = vec![];
            let mut add = |m: &str| {
                if !methods.iter().any(|x| x == m) {
                    methods.push(m.to_string());
                }
            };
            if let Some(body) = n.child_by_field_name("body") {
                for c in named_children(body) {
                    let d = if c.kind() == "decorated_definition" {
                        c.child_by_field_name("definition").unwrap_or(c)
                    } else {
                        c
                    };
                    if d.kind() == "function_definition" {
                        if let Some(nm) = d.child_by_field_name("name").map(|x| text(x, src)) {
                            match nm {
                                "get" | "list" | "retrieve" => add("GET"),
                                "post" | "create" => add("POST"),
                                "put" | "update" => add("PUT"),
                                "patch" | "partial_update" => add("PATCH"),
                                "delete" | "destroy" => add("DELETE"),
                                _ => {}
                            }
                        }
                    }
                }
            }
            for (k, ms) in [
                ("ModelViewSet", &["GET", "POST", "PUT", "PATCH", "DELETE"][..]),
                ("ReadOnlyModelViewSet", &["GET"][..]),
                ("ListCreateAPIView", &["GET", "POST"][..]),
                ("RetrieveUpdateDestroyAPIView", &["GET", "PUT", "PATCH", "DELETE"][..]),
                ("RetrieveUpdateAPIView", &["GET", "PUT", "PATCH"][..]),
                ("RetrieveDestroyAPIView", &["GET", "DELETE"][..]),
                ("ListAPIView", &["GET"][..]),
                ("RetrieveAPIView", &["GET"][..]),
                ("CreateAPIView", &["POST"][..]),
                ("UpdateAPIView", &["PUT", "PATCH"][..]),
                ("DestroyAPIView", &["DELETE"][..]),
                ("TemplateView", &["GET"][..]),
                ("ListView", &["GET"][..]),
                ("DetailView", &["GET"][..]),
                ("CreateView", &["GET", "POST"][..]),
                ("UpdateView", &["GET", "POST"][..]),
                ("DeleteView", &["GET", "POST"][..]),
                ("FormView", &["GET", "POST"][..]),
            ] {
                if bases.split([',', '(', ')']).any(|b| b.trim().rsplit('.').next() == Some(k)) {
                    for m in ms {
                        add(m);
                    }
                }
            }
            if !methods.is_empty() {
                push_view(rows, &f.path, line(n), &name, &methods);
            }
        }
        true
    });
}

/// Module-level dependency aliases: `CurrentUser = Annotated[User, Depends(get_current_user)]` (or `= Depends(f)`):
/// name -> the auth-like dependency functions it injects. Each alias is also a `py:dep` note (text: those functions,
/// comma-separated; empty for a non-auth dependency) so routes in other modules that import it can resolve it.
fn dep_aliases(root: Node, f: &SourceFile, rows: &mut Rows) -> HashMap<String, Vec<String>> {
    let src = f.text.as_str();
    let mut out = HashMap::new();
    for st in named_children(root) {
        if st.kind() != "expression_statement" {
            continue;
        }
        let Some(a) = st.named_child(0).filter(|a| a.kind() == "assignment") else { continue };
        let (Some(l), Some(r)) = (a.child_by_field_name("left"), a.child_by_field_name("right")) else { continue };
        if l.kind() != "identifier" {
            continue;
        }
        let rt = text(r, src);
        if !(rt.contains("Depends(") || rt.contains("Security(")) {
            continue;
        }
        let name = text(l, src).to_string();
        let fs: Vec<String> = depends_hints(rt).into_iter().filter_map(|h| h.strip_prefix("auth:").map(String::from)).collect();
        rows.notes.push(Note { file: f.path.clone(), line: line(st), kind: "py:dep".into(), reference: name.clone(), text: fs.join(",") });
        out.insert(name, fs);
    }
    out
}

/// The plain type names a function's parameters are annotated with (`user: CurrentUser`, `s: SessionDep = None`).
fn param_type_names(def: Node, src: &str) -> Vec<String> {
    let Some(ps) = def.child_by_field_name("parameters") else { return vec![] };
    named_children(ps)
        .into_iter()
        .filter(|p| matches!(p.kind(), "typed_parameter" | "typed_default_parameter"))
        .filter_map(|p| p.child_by_field_name("type"))
        .map(|t| text(t, src).trim().to_string())
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .collect()
}
