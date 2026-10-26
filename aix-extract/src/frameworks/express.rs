//! Express-style servers (Express, Koa router, Fastify, Hono): `app.get('/p', mw, handler)`,
//! `router.route('/p').get(h).post(h)`, `app.use('/prefix', router)` composition across files, and auth-looking
//! middleware names as role hints.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use tree_sitter::Node;

use super::*;
use crate::ts_util::*;
use crate::typescript::lang_for;

ext_impl!(
    Express,
    "express",
    |p| matches!(ext_of(p), "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "mts" | "cts"),
    extract_file
);

/// The file imports a server framework (a browser file calling `api.get('/x')` must never qualify).
static SERVER_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:from\s+|require\(\s*|import\(\s*)['"](?:express|fastify|hono|@hono/[\w-]+|koa|@koa/router|koa-router|@koa/[\w-]+|restify|polka|h3|@fastify/[\w-]+)['"]"#).unwrap()
});
const VERBS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options", "all"];
const SERVER_CTORS: &[&str] = &["express", "Router", "Hono", "fastify", "Fastify", "KoaRouter", "restify"];

fn extract_file(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    if !SERVER_IMPORT.is_match(t)
        || !(t.contains(".get(")
            || t.contains(".post(")
            || t.contains(".use(")
            || t.contains(".route(")
            || t.contains(".put(")
            || t.contains(".delete(")
            || t.contains(".patch(")
            || t.contains(".all("))
    {
        return;
    }
    let Some(tree) = parse(&lang_for(&f.path), t) else { return };
    let root = tree.root_node();
    let mut cx = Cx { f, imports: HashMap::new(), servers: HashMap::new(), mw: HashMap::new(), unk: Default::default(), routers: Default::default(), consts: vec![] };
    cx.scan_decls(root);
    cx.visit(root, rows);
    for (name, l, v) in cx.consts {
        rows.consts.push(Const { file: f.path.clone(), line: l, name, values: vec![v] });
    }
}

struct Cx<'a> {
    f: &'a SourceFile,
    /// local name -> (module specifier, imported name | "default" | "*")
    imports: HashMap<String, (String, String)>,
    /// server/router variables declared in this file
    servers: HashMap<String, ()>,
    /// scope -> auth-looking `use(...)` middleware seen so far
    mw: HashMap<String, Vec<String>>,
    /// scopes that had a middleware we could not classify (so "no auth" cannot be claimed)
    unk: std::collections::HashSet<String>,
    /// scopes that are `Router()` instances (mounted somewhere), not the app
    routers: std::collections::HashSet<String>,
    consts: Vec<(String, u32, String)>,
}

fn is_server_ctor(v: Node, src: &str) -> bool {
    let call = match v.kind() {
        "new_expression" => v.child_by_field_name("constructor"),
        "call_expression" => {
            let f = v.child_by_field_name("function");
            // `Router().use(a).use(b)`: look through the chain to its root call
            if let Some(fx) = f.filter(|x| x.kind() == "member_expression") {
                if let Some(o) = fx
                    .child_by_field_name("object")
                    .filter(|o| matches!(o.kind(), "call_expression" | "new_expression"))
                {
                    return is_server_ctor(o, src);
                }
            }
            f
        }
        "await_expression" | "parenthesized_expression" => {
            return v.named_child(0).is_some_and(|c| is_server_ctor(c, src))
        }
        _ => None,
    };
    let Some(c) = call else { return false };
    let t = text(c, src);
    let last = t.rsplit('.').next().unwrap_or(t);
    SERVER_CTORS.contains(&last) || t == "express.Router" || t.ends_with(".Router")
}

fn require_spec(v: Node, src: &str) -> Option<String> {
    if v.kind() != "call_expression" {
        return None;
    }
    let func = v.child_by_field_name("function")?;
    if text(func, src) != "require" {
        return None;
    }
    let a = v.child_by_field_name("arguments")?.named_child(0)?;
    js_string(a, src)
}

impl<'a> Cx<'a> {
    fn src(&self) -> &'a str {
        &self.f.text
    }

    fn scan_decls(&mut self, root: Node) {
        let src = self.src();
        walk(root, |n| {
            match n.kind() {
                "import_statement" => {
                    let Some(spec) = n.child_by_field_name("source").and_then(|s| js_string(s, src)) else {
                        return false;
                    };
                    walk(n, |c| {
                        match c.kind() {
                            "import_clause" => {
                                for x in named_children(c) {
                                    match x.kind() {
                                        "identifier" => {
                                            self.imports
                                                .insert(text(x, src).to_string(), (spec.clone(), "default".into()));
                                        }
                                        "namespace_import" => {
                                            if let Some(id) =
                                                named_children(x).into_iter().find(|i| i.kind() == "identifier")
                                            {
                                                self.imports
                                                    .insert(text(id, src).to_string(), (spec.clone(), "*".into()));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            "import_specifier" => {
                                let name = c.child_by_field_name("name").map(|x| text(x, src)).unwrap_or("");
                                let alias = c.child_by_field_name("alias").map(|x| text(x, src)).unwrap_or(name);
                                self.imports.insert(alias.to_string(), (spec.clone(), name.to_string()));
                            }
                            _ => {}
                        }
                        true
                    });
                    return false;
                }
                "variable_declarator" => {
                    let (Some(name), Some(v)) = (n.child_by_field_name("name"), n.child_by_field_name("value")) else {
                        return true;
                    };
                    if let Some(spec) = require_spec(v, src).or_else(|| {
                        // `require('./x').router`
                        (v.kind() == "member_expression")
                            .then(|| v.child_by_field_name("object").and_then(|o| require_spec(o, src)))
                            .flatten()
                    }) {
                        match name.kind() {
                            "identifier" => {
                                let prop = if v.kind() == "member_expression" {
                                    v.child_by_field_name("property")
                                        .map(|p| text(p, src).to_string())
                                        .unwrap_or_default()
                                } else {
                                    "default".into()
                                };
                                self.imports.insert(text(name, src).to_string(), (spec, prop));
                            }
                            "object_pattern" => {
                                for c in named_children(name) {
                                    if c.kind() == "shorthand_property_identifier_pattern" {
                                        let nm = text(c, src).to_string();
                                        self.imports.insert(nm.clone(), (spec.clone(), nm));
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else if name.kind() == "identifier" && js_string(v, src).is_some_and(|s| s.starts_with('/')) {
                        self.consts.push((text(name, src).to_string(), line(n), js_string(v, src).unwrap_or_default()));
                    } else if name.kind() == "identifier" && is_server_ctor(v, src) {
                        self.servers.insert(text(name, src).to_string(), ());
                        if text(v, src).contains("Router(") {
                            self.routers.insert(text(name, src).to_string());
                        }
                    }
                }
                _ => {}
            }
            true
        });
    }

    fn is_server(&self, name: &str) -> bool {
        self.servers.contains_key(name) || matches!(name, "app" | "router" | "server" | "routes" | "fastify")
    }

    fn visit(&mut self, root: Node, rows: &mut Rows) {
        let src = self.src();
        let mut calls: Vec<Node> = vec![];
        walk(root, |n| {
            if n.kind() == "call_expression" {
                calls.push(n);
            }
            true
        });
        for n in calls {
            let Some(func) = n.child_by_field_name("function") else { continue };
            if func.kind() != "member_expression" {
                continue;
            }
            let (Some(obj), Some(prop)) = (func.child_by_field_name("object"), func.child_by_field_name("property"))
            else {
                continue;
            };
            let prop = text(prop, src);
            let args = n.child_by_field_name("arguments").map(named_children).unwrap_or_default();
            if obj.kind() == "identifier" {
                let scope = text(obj, src);
                if !self.is_server(scope) {
                    continue;
                }
                if prop == "use" {
                    self.use_call(n, scope, &args, rows);
                } else if VERBS.contains(&prop) && args.len() >= 2 {
                    if let Some(p) = args.first().and_then(|a| route_path(*a, src)) {
                        self.route(n, scope, prop, &p, &args[1..], true, rows);
                    }
                }
            } else if prop == "use" && obj.kind() == "call_expression" && is_server_ctor(obj, src) {
                // fluent chain: `const api = Router().use(a).use('/x', b)` / `export default Router().use('/api', api)`
                if let Some(scope) = chain_scope(n, src) {
                    self.servers.insert(scope.clone(), ());
                    self.routers.insert(scope.clone());
                    self.use_call(n, &scope, &args, rows);
                }
            } else if VERBS.contains(&prop) && obj.kind() == "call_expression" {
                // router.route('/p').get(h).post(h)
                if let Some((scope, p)) = chain_root(obj, src) {
                    if self.is_server(&scope) {
                        self.route(n, &scope, prop, &p, &args, false, rows);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn route(
        &mut self,
        n: Node,
        scope: &str,
        verb: &str,
        path: &str,
        handlers: &[Node],
        direct: bool,
        rows: &mut Rows,
    ) {
        let src = self.src();
        let is_fn =
            |h: &Node| matches!(h.kind(), "arrow_function" | "function_expression" | "function" | "generator_function");
        let (class, handler) = match handlers.iter().rev().find(|h| is_fn(h)) {
            // `scope.verb /path handler`: the member the code graph names for an inline callback
            Some(_) if direct => (
                String::new(),
                if path.is_empty() {
                    format!("{scope}.{verb} handler")
                } else {
                    format!("{scope}.{verb} {path} handler")
                },
            ),
            _ => handler_name(handlers.last().copied(), src),
        };
        let mut roles = vec![];
        if handlers.len() > 1 {
            for h in &handlers[..handlers.len() - 1] {
                roles.extend(mw_roles(*h, src));
            }
        }
        if let Some(m) = self.mw.get(scope) {
            for r in m {
                if !roles.contains(r) {
                    roles.push(r.clone());
                }
            }
        }
        let method = if verb == "all" { "ANY" } else { verb };
        if let Some(h) = handlers.last().filter(|h| {
            matches!(h.kind(), "arrow_function" | "function_expression" | "function" | "generator_function")
        }) {
            // an inline handler is a member of its own, so the call graph (and `trace`) can start from it
            let name = format!("{} {}", method.to_ascii_uppercase(), param_syntax(path));
            rows.members.push(crate::codegraph::Member {
                file: self.f.path.clone(),
                line: line(n),
                end_line: end_line(h.to_owned()).max(line(n)),
                name: name.clone(),
                container: None,
                qname: name,
                kind: "function".into(),
                sig: String::new(),
                vis: "local".into(),
                annos: vec!["route-handler".into()],
                is_static: false,
                supers: vec![],
                ret: String::new(),
            });
        }
        // no auth anywhere we can see on a plain route: Express serves it to everyone
        if roles.is_empty() && handlers.len() == 1 && !self.unk.contains(scope) {
            roles.push("public".into());
        }
        push_scoped_ex(
            rows,
            scope,
            Ep {
                file: &self.f.path,
                line: line(n),
                method,
                path: &param_syntax(path),
                class: &class,
                handler: &handler,
                roles,
            },
            self.routers.contains(scope),
        );
    }

    fn use_call(&mut self, n: Node, scope: &str, args: &[Node], rows: &mut Rows) {
        let src = self.src();
        let (prefix, rest): (String, &[Node]) = match args.first() {
            Some(a) if js_string(*a, src).is_some() => (js_string(*a, src).unwrap_or_default(), &args[1..]),
            // `app.use(API_PREFIX, router)`: the constant is resolved after all files are known
            Some(a)
                if args.len() >= 2
                    && matches!(a.kind(), "identifier" | "member_expression")
                    && !authish(text(*a, src)) =>
            {
                (format!("${}", text(*a, src).rsplit('.').next().unwrap_or("")), &args[1..])
            }
            _ => (String::new(), args),
        };
        // auth hints and unclassified middleware passed in the same call as the router (`use('/api', requireAuth, api)`)
        let mut mount_roles: Vec<String> = self.mw.get(scope).cloned().unwrap_or_default();
        let mut mount_mw = self.unk.contains(scope);
        for a in rest {
            if matches!(a.kind(), "call_expression" | "arrow_function" | "function_expression" | "function") {
                if require_spec(*a, src).is_none() && !mw_benign(*a, src) {
                    let r = mw_roles(*a, src);
                    if r.is_empty() {
                        mount_mw = true;
                    }
                    mount_roles.extend(r);
                }
            } else if matches!(a.kind(), "identifier" | "member_expression") && rest.len() > 1 && !routerish(text(*a, src)) {
                mount_roles.extend(mw_roles(*a, src));
            }
        }
        for a in rest {
            let (child, spec) = match a.kind() {
                "identifier" => {
                    let nm = text(*a, src).to_string();
                    match self.imports.get(&nm) {
                        Some((s, orig)) => {
                            (if orig == "default" || orig == "*" { nm } else { orig.clone() }, s.clone())
                        }
                        None => (nm, String::new()),
                    }
                }
                "call_expression" => match require_spec(*a, src) {
                    Some(s) => ("default".to_string(), s),
                    None => {
                        let r = mw_roles(*a, src);
                        if r.is_empty() && !mw_benign(*a, src) {
                            self.unk.insert(scope.to_string());
                        }
        // `use('/api', auth, router)` guards that prefix only, not the whole app
                        if prefix.is_empty() {
                            for x in r {
                                self.mw.entry(scope.to_string()).or_default().push(x);
                            }
                        }
                        continue;
                    }
                },
                "member_expression" => {
                    // `users.router` where users is an import
                    let o = a.child_by_field_name("object").map(|x| text(x, src)).unwrap_or("");
                    let p = a.child_by_field_name("property").map(|x| text(x, src)).unwrap_or("");
                    match self.imports.get(o) {
                        Some((s, _)) => (p.to_string(), s.clone()),
                        None => continue,
                    }
                }
                _ => continue,
            };
            // a plain local identifier that is an auth middleware, not a router
            if spec.is_empty() && !self.servers.contains_key(&child) {
                let r = mw_roles(*a, src);
                if r.is_empty() && !mw_benign(*a, src) {
                    self.unk.insert(scope.to_string());
                }
if prefix.is_empty() {
                    for x in r {
                        self.mw.entry(scope.to_string()).or_default().push(x);
                    }
                }
                continue;
            }
            if spec.is_empty()
                || spec.starts_with('.')
                || spec.starts_with('/')
                || spec.starts_with('@')
                || spec.starts_with('~')
            {
                // an imported identifier passed alone to `use` with a non-router-looking name may be middleware
                if prefix.is_empty() && rest.len() == 1 && a.kind() == "identifier" && !routerish(&child) && mw_roles(*a, src).is_empty() {
                    self.unk.insert(scope.to_string());
                    mount_mw = true;
                }
                push_mount_ex(rows, &self.f.path, line(n), "ts", scope, &prefix, &child, &spec, &mount_roles, mount_mw);
            }
        }
    }
}

/// Name of the variable a fluent router chain is assigned to (`default` for an export).
fn chain_scope(call: Node, src: &str) -> Option<String> {
    let mut top = call;
    // climb to the outermost call of the chain
    while let Some(p) = top.parent() {
        match p.kind() {
            "member_expression" => top = p.parent().filter(|x| x.kind() == "call_expression")?,
            _ => break,
        }
    }
    let p = top.parent()?;
    match p.kind() {
        "variable_declarator" => p.child_by_field_name("name").map(|n| text(n, src).to_string()),
        "export_statement" => Some("default".into()),
        "assignment_expression" => Some("default".into()),
        _ => None,
    }
}

/// First-argument route path: a string or template.
fn route_path(a: Node, src: &str) -> Option<String> {
    let s = js_string(a, src)?;
    if s.starts_with('/') || s.is_empty() || s.starts_with('*') || s.starts_with(':') {
        Some(s)
    } else {
        None
    }
}

/// `router.route('/p')` at the bottom of `...get(h).post(h)` chains: (router, path).
fn chain_root(mut n: Node, src: &str) -> Option<(String, String)> {
    for _ in 0..12 {
        let func = n.child_by_field_name("function")?;
        if func.kind() != "member_expression" {
            return None;
        }
        let prop = text(func.child_by_field_name("property")?, src);
        let obj = func.child_by_field_name("object")?;
        if prop == "route" && obj.kind() == "identifier" {
            let a = n.child_by_field_name("arguments")?.named_child(0)?;
            return Some((text(obj, src).to_string(), js_string(a, src)?));
        }
        if obj.kind() == "call_expression" {
            n = obj;
        } else {
            return None;
        }
    }
    None
}

/// (class/receiver, handler) of the last route argument.
fn handler_name(h: Option<Node>, src: &str) -> (String, String) {
    let Some(h) = h else { return (String::new(), "(inline)".into()) };
    match h.kind() {
        "identifier" => (String::new(), text(h, src).to_string()),
        "member_expression" => {
            let o = h.child_by_field_name("object").map(|x| text(x, src)).unwrap_or("");
            let p = h.child_by_field_name("property").map(|x| text(x, src)).unwrap_or("");
            (o.to_string(), p.to_string())
        }
        "call_expression" => {
            // wrapper like asyncHandler(controller.list)
            let args = h.child_by_field_name("arguments").map(named_children).unwrap_or_default();
            match args.last() {
                Some(a) if matches!(a.kind(), "identifier" | "member_expression") => handler_name(Some(*a), src),
                _ => (String::new(), "(inline)".into()),
            }
        }
        _ => (String::new(), "(inline)".into()),
    }
}

fn authish(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    [
        "auth",
        "jwt",
        "passport",
        "protect",
        "guard",
        "role",
        "permission",
        "admin",
        "verify",
        "login",
        "session",
        "token",
        "require",
        "ensure",
        "authorize",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Roles / auth hints from a middleware argument: `authorize('ADMIN')` -> ADMIN, `requireAuth` -> auth:requireAuth.
fn mw_roles(a: Node, src: &str) -> Vec<String> {
    match a.kind() {
        "identifier" | "member_expression" => {
            let t = text(a, src);
            if authish(t) {
                vec![format!("auth:{}", t.rsplit('.').next().unwrap_or(t))]
            } else {
                vec![]
            }
        }
        "call_expression" => {
            let Some(func) = a.child_by_field_name("function") else { return vec![] };
            let ft = text(func, src);
            let name = ft.rsplit('.').next().unwrap_or(ft);
            if !authish(ft) {
                return vec![];
            }
            let mut roles = vec![];
            if let Some(args) = a.child_by_field_name("arguments") {
                for x in named_children(args) {
                    if let Some(s) = js_string(x, src) {
                        roles.push(s);
                    } else if x.kind() == "array" {
                        roles.extend(named_children(x).into_iter().filter_map(|y| js_string(y, src)));
                    }
                }
            }
            if roles.is_empty() {
                roles.push(format!("auth:{name}"));
            }
            roles
        }
        "array" => named_children(a).into_iter().flat_map(|x| mw_roles(x, src)).collect(),
        _ => vec![],
    }
}

/// Middleware that never decides who may call a route (parsers, CORS, logging, static files, error handlers).
fn mw_benign(a: Node, src: &str) -> bool {
    match a.kind() {
        "arrow_function" | "function_expression" | "function" => {
            // `(err, req, res, next) => ...` is an error handler; anything shorter could be an auth check
            a.child_by_field_name("parameters").map(|p| named_children(p).len() >= 4).unwrap_or(false)
        }
        "call_expression" => {
            let ft = a.child_by_field_name("function").map(|f| text(f, src)).unwrap_or("").to_ascii_lowercase();
            ["json", "urlencoded", "cors", "helmet", "morgan", "compression", "static", "cookieparser", "bodyparser", "text(", "raw", "logger", "favicon", "serve"]
                .iter()
                .any(|k| ft.contains(k))
        }
        _ => false,
    }
}

/// Identifier names that read as a router (`routes`, `articlesController`, `apiRouter`), as opposed to middleware.
fn routerish(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    ["rout", "controller", "api", "handler", "endpoint", "resource"].iter().any(|k| l.contains(k))
}
