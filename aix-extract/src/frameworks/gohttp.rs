//! Go routers: net/http (`HandleFunc`, Go 1.22 `"GET /p"` patterns), chi (`Get`, `Route`, `Group`, `Mount`, `With`),
//! gin / echo / fiber (`GET`, `Group`, `Use`) and gorilla/mux (`HandleFunc(..).Methods(..)`, `PathPrefix().Subrouter()`).
//! Text-based (no Go grammar): calls are found by regex, arguments and blocks by balanced scanning.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;

use super::*;

ext_impl!(GoHttp, "gohttp", |p| ext_of(p) == "go" && !p.ends_with("_test.go"), extract_file);

static FUNC_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^func\s*\(\s*(\w+)").unwrap());
static ROUTER_PARAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\w+\s+\*?(?:gin\.(?:RouterGroup|IRouter|IRoutes)|chi\.Router|mux\.Router|echo\.Group|fiber\.Router)\b|\)\s*\*?(?:chi\.Router|mux\.Router|gin\.RouterGroup|echo\.Group)\s*\{").unwrap()
});
/// A call that hands a router group to another function: `pkg.Register(v1.Group("/x"))` / `Register(v1)`.
static PASS_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?P<callee>[A-Za-z_][\w.]*)\(\s*(?P<v>[A-Za-z_]\w*)\s*[,)]").unwrap());
const BENIGN_MW: &[&str] = &[
    "logger", "recovery", "cors", "gzip", "compress", "requestid", "ratelimit", "static", "helmet", "secure", "timeout",
    "metrics", "trace", "prometheus", "default", "bodylimit", "sessions", "middleware.logger", "middleware.recover",
];
const MW_MARK: &str = "?mw";

/// Roles without the unclassified-middleware marker, and whether the marker was present.
fn fin(roles: &[String]) -> (Vec<String>, bool) {
    (roles.iter().filter(|r| *r != MW_MARK).cloned().collect(), roles.iter().any(|r| r == MW_MARK))
}

/// Auth hint for a middleware argument, or the marker when it is neither auth-like nor obviously benign.
fn mw_class(a: &str) -> Option<String> {
    if let Some(h) = mw_hint(a) {
        return Some(h);
    }
    let name = a.split('(').next().unwrap_or(a).trim().to_ascii_lowercase();
    if name.is_empty() || BENIGN_MW.iter().any(|k| name.contains(k)) {
        None
    } else {
        Some(MW_MARK.to_string())
    }
}
static METHODS_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\.Methods\(([^)]*)\)").unwrap());

const FRAMEWORKS: &[&str] = &[
    "net/http",
    "go-chi/chi",
    "gin-gonic/gin",
    "labstack/echo",
    "gofiber/fiber",
    "gorilla/mux",
    "julienschmidt/httprouter",
];

/// Offset of the matching close for the opener at `open` (a `(` or `{`), skipping string and rune literals.
fn close_of(t: &[u8], open: usize) -> Option<usize> {
    let (o, c) = match t[open] {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0i32;
    let mut i = open;
    while i < t.len() {
        match t[i] {
            b'"' => {
                i += 1;
                while i < t.len() && t[i] != b'"' {
                    if t[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'`' => {
                i += 1;
                while i < t.len() && t[i] != b'`' {
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < t.len() && t[i] != b'\'' {
                    if t[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if i + 1 < t.len() && t[i + 1] == b'/' => {
                while i < t.len() && t[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            x if x == o => depth += 1,
            x if x == c => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split call arguments at top-level commas.
fn split_args(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut start = 0;
    let mut i = 0;
    let mut depth = 0i32;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    i += 1;
                }
            }
            b'(' | b'{' | b'[' => depth += 1,
            b')' | b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        out.push(last.to_string());
    }
    out
}

/// A string argument: a literal, or a concatenation with literal parts (`"/api"+"/x"`, `baseURL+"/trainings"`: a
/// leading variable is a mount prefix the file cannot see and is left out; a later one becomes `{name}`).
fn lit(a: &str) -> Option<String> {
    let a = a.trim();
    let one = |p: &str| -> Option<String> {
        let p = p.trim();
        (p.len() >= 2 && ((p.starts_with('"') && p.ends_with('"') && !p[1..p.len() - 1].contains('"')) || (p.starts_with('`') && p.ends_with('`') && !p[1..p.len() - 1].contains('`'))))
            .then(|| p[1..p.len() - 1].to_string())
    };
    if let Some(v) = one(a) {
        return Some(v);
    }
    // split on `+` outside string literals
    let mut parts: Vec<String> = vec![];
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut esc = false;
    for c in a.chars() {
        if let Some(qc) = q {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' && qc == '"' {
                esc = true;
            } else if c == qc {
                q = None;
            }
            continue;
        }
        match c {
            '"' | '`' => {
                q = Some(c);
                cur.push(c);
            }
            '+' => parts.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    parts.push(cur);
    if parts.len() < 2 {
        return None;
    }
    let mut out = String::new();
    let mut any = false;
    for (i, p) in parts.iter().enumerate() {
        match one(p) {
            Some(v) => {
                out.push_str(&v);
                any = true;
            }
            None => {
                let id = p.trim();
                if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') || id.is_empty() {
                    return None;
                }
                if i > 0 {
                    out.push_str(&format!("{{{}}}", id.rsplit('.').next().unwrap_or(id)));
                }
            }
        }
    }
    any.then_some(out)
}

fn authish(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    [
        "auth",
        "jwt",
        "token",
        "session",
        "login",
        "role",
        "permission",
        "admin",
        "guard",
        "protect",
        "basicauth",
        "require",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn mw_hint(a: &str) -> Option<String> {
    let name = a.split('(').next().unwrap_or(a).trim();
    if name.starts_with("func") || !authish(name) {
        return None;
    }
    // `AuthMiddleware(false)` / `(true)` differ in meaning (optional vs required); keep the literal
    let arg = a.split_once('(').map(|x| x.1.trim_end_matches(')').trim()).filter(|x| matches!(*x, "true" | "false"));
    Some(match arg {
        Some(x) => format!("auth:{}({x})", name.rsplit('.').next().unwrap_or(name)),
        None => format!("auth:{}", name.rsplit('.').next().unwrap_or(name)),
    })
}

/// Name of the call that encloses offset `at` (`pkg.Register` in `pkg.Register(v1.Group("/x"))`), if any.
fn enclosing_call(t: &str, at: usize) -> Option<String> {
    let b = t.as_bytes();
    let lo = at.saturating_sub(300);
    let mut depth = 0i32;
    let mut i = at;
    while i > lo {
        i -= 1;
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                if depth == 0 {
                    let mut s = i;
                    while s > 0 && (b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_' || b[s - 1] == b'.') {
                        s -= 1;
                    }
                    return (s < i).then(|| t[s..i].to_string());
                }
                depth -= 1;
            }
            b'{' | b'}' | b';' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

const GO_VERBS: &[&str] = &[
    "Get", "Post", "Put", "Delete", "Patch", "Head", "Options", "Connect", "Trace", "GET", "POST", "PUT", "DELETE",
    "PATCH", "HEAD", "OPTIONS", "Any", "Handle", "HandleFunc", "Method", "MethodFunc", "Route", "Group", "Mount", "Use",
    "PathPrefix", "Static", "StaticFS", "With",
];

/// (class, handler) from a handler argument.
fn handler_of(a: &str) -> (String, String) {
    let a = a.trim();
    if a.starts_with("func") {
        return (String::new(), "(inline)".into());
    }
    let inner = if let Some(x) = a.strip_prefix("http.HandlerFunc(").and_then(|r| r.strip_suffix(')')) { x } else { a };
    let inner = inner.split('(').next().unwrap_or(inner);
    match inner.rsplit_once('.') {
        Some((c, h)) => (c.rsplit('.').next().unwrap_or(c).to_string(), h.to_string()),
        None => (String::new(), inner.to_string()),
    }
}

struct Sc {
    var: String,
    prefix: String,
    roles: Vec<String>,
    end: usize,
}

fn extract_file(f: &SourceFile, rows: &mut Rows) {
    let t = &f.text;
    if !FRAMEWORKS.iter().any(|m| t.contains(m)) {
        return;
    }
    let b = t.as_bytes();
    let line_of = |off: usize| b[..off.min(b.len())].iter().filter(|c| **c == b'\n').count() as u32 + 1;
    let funcs: Vec<(usize, String, bool)> = Regex::new(r"(?m)^func\s+(?:\(\s*\w*\s*\*?\s*(\w+)[^)]*\)\s*)?(\w+)")
        .unwrap()
        .captures_iter(t)
        .map(|c| {
            let st = c.get(0).unwrap().start();
            let hdr = t[st..].lines().next().unwrap_or("");
            // a function that receives a router / group: its routes are relative to wherever it is called
            let sub = ROUTER_PARAM.is_match(hdr);
            (
                st,
                match c.get(1) {
                    Some(r) => format!("{}.{}", r.as_str(), &c[2]),
                    None => c[2].to_string(),
                },
                sub,
            )
        })
        .collect();
    let func_at = |off: usize| funcs.iter().rev().find(|(s, _, _)| *s <= off).map(|(_, n, _)| n.clone()).unwrap_or_default();
    let func_sub = |off: usize| funcs.iter().rev().find(|(s, _, _)| *s <= off).is_some_and(|(_, _, b)| *b);
    let echo = t.contains("labstack/echo");
    let mut seen: std::collections::HashSet<(String, String, String, String)> = Default::default();

    let call = Regex::new(
        r"(?x)
        (?:\b(?P<assign>\w+)\s*:?=\s*)?              # v :=
        \b(?P<recv>[A-Za-z_]\w*)
        (?:\.With\((?P<with>[^)]*)\))?
        \.(?P<verb>Get|Post|Put|Delete|Patch|Head|Options|Connect|Trace|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Handle|HandleFunc|Method|MethodFunc|Route|Group|Mount|Use|PathPrefix|Static|StaticFS)\(",
    )
    .unwrap();
    let mut vars: HashMap<(String, String), (String, Vec<String>)> = HashMap::new(); // (func, var) -> (prefix, roles)
    let mut stack: Vec<Sc> = vec![];
    let passes: Vec<(usize, String, String)> = PASS_CALL
        .captures_iter(t)
        .filter(|c| {
            let last = c["callee"].rsplit('.').next().unwrap_or("");
            !GO_VERBS.contains(&last) && !matches!(last, "func" | "if" | "for" | "switch" | "make" | "len" | "append" | "new" | "panic" | "string" | "int")
        })
        .map(|c| (c.get(0).unwrap().start(), c["callee"].to_string(), c["v"].to_string()))
        .collect();
    let mut next_pass = 0usize;
    // flush the `Register(group)` calls that come before `upto`, in source order, with the group state at that point
    macro_rules! flush_passes {
        ($upto:expr) => {
            while next_pass < passes.len() && passes[next_pass].0 < $upto {
                let (pos, callee, v) = passes[next_pass].clone();
                next_pass += 1;
                let ls = t[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
                if t[ls..pos].contains("//") {
                    continue;
                }
                stack.retain(|s| s.end > pos);
                let func = func_at(pos);
                let known = stack
                    .iter()
                    .rev()
                    .find(|s| s.var == v)
                    .map(|s| (s.prefix.clone(), s.roles.clone()))
                    .or_else(|| vars.get(&(func.clone(), v.clone())).cloned());
                if let Some((pre, roles)) = known {
                    let (r, mw) = fin(&roles);
                    let child = callee.rsplit('.').next().unwrap_or(&callee);
                    push_mount_ex(rows, &f.path, line_of(pos), "go", &func, &pre, child, "", &r, mw);
                }
            }
        };
    }
    for m in call.captures_iter(t) {
        let whole = m.get(0).unwrap();
        let start = whole.start();
        flush_passes!(start);
        // examples inside comments are not routes
        let ls = t[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        if t[ls..start].contains("//") || t[ls..start].trim_start().starts_with('*') {
            continue;
        }
        stack.retain(|s| s.end > start);
        let func = func_at(start);
        let recv = m["recv"].to_string();
        // skip obvious non-routers
        if matches!(recv.as_str(), "client" | "http" if &m["verb"] != "Handle" && &m["verb"] != "HandleFunc") {
            continue;
        }
        let (base, mut roles) = stack
            .iter()
            .rev()
            .find(|s| s.var == recv)
            .map(|s| (s.prefix.clone(), s.roles.clone()))
            .or_else(|| vars.get(&(func.clone(), recv.clone())).cloned())
            .unwrap_or_default();
        if let Some(w) = m.name("with") {
            roles.extend(split_args(w.as_str()).iter().filter_map(|a| mw_class(a)));
        }
        let open = whole.end() - 1;
        let Some(close) = close_of(b, open) else { continue };
        let args = split_args(&t[open + 1..close]);
        let verb = &m["verb"];
        let ln = line_of(start);
        match verb {
            "Use" => {
                let hint: Vec<String> = args.iter().filter_map(|a| mw_class(a)).collect();
                if hint.is_empty() {
                    continue;
                }
                if let Some(s) = stack.iter_mut().rev().find(|s| s.var == recv) {
                    s.roles.extend(hint);
                } else {
                    let e = vars.entry((func.clone(), recv.clone())).or_default();
                    e.1.extend(hint);
                }
            }
            "Group" | "PathPrefix" => {
                let (pre, rest) = match args.first().and_then(|a| lit(a)) {
                    Some(p) => (p, &args[1..]),
                    None => (String::new(), &args[..]),
                };
                let mut r2 = roles.clone();
                r2.extend(rest.iter().filter(|a| !a.starts_with("func")).filter_map(|a| mw_class(a)));
                let full = if pre.is_empty() { base.clone() } else { join(&base, &pre) };
                if let Some(v) = m.name("assign") {
                    vars.insert((func.clone(), v.as_str().to_string()), (full.clone(), r2.clone()));
                }
                // `pkg.Register(v1.Group("/x"))`: the group is handed to another function, whose routes are relative to it
                if m.name("assign").is_none() && verb == "Group" && !args.iter().any(|a| a.starts_with("func")) {
                    if let Some(callee) = enclosing_call(t, start) {
                        let last = callee.rsplit('.').next().unwrap_or(&callee).to_string();
                        if !GO_VERBS.contains(&last.as_str()) {
                            let (r, mw) = fin(&r2);
                            push_mount_ex(rows, &f.path, ln, "go", &func, &full, &last, "", &r, mw);
                        }
                    }
                }
                // chi: r.Group(func(r chi.Router) { ... }) / gin: r.Group("/x", func(g *gin.RouterGroup) {...})
                if let Some(blk) = args.iter().find(|a| a.starts_with("func")) {
                    if let Some(v) = FUNC_PARAM.captures(blk) {
                        let hdr = t[open..close + 1].find("func").map(|x| open + x).unwrap_or(open);
                        if let Some(bo) = t[hdr..].find('{').map(|x| hdr + x) {
                            if let Some(end) = close_of(b, bo) {
                                stack.push(Sc { var: v[1].to_string(), prefix: full, roles: r2, end });
                            }
                        }
                    }
                }
            }
            "Route" => {
                let Some(pre) = args.first().and_then(|a| lit(a)) else { continue };
                if let Some(blk) = args.iter().find(|a| a.starts_with("func")) {
                    if let Some(v) = FUNC_PARAM.captures(blk) {
                        // body brace: first `{` after the func header inside the call
                        let hdr = t[open..close + 1].find("func").map(|x| open + x).unwrap_or(open);
                        if let Some(bo) = t[hdr..].find('{').map(|x| hdr + x) {
                            if let Some(end) = close_of(b, bo) {
                                stack.push(Sc { var: v[1].to_string(), prefix: join(&base, &pre), roles, end });
                            }
                        }
                    }
                }
            }
            "Mount" => {
                let Some(pre) = args.first().and_then(|a| lit(a)) else { continue };
                let Some(h) = args.get(1) else { continue };
                // chi: r.Mount("/x", subRouter()) / users{}.Routes() / handler var
                let callee = h.split('(').next().unwrap_or(h).trim();
                let callee = match callee.rsplit_once('.') {
                    Some((o, m)) => {
                        let ty = o.split('{').next().unwrap_or(o).trim();
                        if ty.is_empty()
                            || !ty.chars().next().unwrap().is_uppercase() && !ty.chars().next().unwrap().is_lowercase()
                        {
                            m.to_string()
                        } else {
                            format!("{}.{}", ty.rsplit('.').next().unwrap_or(ty), m)
                        }
                    }
                    None => callee.to_string(),
                };
                let (r, mw) = fin(&roles);
                push_mount_ex(rows, &f.path, ln, "go", &func, &join(&base, &pre), &callee, "", &r, mw);
            }
            "Static" | "StaticFS" => {}
            _ => {
                // route registration
                let (mut method, path_i) = match verb {
                    "Method" | "MethodFunc" => {
                        (args.first().and_then(|a| lit(a)).unwrap_or_default().to_ascii_uppercase(), 1)
                    }
                    // `r.Handle("PUT", "/h", h)` (gin / echo style): the method comes first
                    "Any" | "Handle" | "HandleFunc"
                        if args.len() >= 3
                            && args.first().and_then(|a| lit(a)).is_some_and(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_uppercase()))
                            && args.get(1).and_then(|a| lit(a)).is_some_and(|p| p.starts_with('/')) =>
                    {
                        (args.first().and_then(|a| lit(a)).unwrap_or_default(), 1)
                    }
                    "Any" | "Handle" | "HandleFunc" => ("ANY".to_string(), 0),
                    v => (v.to_ascii_uppercase(), 0),
                };
                let Some(mut p) = args.get(path_i).and_then(|a| lit(a)) else { continue };
                if matches!(verb, "Handle" | "HandleFunc" | "Any") {
                    // Go 1.22 "GET /users/{id}"
                    if let Some((mm, rest)) = p.split_once(' ') {
                        if mm.chars().all(|c| c.is_ascii_uppercase()) && rest.starts_with('/') {
                            method = mm.to_string();
                            p = rest.to_string();
                        }
                    }
                }
                if !p.starts_with('/') {
                    continue;
                }
                let hargs = &args[path_i + 1..];
                if hargs.is_empty() {
                    continue;
                }
                let mut roles2 = roles.clone();
                // echo puts the handler first and the route middleware after it; everything else the other way round
                let (hand, mws): (&String, &[String]) =
                    if echo && verb.chars().all(|c| c.is_ascii_uppercase()) { (&hargs[0], &hargs[1..]) } else { (hargs.last().unwrap(), &hargs[..hargs.len() - 1]) };
                for a in mws {
                    roles2.extend(mw_class(a));
                }
                // a wrapped handler (`requireAuth(h)`) is middleware too
                if hand.contains('(') && !hand.starts_with("func") && !hand.starts_with("http.HandlerFunc(") {
                    roles2.extend(mw_class(hand));
                }
                let (class, handler) = handler_of(hand);
                let (mut roles2, mw) = fin(&roles2);
                if roles2.is_empty() && !mw {
                    roles2.push("public".into());
                }
                // gorilla: .Methods("GET", "POST")
                let after = &t[close + 1..];
                let methods: Vec<String> = match METHODS_SUFFIX.captures(after) {
                    Some(mc) => split_args(&mc[1]).iter().filter_map(|a| lit(a)).collect(),
                    None => vec![method.clone()],
                };
                let p = p.trim_end_matches("{$}").to_string();
                let path = join(&base, &p.replace("/{path...}", "/{path}"));
                for me in methods {
                    // `/x` and `/x/` register the same handler twice: one row
                    if !seen.insert((func.clone(), me.clone(), path.clone(), handler.clone())) {
                        continue;
                    }
                    push_scoped_ex(
                        rows,
                        &func,
                        Ep {
                            file: &f.path,
                            line: ln,
                            method: &me,
                            path: &path,
                            class: &class,
                            handler: &handler,
                            roles: roles2.clone(),
                        },
                        func_sub(start),
                    );
                }
            }
        }
    }
    flush_passes!(usize::MAX);
}
