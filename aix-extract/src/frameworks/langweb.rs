//! Web routes of the newer languages, read as text (comments blanked first): ASP.NET Core (attribute routes and
//! minimal APIs), Laravel (`routes/*.php`), Rails (`config/routes.rb`), Ktor and Spring in Kotlin, and Rust's Actix
//! web / Axum / Rocket. Each endpoint carries method, full path (as far as this file shows it) and handler.

use std::sync::LazyLock;

use regex::Regex;

use super::*;
use crate::text::Lines;

ext_impl!(AspNet, "aspnet", |p| ext_of(p) == "cs", aspnet);
ext_impl!(Laravel, "laravel", |p| ext_of(p) == "php" && (p.contains("routes/") || p.contains("Routes/")), laravel);
ext_impl!(Rails, "rails", |p| p.ends_with("routes.rb") || p.contains("config/routes/"), rails);
ext_impl!(KotlinWeb, "kotlinweb", |p| ext_of(p) == "kt", kotlin_web);
ext_impl!(RustWeb, "rustweb", |p| ext_of(p) == "rs", rust_web);

thread_local! {
    static CACHE: std::cell::RefCell<std::collections::HashMap<&'static str, Regex>> = std::cell::RefCell::new(Default::default());
}

/// A compiled regex for a literal pattern, built once per thread (the route scanners use many small patterns per match).
fn rx(p: &'static str) -> Regex {
    CACHE.with(|c| c.borrow_mut().entry(p).or_insert_with(|| Regex::new(p).unwrap()).clone())
}

const VERBS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// Blank `//` and `/* */` comments (and `#` ones when `hash`) keeping offsets; string contents are left alone.
fn blank_comments(t: &str, hash: bool) -> String {
    lex(t, hash, false).0
}

/// Interior byte ranges of string literals (sorted, non-overlapping).
type Strs = Vec<(usize, usize)>;

/// True when `pos` lies inside a string literal (a route-looking text in a test fixture or a message is no route).
fn in_str(strs: &Strs, pos: usize) -> bool {
    let i = strs.partition_point(|r| r.1 <= pos);
    strs.get(i).is_some_and(|r| r.0 <= pos && pos < r.1)
}

/// Comments blanked (offsets kept) plus the string-literal interiors. `rust` switches on raw strings (`r#".."#`) and
/// lifetime-aware char literals; `@".."` (C# verbatim) and `"""` (raw / Kotlin) strings are always understood.
fn lex(t: &str, hash: bool, rust: bool) -> (String, Strs) {
    let b = t.as_bytes();
    let mut out = b.to_vec();
    let mut strs: Strs = vec![];
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        // raw strings: Rust r#"..."#, triple-quoted
        if rust && (c == b'r' || c == b'b') && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
            let mut j = i + 1;
            if c == b'b' && b.get(j) == Some(&b'r') {
                j += 1;
            }
            if c == b'r' || j > i + 1 {
                let h0 = j;
                while b.get(j) == Some(&b'#') {
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    let hashes = j - h0;
                    let close: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
                    let start = j + 1;
                    let end = t[start..].find(std::str::from_utf8(&close).unwrap()).map(|x| start + x).unwrap_or(b.len());
                    strs.push((start, end));
                    i = (end + close.len()).min(b.len());
                    continue;
                }
            }
        }
        if c == b'"' && b.get(i + 1) == Some(&b'"') && b.get(i + 2) == Some(&b'"') {
            let start = i + 3;
            let end = t[start..].find("\"\"\"").map(|x| start + x).unwrap_or(b.len());
            strs.push((start, end));
            i = (end + 3).min(b.len());
            continue;
        }
        if c == b'"' {
            let verbatim = i > 0 && b[i - 1] == b'@';
            let start = i + 1;
            let mut j = start;
            while j < b.len() {
                if verbatim {
                    if b[j] == b'"' {
                        if b.get(j + 1) == Some(&b'"') {
                            j += 2;
                            continue;
                        }
                        break;
                    }
                } else if b[j] == b'\\' {
                    j += 2;
                    continue;
                } else if b[j] == b'"' {
                    break;
                }
                j += 1;
            }
            let j = j.min(b.len());
            strs.push((start, j));
            i = (j + 1).min(b.len());
            continue;
        }
        if c == b'\'' || c == b'`' {
            if c == b'\'' && rust {
                // char literal `'x'` / `'\n'`; anything else is a lifetime
                if b.get(i + 1) == Some(&b'\\') {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != b'\'' && b[j] != b'\n' {
                        j += 1;
                    }
                    i = (j + 1).min(b.len());
                } else {
                    let ch = t[i + 1..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                    i += if b.get(i + 1 + ch) == Some(&b'\'') { ch + 2 } else { 1 };
                }
                continue;
            }
            // a Ruby symbol quote / apostrophe is not a string start when it has no closing quote on the line
            if c == b'\'' {
                let rest = &b[i + 1..b.len().min(i + 200)];
                let eol = rest.iter().position(|&x| x == b'\n').unwrap_or(rest.len());
                if !rest[..eol].contains(&b'\'') {
                    i += 1;
                    continue;
                }
            }
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != c {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let j = j.min(b.len());
            strs.push((start, j));
            i = (j + 1).min(b.len());
            continue;
        }
        if (c == b'/' && b.get(i + 1) == Some(&b'/')) || (hash && c == b'#') {
            while i < b.len() && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                if b[i] != b'\n' {
                    out[i] = b' ';
                }
                i += 1;
            }
            if i < b.len() {
                out[i] = b' ';
                if i + 1 < b.len() {
                    out[i + 1] = b' ';
                }
                i += 2;
            }
            continue;
        }
        i += 1;
    }
    (String::from_utf8(out).unwrap_or_else(|_| t.to_string()), strs)
}

/// Offset just past the delimiter matching the opener at `open`.
fn close_of(t: &str, open: usize) -> Option<usize> {
    let b = t.as_bytes();
    let (o, c) = match b[open] {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let (mut depth, mut i, mut q) = (0i32, open, 0u8);
    while i < b.len() {
        let ch = b[i];
        if q != 0 {
            if ch == b'\\' {
                i += 2;
                continue;
            }
            if ch == q {
                q = 0;
            }
        } else if ch == b'"' {
            q = ch;
        } else if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

fn first_string(s: &str) -> Option<String> {
    static S: LazyLock<Regex> = LazyLock::new(|| rx(r#"^\s*(?:@?"([^"]*)"|'([^']*)')"#));
    S.captures(s).map(|c| c.get(1).or_else(|| c.get(2)).unwrap().as_str().to_string())
}

#[allow(clippy::too_many_arguments)]
fn push(rows: &mut Rows, f: &SourceFile, line: u32, method: &str, path: &str, class: &str, handler: &str, roles: Vec<String>) {
    push_ep(rows, Ep { file: &f.path, line, method, path, class, handler, roles });
}

/// `{id:int}`, `<id>`, `:id`, `{id?}` -> `{id}`.
fn norm_params(p: &str) -> String {
    static R: LazyLock<Regex> = LazyLock::new(|| rx(r"\{([A-Za-z_]\w*)[^}/]*\}|<(?:[\w]+:)?([A-Za-z_]\w*)>|/:([A-Za-z_]\w*)"));
    R.replace_all(p, |c: &regex::Captures| {
        if let Some(m) = c.get(3) {
            format!("/{{{}}}", m.as_str())
        } else {
            format!("{{{}}}", c.get(1).or_else(|| c.get(2)).unwrap().as_str())
        }
    })
    .into_owned()
}

// ---------------------------------------------------------------------------------------------------
// ASP.NET Core
// ---------------------------------------------------------------------------------------------------

/// Effective access of a run of C# attributes: `public` (AllowAnonymous), the roles of `[Authorize(Roles = ..)]`
/// (constant expressions shown as written), `policy:<name>`, or `authenticated` for a bare `[Authorize]`.
fn auth_roles(attrs: &str) -> Option<Vec<String>> {
    static AUTH: LazyLock<Regex> = LazyLock::new(|| rx(r#"\bAuthorize(?:Attribute)?\b(?:\s*\(((?:[^()"]|"[^"]*")*)\))?"#));
    if attrs.contains("AllowAnonymous") {
        return Some(vec!["public".into()]);
    }
    let mut out: Vec<String> = vec![];
    let mut found = false;
    for c in AUTH.captures_iter(attrs) {
        found = true;
        let args = c.get(1).map(|x| x.as_str()).unwrap_or("");
        let named = |k: &str| -> Option<String> {
            let m = Regex::new(&format!(r"\b{k}\s*=\s*")).unwrap().find(args)?;
            let rest = &args[m.end()..];
            // the expression runs to the next top-level `, Name =` or the end
            let (mut depth, mut q, mut end) = (0i32, false, rest.len());
            for (i, ch) in rest.char_indices() {
                match ch {
                    '"' => q = !q,
                    '(' | '[' | '{' if !q => depth += 1,
                    ')' | ']' | '}' if !q => depth -= 1,
                    ',' if !q && depth == 0 => {
                        let tail = rest[i + 1..].trim_start();
                        let id: String = tail.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                        let after = tail[id.len()..].trim_start();
                        if !id.is_empty() && after.starts_with('=') && !after.starts_with("==") {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            Some(rest[..end].trim().to_string())
        };
        let mut had = false;
        if let Some(r) = named("Roles") {
            had = true;
            if let Some(lit) = r.strip_prefix('"').and_then(|x| x.strip_suffix('"')).filter(|x| !x.contains('"')) {
                out.extend(lit.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
            } else if !r.is_empty() {
                out.push(r.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
        if let Some(p) = named("Policy") {
            had = true;
            out.push(format!("policy:{}", p.trim_matches('"')));
        }
        if !had {
            // `[Authorize("PolicyName")]` positional policy
            if let Some(lit) = first_string(args).filter(|_| !args.contains('=')) {
                out.push(format!("policy:{lit}"));
            }
        }
    }
    if !found {
        return None;
    }
    if out.is_empty() {
        out.push("authenticated".into());
    }
    out.dedup();
    Some(out)
}

/// `.RequireAuthorization()` -> authenticated; `("Policy")` -> the policy name as written.
fn require_auth(stmt: &str) -> Vec<String> {
    rx(r#"RequireAuthorization\(\s*"([^"]*)""#).captures(stmt).map(|c| vec![c[1].to_string()]).unwrap_or_else(|| vec!["authenticated".to_string()])
}

fn aspnet(f: &SourceFile, rows: &mut Rows) {
    static CLASS: LazyLock<Regex> = LazyLock::new(|| rx(r"(?m)((?:^[ \t]*\[[^\n]*?\][ \t]*\n?)*)[ \t]*(?:public\s+|internal\s+|sealed\s+|abstract\s+|partial\s+)*class\s+(\w+)(?:\s*\([^)]*\))?\s*(?::\s*([^\n{]*))?"));
    static ACTION: LazyLock<Regex> = LazyLock::new(|| {
        rx(r"(?m)^((?:[ \t]*\[[^\n]*?\][ \t]*\n?)+)[ \t]*(?:public|protected|internal)\s+(?:static\s+|async\s+|virtual\s+|override\s+)*[\w<>\[\],?.() ]+?\s+(\w+)\s*(?:<[^>]*>)?\s*\(")
    });
    static MIN: LazyLock<Regex> = LazyLock::new(|| rx(r#"(\w+)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods)\s*\(\s*(?:@?"([^"]*)")"#));
    static GROUP: LazyLock<Regex> = LazyLock::new(|| rx(r#"(?:var\s+)?(\w+)\s*=\s*(\w+)\s*\.\s*MapGroup\s*\(\s*"([^"]*)""#));
    let (t, strs) = lex(&f.text, false, false);
    let ln = Lines::new(&t);
    // controllers
    if t.contains("Controller") || t.contains("[Http") || t.contains("PageModel") {
        let mut classes: Vec<(usize, String, String, String)> = vec![];
        for c in CLASS.captures_iter(&t) {
            let m = c.get(2).unwrap();
            if in_str(&strs, m.start()) {
                continue;
            }
            classes.push((m.start(), m.as_str().to_string(), c[1].to_string(), c.get(3).map(|x| x.as_str().to_string()).unwrap_or_default()));
        }
        for (k, (at, name, cattrs, bases)) in classes.iter().enumerate() {
            let end = classes.get(k + 1).map(|x| x.0).unwrap_or(t.len());
            // Razor Pages: `OnGet` / `OnPostAsync` / `OnPostDelete` of a PageModel serve the page's own path
            if bases.contains("PageModel") {
                if let Some(page) = razor_page_path(&f.path) {
                    for a in rx(r"\b(?:public\s+)?(?:async\s+)?[\w<>]+\s+(On(Get|Post|Put|Delete|Patch)(\w*?)(?:Async)?)\s*\(").captures_iter(&t[*at..end]) {
                        let off = at + a.get(1).unwrap().start();
                        if in_str(&strs, off) {
                            continue;
                        }
                        let handler_name = &a[3];
                        let path = if handler_name.is_empty() { page.clone() } else { format!("{page}?handler={handler_name}") };
                        push(rows, f, ln.at(off), &a[2].to_uppercase(), &path, name, &a[1], auth_roles(cattrs).unwrap_or_default());
                    }
                }
                continue;
            }
            // Ardalis ApiEndpoints (`EndpointBaseAsync.WithRequest<..>`) are controllers with one action
            let ctl_like = bases.contains("Controller") || bases.contains("EndpointBase") || bases.contains("BaseAsyncEndpoint") || bases.contains("BaseEndpoint") || cattrs.contains("ApiController") || name.ends_with("Controller");
            if !ctl_like {
                continue;
            }
            let route = rx(r#"\[\s*Route\s*\(\s*"([^"]*)""#).captures(cattrs).map(|c| c[1].to_string()).unwrap_or_default();
            let short = name.trim_end_matches("Controller").to_lowercase();
            let class_auth = auth_roles(cattrs);
            for a in ACTION.captures_iter(&t[*at..end]) {
                let attrs = &a[1];
                let handler = a[2].to_string();
                let off = at + a.get(0).unwrap().start();
                if in_str(&strs, off) {
                    continue;
                }
                let mut verbs: Vec<(String, String)> = vec![];
                for h in rx(r#"\[\s*Http(Get|Post|Put|Delete|Patch|Head|Options)(?:\s*\(\s*(?:Name\s*=\s*"[^"]*"|"([^"]*)")?[^)\]]*\))?\s*\]"#).captures_iter(attrs) {
                    verbs.push((h[1].to_uppercase(), h.get(2).map(|x| x.as_str().to_string()).unwrap_or_default()));
                }
                let mroute = rx(r#"\[\s*Route\s*\(\s*"([^"]*)""#).captures(attrs).map(|c| c[1].to_string());
                if verbs.is_empty() {
                    continue;
                }
                let roles = auth_roles(attrs).or(class_auth.clone()).unwrap_or_default();
                for (v, p) in verbs {
                    let local = mroute.clone().unwrap_or(p);
                    let full = if local.starts_with('/') || local.starts_with('~') {
                        local.trim_start_matches('~').to_string()
                    } else {
                        join(&route, &local)
                    };
                    let full = full.replace("[controller]", &short).replace("[action]", &handler.to_lowercase());
                    push(rows, f, ln.at(off + a[1].len()), &v, &norm_params(&full), name, &handler, roles.clone());
                }
            }
        }
    }
    // minimal APIs
    if t.contains(".Map") {
        let mut prefixes: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut group_auth: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for g in GROUP.captures_iter(&t) {
            let gm = g.get(0).unwrap();
            if in_str(&strs, gm.start()) {
                continue;
            }
            let base = prefixes.get(&g[2]).cloned().unwrap_or_default();
            prefixes.insert(g[1].to_string(), join(&base, &g[3]));
            let end = t[gm.end()..].find(';').map(|x| gm.end() + x).unwrap_or(t.len());
            let tail = &t[gm.end()..end];
            let mut ga = group_auth.get(&g[2]).cloned().unwrap_or_default();
            if tail.contains("AllowAnonymous") {
                ga = vec!["public".into()];
            } else if tail.contains("RequireAuthorization") {
                ga = require_auth(tail);
            }
            if !ga.is_empty() {
                group_auth.insert(g[1].to_string(), ga);
            }
        }
        for m in MIN.captures_iter(&t) {
            let whole = m.get(0).unwrap();
            if in_str(&strs, whole.start()) {
                continue;
            }
            let var = &m[1];
            let verb = m[2].to_uppercase();
            let verb = if verb == "METHODS" { "ANY".to_string() } else { verb };
            let open = whole.end() - 1 - m[3].len() - 1;
            // handler: the argument after the path
            let after = &t[whole.end()..];
            let rest = after.trim_start().trim_start_matches(')');
            let stmt_end = t[whole.start()..].find(';').map(|x| whole.start() + x).unwrap_or(t.len());
            let stmt = &t[whole.start()..stmt_end.min(whole.start() + 600)];
            let handler = if let Some(r) = rest.strip_prefix(',') {
                let r = r.trim_start();
                let id: String = r.chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.').collect();
                if !id.is_empty() && !r[id.len()..].trim_start().starts_with("=>") && !matches!(id.as_str(), "async" | "static" | "delegate" | "new") {
                    id.rsplit('.').next().unwrap_or("").to_string()
                } else {
                    "(inline)".to_string()
                }
            } else {
                "(inline)".to_string()
            };
            // endpoint-level attributes sit inside the call (`[Authorize(Roles = "x")] () => ..`), conventions after it
            let call_head = &stmt[..stmt.find("=>").unwrap_or(stmt.len())];
            let roles = if stmt.contains("AllowAnonymous") {
                vec!["public".to_string()]
            } else if stmt.contains("RequireAuthorization") {
                require_auth(stmt)
            } else {
                auth_roles(call_head).unwrap_or_else(|| group_auth.get(var).cloned().unwrap_or_default())
            };
            let base = prefixes.get(var).cloned().unwrap_or_default();
            let path = if base.is_empty() { m[3].to_string() } else { join(&base, &m[3]) };
            let _ = open;
            push(rows, f, ln.at(whole.start()), &verb, &norm_params(&path), "", &handler, roles);
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Laravel
// ---------------------------------------------------------------------------------------------------

fn laravel(f: &SourceFile, rows: &mut Rows) {
    static ROUTE: LazyLock<Regex> = LazyLock::new(|| {
        rx(r"Route\s*::\s*(get|post|put|patch|delete|options|any|match|resource|apiResource|view|redirect)\s*\(")
    });
    static GROUP: LazyLock<Regex> = LazyLock::new(|| rx(r"Route\s*::(?:\s*group\s*\(|[^;{]*?(?:->\s*group\s*\(|::\s*group\s*\())"));
    let (t, strs) = lex(&f.text, true, false);
    let ln = Lines::new(&t);
    // routes/api.php is mounted under `/api` by the framework's default RouteServiceProvider
    let base_prefix = if f.path.ends_with("routes/api.php") || f.path.ends_with("Routes/api.php") { "/api".to_string() } else { String::new() };
    // `auth` / `auth:sanctum` middleware (any guard) means a logged-in user
    let is_auth = |s: &str| s == "auth" || s.starts_with("auth:") || s.starts_with("auth.") || s == "verified";
    // group scopes: (start, end, prefix, controller, roles)
    struct G {
        start: usize,
        end: usize,
        prefix: String,
        ctl: String,
        roles: Vec<String>,
        auth: bool,
    }
    let mut groups: Vec<G> = vec![];
    for m in GROUP.find_iter(&t).filter(|m| !in_str(&strs, m.start())) {
        let head = m.as_str();
        let open = m.end() - 1;
        let Some(close) = close_of(&t, open) else { continue };
        let prefix = rx(r#"prefix\s*\(\s*['"]([^'"]*)['"]"#).captures(head).map(|c| c[1].to_string())
            .or_else(|| rx(r#"'prefix'\s*=>\s*['"]([^'"]*)['"]"#).captures(&t[open..close.min(open + 300)]).map(|c| c[1].to_string()))
            .unwrap_or_default();
        let ctl = rx(r"controller\s*\(\s*([\w\\]+)::class").captures(head).map(|c| c[1].rsplit('\\').next().unwrap_or("").to_string()).unwrap_or_default();
        let mut roles = vec![];
        let mut auth = false;
        for mw in rx(r#"middleware['"]?\s*(?:\(|=>)\s*(\[[^\]]*\]|['"][^'"]*['"])"#).captures_iter(&format!("{head}{}", &t[open..close.min(open + 200)])) {
            for s in rx(r#"['"]([^'"]+)['"]"#).captures_iter(&mw[1]) {
                let s = &s[1];
                if is_auth(s) {
                    auth = true;
                }
                if let Some(r) = s.strip_prefix("role:").or_else(|| s.strip_prefix("can:")).or_else(|| s.strip_prefix("permission:")) {
                    roles.push(r.to_string());
                }
            }
        }
        groups.push(G { start: m.start(), end: close, prefix, ctl, roles, auth });
    }
    for m in ROUTE.captures_iter(&t).filter(|m| !in_str(&strs, m.get(0).unwrap().start())) {
        let whole = m.get(0).unwrap();
        // a `Route::get(...)` that is itself the head of a group chain is not an endpoint
        let open = whole.end() - 1;
        let Some(close) = close_of(&t, open) else { continue };
        let args = &t[open + 1..close - 1];
        let verb = m[1].to_string();
        let enclosing: Vec<&G> = groups.iter().filter(|g| g.start < whole.start() && whole.start() < g.end).collect();
        let mut prefix = base_prefix.clone();
        let mut ctl = String::new();
        let mut roles: Vec<String> = vec![];
        let mut auth = false;
        for g in &enclosing {
            auth |= g.auth;
            prefix = join(&prefix, &g.prefix);
            if !g.ctl.is_empty() {
                ctl = g.ctl.clone();
            }
            roles.extend(g.roles.clone());
        }
        // chained `->middleware('role:admin')` after the call
        let tail = &t[close..t.len().min(close + 160)];
        let tail = tail.split(';').next().unwrap_or("");
        for s in rx(r#"['"](?:role|can|permission):([^'"]+)['"]"#).captures_iter(tail) {
            roles.push(s[1].to_string());
        }
        for s in rx(r#"['"]([^'"]+)['"]"#).captures_iter(tail) {
            if is_auth(&s[1]) {
                auth = true;
            }
        }
        if roles.is_empty() && auth {
            roles.push("authenticated".into());
        }
        let line = ln.at(whole.start());
        // `Class::class` / 'Class@method' / [Class::class, 'method'] / closure
        let handler_of = |rest: &str| -> (String, String) {
            if let Some(c) = rx(r#"\[\s*([\w\\]+)::class\s*,\s*['"](\w+)['"]"#).captures(rest) {
                return (c[1].rsplit('\\').next().unwrap_or("").to_string(), c[2].to_string());
            }
            if let Some(c) = rx(r#"['"]([\w\\]+)@(\w+)['"]"#).captures(rest) {
                return (c[1].rsplit('\\').next().unwrap_or("").to_string(), c[2].to_string());
            }
            if let Some(c) = rx(r#"^\s*([\w\\]+)::class\s*(?:\)|$)"#).captures(rest) {
                return (c[1].rsplit('\\').next().unwrap_or("").to_string(), "__invoke".to_string());
            }
            if !ctl.is_empty() {
                if let Some(c) = rx(r#"^\s*['"](\w+)['"]"#).captures(rest) {
                    return (ctl.clone(), c[1].to_string());
                }
            }
            (String::new(), "(inline)".to_string())
        };
        match verb.as_str() {
            "resource" | "apiResource" => {
                let Some(name) = first_string(args) else { continue };
                let c = rx(r"([\w\\]+)::class").captures(args).map(|c| c[1].rsplit('\\').next().unwrap_or("").to_string()).unwrap_or_default();
                let base = join(&prefix, &name);
                let single = name.rsplit('/').next().unwrap_or(&name).trim_end_matches('s');
                let mut set: Vec<(&str, String, &str)> = vec![
                    ("GET", base.clone(), "index"),
                    ("POST", base.clone(), "store"),
                    ("GET", format!("{base}/{{{single}}}"), "show"),
                    ("PUT", format!("{base}/{{{single}}}"), "update"),
                    ("DELETE", format!("{base}/{{{single}}}"), "destroy"),
                ];
                if verb == "resource" {
                    set.insert(1, ("GET", format!("{base}/create"), "create"));
                    set.push(("GET", format!("{base}/{{{single}}}/edit"), "edit"));
                }
                let list = |k: &str| -> Option<Vec<String>> {
                    Regex::new(&format!(r"->\s*{k}\s*\(\s*\[([^\]]*)\]")).unwrap().captures(tail).map(|c| rx(r#"['"](\w+)['"]"#).captures_iter(&c[1]).map(|x| x[1].to_string()).collect())
                };
                let (only, except) = (list("only"), list("except"));
                for (mth, p, h) in set {
                    if only.as_ref().is_some_and(|o| !o.iter().any(|x| x == h)) || except.as_ref().is_some_and(|o| o.iter().any(|x| x == h)) {
                        continue;
                    }
                    push(rows, f, line, mth, &p, &c, h, roles.clone());
                }
            }
            _ => {
                let Some(path) = first_string(args) else {
                    // Route::match(['get','post'], '/x', ...)
                    if verb == "match" {
                        let Some(rb) = args.find(']') else { continue };
                        let methods: Vec<String> = rx(r#"['"](\w+)['"]"#).captures_iter(&args[..rb]).map(|c| c[1].to_uppercase()).collect();
                        let rest = &args[rb + 1..].trim_start().trim_start_matches(',').to_string();
                        let Some(p) = first_string(rest) else { continue };
                        let after = rest[rest.find(',').map(|x| x + 1).unwrap_or(rest.len())..].to_string();
                        let (c, h) = handler_of(&after);
                        for mth in methods {
                            push(rows, f, line, &mth, &join(&prefix, &p), &c, &h, roles.clone());
                        }
                    }
                    continue;
                };
                let after = args.find(',').map(|x| &args[x + 1..]).unwrap_or("");
                let (c, h) = handler_of(after);
                let mth = match verb.as_str() {
                    "any" => "ANY".to_string(),
                    "view" | "redirect" => "GET".to_string(),
                    v => v.to_uppercase(),
                };
                push(rows, f, line, &mth, &join(&prefix, &path), &c, &h, roles.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Rails
// ---------------------------------------------------------------------------------------------------

fn rails(f: &SourceFile, rows: &mut Rows) {
    #[derive(Clone)]
    struct Ctx {
        path: String,
        module: String,
        /// resources name (plural), singular, for member / collection / nested paths
        res: Option<(String, bool)>,
        kind: &'static str,
    }
    static VERB: LazyLock<Regex> = LazyLock::new(|| {
        rx(r#"^\s*(get|post|put|patch|delete|match|root)\b\s*\(?\s*(?::(\w+)|['"]([^'"]*)['"])?\s*(.*)$"#)
    });
    static RES: LazyLock<Regex> = LazyLock::new(|| rx(r"^\s*(resources|resource)\s+\(?\s*:(\w+)(.*)$"));
    static NS: LazyLock<Regex> = LazyLock::new(|| rx(r"^\s*(namespace|scope|member|collection|concern|constraints|defaults|devise_scope|authenticate)\b\s*\(?(.*)$"));
    let t = blank_comments(&f.text, true);
    let mut stack: Vec<Ctx> = vec![Ctx { path: String::new(), module: String::new(), res: None, kind: "root" }];
    let controller_of = |to: &str, ctx: &Ctx| -> (String, String) {
        let (c, a) = to.split_once('#').unwrap_or((to, ""));
        let m = ctx.module.clone();
        let cname = format!("{}{}Controller", if m.is_empty() { String::new() } else { camel_path(&m) }, camel(c));
        (cname, a.to_string())
    };
    for (line, stmt) in ruby_statements(&t) {
        let l = stmt.as_str();
        let top = stack.last().cloned().unwrap();
        let opens = l.ends_with(" do") || l.contains(" do |") || l.ends_with("{");
        if l == "end" || l == "}" {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        if let Some(c) = RES.captures(l) {
            let single = &c[1] == "resource";
            let name = c[2].to_string();
            let rest = c[3].to_string();
            let only: Option<Vec<String>> = opt_list(&rest, "only");
            let except: Vec<String> = opt_list(&rest, "except").unwrap_or_default();
            let path_name = rx(r#"path:\s*['"]([^'"]*)['"]"#).captures(&rest).map(|c| c[1].to_string()).unwrap_or(name.clone());
            let ctrl = rx(r#"controller:\s*['"]([^'"]*)['"]"#).captures(&rest).map(|c| c[1].to_string()).unwrap_or(name.clone());
            let base = match &top.res {
                Some((p, false)) if top.kind == "res" => format!("{}/{{{}_id}}/{}", top.path, p.trim_end_matches('s'), path_name),
                _ => format!("{}/{}", top.path, path_name),
            };
            let base = base.replace("//", "/");
            let item = if single { base.clone() } else { format!("{base}/{{id}}") };
            let mut acts: Vec<(&str, String, &str)> = vec![];
            if !single {
                acts.push(("GET", base.clone(), "index"));
            }
            acts.push(("POST", base.clone(), "create"));
            acts.push(("GET", format!("{base}/new"), "new"));
            acts.push(("GET", format!("{item}/edit"), "edit"));
            acts.push(("GET", item.clone(), "show"));
            acts.push(("PATCH", item.clone(), "update"));
            acts.push(("PUT", item.clone(), "update"));
            acts.push(("DELETE", item.clone(), "destroy"));
            // `resource :profile` (singular) still routes to the plural `ProfilesController`
            let ctrl = if single && !rest.contains("controller:") { plural(&ctrl) } else { ctrl };
            let (c_name, _) = controller_of(&format!("{ctrl}#"), &top);
            for (m, p, a) in acts {
                if only.as_ref().is_some_and(|o| !o.iter().any(|x| x == a)) || except.iter().any(|x| x == a) {
                    continue;
                }
                push(rows, f, line, m, &p, &c_name, a, vec![]);
            }
            if opens {
                stack.push(Ctx { path: base, module: top.module.clone(), res: Some((name, single)), kind: "res" });
            }
            continue;
        }
        if let Some(c) = NS.captures(l) {
            let kind = c[1].to_string();
            let rest = c[2].to_string();
            if opens || kind == "member" || kind == "collection" {
                let mut ctx = Ctx { ..top.clone() };
                match kind.as_str() {
                    "namespace" => {
                        if let Some(n) = rx(r#":(\w+)|['"]([^'"]+)['"]"#).captures(&rest) {
                            let n = n.get(1).or_else(|| n.get(2)).unwrap().as_str().to_string();
                            ctx.path = format!("{}/{}", top.path, n);
                            ctx.module = if top.module.is_empty() { n } else { format!("{}/{}", top.module, n) };
                        }
                    }
                    "scope" => {
                        if let Some(p) = rx(r#"(?:path:\s*)?['"]([^'"]+)['"]|path:\s*:(\w+)|^:(\w+)"#).captures(&rest) {
                            let p = p.get(1).or_else(|| p.get(2)).or_else(|| p.get(3)).unwrap().as_str();
                            ctx.path = format!("{}/{}", top.path, p.trim_matches('/'));
                        }
                        if let Some(m) = rx(r#"module:\s*['":]+(\w+)"#).captures(&rest) {
                            ctx.module = if top.module.is_empty() { m[1].to_string() } else { format!("{}/{}", top.module, &m[1]) };
                        }
                    }
                    "member" => {
                        if let Some((p, _)) = &top.res {
                            ctx.path = format!("{}/{{id}}", top.path);
                            let _ = p;
                        }
                        ctx.kind = "member";
                    }
                    "collection" => ctx.kind = "collection",
                    _ => {}
                }
                // a collection keeps the resources base path; a member got `/{id}` above
                ctx.res = top.res.clone();
                if opens {
                    stack.push(ctx);
                }
            }
            continue;
        }
        if let Some(c) = VERB.captures(l) {
            let verb = c[1].to_string();
            let sym = c.get(2).map(|x| x.as_str().to_string());
            let lit = c.get(3).map(|x| x.as_str().to_string());
            let rest = c[4].to_string();
            let to = rx(r#"(?:to:\s*|=>\s*)['"]([\w/]+#\w+)['"]"#).captures(&format!("{} {}", lit.clone().unwrap_or_default(), rest)).map(|c| c[1].to_string())
                .or_else(|| rx(r#"^\s*,?\s*['"]([\w/]+#\w+)['"]"#).captures(&rest).map(|c| c[1].to_string()));
            if verb == "root" {
                let target = lit.clone().filter(|x| x.contains('#')).or(to.clone()).or_else(|| rx(r#"to:\s*['"]([\w/]+#\w+)['"]"#).captures(&rest).map(|c| c[1].to_string()));
                if let Some(tg) = target {
                    let (cn, a) = controller_of(&tg, &top);
                    push(rows, f, line, "GET", &if top.path.is_empty() { "/".into() } else { top.path.clone() }, &cn, &a, vec![]);
                }
                continue;
            }
            let path_part = lit.clone().filter(|x| !x.contains('#') || x.starts_with('/')).or(sym.clone());
            let action = rx(r#"\baction:\s*(?::(\w+)|['"](\w+)['"])"#).captures(&rest).map(|c| c.get(1).or_else(|| c.get(2)).unwrap().as_str().to_string());
            let Some(pp) = path_part else { continue };
            let (cn, a) = match &to {
                Some(tg) => controller_of(tg, &top),
                None => match &top.res {
                    Some((r, single)) if matches!(top.kind, "member" | "collection" | "res") => {
                        let r = if *single { plural(r) } else { r.clone() };
                        (controller_of(&format!("{r}#"), &top).0, action.clone().or(sym.clone()).unwrap_or(pp.clone()))
                    }
                    _ => (String::new(), "(inline)".to_string()),
                },
            };
            // `get :x, on: :member` inside `resources :posts` is `/posts/{id}/x`; `on: :collection` stays `/posts/x`
            let on_member = rx(r"\bon:\s*:member\b").is_match(&rest) && top.res.is_some() && top.kind != "member";
            let base = if on_member { format!("{}/{{id}}", top.path) } else { top.path.clone() };
            // a leading `/` is still under the enclosing namespace / scope (`namespace :api do get '/x'` is `/api/x`)
            let path = format!("{}/{}", base, pp.trim_start_matches('/'));
            let verbs: Vec<String> = if verb == "match" {
                rx(r"via:\s*\[([^\]]*)\]|via:\s*:(\w+)").captures(&rest).map(|o| rx(r"\w+").find_iter(o.get(1).or_else(|| o.get(2)).unwrap().as_str()).map(|m| m.as_str().to_uppercase()).collect()).unwrap_or_else(|| vec!["ANY".into()])
            } else {
                vec![verb.to_uppercase()]
            };
            for v in verbs {
                push(rows, f, line, &v, &path.replace("//", "/"), &cn, &a, vec![]);
            }
            if opens {
                stack.push(Ctx { ..top.clone() });
            }
            continue;
        }
        if opens {
            stack.push(Ctx { ..top.clone() });
        }
    }
}

/// The route file as statements: a call whose arguments continue on later lines (an open bracket, a trailing comma
/// or backslash) is one statement, numbered by its first line.
fn ruby_statements(t: &str) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = vec![];
    let mut cur = String::new();
    let mut start = 0u32;
    let mut depth = 0i32;
    for (i, raw) in t.lines().enumerate() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if cur.is_empty() {
            start = i as u32 + 1;
        } else {
            cur.push(' ');
        }
        cur.push_str(l);
        let mut q: Option<char> = None;
        let mut esc = false;
        for ch in l.chars() {
            if let Some(c) = q {
                if esc {
                    esc = false;
                } else if ch == '\\' {
                    esc = true;
                } else if ch == c {
                    q = None;
                }
                continue;
            }
            match ch {
                '\'' | '"' => q = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        let cont = depth > 0 || l.ends_with(',') || l.ends_with('\\');
        if !cont {
            depth = 0;
            out.push((start, std::mem::take(&mut cur)));
        }
    }
    if !cur.is_empty() {
        out.push((start, cur));
    }
    out
}

/// `only: [:a, :b]`, `only: %i[a b]`, `only: :a`, `only: 'a'`.
fn opt_list(rest: &str, key: &str) -> Option<Vec<String>> {
    let re = Regex::new(&format!(r#"\b{key}:\s*(?:%[iIwW]\[([^\]]*)\]|\[([^\]]*)\]|:(\w+)|['"](\w+)['"])"#)).ok()?;
    let c = re.captures(rest)?;
    let body = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)).or_else(|| c.get(4))?.as_str();
    Some(rx(r"\w+").find_iter(body).map(|m| m.as_str().to_string()).collect())
}

/// Rails' controller name for a singular resource: `profile` -> `profiles`, `category` -> `categories`.
fn plural(s: &str) -> String {
    let vowel_y = s.len() >= 2 && matches!(s.as_bytes()[s.len() - 2], b'a' | b'e' | b'i' | b'o' | b'u');
    if s.ends_with('y') && !vowel_y {
        format!("{}ies", &s[..s.len() - 1])
    } else if s.ends_with('s') || s.ends_with('x') || s.ends_with("ch") || s.ends_with("sh") {
        format!("{s}es")
    } else {
        format!("{s}s")
    }
}

/// `Pages/Orders/Index.cshtml.cs` -> `/Orders`, `Pages/Account/Login.cshtml.cs` -> `/Account/Login`.
fn razor_page_path(path: &str) -> Option<String> {
    let rest = &path[path.find("Pages/")? + "Pages/".len()..];
    let rest = rest.strip_suffix(".cshtml.cs")?;
    let rest = rest.strip_suffix("/Index").or_else(|| (rest == "Index").then_some("")).unwrap_or(rest);
    Some(format!("/{rest}"))
}

fn camel(s: &str) -> String {
    s.split(['_', '/']).map(|p| {
        let mut c = p.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    }).collect()
}

fn camel_path(m: &str) -> String {
    m.split('/').map(camel).collect::<Vec<_>>().join("::") + "::"
}

// ---------------------------------------------------------------------------------------------------
// Kotlin: Ktor and Spring
// ---------------------------------------------------------------------------------------------------

fn kotlin_web(f: &SourceFile, rows: &mut Rows) {
    let (t, strs) = lex(&f.text, false, false);
    let ln = Lines::new(&t);
    if t.contains("io.ktor") {
        ktor(f, &t, &strs, &ln, rows);
    }
    if t.contains("org.springframework") && (t.contains("Mapping") ) {
        spring_kotlin(f, &t, &strs, &ln, rows);
    }
}

fn ktor(f: &SourceFile, t: &str, strs: &Strs, ln: &Lines, rows: &mut Rows) {
    // the routing DSL: `routing { }`, `install(Routing) { }` and the bodies of `fun Route.x() { }` extension functions;
    // `client.get(..)` and friends elsewhere are HTTP client calls
    static DSL: LazyLock<Regex> = LazyLock::new(|| {
        rx(r"\brouting\s*(?:\([^)]*\))?\s*\{|\binstall\s*\(\s*Routing\s*\)\s*\{|\bfun\s+(?:<[^>]*>\s*)?(?:\w+\.)*(?:Route|Routing|RoutingBuilder)\.\w+\s*\([^)]*\)\s*(?::\s*[\w<>?.]+\s*)?\{")
    });
    let mut dsl: Vec<(usize, usize)> = vec![];
    for m in DSL.find_iter(t) {
        if in_str(strs, m.start()) {
            continue;
        }
        if let Some(close) = close_of(t, m.end() - 1) {
            dsl.push((m.end() - 1, close));
        }
    }
    let in_dsl = |at: usize| dsl.iter().any(|(a, b)| *a < at && at < *b);
    static CALL: LazyLock<Regex> = LazyLock::new(|| rx(r#"\b(get|post|put|delete|patch|head|options|route|authenticate|webSocket)\s*(?:<[^>]*>)?\s*\(\s*(?:"([^"]*)")?([^)]*)\)\s*\{|\b(get|post|put|delete|patch|head|options)\s*\{"#));
    // scopes: (open brace offset, end, prefix, roles)
    let mut scopes: Vec<(usize, usize, String, Vec<String>)> = vec![];
    let mut eps: Vec<(usize, String, String)> = vec![];
    for c in CALL.captures_iter(t) {
        let whole = c.get(0).unwrap();
        if in_str(strs, whole.start()) || !in_dsl(whole.start()) {
            continue;
        }
        // `client.get("/x") { }`: a call on a receiver is a client call (the DSL's own `this.get` / `route.get` stay)
        let before = t[..whole.start()].trim_end();
        if let Some(r) = before.strip_suffix('.') {
            let recv: String = r.chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>().chars().rev().collect();
            if !matches!(recv.as_str(), "this" | "route" | "routing" | "it") {
                continue;
            }
        }
        let open = whole.end() - 1;
        let Some(close) = close_of(t, open) else { continue };
        let name = c.get(1).or_else(|| c.get(4)).unwrap().as_str();
        let path = c.get(2).map(|x| x.as_str().to_string()).unwrap_or_default();
        match name {
            "route" => {
                let extra = c.get(3).map(|x| x.as_str()).unwrap_or("");
                if let Some(m) = rx(r"HttpMethod\.(\w+)").captures(extra) {
                    eps.push((whole.start(), m[1].to_uppercase(), path));
                } else {
                    scopes.push((open, close, path, vec![]));
                }
            }
            "authenticate" => {
                let n = rx(r#"^\s*"([^"]*)""#).captures(&t[whole.start() + "authenticate".len()..whole.end()].replacen('(', "", 1)).map(|c| c[1].to_string());
                scopes.push((open, close, String::new(), vec![format!("auth:{}", n.unwrap_or_default())]));
            }
            "webSocket" => {}
            v => eps.push((whole.start(), v.to_uppercase(), path)),
        }
    }
    for (at, method, path) in eps {
        let mut prefix = String::new();
        let mut roles = vec![];
        for (o, e, p, r) in &scopes {
            if *o < at && at < *e {
                if !p.is_empty() {
                    prefix = join(&prefix, p);
                }
                roles.extend(r.clone());
            }
        }
        let full = if prefix.is_empty() && path.is_empty() { "/".to_string() } else { join(&prefix, &path) };
        push(rows, f, ln.at(at), &method, &norm_params(&full), "", "(inline)", roles);
    }
}

fn spring_kotlin(f: &SourceFile, t: &str, strs: &Strs, ln: &Lines, rows: &mut Rows) {
    static MAP: LazyLock<Regex> = LazyLock::new(|| {
        rx(r"(?m)^[ \t]*@(Get|Post|Put|Delete|Patch|Request)Mapping\b(\([^\n]*\))?[ \t]*\n?((?:[ \t]*@[^\n]*\n)*)[ \t]*(?:(?:public|private|protected|internal|override|suspend|open)\s+)*fun\s+(?:<[^>]*>\s*)?(\w+)")
    });
    static CLS: LazyLock<Regex> = LazyLock::new(|| rx(r"(?m)^[ \t]*@RequestMapping\b(\([^\n]*\))?[ \t]*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:\w+\s+)*class\s+(\w+)"));
    let path_of = |args: &str| -> String {
        rx(r#"(?:value\s*=\s*|path\s*=\s*)?\[?\s*"([^"]*)""#).captures(args).map(|c| c[1].to_string()).unwrap_or_default()
    };
    let classes: Vec<(usize, String, String)> = {
        let mut v: Vec<(usize, String, String)> = CLS.captures_iter(t).map(|c| (c.get(0).unwrap().start(), c[2].to_string(), path_of(c.get(1).map(|x| x.as_str()).unwrap_or("")))).collect();
        // class-level @RequestMapping that sits directly above a class with other annotations in between is covered by the regex; plain classes get "" below
        v.sort_by_key(|x| x.0);
        v
    };
    let all_classes: Vec<(usize, String)> = rx(r"(?m)^[ \t]*(?:(?:open|data|abstract|internal|public)\s+)*class\s+(\w+)").captures_iter(t).map(|c| (c.get(0).unwrap().start(), c[1].to_string())).collect();
    for m in MAP.captures_iter(t) {
        let at = m.get(0).unwrap().start();
        if in_str(strs, at) {
            continue;
        }
        let kind = &m[1];
        let args = m.get(2).map(|x| x.as_str()).unwrap_or("");
        let method = match kind {
            "Request" => rx(r"RequestMethod\.(\w+)").captures(args).map(|c| c[1].to_uppercase()).unwrap_or_else(|| "ANY".into()),
            k => k.to_uppercase(),
        };
        let class = all_classes.iter().rfind(|c| c.0 < at).map(|c| c.1.clone()).unwrap_or_default();
        let base = classes.iter().find(|c| c.1 == class).map(|c| c.2.clone()).unwrap_or_default();
        let roles = {
            let ctx = &t[at.saturating_sub(300)..at];
            let own = &m[0];
            let src = format!("{ctx}{own}");
            rx(r#"@(?:PreAuthorize|Secured|RolesAllowed)\(\s*(?:value\s*=\s*)?[\[\{]?\s*"([^"]*)""#).captures_iter(&src).last().map(|c| {
                rx(r"ROLE_(\w+)|hasRole\('(\w+)'\)|hasAnyRole\(([^)]*)\)|^(\w+)$").captures_iter(&c[1]).flat_map(|r| {
                    if let Some(x) = r.get(3) { rx(r"'(\w+)'").captures_iter(x.as_str()).map(|q| q[1].to_string()).collect::<Vec<_>>() } else { vec![r.get(1).or_else(|| r.get(2)).or_else(|| r.get(4)).map(|x| x.as_str().to_string()).unwrap_or_default()] }
                }).filter(|s| !s.is_empty()).collect::<Vec<_>>()
            }).unwrap_or_default()
        };
        let own_path = path_of(args);
        let full = join(&base, &own_path);
        push(rows, f, ln.at(at), &method, &norm_params(&full), &class, &m[4], roles);
    }
}

// ---------------------------------------------------------------------------------------------------
// Rust: Actix web, Axum, Rocket
// ---------------------------------------------------------------------------------------------------

fn rust_web(f: &SourceFile, rows: &mut Rows) {
    if !(f.text.contains("actix") || f.text.contains("axum") || f.text.contains("rocket") || f.text.contains("poem") || f.text.contains("warp")) {
        return;
    }
    static ATTR: LazyLock<Regex> = LazyLock::new(|| {
        rx(r#"(?m)#\[\s*(?:\w+::)*(get|post|put|delete|patch|head|options|route)\s*\(\s*"([^"]*)"([^\]]*)\]\s*(?:#\[[^\n]*?\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)"#)
    });
    static ROUTE: LazyLock<Regex> = LazyLock::new(|| rx(r#"\.route\s*\(\s*"([^"]*)"\s*,"#));
    static MOUNT: LazyLock<Regex> = LazyLock::new(|| rx(r#"\.mount\s*\(\s*"([^"]*)"\s*,\s*routes!\s*\[([^\]]*)\]"#));
    static SCOPE: LazyLock<Regex> = LazyLock::new(|| rx(r#"web::scope\s*\(\s*"([^"]*)"\s*\)"#));
    static NEST: LazyLock<Regex> = LazyLock::new(|| rx(r#"\.nest\s*\(\s*"([^"]*)"\s*,"#));
    let (t, strs) = lex(&f.text, false, true);
    let ln = Lines::new(&t);
    // prefixes per handler name: rocket mount / actix scope .service(name)
    let mut prefix_of: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for m in MOUNT.captures_iter(&t).filter(|m| !in_str(&strs, m.get(0).unwrap().start())) {
        for h in m[2].split(',') {
            prefix_of.insert(h.trim().rsplit("::").next().unwrap_or("").to_string(), m[1].to_string());
        }
    }
    // scopes: (open paren end offset, close, prefix)
    let mut scopes: Vec<(usize, usize, String)> = vec![];
    for m in SCOPE.captures_iter(&t).filter(|m| !in_str(&strs, m.get(0).unwrap().start())) {
        let at = m.get(0).unwrap().end();
        // the chain continues until the statement ends: find the matching end by balancing brackets from the scope start
        let rest = &t[at..];
        let mut depth = 0i32;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        end = i;
                        break;
                    }
                }
                ';' if depth == 0 => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        scopes.push((at, at + end, m[1].to_string()));
    }
    for m in NEST.captures_iter(&t).filter(|m| !in_str(&strs, m.get(0).unwrap().start())) {
        let open = m.get(0).unwrap().start() + m.get(0).unwrap().as_str().find('(').unwrap_or(0);
        if let Some(close) = close_of(&t, open) {
            scopes.push((open, close, m[1].to_string()));
        }
    }
    let scope_prefix = |at: usize| -> String {
        let mut inside: Vec<&(usize, usize, String)> = scopes.iter().filter(|s| s.0 <= at && at < s.1).collect();
        inside.sort_by_key(|s| s.0);
        inside.iter().fold(String::new(), |acc, s| join(&acc, &s.2))
    };
    for m in ATTR.captures_iter(&t) {
        let whole = m.get(0).unwrap();
        if in_str(&strs, whole.start()) {
            continue;
        }
        let verb = m[1].to_uppercase();
        let handler = m[4].to_string();
        let methods: Vec<String> = if verb == "ROUTE" {
            let v: Vec<String> = rx(r#"method\s*=\s*"(\w+)""#).captures_iter(&m[3]).map(|c| c[1].to_uppercase()).collect();
            if v.is_empty() { vec!["ANY".into()] } else { v }
        } else {
            vec![verb]
        };
        let path = rocket_path(&m[2]);
        let pre = prefix_of.get(&handler).cloned().unwrap_or_default();
        let full = if pre.is_empty() { path } else { join(&pre, &path) };
        for method in methods {
            push(rows, f, ln.at(whole.start()), &method, &full, "", &handler, vec![]);
        }
    }
    // .service(handler) inside web::scope("/p"): re-prefix the attribute routes of this file
    for (s, e, p) in scopes.clone() {
        let region = &t[s..e.min(t.len())];
        for sv in rx(r"\.service\s*\(\s*(?:\w+::)*(\w+)\s*\)").captures_iter(region) {
            let h = sv[1].to_string();
            for ep in rows.endpoints.iter_mut().filter(|x| x.file == f.path && x.handler == h && !x.path.starts_with(&p) && x.line > 0) {
                let np = join(&p, &ep.path);
                ep.norm_path = norm_path(&np);
                ep.path = np;
            }
        }
    }
    // .route("/x", get(h).post(h2))  /  .route("/x", web::get().to(h))
    // actix `web::resource("/p").route(web::post().to(h)).to(h2)`
    static RESOURCE: LazyLock<Regex> = LazyLock::new(|| rx(r#"web::resource\s*\(\s*"([^"]*)"\s*\)"#));
    for m in RESOURCE.captures_iter(&t).filter(|m| !in_str(&strs, m.get(0).unwrap().start())) {
        let whole = m.get(0).unwrap();
        let rest = &t[whole.end()..];
        let (mut depth, mut end) = (0i32, rest.len());
        for (i, c) in rest.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        end = i;
                        break;
                    }
                }
                ';' if depth == 0 => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        let chain = &rest[..end];
        let pre = scope_prefix(whole.start());
        let path = if pre.is_empty() { m[1].to_string() } else { join(&pre, &m[1]) };
        let line = ln.at(whole.start());
        let mut found = false;
        for c in rx(r"\bweb::(get|post|put|delete|patch|head|options)\s*\(\s*\)\s*\.to\s*\(\s*((?:\w+::)*\w+)").captures_iter(chain) {
            push(rows, f, line, &c[1].to_uppercase(), &path, "", c[2].rsplit("::").next().unwrap_or(""), vec![]);
            found = true;
        }
        if !found {
            if let Some(c) = rx(r"\.to\s*\(\s*((?:\w+::)*\w+)").captures(chain) {
                push(rows, f, line, "ANY", &path, "", c[1].rsplit("::").next().unwrap_or(""), vec![]);
            }
        }
    }
    for m in ROUTE.captures_iter(&t) {
        let whole = m.get(0).unwrap();
        if in_str(&strs, whole.start()) {
            continue;
        }
        let open = whole.start() + whole.as_str().find('(').unwrap_or(0);
        let Some(close) = close_of(&t, open) else { continue };
        let args = &t[whole.end()..close - 1];
        let pre = scope_prefix(whole.start());
        let path = if pre.is_empty() { m[1].to_string() } else { join(&pre, &m[1]) };
        let line = ln.at(whole.start());
        let mut found = false;
        // axum: get(h).post(h2)    actix: web::get().to(h)
        for c in rx(r"(?:web::|routing::|\.)?\b(get|post|put|delete|patch|head|options|any)\s*\(\s*((?:\w+::)*\w+)?\s*\)(?:\s*\.to\s*\(\s*((?:\w+::)*\w+)\s*\))?").captures_iter(args) {
            let h = c.get(3).or_else(|| c.get(2)).map(|x| x.as_str().rsplit("::").next().unwrap_or("").to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "(inline)".into());
            push(rows, f, line, &c[1].to_uppercase(), &path, "", &h, vec![]);
            found = true;
        }
        if !found && VERBS.iter().any(|v| args.contains(v)) {
            push(rows, f, line, "ANY", &path, "", "(inline)", vec![]);
        }
    }
}

/// Rocket `<id>` / `<rest..>` -> `{id}`.
fn rocket_path(p: &str) -> String {
    static R: LazyLock<Regex> = LazyLock::new(|| rx(r"<(\w+)(?:\.\.)?>"));
    R.replace_all(p, "{$1}").into_owned()
}
