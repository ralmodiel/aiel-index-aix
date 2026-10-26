//! Web-framework endpoint and frontend-route extractors (Spring MVC, Express, Next.js, FastAPI, Flask, Django,
//! Go net/http + chi/gin/echo, React Router objects, Vue Router, MarkLogic REST extensions and rewriters).
//!
//! Endpoints whose full path depends on how routers are mounted in other files (Express `app.use('/p', router)`,
//! FastAPI `include_router(prefix=)`, Django `include()`, chi `Mount`, Flask `register_blueprint`) are emitted with
//! their router-local path plus two bookkeeping notes (kinds `ep:local` and `ep:mount`, never searched); the core's
//! `compose` pass joins them after all files are known. Everything else is emitted final.

use crate::model::*;
use crate::Extractor;

pub mod express;
pub mod frontend;
pub mod gohttp;
pub mod langweb;
pub mod marklogic;
pub mod next;
pub mod pyweb;
pub mod spring;

pub const HTTP_LOWER: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// Join path pieces with single slashes, a leading slash, no trailing slash.
pub fn join(a: &str, b: &str) -> String {
    let mut s = format!("/{}/{}", a.trim_matches('/'), b.trim_matches('/'));
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    if s.len() > 1 {
        s = s.trim_end_matches('/').to_string();
    }
    s
}

/// `<int:id>` / `<id>` / `[id]` / `[...slug]` / `[[...slug]]` to `{id}`; `:id` and `{id}` stay.
pub fn param_syntax(p: &str) -> String {
    p.split('/')
        .map(|seg| {
            let s = seg.trim();
            let inner = if s.starts_with('<') && s.ends_with('>') {
                Some(s[1..s.len() - 1].rsplit(':').next().unwrap_or(""))
            } else if s.starts_with('[') && s.ends_with(']') {
                Some(s.trim_matches(['[', ']']).trim_start_matches("..."))
            } else {
                None
            };
            match inner {
                Some(n) => format!("{{{n}}}"),
                None => s.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Escape-free JSON for a bookkeeping note.
fn js(v: serde_json::Value) -> String {
    v.to_string()
}

/// Everything that identifies one endpoint to push.
pub struct Ep<'a> {
    pub file: &'a str,
    pub line: u32,
    pub method: &'a str,
    pub path: &'a str,
    pub class: &'a str,
    pub handler: &'a str,
    pub roles: Vec<String>,
}

/// Push a final endpoint (no cross-file composition).
pub fn push_ep(rows: &mut Rows, e: Ep) {
    let path = if e.path.starts_with('/') { e.path.to_string() } else { join("", e.path) };
    rows.endpoints.push(Endpoint {
        file: e.file.to_string(),
        line: e.line,
        method: e.method.to_ascii_uppercase(),
        norm_path: norm_path(&path),
        path,
        class: e.class.to_string(),
        handler: e.handler.to_string(),
        roles: e.roles,
    });
}

/// Push an endpoint whose path is local to router `scope`; the compose pass prepends the mount prefixes.
pub fn push_scoped(rows: &mut Rows, scope: &str, e: Ep) {
    push_scoped_ex(rows, scope, e, false)
}

/// Like [`push_scoped`]; `sub` marks a scope that is a mounted sub-router (not the app root). An endpoint whose
/// roles are the default marker `["public"]` is only kept public when the compose pass can see its whole mount chain.
pub fn push_scoped_ex(rows: &mut Rows, scope: &str, e: Ep, sub: bool) {
    let local = e.path.to_string();
    let base_roles = e.roles.clone();
    let (file, line, method, handler) =
        (e.file.to_string(), e.line, e.method.to_ascii_uppercase(), e.handler.to_string());
    push_ep(rows, e);
    rows.notes.push(Note {
        file,
        line,
        kind: "ep:local".into(),
        reference: js(serde_json::json!({"s": scope, "l": local, "m": method, "h": handler, "sub": sub, "r": base_roles})),
        text: String::new(),
    });
}

/// Router `child` (a variable in this file, or imported via `src`) is mounted under `prefix` of router `parent`.
/// `lang`: ts | py | go | dj. `name` is the attribute/variable looked up in the child module.
#[allow(clippy::too_many_arguments)]
pub fn push_mount(
    rows: &mut Rows,
    file: &str,
    line: u32,
    lang: &str,
    parent: &str,
    prefix: &str,
    child: &str,
    src: &str,
) {
    push_mount_ex(rows, file, line, lang, parent, prefix, child, src, &[], false)
}

/// Like [`push_mount`]; `roles` are auth hints applied by the mount (`g.Use(AuthMiddleware)`, `include_router(dependencies=)`),
/// `mw` says the mount passes through middleware we could not classify (so a default "public" cannot be claimed).
#[allow(clippy::too_many_arguments)]
pub fn push_mount_ex(
    rows: &mut Rows,
    file: &str,
    line: u32,
    lang: &str,
    parent: &str,
    prefix: &str,
    child: &str,
    src: &str,
    roles: &[String],
    mw: bool,
) {
    rows.notes.push(Note {
        file: file.to_string(),
        line,
        kind: "ep:mount".into(),
        reference: js(serde_json::json!({"p": parent, "pre": prefix, "c": child, "src": src, "lang": lang, "roles": roles, "mw": mw})),
        text: String::new(),
    });
}

/// A class-based view (Django): which HTTP methods it serves.
pub fn push_view(rows: &mut Rows, file: &str, line: u32, class: &str, methods: &[String]) {
    rows.notes.push(Note {
        file: file.to_string(),
        line,
        kind: "ep:view".into(),
        reference: js(serde_json::json!({"c": class, "m": methods})),
        text: String::new(),
    });
}

macro_rules! ext_impl {
    ($ty:ident, $name:expr, $handles:expr, $f:path) => {
        pub struct $ty;
        impl crate::Extractor for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn detect(&self, _repo: &std::path::Path) -> bool {
                true
            }
            fn handles(&self, path: &str) -> bool {
                let h: fn(&str) -> bool = $handles;
                h(path)
            }
            fn extract(&self, _repo: &std::path::Path, files: &[crate::model::SourceFile]) -> crate::model::Rows {
                let mut rows = crate::model::Rows::default();
                for f in files {
                    $f(f, &mut rows);
                }
                rows
            }
        }
    };
}
pub(crate) use ext_impl;

pub fn all() -> Vec<Box<dyn Extractor>> {
    vec![
        Box::new(spring::Spring),
        Box::new(express::Express),
        Box::new(next::NextRoutes),
        Box::new(pyweb::PyWeb),
        Box::new(gohttp::GoHttp),
        Box::new(langweb::AspNet),
        Box::new(langweb::Laravel),
        Box::new(langweb::Rails),
        Box::new(langweb::KotlinWeb),
        Box::new(langweb::RustWeb),
        Box::new(marklogic::MarkLogic),
        Box::new(frontend::FrontendRoutes),
    ]
}

/// Calls inside an inline route handler belong to that handler's member, not to the file level or an outer function.
pub fn attach_inline_handlers(rows: &mut Rows) {
    let hs: Vec<(u32, u32, String)> = rows
        .members
        .iter()
        .filter(|m| m.annos.iter().any(|a| a == "route-handler"))
        .map(|m| (m.line, m.end_line, m.qname.clone()))
        .collect();
    if hs.is_empty() {
        return;
    }
    // locals declared inside a handler body (`const tags = await ...`) can show up as file-level const members
    let locals: std::collections::HashSet<u32> =
        rows.members.iter().filter(|m| matches!(m.kind.as_str(), "const" | "field")).map(|m| m.line).collect();
    for r in rows.refs.iter_mut() {
        let inner_local = |l: u32| r.caller_line >= l && locals.contains(&r.caller_line);
        if let Some((l, _, q)) = hs
            .iter()
            .filter(|(l, e, _)| *l <= r.line && r.line <= *e && (r.caller_line < *l || inner_local(*l)))
            .min_by_key(|(l, e, _)| e - l)
        {
            r.caller_line = *l;
            r.caller = q.clone();
        }
    }
}
