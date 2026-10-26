//! aix-extract: deterministic fact extractors.
//!
//! An [`Extractor`] says whether it applies to a repo (`detect`), which files it wants (`handles`), and
//! turns a batch of changed files into [`Rows`]. Every row carries its source file so the engine can
//! replace one file's facts when that file changes.

pub mod codegraph;
pub mod datamodel;
pub mod features;
pub mod frameworks;
pub mod git;
pub mod java;
pub mod lang;
pub mod logparse;
pub mod markdown;
pub mod model;
pub mod pybash;
pub mod router;
pub mod sqlparse;
pub mod scripts;
pub mod specs;
pub mod masks;
pub mod redact;
pub mod text;
pub mod ts_util;
pub mod typescript;
pub mod warm;

use std::path::Path;

pub use model::*;

/// The user's home: `$HOME`, else `%USERPROFILE%` on Windows (only Git Bash sets HOME there, so aix started from
/// PowerShell, cmd or as Claude Code's MCP server would otherwise have no home, and no global masks or config).
pub fn home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").or_else(|| if cfg!(windows) { std::env::var_os("USERPROFILE") } else { None }).map(std::path::PathBuf::from)
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Windows PowerShell starts text it pipes into a program with a UTF-8 byte-order mark: drop it from what was read
/// on stdin (Windows only; elsewhere a BOM on stdin is the data's own).
pub fn strip_stdin_bom(s: &mut String) {
    if cfg!(windows) && s.starts_with('\u{feff}') {
        s.drain(..3);
    }
}

/// `strip_stdin_bom` for bytes read from stdin.
pub fn strip_stdin_bom_bytes(b: &mut Vec<u8>) {
    if cfg!(windows) && b.starts_with(BOM) {
        b.drain(..3);
    }
}

/// `strip_stdin_bom` for a reader over stdin, before its first read.
pub fn skip_stdin_bom<R: std::io::BufRead>(r: &mut R) {
    if cfg!(windows) && r.fill_buf().is_ok_and(|b| b.starts_with(BOM)) {
        r.consume(3);
    }
}

/// Bump when extraction output changes: the engine re-extracts everything once when it sees a new value.
pub const REVISION: u32 = 29; // 29: a UTF-8 BOM is not part of line 1 (Visual Studio and Windows PowerShell write one: `^using` missed line 1, stored line text began with U+FEFF). 28: extractors read a CRLF file as LF (ASP.NET, Kotlin and Rust routes were missing from CRLF files, as in every Git for Windows checkout). 27: Node backend files (Express/Fastify/serverless under server/api/routes ... folders) are kind backend, not frontend, so stored file kinds are recomputed; Latin-1 sources decoded as Latin-1 (caf\xe9_total was cut to _total), data access for ActiveRecord / Eloquent / EF Core / SQLModel / Go (SQL strings, GORM) and Rails db/schema.rb, Kotlin/C#/PHP super/base/parent calls, Rust fn names handed to user macros, Java lambda params typed as collection elements, Ruby belongs_to/has_one readers typed; 26: Rails routes parsed as statements (continuation lines, %i[], singular resources -> plural controllers, action:), calls never bind across languages, Laravel handlers matched by class; redaction keeps aix command spans, counts after credential-named keys, string-method and regex-constructor arguments, generic types and credential-word identifiers readable (stored text changes). 25: source files are never secret by name (api_key.rb indexed), .htpasswd / wp-config.php / .docker/config.json are; materialized patterns select on the file text (stored redacted)

pub trait Extractor: Send + Sync {
    /// Short stable name (shown in `stats`).
    fn name(&self) -> &'static str;
    /// Does this extractor apply to the repo at all?
    fn detect(&self, repo: &Path) -> bool;
    /// Cheap path filter: does it want this file?
    fn handles(&self, path: &str) -> bool;
    /// Extract rows from the given (changed) files.
    fn extract(&self, repo: &Path, changed: &[SourceFile]) -> Rows;
}

/// Every built-in extractor: generic ones first, then stack-specific ones.
pub fn all() -> Vec<Box<dyn Extractor>> {
    let mut v: Vec<Box<dyn Extractor>> = vec![
        Box::new(typescript::TypeScript),
        Box::new(java::Java),
        Box::new(pybash::Python),
        Box::new(pybash::Bash),
        Box::new(codegraph::CodeGraph),
        Box::new(lang::templates::Templates),
        Box::new(datamodel::DataModel),
        Box::new(markdown::Markdown),
        Box::new(scripts::Scripts),
        Box::new(specs::Sql),
        // stack extractors
        Box::new(router::ReactRouter),
        Box::new(specs::E2eSpecs),
        Box::new(specs::FindingsJson),
        Box::new(features::FeatureSources),
    ];
    v.extend(frameworks::all());
    v
}

/// The extractors whose `detect` passes for this repo.
pub fn detected(repo: &Path) -> Vec<Box<dyn Extractor>> {
    all().into_iter().filter(|e| e.detect(repo)).collect()
}

/// Stack for the per-file extraction thread: the walkers recurse over the syntax tree, and the main/rayon stacks
/// (2-8 MB) are too small for deeply nested but legal source. Reserved lazily by the OS, so it costs nothing unused.
const EXTRACT_STACK: usize = 256 * 1024 * 1024;

fn note(f: &SourceFile, why: &str) -> Note {
    Note { file: f.path.clone(), line: 1, kind: "extract-skipped".into(), reference: String::new(), text: format!("extract skipped: {why}") }
}

/// Run every applicable extractor on one file. One file can never abort the process: extraction runs on a
/// big-stack thread, a panic is caught, and a too-deep or panicking file yields an `extract-skipped` note
/// ("extract skipped: too deep" / "panic") instead of rows.
pub fn extract_file(repo: &Path, exts: &[Box<dyn Extractor>], f: &SourceFile) -> Rows {
    // extractors read LF text: a CRLF file (a Windows checkout, many .NET repos) is the same lines without the \r, and
    // rows carry line numbers only, so nothing shifts
    let lf;
    let f = if f.text.contains("\r\n") {
        lf = SourceFile::new(f.path.clone(), f.text.replace("\r\n", "\n"));
        &lf
    } else {
        f
    };
    let run = || {
        let mut rows = Rows::default();
        let _ = ts_util::take_too_deep();
        for e in exts.iter().filter(|e| e.handles(&f.path)) {
            rows.extend(e.extract(repo, std::slice::from_ref(f)));
        }
        if ts_util::take_too_deep() {
            rows.notes.push(note(f, "too deep"));
        }
        // `router.get('/x', handler)` seen as a server route is an endpoint, not a client call
        if !rows.api_calls.is_empty() && !rows.endpoints.is_empty() {
            let eps: std::collections::HashSet<(u32, String)> = rows.endpoints.iter().map(|e| (e.line, e.method.clone())).collect();
            rows.api_calls.retain(|a| !eps.contains(&(a.line, a.method.clone())) && !eps.contains(&(a.line, "ANY".into())));
        }
        frameworks::attach_inline_handlers(&mut rows);
        rows
    };
    std::thread::scope(|s| {
        match std::thread::Builder::new().stack_size(EXTRACT_STACK).spawn_scoped(s, run) {
            Ok(h) => h.join().unwrap_or_else(|_| {
                let mut r = Rows::default();
                r.notes.push(note(f, "panic"));
                r
            }),
            // no thread available: run inline rather than lose the file
            Err(_) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
                let mut r = Rows::default();
                r.notes.push(note(f, "panic"));
                r
            }),
        }
    })
}

/// True if any package.json in the repo (top level or up to two levels down) mentions `needle`.
pub fn package_json_mentions(repo: &Path, needle: &str) -> bool {
    let skip =
        |p: &Path| p.ends_with("node_modules") || p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'));
    let mut cands = vec![repo.join("package.json")];
    for e in std::fs::read_dir(repo).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() && !skip(&p) {
            cands.push(p.join("package.json"));
            for e2 in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                if e2.path().is_dir() && !skip(&e2.path()) {
                    cands.push(e2.path().join("package.json"));
                }
            }
        }
    }
    cands.iter().any(|p| std::fs::read_to_string(p).map(|t| t.contains(needle)).unwrap_or(false))
}

/// Is this a test file (unit test, e2e script, regression script)?
pub fn is_test_path(p: &str) -> bool {
    let n = p.rsplit('/').next().unwrap_or(p);
    let stem = n.rsplit_once('.').map(|x| x.0).unwrap_or(n);
    n.contains(".test.")
        || n.contains(".spec.")
        || p.contains("/__tests__/")
        || p.starts_with("e2e/")
        || p.contains("/e2e/")
        || p.contains("/regress/")
        || p.contains("/src/test/")
        // Python / Go / Java / Ruby conventions
        || (n.ends_with(".py") && (n.starts_with("test_") || stem.ends_with("_test") || n == "conftest.py"))
        || n.ends_with("_test.go")
        || (n.ends_with(".java") && (stem.ends_with("Test") || stem.ends_with("Tests") || stem.ends_with("IT")))
        || p.starts_with("tests/")
        || p.contains("/tests/")
        || n.ends_with("_spec.rb")
}
