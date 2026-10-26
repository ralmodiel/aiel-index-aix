//! Which files get indexed: gitignore-aware walk, an extension allowlist, vendored/build dirs excluded,
//! and secrets never read (`.env*`, `*.tok`, `*.pem`, key/credential files, anything .gitignore'd).

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

/// Never indexed, tracked or not: VCS/tooling/cache dirs, lockfiles, minified bundles, generated perf snapshots.
static EXCLUDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(^|/)(node_modules|\.ai|\.git|\.aix|worktrees|\.venv|venv|__pycache__)/|^docs/perf/snapshots/|",
        r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock)$|\.min\.(js|css)$|\.map$"
    ))
    .unwrap()
});

/// Build/vendor output dirs by name. Applied only when there is no git tracked set to trust (the plain walk):
/// a git-tracked file under `reports/` or `build/` is source (`pages/reports/ReportCard.tsx`), and generated
/// output is already dropped there because it is gitignored.
static GENERATED_DIRS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(dist|build|target|vendor|\.gradle|dev-dist|reports|android|ios|coverage|\.next|\.cache)/").unwrap()
});

const EXT: &[&str] = &[
    "ts",
    "tsx",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "java",
    "kt",
    "sql",
    "sh",
    "bash",
    "py",
    "md",
    "css",
    "properties",
    "yml",
    "yaml",
    "ftl",
    "html",
    "go",
    "rs",
    // more source languages (aix-extract `lang`) and template / component files
    "cs", "php", "rb", "rake", "swift", "scala", "sc", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "dart", "lua",
    "vue", "svelte", "erb", "jinja", "jinja2", "j2", "twig",
    // XQuery / MarkLogic (XQuery modules, Server-Side JavaScript)
    "xqy", "xq", "xqm", "xql", "xquery", "xqe", "sjs",
    "toml",
    "prisma",
    // light text types (size-capped to LIGHT_MAX_BYTES, redacted when printed, secrets excluded by is_secret)
    "conf",
    "kts",
    "xml",
    "txt",
];

/// Extensions of the "light" text types: searchable by `grep`, never parsed by an extractor.
pub const LIGHT_EXT: &[&str] = &["conf", "kts", "xml", "txt", "json"];
/// Size cap for the light text types (generated JSON/XML dumps are not worth indexing).
pub const LIGHT_MAX_BYTES: u64 = 200_000;

/// Extension of a path's file name, lower-cased ("" when none).
pub fn ext_lower(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(i) if i > 0 => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Directory names that hold credentials: nothing below them is indexed, read or printed.
fn secret_dir(c: &str) -> bool {
    let c = c.to_ascii_lowercase();
    matches!(c.as_str(), "secrets" | "secret" | ".ssh" | ".aws" | ".gnupg" | "private" | "vault" | "credentials")
        || c.starts_with(".env")
}

/// `application-prod.yml`, `db-prod.properties`, `prod.env`, `config.production.json`: per-environment production config.
static PROD_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|[-_.])prod(uction)?\.(properties|ya?ml|json|conf|env|ini|toml|xml|txt)$|^application-prod[-_.]").unwrap()
});

static JSON_OK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(e2e/specs/[^/]+\.json|package\.json|[^/]*findings[^/]*\.json|[^/]*specs?/[^/]+\.json)$").unwrap()
});

/// Never index or print these, even when not gitignored.
pub fn is_secret(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop();
    if parts.iter().any(|c| secret_dir(c)) {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|x| x.1).unwrap_or("");
    if PROD_ENV.is_match(&name) {
        return true;
    }
    if name.starts_with(".env") || name.ends_with(".tok") || name.ends_with(".token") {
        return true;
    }
    if matches!(ext, "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" | "crt" | "der" | "asc" | "gpg") {
        return true;
    }
    if name.starts_with("id_rsa") || name.starts_with("id_ed25519") || name.starts_with("id_ecdsa") {
        return true;
    }
    // cloud service-account key files (`service-account.json`, `service-account-prod.json`)
    if (name.starts_with("service-account") || name.starts_with("service_account")) && ext == "json" {
        return true;
    }
    let code =
        matches!(ext, "ts" | "tsx" | "js" | "jsx" | "mjs" | "java" | "kt" | "py" | "rs" | "go" | "cs" | "php" | "rb" | "swift" | "scala" | "c" | "h" | "cc" | "cpp" | "hpp" | "dart" | "lua" | "vue" | "svelte" | "erb" | "md" | "css" | "sh" | "ftl" | "html" | "xqy" | "xq" | "xqm" | "xql" | "xquery" | "xqe" | "sjs");
    // data/config files named like secrets; source files (`TenantSecretStore.java`) stay searchable
    if !code && (name.contains("secret") || name.contains("credential") || name.contains("password")) {
        return true;
    }
    // credential files that hold values by design: htpasswd hashes, WordPress's DB credentials, docker registry auth
    if name == ".htpasswd" || name.ends_with(".htpasswd") || name == "wp-config.php" || path.to_ascii_lowercase().ends_with(".docker/config.json") {
        return true;
    }
    // `*key*` files: data/config files only. A source file is code whatever its name (`api_key.rb`,
    // `ApiKeyAuthenticator.php`, `KeyboardShortcuts.tsx`): indexed, and its content redacted like any other.
    let kname = name.replace("keycloak", "kc").replace("keyboard", "kb").replace("keyword", "kw");
    if kname.contains("key") && !code {
        return true;
    }
    false
}

pub fn wanted(path: &str, extra: &[Regex]) -> bool {
    wanted_in(path, extra, false)
}

/// `wanted`, and with `untrusted_set` also drop build/vendor dirs by name (no git tracked set to rely on).
pub fn wanted_in(path: &str, extra: &[Regex], untrusted_set: bool) -> bool {
    // a name with a newline or other control character cannot be shown or stored (the skipped list is line based)
    if path.chars().any(char::is_control) {
        return false;
    }
    if EXCLUDE.is_match(path)
        || (untrusted_set && GENERATED_DIRS.is_match(path))
        || is_secret(path)
        || extra.iter().any(|r| r.is_match(path))
    {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = match name.rfind('.') {
        Some(i) if i > 0 => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    };
    if EXT.contains(&ext.as_str()) {
        return true;
    }
    if ext == "json" {
        return true; // size-capped like the other light text types (list_with_skips)
    }
    ext.is_empty() && (path.starts_with("scripts/") || path.starts_with("bin/") || path.contains("/scripts/"))
}

/// A schema migration file by location and extension (SQL, Liquibase/Alembic/Rails style).
pub fn is_migration_path(p: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|/)(db|migrations?|changelog|liquibase|alembic|flyway)[^/]*/.*\.(sql|xml|ya?ml|py|rb|json)$|(^|/)migrations?/[^/]*\.(sql|py|rb|ts|js)$").unwrap());
    RE.is_match(p)
}

pub struct Listed {
    pub path: String,
    pub size: u64,
    pub mtime_ns: i64,
}

/// Files git tracks (`ls-files --cached`, minus tracked files that match an ignore rule), plus, when asked,
/// untracked-but-not-ignored ones. None when `repo` is not a git work tree or git fails.
fn git_files(repo: &Path, untracked: bool) -> Option<Vec<String>> {
    use std::process::Command;
    let run = |args: &[&str]| -> Option<Vec<String>> {
        let o = Command::new("git").arg("-C").arg(repo).args(["ls-files", "-z"]).args(args).output().ok()?;
        if !o.status.success() {
            return None;
        }
        Some(o.stdout.split(|b| *b == 0).filter(|x| !x.is_empty()).map(|x| String::from_utf8_lossy(x).into_owned()).collect())
    };
    let mut tracked = run(&["--cached"])?;
    let ignored: std::collections::HashSet<String> = run(&["--cached", "--ignored", "--exclude-standard"])?.into_iter().collect();
    tracked.retain(|f| !ignored.contains(f));
    if untracked {
        tracked.extend(run(&["--others", "--exclude-standard"])?);
    }
    tracked.sort();
    tracked.dedup();
    Some(tracked)
}

/// (files, true when they come from git's tracked set)
fn candidates(repo: &Path, untracked: bool) -> (Vec<String>, bool) {
    // A fresh credentials file is untracked until committed: by default only what git tracks is indexed.
    // Outside a git work tree there is no tracked set, so fall back to the gitignore-aware walk.
    if repo.join(".git").exists() {
        if let Some(v) = git_files(repo, untracked) {
            return (v, true);
        }
    }
    let mut out = vec![];
    let walker = ignore::WalkBuilder::new(repo)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            !(e.file_type().is_some_and(|t| t.is_dir())
                && matches!(n.as_ref(), ".git" | "node_modules" | ".aix" | "target" | ".gradle" | ".venv"))
        })
        .build();
    for e in walker.flatten() {
        if !e.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        if let Ok(rel) = e.path().strip_prefix(repo) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    (out, false)
}

/// Wanted files that could not be indexed, with the reason (shown by `grep` so a miss is never silent).
#[derive(Default, Clone, Debug)]
pub struct Skipped {
    /// (path, "too big" | "non-UTF-8 name")
    pub files: Vec<(String, &'static str)>,
    /// tracked text files of a type aix does not index (`Makefile`, `build.gradle`, `*.scss`, `*.cshtml`): grep, ls
    /// and files name them so a positive answer is never silently partial
    pub unsupported: Vec<String>,
}

/// Binary or generated types that are never text worth naming as "not indexed".
pub const BINARY_EXT: &[&str] = &["png", "jpg", "jpeg", "gif", "ico", "webp", "svg", "woff", "woff2", "ttf", "eot", "otf", "pdf", "zip", "gz", "tgz", "bz2", "xz", "7z", "jar", "war", "class", "mp4", "mp3", "wav", "ogg", "webm", "mov", "bin", "exe", "dll", "so", "dylib", "a", "o", "lock", "map", "pem", "key", "crt", "p12", "keystore", "jks", "psd", "ai", "sketch", "fig", "xlsx", "xls", "docx", "doc", "pptx", "odt", "db", "sqlite", "pyc", "wasm", "bmp", "tif", "tiff", "heic", "avif", "mkv", "avi", "flac", "m4a", "aac", "dat"];

pub fn list(repo: &Path, extra: &[Regex], max_bytes: u64, untracked: bool) -> Vec<Listed> {
    list_with_skips(repo, extra, max_bytes, untracked).0
}

/// Listing of wanted files (repo-relative, forward slashes): git-tracked files (plus untracked ones when
/// `untracked`), regular files only (no symlinks), and the wanted files left out (too big, unusable name).
pub fn list_with_skips(repo: &Path, extra: &[Regex], max_bytes: u64, untracked: bool) -> (Vec<Listed>, Skipped) {
    let mut out = vec![];
    let mut skipped = Skipped::default();
    let (cands, tracked_set) = candidates(repo, untracked);
    // one stat per file, in parallel (results kept in listing order: the same output as a serial pass)
    enum One {
        Skip,
        Skipped(String, &'static str),
        Unsupported(String),
        Keep(Listed),
    }
    let one = |rel: &String| -> One {
        let rel = rel.clone();
        if !wanted_in(&rel, extra, !tracked_set) {
            // a secret-named migration is never read, but `table` says its history may be incomplete
            if is_secret(&rel) && is_migration_path(&rel) && !rel.chars().any(char::is_control) {
                return One::Skipped(rel, "secret-named");
            }
            let git_meta = matches!(rel.rsplit('/').next().unwrap_or(""), ".gitignore" | ".gitattributes" | ".gitmodules" | ".gitkeep" | ".keep");
            if tracked_set && !git_meta && !is_secret(&rel) && !EXCLUDE.is_match(&rel) && !rel.chars().any(char::is_control) && !BINARY_EXT.contains(&ext_lower(&rel).as_str()) && !extra.iter().any(|r| r.is_match(&rel)) {
                return One::Unsupported(rel);
            }
            return One::Skip;
        }
        let Ok(md) = std::fs::symlink_metadata(repo.join(&rel)) else {
            if rel.contains('\u{FFFD}') {
                return One::Skipped(rel, "non-UTF-8 name");
            }
            return One::Skip;
        };
        if !md.file_type().is_file() {
            return One::Skip;
        }
        if md.len() > max_bytes || (md.len() > LIGHT_MAX_BYTES && LIGHT_EXT.contains(&ext_lower(&rel).as_str()) && !JSON_OK.is_match(&rel)) {
            return One::Skipped(rel, "too big");
        }
        let mtime_ns = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        One::Keep(Listed { path: rel, size: md.len(), mtime_ns })
    };
    let all: Vec<One> = if cands.len() < 2048 {
        cands.iter().map(one).collect()
    } else {
        use rayon::prelude::*;
        crate::par::pool().install(|| cands.par_iter().map(one).collect())
    };
    for o in all {
        match o {
            One::Skip => {}
            One::Skipped(rel, why) => skipped.files.push((rel, why)),
            One::Unsupported(rel) => skipped.unsupported.push(rel),
            One::Keep(l) => out.push(l),
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    (out, skipped)
}

/// Coarse file kind, used for ranking and `brief`/`impact`.
pub fn file_kind(p: &str) -> &'static str {
    static TEST: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.(test|spec)\.[jt]sx?$|/__tests__/|(^|/)src/test/").unwrap());
    static MIG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(^|/)db/(migration|tenant)/.*\.sql$|(^|/)migrations?/").unwrap());
    static MODEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/(model|entity|dto|domain)/").unwrap());
    static SCRIPT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(^|/)(scripts|bin|tools)/|^e2e/.*\.(mjs|sh|js)$").unwrap());
    static LIB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"src/(lib|hooks|data|services|utils|api)/").unwrap());
    let n = p.rsplit('/').next().unwrap_or(p);
    if TEST.is_match(p) {
        return "test";
    }
    if p.starts_with("e2e/specs/") && p.ends_with(".json") {
        return "spec";
    }
    if MIG.is_match(p) {
        return "migration";
    }
    if p.ends_with(".md") {
        return "doc";
    }
    if p.contains("/pages/") && (p.ends_with(".tsx") || p.ends_with(".ts")) {
        return "page";
    }
    if p.contains("/components/") {
        return "component";
    }
    if p.ends_with(".java") {
        if n.ends_with("Resource.java") || n.ends_with("Controller.java") {
            return "backend-resource";
        }
        if n.ends_with("Service.java") {
            return "service";
        }
        if MODEL.is_match(p) {
            return "model";
        }
        return "backend";
    }
    if SCRIPT.is_match(p) {
        return "script";
    }
    if LIB.is_match(p) {
        return "lib";
    }
    // Node backends (Express, Fastify, Nest, serverless handlers): a server-side folder and no client-side one
    if [".ts", ".js", ".mjs", ".cjs"].iter().any(|e| p.ends_with(e)) && !p.ends_with(".d.ts") {
        let dirs: Vec<&str> = p.split('/').rev().skip(1).collect();
        let server = dirs.iter().any(|d| matches!(*d, "backend" | "server" | "servers" | "api" | "functions" | "lambda" | "lambdas" | "routes" | "controllers" | "middleware" | "middlewares"));
        let client = dirs.iter().any(|d| matches!(*d, "frontend" | "client" | "web" | "ui" | "components" | "pages" | "views" | "public" | "static"));
        if server && !client {
            return "backend";
        }
    }
    if p.ends_with(".ts") || p.ends_with(".tsx") {
        return "frontend";
    }
    "other"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_backends_are_backend_not_frontend() {
        assert_eq!(file_kind("server/routes/orders.ts"), "backend");
        assert_eq!(file_kind("backend/src/app.js"), "backend");
        assert_eq!(file_kind("api/src/middleware/auth.ts"), "backend");
        assert_eq!(file_kind("frontend/src/api/client.ts"), "lib");
        assert_eq!(file_kind("web/src/App.tsx"), "frontend");
        assert_eq!(file_kind("src/routes/Home.tsx"), "frontend");
    }
    #[test]
    fn secrets() {
        for s in [
            ".env",
            "a/.env.local",
            "x.tok",
            "certs/dev.pem",
            "deploy/sa-key.json",
            "cfg/keys.yml",
            "id_rsa",
            "db-password.txt",
            "web/.htpasswd",
            "site/wp-config.php",
            "home/.docker/config.json",
            "certs/server.key",
            "secrets/credentials.json",
            "deploy/service-account.json",
        ] {
            assert!(is_secret(s), "{s}");
        }
        // secret directories and production env files, whatever the file is called
        for s in ["secrets/a.md", "app/secret/x.ts", "home/.ssh/config", ".aws/config", "a/.gnupg/b.txt", "a/.env.d/x.yml",
                  "infra/private/notes.md", "ops/vault/policy.hcl", "a/credentials/b.json", "src/main/resources/application-prod.yml",
                  "conf/db-prod.properties", "conf/app.prod.yaml", "application-production.properties"] {
            assert!(is_secret(s), "{s}");
        }
        assert!(!is_secret("src/secretary/Desk.ts") && !is_secret("docs/production-notes.md") && !is_secret("conf/application-dev.yml"));
        for s in ["src/KeyboardShortcuts.tsx", "lib/keycloak.ts", "docs/key-decisions.md", "a/b.ts", "backend/keys.py", "tools/jwt-keys.py", "kc/login-reset-password.ftl", "apiKey.ts", "app/models/api_key.rb", "src/ApiKeyAuthenticator.php", "lib/private_key_loader.go"] {
            assert!(!is_secret(s), "{s}");
        }
    }
    #[test]
    fn wanted_files() {
        assert!(wanted("frontend/src/App.tsx", &[]));
        assert!(!wanted("frontend/node_modules/x/index.js", &[]));
        // tracked source in dirs that merely sound generated stays searchable; the untracked walk still drops them
        for p in ["frontend/src/pages/reports/ReportCard.tsx", "app/build/Gen.java", "android/App.kt", "x/vendor/a.ts"] {
            assert!(wanted(p, &[]), "{p}");
            assert!(!wanted_in(p, &[], true), "{p}");
        }
        assert!(!wanted("web/app.min.js", &[]) && !wanted("Cargo.lock", &[]));
        assert!(wanted("e2e/specs/teacher.json", &[]));
        // light text types are indexed (size-capped), unless secret
        for p in ["conf/app.conf", "build.gradle.kts", "data/x.json", "pom.xml", "notes/a.txt"] {
            assert!(wanted(p, &[]), "{p}");
        }
        assert!(!wanted("config/app.conf.pem", &[]));
        assert!(wanted("scripts/gate", &[]));
        assert!(!wanted("img/logo.png", &[]));
    }
}
