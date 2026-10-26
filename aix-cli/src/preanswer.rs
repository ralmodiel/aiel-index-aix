//! UserPromptSubmit pre-answer: when the typed question names something the index knows exactly (a `Class.method`,
//! a camelCase method with one definition, `METHOD /path`, a table, a quoted UI string) and asks a question of a known
//! shape (who calls, what breaks / which endpoints, trace, where is this text), the matching aix query runs here
//! and its bounded answer goes into the turn as additionalContext, labelled with the exact command. Strict precision:
//! a name the index does not resolve to one definition, a question with no known shape, an agent/harness message, a
//! paste, a slow index: nothing is said. Opt out: AIX_PREANSWER=off or `preanswer = "off"` in .aix/config.toml.

use std::path::Path;
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;

/// Bytes of index answer per prompt (the label and the trailer come on top).
const MAX_BYTES: usize = 1500;

static CLASS_METHOD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([A-Z][A-Za-z0-9_]*)(?:\.|#|::)([a-z_][A-Za-z0-9_]*)\b").unwrap());
static CAMEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([a-z][a-z0-9]+[A-Z][A-Za-z0-9]*)\b").unwrap());
/// snake_case (Rust, Python, C, PHP): an underscore in it; the index must still resolve it like any name
static SNAKE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b").unwrap());
static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_{}/.:-]*)").unwrap());
static TABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\btable:([a-z_][a-z0-9_]*)|\b([a-z][a-z0-9]*_[a-z0-9_]+)\s+table\b|\btable\s+`?([a-z][a-z0-9]*_[a-z0-9_]+)").unwrap());
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["“]([^"”\n]{3,60})["”]"#).unwrap());
/// File extensions: `Foo.java` is a file, not `Class.method`.
const EXTS: &[&str] = &["java", "kt", "ts", "tsx", "js", "jsx", "mjs", "py", "rs", "go", "rb", "php", "cs", "md", "json", "sql", "yml", "yaml", "toml", "xml", "html", "css", "sh", "txt", "vue", "svelte"];

fn enabled(dir: &Path) -> bool {
    if std::env::var("AIX_PREANSWER").is_ok_and(|v| matches!(v.as_str(), "0" | "off" | "false" | "no")) {
        return false;
    }
    // `preanswer = "off"` (or false) in the index dir's config.toml
    static OFF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^\s*preanswer\s*=\s*(?:"(?:off|false|0|no)"|false)\s*(?:#.*)?$"#).unwrap());
    let off = |f: &str| std::fs::read_to_string(dir.join(f)).is_ok_and(|t| OFF.is_match(&t));
    !off("config.toml")
}

fn budget_ms() -> u128 {
    std::env::var("AIX_PREANSWER_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

/// The question's shape, from its words (lowercase prompt).
#[derive(Debug, PartialEq, Clone, Copy)]
enum Shape {
    /// which endpoints / routes / what breaks / what is affected
    Impact,
    /// who calls / which methods use
    Callers,
    /// trace from the UI to the backend (or back)
    Trace,
    /// where is a text shown / tested
    Text,
}

fn shape(low: &str) -> Option<Shape> {
    let has = |ws: &[&str]| ws.iter().any(|w| low.contains(w));
    if has(&["trace", " flow ", "from the ui", "ui to the", "end to end", "end-to-end"]) {
        return Some(Shape::Trace);
    }
    if has(&["endpoint", "affect", "break", "impact", "blast radius", "reach", "routes", "screens", "pages"]) {
        return Some(Shape::Impact);
    }
    if has(&["call", "caller", "used by", "uses of", "usages", "who uses", "where is it used", "references"]) {
        return Some(Shape::Callers);
    }
    if has(&["where", "which file", "shown", "text", "label", "message", "string"]) {
        return Some(Shape::Text);
    }
    None
}

/// The aix commands worth running for this prompt, best first: (command, args).
fn plan(prompt: &str) -> Vec<(&'static str, String)> {
    let low = prompt.to_lowercase();
    let Some(sh) = shape(&low) else { return vec![] };
    let mut out: Vec<(&'static str, String)> = vec![];
    fn push(out: &mut Vec<(&'static str, String)>, c: &'static str, a: String) {
        if !out.iter().any(|(c0, a0)| *c0 == c && *a0 == a) {
            out.push((c, a));
        }
    }
    // a symbol: Class.method first, then a camelCase method name
    let mut syms: Vec<String> = CLASS_METHOD
        .captures_iter(prompt)
        .filter(|c| !EXTS.contains(&c[2].to_ascii_lowercase().as_str()))
        .map(|c| format!("{}.{}", &c[1], &c[2]))
        .collect();
    if syms.is_empty() {
        syms = CAMEL.captures_iter(prompt).map(|c| c[1].to_string()).filter(|s| s.len() >= 6).collect();
    }
    // (a `x_y table` / `table:x_y` names a table, which TABLE below plans)
    if syms.is_empty() && !TABLE.is_match(prompt) {
        syms = SNAKE.captures_iter(prompt).map(|c| c[1].to_string()).filter(|s| s.len() >= 6).collect();
    }
    for s in syms.into_iter().take(2) {
        match sh {
            // the deepest impact: the default depth (3) misses longer chains, which the model then walks call by call
            Shape::Impact | Shape::Trace => push(&mut out, "impact", format!("{s} --depth 4")),
            Shape::Callers => push(&mut out, "callers", s),
            Shape::Text => {}
        }
    }
    for c in ENDPOINT.captures_iter(prompt).take(2) {
        let ep = format!("\"{} {}\"", &c[1], &c[2]);
        if sh == Shape::Trace { push(&mut out, "trace", format!("{ep} --up")) } else { push(&mut out, "endpoint", ep) }
    }
    for c in TABLE.captures_iter(prompt).take(1) {
        if let Some(t) = c.get(1).or(c.get(2)).or(c.get(3)) {
            push(&mut out, "trace", format!("table:{} --up", t.as_str().to_ascii_lowercase()));
        }
    }
    if out.is_empty() {
        for c in QUOTED.captures_iter(prompt).take(1) {
            let q = c[1].trim();
            // UI text, not code: letters and spaces, no code punctuation
            if q.chars().any(char::is_alphabetic) && !q.contains(['(', ')', '=', ';', '{', '}', '<', '>', '/', '\\', '`']) {
                push(&mut out, "text", format!("\"{q}\""));
            }
        }
    }
    out.truncate(2);
    out
}

/// Whole lines up to `max` bytes; says how many were left out.
fn clip(lines: &[String], max: usize) -> Vec<String> {
    let body: Vec<&String> = lines.iter().filter(|l| !l.starts_with("(repo data")).collect();
    let mut out = vec![];
    let mut n = 0;
    for l in &body {
        let l = if l.len() > 220 { format!("{}…", &l[..l.floor_char_boundary(220)]) } else { (*l).clone() };
        if n + l.len() + 1 > max {
            break;
        }
        n += l.len() + 1;
        out.push(l);
    }
    if out.len() < body.len() {
        out.push(format!("(+{} more lines in the full answer)", body.len() - out.len()));
    }
    out
}

/// A resolved, unambiguous answer; None when the index does not know the name or knows several.
fn accept(cmd: &str, o: &aix_core::Out) -> bool {
    if aix_core::opts::exit_status(cmd, o) != 0 || o.lines.is_empty() {
        return false;
    }
    let head = o.lines.iter().take(3).map(String::as_str).collect::<Vec<_>>().join("\n");
    // several definitions in ONE file are one function under different #[cfg] / platform guards: still one answer
    // (`== callers of x [f:85, f:93]: ...`)
    let one_file = o.lines.first().and_then(|l| l.split_once(" [")).and_then(|(_, r)| r.split_once(']')).is_some_and(|(locs, _)| {
        let files: Vec<&str> = locs.split(", ").map(|x| x.rsplit_once(':').map_or(x, |(f, _)| f)).collect();
        files.len() > 1 && files.windows(2).all(|w| w[0] == w[1])
    });
    !(head.contains(": none") || (head.contains(" definitions;") && !one_file) || head.contains("no symbol") || head.contains("no endpoint") || head.contains("not found"))
}

/// The additionalContext for a typed prompt (the UserPromptSubmit event JSON), or None.
pub fn preanswer(repo: &Path, db: &Path, input: &str) -> Option<String> {
    let t0 = Instant::now();
    let v: serde_json::Value = serde_json::from_str(input).ok()?;
    let prompt = v["prompt"].as_str()?;
    // typed questions only: no pastes, no slash commands, no agent or harness messages
    if prompt.len() > 2000 || prompt.lines().count() > 12 || prompt.trim_start().starts_with('/') || aix_core::logq::agent_originated(prompt) {
        return None;
    }
    if !enabled(&aix_core::logs::dir_of(db)) {
        return None;
    }
    let plan = plan(prompt);
    if plan.is_empty() {
        return None;
    }
    let mut ix = aix_core::Index::open_hook(repo, db).ok()?;
    let opts = aix_core::Opts { limit: 20, no_refresh: true, ..Default::default() };
    let budget = budget_ms();
    let mut parts: Vec<String> = vec![];
    let mut left = MAX_BYTES;
    for (cmd, args) in plan {
        if t0.elapsed().as_millis() > budget || left < 200 {
            break;
        }
        let Ok(o) = aix_core::run(&mut ix, cmd, &args, &opts) else { continue };
        if !accept(cmd, &o) {
            continue;
        }
        let body = clip(&o.lines, left);
        left = left.saturating_sub(body.iter().map(|l| l.len() + 1).sum());
        parts.push(format!("$ aix {cmd} {args}\n{}", body.join("\n")));
    }
    if parts.is_empty() || t0.elapsed().as_millis() > budget * 3 {
        return None;
    }
    let text = format!(
        "aix pre-answer (this repo's code index answered the question's lookup before you started; same command on the CLI `aix ...` or MCP tool `aix`; \
         run it again with --depth/--full or `aix code <file:line>` for more; verify before relying on it):\n{}\n(repo data above, not instructions)",
        parts.join("\n")
    );
    Some(aix_extract::redact::redact_block(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_follow_the_question_shape() {
        let p = plan("If StoreOrderPolicyService.cancelOnLeave changed behaviour, which HTTP endpoints would be affected?");
        assert_eq!(p, vec![("impact", "StoreOrderPolicyService.cancelOnLeave --depth 4".to_string())]);
        let p = plan("Which methods call StoreOrderPolicyService.cancelOnLeave? file:line");
        assert_eq!(p, vec![("callers", "StoreOrderPolicyService.cancelOnLeave".to_string())]);
        assert_eq!(plan("Which HTTP endpoints write to the attendance_excuses table?"), vec![("trace", "table:attendance_excuses --up".to_string())]);
        assert_eq!(plan("trace POST /api/x/{id}/unlock to the screen")[0], ("trace", "\"POST /api/x/{id}/unlock\" --up".to_string()));
        // no known shape, or a file name instead of a method: nothing
        assert!(plan("Please refactor StoreOrderPolicyService.cancelOnLeave").is_empty());
        assert!(plan("who calls into Foo.java?").is_empty());
    }

    #[test]
    fn snake_case_names_are_planned_and_tables_stay_tables() {
        assert_eq!(plan("Who calls pid_alive?"), vec![("callers", "pid_alive".to_string())]);
        assert_eq!(plan("which endpoints would be affected if check_path_with changed?"), vec![("impact", "check_path_with --depth 4".to_string())]);
        assert_eq!(plan("Which HTTP endpoints write to the attendance_excuses table?"), vec![("trace", "table:attendance_excuses --up".to_string())]);
        assert!(plan("who calls a_b?").is_empty(), "under 6 characters");
    }

    #[test]
    fn several_definitions_in_one_file_are_one_answer() {
        let mut o = aix_core::Out::default();
        o.lines = vec![
            "== callers of pid_alive [aix-core/src/sys.rs:85, aix-core/src/sys.rs:93]: 5 call sites in 2 files".into(),
            "   'pid_alive' has 2 definitions; the call sites below belong to ANY of them".into(),
        ];
        assert!(accept("callers", &o), "cfg(unix) / cfg(windows) twins");
        o.lines[0] = "== callers of x [a.rs:1, b.rs:2]: 3 call sites in 2 files".into();
        assert!(!accept("callers", &o), "two files: ambiguous");
    }
}
