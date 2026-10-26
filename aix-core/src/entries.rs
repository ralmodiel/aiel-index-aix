//! The search corpus: one `entries` row per searchable fact (kind, file:line, ref, text), mirrored into
//! FTS5 by triggers. Rows flagged `sem=1` also get an embedding, keyed by a hash of their text.

use anyhow::Result;
use rusqlite::{params, Transaction};
use aix_extract::git::Commit;
use aix_extract::text::clip;
use aix_extract::Rows;

/// Entry kinds that get embeddings (meaning-based search).
pub const SEM_KINDS: &[&str] =
    &["feature", "bug", "task", "e2e", "script", "doc", "learning", "summary", "page-text", "commit", "code"];

pub fn sig(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex()[..16].to_string()
}

pub struct Entry<'a> {
    pub kind: &'a str,
    pub file: &'a str,
    pub line: u32,
    pub reference: &'a str,
    pub text: String,
    pub src: i32,
}

/// An entry whose text is already redacted and signed (built by a worker thread, inserted by the writer).
pub struct Built {
    kind: String,
    file: String,
    line: u32,
    reference: String,
    text: String,
    src: i32,
    sem: bool,
    sig: String,
}

impl Built {
    /// Every column it is written with (compared to tell whether derived rows changed).
    pub fn key(&self) -> [String; 8] {
        [self.kind.clone(), self.file.clone(), self.line.to_string(), self.reference.clone(), self.text.clone(), self.src.to_string(), self.sem.to_string(), self.sig.clone()]
    }
}

pub fn build(e: Entry) -> Built {
    // nothing searchable (or embedded, or printed by find/ask) carries a credential
    let text = aix_extract::text::redact(&e.text);
    let sem = SEM_KINDS.contains(&e.kind);
    let sig = if sem { sig(&text) } else { String::new() };
    Built { kind: e.kind.to_string(), file: e.file.to_string(), line: e.line, reference: e.reference.to_string(), text, src: e.src, sem, sig }
}

pub fn write_built(tx: &Transaction, v: &[Built]) -> Result<()> {
    let mut st = tx.prepare_cached("INSERT INTO entries(kind, file, line, ref, text, src, sem, sig) VALUES(?,?,?,?,?,?,?,?)")?;
    for e in v {
        st.execute(params![e.kind, e.file, e.line, e.reference, e.text, e.src, e.sem, e.sig])?;
    }
    Ok(())
}

pub fn add(tx: &Transaction, e: Entry) -> Result<()> {
    write_built(tx, &[build(e)])
}

pub fn file_entries(tx: &Transaction, path: &str, kind: &str, r: &Rows) -> Result<()> {
    write_built(tx, &build_file_entries(path, kind, r))
}

/// The search entries of one file, pure: safe to compute in a worker thread (redaction included).
pub fn build_file_entries(path: &str, kind: &str, r: &Rows) -> Vec<Built> {
    let mut out: Vec<Built> = vec![];
    let mut add = |_: (), e: Entry| -> Result<()> {
        out.push(build(e));
        Ok(())
    };
    let tx = ();
    let res: Result<()> = (|| {
    let syms: Vec<&str> = r.symbols.iter().filter(|s| s.exported).take(30).map(|s| s.name.as_str()).collect();
    add(
        tx,
        Entry {
            kind: "file",
            file: path,
            line: 1,
            reference: kind,
            text: format!("{path} {kind} {}", syms.join(" ")),
            src: 0,
        },
    )?;
    let mut page_text: Vec<&str> = vec![];
    for u in &r.ui_strings {
        add(tx, Entry { kind: "ui", file: path, line: u.line, reference: &u.kind, text: u.text.clone(), src: 0 })?;
        if u.kind != "test" && !page_text.contains(&u.text.as_str()) {
            page_text.push(&u.text);
        }
    }
    if !page_text.is_empty() && !path.ends_with("lib/api.ts") {
        let t: String = format!("{path} UI text: {}", page_text.join(" | ")).chars().take(1500).collect();
        add(tx, Entry { kind: "page-text", file: path, line: 1, reference: "ui", text: t, src: 0 })?;
    }
    for s in &r.sections {
        let t = if s.body.is_empty() { s.heading.clone() } else { format!("{} — {}", s.heading, s.body) };
        let lvl = format!("h{}", s.level);
        add(tx, Entry { kind: "doc", file: path, line: s.line, reference: &lvl, text: t, src: 0 })?;
    }
    for t in &r.tasks {
        let text = format!("{} {} {} {}", t.kind, t.status, t.round, t.text);
        add(tx, Entry { kind: "task", file: path, line: t.line, reference: &t.kind, text, src: 0 })?;
    }
    for s in &r.scripts {
        let text = format!("{path} {} {} {} {}", s.kind, s.header, s.usage, s.flags);
        add(tx, Entry { kind: "script", file: path, line: 1, reference: &s.kind, text, src: 0 })?;
    }
    for t in &r.tests {
        let text = format!("{} {} {} {} {}", t.id, t.title, t.role, t.routes.join(" "), t.texts.join(" | "));
        add(tx, Entry { kind: "e2e", file: path, line: t.line, reference: &t.id, text: clip(&text, 1200), src: 0 })?;
    }
    for b in &r.bugs {
        add(
            tx,
            Entry { kind: "bug", file: path, line: b.line, reference: &b.kind, text: clip(&b.text, 1200), src: 0 },
        )?;
    }
    for f in &r.features {
        let text = format!("{} {} {} {} {}", f.kind, f.name, f.route, f.purpose, f.extra);
        add(tx, Entry { kind: "feature", file: path, line: f.line, reference: &f.kind, text, src: 0 })?;
    }
    for a in r.api_calls.iter().filter(|a| a.object.is_some()) {
        let text = format!(
            "{}.{} {} {}",
            a.object.as_deref().unwrap_or(""),
            a.name.as_deref().unwrap_or(""),
            a.method,
            a.path
        );
        add(tx, Entry { kind: "api", file: path, line: a.line, reference: &a.norm_path, text, src: 0 })?;
    }
    let mut tables: Vec<(&str, u32, Vec<&str>)> = vec![];
    for d in &r.db_tables {
        match tables.iter_mut().find(|t| t.0 == d.table) {
            Some(t) => {
                if !t.2.contains(&d.op.as_str()) {
                    t.2.push(&d.op)
                }
            }
            None => tables.push((&d.table, d.line, vec![&d.op])),
        }
    }
    for (t, line, ops) in tables {
        add(
            tx,
            Entry { kind: "table", file: path, line, reference: t, text: format!("{t} {}", ops.join(" ")), src: 0 },
        )?;
    }
    for n in r.notes.iter().filter(|n| !n.kind.starts_with("ep:")) {
        let text = format!("{} :: {}", n.reference, n.text);
        add(tx, Entry { kind: &n.kind, file: path, line: n.line, reference: &n.kind, text, src: 0 })?;
    }
    Ok(())
    })();
    res.expect("infallible");
    out
}

const CODE_EXTS: &[&str] = &[
    "java", "kt", "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "go", "rs", "rb", "php", "cs", "swift", "scala", "sh", "sql", "c", "cc",
    "cpp", "h", "hpp", "vue", "svelte",
];
/// Lines per fixed window (files without members) and per window of a long member.
const CHUNK_WINDOW: usize = 50;
const CHUNK_MAX_PER_FILE: usize = 400;
const CHUNK_MAX_CHARS: usize = 3500;

/// Split `Foo.barBaz_qux` into `foo bar baz qux` so word queries match identifiers.
fn ident_words(s: &str) -> String {
    let mut out = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if c.is_alphanumeric() {
            if c.is_uppercase() && prev_lower {
                out.push(' ');
            }
            out.extend(c.to_lowercase());
            prev_lower = c.is_lowercase() || c.is_ascii_digit();
        } else {
            out.push(' ');
            prev_lower = false;
        }
    }
    out
}

static STR_LIT: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r#""([^"\\\n]{12,160})"|'([^'\\\n]{12,160})'"#).unwrap());

/// What a chunk says in words: its comments and the human-readable string literals (error messages, labels). Placed
/// right after the signature so the embedder, which sees only the start of a chunk, reads them even in a long body.
fn digest(body: &[&str]) -> String {
    let mut parts: Vec<String> = vec![];
    let mut n = 0;
    for l in body {
        let t = l.trim();
        let comment = t.strip_prefix("//").or_else(|| t.strip_prefix("/**")).or_else(|| t.strip_prefix("/*")).or_else(|| t.strip_prefix('*')).or_else(|| t.strip_prefix('#'));
        let mut add = |s: &str| {
            let s = s.trim().trim_end_matches("*/").trim();
            if s.split_whitespace().count() >= 3 && !parts.iter().any(|p| p == s) && n < 700 {
                n += s.len() + 1;
                parts.push(s.to_string());
            }
        };
        if let Some(c) = comment {
            add(c);
        } else {
            for c in STR_LIT.captures_iter(t) {
                add(c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str()));
            }
        }
    }
    parts.join(" | ")
}

/// Meaning-search units of one source file: one chunk per function/method (from the code-graph members, long ones in
/// windows, with the comment lines just above), else fixed windows. `ref` is `END qname`; the entry line is the start.
pub fn build_code_chunks(path: &str, text: &str, r: &Rows, memo: &std::collections::HashMap<String, String>) -> Vec<Built> {
    let ext = path.rsplit('.').next().unwrap_or("");
    if !CODE_EXTS.contains(&ext) || path.ends_with(".min.js") || text.len() > 600_000 {
        return vec![];
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() || text.len() / lines.len() > 300 {
        return vec![]; // minified or generated
    }
    let is_comment = |l: &str| {
        let t = l.trim_start();
        t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") || t.starts_with('#') || t.starts_with("\"\"\"")
    };
    let mut spans: Vec<(usize, usize, String, String)> = vec![]; // start, end (1-based), qname, sig
    for m in r.members.iter().filter(|m| matches!(m.kind.as_str(), "method" | "ctor" | "function" | "component" | "const")) {
        let (s, e) = (m.line as usize, (m.end_line as usize).min(lines.len()));
        if s == 0 || e < s || (m.kind == "const" && e - s < 3) || e - s < 1 && m.kind != "component" {
            continue;
        }
        spans.push((s, e, m.qname.clone(), m.sig.clone()));
    }
    if spans.is_empty() {
        let mut i = 0;
        while i < lines.len() {
            let e = (i + CHUNK_WINDOW).min(lines.len());
            spans.push((i + 1, e, String::new(), String::new()));
            i = e;
        }
    }
    let stem = path.rsplit('/').next().unwrap_or(path).split('.').next().unwrap_or("");
    let mut out = vec![];
    for (s, e, qname, sig) in spans {
        let mut a = s;
        while a < e + 1 {
            let b = (a + CHUNK_WINDOW + 20).min(e); // a long member is cut into windows
            let b = if e - b < 15 { e } else { b };
            let mut from = a;
            if a == s {
                let mut n = 0;
                while from > 1 && n < 8 && is_comment(lines[from - 2]) {
                    from -= 1;
                    n += 1;
                }
            }
            let body: Vec<&str> = lines[from - 1..b].iter().map(|l| l.trim_end()).collect();
            let indent = body.iter().filter(|l| !l.trim().is_empty()).map(|l| l.len() - l.trim_start().len()).min().unwrap_or(0);
            let mut t = format!("{path} {qname}\n{} {}\n", ident_words(stem), ident_words(&qname));
            if !sig.is_empty() && a == s {
                t.push_str(&format!("{sig}\n"));
            }
            let dig = digest(&body);
            if !dig.is_empty() {
                t.push_str(&format!("says: {dig}\n"));
            }
            for l in body {
                if t.len() >= CHUNK_MAX_CHARS {
                    break;
                }
                let l = l.get(indent.min(l.len())..).unwrap_or(l);
                if !l.trim().is_empty() {
                    t.extend(l.chars().take(200));
                    t.push('\n');
                }
            }
            if t.lines().count() > 3 {
                // strings the extractor redacted in their own context (a sentence holding a password) stay redacted here
                for (raw, red) in memo {
                    if raw != red && raw.len() >= 6 && t.contains(raw.as_str()) {
                        t = t.replace(raw.as_str(), red);
                    }
                }
                let reference = format!("{b} {}", if qname.is_empty() { stem } else { &qname });
                out.push(build(Entry { kind: "code", file: path, line: a as u32, reference: &reference, text: t, src: 0 }));
            }
            if out.len() >= CHUNK_MAX_PER_FILE || b >= e {
                break;
            }
            a = b + 1;
        }
        if out.len() >= CHUNK_MAX_PER_FILE {
            break;
        }
    }
    out
}

pub fn commit_entry(tx: &Transaction, c: &Commit) -> Result<()> {
    let files: Vec<&str> = c.files.iter().take(20).map(String::as_str).collect();
    let text = format!("{} {}", c.subject, files.join(" "));
    add(tx, Entry { kind: "commit", file: "", line: 0, reference: &c.short, text, src: 2 })?;
    tx.prepare_cached("INSERT INTO bugs VALUES('',0,'commit',?,?,?,'',?,?,?)")?.execute(params![
        c.date,
        aix_extract::text::severity_of(&[&c.subject]),
        if c.is_revert { "reverted" } else { "fixed" },
        c.short,
        clip(&c.subject, 140),
        format!("{} | files: {}", c.subject, c.files.iter().take(12).cloned().collect::<Vec<_>>().join(" ")),
    ])?;
    Ok(())
}
