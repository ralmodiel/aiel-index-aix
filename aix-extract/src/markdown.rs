//! Markdown: headings + sections, checklists (task / DECISION / Found / BLOCKER), QA-findings docs ->
//! bugs, user-flow docs -> features, LEARNINGS files -> notes. A simple line parser (fences respected).

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::*;
use crate::text::{clip, redact, severity_of, status_of};
use crate::Extractor;

pub struct Markdown;

static HEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(#{1,6})\s+(.+)").unwrap());
static TASK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*[-*] \[( |x|X|~)\] (.*)").unwrap());
static ROUND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\*{0,2}([A-Z]{1,3}\d+(?:-[A-Z]{1,3}\d*)?)\b").unwrap());
static SHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b([0-9a-f]{7,12})\b").unwrap());
static BUG_DOC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^docs/(qa-|audit|hardening/|pre-launch-audit|improvement-log|security-audit|audit-backlog)[^/]*(/[^/]+)?\.md$|(^|/)[^/]*(findings|bugs?|BUGS)[^/]*\.md$").unwrap()
});
static FLOW_DOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)docs/(.+/)?[^/]*flows\.md$").unwrap());

pub fn is_tasks_file(path: &str) -> bool {
    let n = path.rsplit('/').next().unwrap_or(path);
    n == "TASKS.md" || n == "TODO.md"
}

impl Extractor for Markdown {
    fn name(&self) -> &'static str {
        "markdown"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        matches!(ext_of(path), "md" | "markdown")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            sections(f, &mut rows);
            tasks(f, &mut rows);
            if BUG_DOC.is_match(&f.path) {
                bug_doc(f, &mut rows);
            }
            if FLOW_DOC.is_match(&f.path) {
                flow_doc(f, &mut rows);
            }
            if f.name().to_ascii_uppercase().starts_with("LEARNINGS") {
                learnings(f, &mut rows);
            }
        }
        rows
    }
}

/// (line index, level, heading) outside code fences.
fn headings(lines: &[&str]) -> Vec<(usize, u8, String)> {
    let mut fence = false;
    let mut out = vec![];
    for (i, l) in lines.iter().enumerate() {
        if l.starts_with("```") || l.starts_with("~~~") {
            fence = !fence;
            continue;
        }
        if fence {
            continue;
        }
        if let Some(c) = HEAD.captures(l) {
            out.push((i, c[1].len() as u8, c[2].trim().trim_end_matches('#').trim().to_string()));
        }
    }
    out
}

fn sections(f: &SourceFile, rows: &mut Rows) {
    let lines: Vec<&str> = f.text.lines().collect();
    let hs = headings(&lines);
    for (k, (i, lvl, h)) in hs.iter().enumerate() {
        let end = hs[k + 1..].iter().find(|x| x.1 <= *lvl).map(|x| x.0).unwrap_or(lines.len());
        let mut para: Vec<&str> = vec![];
        let mut len = 0;
        for nl in lines.iter().skip(i + 1).take(11) {
            if nl.starts_with('#') {
                break;
            }
            let t = nl.trim();
            if !t.is_empty() {
                para.push(t);
                len += t.len();
            }
            if len > 320 {
                break;
            }
        }
        let body: String = redact(&para.join(" ")).chars().take(400).collect();
        rows.sections.push(Section {
            file: f.path.clone(),
            line: *i as u32 + 1,
            end_line: end as u32,
            level: *lvl,
            heading: redact(h),
            body,
        });
    }
}

fn tasks(f: &SourceFile, rows: &mut Rows) {
    let lines: Vec<&str> = f.text.lines().collect();
    let tasks_file = is_tasks_file(&f.path);
    let mut section = String::new();
    let mut fence = false;
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.starts_with("```") {
            fence = !fence;
        }
        if fence {
            i += 1;
            continue;
        }
        if l.starts_with('#') {
            section = l.trim_start_matches('#').trim().to_string();
            i += 1;
            continue;
        }
        let Some(m) = TASK.captures(l) else {
            i += 1;
            continue;
        };
        let mut body = vec![m[2].to_string()];
        let mut j = i + 1;
        while j < lines.len() && lines[j].starts_with("  ") && !TASK.is_match(lines[j]) {
            body.push(lines[j].trim().to_string());
            j += 1;
        }
        let t = redact(&body.join(" "));
        let head40: String = t.chars().take(40).collect();
        let kind = if t.starts_with("DECISION") {
            "DECISION"
        } else if head40.contains("BLOCKER") {
            "BLOCKER"
        } else if t.starts_with("Found") || section.to_lowercase().contains("found") {
            "Found"
        } else {
            "task"
        };
        let round = ROUND.captures(&t).map(|c| c[1].to_string()).unwrap_or_default();
        let sha: Vec<String> = SHA.captures_iter(&t).take(4).map(|c| c[1].to_string()).collect();
        let sha = sha.join(",");
        let status = match &m[1] {
            "x" | "X" => "done",
            "~" => "dropped",
            _ => "open",
        };
        rows.tasks.push(Task {
            file: f.path.clone(),
            line: i as u32 + 1,
            status: status.into(),
            kind: kind.into(),
            round: round.clone(),
            sha: sha.clone(),
            text: t.clone(),
            heading: section.clone(),
        });
        if tasks_file && (kind == "Found" || kind == "BLOCKER") {
            rows.bugs.push(Bug {
                file: f.path.clone(),
                line: i as u32 + 1,
                kind: format!("tasks-{}", kind.to_lowercase()),
                date: String::new(),
                severity: severity_of(&[&t]),
                status: status.into(),
                round,
                sha,
                title: clip(&t, 120),
                text: t,
            });
        }
        i = j;
    }
}

static DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d{4}-\d{2}(?:-\d{2})?)").unwrap());
static DATE_FULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap());
static ROUND_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"round-?(\d+)|rounds?-(\d+(?:-\d+)?)").unwrap());
static BUG_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#\d+|\b[A-Z]{1,8}-?\d+\b").unwrap());
static BULLET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s{0,3})(?:[-*]|\d+[.)])\s+(.*)").unwrap());
static BULLET_OR_BREAK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s{0,3}(?:[-*]|\d+[.)])\s+|#|\|)").unwrap());
static SUB_BULLET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s{4,}(?:[-*]|\d+[.)])\s+").unwrap());
static TABLE_SEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\|?\s*:?-{2,}").unwrap());
static SKIP_BUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(total|count|severity|track)\b").unwrap());
static ONLY_PUNCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\W\d ]+$").unwrap());
static RID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(#\d{2,4}|[A-Z]{1,8}-\d{1,3}|R\d{1,2}-[A-Z]?\d+)\b").unwrap());
static BT_SHA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`([0-9a-f]{7,12})`").unwrap());
static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
static MD_MARK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[*`~]").unwrap());

/// Port of the prototype's QA-findings parser: headings with a severity or id, table rows, and bullets
/// each become a bug row.
fn bug_doc(f: &SourceFile, rows: &mut Rows) {
    let fdate = DATE.captures(&f.path).map(|c| c[1].to_string()).unwrap_or_default();
    let fround = ROUND_FILE
        .captures(&f.path)
        .and_then(|c| c.get(1).or(c.get(2)).map(|m| format!("r{}", m.as_str())))
        .unwrap_or_default();
    let lines: Vec<&str> = f.text.lines().collect();
    let mut section = String::new();
    let mut sec_date = String::new();
    let mut hdr = false;
    let mut i = 0;
    let date = |sd: &str| {
        if fdate.is_empty() {
            sd.to_string()
        } else {
            fdate.clone()
        }
    };
    while i < lines.len() {
        let l = lines[i];
        if let Some(h) = HEAD.captures(l) {
            section = h[2].trim().to_string();
            if let Some(d) = DATE_FULL.find(&section) {
                sec_date = d.as_str().to_string();
            }
            let sev = severity_of(&[&section]);
            if h[1].len() >= 3 && (!sev.is_empty() || BUG_ID.is_match(&section)) {
                let para: Vec<&str> = lines[i + 1..lines.len().min(i + 6)]
                    .iter()
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty() && !x.starts_with('#'))
                    .collect();
                let t = format!("{} — {}", section, para.join(" "));
                add_bug(f, i + 1, &t, &section, &date(&sec_date), &fround, "doc", rows);
            }
            hdr = false;
            i += 1;
            continue;
        }
        if l.starts_with('|') {
            if TABLE_SEP.is_match(l) {
                i += 1;
                continue;
            }
            let cells: Vec<&str> = l.trim().trim_matches('|').split('|').map(|c| c.trim()).collect();
            if !hdr {
                hdr = true;
                i += 1;
                continue;
            }
            if cells.len() >= 3 && cells.join(" ").len() > 30 {
                add_bug(f, i + 1, &cells.join(" | "), &section, &date(&sec_date), &fround, "doc", rows);
            }
            i += 1;
            continue;
        }
        hdr = false;
        if let Some(b) = BULLET.captures(l) {
            let mut body = vec![b[2].to_string()];
            let mut j = i + 1;
            while j < lines.len() && !lines[j].trim().is_empty() && !BULLET_OR_BREAK.is_match(lines[j]) {
                body.push(lines[j].trim().to_string());
                j += 1;
            }
            while j < lines.len() && SUB_BULLET.is_match(lines[j]) {
                body.push(lines[j].trim().to_string());
                j += 1;
            }
            let t = body.join(" ");
            if t.len() > 25 {
                add_bug(f, i + 1, &t, &section, &date(&sec_date), &fround, "doc", rows);
            }
            i = j;
            continue;
        }
        i += 1;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn add_bug(
    f: &SourceFile,
    line: usize,
    t: &str,
    section: &str,
    date: &str,
    rnd: &str,
    kind: &str,
    rows: &mut Rows,
) {
    let t = redact(WS.replace_all(t, " ").trim());
    if SKIP_BUG.is_match(&t) || ONLY_PUNCT.is_match(&t) {
        return;
    }
    let rid = RID.captures(&t).map(|c| c[1].to_string()).unwrap_or_default();
    let mut shas: Vec<String> = vec![];
    for c in BT_SHA.captures_iter(&t) {
        if !shas.contains(&c[1].to_string()) {
            shas.push(c[1].to_string());
        }
    }
    let title = MD_MARK.replace_all(&t, "");
    let round = if rnd.is_empty() { rid } else { rnd.to_string() };
    rows.bugs.push(Bug {
        file: f.path.clone(),
        line: line as u32,
        kind: kind.into(),
        date: date.into(),
        severity: severity_of(&[&t, section]),
        status: status_of(&format!("{t} {section}")).into(),
        round,
        sha: shas.join(",").chars().take(60).collect(),
        title: clip(&title, 140),
        text: t.chars().take(1500).collect(),
    });
}

static ROUTE_TICK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`(/[a-z][\w/:-]*)`").unwrap());
static API_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(/api/[\w/{}.:-]+)").unwrap());
static STEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*(\d+[.)]|[-*])\s").unwrap());

fn flow_doc(f: &SourceFile, rows: &mut Rows) {
    let lines: Vec<&str> = f.text.lines().collect();
    let hs: Vec<(usize, u8, String)> = headings(&lines).into_iter().filter(|h| (2..=4).contains(&h.1)).collect();
    for (k, (i, _, h)) in hs.iter().enumerate() {
        let end = hs.get(k + 1).map(|x| x.0).unwrap_or(lines.len());
        let body = lines[i + 1..end].join("\n");
        let mut routes: Vec<String> = vec![];
        for c in ROUTE_TICK.captures_iter(&body) {
            let r = c[1].to_string();
            if !r.starts_with("/api/") && !routes.contains(&r) && routes.len() < 10 {
                routes.push(r);
            }
        }
        let mut apis: Vec<String> = vec![];
        for c in API_PATH.captures_iter(&body) {
            let r = c[1].to_string();
            if !apis.contains(&r) && apis.len() < 10 {
                apis.push(r);
            }
        }
        if routes.is_empty() && apis.is_empty() {
            continue;
        }
        let steps: String = lines[i + 1..end]
            .iter()
            .filter(|x| STEP.is_match(x))
            .map(|x| x.trim())
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(500)
            .collect();
        rows.features.push(Feature {
            file: f.path.clone(),
            line: *i as u32 + 1,
            kind: "flow".into(),
            name: h.clone(),
            route: routes.join(" "),
            roles: String::new(),
            purpose: redact(&clip(&steps, 300)),
            extra: apis.join(" "),
        });
    }
}

static LEARN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s{0,2}[-*] |\d+\. )").unwrap());

fn learnings(f: &SourceFile, rows: &mut Rows) {
    let mut section = String::new();
    for (i, l) in f.text.lines().enumerate() {
        if l.starts_with('#') {
            section = l.trim_start_matches('#').trim().to_string();
            continue;
        }
        if LEARN.is_match(l) && l.len() > 30 {
            let t = redact(l.trim().trim_start_matches(['-', '*', ' ']).trim());
            rows.notes.push(Note {
                file: f.path.clone(),
                line: i as u32 + 1,
                kind: "learning".into(),
                reference: section.clone(),
                text: t,
            });
        }
    }
}
