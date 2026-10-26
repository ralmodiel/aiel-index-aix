//! Optional LLM layer on the local AI harness ("chat" role): one-line purposes for files, menu features
//! and bug clusters, and `ask --answer`. Always labelled `summary_source=local-llm`, resumable (keyed by
//! an input hash), short deadlines, never part of the index build.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use rusqlite::params;

use crate::entries::{add, sig, Entry};
use crate::index::Index;
use crate::llm;
use crate::query::{rows, Hit};

const SYSTEM: &str = "You write one-line summaries of a software project's parts for a code index. \
Reply with ONE plain sentence (max 25 words), no preamble, no markdown. Say what it does for the user or the system.";

#[derive(Debug, Default, serde::Serialize)]
pub struct SumReport {
    pub files: usize,
    pub features: usize,
    pub bug_clusters: usize,
    pub failed: usize,
    pub pending_files: usize,
    pub note: Option<String>,
}

fn call(ix: &Index, prompt: &str, timeout: Duration) -> Result<(String, String)> {
    let mut last = anyhow!("no chat endpoint configured");
    for ep in &ix.cfg.chat {
        match llm::chat(ep, SYSTEM, prompt, 120, timeout) {
            Ok(t) => {
                let t = t.lines().next().unwrap_or("").trim().trim_matches('"').to_string();
                return Ok((t, if ep.model.is_empty() { ep.name.clone() } else { ep.model.clone() }));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

const FILE_KINDS: &str =
    "CASE kind WHEN 'page' THEN 0 WHEN 'backend-resource' THEN 1 WHEN 'service' THEN 2 WHEN 'component' THEN 3 \
    WHEN 'script' THEN 4 WHEN 'lib' THEN 5 WHEN 'backend' THEN 6 ELSE 9 END";

/// Summarise up to `max` items until `deadline`. Files first (missing summaries; codemap ones are reused),
/// then menu features without a purpose, then bug clusters per file.
pub fn summarize(ix: &Index, deadline: Duration, max: usize) -> Result<SumReport> {
    let t0 = Instant::now();
    let mut rep = SumReport::default();
    if ix.cfg.chat.is_empty() {
        rep.note = Some("no chat endpoint (config `chat` or ~/.config/local-llm/backends.json role \"chat\")".into());
        return Ok(rep);
    }
    let left = |t0: &Instant| deadline.saturating_sub(t0.elapsed());
    let per_call = Duration::from_secs(45);
    // files
    let todo = rows(
        &ix.conn,
        &format!("SELECT path, kind FROM files WHERE summary='' AND kind NOT IN ('doc','spec','migration','test','other') ORDER BY {FILE_KINDS}, path LIMIT ?"),
        &[&(max as i64)],
    );
    for f in todo {
        if left(&t0).is_zero() || rep.files + rep.failed >= max {
            break;
        }
        let text = std::fs::read_to_string(ix.repo.join(&f[0])).unwrap_or_default();
        let head: String = text.lines().take(120).map(aix_extract::text::redact).collect::<Vec<_>>().join("\n").chars().take(6000).collect();
        let syms: Vec<String> =
            rows(&ix.conn, "SELECT name FROM symbols WHERE file=? AND exported=1 LIMIT 20", &[&f[0]])
                .into_iter()
                .map(|r| r[0].clone())
                .collect();
        let prompt = format!(
            "File {} ({}), exports: {}.\n```\n{}\n```\nOne sentence: what is this file for?",
            f[0],
            f[1],
            syms.join(", "),
            head
        );
        match call(ix, &prompt, per_call.min(left(&t0)).max(Duration::from_secs(5))) {
            Ok((s, _)) if !s.is_empty() => {
                let tx = rusqlite::Transaction::new_unchecked(&ix.conn, rusqlite::TransactionBehavior::Immediate)?;
                tx.execute("UPDATE files SET summary=?, summary_source='local-llm' WHERE path=?", params![aix_extract::text::redact(&s), f[0]])?;
                tx.execute("DELETE FROM entries WHERE file=? AND src=3", [&f[0]])?;
                add(
                    &tx,
                    Entry {
                        kind: "summary",
                        file: &f[0],
                        line: 1,
                        reference: "local-llm",
                        text: format!("{}: {}", f[0], s),
                        src: 3,
                    },
                )?;
                tx.commit()?;
                rep.files += 1;
            }
            _ => {
                rep.failed += 1;
                if rep.failed >= 3 && rep.files == 0 {
                    rep.note = Some("local chat model not answering; stopped".into());
                    break;
                }
            }
        }
    }
    // menu features without a purpose -> llm_notes(feature, href)
    let feats = rows(
        &ix.conn,
        "SELECT route, name, file, extra FROM features WHERE kind='menu' AND purpose='' LIMIT ?",
        &[&(max as i64)],
    );
    for f in feats {
        if left(&t0).is_zero() {
            break;
        }
        let ui: Vec<String> =
            rows(&ix.conn, "SELECT text FROM ui_strings WHERE file=? AND kind!='test' LIMIT 40", &[&f[2]])
                .into_iter()
                .map(|r| r[0].clone())
                .collect();
        let input = format!("Page '{}' at {} ({}). Visible text: {}", f[1], f[0], f[3], ui.join(" | "));
        if note_done(ix, "feature", &f[0], &input) {
            continue;
        }
        if let Ok((s, m)) = call(
            ix,
            &format!("{input}\nOne sentence: what can a user do on this page?"),
            per_call.min(left(&t0)).max(Duration::from_secs(5)),
        ) {
            put_note(ix, "feature", &f[0], &input, &s, &m)?;
            rep.features += 1;
        }
    }
    // bug clusters: files named by 3+ findings
    let mut clusters: Vec<Vec<String>> = vec![];
    for f in
        rows(&ix.conn, "SELECT path FROM files WHERE kind IN ('page','backend-resource','service','component')", &[])
    {
        let stem = f[0].rsplit('/').next().unwrap_or(&f[0]).split('.').next().unwrap_or("").to_string();
        // short stems ("Modal", "codes") match unrelated findings
        if stem.len() < 8 {
            continue;
        }
        let n: i64 = ix.conn.query_row(
            "SELECT count(*) FROM bugs WHERE kind!='commit' AND text LIKE ?",
            [format!("%{stem}%")],
            |r| r.get(0),
        )?;
        if n >= 3 {
            clusters.push(vec![f[0].clone(), n.to_string()]);
        }
    }
    clusters.sort_by_key(|c| std::cmp::Reverse(c[1].parse::<i64>().unwrap_or(0)));
    clusters.truncate(max);
    {
        let keep: Vec<&str> = clusters.iter().map(|c| c[0].as_str()).collect();
        let stale: Vec<String> = rows(&ix.conn, "SELECT key FROM llm_notes WHERE kind='bug-cluster'", &[])
            .into_iter()
            .map(|r| r[0].clone())
            .filter(|k| !keep.contains(&k.as_str()))
            .collect();
        for k in stale {
            ix.conn.execute("DELETE FROM llm_notes WHERE kind='bug-cluster' AND key=?", [k])?;
        }
    }
    for c in clusters {
        if left(&t0).is_zero() {
            break;
        }
        let stem = c[0].rsplit('/').next().unwrap_or(&c[0]).split('.').next().unwrap_or("").to_string();
        let titles: Vec<String> = rows(
            &ix.conn,
            "SELECT title FROM bugs WHERE kind!='commit' AND text LIKE ? LIMIT 25",
            &[&format!("%{stem}%")],
        )
        .into_iter()
        .map(|r| r[0].clone())
        .collect();
        let input = format!("Past findings naming {}:\n- {}", c[0], titles.join("\n- "));
        if note_done(ix, "bug-cluster", &c[0], &input) {
            continue;
        }
        if let Ok((s, m)) = call(
            ix,
            &format!("{input}\nOne sentence: what keeps going wrong here?"),
            per_call.min(left(&t0)).max(Duration::from_secs(5)),
        ) {
            put_note(ix, "bug-cluster", &c[0], &input, &s, &m)?;
            rep.bug_clusters += 1;
        }
    }
    rep.pending_files = rows(
        &ix.conn,
        "SELECT count(*) FROM files WHERE summary='' AND kind NOT IN ('doc','spec','migration','test','other')",
        &[],
    )
    .first()
    .and_then(|r| r[0].parse().ok())
    .unwrap_or(0);
    Ok(rep)
}

fn note_done(ix: &Index, kind: &str, key: &str, input: &str) -> bool {
    !rows(&ix.conn, "SELECT 1 FROM llm_notes WHERE kind=? AND key=? AND sig=?", &[&kind, &key, &sig(input)]).is_empty()
}

fn put_note(ix: &Index, kind: &str, key: &str, input: &str, text: &str, model: &str) -> Result<()> {
    ix.conn.execute(
        "INSERT OR REPLACE INTO llm_notes VALUES(?,?,?,?,?,?)",
        params![kind, key, sig(input), text, model, crate::index::chrono_now()],
    )?;
    Ok(())
}

/// `ask --answer`: a short cited answer from the top hits (local chat model).
pub fn answer(ix: &Index, q: &str, hits: &[Hit]) -> Result<String> {
    let ctx: Vec<String> = hits
        .iter()
        .take(12)
        .enumerate()
        .map(|(i, h)| {
            format!("[{}] {} {}:{} {}", i + 1, h.kind, h.file, h.line, h.text.chars().take(400).collect::<String>())
        })
        .collect();
    let prompt = format!(
        "Question: {q}\n\nIndex hits:\n{}\n\nAnswer in at most 5 short lines using ONLY these hits; cite them like [2]. If they do not answer it, say so.",
        ctx.join("\n")
    );
    let sys = "You answer questions about a codebase from search hits. Be brief and exact; cite hit numbers.";
    let mut last = anyhow!("no chat endpoint configured");
    for ep in &ix.cfg.chat {
        match llm::chat(ep, sys, &prompt, 400, Duration::from_secs(60)) {
            Ok(t) => return Ok(t),
            Err(e) => last = e,
        }
    }
    Err(last)
}
