//! Retroactive masking: after `aix mask add`, rows already stored are re-masked with the user masks (every text
//! column of every table, so tables added later - logs, pastes - are covered without a list to maintain).

use anyhow::Result;
use rusqlite::params;

use crate::index::Index;

const BATCH: usize = 500;
const SKIP_TABLES: &[&str] = &["meta", "savings", "vectors", "patterns", "grep_usage", "script_usage"];
const SKIP_COLS: &[&str] = &["file", "path", "sha", "short", "sig", "key", "regex", "kind", "model", "ts", "date", "norm", "target", "page_file"];

/// Re-mask stored text. Returns (rows changed, tables touched). `progress` gets a line per table with changes.
pub fn remask(ix: &Index, mut progress: impl FnMut(String)) -> Result<(usize, usize)> {
    let c = &ix.conn;
    // freed pages must not keep the old text: zero them, and compact afterwards
    let _ = c.execute_batch("PRAGMA secure_delete=ON");
    let tables: Vec<String> = {
        let mut st = c.prepare("SELECT name FROM sqlite_master WHERE type='table' AND sql NOT LIKE 'CREATE VIRTUAL%' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'entries_fts%' ORDER BY name")?;
        let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
        v
    };
    let (mut rows_changed, mut tables_touched) = (0, 0);
    let mut entries_changed = false;
    let started = std::time::Instant::now();
    // summaries (crate::matviews) are derived: recomputed from the masked base rows below, never masked on their own
    for t in tables.iter().filter(|t| !SKIP_TABLES.contains(&t.as_str()) && !t.starts_with("mv_")) {
        let cols: Vec<String> = {
            let mut st = c.prepare(&format!("PRAGMA table_info(\"{t}\")"))?;
            let v: Vec<(String, String)> = st.query_map([], |r| Ok((r.get(1)?, r.get::<_, String>(2)?)))?.collect::<Result<_, _>>()?;
            v.into_iter().filter(|(n, ty)| ty.to_ascii_uppercase().contains("TEXT") && !SKIP_COLS.contains(&n.as_str())).map(|x| x.0).collect()
        };
        if cols.is_empty() {
            continue;
        }
        let sel = format!("SELECT rowid, {} FROM \"{t}\" WHERE rowid > ? ORDER BY rowid LIMIT {BATCH}", cols.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", "));
        let mut last = i64::MIN;
        let mut n_t = 0;
        loop {
            let batch: Vec<(i64, Vec<Option<String>>)> = {
                let mut st = c.prepare_cached(&sel)?;
                let v = st
                    .query_map(params![last], |r| Ok((r.get::<_, i64>(0)?, (0..cols.len()).map(|i| r.get::<_, Option<String>>(i + 1)).collect::<Result<Vec<_>, _>>()?)))?
                    .collect::<Result<_, _>>()?;
                v
            };
            if batch.is_empty() {
                break;
            }
            let tx = c.unchecked_transaction()?;
            for (rid, vals) in &batch {
                last = *rid;
                for (col, v) in cols.iter().zip(vals) {
                    if let Some(new) = v.as_deref().and_then(aix_extract::masks::apply) {
                        tx.execute(&format!("UPDATE \"{t}\" SET \"{col}\"=? WHERE rowid=?"), params![new, rid])?;
                        n_t += 1;
                    }
                }
            }
            tx.commit()?;
        }
        if n_t > 0 {
            rows_changed += n_t;
            tables_touched += 1;
            entries_changed |= t == "entries";
            progress(format!("re-masked {n_t} value(s) in {t} ({:.1}s)", started.elapsed().as_secs_f32()));
        }
    }
    if rows_changed > 0 {
        crate::matviews::rebuild(c)?;
    }
    // typed searches and auto patterns that a new mask now covers
    let purged = crate::patterns::purge_sensitive(c);
    if purged > 0 {
        rows_changed += purged;
        tables_touched += 1;
        progress(format!("dropped {purged} stored search(es)/auto pattern(s) that a mask now covers"));
    }
    if entries_changed {
        // the FTS index is content-linked: rebuild it from the masked rows
        c.execute("INSERT INTO entries_fts(entries_fts) VALUES('rebuild')", [])?;
    }
    let _ = c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
    let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0)).unwrap_or(0);
    if free > 0 {
        let _ = c.execute_batch("PRAGMA incremental_vacuum");
        let left: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0)).unwrap_or(0);
        if left > 0 {
            progress(format!("{left} free page(s) remain in the index (zeroed; `aix update --full` rebuilds the file)"));
        }
    }
    // the separate log and paste stores (.aix/logs.db, .aix/pastes.db)
    let (r2, t2) = crate::logs::remask_stores(&ix.db_path, &mut progress);
    Ok((rows_changed + r2, tables_touched + t2))
}
