//! Semantic layer: embed entries incrementally under a deadline, cosine search over stored f32 BLOBs.
//! If the embedder is down nothing blocks: callers fall back to bm25 and print one line saying so.

use std::time::{Duration, Instant};

use anyhow::Result;
use rusqlite::params;

use crate::entries::sig;
use crate::index::Index;
use crate::llm;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct EmbedReport {
    pub embedded: usize,
    pub pending: usize,
    pub error: Option<String>,
}

/// Embed priority: what `ask`/`bugs`/`feature` lean on most goes first.
const PRIORITY: &str = "CASE kind WHEN 'feature' THEN 0 WHEN 'bug' THEN 1 WHEN 'task' THEN 2 WHEN 'e2e' THEN 3 \
    WHEN 'script' THEN 4 WHEN 'summary' THEN 5 WHEN 'learning' THEN 6 WHEN 'page-text' THEN 7 WHEN 'commit' THEN 8 ELSE 9 END";

/// `pending`, counted only up to `cap` (stops at the cap: the session card asks "at least 200 behind?", and the full
/// count is a scan of every entry, ~250 ms at 40k files).
pub fn pending_capped(ix: &Index, cap: usize) -> Result<usize> {
    Ok(ix.conn.query_row(
        "SELECT count(*) FROM (SELECT DISTINCT sig FROM entries WHERE sem=1 AND sig NOT IN (SELECT sig FROM vectors) LIMIT ?)",
        [cap as i64],
        |r| r.get::<_, i64>(0),
    )? as usize)
}

pub fn pending(ix: &Index) -> Result<usize> {
    Ok(ix.conn.query_row(
        "SELECT count(DISTINCT sig) FROM entries WHERE sem=1 AND sig NOT IN (SELECT sig FROM vectors)",
        [],
        |r| r.get::<_, i64>(0),
    )? as usize)
}

/// Characters of a code chunk that are embedded (name, signature, comments and the first statements carry the meaning).
const CODE_EMBED_CHARS: usize = 1100;

/// Seconds the embedder is left alone after it was unreachable (circuit breaker shared by every run on this index).
const BREAKER_SECS: i64 = 120;

/// Embed pending entries until `deadline`. Built to make progress against a busy, shared embedder:
/// - the batch is sized to the time left (measured seconds per text), so the last batch fits instead of timing out
///   and throwing its work away;
/// - a timeout halves the batch and retries after a short backoff (another client may hold the embedder), up to 3
///   failures in a row; a refused connection opens a circuit breaker for BREAKER_SECS so later runs (hooks, the
///   watcher) skip embedding instead of waiting on a dead endpoint;
/// - every batch is committed as it lands, so any progress survives an interrupted run.
pub fn embed_pending(ix: &Index, deadline: Duration) -> Result<EmbedReport> {
    let mut rep = EmbedReport::default();
    let Some(ep) = ix.cfg.embed.clone() else {
        rep.error = Some("no embedder configured".into());
        rep.pending = pending(ix)?;
        return Ok(rep);
    };
    let now_s = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if let Some(until) = ix.meta("embed_down_until").and_then(|v| v.parse::<i64>().ok()) {
        if now_s() < until {
            rep.error = Some(format!("embedder {} unreachable recently; retrying in {} s", ep.url, until - now_s()));
            rep.pending = pending(ix)?;
            return Ok(rep);
        }
    }
    let t0 = Instant::now();
    let max_batch = ix.cfg.embed_batch.max(1);
    let mut batch = max_batch;
    // seconds per text, measured (EWMA); unknown until the first batch lands
    let mut per_text: Option<f64> = ix.meta("embed_secs_per_text").and_then(|v| v.parse().ok());
    let mut fails = 0u32;
    while t0.elapsed() < deadline {
        let left = deadline.saturating_sub(t0.elapsed()).as_secs_f64();
        let mut b = batch;
        if let Some(pt) = per_text {
            let fit = (left / (pt * 1.5)).floor() as usize;
            if fit == 0 {
                break; // not even one text fits: leave it for the next run instead of overrunning
            }
            b = b.min(fit);
        }
        let rows: Vec<(String, String, String)> = ix
            .conn
            .prepare(&format!(
                "SELECT sig, text, MIN(kind) FROM entries WHERE sem=1 AND sig NOT IN (SELECT sig FROM vectors) GROUP BY sig ORDER BY MIN({PRIORITY}) LIMIT ?"
            ))?
            .query_map([b as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        if rows.is_empty() {
            break;
        }
        let texts: Vec<String> =
            rows.iter().map(|(_, t, k)| format!("{}{}", ix.cfg.embed_doc_prefix, clip_chars(t, if k == "code" { CODE_EMBED_CHARS } else { 1500 }))).collect();
        // generous per-request timeout: a queue behind another client is not an outage
        let timeout = match per_text {
            Some(pt) => (pt * rows.len() as f64 * 4.0 + 5.0).clamp(5.0, 120.0),
            None => left.clamp(10.0, 60.0),
        };
        let tb = Instant::now();
        match llm::embed(&ep, &texts, Duration::from_secs_f64(timeout)) {
            Ok(vecs) => {
                let tx = rusqlite::Transaction::new_unchecked(&ix.conn, rusqlite::TransactionBehavior::Immediate)?;
                {
                    let mut st = tx.prepare_cached("INSERT OR REPLACE INTO vectors VALUES(?,?,?)")?;
                    for ((s, _, _), v) in rows.iter().zip(&vecs) {
                        st.execute(params![s, v.len() as i64, llm::to_blob(v)])?;
                    }
                }
                tx.commit()?;
                rep.embedded += rows.len();
                let pt = tb.elapsed().as_secs_f64() / rows.len().max(1) as f64;
                per_text = Some(per_text.map_or(pt, |old| old * 0.7 + pt * 0.3));
                fails = 0;
                batch = (batch * 2).min(max_batch);
            }
            Err(e) => {
                let msg = short_err(&e.to_string());
                fails += 1;
                let refused = !msg.to_lowercase().contains("timeout");
                if refused || fails >= 3 {
                    if refused {
                        let _ = ix.set_meta("embed_down_until", &(now_s() + BREAKER_SECS).to_string());
                    }
                    rep.error = Some(format!("embedder {} unavailable: {msg}", ep.url));
                    break;
                }
                batch = (batch / 2).max(1);
                std::thread::sleep(Duration::from_millis(500 * fails as u64));
            }
        }
    }
    if let Some(pt) = per_text {
        let _ = ix.set_meta("embed_secs_per_text", &format!("{pt:.4}"));
    }
    if rep.error.is_none() {
        let _ = ix.conn.execute("DELETE FROM meta WHERE key='embed_down_until'", []);
    }
    rep.pending = pending(ix)?;
    Ok(rep)
}

fn clip_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn short_err(e: &str) -> String {
    e.lines().next().unwrap_or("").chars().take(120).collect()
}

#[derive(Debug, Clone)]
pub struct SemHit {
    pub id: i64,
    pub kind: String,
    pub file: String,
    pub line: i64,
    pub reference: String,
    pub text: String,
    pub score: f32,
}

/// Bumped (by triggers, in the writing transaction) whenever an embedded entry or an entry vector is added, changed or
/// removed: a cached vector matrix is current exactly while it is unchanged. Created by every update (and by the MCP
/// server at start) when missing; an index without it is never served from the cache.
pub const GEN_DDL: &str = "INSERT OR IGNORE INTO meta VALUES('sem_gen', '0');
CREATE TRIGGER IF NOT EXISTS entries_sem_ai AFTER INSERT ON entries WHEN NEW.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;
CREATE TRIGGER IF NOT EXISTS entries_sem_ad AFTER DELETE ON entries WHEN OLD.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;
CREATE TRIGGER IF NOT EXISTS entries_sem_au AFTER UPDATE ON entries WHEN OLD.sem=1 OR NEW.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;
CREATE TRIGGER IF NOT EXISTS vectors_sem_ai AFTER INSERT ON vectors WHEN substr(NEW.sig,1,2)<>'q:' BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;
CREATE TRIGGER IF NOT EXISTS vectors_sem_ad AFTER DELETE ON vectors WHEN substr(OLD.sig,1,2)<>'q:' BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;
CREATE TRIGGER IF NOT EXISTS vectors_sem_au AFTER UPDATE ON vectors BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen'; END;";

/// Install [`GEN_DDL`] when missing (one short write transaction; best effort).
pub fn ensure_gen(ix: &Index) {
    if ix.meta("sem_gen").is_some() {
        return;
    }
    let _ = (|| -> rusqlite::Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(&ix.conn, rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(GEN_DDL)?;
        tx.commit()
    })();
}

/// Query vectors kept in the process (a server is asked the same questions again): (endpoint, model, text) -> vector.
const QCACHE_MAX: usize = 256;
static QCACHE: std::sync::Mutex<std::collections::VecDeque<(String, std::sync::Arc<Vec<f32>>)>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());

/// The rows and vectors one kind filter searches, as loaded at generation `gen` of index file `file`.
struct Mat {
    key: (std::path::PathBuf, u64, u64, String), // (db path, device, inode, kind filter)
    gen: String,
    m: crate::vecpack::KindMat,
    bytes: usize,
}
/// Matrices kept in the process: at most this many, and this many bytes of vectors in all.
const MAT_MAX: usize = 4;
const MAT_BYTES: usize = 512 << 20;
static MATS: std::sync::Mutex<Vec<std::sync::Arc<Mat>>> = std::sync::Mutex::new(Vec::new());

fn file_id(p: &std::path::Path) -> Option<(u64, u64)> {
    std::fs::metadata(p).ok().map(|m| crate::sys::file_id(p, &m))
}

/// The embedded entries of one kind filter with their vectors, in entry order: from the process cache when the index
/// file and its embedding generation are the ones it was loaded at, else read (from the stored packs where current,
/// see `vecpack.rs`) and kept, within the bounds. Called inside the read transaction the answer is built in; the
/// second value holds packs worth writing once that transaction is over.
#[allow(clippy::type_complexity)]
fn matrix(ix: &Index, kq: &str, sel: &crate::vecpack::Sel) -> std::result::Result<(std::sync::Arc<Mat>, Vec<(String, crate::vecpack::KindMat)>), String> {
    let gen: Option<String> = ix.conn.query_row("SELECT value FROM meta WHERE key='sem_gen'", [], |r| r.get(0)).ok();
    let key = file_id(&ix.db_path).map(|(d, i)| (ix.db_path.clone(), d, i, kq.to_string()));
    if let (Some(g), Some(k)) = (&gen, &key) {
        if let Ok(m) = MATS.lock() {
            if let Some(hit) = m.iter().find(|x| &x.key == k && &x.gen == g) {
                return Ok((hit.clone(), vec![]));
            }
        }
    }
    let ex = ix.excl();
    let drops = |f: &str| ex.drops(f);
    let shadowed = crate::vecpack::entries_shadowed(&ix.conn);
    let (m, mut to_store) = crate::vecpack::matrix(&ix.conn, sel, if shadowed { Some(&drops) } else { None })?;
    if gen.is_none() {
        to_store.clear(); // no generation to label a pack with
    }
    let bytes = m.flat.len() * 4 + m.ids.len() * 16;
    let m = std::sync::Arc::new(Mat { key: key.clone().unwrap_or_default(), gen: gen.clone().unwrap_or_default(), m, bytes });
    if let (Some(_), Some(k)) = (gen, key) {
        if m.bytes <= MAT_BYTES {
            if let Ok(mut c) = MATS.lock() {
                c.retain(|x| x.key != k);
                c.insert(0, m.clone());
                while c.len() > MAT_MAX || c.iter().map(|x| x.bytes).sum::<usize>() > MAT_BYTES {
                    c.pop();
                }
            }
        }
    }
    Ok((m, to_store))
}

/// Cosine search over embedded entries of the given kinds. Err = embedder unavailable / no vectors.
pub fn search(ix: &Index, q: &str, kinds: Option<&[&str]>, limit: usize) -> std::result::Result<Vec<SemHit>, String> {
    let Some(ep) = ix.cfg.embed.clone() else {
        return Err("no embedder configured".into());
    };
    let have: i64 = ix.conn.query_row("SELECT count(*) FROM vectors", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    if have == 0 {
        return Err("no embeddings yet (run: aix update --embed-deadline 300)".into());
    }
    // the question with its spacing normalised (the same question asked twice is embedded once)
    let qtext = format!("{}{}", ix.cfg.embed_query_prefix, q.split_whitespace().collect::<Vec<_>>().join(" "));
    let qkey = format!("{}\u{1f}{}\u{1f}{qtext}", ep.url, ep.model);
    let hit = QCACHE.lock().ok().and_then(|mut c| {
        let i = c.iter().position(|x| x.0 == qkey)?;
        let e = c.remove(i)?;
        c.push_front(e.clone());
        Some(e.1)
    });
    let qv: std::sync::Arc<Vec<f32>> = match hit {
        Some(v) => v,
        None => {
            let qsig = format!("q:{}", sig(&qtext));
            let cached: Option<Vec<u8>> = ix.conn.query_row("SELECT vec FROM vectors WHERE sig=?", [&qsig], |r| r.get(0)).ok();
            let v = match cached {
                Some(b) => llm::from_blob(&b),
                None => {
                    let v = llm::embed(&ep, &[qtext], Duration::from_secs(8))
                        .map_err(|e| format!("embedder {} unavailable: {}", ep.url, short_err(&e.to_string())))?;
                    let v = v.into_iter().next().unwrap_or_default();
                    let _ = ix.conn.execute(
                        "INSERT OR REPLACE INTO vectors VALUES(?,?,?)",
                        params![qsig, v.len() as i64, llm::to_blob(&v)],
                    );
                    v
                }
            };
            let v = std::sync::Arc::new(v);
            if let Ok(mut c) = QCACHE.lock() {
                c.push_front((qkey, v.clone()));
                c.truncate(QCACHE_MAX);
            }
            v
        }
    };
    let kq = kinds
        .map(|k| {
            format!(
                " AND e.kind IN ({})",
                k.iter().map(|x| format!("'{}'", x.replace('\'', ""))).collect::<Vec<_>>().join(",")
            )
        })
        .unwrap_or_else(|| " AND e.kind<>'code'".into());
    let sel = match kinds {
        Some(k) => crate::vecpack::Sel::In(k.iter().map(|x| x.replace('\'', "")).collect()),
        None => crate::vecpack::Sel::NotCode,
    };
    // one read transaction: the rows, their generation and the hits' columns are one snapshot (inside a caller's
    // transaction that already holds)
    let own = ix.conn.is_autocommit() && ix.conn.execute_batch("BEGIN DEFERRED").is_ok();
    let r = ranked(ix, &qv, &kq, &sel, limit);
    if own {
        let _ = ix.conn.execute_batch("COMMIT");
    }
    let (hits, gen, to_store) = r?;
    if own && !to_store.is_empty() {
        crate::vecpack::store(&ix.conn, &gen, &to_store, ix.wait());
    }
    Ok(hits)
}

/// Score every row, best first (ties in entry order), one hit per identical text, the first `limit`.
#[allow(clippy::type_complexity)]
fn ranked(ix: &Index, qv: &[f32], kq: &str, sel: &crate::vecpack::Sel, limit: usize) -> std::result::Result<(Vec<SemHit>, String, Vec<(String, crate::vecpack::KindMat)>), String> {
    let (m, to_store) = matrix(ix, kq, sel)?;
    let km = &m.m;
    let scores: Vec<f32> = (0..km.len()).map(|i| llm::dot(qv, km.vec(i))).collect();
    let mut order: Vec<usize> = (0..km.len()).collect();
    order.sort_by(|a, b| scores[*b].total_cmp(&scores[*a]));
    let mut st = ix.conn.prepare_cached("SELECT kind, file, line, ref, text FROM main.entries WHERE id=?").map_err(|e| e.to_string())?;
    // one hit per identical text (the same fact can sit in several entries)
    let mut seen = std::collections::HashSet::new();
    let mut hits: Vec<SemHit> = vec![];
    for i in order {
        if hits.len() >= limit {
            break;
        }
        let id = km.ids[i];
        let Ok((kind, file, line, reference, text)) = st.query_row([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?))) else {
            continue;
        };
        if seen.insert((file.clone(), line, text.chars().take(60).collect::<String>())) {
            hits.push(SemHit { id, kind, file, line, reference, text, score: scores[i] });
        }
    }
    Ok((hits, m.gen.clone(), to_store))
}
