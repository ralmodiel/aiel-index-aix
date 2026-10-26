//! Named, materialized regex patterns.
//!
//! Three sources feed the registry (`patterns`):
//! - **seeded**: built-in patterns mined from what the project's scripts and Claude actually search with
//!   (`seed_patterns.tsv`, chosen by `scripts/mine-regex.py`);
//! - **auto**: every regex Claude searches with (`aix grep`, `grep -r`/`rg`/Grep seen by the PreToolUse hook) is
//!   counted in `grep_usage`; one used PROMOTE_AFTER times is promoted;
//! - **manual**: `patterns add <name> <regex>`.
//!
//! Matches live in `pattern_hits` (file, line, enclosing symbol, container, lang, kind, redacted text) and a view
//! `pat_<name>`. Capture groups become fields: a pattern with groups gets its own table `patcap_<name>(file, line,
//! symbol, <one TEXT column per group>)` with an index on every column, and `pat_<name>` joins it in, so
//! `select path, count(*) from pat_jaxrs_path group by path` is an indexed query. Named groups keep their names,
//! unnamed ones are g1, g2, ...
//!
//! The update engine keeps everything current: each changed file is read once and tested against all patterns with
//! one RegexSet (linear time, bounded size), so the cost does not grow with the file count times the pattern count.
//!
//! Policy (visible in `patterns list`, controllable with `patterns pin|unpin|rm`): every use (a grep answered from
//! the table, the same regex searched again, a `sql` query naming `pat_<name>`) bumps `uses` and a decayed score
//! (half-life HALF_LIFE_DAYS). Auto patterns unused for DORMANT_AFTER_DAYS go dormant (rows dropped, definition kept,
//! rebuilt on the next search); seeded ones only after SEED_DORMANT_AFTER_DAYS without any use. Above
//! MAX_TOTAL_HITS rows the lowest decayed score goes dormant first, auto before seeded. Pinned and hand-added patterns
//! are never pruned. A pattern matching more than MAX_HITS lines is "broad": not materialized (grep scans live).
//! Only pattern text is stored, never a command line; matched lines and captured values are redacted.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};

use crate::index::Index;

/// Uses before a searched regex becomes a named, materialized pattern.
pub const PROMOTE_AFTER: i64 = 3;
/// Auto patterns unused this long go dormant.
pub const DORMANT_AFTER_DAYS: i64 = 14;
/// Seeded patterns go dormant only after this long without a single use.
pub const SEED_DORMANT_AFTER_DAYS: i64 = 60;
/// Half-life of the use score that ranks patterns under the row budget.
pub const HALF_LIFE_DAYS: f64 = 14.0;
/// Total materialized rows kept; above it the least-used patterns go dormant first.
pub const MAX_TOTAL_HITS: i64 = 200_000;
/// A pattern matching more lines than this is too broad to be worth materializing.
pub const MAX_HITS: usize = 5000;
const MAX_AUTO_PATTERNS: i64 = 60;
/// Capture groups kept as columns (the rest are ignored).
const MAX_CAPS: usize = 8;
/// Files per batch while materializing (bounds memory on very large repos).
const CHUNK: usize = 2000;
/// Built-in seeds: name, regex, the mined regex it comes from.
const SEEDS: &str = include_str!("seed_patterns.tsv");
/// Bump when the seed list changes (re-applied once per index).
const SEED_REV: &str = "1";
const BASE_COLS: &[&str] = &["file", "line", "symbol", "container", "lang", "kind", "text", "name", "m"];

/// Older indexes predate the usage/policy columns.
pub fn ensure_columns(conn: &Connection) {
    if conn.prepare("SELECT broad FROM patterns LIMIT 0").is_ok() {
        return;
    }
    for c in [
        "uses INT DEFAULT 0",
        "last_used INT",
        "dormant INT DEFAULT 0",
        "seeded INT DEFAULT 0",
        "pinned INT DEFAULT 0",
        "score REAL DEFAULT 0",
        "caps TEXT DEFAULT ''",
        "removed INT DEFAULT 0",
        "broad INT DEFAULT 0",
    ] {
        let _ = conn.execute_batch(&format!("ALTER TABLE patterns ADD COLUMN {c}"));
    }
}

/// The use score decays by half every HALF_LIFE_DAYS.
pub fn decayed(score: f64, last: i64, now: i64) -> f64 {
    let days = (now - last).max(0) as f64 / 86_400.0;
    score * 0.5f64.powf(days / HALF_LIFE_DAYS)
}

/// A pattern answered a query (or was searched again): count it and refresh its decayed score.
pub fn touch(conn: &Connection, name: &str) {
    let now = now();
    let cur: Option<(f64, i64)> = conn
        .query_row(
            "SELECT COALESCE(score,0), COALESCE(last_used, created, 0) FROM patterns WHERE name=?",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    if let Some((s, last)) = cur {
        let _ = conn.execute(
            "UPDATE patterns SET uses=COALESCE(uses,0)+1, score=?, last_used=? WHERE name=?",
            params![decayed(s, last, now) + 1.0, now, name],
        );
    }
}

/// `pat_<name>` views named in a SQL query count as uses of those patterns.
pub fn touch_views_in(conn: &Connection, sql: &str) {
    static VIEW: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)\bpat_([a-z0-9_]{1,40})\b").unwrap());
    let names: HashSet<String> = VIEW.captures_iter(sql).map(|c| c[1].to_ascii_lowercase()).collect();
    for n in names {
        touch(conn, &n);
    }
}

pub fn compile(re: &str) -> Option<Regex> {
    // multi_line + crlf: `^`/`$` anchor at every line, as in grep (and in the whole-file RegexSet prefilter)
    regex::RegexBuilder::new(re).multi_line(true).crlf(true).size_limit(1 << 20).build().ok()
}

/// A short field-like name for a regex: `token\.sh` -> `token_sh`, `canPay\s*=` -> `canpay_s`.
pub fn slug(re: &str) -> String {
    let words: Vec<String> = re
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 1 || (!w.is_empty() && w.chars().all(|c| c.is_ascii_digit())))
        .map(|w| w.to_ascii_lowercase())
        .collect();
    let mut s = words.join("_");
    s.truncate(30);
    let s = s.trim_matches('_').to_string();
    if s.is_empty() {
        "pattern".into()
    } else if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("p_{s}")
    } else {
        s
    }
}

/// Column names for a regex's capture groups: named groups keep their (sanitized) name, unnamed ones are g1, g2, ...
pub fn cap_names(rx: &Regex) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for (i, n) in rx.capture_names().enumerate().skip(1) {
        let mut c: String = match n {
            Some(n) => n.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect(),
            None => format!("g{i}"),
        };
        c.truncate(30);
        if c.is_empty() || c.starts_with(|x: char| x.is_ascii_digit()) || BASE_COLS.contains(&c.as_str()) {
            c = format!("c_{c}");
        }
        while out.contains(&c) {
            c.push('_');
        }
        out.push(c);
        if out.len() == MAX_CAPS {
            break;
        }
    }
    out
}

fn view_sql(name: &str, caps: &[String]) -> String {
    if caps.is_empty() {
        format!(
            "CREATE VIEW IF NOT EXISTS \"pat_{name}\" AS SELECT file, line, symbol, container, lang, kind, text FROM pattern_hits WHERE name='{name}'"
        )
    } else {
        let cols: Vec<String> = caps.iter().map(|c| format!("c.\"{c}\"")).collect();
        format!(
            "CREATE VIEW IF NOT EXISTS \"pat_{name}\" AS SELECT h.file, h.line, c.symbol, h.container, h.lang, h.kind, h.text, {} FROM \"patcap_{name}\" c JOIN pattern_hits h ON h.name='{name}' AND h.file=c.file AND h.line=c.line",
            cols.join(", ")
        )
    }
}

/// The per-pattern capture table with an index on every column queries filter by.
fn cap_table_sql(name: &str, caps: &[String]) -> String {
    let cols: Vec<String> = caps.iter().map(|c| format!("\"{c}\" TEXT")).collect();
    let mut s = format!(
        "CREATE TABLE IF NOT EXISTS \"patcap_{name}\"(file TEXT, line INT, symbol TEXT, {});
         CREATE INDEX IF NOT EXISTS \"patcap_{name}__file\" ON \"patcap_{name}\"(file, line);
         CREATE INDEX IF NOT EXISTS \"patcap_{name}__symbol\" ON \"patcap_{name}\"(symbol);",
        cols.join(", ")
    );
    for c in caps {
        s.push_str(&format!("CREATE INDEX IF NOT EXISTS \"patcap_{name}_{c}\" ON \"patcap_{name}\"(\"{c}\");"));
    }
    s
}

fn drop_materialized(conn: &Connection, name: &str) -> Result<()> {
    conn.execute("DELETE FROM pattern_hits WHERE name=?", [name])?;
    conn.execute_batch(&format!("DROP VIEW IF EXISTS \"pat_{name}\"; DROP TABLE IF EXISTS \"patcap_{name}\";"))?;
    Ok(())
}

/// A query that must never be stored or materialized: one `redact()` would change (it holds a credential, or
/// is shaped like one) or one that looks like a high-entropy token (a long run mixing digits and letters, or hex).
pub fn sensitive_query(q: &str) -> bool {
    if aix_extract::text::redact(q) != q {
        return true;
    }
    // a random-looking word typed as a search (digits scattered through letters, or a long vowel-poor run)
    let randomish = q.split(|c: char| !c.is_ascii_alphanumeric()).any(|run| {
        let n = run.chars().count();
        if n < 10 {
            return false;
        }
        let digit = run.chars().any(|c| c.is_ascii_digit());
        let alpha = run.chars().any(|c| c.is_ascii_alphabetic());
        let mut clusters = 0;
        let mut prev_digit = false;
        for c in run.chars() {
            let d = c.is_ascii_digit();
            if d && !prev_digit {
                clusters += 1;
            }
            prev_digit = d;
        }
        let vowels = run.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
        (digit && alpha && clusters >= 2) || (n >= 12 && !digit && alpha && vowels * 100 < n * 15)
    });
    if randomish {
        return true;
    }
    q.split(|c: char| !(c.is_ascii_alphanumeric() || "+/_=-".contains(c))).any(|run| {
        let n = run.chars().count();
        let digit = run.chars().any(|c| c.is_ascii_digit());
        let alpha = run.chars().any(|c| c.is_ascii_alphabetic());
        (n >= 16 && digit && alpha) || (n >= 24 && run.chars().all(|c| c.is_ascii_hexdigit())) || {
            let (up, lo) = (run.chars().any(|c| c.is_ascii_uppercase()), run.chars().any(|c| c.is_ascii_lowercase()));
            n >= 24 && up && lo && digit
        }
    })
}

/// Drop stored searches and auto-materialized patterns that the redactor, a user mask or the token heuristics would
/// refuse today (rows stored before a mask was added, or by an older version). Returns how many rows went.
pub fn purge_sensitive(conn: &Connection) -> usize {
    let mut n = 0;
    ensure_columns(conn);
    let rows: Vec<String> = conn
        .prepare("SELECT regex FROM grep_usage")
        .and_then(|mut q| q.query_map([], |r| r.get::<_, String>(0)).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    for re in rows.iter().filter(|r| sensitive_query(r)) {
        n += conn.execute("DELETE FROM grep_usage WHERE regex=?", [re]).unwrap_or(0);
    }
    let pats: Vec<(String, String)> = conn
        .prepare("SELECT name, regex FROM patterns WHERE auto=1")
        .and_then(|mut q| q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map(|i| i.flatten().collect()))
        .unwrap_or_default();
    for (name, re) in pats.iter().filter(|p| sensitive_query(&p.1)) {
        if remove(conn, name).unwrap_or(false) {
            n += 1;
        }
        let _ = re;
    }
    n
}

/// Count one use of a regex; promote it to a named pattern once it reaches PROMOTE_AFTER. Returns the pattern
/// name when the regex is (now) a pattern.
pub fn record_use(conn: &Connection, re: &str) -> Option<String> {
    let re = re.trim();
    if re.len() < 3 || re.len() > 200 || compile(re).is_none() || sensitive_query(re) {
        return None;
    }
    let re = re.to_string();
    let now = now();
    let _ = conn.execute(
        "INSERT INTO grep_usage(regex, n, last) VALUES(?, 1, ?) ON CONFLICT(regex) DO UPDATE SET n=n+1, last=excluded.last",
        params![re, now],
    );
    ensure_columns(conn);
    if let Ok(Some(name)) = conn
        .query_row("SELECT name FROM patterns WHERE regex=? AND removed=0", [&re], |r| r.get::<_, String>(0))
        .optional()
    {
        // searched again: counts as a use, and a dormant pattern comes back (re-materialized on the next update)
        touch(conn, &name);
        let _ = conn.execute(
            "UPDATE patterns SET dirty=CASE WHEN dormant=1 THEN 1 ELSE dirty END, dormant=0 WHERE name=?",
            [&name],
        );
        return Some(name);
    }
    let n: i64 = conn.query_row("SELECT n FROM grep_usage WHERE regex=?", [&re], |r| r.get(0)).unwrap_or(0);
    let auto: i64 = conn.query_row("SELECT count(*) FROM patterns WHERE auto=1", [], |r| r.get(0)).unwrap_or(0);
    let exists = conn.query_row("SELECT 1 FROM patterns WHERE regex=?", [&re], |_| Ok(())).optional().ok().flatten().is_some();
    if n >= PROMOTE_AFTER && auto < MAX_AUTO_PATTERNS && !exists {
        return add(conn, None, &re, true).ok();
    }
    None
}

/// Add a named pattern (dirty until the next update materializes it). Returns its name.
pub fn add(conn: &Connection, name: Option<&str>, re: &str, auto: bool) -> Result<String> {
    ensure_columns(conn);
    anyhow::ensure!(!re.trim().is_empty(), "empty regex: a pattern needs something to match (usage: patterns add <name> '<regex>')");
    let rx = compile(re).ok_or_else(|| anyhow::anyhow!("bad regex (or too big for the linear-time engine)"))?;
    anyhow::ensure!(!rx.is_match(""), "the regex matches the empty string, so it would match every line; make it more specific");
    anyhow::ensure!(!sensitive_query(re), "the regex looks like a credential (or holds one); patterns are stored in the index, so it is refused");
    if let (Some(n), false) = (name, auto) {
        // an explicit name is used as typed (lower-cased): never silently rewritten into another one
        let ok = !n.is_empty() && n.len() <= 30 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        anyhow::ensure!(
            ok,
            "invalid name '{n}': use 1-30 letters, digits or _ (no spaces, dashes or dots), e.g. '{}'",
            slug(n)
        );
        let n = n.to_ascii_lowercase();
        if let Some((r, removed)) = conn
            .query_row("SELECT regex, removed FROM patterns WHERE name=?", [&n], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .optional()?
        {
            anyhow::ensure!(
                r == re || removed == 1,
                "the name pat:{n} is already used by /{r}/; pick another name or `patterns rm {n}` first"
            );
        }
        conn.execute(
            "INSERT INTO patterns(name, regex, auto, created, dirty) VALUES(?,?,?,?,1)
             ON CONFLICT(name) DO UPDATE SET regex=excluded.regex, dirty=1, dormant=0, removed=0, broad=0",
            params![n, re, auto as i64, now()],
        )?;
        return Ok(n);
    }
    let base = name.map(slug).unwrap_or_else(|| slug(re));
    let mut name = base.clone();
    let mut k = 2;
    while conn
        .query_row("SELECT regex FROM patterns WHERE name=?", [&name], |r| r.get::<_, String>(0))
        .optional()?
        .is_some_and(|r| r != re)
    {
        name = format!("{base}_{k}");
        k += 1;
    }
    conn.execute(
        "INSERT INTO patterns(name, regex, auto, created, dirty) VALUES(?,?,?,?,1)
         ON CONFLICT(name) DO UPDATE SET regex=excluded.regex, dirty=1, dormant=0, removed=0, broad=0",
        params![name, re, auto as i64, now()],
    )?;
    Ok(name)
}

/// Remove a pattern. A seeded one keeps a tombstone so it is not seeded again.
pub fn remove(conn: &Connection, name: &str) -> Result<bool> {
    ensure_columns(conn);
    let seeded: Option<i64> =
        conn.query_row("SELECT seeded FROM patterns WHERE name=? AND removed=0", [name], |r| r.get(0)).optional()?;
    let Some(seeded) = seeded else { return Ok(false) };
    drop_materialized(conn, name)?;
    if seeded == 1 {
        conn.execute("UPDATE patterns SET removed=1, dormant=1, pinned=0 WHERE name=?", [name])?;
    } else {
        conn.execute("DELETE FROM patterns WHERE name=?", [name])?;
    }
    Ok(true)
}

/// Pin (never pruned) or unpin a pattern. Pinning a dormant pattern brings it back.
pub fn pin(conn: &Connection, name: &str, on: bool) -> Result<bool> {
    ensure_columns(conn);
    let n = if on {
        conn.execute(
            "UPDATE patterns SET pinned=1, dirty=CASE WHEN dormant=1 THEN 1 ELSE dirty END, dormant=0 WHERE name=? AND removed=0",
            [name],
        )?
    } else {
        conn.execute("UPDATE patterns SET pinned=0 WHERE name=? AND removed=0", [name])?
    };
    Ok(n > 0)
}

/// Insert the built-in seeds once per SEED_REV (a seed removed by the user stays removed).
pub fn seed(conn: &Connection, enabled: bool) -> Result<usize> {
    ensure_columns(conn);
    let rev: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key='seed_rev'", [], |r| r.get(0)).optional()?;
    if !enabled || rev.as_deref() == Some(SEED_REV) {
        return Ok(0);
    }
    let mut n = 0;
    for (name, re) in seeds() {
        let cur: Option<(String, i64, i64)> = conn
            .query_row("SELECT regex, seeded, removed FROM patterns WHERE name=?", [name], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        match cur {
            None => {
                conn.execute(
                    "INSERT INTO patterns(name, regex, auto, seeded, created, dirty) VALUES(?,?,0,1,?,1)",
                    params![name, re, now()],
                )?;
                n += 1;
            }
            Some((old, 1, 0)) if old != re => {
                conn.execute("UPDATE patterns SET regex=?, dirty=1 WHERE name=?", params![re, name])?;
            }
            _ => {} // same seed, a removed seed, or a user pattern with that name: leave it
        }
    }
    conn.execute("INSERT OR REPLACE INTO meta VALUES('seed_rev', ?)", [SEED_REV])?;
    Ok(n)
}

/// The built-in seed list (name, regex).
pub fn seeds() -> Vec<(&'static str, &'static str)> {
    SEEDS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut it = l.split('\t');
            Some((it.next()?, it.next()?))
        })
        .collect()
}

struct Pat {
    name: String,
    rx: Regex,
    caps: Vec<String>,
    whole: bool,
}

/// One matching line: pattern index, file, line, redacted text, captured values of each match on the line.
type Hit = (usize, String, i64, String, Vec<Vec<Option<String>>>);

/// Keep `pattern_hits` and the capture tables current: re-scan `changed` files, drop rows of `removed` files, and
/// fully materialize patterns that are new (dirty) or everything after a full rebuild.
pub fn refresh(ix: &Index, changed: &[String], removed: &[String], full: bool) -> Result<()> {
    ensure_columns(&ix.conn);
    seed(&ix.conn, ix.cfg.seed_patterns)?;
    prune(&ix.conn)?;
    // a broad pattern is retried on a full rebuild (the repo may have changed)
    if full {
        ix.conn.execute("UPDATE patterns SET broad=0, dirty=1 WHERE broad=1 AND dormant=0 AND removed=0", [])?;
    }
    let defs: Vec<(String, String, bool, String)> = {
        let mut st = ix.conn.prepare(
            "SELECT name, regex, dirty, COALESCE(caps,'') FROM patterns WHERE dormant=0 AND removed=0 AND broad=0 ORDER BY name",
        )?;
        let v = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? == 1, r.get(3)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        v
    };
    let tx = rusqlite::Transaction::new_unchecked(&ix.conn, rusqlite::TransactionBehavior::Immediate)?;
    let mut pats: Vec<Pat> = vec![];
    for (name, re, dirty, old_caps) in defs {
        let Some(rx) = compile(&re) else { continue };
        let caps = cap_names(&rx);
        let joined = caps.join(",");
        let mut whole = full || dirty;
        if joined != old_caps {
            // the fields changed (new pattern, edited regex, older index): rebuild table + view
            tx.execute_batch(&format!("DROP VIEW IF EXISTS \"pat_{name}\"; DROP TABLE IF EXISTS \"patcap_{name}\";"))?;
            tx.execute("UPDATE patterns SET caps=? WHERE name=?", params![joined, name])?;
            whole = true;
        }
        if !caps.is_empty() {
            tx.execute_batch(&cap_table_sql(&name, &caps))?;
        }
        tx.execute_batch(&view_sql(&name, &caps))?;
        pats.push(Pat { name, rx, caps, whole });
    }
    // drop rows of changed/removed files, and everything of patterns rebuilt whole
    if !full {
        let mut del = tx.prepare_cached("DELETE FROM pattern_hits WHERE file=?")?;
        for f in removed.iter().chain(changed.iter()) {
            del.execute([f])?;
        }
        drop(del);
        for p in pats.iter().filter(|p| !p.caps.is_empty() && !p.whole) {
            let mut d = tx.prepare(&format!("DELETE FROM \"patcap_{}\" WHERE file=?", p.name))?;
            for f in removed.iter().chain(changed.iter()) {
                d.execute([f])?;
            }
        }
    }
    for p in pats.iter().filter(|p| p.whole) {
        tx.execute("DELETE FROM pattern_hits WHERE name=?", [&p.name])?;
        if !p.caps.is_empty() {
            tx.execute_batch(&format!("DELETE FROM \"patcap_{}\"", p.name))?;
        }
    }
    if pats.is_empty() {
        tx.commit()?;
        return Ok(());
    }
    let files: Vec<String> = if pats.iter().any(|p| p.whole) {
        let mut st = tx.prepare("SELECT path FROM files ORDER BY path")?;
        let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
        v
    } else {
        let mut v: Vec<String> = changed.to_vec();
        v.sort();
        v
    };
    let changed_set: HashSet<&str> = changed.iter().map(String::as_str).collect();
    // one RegexSet answers "which patterns match this file" in a single linear pass
    let set = regex::RegexSetBuilder::new(pats.iter().map(|p| p.rx.as_str())).multi_line(true).crlf(true).size_limit(64 << 20).build().ok();
    let max_bytes = ix.cfg.max_file_bytes;
    let mut counts: HashMap<usize, usize> = HashMap::new();
    let mut broad: HashSet<usize> = HashSet::new();
    let repo = ix.repo.clone();
    let clip = |s: &str| aix_extract::text::redact(&aix_extract::text::clip(s, 200));
    for chunk in files.chunks(CHUNK) {
        // a pattern already over MAX_HITS is broad: stop scanning for it
        let skip = broad.clone();
        let hits: Vec<Hit> = chunk
            .par_iter()
            .flat_map_iter(|f| {
                let in_changed = changed_set.contains(f.as_str());
                let wanted: Vec<usize> =
                    (0..pats.len()).filter(|&i| (pats[i].whole || in_changed) && !skip.contains(&i)).collect();
                let mut v: Vec<Hit> = vec![];
                if wanted.is_empty() {
                    return v;
                }
                let Some(t) = crate::query::read_for_grep(&repo, f, max_bytes) else { return v };
                let matched: Vec<usize> = match &set {
                    Some(s) => {
                        let m = s.matches(&t);
                        wanted.into_iter().filter(|&i| m.matched(i)).collect()
                    }
                    None => wanted.into_iter().filter(|&i| pats[i].rx.is_match(&t)).collect(),
                };
                if matched.is_empty() {
                    return v;
                }
                // select on the file's own lines (as live grep does), store the redacted line; captures come from the
                // redacted line when the redactor changed it, so they never hold a secret
                let (raw, red) = aix_extract::text::select_and_show(&t);
                for (k, l) in red.iter().map(String::as_str).enumerate() {
                    let sel = if raw.is_empty() { l } else { raw[k] };
                    for &i in &matched {
                        let p = &pats[i];
                        if !aix_extract::text::visible_match(&p.rx, sel, l) {
                            continue;
                        }
                        let caps: Vec<Vec<Option<String>>> = if p.caps.is_empty() {
                            vec![]
                        } else {
                            p.rx.captures_iter(if sel == l { sel } else { l })
                                .take(20)
                                .map(|c| (1..=p.caps.len()).map(|g| c.get(g).map(|m| clip(m.as_str()))).collect())
                                .collect()
                        };
                        v.push((i, f.clone(), k as i64 + 1, clip(l.trim()), caps));
                    }
                }
                v
            })
            .collect();
        let mut ins = tx.prepare_cached("INSERT INTO pattern_hits(name, file, line, text) VALUES(?,?,?,?)")?;
        let mut cap_ins: HashMap<usize, rusqlite::CachedStatement> = HashMap::new();
        for (i, f, line, text, caps) in hits {
            if broad.contains(&i) {
                continue;
            }
            let c = counts.entry(i).or_default();
            *c += 1;
            if *c > MAX_HITS {
                broad.insert(i);
                continue;
            }
            ins.execute(params![pats[i].name, f, line, text])?;
            if pats[i].caps.is_empty() {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = cap_ins.entry(i) {
                let p = &pats[i];
                let qs = vec!["?"; p.caps.len()].join(",");
                let cols: Vec<String> = p.caps.iter().map(|c| format!("\"{c}\"")).collect();
                e.insert(tx.prepare_cached(&format!(
                    "INSERT INTO \"patcap_{}\"(file, line, {}) VALUES(?,?,{qs})",
                    p.name,
                    cols.join(",")
                ))?);
            }
            let st = cap_ins.get_mut(&i).expect("prepared above");
            for vals in caps {
                let mut args: Vec<&dyn rusqlite::ToSql> = vec![&f, &line];
                for v in &vals {
                    args.push(v);
                }
                st.execute(args.as_slice())?;
            }
        }
    }
    // incremental additions can push a pattern over the cap too (only patterns that gained rows here)
    for (i, p) in pats.iter().enumerate() {
        if !p.whole && !broad.contains(&i) && counts.contains_key(&i) {
            let n: i64 = tx.query_row("SELECT count(*) FROM pattern_hits WHERE name=?", [&p.name], |r| r.get(0))?;
            if n as usize > MAX_HITS {
                broad.insert(i);
            }
        }
    }
    for &i in &broad {
        let name = &pats[i].name;
        drop_materialized(&tx, name)?;
        tx.execute("UPDATE patterns SET broad=1, dirty=0 WHERE name=?", [name])?;
    }
    // only rows of the files scanned here need their fields filled (indexed by file; no full-table scan)
    tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS pat_touched(path TEXT PRIMARY KEY); DELETE FROM temp.pat_touched;")?;
    {
        let mut st = tx.prepare_cached("INSERT OR IGNORE INTO temp.pat_touched VALUES(?)")?;
        for f in &files {
            st.execute([f])?;
        }
    }
    // fields beside the match: the innermost enclosing symbol (method/function/component), its container (class),
    // and the file's language and kind (source/test/script/doc)
    tx.execute_batch(
        "UPDATE pattern_hits SET
           symbol = (SELECT s.name FROM symbols s WHERE s.file=pattern_hits.file AND s.line<=pattern_hits.line AND s.end_line>=pattern_hits.line AND s.kind!='class' ORDER BY s.end_line-s.line LIMIT 1),
           container = (SELECT COALESCE(s.container, CASE WHEN s.kind='class' THEN s.name END) FROM symbols s WHERE s.file=pattern_hits.file AND s.line<=pattern_hits.line AND s.end_line>=pattern_hits.line ORDER BY s.kind!='class', s.end_line-s.line LIMIT 1),
           lang = (SELECT f.lang FROM files f WHERE f.path=pattern_hits.file),
           kind = (SELECT f.kind FROM files f WHERE f.path=pattern_hits.file)
         WHERE lang IS NULL AND file IN (SELECT path FROM temp.pat_touched)",
    )?;
    for (i, p) in pats.iter().enumerate() {
        if !p.caps.is_empty() && !broad.contains(&i) {
            tx.execute(
                &format!(
                    "UPDATE \"patcap_{n}\" SET symbol=(SELECT h.symbol FROM pattern_hits h WHERE h.name=? AND h.file=\"patcap_{n}\".file AND h.line=\"patcap_{n}\".line LIMIT 1) WHERE symbol IS NULL AND file IN (SELECT path FROM temp.pat_touched)",
                    n = p.name
                ),
                [&p.name],
            )?;
        }
    }
    tx.execute("UPDATE patterns SET dirty=0 WHERE dirty=1 AND dormant=0 AND removed=0 AND broad=0", [])?;
    tx.commit()?;
    Ok(())
}

/// Auto-tune (see the module doc). Returns how many patterns went dormant.
pub fn prune(conn: &Connection) -> Result<usize> {
    ensure_columns(conn);
    let now = now();
    // name, auto, seeded, protected (pinned or hand-added), score, last activity, rows
    type Row = (String, bool, bool, bool, f64, i64, i64);
    let mut all: Vec<Row> = {
        let mut st = conn.prepare(
            "SELECT p.name, p.auto, p.seeded, (p.pinned=1 OR (p.auto=0 AND p.seeded=0)), COALESCE(p.score,0),
                    COALESCE(p.last_used, p.created, 0), COALESCE(h.n, 0)
             FROM patterns p LEFT JOIN (SELECT name, count(*) n FROM pattern_hits GROUP BY name) h ON h.name=p.name
             WHERE p.dormant=0 AND p.removed=0",
        )?;
        let v = st
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, i64>(1)? == 1,
                    r.get::<_, i64>(2)? == 1,
                    r.get::<_, i64>(3)? == 1,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        v
    };
    let mut stale: Vec<String> = all
        .iter()
        .filter(|r| !r.3)
        .filter(|r| {
            let age = now - r.5;
            (r.1 && age > DORMANT_AFTER_DAYS * 86_400) || (r.2 && age > SEED_DORMANT_AFTER_DAYS * 86_400)
        })
        .map(|r| r.0.clone())
        .collect();
    let total: i64 = all.iter().filter(|r| !stale.contains(&r.0)).map(|r| r.6).sum();
    if total > MAX_TOTAL_HITS {
        // least valuable first: auto before seeded, then the lowest decayed score, then the oldest use
        all.retain(|r| !r.3 && !stale.contains(&r.0));
        all.sort_by(|a, b| {
            (a.2, decayed(a.4, a.5, now), a.5)
                .partial_cmp(&(b.2, decayed(b.4, b.5, now), b.5))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut over = total - MAX_TOTAL_HITS;
        for r in all {
            if over <= 0 {
                break;
            }
            over -= r.6;
            stale.push(r.0);
        }
    }
    for n in &stale {
        drop_materialized(conn, n)?;
        conn.execute("UPDATE patterns SET dormant=1, dirty=1 WHERE name=?", [n])?;
    }
    Ok(stale.len())
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(crate::schema::SCHEMA).unwrap();
        c
    }
    #[test]
    fn slugs() {
        assert_eq!(slug(r"token\.sh"), "token_sh");
        assert_eq!(slug(r"canPay\s*="), "canpay");
        assert_eq!(slug(r"@RolesAllowed\(.*order_admin"), "rolesallowed_order_admin");
        assert_eq!(slug(r"\d{4}"), "p_4");
        assert_eq!(slug(r".*"), "pattern");
        assert_eq!(slug(r"@RolesAllowed\(.*fees_officer"), "rolesallowed_fees_officer");
    }
    #[test]
    fn capture_columns() {
        let rx = compile(r#"api\.(?P<method>get|post)\('(?P<path>[^']+)'"#).unwrap();
        assert_eq!(cap_names(&rx), vec!["method", "path"]);
        let rx = compile(r#"(a)(?P<file>b)(?P<Kind>c)(d)"#).unwrap();
        assert_eq!(cap_names(&rx), vec!["g1", "c_file", "c_kind", "g4"]);
        assert!(cap_names(&compile("no groups (?:here)").unwrap()).is_empty());
    }
    #[test]
    fn seeds_parse_and_compile() {
        let s = seeds();
        assert!(s.len() >= 15 && s.len() <= 40, "{} seeds", s.len());
        let mut names = HashSet::new();
        for (n, re) in &s {
            assert!(compile(re).is_some(), "seed {n} must compile in the linear-time engine");
            assert_eq!(slug(n), *n, "seed name {n} must be a valid slug");
            assert!(names.insert(*n), "duplicate seed {n}");
        }
        assert!(regex::RegexSetBuilder::new(s.iter().map(|x| x.1)).size_limit(64 << 20).build().is_ok());
    }
    #[test]
    fn decay_halves() {
        assert!((decayed(4.0, 0, (HALF_LIFE_DAYS * 86_400.0) as i64) - 2.0).abs() < 1e-9);
        assert_eq!(decayed(3.0, 100, 100), 3.0);
    }
    #[test]
    fn promote_prune_revive() {
        let c = db();
        assert_eq!(record_use(&c, "foo\\(bar"), None);
        assert_eq!(record_use(&c, "foo\\(bar"), None);
        let name = record_use(&c, "foo\\(bar").expect("promoted after 3 uses");
        assert_eq!(name, "foo_bar");
        c.execute("INSERT INTO pattern_hits(name, file, line, text) VALUES(?, 'a.ts', 1, 'foo(bar')", [&name]).unwrap();
        c.execute("UPDATE patterns SET dirty=0, created=0, last_used=0", []).unwrap();
        assert_eq!(prune(&c).unwrap(), 1, "unused auto pattern goes dormant");
        let (dormant, hits): (i64, i64) = c
            .query_row("SELECT dormant, (SELECT count(*) FROM pattern_hits) FROM patterns WHERE name=?", [&name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((dormant, hits), (1, 0));
        record_use(&c, "foo\\(bar");
        let (dormant, dirty, uses): (i64, i64, i64) = c
            .query_row("SELECT dormant, dirty, uses FROM patterns WHERE name=?", [&name], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((dormant, dirty, uses), (0, 1, 1), "searched again: revived, counted, re-materialized next update");
        // hand-added patterns are never pruned
        add(&c, Some("mine"), "baz", false).unwrap();
        c.execute("UPDATE patterns SET created=0, last_used=0 WHERE name='mine'", []).unwrap();
        prune(&c).unwrap();
        let d: i64 = c.query_row("SELECT dormant FROM patterns WHERE name='mine'", [], |r| r.get(0)).unwrap();
        assert_eq!(d, 0);
    }
    #[test]
    fn seeded_policy_pin_and_tombstone() {
        let c = db();
        assert!(seed(&c, true).unwrap() >= 15);
        assert_eq!(seed(&c, true).unwrap(), 0, "applied once per seed revision");
        let (name, re) = seeds()[0];
        // 20 days unused: an auto pattern goes dormant, a seed is kept
        c.execute("UPDATE patterns SET created=?, dirty=0", [now() - 20 * 86_400]).unwrap();
        add(&c, None, "zzz_auto", true).unwrap();
        c.execute("UPDATE patterns SET created=? WHERE name='zzz_auto'", [now() - 20 * 86_400]).unwrap();
        assert_eq!(prune(&c).unwrap(), 1, "only the auto pattern goes dormant");
        // 61 days without a single use: seeds go too, unless pinned
        c.execute("UPDATE patterns SET created=? WHERE seeded=1", [now() - 61 * 86_400]).unwrap();
        pin(&c, name, true).unwrap();
        assert_eq!(prune(&c).unwrap(), seeds().len() - 1, "all seeds but the pinned one");
        let d: i64 = c.query_row("SELECT dormant FROM patterns WHERE name=?", [name], |r| r.get(0)).unwrap();
        assert_eq!(d, 0);
        // a removed seed is not seeded again
        assert!(remove(&c, name).unwrap());
        c.execute("DELETE FROM meta WHERE key='seed_rev'", []).unwrap();
        seed(&c, true).unwrap();
        let r: i64 = c.query_row("SELECT removed FROM patterns WHERE name=?", [name], |r| r.get(0)).unwrap();
        assert_eq!(r, 1);
        assert!(!remove(&c, name).unwrap(), "already removed");
        // `add` with the same name brings it back
        add(&c, Some(name), re, false).unwrap();
        let r: i64 = c.query_row("SELECT removed FROM patterns WHERE name=?", [name], |r| r.get(0)).unwrap();
        assert_eq!(r, 0);
    }
    #[test]
    fn budget_prunes_lowest_score_auto_first() {
        let c = db();
        add(&c, Some("busy"), "busy", true).unwrap();
        add(&c, Some("idle"), "idle", true).unwrap();
        add(&c, Some("seedy"), "seedy", false).unwrap();
        c.execute("UPDATE patterns SET seeded=1 WHERE name='seedy'", []).unwrap();
        touch(&c, "busy");
        touch(&c, "busy");
        let ins = |n: &str, k: i64| {
            c.execute(
                "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<?) INSERT INTO pattern_hits(name, file, line, text) SELECT ?, 'f', i, 't' FROM s",
                params![k, n],
            )
            .unwrap();
        };
        ins("busy", MAX_TOTAL_HITS / 2);
        ins("idle", MAX_TOTAL_HITS / 2);
        ins("seedy", 10);
        assert_eq!(prune(&c).unwrap(), 1);
        let d: String = c.query_row("SELECT group_concat(name) FROM patterns WHERE dormant=1", [], |r| r.get(0)).unwrap();
        assert_eq!(d, "idle");
    }
    #[test]
    fn sql_views_count_as_uses() {
        let c = db();
        add(&c, Some("route_path"), "x", false).unwrap();
        touch_views_in(&c, "select path, count(*) from pat_route_path group by 1");
        let u: i64 = c.query_row("SELECT uses FROM patterns WHERE name='route_path'", [], |r| r.get(0)).unwrap();
        assert_eq!(u, 1);
    }
}
