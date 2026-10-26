//! Materialized summaries ("materialized views": derived tables the indexer keeps current) for the hottest query
//! statements.
//!
//! SQLite has no materialized views, so each summary is an ordinary table with the exact query it replaces
//! ([`SOURCES`]). Every update that wrote anything brings each one up to date in the transaction that marks the index
//! built: the fresh aggregate is compared with the stored one and only the keys that differ are written (a re-indexed
//! file touches exactly the rows of the keys it changed). Readers use a summary only when it was refreshed by the same
//! build as the base tables ([`ready`]: `mv_built` equals `built`), and otherwise run the original query, so an index
//! refreshed by an older binary, or one this binary has not migrated yet, still answers the same.
//!
//! Migration is in place (no schema reset): [`ensure`] creates the tables on an existing index of this
//! schema and fills them, once, at the start of the next `update`.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};

/// No new index on a base table: an extra index can change the scan order of a query without a full ORDER BY (rows
/// tied on the sort key, `LIMIT` without `ORDER BY`) and so its answer; summaries are only read by the queries written
/// for them.
/// Bumped when a summary below changes: the next update re-creates and refills them.
pub const MV_VERSION: &str = "1";

pub const DDL: &str = "
-- page_closure: how many files import a module (a shared module is not part of one page)
CREATE TABLE IF NOT EXISTS mv_import_fanin(target TEXT PRIMARY KEY, n INT NOT NULL) WITHOUT ROWID;
-- tracecmd: endpoints reaching each table access (an access reached from very many is shared infrastructure)
CREATE TABLE IF NOT EXISTS mv_table_access(tbl TEXT, rw TEXT, cfid INT, cline INT, n INT NOT NULL,
  PRIMARY KEY(tbl, rw, cfid, cline)) WITHOUT ROWID;
";

/// (summary table, key columns, the query it materializes): the refresh and the consistency check both use these.
pub const SOURCES: &[(&str, &str, &str)] = &[
    (
        "mv_import_fanin",
        "target",
        "SELECT target, count(DISTINCT file) FROM imports WHERE target!='' GROUP BY target",
    ),
    (
        "mv_table_access",
        "tbl, rw, cfid, cline",
        "SELECT tbl, rw, cfid, cline, count(DISTINCT tid) FROM trace_paths WHERE layer='table' AND tbl IS NOT NULL AND rw IS NOT NULL AND cfid IS NOT NULL AND cline IS NOT NULL GROUP BY tbl, rw, cfid, cline",
    ),
];

fn meta(c: &Connection, k: &str) -> Option<String> {
    c.query_row("SELECT value FROM meta WHERE key=?", [k], |r| r.get(0)).optional().ok().flatten()
}

/// The summaries describe the current build (same `built` stamp) and have this binary's layout.
pub fn ready(c: &Connection) -> bool {
    let Ok(mut st) = c.prepare_cached("SELECT (SELECT value FROM meta WHERE key='mv_built') = (SELECT value FROM meta WHERE key='built') AND (SELECT value FROM meta WHERE key='mv_ver') = ?") else {
        return false;
    };
    st.query_row([MV_VERSION], |r| r.get::<_, Option<bool>>(0)).ok().flatten().unwrap_or(false)
}

/// Create (on an index made before them) and fill the summaries when their layout is not this binary's. Cheap no-op
/// otherwise. Runs inside the caller's write transaction when there is one.
pub fn ensure(c: &Connection) -> Result<bool> {
    if meta(c, "mv_ver").as_deref() == Some(MV_VERSION) || meta(c, "schema").is_none() {
        return Ok(false);
    }
    let own = c.is_autocommit();
    if own {
        c.execute_batch("BEGIN IMMEDIATE")?;
    }
    let r = (|| -> Result<()> {
        for (t, _, _) in SOURCES {
            c.execute_batch(&format!("DROP TABLE IF EXISTS {t}"))?;
        }
        c.execute_batch(DDL)?;
        refresh(c)?;
        c.execute("INSERT OR REPLACE INTO meta VALUES('mv_ver', ?)", [MV_VERSION])?;
        // stamped with the build they were computed from (none yet: a first build stamps them at its end)
        c.execute("INSERT OR REPLACE INTO meta SELECT 'mv_built', value FROM meta WHERE key='built'", [])?;
        Ok(())
    })();
    if own {
        c.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" })?;
    }
    r.map(|_| true)
}

/// Bring every summary up to date with its query, writing only the keys whose value changed. Returns rows written.
pub fn refresh(c: &Connection) -> Result<usize> {
    c.execute_batch(DDL)?;
    let mut n = 0;
    for (t, key, q) in SOURCES {
        // keys gone from the source
        n += c.execute(&format!("DELETE FROM {t} WHERE ({key}) IN (SELECT {key} FROM {t} EXCEPT SELECT {key} FROM ({q}))"), [])?;
        // new keys and changed values
        n += c.execute(&format!("INSERT OR REPLACE INTO {t} SELECT * FROM ({q} EXCEPT SELECT * FROM {t})"), [])?;
    }
    Ok(n)
}

/// Recompute every summary from scratch (after base rows were rewritten in place, e.g. by `remask`: the old rows are
/// deleted, so with `secure_delete` their text does not survive in free pages).
pub fn rebuild(c: &Connection) -> Result<usize> {
    if meta(c, "mv_ver").is_none() {
        return Ok(0);
    }
    for (t, _, _) in SOURCES {
        c.execute_batch(&format!("DELETE FROM {t}"))?;
    }
    refresh(c)
}

/// Stamp the summaries as current for the build stamp `built` (in the transaction that writes it).
pub fn stamp(c: &Connection, built: &str) -> Result<()> {
    c.execute("INSERT OR REPLACE INTO meta VALUES('mv_built', ?)", [built])?;
    c.execute("INSERT OR REPLACE INTO meta VALUES('mv_ver', ?)", [MV_VERSION])?;
    Ok(())
}

/// Consistency check: every summary equals the query it replaces. Returns one line per summary that differs.
pub fn check(c: &Connection) -> Vec<String> {
    let mut bad = vec![];
    for (t, _, q) in SOURCES {
        let diff = |sql: String| c.query_row(&sql, [], |r| r.get::<_, i64>(0)).unwrap_or(-1);
        let missing = diff(format!("SELECT count(*) FROM ({q} EXCEPT SELECT * FROM {t})"));
        let extra = diff(format!("SELECT count(*) FROM (SELECT * FROM {t} EXCEPT {q})"));
        if missing != 0 || extra != 0 {
            bad.push(format!("{t}: {missing} rows missing, {extra} rows stale"));
        }
    }
    bad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO meta VALUES('schema','9'),('built','t1');
             CREATE TABLE imports(file TEXT, line INT, name TEXT, source TEXT, target TEXT);
             CREATE TABLE trace_paths(tid INT, pid INT, hop INT, layer TEXT, fid INT, line INT, cfid INT, cline INT, conf TEXT, tbl TEXT, rw TEXT, via TEXT);
             INSERT INTO imports VALUES('a.ts',1,'x','./x','x.ts'),('b.ts',1,'x','./x','x.ts'),('b.ts',2,'x','./x','x.ts'),('a.ts',2,'y','y','');
             INSERT INTO trace_paths VALUES(1,1,2,'table',1,10,2,20,'exact','orders','R',''),(2,1,2,'table',1,10,2,20,'exact','orders','R',''),
                                           (2,2,2,'table',1,10,2,20,'exact','orders','R',''),(3,1,1,'service',1,10,2,20,'exact','','','');",
        )
        .unwrap();
        c
    }

    #[test]
    fn ensure_fills_refresh_tracks_changes_and_ready_follows_the_build() {
        let c = db();
        assert!(!ready(&c));
        assert!(ensure(&c).unwrap());
        assert!(!ensure(&c).unwrap(), "second ensure is a no-op");
        assert!(ready(&c));
        assert!(check(&c).is_empty(), "{:?}", check(&c));
        let n: i64 = c.query_row("SELECT n FROM mv_import_fanin WHERE target='x.ts'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        let n: i64 = c.query_row("SELECT n FROM mv_table_access WHERE tbl='orders'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2);
        // a re-indexed file: one key changes, one disappears, one appears
        c.execute_batch(
            "DELETE FROM imports WHERE file='b.ts'; INSERT INTO imports VALUES('b.ts',1,'z','./z','z.ts');
             DELETE FROM trace_paths WHERE tid=1; INSERT INTO trace_paths VALUES(4,1,2,'table',1,11,3,5,'exact','users','W','');
             UPDATE meta SET value='t2' WHERE key='built';",
        )
        .unwrap();
        assert!(!ready(&c), "a newer build than the summaries");
        assert_eq!(check(&c).len(), 2);
        let written = refresh(&c).unwrap();
        assert!(written <= 4, "only changed keys are written ({written})");
        stamp(&c, "t2").unwrap();
        assert!(ready(&c) && check(&c).is_empty(), "{:?}", check(&c));
        let n: i64 = c.query_row("SELECT n FROM mv_import_fanin WHERE target='x.ts'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(refresh(&c).unwrap(), 0, "nothing changed: nothing written");
    }
}
