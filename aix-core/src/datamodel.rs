//! Data model tables. Per-file facts (entities, mapped fields, migrations, raw foreign keys, raw access facts) are
//! replaced when their file changes; the derived tables are recomputed from them only for what changed:
//! - `entity_columns`: fields with inherited columns and the table name resolved (rebuilt when an entity file changed);
//! - `fks`: foreign keys from migrations and entity relations, entity names resolved to tables;
//! - `migrations.ord`: the apply order (Flyway versions, timestamps, Alembic chains, Liquibase file order);
//! - `data_access`: which member reads or writes which table, from ORM calls on entities / repositories (joined from
//!   `refs`), and from SQL strings (joined to the enclosing member by line). Recomputed for the dirty files only,
//!   or in full when the entity -> table mapping itself changed.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use rusqlite::{params, Transaction};
use aix_extract::Rows;

use crate::index::Index;

/// Tables added after schema version 8: also created by `resolve`, so an index made by an older build gains them on its
/// next (REVISION-forced) re-extraction instead of needing a schema reset.
macro_rules! late_ddl {
    () => {
        r#"
-- lifecycle-state literals joined to a table: op set (val; from_vals = the states the same statement is guarded by) | test
CREATE TABLE IF NOT EXISTS state_refs(file TEXT, line INT, sline INT, symbol TEXT, tbl TEXT, col TEXT, op TEXT, val TEXT, from_vals TEXT);
CREATE INDEX IF NOT EXISTS state_refs_val ON state_refs(tbl, col, val);
CREATE INDEX IF NOT EXISTS state_refs_node ON state_refs(file, sline);
"#
    };
}
pub const LATE_DDL: &str = late_ddl!();

pub const SCHEMA: &str = concat!(r#"
CREATE TABLE IF NOT EXISTS entities(file TEXT, line INT, end_line INT, name TEXT, tbl TEXT, orm TEXT, supers TEXT, kind TEXT);
CREATE INDEX IF NOT EXISTS entities_file ON entities(file);
CREATE INDEX IF NOT EXISTS entities_name ON entities(name);
CREATE INDEX IF NOT EXISTS entities_tbl ON entities(tbl);
CREATE TABLE IF NOT EXISTS dm_fields(file TEXT, line INT, entity TEXT, field TEXT, col TEXT, ty TEXT, nullable INT, transient INT, pk INT, rel TEXT, flags TEXT);
CREATE INDEX IF NOT EXISTS dm_fields_file ON dm_fields(file);
CREATE TABLE IF NOT EXISTS migrations(file TEXT, line INT, version TEXT, tool TEXT, tbl TEXT, op TEXT, obj TEXT, col TEXT, detail TEXT, ord INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS migrations_tbl ON migrations(tbl, ord);
CREATE INDEX IF NOT EXISTS migrations_file ON migrations(file);
CREATE TABLE IF NOT EXISTS dm_fks(file TEXT, line INT, from_tbl TEXT, from_col TEXT, to_tbl TEXT, to_col TEXT, src TEXT);
CREATE INDEX IF NOT EXISTS dm_fks_file ON dm_fks(file);
CREATE TABLE IF NOT EXISTS dm_raw(file TEXT, line INT, kind TEXT, target TEXT, op TEXT, via TEXT, extra TEXT);
CREATE INDEX IF NOT EXISTS dm_raw_file ON dm_raw(file);
CREATE TABLE IF NOT EXISTS entity_columns(entity TEXT, tbl TEXT, field TEXT, col TEXT, ty TEXT, nullable INT, transient INT, pk INT, rel TEXT, flags TEXT,
  file TEXT, line INT, inherited INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS entity_columns_tbl ON entity_columns(tbl);
CREATE INDEX IF NOT EXISTS entity_columns_entity ON entity_columns(entity);
CREATE TABLE IF NOT EXISTS fks(file TEXT, line INT, from_tbl TEXT, from_col TEXT, to_tbl TEXT, to_col TEXT, src TEXT);
CREATE INDEX IF NOT EXISTS fks_from ON fks(from_tbl);
CREATE INDEX IF NOT EXISTS fks_to ON fks(to_tbl);
CREATE TABLE IF NOT EXISTS data_access(file TEXT, line INT, symbol TEXT, sline INT, tbl TEXT, entity TEXT, rw TEXT, via TEXT, conf TEXT);
CREATE INDEX IF NOT EXISTS data_access_tbl ON data_access(tbl, rw);
CREATE INDEX IF NOT EXISTS data_access_sym ON data_access(file, sline);
CREATE INDEX IF NOT EXISTS data_access_symbol ON data_access(symbol);
-- files whose data-model rows were dropped or added by this update (had: they carried data-model rows before)
CREATE TABLE IF NOT EXISTS dm_dirty(file TEXT PRIMARY KEY, had INT DEFAULT 0, fid INT DEFAULT 0);
"#, late_ddl!());

pub const FILE_TABLES: &[&str] = &["entities", "dm_fields", "migrations", "dm_fks", "dm_raw"];
/// Per-file tables plus derived ones: wiped by a full rebuild.
pub const WIPE_TABLES: &[&str] = &["entity_columns", "fks", "data_access", "state_refs"];

pub fn mark_dirty_file(tx: &Transaction, path: &str) -> Result<()> {
    let had: i64 = tx
        .prepare_cached(
            // 1: the file carried entities / mapped fields / repository declarations (entity -> table mapping), 2: migrations or foreign keys
            "SELECT (EXISTS(SELECT 1 FROM entities WHERE file=?1) OR EXISTS(SELECT 1 FROM dm_fields WHERE file=?1) OR EXISTS(SELECT 1 FROM dm_raw WHERE file=?1 AND kind='repo'))
                  + 2 * (EXISTS(SELECT 1 FROM migrations WHERE file=?1) OR EXISTS(SELECT 1 FROM dm_fks WHERE file=?1))",
        )?
        .query_row([path], |r| r.get(0))?;
    tx.prepare_cached(
        "INSERT INTO dm_dirty VALUES(?1, ?2, COALESCE((SELECT rowid FROM files WHERE path=?1), 0)) ON CONFLICT(file) DO UPDATE SET had = had | ?2, fid = excluded.fid",
    )?
    .execute(params![path, had])?;
    Ok(())
}

pub fn insert(tx: &Transaction, rows: &Rows) -> Result<()> {
    let rd = |s: &str| crate::par::rd(s);
    {
        let mut st = tx.prepare_cached("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?)")?;
        for e in &rows.entities {
            st.execute(params![e.file, e.line, e.end_line, e.name, e.table, e.orm, e.supers.join(","), e.kind])?;
        }
        let mut st = tx.prepare_cached("INSERT INTO dm_fields VALUES(?,?,?,?,?,?,?,?,?,?,?)")?;
        for x in &rows.entity_fields {
            st.execute(params![x.file, x.line, x.entity, x.field, x.column, x.ty, x.nullable, x.transient, x.pk, x.rel, rd(&x.flags)])?;
        }
        let mut st = tx.prepare_cached("INSERT INTO migrations VALUES(?,?,?,?,?,?,?,?,?,0)")?;
        for m in &rows.migrations {
            st.execute(params![m.file, m.line, m.version, m.tool, m.table, m.op, m.obj, m.column, rd(&m.detail)])?;
        }
        let mut st = tx.prepare_cached("INSERT INTO dm_fks VALUES(?,?,?,?,?,?,?)")?;
        for x in &rows.fks {
            st.execute(params![x.file, x.line, x.from_table, x.from_col, x.to_table, x.to_col, x.src])?;
        }
        let mut st = tx.prepare_cached("INSERT INTO dm_raw VALUES(?,?,?,?,?,?,?)")?;
        for x in &rows.data_raw {
            st.execute(params![x.file, x.line, x.kind, x.target, x.op, x.via, x.extra])?;
        }
    }
    let mut files: HashSet<&str> = HashSet::new();
    files.extend(rows.entities.iter().map(|x| x.file.as_str()));
    files.extend(rows.entity_fields.iter().map(|x| x.file.as_str()));
    files.extend(rows.migrations.iter().map(|x| x.file.as_str()));
    files.extend(rows.fks.iter().map(|x| x.file.as_str()));
    files.extend(rows.data_raw.iter().map(|x| x.file.as_str()));
    for f in files {
        tx.prepare_cached("INSERT OR IGNORE INTO dm_dirty VALUES(?1, 0, COALESCE((SELECT rowid FROM files WHERE path=?1), 0))")?.execute([f])?;
    }
    Ok(())
}

/// Dotted-number sort key: "1.10" > "1.2".
fn vkey(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap_or(0)).collect()
}

/// Assign the apply order: `ord` is the position of the migration file in its project-wide order.
fn order_migrations(tx: &Transaction) -> Result<()> {
    // (file, version, tool) of every migration file, with the first line for Liquibase
    let mut files: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut revs: HashMap<String, (String, String)> = HashMap::new(); // alembic: revision -> (down, file)
    {
        let mut st = tx.prepare("SELECT file, version, tool, obj, detail FROM migrations GROUP BY file, version, tool, obj")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?)))?;
        for r in rows {
            let (f, v, t, obj, d) = r?;
            if t == "alembic" && obj == "revision" {
                revs.insert(v.clone(), (d.trim_start_matches("down=").to_string(), f.clone()));
            }
            files.entry(f).or_insert((v, t));
        }
    }
    let mut depth_cache: HashMap<String, u64> = HashMap::new();
    fn depth(rev: &str, revs: &HashMap<String, (String, String)>, cache: &mut HashMap<String, u64>, guard: u32) -> u64 {
        if let Some(d) = cache.get(rev) {
            return *d;
        }
        let d = match revs.get(rev) {
            Some((down, _)) if !down.is_empty() && guard < 5000 => 1 + depth(down, revs, cache, guard + 1),
            _ => 0,
        };
        cache.insert(rev.to_string(), d);
        d
    }
    // sort key per file: (tool rank, kind rank, numeric version, file)
    let mut keyed: Vec<((u8, u8, Vec<u64>, String), String)> = vec![];
    for (f, (v, t)) in &files {
        let key = match t.as_str() {
            // a schema dump states the result of every migration: it comes last
            _ if t == "rails-schema" || f.ends_with("db/structure.sql") => (9, 0, vec![], f.clone()),
            "flyway" if v == "R" => (0, 1, vec![], f.clone()),
            "flyway" => (0, 0, vkey(v), f.clone()),
            "alembic" => (2, 0, vec![depth(v, &revs, &mut depth_cache, 0)], f.clone()),
            "liquibase" => (3, 0, vec![], f.clone()),
            "django" => (4, 0, vec![], f.clone()),
            "rails" => (1, 0, vkey(v), f.clone()),
            "prisma" => (1, 0, vkey(v), f.clone()),
            _ => (1, 0, vkey(v), f.clone()),
        };
        keyed.push((key, f.clone()));
    }
    keyed.sort();
    let mut up = tx.prepare("UPDATE migrations SET ord=? WHERE file=? AND ord<>?")?;
    for (i, (_, f)) in keyed.iter().enumerate() {
        up.execute(params![i as i64 + 1, f, i as i64 + 1])?;
    }
    Ok(())
}

/// Members (fid, declaration line) called, through resolved edges up to 4 hops, from a method that runs in a
/// transaction (@Transactional on it or its class, or a REST verb method): they run inside the caller's transaction.
fn tx_reach(tx: &Transaction) -> Result<HashSet<(i64, i64)>> {
    let mut classes: HashSet<(String, String)> = HashSet::new();
    let mut seeds: Vec<(i64, i64)> = vec![];
    {
        let mut st = tx.prepare("SELECT file, qname FROM members WHERE kind IN ('class','interface','record') AND annos LIKE '%Transactional%' AND file LIKE '%.java'")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            classes.insert(r?);
        }
        let mut st = tx.prepare("SELECT f.rowid, m.line, m.file, COALESCE(m.container,''), m.annos FROM members m JOIN files f ON f.path=m.file WHERE m.kind IN ('method','ctor') AND m.file LIKE '%.java'")?;
        for r in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?)))? {
            let (fid, line, file, cont, annos) = r?;
            let verb = annos.split(',').any(|a| matches!(a.trim(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE"));
            if verb || annos.contains("Transactional") || classes.contains(&(file, cont)) {
                seeds.push((fid, line));
            }
        }
    }
    let mut adj: HashMap<(i64, i64), Vec<(i64, i64)>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT fid, caller_line, cfid, callee_line FROM call_edges WHERE kind IN ('call','new') AND caller_line>0 AND conf<>'name'")?;
        for r in st.query_map([], |r| Ok(((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?), (r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))))? {
            let (a, b) = r?;
            adj.entry(a).or_default().push(b);
        }
    }
    let mut seen: HashSet<(i64, i64)> = HashSet::new();
    let mut frontier = seeds;
    for _ in 0..4 {
        let mut next = vec![];
        for n in &frontier {
            for &m in adj.get(n).into_iter().flatten() {
                if seen.insert(m) {
                    next.push(m);
                }
            }
        }
        frontier = next;
    }
    Ok(seen)
}

fn orm_op(callee: &str) -> Option<&'static str> {
    const W: &[&str] = &[
        "persist", "persistAndFlush", "persistAll", "delete", "deleteAll", "deleteById", "deleteAllById", "deleteInBatch", "update", "merge", "remove", "save",
        "saveAll", "saveAndFlush", "insert", "upsert", "truncate", "softRemove", "create", "createMany", "bulkCreate",
    ];
    const R: &[&str] = &[
        "find", "findAll", "findById", "findOne", "findAllById", "list", "listAll", "count", "exists", "existsById", "stream", "streamAll", "getById", "getOne",
        "getReferenceById", "findFirst", "findMany", "findUnique", "findByIdOptional", "findAllInRange", "page", "firstResult", "singleResult", "listAllPaged",
    ];
    if W.contains(&callee) {
        return Some("w");
    }
    if R.contains(&callee) {
        return Some("r");
    }
    for (p, op) in [
        ("deleteBy", "w"),
        ("removeBy", "w"),
        ("saveAll", "w"),
        ("updateBy", "w"),
        ("findBy", "r"),
        ("findAllBy", "r"),
        ("findFirstBy", "r"),
        ("findTopBy", "r"),
        ("findDistinctBy", "r"),
        ("readBy", "r"),
        ("getBy", "r"),
        ("queryBy", "r"),
        ("streamBy", "r"),
        ("countBy", "r"),
        ("existsBy", "r"),
        ("find", "r"),
        ("list", "r"),
        ("count", "r"),
        ("delete", "w"),
        ("update", "w"),
    ] {
        if callee.starts_with(p) && callee[p.len()..].chars().next().is_some_and(|c| c.is_uppercase()) {
            return Some(op);
        }
    }
    None
}

/// Recompute the derived data-model tables for what changed. Called after the call graph is resolved.
pub fn resolve(ix: &mut Index, full: bool) -> Result<bool> {
    let dirty: Vec<(String, i64)> = {
        let mut st = ix.conn.prepare("SELECT file, had FROM dm_dirty")?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        r
    };
    let built = ix.meta("dm_built").is_some();
    let full = full || !built;
    let tx = ix.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch(LATE_DDL)?;
    // does the entity -> table mapping (or a repository / entity class body) possibly differ?
    let touched = |tx: &Transaction, table: &str, f: &str| -> bool {
        tx.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE file=?)"), [f], |r| r.get::<_, i64>(0)).unwrap_or(0) == 1
    };
    let mut ent_changed = full;
    let mut mig_changed = full;
    let mut fks_changed = full;
    let mut raw_changed = full;
    for (f, had) in &dirty {
        let ent_now = touched(&tx, "entities", f) || touched(&tx, "dm_fields", f);
        let repo_now: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM dm_raw WHERE file=? AND kind='repo')", [f], |r| r.get::<_, i64>(0)).unwrap_or(0) == 1;
        let mig_now = touched(&tx, "migrations", f) || touched(&tx, "dm_fks", f);
        ent_changed |= ent_now || repo_now || (*had & 1) != 0;
        mig_changed |= mig_now || (*had & 2) != 0;
        fks_changed |= mig_now || (*had & 2) != 0;
        raw_changed = true;
    }
    if dirty.is_empty() && !full {
        tx.commit()?;
        return Ok(false);
    }
    if mig_changed {
        { let _s = crate::par::span("dm:order_migrations"); order_migrations(&tx)?; }
    }
    if ent_changed || fks_changed {
        { let _s = crate::par::span("dm:rebuild_entities"); rebuild_entities(&tx)?; }
    }
    // data_access: all rows when the mapping changed or the set of known tables did (a native query on a table that now
    // exists is `resolved`, not `name`), else the dirty files only
    let known_sig: String = {
        let mut st = tx.prepare("SELECT DISTINCT tbl FROM migrations WHERE obj IN ('table','view') UNION SELECT tbl FROM entities WHERE tbl<>'' ORDER BY 1")?;
        let v: Vec<String> = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
        format!("{}:{:x}", v.len(), v.iter().fold(0xcbf29ce484222325u64, |h, t| t.bytes().chain([0u8]).fold(h, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))))
    };
    let known_changed = tx.query_row("SELECT value FROM meta WHERE key='dm_known'", [], |r| r.get::<_, String>(0)).ok().as_deref() != Some(known_sig.as_str());
    tx.execute("INSERT OR REPLACE INTO meta VALUES('dm_known', ?)", [&known_sig])?;
    let fn_changed = mig_changed && tx.query_row("SELECT EXISTS(SELECT 1 FROM migrations WHERE obj='function')", [], |r| r.get::<_, i64>(0)).unwrap_or(0) == 1;
    let all_access = full || ent_changed || known_changed || fn_changed;
    let dirty_files: HashSet<String> = dirty.iter().map(|d| d.0.clone()).collect();
    if raw_changed || all_access {
        { let _s = crate::par::span("dm:rebuild_access"); rebuild_access(&tx, all_access, &dirty_files)?; }
        { let _s = crate::par::span("dm:rebuild_state"); rebuild_state(&tx, all_access, &dirty_files)?; }
    }
    tx.execute("INSERT OR REPLACE INTO meta VALUES('dm_built', ?)", [crate::index::chrono_now()])?;
    tx.commit()?;
    Ok(true)
}

fn rebuild_entities(tx: &Transaction) -> Result<()> {
    tx.execute("DELETE FROM entity_columns", [])?;
    tx.execute("DELETE FROM fks", [])?;
    struct E {
        tbl: String,
        file: String,
        supers: Vec<String>,
        kind: String,
    }
    let mut ents: HashMap<String, Vec<E>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT name, tbl, file, supers, kind FROM entities")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?)))?;
        for r in rows {
            let (n, t, f, s, k) = r?;
            ents.entry(n).or_default().push(E { tbl: t, file: f, supers: s.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect(), kind: k });
        }
    }
    type F = (String, i64, String, String, String, String, i64, i64, i64, String, String);
    let mut fields: HashMap<(String, String), Vec<F>> = HashMap::new(); // (entity, file) -> fields
    {
        let mut st = tx.prepare("SELECT file, line, entity, field, col, ty, nullable, transient, pk, rel, flags FROM dm_fields ORDER BY file, line")?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?, r.get::<_, i64>(8)?, r.get::<_, String>(9)?, r.get::<_, String>(10)?))
        })?;
        for r in rows {
            let x = r?;
            fields.entry((x.2.clone(), x.0.clone())).or_default().push(x);
        }
    }
    let mut ins = tx.prepare("INSERT INTO entity_columns VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
    for (name, defs) in &ents {
        for d in defs {
            if d.kind != "entity" {
                continue;
            }
            // own fields, then the fields of mapped superclasses (nearest first)
            let mut chain: Vec<(String, String, bool)> = vec![(name.clone(), d.file.clone(), false)];
            let mut seen: HashSet<String> = HashSet::from([name.clone()]);
            let mut stack: Vec<String> = d.supers.clone();
            while let Some(s) = stack.pop() {
                if !seen.insert(s.clone()) {
                    continue;
                }
                if let Some(sd) = ents.get(&s) {
                    for x in sd.iter().filter(|x| x.kind != "entity") {
                        chain.push((s.clone(), x.file.clone(), true));
                        stack.extend(x.supers.clone());
                    }
                }
            }
            let mut have: HashSet<String> = HashSet::new();
            for (en, ef, inherited) in chain {
                for x in fields.get(&(en.clone(), ef)).into_iter().flatten() {
                    if !have.insert(x.3.clone()) {
                        continue;
                    }
                    ins.execute(params![name, d.tbl, x.3, x.4, x.5, x.6, x.7, x.8, x.9, x.10, x.0, x.1, inherited])?;
                }
            }
        }
    }
    // foreign keys: entity names resolved to tables
    let tbl_of = |n: &str| -> String {
        let n = n.strip_prefix("entity:").unwrap_or(n);
        ents.get(n).and_then(|v| v.iter().find(|e| e.kind == "entity").map(|e| e.tbl.clone())).unwrap_or_else(|| n.to_lowercase())
    };
    let mut st = tx.prepare("SELECT file, line, from_tbl, from_col, to_tbl, to_col, src FROM dm_fks")?;
    let rows: Vec<(String, i64, String, String, String, String, String)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?.collect::<Result<_, _>>()?;
    let mut insf = tx.prepare("INSERT INTO fks VALUES(?,?,?,?,?,?,?)")?;
    for (f, l, ft, fc, tt, tc, src) in rows {
        let (ft2, tt2) = (if ft.starts_with("entity:") { tbl_of(&ft) } else { ft }, if tt.starts_with("entity:") { tbl_of(&tt) } else { tt });
        let tt2 = tt2.strip_prefix("table:").map(str::to_string).unwrap_or(tt2);
        insf.execute(params![f, l, ft2, fc, tt2, tc, src])?;
    }
    Ok(())
}

#[derive(Clone)]
struct Mem {
    qname: String,
    line: i64,
    end: i64,
    container: String,
    kind: String,
}

/// `state_refs`: the lifecycle-state literals of `dm_raw` (kind `state`) joined to the table whose column they name. A literal
/// belongs to a table when (1) a field read of an entity with that column sits on its line (`r.status`), (2) the same
/// SQL / JPQL literal names the table, or (3) the member holds a data access to a table with that column within 8 lines.
fn rebuild_state(tx: &Transaction, all: bool, dirty: &HashSet<String>) -> Result<()> {
    if all {
        tx.execute("DELETE FROM state_refs", [])?;
    } else {
        let mut d = tx.prepare("DELETE FROM state_refs WHERE file=?")?;
        for f in dirty {
            d.execute([f])?;
        }
    }
    let norm = |s: &str| s.to_lowercase().replace('_', "");
    // table -> normalised column / field names; entity -> tables
    let mut cols: HashMap<String, HashSet<String>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT tbl, field, col FROM entity_columns")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (t, f, c) = r?;
            let e = cols.entry(t).or_default();
            e.insert(norm(&f));
            e.insert(norm(&c));
        }
    }
    let mut ent_tbl: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT name, tbl FROM entities WHERE kind='entity'")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (n, t) = r?;
            ent_tbl.entry(n).or_default().push(t);
        }
    }
    let has_col = |t: &str, c: &str| cols.get(t).is_some_and(|s| s.contains(&norm(c)));
    let scope = if all { String::new() } else { format!(" AND file IN ({})", dirty.iter().map(|d| format!("'{}'", d.replace('\'', "''"))).collect::<Vec<_>>().join(",")) };
    let raws: Vec<(String, i64, String, String, String, String)> = {
        let mut st = tx.prepare(&format!("SELECT file, line, target, op, extra, via FROM dm_raw WHERE kind='state'{scope} ORDER BY file, line"))?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect::<Result<_, _>>()?;
        r
    };
    if raws.is_empty() {
        return Ok(());
    }
    let mut mem_cache: HashMap<String, Vec<Mem>> = HashMap::new();
    let mut ins = tx.prepare("INSERT INTO state_refs VALUES(?,?,?,?,?,?,?,?,?)")?;
    let mut seen: HashSet<(String, i64, String, String, String, String)> = HashSet::new();
    for (file, line, col, op, extra, via) in raws {
        let hint = via.strip_prefix("state:").unwrap_or("").to_string(); // the table / entity the literal's alias names
        let hinted = |t: &str, ent_tbl: &HashMap<String, Vec<String>>| -> bool {
            hint.is_empty() || t.eq_ignore_ascii_case(&hint) || ent_tbl.iter().any(|(n, ts)| n.eq_ignore_ascii_case(&hint) && ts.iter().any(|x| x == t))
        };
        if !mem_cache.contains_key(&file) {
            let mut st = tx.prepare_cached("SELECT qname, line, end_line, COALESCE(container,''), kind FROM members WHERE file=? AND kind IN ('method','ctor','function','component','field','const') ORDER BY line")?;
            let v: Vec<Mem> = st
                .query_map([&file], |r| Ok(Mem { qname: r.get(0)?, line: r.get(1)?, end: r.get(2)?, container: r.get(3)?, kind: r.get(4)? }))?
                .collect::<Result<_, _>>()?;
            mem_cache.insert(file.clone(), v);
        }
        let Some(m) = mem_cache[&file].iter().filter(|m| m.line <= line && line <= m.end).min_by_key(|m| m.end - m.line) else { continue };
        let (sym, sline) = (m.qname.clone(), m.line);
        let mut tbls: Vec<String> = vec![];
        // (1) a field read / write of that name on this line
        {
            let mut st = tx.prepare_cached("SELECT r.recv_type FROM files f CROSS JOIN refs r INDEXED BY refs_file ON r.fid=f.rowid WHERE f.path=? AND r.line BETWEEN ? AND ? AND r.kind='field' AND r.callee=? ORDER BY r.rowid")?;
            for rt in st.query_map(params![file, line - 1, line + 1, col], |r| r.get::<_, String>(0))?.flatten() {
                for t in ent_tbl.get(&rt).into_iter().flatten() {
                    if has_col(t, &col) && hinted(t, &ent_tbl) && !tbls.contains(t) {
                        tbls.push(t.clone());
                    }
                }
            }
        }
        // (2) the SQL / JPQL literal names the table or an entity
        if tbls.is_empty() {
            let mut st = tx.prepare_cached("SELECT kind, target FROM dm_raw WHERE file=? AND line=? AND kind IN ('table','jpql')")?;
            for (k, target) in st.query_map(params![file, line], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.flatten() {
                let cand: Vec<String> = if k == "jpql" { ent_tbl.get(&target).cloned().unwrap_or_default() } else { vec![target] };
                for t in cand {
                    if has_col(&t, &col) && hinted(&t, &ent_tbl) && !tbls.contains(&t) {
                        tbls.push(t);
                    }
                }
            }
        }
        // (3) the member's own data access nearby
        if tbls.is_empty() {
            let mut st = tx.prepare_cached("SELECT DISTINCT tbl, abs(line - ?3) FROM data_access WHERE file=?1 AND sline=?2 AND abs(line - ?3) <= 8 ORDER BY 2")?;
            for t in st.query_map(params![file, sline, line], |r| r.get::<_, String>(0))?.flatten() {
                if has_col(&t, &col) && hinted(&t, &ent_tbl) && !tbls.contains(&t) {
                    tbls.push(t);
                }
            }
        }
        let (val, from) = match op.as_str() {
            "set" => extra.split_once('|').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((extra.clone(), String::new())),
            _ => (extra.clone(), String::new()),
        };
        for t in tbls {
            if seen.insert((file.clone(), line, t.clone(), col.clone(), op.clone(), val.clone())) {
                ins.execute(params![file, line, sline, sym, t, col, op, val, from])?;
            }
        }
    }
    Ok(())
}

fn rebuild_access(tx: &Transaction, all: bool, dirty: &HashSet<String>) -> Result<()> {
    if all {
        tx.execute("DELETE FROM data_access", [])?;
    } else {
        let mut d = tx.prepare("DELETE FROM data_access WHERE file=?")?;
        for f in dirty {
            d.execute([f])?;
        }
    }
    // entity name -> tables; repository -> entity names; known tables
    let mut ent_tbl: HashMap<String, Vec<(String, String)>> = HashMap::new(); // name -> [(tbl, orm)]
    let mut ent_files: HashSet<String> = HashSet::new();
    // tables the migrations / schema dump define: a table named by convention (ActiveRecord, Eloquent, EF Core, GORM
    // pluralise the class name) that the schema does not have is a wrong guess (a prefix, a custom name), not a table
    let mig_tbls: HashSet<String> = {
        let mut st = tx.prepare("SELECT DISTINCT tbl FROM migrations WHERE obj IN ('table','view')")?;
        let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
        v
    };
    {
        let mut st = tx.prepare("SELECT name, tbl, orm, file FROM entities WHERE kind='entity'")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)))? {
            let (n, t, o, f) = r?;
            if matches!(o.as_str(), "activerecord" | "eloquent" | "efcore" | "gorm" | "sqlmodel") && !mig_tbls.is_empty() && !mig_tbls.contains(&t) {
                continue;
            }
            ent_tbl.entry(n).or_default().push((t, o));
            ent_files.insert(f);
        }
    }
    // EF Core: an explicit `ToTable("x")` / `[Table("x")]` replaces the DbSet-name convention
    for v in ent_tbl.values_mut() {
        if v.iter().any(|x| x.1 == "efcore-table") {
            v.retain(|x| x.1 != "efcore");
        }
        v.dedup();
    }
    let mut repo_ent: HashMap<String, Vec<String>> = HashMap::new();
    let mut repo_files: HashSet<String> = HashSet::new();
    {
        let mut st = tx.prepare("SELECT target, extra, file FROM dm_raw WHERE kind='repo'")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (t, e, f) = r?;
            repo_ent.entry(t).or_default().push(e);
            repo_files.insert(f);
        }
    }
    let mut known: HashSet<String> = HashSet::new();
    {
        let mut st = tx.prepare("SELECT DISTINCT tbl FROM migrations WHERE obj IN ('table','view') UNION SELECT tbl FROM entities WHERE tbl<>''")?;
        for r in st.query_map([], |r| r.get::<_, String>(0))? {
            known.insert(r?);
        }
    }
    // members that are declared inside entities / repositories (custom finders are real call-graph edges)
    let mut custom: HashSet<(String, String)> = HashSet::new();
    {
        let mut st = tx.prepare("SELECT container, name, annos FROM members WHERE kind IN ('method','ctor') AND container IS NOT NULL")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (c, n, a) = r?;
            if ent_tbl.contains_key(&c) || (repo_ent.contains_key(&c) && a.contains("Query")) {
                custom.insert((c, n));
            }
        }
    }
    let mut ins = tx.prepare("INSERT INTO data_access VALUES(?,?,?,?,?,?,?,?,?)")?;
    let mut seen: HashSet<(String, String, i64, String, String, String)> = HashSet::new();
    let mut put = |ins: &mut rusqlite::Statement, file: &str, line: i64, sym: &str, sline: i64, tbl: &str, ent: &str, rw: &str, via: &str, conf: &str| -> Result<()> {
        if !seen.insert((file.to_string(), sym.to_string(), sline, tbl.to_string(), rw.to_string(), via.to_string())) {
            return Ok(());
        }
        ins.execute(params![file, line, sym, sline, tbl, ent, rw, via, conf])?;
        Ok(())
    };
    // 1. ORM calls through refs
    tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS dm_types(name TEXT PRIMARY KEY); DELETE FROM dm_types;")?;
    {
        let mut st = tx.prepare("INSERT OR IGNORE INTO dm_types VALUES(?)")?;
        for n in ent_tbl.keys().chain(repo_ent.keys()) {
            st.execute([n])?;
        }
    }
    let scope = if all {
        String::new()
    } else {
        format!(" AND f.path IN ({})", dirty.iter().map(|d| format!("'{}'", d.replace('\'', "''"))).collect::<Vec<_>>().join(","))
    };
    let own_files: HashSet<&String> = ent_files.iter().chain(repo_files.iter()).collect();
    let sql = format!(
        "SELECT f.path, r.line, r.caller_line, r.callee, r.recv, r.recv_type, r.conf,
           COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=r.caller_line AND m.kind IN ('method','ctor','function','component','field','const') LIMIT 1), ''),
           COALESCE((SELECT m.container FROM members m WHERE m.file=f.path AND m.line=r.caller_line AND m.kind IN ('method','ctor','function','component','field','const') LIMIT 1), '')
         FROM refs r JOIN files f ON f.rowid=r.fid
         WHERE r.kind='call' AND r.caller_line>0 AND f.path LIKE '%.java'{scope}
           AND (r.recv_type IN (SELECT name FROM dm_types) OR r.recv IN ('', 'this', 'super'))"
    );
    {
        let mut st = tx.prepare(&sql)?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let (file, line, cl, callee, recv, rt, conf, qname, container): (String, i64, i64, String, String, String, String, String, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?);
            // which type does the call go to?
            let ty = if !rt.is_empty() && (ent_tbl.contains_key(&rt) || repo_ent.contains_key(&rt)) {
                rt.clone()
            } else if (recv.is_empty() || recv == "this" || recv == "super") && own_files.contains(&file) && (ent_tbl.contains_key(&container) || repo_ent.contains_key(&container)) {
                container.clone()
            } else {
                continue;
            };
            let Some(op) = orm_op(&callee) else { continue };
            if custom.contains(&(ty.clone(), callee.clone())) {
                continue; // a method the class declares itself: the call-graph edge carries it
            }
            let (via, tables): (&str, Vec<(String, String)>) = if let Some(t) = ent_tbl.get(&ty) {
                ("orm", t.iter().map(|x| (x.0.clone(), ty.clone())).collect())
            } else {
                let mut v = vec![];
                for e in repo_ent.get(&ty).into_iter().flatten() {
                    for t in ent_tbl.get(e).into_iter().flatten() {
                        v.push((t.0.clone(), e.clone()));
                    }
                }
                ("repo", v)
            };
            let c = if conf == "exact" { "exact" } else { "resolved" };
            for (t, e) in tables {
                put(&mut ins, &file, line, &qname, cl, &t, &e, op, via, c)?;
            }
        }
    }
    // 1b. JPA dirty checking: a field assignment / setter on an entity looked up in the same method is flushed at commit
    // when the method runs in a transaction (@Transactional on it or its class, or a REST resource method). A helper that
    // has no transaction of its own but is called (up to 4 hops, resolved edges) from such a method runs inside the
    // caller's transaction: its writes belong to the caller's endpoints. An entity handed in as a parameter is NOT
    // assumed managed (validators and mappers fill request bodies that are never persisted). A method that detaches or copies entities, or builds a new one of that type, before the assignment is left out: the
    // assignment may hit an unmanaged object that is never persisted
    {
        let mut in_tx: Option<HashSet<(i64, i64)>> = None; // computed on the first candidate only
        let transient: HashSet<(String, String)> = {
            let mut st = tx.prepare("SELECT entity, field FROM dm_fields WHERE transient=1")?;
            let v = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<_, _>>()?;
            v
        };
        let sql = format!(
            "SELECT f.path, r.line, r.caller_line, r.recv_type,
               COALESCE((SELECT m.qname FROM members m WHERE m.file=f.path AND m.line=r.caller_line AND m.kind IN ('method','ctor','function') LIMIT 1), ''),
               COALESCE((SELECT m.annos FROM members m WHERE m.file=f.path AND m.line=r.caller_line AND m.kind IN ('method','ctor','function') LIMIT 1), ''),
               COALESCE((SELECT c.annos FROM members c WHERE c.file=f.path AND c.kind IN ('class','interface','record')
                         AND c.qname=(SELECT m.container FROM members m WHERE m.file=f.path AND m.line=r.caller_line AND m.kind IN ('method','ctor','function') LIMIT 1) LIMIT 1), ''),
               r.fid, r.callee
             FROM refs r JOIN files f ON f.rowid=r.fid
             WHERE r.kind='fwrite' AND r.caller_line>0 AND f.path LIKE '%.java'{scope} AND r.recv_type IN (SELECT name FROM dm_types)
               AND NOT EXISTS (SELECT 1 FROM refs d WHERE d.fid=r.fid AND d.caller_line=r.caller_line AND d.line<=r.line
                               AND (d.callee IN ('detach','clone','copy','copyOf','toBuilder') OR (d.kind='new' AND d.callee=r.recv_type)))"
        );
        let mut st = tx.prepare(&sql)?;
        let mut rows = st.query([])?;
        while let Some(r) = rows.next()? {
            let (file, line, cl, rt, qname, annos, cannos, fid, callee): (String, i64, i64, String, String, String, String, i64, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?);
            // display-only fields (@Transient) are never flushed
            let fld = match callee.strip_prefix("set") {
                Some(rest) if rest.chars().next().is_some_and(|c| c.is_uppercase()) => {
                    let mut cs = rest.chars();
                    cs.next().map(|c| c.to_lowercase().collect::<String>() + cs.as_str()).unwrap_or_default()
                }
                _ => callee.clone(),
            };
            if transient.contains(&(rt.clone(), fld)) {
                continue;
            }
            let verb = annos.split(',').any(|a| matches!(a.trim(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE"));
            let own_tx = annos.contains("Transactional") || cannos.contains("Transactional") || verb;
            if in_tx.is_none() {
                in_tx = Some(tx_reach(&tx)?);
            }
            let helper = in_tx.as_ref().is_some_and(|s| s.contains(&(fid, cl)));
            let ok = own_tx || helper;
            if !ok {
                continue;
            }
            for (t, _) in ent_tbl.get(&rt).into_iter().flatten() {
                put(&mut ins, &file, line, &qname, cl, t, &rt, "w", "orm", "resolved")?;
            }
        }
    }
    // 2. SQL strings and ORM facts of other stacks: raw rows joined to the enclosing member
    let sql = format!(
        "SELECT file, line, kind, target, op, via, extra FROM dm_raw WHERE kind IN ('table','jpql','entity','fncall'){}",
        if all { String::new() } else { format!(" AND file IN ({})", dirty.iter().map(|d| format!("'{}'", d.replace('\'', "''"))).collect::<Vec<_>>().join(",")) }
    );
    let raws: Vec<(String, i64, String, String, String, String, String)> = {
        let mut st = tx.prepare(&sql)?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)))?.collect::<Result<_, _>>()?;
        r
    };
    let mut mem_cache: HashMap<String, Vec<Mem>> = HashMap::new();
    // SQL functions defined in migrations: name -> (tables read, tables written) from the detail the extractor left
    let mut sql_fns: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT tbl, detail FROM migrations WHERE obj='function' ORDER BY ord, file, line")?;
        for r in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (n, d) = r?;
            let e = sql_fns.entry(n.rsplit('.').next().unwrap_or(&n).to_lowercase()).or_default();
            if d.contains(" r:") || d.contains(" w:") {
                *e = (vec![], vec![]); // the newest definition wins
            }
            for part in d.split_whitespace() {
                if let Some(l) = part.strip_prefix("r:") {
                    e.0.extend(l.split(',').map(str::to_string));
                } else if let Some(l) = part.strip_prefix("w:") {
                    e.1.extend(l.split(',').map(str::to_string));
                }
            }
        }
    }
    for (file, line, kind, target, op, _via, extra) in raws {
        if !mem_cache.contains_key(&file) {
            let mut st = tx.prepare_cached("SELECT qname, line, end_line, COALESCE(container,''), kind FROM members WHERE file=? AND kind IN ('method','ctor','function','component','field','const') ORDER BY line")?;
            let v: Vec<Mem> = st
                .query_map([&file], |r| Ok(Mem { qname: r.get(0)?, line: r.get(1)?, end: r.get(2)?, container: r.get(3)?, kind: r.get(4)? }))?
                .collect::<Result<_, _>>()?;
            mem_cache.insert(file.clone(), v);
        }
        let ms = &mem_cache[&file];
        let m = ms.iter().filter(|m| m.line <= line && line <= m.end).min_by_key(|m| m.end - m.line);
        // outside any method (a Rails `scope :x, -> { where(..) }`, a class-body statement): the enclosing class
        let cls = if m.is_none() {
            let mut st = tx.prepare_cached("SELECT qname, line FROM members WHERE file=? AND kind IN ('class','module','struct','record','object') AND line<=? AND end_line>=? ORDER BY end_line-line LIMIT 1")?;
            st.query_row(params![file, line, line], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).ok()
        } else {
            None
        };
        let (sym, sline) = m.map(|m| (m.qname.clone(), m.line)).or(cls).unwrap_or_else(|| (format!("{file} (file level)"), 0));
        let _ = m.map(|m| (&m.container, &m.kind));
        match kind.as_str() {
            "fncall" => {
                if let Some((rd, wr)) = sql_fns.get(&target) {
                    let via = format!("sql function {target}");
                    for (list, rw) in [(rd, "r"), (wr, "w")] {
                        for t in list.iter().filter(|t| known.contains(*t)) {
                            put(&mut ins, &file, line, &sym, sline, t, "", rw, &via, "resolved")?;
                        }
                    }
                }
            }
            "table" => {
                let known_tbl = known.contains(&target);
                // a native query on a table the project does not define is kept but marked name-level
                put(&mut ins, &file, line, &sym, sline, &target, "", &op, "native", if known_tbl { "resolved" } else { "name" })?;
            }
            "jpql" => {
                for t in ent_tbl.get(&target).into_iter().flatten() {
                    put(&mut ins, &file, line, &sym, sline, &t.0, &target, &op, "jpql", "resolved")?;
                }
            }
            _ => {
                // entity-name facts of Python / TypeScript ORMs: match a class / model / table variable
                let mut hits: Vec<(String, String)> = vec![];
                if let Some(t) = ent_tbl.get(&target) {
                    hits.extend(t.iter().map(|x| (x.0.clone(), target.clone())));
                } else if let Some(es) = repo_ent.get(&target).filter(|_| extra == "efcore") {
                    // an EF Core DbSet property (`_db.Orders`): the entity it holds
                    for e in es {
                        hits.extend(ent_tbl.get(e).into_iter().flatten().map(|x| (x.0.clone(), e.clone())));
                    }
                } else if extra == "prisma" {
                    for (n, ts) in &ent_tbl {
                        let lc = n.chars().next().map(|c| c.to_lowercase().collect::<String>() + &n[c.len_utf8()..]).unwrap_or_default();
                        if lc == target && ts.iter().any(|t| t.1 == "prisma") {
                            hits.extend(ts.iter().map(|x| (x.0.clone(), n.clone())));
                        }
                    }
                }
                for (t, e) in hits {
                    put(&mut ins, &file, line, &sym, sline, &t, &e, &op, "orm", "resolved")?;
                }
            }
        }
    }
    Ok(())
}
