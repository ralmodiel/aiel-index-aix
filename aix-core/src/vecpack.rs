//! Packed vector matrices for the semantic search: the embedded entries of one kind as three BLOBs (ids, vector
//! lengths, vectors), so a query reads one row instead of joining `entries` with `vectors` row by row (a scan of
//! every entry plus one overflow-page chain per vector: 2.6k bug vectors = 10.8 MB, about 10 ms).
//!
//! Exactness: a pack holds the same f32 bytes, the same rows (the ones the join returned and decoded) in the same
//! (id) order, so scores, sort order and ties are unchanged. A pack is used only while the kind's generation counter
//! (`meta` key `sem_gen:<kind>`) equals the one it was written at. The counter is created by the transaction that
//! installs [`KIND_GEN_DDL`] and writes the first pack, and from then on those triggers move it on every change that
//! could change the pack (an embedded entry of the kind added, removed or changed; a vector of one of its
//! signatures added, removed or replaced). A kind without a counter is never served from a pack.

use rusqlite::{params, Connection, OptionalExtension};

/// The pack table and the per-kind generation triggers (installed with the first pack).
pub(crate) const KIND_GEN_DDL: &str = "CREATE TABLE IF NOT EXISTS vec_pack(kind TEXT PRIMARY KEY, gen TEXT NOT NULL, ids BLOB NOT NULL, lens BLOB NOT NULL, vecs BLOB NOT NULL, files TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS entries_semk_ai AFTER INSERT ON entries WHEN NEW.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen:#kinds' AND NEW.kind<>'code' AND NOT EXISTS (SELECT 1 FROM meta WHERE key='sem_gen:'||NEW.kind); UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen:'||NEW.kind; END;
CREATE TRIGGER IF NOT EXISTS entries_semk_ad AFTER DELETE ON entries WHEN OLD.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen:'||OLD.kind; END;
CREATE TRIGGER IF NOT EXISTS entries_semk_au AFTER UPDATE ON entries WHEN OLD.sem=1 OR NEW.sem=1 BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='sem_gen:#kinds' AND NEW.sem=1 AND NEW.kind<>'code' AND NOT EXISTS (SELECT 1 FROM meta WHERE key='sem_gen:'||NEW.kind); UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key IN ('sem_gen:'||OLD.kind, 'sem_gen:'||NEW.kind); END;
CREATE TRIGGER IF NOT EXISTS vectors_semk_ai AFTER INSERT ON vectors WHEN substr(NEW.sig,1,2)<>'q:' BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key IN (SELECT 'sem_gen:'||kind FROM entries WHERE sig=NEW.sig AND sem=1); END;
CREATE TRIGGER IF NOT EXISTS vectors_semk_ad AFTER DELETE ON vectors WHEN substr(OLD.sig,1,2)<>'q:' BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key IN (SELECT 'sem_gen:'||kind FROM entries WHERE sig=OLD.sig AND sem=1); END;
CREATE TRIGGER IF NOT EXISTS vectors_semk_au AFTER UPDATE ON vectors BEGIN UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key IN (SELECT 'sem_gen:'||kind FROM entries WHERE sig IN (OLD.sig, NEW.sig) AND sem=1); END;";

/// The embedded entries of one kind, in id order: ids, files, and the vectors laid end to end.
#[derive(Default)]
pub(crate) struct KindMat {
    pub ids: Vec<i64>,
    pub files: Vec<String>,
    pub offs: Vec<usize>, // vector i is flat[offs[i]..offs[i + 1]]
    pub flat: Vec<f32>,
}

impl KindMat {
    fn push(&mut self, id: i64, file: String, v: &[f32]) {
        if self.offs.is_empty() {
            self.offs.push(0);
        }
        self.ids.push(id);
        self.files.push(file);
        self.flat.extend_from_slice(v);
        self.offs.push(self.flat.len());
    }
    pub fn len(&self) -> usize {
        self.ids.len()
    }
    pub fn vec(&self, i: usize) -> &[f32] {
        &self.flat[self.offs[i]..self.offs[i + 1]]
    }
}

/// The kind's current generation, when it has a counter.
fn kind_gen(conn: &Connection, kind: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key=?", [format!("sem_gen:{kind}")], |r| r.get(0)).optional().ok().flatten()
}

fn table_exists(conn: &Connection) -> bool {
    conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name='vec_pack'", [], |_| Ok(())).optional().ok().flatten().is_some()
}

/// The stored pack of `kind`, when it is current. Call inside the read transaction the answer is built in.
pub(crate) fn load(conn: &Connection, kind: &str) -> Option<KindMat> {
    if !table_exists(conn) {
        return None;
    }
    let g = kind_gen(conn, kind)?;
    let (ids, lens, vecs, files): (Vec<u8>, Vec<u8>, Vec<u8>, String) = conn
        .query_row("SELECT ids, lens, vecs, files FROM main.vec_pack WHERE kind=? AND gen=?", params![kind, g], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional()
        .ok()
        .flatten()?;
    let ids: Vec<i64> = ids.as_chunks::<8>().0.iter().map(|c| i64::from_le_bytes(*c)).collect();
    let lens: Vec<usize> = lens.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c) as usize).collect();
    let files: Vec<String> = if ids.is_empty() { vec![] } else { files.split('\n').map(str::to_string).collect() };
    if lens.len() != ids.len() || files.len() != ids.len() || lens.iter().sum::<usize>() * 4 != vecs.len() {
        return None; // not a pack this code wrote: read the rows instead
    }
    let flat = crate::llm::from_blob(&vecs);
    let mut offs = Vec::with_capacity(ids.len() + 1);
    offs.push(0);
    for l in &lens {
        offs.push(offs[offs.len() - 1] + l);
    }
    Some(KindMat { ids, files, offs, flat })
}

/// Which embedded entries a search covers (the unpacked search's `e.kind IN (...)` or `e.kind<>'code'`).
pub(crate) enum Sel {
    In(Vec<String>),
    NotCode,
}

/// Kinds never packed: code chunks change with every edit (the pack would be rewritten after each save).
fn packable(kind: &str) -> bool {
    kind != "code" && !kind.starts_with('#')
}

/// The embedded rows `sel` covers, in id order, with their vectors: from current packs where there are some, the
/// rest read with the unpacked search's join (one statement for all of them). `drops`: the active path exclusion
/// when `entries` is a filtering TEMP VIEW (packs hold every row; the view's rows are the ones it keeps). Also
/// returns the packs worth writing (rows read without a view, of packable kinds) for [`store`].
pub(crate) fn matrix(conn: &Connection, sel: &Sel, drops: Option<&dyn Fn(&str) -> bool>) -> Result<(KindMat, Vec<(String, KindMat)>), String> {
    let shadowed = drops.is_some();
    let mut to_store: Vec<(String, KindMat)> = vec![];
    let have_table = table_exists(conn);
    let kinds: Vec<String> = match sel {
        Sel::In(k) => {
            let mut v: Vec<String> = vec![];
            for x in k {
                if !v.contains(x) {
                    v.push(x.clone());
                }
            }
            v
        }
        Sel::NotCode => {
            let cached = if have_table && !shadowed { load_kinds(conn) } else { None };
            match cached {
                Some(k) => k,
                None => {
                    let mut st = conn.prepare("SELECT DISTINCT kind FROM entries WHERE sem=1 AND kind<>'code'").map_err(|e| e.to_string())?;
                    let k: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?.flatten().collect();
                    if !shadowed {
                        to_store.push(("#kinds".to_string(), KindMat { files: k.clone(), ..Default::default() }));
                    }
                    k
                }
            }
        }
    };
    let mut parts: Vec<KindMat> = vec![];
    let mut missing: Vec<String> = vec![];
    for k in &kinds {
        match (have_table && packable(k)).then(|| load(conn, k)).flatten() {
            Some(mut m) => {
                if let Some(d) = drops {
                    m = m.filtered(|f| !d(f));
                }
                parts.push(m);
            }
            None => missing.push(k.clone()),
        }
    }
    if !missing.is_empty() {
        let marks = vec!["?"; missing.len()].join(",");
        let sql = format!("SELECT e.id, e.kind, e.file, e.line, e.ref, e.text, v.vec FROM entries e JOIN vectors v ON v.sig = e.sig WHERE e.sem=1 AND e.kind IN ({marks}) ORDER BY e.id");
        let mut st = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mut by: Vec<KindMat> = missing.iter().map(|_| KindMat::default()).collect();
        let rows = st
            .query_map(rusqlite::params_from_iter(missing.iter()), |r| {
                // the unpacked search decoded every column and dropped a row that did not decode: so does this
                let b: Vec<u8> = r.get(6)?;
                let (_r, _t, _l): (String, String, i64) = (r.get(4)?, r.get(5)?, r.get(3)?);
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, crate::llm::from_blob(&b)))
            })
            .map_err(|e| e.to_string())?;
        for (id, kind, file, v) in rows.flatten() {
            if let Some(i) = missing.iter().position(|k| *k == kind) {
                by[i].push(id, file, &v);
            }
        }
        for (k, m) in missing.into_iter().zip(by) {
            if !shadowed && packable(&k) {
                to_store.push((k, m.clone_rows()));
            }
            parts.push(m);
        }
    }
    Ok((merge(parts), to_store))
}

/// The kinds list stored with the packs, when current (`sem_gen:#kinds` moves when an embedded entry of a kind
/// without a counter appears).
fn load_kinds(conn: &Connection) -> Option<Vec<String>> {
    let g = kind_gen(conn, "#kinds")?;
    let f: String = conn.query_row("SELECT files FROM main.vec_pack WHERE kind='#kinds' AND gen=?", [g], |r| r.get(0)).optional().ok().flatten()?;
    let k: Vec<String> = if f.is_empty() { vec![] } else { f.split('\n').map(str::to_string).collect() };
    // every listed kind must have a counter, or a change to it would go unnoticed
    k.iter().all(|x| kind_gen(conn, x).is_some() || !packable(x)).then_some(k)
}

/// Rows of several kinds (each in id order, no id in two kinds) merged into one id order.
fn merge(parts: Vec<KindMat>) -> KindMat {
    if parts.len() == 1 {
        return parts.into_iter().next().unwrap_or_default();
    }
    let mut all: Vec<(i64, usize, usize)> = vec![];
    for (p, m) in parts.iter().enumerate() {
        all.extend(m.ids.iter().enumerate().map(|(i, id)| (*id, p, i)));
    }
    all.sort_by_key(|x| x.0);
    let mut out = KindMat::default();
    for (id, p, i) in all {
        out.push(id, String::new(), parts[p].vec(i));
    }
    out.files.clear();
    out
}

impl KindMat {
    fn filtered(self, keep: impl Fn(&str) -> bool) -> KindMat {
        let mut out = KindMat::default();
        for i in 0..self.len() {
            if keep(&self.files[i]) {
                out.push(self.ids[i], self.files[i].clone(), self.vec(i));
            }
        }
        out
    }
    fn clone_rows(&self) -> KindMat {
        KindMat { ids: self.ids.clone(), files: self.files.clone(), offs: self.offs.clone(), flat: self.flat.clone() }
    }
}

/// Write packs read at global generation `gen` (best effort, never waits): only when nothing embedded changed since
/// (the global counter is still `gen`), so the rows are exactly the ones a fresh read would give now.
pub(crate) fn store(conn: &Connection, gen: &str, packs: &[(String, KindMat)], wait: std::time::Duration) {
    if packs.is_empty() || !conn.is_autocommit() {
        return;
    }
    let _ = conn.busy_timeout(std::time::Duration::ZERO);
    let _ = (|| -> rusqlite::Result<()> {
        let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let now: Option<String> = tx.query_row("SELECT value FROM meta WHERE key='sem_gen'", [], |r| r.get(0)).optional()?;
        if now.as_deref() != Some(gen) {
            return Ok(()); // something changed meanwhile: the next query reads afresh (rolled back on drop)
        }
        tx.execute_batch(KIND_GEN_DDL)?;
        for (kind, m) in packs {
            let key = format!("sem_gen:{kind}");
            tx.execute("INSERT OR IGNORE INTO meta VALUES(?, '0')", [&key])?;
            if kind == "#kinds" {
                // counters for every listed kind, so a change to any of them is seen
                for k in m.files.iter().filter(|k| packable(k)) {
                    tx.execute("INSERT OR IGNORE INTO meta VALUES(?, '0')", [format!("sem_gen:{k}")])?;
                }
            }
            let g: String = tx.query_row("SELECT value FROM meta WHERE key=?", [&key], |r| r.get(0))?;
            let ids: Vec<u8> = m.ids.iter().flat_map(|i| i.to_le_bytes()).collect();
            let lens: Vec<u8> = m.offs.windows(2).flat_map(|w| ((w[1] - w[0]) as u32).to_le_bytes()).collect();
            let vecs = crate::llm::to_blob(&m.flat);
            tx.execute(
                "INSERT OR REPLACE INTO main.vec_pack(kind, gen, ids, lens, vecs, files) VALUES(?,?,?,?,?,?)",
                params![kind, g, ids, lens, vecs, m.files.join("\n")],
            )?;
        }
        tx.commit()
    })();
    let _ = conn.busy_timeout(wait);
}

/// True when `entries` currently names a filtering TEMP VIEW (an exclusion is active).
pub(crate) fn entries_shadowed(conn: &Connection) -> bool {
    conn.query_row("SELECT 1 FROM sqlite_temp_master WHERE type='view' AND name='entries'", [], |_| Ok(())).optional().ok().flatten().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE entries(id INTEGER PRIMARY KEY, kind TEXT, file TEXT, line INT, ref TEXT, text TEXT, src INT DEFAULT 0, sem INT DEFAULT 0, sig TEXT);
             CREATE TABLE vectors(sig TEXT PRIMARY KEY, dim INT, vec BLOB);",
        )
        .unwrap();
        c.execute_batch(crate::semantic::GEN_DDL).unwrap();
        for (i, k) in ["bug", "bug", "doc", "code"].iter().enumerate() {
            c.execute("INSERT INTO entries(kind, file, line, ref, text, sem, sig) VALUES(?,?,1,'','t',1,?)", params![k, format!("f{i}"), format!("s{i}")]).unwrap();
            c.execute("INSERT INTO vectors VALUES(?,2,?)", params![format!("s{i}"), crate::llm::to_blob(&[i as f32, 1.0])]).unwrap();
        }
        c
    }
    fn gen(c: &Connection) -> String {
        c.query_row("SELECT value FROM meta WHERE key='sem_gen'", [], |r| r.get(0)).unwrap()
    }
    fn packed(c: &Connection, sel: &Sel) -> Vec<i64> {
        let (m, st) = matrix(c, sel, None).unwrap();
        store(c, &gen(c), &st, std::time::Duration::ZERO);
        m.ids
    }

    /// Packs answer like the join; every change that could alter a pack retires it.
    #[test]
    fn packs_follow_every_change() {
        let c = db();
        assert_eq!(packed(&c, &Sel::NotCode), vec![1, 2, 3]);
        assert!(load(&c, "bug").is_some() && load(&c, "doc").is_some() && load_kinds(&c).is_some());
        assert!(load(&c, "code").is_none(), "code is never packed");
        // an entry of the kind changes
        c.execute("UPDATE entries SET text='u' WHERE id=1", []).unwrap();
        assert!(load(&c, "bug").is_none() && load(&c, "doc").is_some());
        assert_eq!(packed(&c, &Sel::In(vec!["bug".into()])), vec![1, 2]);
        // a vector of one of its signatures is replaced
        c.execute("INSERT OR REPLACE INTO vectors VALUES('s2',2,?)", [crate::llm::to_blob(&[9.0, 9.0])]).unwrap();
        assert!(load(&c, "doc").is_none() && load(&c, "bug").is_some());
        // a new kind appears: the kinds list is retired; a code entry does not retire it
        c.execute("INSERT INTO entries(kind, file, line, ref, text, sem, sig) VALUES('code','g',1,'','c',1,'s9')", []).unwrap();
        assert!(load_kinds(&c).is_some());
        c.execute("INSERT INTO entries(kind, file, line, ref, text, sem, sig) VALUES('task','g',1,'','x',1,'s1')", []).unwrap();
        assert!(load_kinds(&c).is_none());
        assert_eq!(packed(&c, &Sel::NotCode), vec![1, 2, 3, 6]);
        // an entry moves to another kind; a deleted entry leaves its kind's pack
        c.execute("UPDATE entries SET kind='doc' WHERE id=2", []).unwrap();
        assert!(load(&c, "bug").is_none() && load(&c, "doc").is_none());
        assert_eq!(packed(&c, &Sel::NotCode), vec![1, 2, 3, 6]);
        c.execute("DELETE FROM entries WHERE id=6", []).unwrap();
        assert!(load(&c, "task").is_none());
        // the packed rows are the joined rows, vector for vector
        let (m, _) = matrix(&c, &Sel::NotCode, None).unwrap();
        assert_eq!(m.ids, vec![1, 2, 3]);
        assert_eq!(m.vec(2), &[9.0, 9.0]);
        // a store labelled with an older global generation is refused
        let (_, st) = matrix(&c, &Sel::In(vec!["task".into()]), None).unwrap();
        store(&c, "0", &st, std::time::Duration::ZERO);
        assert!(load(&c, "task").is_none());
    }
}
