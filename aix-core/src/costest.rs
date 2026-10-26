//! The savings estimate's file sizes, looked up in memory. `estimate_cost` asked SQLite
//! `SELECT bytes FROM files WHERE path=? OR path LIKE '%/<f>' LIMIT 1` once per path-shaped token of the answer: a full
//! scan of `files` each time (the LIKE cannot use an index). Here the table is read once, in the same (rowid) order,
//! and the same predicate is evaluated in Rust, so every lookup returns what the statement returned.

use rusqlite::Connection;

pub(crate) struct FileBytes {
    rows: Vec<(String, Option<i64>)>,
}

impl FileBytes {
    /// None when `files` cannot be read (every lookup then finds nothing, as the failing statement did).
    pub(crate) fn load(conn: &Connection) -> Option<FileBytes> {
        let mut st = conn.prepare("SELECT path, bytes FROM files ORDER BY rowid").ok()?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1).ok().flatten())))
            .ok()?
            .filter_map(Result::ok)
            .collect();
        Some(FileBytes { rows })
    }

    /// `bytes` of the first row (rowid order) whose path is `f` or ends in `/f` under SQLite's default LIKE rules
    /// (`_` matches any one character, ASCII letters match either case, other characters match only themselves).
    /// None when there is no such row or its `bytes` is NULL (LIMIT 1 stops at that row either way).
    pub(crate) fn lookup(&self, f: &str) -> Option<i64> {
        let pat: Vec<char> = std::iter::once('/').chain(f.chars()).collect();
        let row = self.rows.iter().find(|(p, _)| p == f || like_suffix(p, &pat))?;
        row.1
    }
}

/// `path LIKE '%' || pat` where `pat` holds no `%` (a leading `%` then fixed-width characters: the last
/// `pat.len()` characters of `path` must match one for one).
fn like_suffix(path: &str, pat: &[char]) -> bool {
    if pat.iter().any(|&c| c == '%') {
        return false; // never produced by the path-shaped tokens; refuse rather than mis-evaluate
    }
    let mut it = path.chars().rev();
    for &pc in pat.iter().rev() {
        let Some(c) = it.next() else { return false };
        if pc == '_' {
            continue;
        }
        let eq = if pc.is_ascii() && c.is_ascii() { pc.eq_ignore_ascii_case(&c) } else { pc == c };
        if !eq {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust predicate agrees with SQLite's on a table of tricky names.
    #[test]
    fn same_answers_as_sqlite() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE files(path TEXT PRIMARY KEY, bytes INT)").unwrap();
        let paths = ["src/A.rs", "lib/a.rs", "a.rs", "x/a_rs", "x/aXrs", "deep/dir/Foo.Java", "é/ü.md", "É/Ü.md", "n/null.ts", "src/b.rs"];
        for (i, p) in paths.iter().enumerate() {
            let b: Option<i64> = if p.starts_with("n/") { None } else { Some(100 + i as i64) };
            c.execute("INSERT INTO files(path, bytes) VALUES(?,?)", rusqlite::params![p, b]).unwrap();
        }
        let fb = FileBytes::load(&c).unwrap();
        for f in ["a.rs", "A.RS", "a_rs", "a.r_", "foo.java", "dir/foo.java", "ü.md", "Ü.md", "null.ts", "b.rs", "nope", "1.5", "_", "s/a.rs", "rs"] {
            let want: Option<i64> =
                c.query_row("SELECT bytes FROM files WHERE path=? OR path LIKE ? LIMIT 1", [f.to_string(), format!("%/{f}")], |r| r.get(0)).ok();
            assert_eq!(fb.lookup(f), want, "{f}");
        }
    }
}
