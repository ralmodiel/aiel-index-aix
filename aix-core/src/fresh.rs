//! Files edited since they were indexed, while the refresh has not caught up (another process holds the update
//! lock, or a large change was deferred to a background refresh). `code` and `outline` print line ranges from the
//! index but text from the disk: for such a file they re-extract it in memory (milliseconds, nothing is written)
//! so a member's name and the lines printed under it agree.

use crate::index::Index;
use aix_extract::Rows;

/// Has `file` changed on disk since the index read it? Same test as the update plan (mtime and size), then the
/// content hash, so a touched but unchanged file is not "changed".
pub fn changed(ix: &Index, file: &str) -> bool {
    let row: Option<(String, i64, i64)> =
        ix.conn.query_row("SELECT hash, mtime_ns, bytes FROM files WHERE path=?", [file], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok();
    let Some((hash, mtime, bytes)) = row else { return false };
    let Ok(md) = std::fs::metadata(ix.repo.join(file)) else { return false };
    let m = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos() as i64).unwrap_or(0);
    if m == mtime && md.len() as i64 == bytes {
        return false;
    }
    match std::fs::read(ix.repo.join(file)) {
        Ok(b) => blake3::hash(&b).to_hex()[..32] != hash[..],
        Err(_) => false,
    }
}

/// The facts of `file` as it is now on disk (None: unreadable or not an indexed file).
pub fn extract(ix: &Index, file: &str) -> Option<Rows> {
    let text = crate::query::read_indexed(ix, file)?;
    Some(ix.extract_now(file, text))
}

/// The note printed once above an answer read from a changed file.
pub fn note(file: &str) -> String {
    format!("({file} changed since it was indexed and the refresh has not caught up: its members and lines below are read from the file as it is now)")
}

/// A definition of `name` in fresh rows: (line, end_line, kind, container). `container` narrows when non-empty;
/// among several, the one nearest the line the index had.
pub fn find(rows: &Rows, name: &str, container: &str, kind: &str, old_line: i64) -> Option<(i64, i64, String, String)> {
    let mut c: Vec<(i64, i64, String, String)> = rows
        .symbols
        .iter()
        .filter(|s| s.name == name)
        .map(|s| (s.line as i64, s.end_line as i64, s.kind.clone(), s.container.clone().unwrap_or_default()))
        .chain(rows.members.iter().filter(|m| m.name == name && m.kind != "field").map(|m| (m.line as i64, m.end_line as i64, m.kind.clone(), m.container.clone().unwrap_or_default())))
        .collect();
    if !container.is_empty() && c.iter().any(|d| d.3 == container) {
        c.retain(|d| d.3 == container);
    }
    if c.iter().any(|d| d.2 == kind) {
        c.retain(|d| d.2 == kind);
    }
    c.into_iter().min_by_key(|d| (d.0 - old_line).abs())
}

/// The innermost member around `line` in fresh rows: (name, line, end_line).
pub fn enclosing(rows: &Rows, line: i64) -> Option<(String, i64, i64)> {
    rows.symbols
        .iter()
        .map(|s| (s.name.clone(), s.line as i64, s.end_line as i64))
        .chain(rows.members.iter().filter(|m| m.kind != "field").map(|m| (m.name.clone(), m.line as i64, m.end_line as i64)))
        .filter(|d| d.1 <= line && line <= d.2)
        .min_by_key(|d| d.2 - d.1)
}
