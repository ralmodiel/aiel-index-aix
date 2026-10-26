//! SQLite schema: plain fact tables with indexes for exact joins, one FTS5 corpus (`entries_fts`,
//! porter + unicode61, external content) ranked by bm25, and an embeddings table keyed by text hash.

pub const SCHEMA_VERSION: &str = "9";

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files(
  path TEXT PRIMARY KEY, kind TEXT, lang TEXT, lines INT, bytes INT, hash TEXT, mtime_ns INT,
  summary TEXT DEFAULT '', summary_source TEXT DEFAULT '', commit_sha TEXT DEFAULT '', commit_date TEXT DEFAULT '', class TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS symbols(file TEXT, line INT, end_line INT, name TEXT, kind TEXT, exported INT, container TEXT);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS symbols_file ON symbols(file);
CREATE TABLE IF NOT EXISTS ui_strings(file TEXT, line INT, kind TEXT, text TEXT, component TEXT);
CREATE INDEX IF NOT EXISTS ui_file ON ui_strings(file);
CREATE TABLE IF NOT EXISTS sections(file TEXT, line INT, end_line INT, level INT, heading TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS sections_file ON sections(file);
CREATE TABLE IF NOT EXISTS scripts(file TEXT PRIMARY KEY, kind TEXT, header TEXT, usage TEXT, flags TEXT);
CREATE TABLE IF NOT EXISTS script_refs(file TEXT, line INT, norm TEXT);
CREATE INDEX IF NOT EXISTS script_refs_norm ON script_refs(norm);
CREATE INDEX IF NOT EXISTS script_refs_file ON script_refs(file);
CREATE TABLE IF NOT EXISTS tasks(file TEXT, line INT, status TEXT, kind TEXT, round TEXT, sha TEXT, heading TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS tasks_file ON tasks(file);
CREATE TABLE IF NOT EXISTS imports(file TEXT, line INT, name TEXT, source TEXT, target TEXT);
CREATE INDEX IF NOT EXISTS imports_file ON imports(file);
CREATE INDEX IF NOT EXISTS imports_target ON imports(target);
CREATE TABLE IF NOT EXISTS calls(file TEXT, line INT, obj TEXT, member TEXT);
CREATE INDEX IF NOT EXISTS calls_file ON calls(file);
CREATE INDEX IF NOT EXISTS calls_obj ON calls(obj, member);
CREATE TABLE IF NOT EXISTS api_calls(file TEXT, line INT, obj TEXT, name TEXT, method TEXT, path TEXT, norm TEXT);
CREATE INDEX IF NOT EXISTS api_calls_file ON api_calls(file);
CREATE INDEX IF NOT EXISTS api_calls_obj ON api_calls(obj, name);
CREATE INDEX IF NOT EXISTS api_calls_norm ON api_calls(norm, method);
CREATE TABLE IF NOT EXISTS consts(file TEXT, line INT, name TEXT, vals TEXT);
CREATE INDEX IF NOT EXISTS consts_name ON consts(name);
CREATE INDEX IF NOT EXISTS consts_file ON consts(file);
CREATE TABLE IF NOT EXISTS routes(file TEXT, line INT, path TEXT, component TEXT, roles TEXT, role_expr TEXT,
  feature TEXT, redirect TEXT, page_file TEXT DEFAULT '', roles_raw TEXT);
CREATE INDEX IF NOT EXISTS routes_path ON routes(path);
CREATE INDEX IF NOT EXISTS routes_file ON routes(file);
CREATE TABLE IF NOT EXISTS menu(file TEXT, line INT, nav TEXT, grp TEXT, label TEXT, href TEXT, roles TEXT, grp_roles TEXT,
  keywords TEXT, tooltip TEXT, tabs TEXT, roles_raw TEXT, grp_roles_raw TEXT);
CREATE INDEX IF NOT EXISTS menu_href ON menu(href);
CREATE INDEX IF NOT EXISTS menu_file ON menu(file);
CREATE TABLE IF NOT EXISTS endpoints(file TEXT, line INT, method TEXT, path TEXT, norm TEXT, class TEXT, handler TEXT,
  roles TEXT, roles_raw TEXT);
CREATE INDEX IF NOT EXISTS endpoints_norm ON endpoints(norm, method);
CREATE INDEX IF NOT EXISTS endpoints_file ON endpoints(file);
CREATE TABLE IF NOT EXISTS tests(file TEXT, line INT, sid TEXT, title TEXT, role TEXT, routes TEXT, texts TEXT);
CREATE INDEX IF NOT EXISTS tests_file ON tests(file);
CREATE TABLE IF NOT EXISTS test_steps(file TEXT, line INT, sid TEXT, kind TEXT, value TEXT);
CREATE INDEX IF NOT EXISTS test_steps_file ON test_steps(file);
CREATE INDEX IF NOT EXISTS test_steps_kind ON test_steps(kind, value);
CREATE TABLE IF NOT EXISTS bugs(file TEXT, line INT, kind TEXT, date TEXT, severity TEXT, status TEXT, round TEXT,
  sha TEXT, title TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS bugs_file ON bugs(file);
CREATE TABLE IF NOT EXISTS features(file TEXT, line INT, kind TEXT, name TEXT, route TEXT, roles TEXT, purpose TEXT,
  extra TEXT, derived INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS features_file ON features(file);
CREATE INDEX IF NOT EXISTS features_route ON features(route);
CREATE TABLE IF NOT EXISTS db_tables(file TEXT, line INT, tbl TEXT, op TEXT);
CREATE INDEX IF NOT EXISTS db_tables_file ON db_tables(file);
CREATE INDEX IF NOT EXISTS db_tables_tbl ON db_tables(tbl);
CREATE TABLE IF NOT EXISTS notes(file TEXT, line INT, kind TEXT, ref TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS notes_file ON notes(file);
CREATE TABLE IF NOT EXISTS commits(sha TEXT PRIMARY KEY, short TEXT, date TEXT, subject TEXT, is_fix INT, is_revert INT,
  seq INT);
CREATE TABLE IF NOT EXISTS commit_files(sha TEXT, path TEXT);
CREATE INDEX IF NOT EXISTS commit_files_path ON commit_files(path);
CREATE INDEX IF NOT EXISTS commit_files_sha ON commit_files(sha);
-- search corpus: src 0 = per-file facts, 1 = derived (cross-file) facts, 2 = git history
CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, kind TEXT, file TEXT, line INT, ref TEXT, text TEXT,
  src INT DEFAULT 0, sem INT DEFAULT 0, sig TEXT);
CREATE INDEX IF NOT EXISTS entries_file ON entries(file, src);
CREATE INDEX IF NOT EXISTS entries_sig ON entries(sig);
CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(text, content='entries', content_rowid='id',
  tokenize='porter unicode61');
CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
  INSERT INTO entries_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
CREATE TABLE IF NOT EXISTS vectors(sig TEXT PRIMARY KEY, dim INT, vec BLOB);
CREATE TABLE IF NOT EXISTS llm_notes(kind TEXT, key TEXT, sig TEXT, text TEXT, model TEXT, ts TEXT, PRIMARY KEY(kind, key));
CREATE TABLE IF NOT EXISTS savings(ts INT, cmd TEXT, arg TEXT, bytes_out INT, est_bytes INT, ms INT);
-- how often Claude ran each repo script (counted by the PreToolUse hook; only the script path, never the command line)
CREATE TABLE IF NOT EXISTS script_usage(file TEXT PRIMARY KEY, n INT NOT NULL DEFAULT 0, last INT);
-- named regex patterns (auto-promoted from repeated searches, or added by hand), materialized per file
CREATE TABLE IF NOT EXISTS grep_usage(regex TEXT PRIMARY KEY, n INT NOT NULL DEFAULT 0, last INT);
CREATE TABLE IF NOT EXISTS patterns(name TEXT PRIMARY KEY, regex TEXT NOT NULL, auto INT, created INT, dirty INT DEFAULT 1, uses INT DEFAULT 0, last_used INT, dormant INT DEFAULT 0,
  seeded INT DEFAULT 0, pinned INT DEFAULT 0, score REAL DEFAULT 0, caps TEXT DEFAULT '', removed INT DEFAULT 0, broad INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS pattern_hits(name TEXT, file TEXT, line INT, text TEXT, symbol TEXT, container TEXT, lang TEXT, kind TEXT);
DROP INDEX IF EXISTS pattern_hits_name;
CREATE INDEX IF NOT EXISTS pattern_hits_nfl ON pattern_hits(name, file, line);
CREATE INDEX IF NOT EXISTS pattern_hits_file ON pattern_hits(file);
-- hot lookups found by timing the canned queries (symbol uses, brief by page file, innermost-symbol, fix history)
CREATE INDEX IF NOT EXISTS imports_name ON imports(name);
CREATE INDEX IF NOT EXISTS routes_page ON routes(page_file);
CREATE INDEX IF NOT EXISTS symbols_file_line ON symbols(file, line);
CREATE INDEX IF NOT EXISTS menu_label ON menu(label COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS features_kind ON features(kind);
"#;

/// Tables holding per-file facts (deleted and re-inserted when a file changes).
pub const FILE_TABLES: &[&str] = &[
    "symbols",
    "ui_strings",
    "sections",
    "scripts",
    "script_refs",
    "tasks",
    "imports",
    "calls",
    "api_calls",
    "consts",
    "routes",
    "menu",
    "endpoints",
    "tests",
    "test_steps",
    "bugs",
    "db_tables",
    "notes",
];

/// The triggers that mirror `entries` into FTS5 (a full build drops them for the bulk insert, then rebuilds the index).
pub const FTS_TRIGGERS: &str = "CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
  INSERT INTO entries_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
  INSERT INTO entries_fts(entries_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
";

#[cfg(test)]
mod fts_tests {
    #[test]
    fn triggers_match_schema() {
        assert!(super::SCHEMA.contains(super::FTS_TRIGGERS), "FTS_TRIGGERS must be the same text as in SCHEMA");
    }
}
