//! JSON inputs: e2e scenario specs (`{role, scenarios: [{id, title, steps: [...]}]}`), QA findings JSON
//! (`{confirmed: [...]}`), and SQL files -> tables touched.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::markdown::add_bug;
use crate::model::*;
use crate::text::Lines;
use crate::Extractor;

pub struct E2eSpecs;
pub struct FindingsJson;
pub struct Sql;

/// Offset of a JSON-encoded string value in the file text (raw UTF-8 or `\uXXXX`-escaped, as Python writes it).
fn json_find(text: &str, needle: &str, from: usize) -> Option<usize> {
    let enc = serde_json::to_string(needle).ok()?;
    let enc = &enc[1..enc.len() - 1];
    let hay = text.get(from..)?;
    if let Some(k) = hay.find(enc) {
        return Some(k + from);
    }
    let mut ascii = String::new();
    for c in enc.chars() {
        if c.is_ascii() {
            ascii.push(c);
        } else {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                ascii.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    hay.find(&ascii).map(|k| k + from)
}

const STEP_SKIP: &[&str] = &["value", "exact", "fullPage", "nth", "file"];
const DICT_KEYS: &[&str] =
    &["name", "text", "label", "placeholder", "get", "post", "put", "delete", "patch", "expectIncludes", "css"];
const TEXT_STEPS: &[&str] =
    &["expectText", "navPresent", "navAbsent", "click", "expectVisible", "expectHidden", "fill"];
static TPL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{\w+\}\}").unwrap());

impl Extractor for E2eSpecs {
    fn name(&self) -> &'static str {
        "e2e-specs"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "json" && !path.ends_with("package.json")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            if !f.text.contains("\"scenarios\"") {
                continue;
            }
            let Ok(d) = serde_json::from_str::<Value>(&f.text) else {
                continue;
            };
            spec(f, &d, &mut rows);
        }
        rows
    }
}

fn spec(f: &SourceFile, d: &Value, rows: &mut Rows) {
    let stem = f.name().trim_end_matches(".json").to_string();
    let role = d.get("role").and_then(Value::as_str).map(str::to_string).unwrap_or(stem);
    let lt = Lines::new(&f.text);
    let mut pos = 0;
    let Some(scs) = d.get("scenarios").and_then(Value::as_array) else {
        return;
    };
    for sc in scs {
        let sid = sc.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        if let Some(k) = f.text.get(pos..).and_then(|t| t.find(&format!("\"{sid}\""))) {
            pos += k;
        }
        let line = lt.at(pos);
        let mut routes: Vec<String> = vec![];
        let mut texts: Vec<String> = vec![];
        for st in sc.get("steps").and_then(Value::as_array).into_iter().flatten() {
            let Some(obj) = st.as_object() else { continue };
            for (key, v) in obj {
                if STEP_SKIP.contains(&key.as_str()) {
                    continue;
                }
                let vals: Vec<(String, String)> = match v {
                    Value::String(s) => vec![(key.clone(), s.clone())],
                    Value::Object(m) => m
                        .iter()
                        .filter(|(kk, _)| DICT_KEYS.contains(&kk.as_str()))
                        .map(|(kk, x)| {
                            (format!("{key}.{kk}"), x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
                        })
                        .collect(),
                    _ => vec![],
                };
                for (kind, val) in vals {
                    let sl = json_find(&f.text, &val, pos).map(|k| lt.at(k)).unwrap_or(line);
                    if key == "goto" {
                        let r = val.split('?').next().unwrap_or("").to_string();
                        if !routes.contains(&r) {
                            routes.push(r);
                        }
                    } else if TEXT_STEPS.contains(&key.as_str()) && !texts.contains(&val) {
                        texts.push(val.clone());
                    }
                    if key == "api" && val.starts_with('/') {
                        rows.script_refs.push(ScriptRef {
                            file: f.path.clone(),
                            line: sl,
                            norm_path: norm_path(&TPL.replace_all(&val, "{x}")),
                        });
                    }
                    rows.test_steps.push(TestStep {
                        file: f.path.clone(),
                        line: sl,
                        sid: sid.clone(),
                        kind,
                        value: val,
                    });
                }
            }
        }
        rows.tests.push(TestCase {
            file: f.path.clone(),
            line,
            id: sid,
            title: sc.get("title").and_then(Value::as_str).unwrap_or("").to_string(),
            role: role.clone(),
            routes,
            texts,
        });
    }
}

impl Extractor for FindingsJson {
    fn name(&self) -> &'static str {
        "findings-json"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "json" && path.contains("findings")
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        static RND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"round-?(\d+)").unwrap());
        for f in files {
            let Ok(d) = serde_json::from_str::<Value>(&f.text) else {
                continue;
            };
            let items = match &d {
                Value::Object(m) => m.get("confirmed").and_then(Value::as_array).cloned().unwrap_or_default(),
                Value::Array(a) => a.clone(),
                _ => vec![],
            };
            let lt = Lines::new(&f.text);
            let rnd = RND.captures(&f.path).map(|c| format!("r{}", &c[1])).unwrap_or_default();
            for it in items.iter().filter_map(Value::as_object) {
                let g = |k: &str| it.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let title = g("title");
                let probe: String = title.chars().take(60).collect();
                let line = json_find(&f.text, &probe, 0).map(|k| lt.at(k)).unwrap_or(1);
                let file = g("file");
                let file = file.clone();
                let t = format!("{title} [{}] {file} — {} severity {}", g("domain"), g("description"), g("severity"));
                add_bug(f, line as usize, &t, &g("domain"), "", &rnd, "doc", &mut rows);
            }
        }
        rows
    }
}

static SQL_OP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)\b(CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?(?:\s+IF\s+NOT\s+EXISTS)?\s+\w+\s+ON|"#,
        r#"CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REFERENCES|"#,
        r#"CREATE\s+(?:OR\s+REPLACE\s+)?(?:VIEW|FUNCTION|TRIGGER))\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"#,
        r#"(?:ONLY\s+)?([\w."]+)"#
    ))
    .unwrap()
});
static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]\w*$").unwrap());
static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

impl Extractor for Sql {
    fn name(&self) -> &'static str {
        "sql"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "sql"
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let lt = Lines::new(&f.text);
            for c in SQL_OP.captures_iter(&f.text) {
                let raw = c[1].to_uppercase();
                let op_s = WS.replace_all(&raw, " ").to_string();
                let first = op_s.split(' ').next().unwrap_or("");
                let mut op = if op_s.contains("INDEX") {
                    "index".to_string()
                } else if ["ALTER", "DROP", "UPDATE", "REFERENCES"].contains(&first) {
                    first.to_lowercase()
                } else {
                    match first {
                        "CREATE" => "create".into(),
                        "INSERT" => "insert".into(),
                        "DELETE" => "delete".into(),
                        x => x.to_lowercase(),
                    }
                };
                if op_s.contains("VIEW") || op_s.contains("FUNCTION") || op_s.contains("TRIGGER") {
                    op = format!("create-{}", op_s.rsplit(' ').next().unwrap_or("").to_lowercase());
                }
                let name = c[2].trim_matches('"').rsplit('.').next().unwrap_or("").trim_matches('"').to_lowercase();
                if ["set", "on", "table", "public", "only"].contains(&name.as_str()) || !IDENT.is_match(&name) {
                    continue;
                }
                rows.db_tables.push(DbTable {
                    file: f.path.clone(),
                    line: lt.at(c.get(0).unwrap().start()),
                    table: name,
                    op,
                });
            }
        }
        rows
    }
}
