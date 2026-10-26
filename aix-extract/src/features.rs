//! Feature catalogue sources that live in single files: Java `FEATURE_*` flags, in-app tips
//! (`data/tips.ts`) and per-page help (`data/pageHelp.ts`). Menu-derived features need several files and
//! are built by the core after each update.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::*;
use crate::text::Lines;
use crate::Extractor;

pub struct FeatureSources;

static FLAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"static final String (FEATURE_\w+)\s*=\s*"([^"]+)""#).unwrap());
static TIP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""id":\s*"(\w+)",\s*"category":\s*"([^"]*)",\s*"title":\s*"([^"]*)",\s*"body":\s*"((?:[^"\\]|\\.)*)""#)
        .unwrap()
});
static HELP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\[\s*'(/[^']*)',\s*'((?:[^'\\]|\\.)*)',\s*'((?:[^'\\]|\\.)*)'((?:,\s*(?:'(?:[^'\\]|\\.)*'|"[^"]*"))*)\s*\]"#,
    )
    .unwrap()
});
/// `'/route': 'words people type'` entries of a menu-search keyword/synonym table.
static ROUTE_WORDS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^\s*['"](/[\w/:-]*)['"]\s*:\s*['"]([^'"]{3,})['"]"#).unwrap());

/// A file that holds menu search keywords or synonyms (e.g. `lib/menuSearchSynonyms.ts`).
fn is_keyword_table(path: &str) -> bool {
    let b = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(ext_of(path), "ts" | "tsx" | "js") && (b.contains("synonym") || b.contains("keyword") || b.contains("menusearch"))
}

static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"'((?:[^'\\]|\\.)*)'|"([^"]*)""#).unwrap());

fn clean(s: &str) -> String {
    let s = s.replace("\\'", "'").replace("\\\"", "\"");
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Extractor for FeatureSources {
    fn name(&self) -> &'static str {
        "features"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        ext_of(path) == "java"
            || path.ends_with("data/tips.ts")
            || path.ends_with("data/pageHelp.ts")
            || is_keyword_table(path)
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            let lt = Lines::new(&f.text);
            if f.ext() == "java" {
                let lines: Vec<&str> = f.text.lines().collect();
                for (i, l) in lines.iter().enumerate() {
                    if let Some(c) = FLAG.captures(l) {
                        let doc = if i > 0 { lines[i - 1].trim().trim_matches(['/', '*']).trim() } else { "" };
                        rows.features.push(Feature {
                            file: f.path.clone(),
                            line: i as u32 + 1,
                            kind: "flag".into(),
                            name: c[2].to_string(),
                            route: String::new(),
                            roles: String::new(),
                            purpose: doc.to_string(),
                            extra: c[1].to_string(),
                        });
                    }
                }
            } else if f.path.ends_with("data/tips.ts") {
                for c in TIP.captures_iter(&f.text) {
                    rows.features.push(Feature {
                        file: f.path.clone(),
                        line: lt.at(c.get(0).unwrap().start()),
                        kind: "tip".into(),
                        name: c[3].to_string(),
                        route: String::new(),
                        roles: String::new(),
                        purpose: c[4].chars().take(300).collect(),
                        extra: c[2].to_string(),
                    });
                }
            } else if is_keyword_table(&f.path) {
                for c in ROUTE_WORDS.captures_iter(&f.text) {
                    rows.features.push(Feature {
                        file: f.path.clone(),
                        line: lt.at(c.get(0).unwrap().start()),
                        kind: "keywords".into(),
                        name: c[1].to_string(),
                        route: c[1].to_string(),
                        roles: String::new(),
                        purpose: String::new(),
                        extra: clean(&c[2]),
                    });
                }
            } else {
                for c in HELP.captures_iter(&f.text) {
                    let tips: Vec<String> = QUOTED
                        .captures_iter(&c[4])
                        .map(|q| clean(q.get(1).or(q.get(2)).map(|m| m.as_str()).unwrap_or("")))
                        .collect();
                    rows.features.push(Feature {
                        file: f.path.clone(),
                        line: lt.at(c.get(0).unwrap().start()),
                        kind: "help".into(),
                        name: c[2].replace("\\'", "'"),
                        route: c[1].to_string(),
                        roles: String::new(),
                        purpose: c[3].replace("\\'", "'"),
                        extra: tips.join(" ").chars().take(400).collect(),
                    });
                }
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn menu_keyword_table() {
        let t = "export const PAGE_KEYWORDS: Record<string, string> = {\n  '/fees': 'receipt pay cashier cash',\n  '/invoices': 'bill statement',\n}\n";
        let rows = FeatureSources.extract(Path::new("."), &[SourceFile::new("frontend/src/lib/menuSearchSynonyms.ts", t)]);
        let k: Vec<_> = rows.features.iter().map(|f| (f.kind.as_str(), f.route.as_str(), f.extra.as_str())).collect();
        assert_eq!(k, vec![("keywords", "/fees", "receipt pay cashier cash"), ("keywords", "/invoices", "bill statement")]);
    }
}
