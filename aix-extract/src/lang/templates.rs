//! User-facing strings in template files for `aix text`: Vue / Svelte templates, Jinja / Django / Twig, Thymeleaf,
//! ERB, Blade and Go templates. Static text between tags and the usual label attributes are kept; expressions
//! (`{{ x }}`, `<%= x %>`, `th:text="${x}"`) are dropped, translation calls with a literal (`{% trans "Save" %}`,
//! `{{ _('Save') }}`) are kept. Vue / Svelte components also hand their `<script>` blocks to the TypeScript extractor.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::*;
use crate::text::Lines;
use crate::Extractor;

pub struct Templates;

static EXPR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}|<%.*?%>|<\?php.*?\?>|\{@.*?\}|\{\$.*?\}|\{\{!--.*?--\}\}|\{!!.*?!!\}|@\w+\([^)\n]*\)|\{[#:/@]\w+[^}]*\}")
        .unwrap()
});
static BLOCKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<(script|style)\b[^>]*>.*?</(script|style)\s*>|<!--.*?-->").unwrap());
static TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r">([^<>]{2,400})<").unwrap());
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(title|placeholder|aria-label|alt|label|tooltip|data-title|data-confirm|data-tooltip|value)\s*=\s*(?:"([^"]{2,300})"|'([^']{2,300})')"#).unwrap()
});
static TRANS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\{%-?\s*trans\s+|\{\{\s*_\(\s*|\{\{\s*gettext\(\s*|<%=?\s*(?:t|I18n\.t)[( ]\s*|\{\{\s*__\(\s*|@lang\(\s*|\{\{\s*\$t\(\s*)(?:"([^"]{2,300})"|'([^']{2,300})')"#).unwrap()
});

fn is_template(path: &str) -> bool {
    let n = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    n.ends_with(".vue")
        || n.ends_with(".svelte")
        || n.ends_with(".erb")
        || n.ends_with(".jinja")
        || n.ends_with(".jinja2")
        || n.ends_with(".j2")
        || n.ends_with(".twig")
        || n.ends_with(".blade.php")
        || n.ends_with(".tmpl")
        || n.ends_with(".gohtml")
        || n.ends_with(".html")
}

fn wordy(s: &str) -> bool {
    s.chars().filter(|c| c.is_alphabetic()).count() >= 2 && s.len() <= 400 && !s.trim_start().starts_with(['.', '/', '#']) && !s.contains("=>")
}

impl Extractor for Templates {
    fn name(&self) -> &'static str {
        "templates"
    }
    fn detect(&self, _repo: &Path) -> bool {
        true
    }
    fn handles(&self, path: &str) -> bool {
        is_template(path)
    }
    fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
        let mut rows = Rows::default();
        for f in files {
            one(f, &mut rows);
        }
        rows
    }
}

fn one(f: &SourceFile, rows: &mut Rows) {
    let ext = f.ext().to_ascii_lowercase();
    let sfc = matches!(ext.as_str(), "vue" | "svelte");
    let t = &f.text;
    // plain .html is only a template when it uses a template language (Jinja / Django / Twig / Thymeleaf / Go)
    if ext == "html" && !(t.contains("{{") || t.contains("{%") || t.contains("th:") || t.contains("<%")) {
        return;
    }
    if sfc {
        for (off, code) in super::sfc::script_blocks(t) {
            crate::typescript::extract_file(&super::sfc::block_file(f, off, &code), rows);
        }
    }
    // translation calls first (the literal is the message), then plain text with expressions blanked out
    let li = Lines::new(t);
    let mut seen = std::collections::HashSet::new();
    let mut push = |off: usize, s: &str, kind: &str, rows: &mut Rows| {
        let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if wordy(&s) && seen.insert((li.at(off), s.clone())) {
            rows.ui_strings.push(UiString { file: f.path.clone(), line: li.at(off), text: s, kind: kind.into(), component: None });
        }
    };
    for c in TRANS.captures_iter(t) {
        let m = c.get(1).or_else(|| c.get(2)).unwrap();
        push(m.start(), m.as_str(), "jsx", rows);
    }
    // blank scripts, styles, comments and expressions to spaces of equal length so offsets (and lines) stay put
    let blank = |re: &Regex, s: String| re.replace_all(&s, |c: &regex::Captures| c[0].chars().map(|ch| if ch == '\n' { "\n".to_string() } else { " ".repeat(ch.len_utf8()) }).collect::<String>()).into_owned();
    let clean = blank(&EXPR, blank(&BLOCKS, t.clone()));
    for c in TEXT.captures_iter(&clean) {
        let m = c.get(1).unwrap();
        // expression remnants (`$` / `{` / `}`) mean this is code, not copy
        if m.as_str().contains(['{', '}', '$']) {
            continue;
        }
        push(m.start(), m.as_str(), "jsx", rows);
    }
    for c in ATTR.captures_iter(&clean) {
        let m = c.get(2).or_else(|| c.get(3)).unwrap();
        let name = c[1].to_ascii_lowercase();
        if name == "value" && !(m.as_str().contains(' ') && wordy(m.as_str())) {
            continue;
        }
        push(m.start(), m.as_str(), &format!("prop:{name}"), rows);
    }
}
