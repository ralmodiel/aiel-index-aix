//! Defence-in-depth redaction. Text that enters or leaves the index passes through here.
//!
//! Layers (all linear-time: the `regex` crate, byte scans, no backtracking, per-line work is capped):
//!  1. provider detectors (typed masks such as `***aws-key***`) and syntax-aware generic detectors (`:=`, `=>`,
//!     string concatenation, f-strings and template literals, `${VAR:-default}`, XML, JSON-escaped keys);
//!  2. the key/value and prose detectors of [`crate::text`] (`password: x`, `curl -u a:b`, YAML blocks...);
//!  3. base64-wrapped secrets (the token is decoded and re-scanned);
//!  4. a high-entropy token detector (length, charset and Shannon-entropy thresholds, hashes/UUIDs/lockfile
//!     digests/identifiers skipped);
//!  5. PII: emails, phone numbers, Luhn-valid card numbers, national IDs in credential context, IPs (opt-in).
//!
//! Masks keep a short type hint and never a part of the value. A repo's `.aix/config.toml` may ADD rules and
//! allow-list exact strings (stored as hashes); it cannot switch a built-in family off.
//!
//! API: [`redact_line`] (one line), [`redact_block`] (many lines, line count preserved), [`redact_json`].

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock, OnceLock, RwLock};

use regex::{Regex, RegexBuilder};
use serde::Deserialize;

/// Longest slice of a line the (non-linear-in-matches) keyed detectors see at once.
const CHUNK: usize = 4096;

/// `.aix/config.toml` `[redact]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RedactConfig {
    /// Exact false-positive strings, as `sha1:<hex>` (see `aix redact-test --hash`). Never plain text.
    pub allow: Vec<String>,
    /// Also redact IPv4/IPv6 addresses.
    pub ip: bool,
    /// Extra detectors: `[[redact.rules]] name = "internal-id"  pattern = "ACME-[0-9]{8}"  group = 0`.
    pub rules: Vec<ExtraRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExtraRule {
    pub name: String,
    pub pattern: String,
    pub group: usize,
}
impl Default for ExtraRule {
    fn default() -> Self {
        ExtraRule { name: "custom".into(), pattern: String::new(), group: 0 }
    }
}

struct Settings {
    ip: bool,
    allow: HashSet<String>,
    extra: Vec<(String, Regex, usize)>,
}
static SETTINGS: LazyLock<RwLock<Arc<Settings>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Settings { ip: false, allow: HashSet::new(), extra: vec![] })));

fn settings() -> Arc<Settings> {
    SETTINGS.read().map(|g| g.clone()).unwrap_or_else(|p| p.into_inner().clone())
}

/// Hash form of an allow-list entry.
pub fn hash_allow(s: &str) -> String {
    format!("sha1:{}", sha1_smol::Sha1::from(s).digest())
}

/// Install a repo's settings. Returns warnings (ignored entries). Built-in families are not configurable.
pub fn configure(c: &RedactConfig) -> Vec<String> {
    let mut warn = vec![];
    let mut allow = HashSet::new();
    for a in &c.allow {
        let a = a.trim().to_ascii_lowercase();
        if a.len() == 45 && a.starts_with("sha1:") && a[5..].bytes().all(|b| b.is_ascii_hexdigit()) {
            allow.insert(a);
        } else {
            warn.push("redact.allow: entries must be hashes (`sha1:<hex>`, from `aix redact-test --hash`); entry ignored".to_string());
        }
    }
    let mut extra = vec![];
    for r in c.rules.iter().take(64) {
        let name: String = r.name.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(24).collect();
        match RegexBuilder::new(&r.pattern).size_limit(1 << 20).build() {
            Ok(re) if r.group < re.captures_len() && !name.is_empty() => extra.push((name, re, r.group)),
            _ => warn.push(format!("redact.rules: rule '{}' ignored (bad pattern or group)", r.name)),
        }
    }
    if let Ok(mut g) = SETTINGS.write() {
        *g = Arc::new(Settings { ip: c.ip, allow, extra });
    }
    warn
}

// ---------------------------------------------------------------------------------------------------------
// hit recording (for `aix redact-test`)

thread_local! {
    static REC: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    static DEPTH: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
pub(crate) fn note_hit(name: &str) {
    hit(name)
}
fn hit(name: &str) {
    REC.with(|r| {
        if let Some(v) = r.borrow_mut().as_mut() {
            v.push(name.to_string());
        }
    });
}

/// Redact `text` and report which rules fired (rule name, count), sorted.
pub fn redact_with_hits(text: &str) -> (String, Vec<(String, usize)>) {
    REC.with(|r| *r.borrow_mut() = Some(vec![]));
    let out = redact_block(text);
    let hits = REC.with(|r| r.borrow_mut().take()).unwrap_or_default();
    let mut m: std::collections::BTreeMap<String, usize> = Default::default();
    for h in hits {
        *m.entry(h).or_default() += 1;
    }
    (out, m.into_iter().collect())
}

// ---------------------------------------------------------------------------------------------------------
// public API

/// Redact one line (a `\n` inside it is handled as a block).
pub fn redact_line(s: &str) -> String {
    redact_block(s)
}

/// Redact text of any size; the line count is preserved. Never panics (a failure masks everything), never slow.
pub fn redact_block(s: &str) -> String {
    match std::panic::catch_unwind(|| crate::text::redact_inner(s)) {
        Ok(r) => r,
        Err(_) => "***redaction-error***".to_string(),
    }
}

/// Redact every string value of a JSON document in place.
pub fn redact_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => *s = redact_block(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(redact_json),
        serde_json::Value::Object(o) => o.values_mut().for_each(redact_json),
        _ => {}
    }
}

/// Names of the built-in rules (the `***name***` hints): a user mask may not reuse one.
pub fn builtin_names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = COMPILED.defs.iter().map(|d| d.hint).collect();
    v.extend(["email", "phone", "card", "ip", "high-entropy", "base64-secret", "k8s-secret", "vault-blob", "private-key", "jwt", "secret", "redacted", "sql-secret", "name-value", "redaction-error"]);
    v.sort_unstable();
    v.dedup();
    v
}

fn mask(h: &str) -> String {
    format!("***{h}***")
}
fn is_masked(v: &str) -> bool {
    v.contains("***") || v.contains(PH_OPEN)
}

// ---------------------------------------------------------------------------------------------------------
// per-line driver, called by text::redact_one

const PH_OPEN: char = '\u{E000}';
const PH_CLOSE: char = '\u{E001}';

/// Wraps the single-line engine `core`: allow-list, long-line chunking, lookalike/escape-folded views.
pub(crate) fn guard(s: &str, core: &dyn Fn(&str) -> String) -> String {
    if s.is_empty() {
        return String::new();
    }
    let cfg = settings();
    let (s, ph) = if cfg.allow.is_empty() { (Cow::Borrowed(s), vec![]) } else { protect_allowed(s, &cfg.allow) };
    let mut out = if s.len() > CHUNK { chunked(&s, core) } else { views(&s, core) };
    for (i, orig) in ph.iter().enumerate() {
        out = out.replace(&format!("{PH_OPEN}{i}{PH_CLOSE}"), orig);
    }
    out
}

fn views(s: &str, core: &dyn Fn(&str) -> String) -> String {
    let plain = core(s);
    if s.is_ascii() && !s.contains(['%', '\\', '&']) && !(s.contains('+') && s.contains(['"', '\''])) && !(s.len() >= 11 && SPACED.is_match(s)) {
        return plain;
    }
    // a second view with lookalikes folded and escapes (\u0070, %70, &#112;) decoded: kept only when it finds more
    if DEPTH.with(|d| d.get()) > 0 {
        return plain;
    }
    let n = normalise(s);
    if n == s {
        return plain;
    }
    DEPTH.with(|d| d.set(d.get() + 1));
    let rn = core(&n);
    DEPTH.with(|d| d.set(d.get() - 1));
    if rn != n && (rn.matches("***").count() > plain.matches("***").count() || mask_kinds(&rn).iter().any(|k| !mask_kinds(&plain).contains(k))) {
        rn
    } else {
        plain
    }
}

/// The type hints of the `***hint***` masks in `s`.
fn mask_kinds(s: &str) -> Vec<&str> {
    s.split("***").skip(1).step_by(2).filter(|h| !h.is_empty() && h.len() < 24 && !h.contains(' ')).collect()
}

fn chunked(s: &str, core: &dyn Fn(&str) -> String) -> String {
    // whole-line pass first (linear regexes catch tokens that straddle a chunk edge), then bounded slices
    let pre = typed_pass(s);
    let s = pre.as_deref().unwrap_or(s);
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let mut e = (i + CHUNK).min(s.len());
        if e < s.len() {
            let lo = e.saturating_sub(256).max(i + 1);
            if let Some(p) = s.as_bytes()[lo..e].iter().rposition(|b| matches!(b, b' ' | b'\t' | b',' | b';' | b'&')) {
                e = lo + p + 1;
            }
            while !s.is_char_boundary(e) {
                e += 1;
            }
        }
        out.push_str(&views(&s[i..e], core));
        i = e;
    }
    out
}

fn protect_allowed<'a>(s: &'a str, allow: &HashSet<String>) -> (Cow<'a, str>, Vec<String>) {
    let mut ph: Vec<String> = vec![];
    let mut out = s.to_string();
    let mut cands: Vec<&str> = vec![s.trim()];
    for t in s.split(|c: char| c.is_whitespace() || "\"'`,;()<>[]{}".contains(c)) {
        if t.len() >= 4 {
            cands.push(t);
            if let Some((_, v)) = t.split_once(['=', ':']) {
                if v.len() >= 4 {
                    cands.push(v);
                }
            }
        }
    }
    for t in cands {
        if t.len() >= 4 && !ph.iter().any(|p| p == t) && allow.contains(&hash_allow(t)) && out.contains(t) {
            out = out.replace(t, &format!("{PH_OPEN}{}{PH_CLOSE}", ph.len()));
            ph.push(t.to_string());
        }
    }
    if ph.is_empty() {
        (Cow::Borrowed(s), ph)
    } else {
        (Cow::Owned(out), ph)
    }
}

/// Fold what hides a keyword from the detectors: fullwidth forms, Cyrillic/Greek lookalikes, zero-width chars,
/// `\uXXXX` / `\xNN` / `&#NN;` escapes, `%XX` escapes.
fn normalise(s: &str) -> String {
    let joined = despace(&join_literals(s));
    let s = joined.as_str();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let hex = |x: &[u8]| -> Option<u32> { u32::from_str_radix(std::str::from_utf8(x).ok()?, 16).ok() };
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 5 < b.len() + 0 && b[i + 1] == b'u' {
            if let Some(v) = hex(&b[i + 2..i + 6]) {
                if let Some(ch) = char::from_u32(v) {
                    out.push(fold_char(ch));
                    i += 6;
                    continue;
                }
            }
        }
        if c == b'\\' && i + 3 < b.len() + 0 && b[i + 1] == b'x' {
            if let Some(v) = hex(&b[i + 2..i + 4]) {
                out.push(v as u8 as char);
                i += 4;
                continue;
            }
        }
        if c == b'&' && i + 3 < b.len() && b[i + 1] == b'#' {
            let rest = &s[i + 2..(i + 10).min(s.len())];
            if let Some(semi) = rest.find(';') {
                let num = &rest[..semi];
                let v = if let Some(h) = num.strip_prefix(['x', 'X']) { u32::from_str_radix(h, 16).ok() } else { num.parse().ok() };
                if let Some(ch) = v.and_then(char::from_u32) {
                    out.push(fold_char(ch));
                    i += 2 + semi + 1;
                    continue;
                }
            }
        }
        if c == b'%' && i + 2 < b.len() + 0 {
            if let Some(v) = hex(&b[i + 1..i + 3]) {
                if (0x20..0x7f).contains(&v) {
                    out.push(v as u8 as char);
                    i += 3;
                    continue;
                }
            }
        }
        if c < 0x80 {
            out.push(c as char);
            i += 1;
        } else {
            let ch = s[i..].chars().next().unwrap();
            let f = fold_char(ch);
            if f != '\0' {
                out.push(f);
            }
            i += ch.len_utf8();
        }
    }
    out
}

static SPACED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:\b)(?:[A-Za-z][ ._-]){5,}[A-Za-z](?-u:\b)").unwrap());

/// `p a s s w o r d = x`, `p.a.s.s.w.o.r.d: x`: a credential word spelled out letter by letter is joined back.
fn despace(s: &str) -> String {
    const WORDS: &[&str] = &["password", "passwd", "secret", "token", "apikey", "passphrase", "credential", "privatekey", "accesskey"];
    if !SPACED.is_match(s) {
        return s.to_string();
    }
    SPACED
        .replace_all(s, |c: &regex::Captures| {
            let j: String = c[0].chars().filter(|ch| ch.is_ascii_alphabetic()).collect();
            if WORDS.iter().any(|w| j.to_ascii_lowercase().contains(w)) {
                j
            } else {
                c[0].to_string()
            }
        })
        .into_owned()
}

/// `"ab" + "cd"` -> `"abcd"` (also `.`, `~`, implicit adjacency): a secret split over concatenated literals.
fn join_literals(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut last = 0;
    while i < b.len() {
        if matches!(b[i], b'"' | b'\'') {
            let q = b[i];
            let mut j = i + 1;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
                if j > i + 1 && b[j - 1] == q && b[j - 2] != b'\\' {
                    break;
                }
            }
            // `j` is just past a closing quote when one was found
            if j <= b.len() && j > i + 1 && b[j - 1] == q {
                let mut k = j;
                while k < b.len() && matches!(b[k], b' ' | b'\t') {
                    k += 1;
                }
                let mut m = k;
                if m < b.len() && matches!(b[m], b'+' | b'.' | b'~') {
                    m += 1;
                    while m < b.len() && matches!(b[m], b' ' | b'\t') {
                        m += 1;
                    }
                }
                if m < b.len() && b[m] == q && m > j - 1 && (k != j || m != k) {
                    // drop the closing quote, the operator and the opening quote
                    out.push_str(&s[last..j - 1]);
                    last = m + 1;
                    i = m + 1;
                    continue;
                }
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    if last == 0 {
        return s.to_string();
    }
    out.push_str(&s[last..]);
    out
}

/// ASCII look-alike of `c` (or `c`); `\0` for invisible characters.
fn fold_char(c: char) -> char {
    match c {
        '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}' | '\u{200E}' | '\u{200F}' => '\0',
        '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        'а' | 'α' => 'a',
        'ԁ' => 'd',
        'ɡ' => 'g',
        'е' | 'ε' => 'e',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'с' | 'ϲ' => 'c',
        'х' | 'χ' => 'x',
        'у' => 'y',
        'і' | 'ι' | 'ı' => 'i',
        'ј' => 'j',
        'ѕ' => 's',
        'ӏ' | 'ⅼ' => 'l',
        'ո' => 'n',
        'ν' => 'v',
        'τ' => 't',
        'κ' | 'к' => 'k',
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'Е' | 'Ε' => 'E',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'Н' | 'Η' => 'H',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'С' => 'C',
        'Т' | 'Τ' => 'T',
        'Х' | 'Χ' => 'X',
        'Ѕ' => 'S',
        'І' => 'I',
        '\u{2010}'..='\u{2015}' | '\u{2212}' => '-',
        _ => c,
    }
}

// ---------------------------------------------------------------------------------------------------------
// the typed rule table

#[derive(Clone, Copy, PartialEq)]
enum Chk {
    None,
    /// value has a digit
    Digit,
    /// not a reference/placeholder (`${X}`, `<token>`, `$TOKEN`) or a plain word
    Value,
    /// value has a digit or symbol
    Mixed,
    Email,
    Template,
    Ip,
    Literal,
    /// not a `${X}` / `$X` / `{{ x }}` reference
    NotRef,
    /// a default after `${NAME:-` that is a value: not an error message (`:?msg`), an alternative (`:+x`) or empty
    Default,
    /// has a digit and a letter (a bare token, not a word or a number)
    Alnum,
}

struct RuleDef {
    hint: &'static str,
    pat: String,
    grp: usize,
    chk: Chk,
}

const KW: &str = r"(?:password|passwd|passphrase|pass_?word|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?key|credentials?|pwd|psk|preshared[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key)";
const DQ: &str = r#""(?:[^"\\\n]|\\.)*""#;
const SQ: &str = r"'(?:[^'\\\n]|\\.)*'";
const BT: &str = r"`[^`\n]*`";

fn key() -> String {
    format!(r"(?i:(?-u:\b)[A-Za-z0-9_.-]*{KW}(?:[._-][A-Za-z0-9_.-]*|(?-i:[A-Z])[A-Za-z0-9_.-]*)?)")
}

fn rules() -> Vec<RuleDef> {
    let k = key();
    let mut v: Vec<RuleDef> = vec![];
    let mut add = |hint: &'static str, pat: String, grp: usize, chk: Chk| v.push(RuleDef { hint, pat, grp, chk });
    let b = r"(?-u:\b)";
    // ---- private keys (PEM, OpenSSH, PGP, PKCS8, encrypted), body included, truncated blocks too
    add("private-key", r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\z)".into(), 0, Chk::None);
    add("private-key", r"(?-u:\b)PuTTY-User-Key-File-\d: \S+".into(), 0, Chk::None);
    // ---- cloud
    add("aws-key", format!(r"{b}(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|ABIA|ACCA)[0-9A-Z]{{16}}{b}"), 0, Chk::None);
    add("aws-secret", r#"(?i)aws[A-Za-z0-9_.-]{0,24}(?:secret|session|sk)[A-Za-z0-9_.-]{0,24}\\?["']?[ \t]*[:=][ \t]*\\?["']?([A-Za-z0-9/+=]{40}|[A-Za-z0-9/+=]{100,})"#.into(), 1, Chk::None);
    add("aws-secret", r#"(?i)secret_?access_?key\\?["']?[ \t]*[:=][ \t]*\\?["']?([A-Za-z0-9/+=]{40})"#.into(), 1, Chk::None);
    add("gcp-api-key", format!(r"{b}AIza[0-9A-Za-z_-]{{35}}"), 0, Chk::None);
    add("gcp-oauth", format!(r"{b}ya29\.[0-9A-Za-z_-]{{20,}}"), 0, Chk::None);
    add("gcp-secret", format!(r"{b}GOCSPX-[A-Za-z0-9_-]{{20,}}"), 0, Chk::None);
    add("gcp-key-id", r#"(?i)private_key_id\\?"[ \t]*:[ \t]*\\?"([0-9a-f]{40})"#.into(), 1, Chk::None);
    add("azure-key", r#"(?i)(?-u:\b)(?:AccountKey|SharedAccessKey|SharedAccessSignature|PrimaryKey|SecondaryKey)[ \t]*=[ \t]*([^;\s"'<>]{8,})"#.into(), 1, Chk::Value);
    add("azure-sas", r#"(?i)[?&;]sig=([A-Za-z0-9%+/=_-]{20,})"#.into(), 1, Chk::None);
    add("azure-secret", format!(r"{b}[A-Za-z0-9_~.-]{{3}}[0-9]Q~[A-Za-z0-9_~.-]{{31,34}}"), 0, Chk::None);
    add("db-password", r#"(?i);[ \t]*(?:Password|Pwd)[ \t]*=[ \t]*([^;"'<>]+)"#.into(), 1, Chk::Value);
    // ---- git hosts, chat, payment, mail, registries
    add("github-token", format!(r"{b}(?:gh[pousr])_[A-Za-z0-9_]{{20,}}"), 0, Chk::None);
    add("github-token", format!(r"{b}github_pat_[A-Za-z0-9_]{{20,}}"), 0, Chk::None);
    add("gitlab-token", format!(r"{b}(?:glpat|glptt|gldt|glrt|glcbt|glsoat|glagent|gloas|glimt|glffct)-[A-Za-z0-9_-]{{16,}}"), 0, Chk::None);
    add("gitlab-token", format!(r"{b}GR1348941[A-Za-z0-9_-]{{16,}}"), 0, Chk::None);
    add("slack-token", format!(r"{b}xox[abposre]-[A-Za-z0-9-]{{10,}}"), 0, Chk::None);
    add("slack-token", format!(r"{b}xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+"), 0, Chk::None);
    add("slack-webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}".into(), 0, Chk::None);
    add("discord-webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{30,}".into(), 0, Chk::None);
    add("stripe-key", format!(r"{b}(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{{8,}}"), 0, Chk::None);
    add("stripe-key", format!(r"{b}whsec_[A-Za-z0-9]{{16,}}"), 0, Chk::None);
    add("twilio-sid", format!(r"{b}(?:AC|SK)[0-9a-fA-F]{{32}}{b}"), 0, Chk::None);
    add("twilio-token", r"(?i)twilio[^\n]{0,40}?(?-u:\b)([0-9a-f]{32})(?-u:\b)".into(), 1, Chk::None);
    add("sendgrid-key", format!(r"{b}SG\.[A-Za-z0-9_-]{{16,}}\.[A-Za-z0-9_-]{{16,}}"), 0, Chk::None);
    add("mailgun-key", format!(r"{b}key-[0-9a-f]{{32}}{b}"), 0, Chk::None);
    add("mailgun-key", format!(r"{b}[0-9a-f]{{32}}-[0-9a-f]{{8}}-[0-9a-f]{{8}}{b}"), 0, Chk::None);
    add("mailchimp-key", format!(r"{b}[0-9a-f]{{32}}-us[0-9]{{1,2}}{b}"), 0, Chk::None);
    add("npm-token", format!(r"{b}npm_[A-Za-z0-9]{{30,}}"), 0, Chk::None);
    add("npm-auth", r#"(?i)(?:^|[\s"'])(?://[^\s"']+/:)?_(?:authToken|auth|password)[ \t]*=[ \t]*["']?([^\s"']+)"#.into(), 1, Chk::Value);
    add("pypi-token", format!(r"{b}pypi-[A-Za-z0-9_-]{{40,}}"), 0, Chk::None);
    add("docker-token", format!(r"{b}dckr_(?:pat|oat)_[A-Za-z0-9_-]{{20,}}"), 0, Chk::None);
    add("docker-auth", r#"(?i)"(?:auth|identitytoken|registrytoken)\\?"[ \t]*:[ \t]*\\?"([A-Za-z0-9+/=_-]{12,})"#.into(), 1, Chk::None);
    add("hf-token", format!(r"{b}(?:hf|api_org)_[A-Za-z0-9]{{30,}}"), 0, Chk::None);
    add("anthropic-key", format!(r"{b}sk-ant-[A-Za-z0-9_-]{{20,}}"), 0, Chk::None);
    add("openai-key", format!(r"{b}sk-(?:proj-|svcacct-|admin-|live-|test-)?[A-Za-z0-9_-]{{20,}}"), 0, Chk::Digit);
    add("shopify-token", format!(r"{b}shp(?:at|ca|pa|ss)_[a-f0-9]{{32}}"), 0, Chk::None);
    add("square-token", format!(r"{b}sq0(?:atp|csp)-[A-Za-z0-9_-]{{22,}}"), 0, Chk::None);
    add("databricks-token", format!(r"{b}dapi[a-f0-9]{{32}}(?:-[0-9])?"), 0, Chk::None);
    add("digitalocean-token", format!(r"{b}do[pro]_v1_[a-f0-9]{{40,}}"), 0, Chk::None);
    add("atlassian-token", format!(r"{b}ATATT3[A-Za-z0-9_=-]{{40,}}"), 0, Chk::None);
    add("postman-key", format!(r"{b}PMAK-[a-f0-9]{{24}}-[a-f0-9]{{34}}"), 0, Chk::None);
    add("newrelic-key", format!(r"{b}NRAK-[A-Z0-9]{{27}}"), 0, Chk::None);
    add("vault-token", format!(r"{b}hv[sbr]\.[A-Za-z0-9_-]{{20,}}"), 0, Chk::None);
    add("terraform-token", format!(r"{b}[A-Za-z0-9]{{14}}\.atlasv1\.[A-Za-z0-9_=-]{{60,}}"), 0, Chk::None);
    add("age-key", format!(r"{b}AGE-SECRET-KEY-1[A-Z0-9]{{58}}"), 0, Chk::None);
    add("grafana-token", format!(r"{b}glsa_[A-Za-z0-9]{{32}}_[a-f0-9]{{8}}"), 0, Chk::None);
    add("grafana-token", format!(r"{b}glc_[A-Za-z0-9+/]{{30,}}"), 0, Chk::None);
    add("linear-key", format!(r"{b}lin_api_[A-Za-z0-9]{{30,}}"), 0, Chk::None);
    add("supabase-key", format!(r"{b}sbp_[a-f0-9]{{40}}"), 0, Chk::None);
    add("notion-token", format!(r"{b}(?:secret|ntn)_[A-Za-z0-9]{{40,}}"), 0, Chk::Digit);
    add("telegram-token", format!(r"{b}[0-9]{{8,10}}:AA[A-Za-z0-9_-]{{30,40}}(?:{b}|$)"), 0, Chk::None);
    add("sentry-token", format!(r"{b}sntrys_[A-Za-z0-9+/=_]{{40,}}"), 0, Chk::None);
    add("figma-token", format!(r"{b}figd_[A-Za-z0-9_-]{{30,}}"), 0, Chk::None);
    add("bearer", r"(?i)(?-u:\b)bearer\s+([A-Za-z0-9._~+/-]{16,}=*)".into(), 1, Chk::Value);
    // ---- JWTs (signed, unsigned) and password hashes
    add("jwt", r"(?-u:\b)eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?".into(), 0, Chk::None);
    add("jwt", r"(?-u:\b)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*".into(), 0, Chk::None);
    add("pw-hash", r"\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}".into(), 0, Chk::None);
    add("pw-hash", r"\$(?:1|5|6|apr1)\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}".into(), 0, Chk::None);
    add("pw-hash", r"\$argon2(?:id|i|d)\$[^\s\x22']{20,}".into(), 0, Chk::None);
    add("vault-blob", r"ENC\[AES256_GCM,data:[A-Za-z0-9+/=]+(?:,[a-z]+:[A-Za-z0-9+/=]+)*\]".into(), 0, Chk::None);
    add("vault-blob", r"(?-u:\b)vault:v[0-9]+:[A-Za-z0-9+/=]{12,}".into(), 0, Chk::None);
    add("vault-blob", r"\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9]+".into(), 0, Chk::None);
    // ---- URLs with credentials: databases/brokers first, then any scheme. The password may hold `/` or `@`.
    let tail = r#"(@[A-Za-z0-9._\[\]-]*(?:[:/?#]|$|[\s"'<>]))"#;
    add("db-password", format!(r#"(?i)((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|cockroachdb|clickhouse|kafka|nats|memcached|couchdb|cassandra|neo4j|bolt|jdbc:[a-z0-9:]+)://[^/\s:@"']*:)([^\s"'<>]*?){tail}"#), 2, Chk::NotRef);
    add("basic-auth", format!(r#"(?i)([a-z][a-z0-9+.-]*://[^/\s:@"']*:)([^\s"'<>]*?){tail}"#), 2, Chk::NotRef);
    // ---- headers, cookies, netrc, CLI literals
    add("authz", r#"(?i)(?-u:\b)(?:proxy-)?authorization\\?["']?[ \t]*[:=][ \t]*\\?["']?(?:(?:basic|bearer|digest|token|negotiate|apikey|hmac|aws4-hmac-sha256)\s+)?([^\s"',;\\]+)"#.into(), 1, Chk::Value);
    add("header-secret", r#"(?i)(?-u:\b)(?:x-api-key|x-auth-token|x-access-token|x-amz-security-token|x-csrf-token|x-xsrf-token|api-key|private-token|x-gitlab-token|x-vault-token|x-github-token|ocp-apim-subscription-key|x-functions-key)\\?["']?[ \t]*[:=][ \t]*\\?["']?([^\s"',;\\]+)"#.into(), 1, Chk::Value);
    add("cookie", r#"(?i)(?-u:\b)cookie\\?["']?[ \t]*[:=][ \t]*\\?["']?([A-Za-z0-9_.%-]+=[^"'\n]*)"#.into(), 1, Chk::Value);
    add("cookie", r#"(?i)(?:\s-b|--cookie)[\s=]+["']?([^\s"']*=[^\s"']+)"#.into(), 1, Chk::Value);
    add("session", r#"(?i)(?-u:\b)(?:jsessionid|phpsessid|sessionid|session_id|session-id|connect\.sid|aspsessionid[a-z]*|csrftoken|csrf_token|xsrf-token|sid)\\?["']?[ \t]*[:=][ \t]*\\?["']?([A-Za-z0-9%._~+/-]{8,})"#.into(), 1, Chk::Mixed);
    add("netrc", r"(?i)(?-u:\b)machine\s+\S+\s+login\s+\S+\s+password\s+(\S+)".into(), 1, Chk::Value);
    add("netrc", r"(?im)^[ \t]*password\s+(\S+)[ \t]*$".into(), 1, Chk::Mixed);
    add("k8s-literal", r"--from-literal=[A-Za-z0-9_.-]+=(\S+)".into(), 1, Chk::Value);
    // ---- generic key/value in code and configs
    // Go `:=`, Ruby/PHP `=>`, R `<-`: a quoted literal
    add("secret", format!(r#"({k}["']?[ \t]*(?::=|=>|<-)[ \t]*)((?:[fFrRbBuU]{{1,2}})?(?:{DQ}|{SQ}|{BT}))"#), 2, Chk::Literal);
    // f-strings / template literals with literal parts
    add("secret", format!(r#"({k}["']?[ \t]*(?:=|:)[ \t]*)((?:[fFrRbBuU]{{1,2}}(?:{DQ}|{SQ})|{BT}))"#), 2, Chk::Template);
    // concatenation of literals (`"ab" + "cd"`, `"ab" . $x . "cd"`, adjacent literals)
    let lit = format!(r#"(?:[fFrR]?(?:{DQ}|{SQ}))"#);
    let sep = r"(?:[ \t]*[+.~][ \t]*|\s+)";
    add("secret", format!(r#"({k}["']?[ \t]*(?::=|=|:)[ \t]*\(?[ \t]*)({lit}(?:{sep}(?:{lit}|[A-Za-z_][A-Za-z0-9_.]*))*{sep}{lit})"#), 2, Chk::None);
    // JSON inside a string: \"password\": \"value\"
    add("secret", format!(r#"({k}\\+["'][ \t]*[:=][ \t]*\\+["'])((?:[^"'\\]|\\[^"'])+)"#), 2, Chk::Value);
    // XML: <password>x</password>, <add key="ApiKey" value="x"/>, <entry key="db.password">x</entry>
    add("secret", r#"(?i)(<[A-Za-z0-9:._-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential|pwd|private[_-]?key|access[_-]?key)[A-Za-z0-9:.-]*(?:\s[^>]*)?>)([^<>\s][^<>]*)(</)"#.into(), 2, Chk::Value);
    add("secret", r#"(?i)(<[A-Za-z0-9:.-]+\s+(?:key|name)[ \t]*=[ \t]*["'][A-Za-z0-9:._-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential|pwd|private[_-]?key|access[_-]?key)[A-Za-z0-9:._-]*["'][ \t]*>)([^<]+)(</)"#.into(), 2, Chk::Value);
    add("secret", r#"(?i)(\b(?:key|name)[ \t]*=[ \t]*["'][A-Za-z0-9:._-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential|pwd|private[_-]?key|access[_-]?key)[A-Za-z0-9:._-]*["']\s+(?:value|connectionString)[ \t]*=[ \t]*["'])([^"']*)(["'])"#.into(), 2, Chk::Value);
    add("secret", r#"(?i)(\bvalue[ \t]*=[ \t]*["'])([^"']*)(["']\s+(?:key|name)[ \t]*=[ \t]*["'][A-Za-z0-9:._-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|credential|pwd|private[_-]?key|access[_-]?key))"#.into(), 2, Chk::Value);
    // prose: `the api_key is Zq81xKvPlm`
    add("secret", format!(r"(?i)({k}\s+(?:is|was|are)[ \t]*:?[ \t]*)(\S+)"), 2, Chk::Mixed);
    // `${DB_PASSWORD:-hunter2}`, `${db.password:secret}`: the default is the value
    add("secret", format!(r"(?i)(\$\{{[A-Za-z0-9_.-]*{KW}[A-Za-z0-9_.-]*(?::-|:=|:|-|=))([^}}\n$]+)(\}})"), 2, Chk::Default);
    // `os.getenv("DB_PASSWORD", "default")`, `env('KEY', 'default')`, `getOrDefault("pw", "x")`
    add("secret", format!(r#"(?i)((?:getenv|environ\.get|env\.get|env\.fetch|getordefault|get_env|getproperty|\benv)\([ \t]*["'][^"'\n]*(?:password|passwd|secret|token|api[_-]?key|pass|pwd|credential)[^"'\n]*["'][ \t]*,[ \t]*)({DQ}|{SQ})"#), 2, Chk::Literal);
    // PII in credential context: national-ID like digit runs
    add("national-id", r#"(?i)(?-u:\b)(?:ssn|sss|tin|philsys|national[ _-]?id|passport|nin|gsis|umid|pag-?ibig|philhealth|id[ _-]?number)\\?["']?[ \t]*[:=][ \t]*\\?["']?([0-9][0-9 -]{7,18}[0-9])"#.into(), 1, Chk::None);
    // US SSN (ddd-dd-dddd) near an SSN / social-security / tax-id word, any separator wording ("SSN 123-45-6789", "social security number is ...")
    add("national-id", r#"(?i)(?-u:\b)(?:ssn|ss#|social[ _-]?security(?:[ _-]?(?:number|no\.?|num|#))?|tax[ _-]?id|taxpayer[ _-]?id)[^\n0-9]{0,30}?(?-u:\b)([0-9]{3}[- ][0-9]{2}[- ][0-9]{4})(?-u:\b)"#.into(), 1, Chk::None);
    // ---- SQL account statements: IDENTIFIED BY 'x', WITH PASSWORD 'x', PASSWORD('x')
    add("sql-password", r#"(?i)((?-u:\b)IDENTIFIED(?:[ \t]+WITH[ \t]+[A-Za-z0-9_]+)?[ \t]+(?:BY|AS)[ \t]+(?:PASSWORD[ \t]+|RANDOM[ \t]+PASSWORD[ \t]+)?)('(?:[^']|'')*'|"[^"\n]*"|[^\s;,)'"]+)"#.into(), 2, Chk::Value);
    add("sql-password", r#"(?i)((?-u:\b)PASSWORD(?:[ \t]+|[ \t]*\([ \t]*))('(?:[^'\\]|\\.|'')+'|"(?:[^"\\\n]|\\.)+")"#.into(), 2, Chk::Value);
    // ---- name/value pairs on one line: HAR / JSON / cookies / YAML flow `{"name":"X-Api-Key","value":"..."}`
    let nm = r"(?:[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|pwd|psk|session|sid|csrf|xsrf|jwt|bearer|cookie)[A-Za-z0-9_.-]*)";
    add("name-value", format!(r#"(?i)(["']?name["']?[ \t]*[:=][ \t]*["']?{nm}["']?[ \t]*,[ \t]*["']?value["']?[ \t]*[:=][ \t]*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,}}\]"']+)"#), 2, Chk::Value);
    add("name-value", format!(r#"(?i)(["']?value["']?[ \t]*[:=][ \t]*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,}}\]"']+)([ \t]*,[ \t]*["']?name["']?[ \t]*[:=][ \t]*["']?{nm}["']?)"#), 2, Chk::Value);
    // ---- CI log commands and argv lists
    add("add-mask", r"(?i)(::add-mask::)(\S.*)".into(), 2, Chk::None);
    add("argv-secret", r#"(?i)(["']--?(?:[a-z0-9]+[_-])*(?:password|passwd|pass|pwd|passphrase|token|secret|api[_-]?key|auth[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret|psk|key)["'][ \t]*,[ \t]*)("(?:[^"\\\n]|\\.)+"|'(?:[^'\\\n]|\\.)+')"#.into(), 2, Chk::Value);
    // ---- Java / Kotlin / Scala: System.setProperty("db.password", "x"), props.put("secret", "x")
    add("secret", format!(r#"(?i)((?:setProperty|setenv|put|set|setString|setAttribute|putString|setSecret|define)\([ \t]*["'][^"'\n]*{KW}[^"'\n]*["'][ \t]*,[ \t]*)({DQ}|{SQ})"#), 2, Chk::Literal);
    // ---- markdown tables: | password | hunter2 |
    add("table-secret", format!(r#"(?i)^([ \t]*\|[ \t]*[`*_]*[A-Za-z0-9_. -]*{KW}[A-Za-z0-9_. -]*[`*_]*[ \t]*\|[ \t]*)`?([^|\s`]+)`?(?:[ \t]*\||[ \t]*$)"#), 2, Chk::Mixed);
    // ---- a bare 32-character lowercase+digit token right next to a credential word
    let kwn = KW.replace("api[_-]?key", "api[ _-]?key");
    add("token-near-key", format!(r#"(?i)({kwn}[^\n]{{0,24}}?(?-u:\b))([a-z0-9]{{32}})(?-u:\b)"#), 2, Chk::Alnum);
    add("token-near-key", format!(r#"(?i)(?-u:\b)([a-z0-9]{{32}})(?-u:\b)([^\n]{{0,24}}?{kwn})"#), 1, Chk::Alnum);
    v
}

struct Compiled {
    /// byte-mode, ASCII-only twin of the rules: decides which rules can match. (A Unicode set of this size falls out
    /// of the lazy DFA as soon as a line holds a non-ASCII character: 800x slower.)
    /// split in contiguous parts (first rule index, set) compiled in parallel: a set reports a rule exactly when
    /// that rule matches, so the parts together say the same as one set over all rules
    set: Vec<(usize, regex::bytes::RegexSet)>,
    defs: Vec<RuleDef>,
    res: Vec<OnceLock<Option<Regex>>>,
}
static COMPILED: LazyLock<Compiled> = LazyLock::new(|| {
    let defs = rules();
    let pats: Vec<&str> = defs.iter().map(|d| d.pat.as_str()).collect();
    let set = crate::warm::split_compile(&pats, |p| regex::bytes::RegexSetBuilder::new(p).unicode(false).size_limit(1 << 28).dfa_size_limit(1 << 27).build().expect("redact rules"));
    let res = (0..defs.len()).map(|_| OnceLock::new()).collect();
    Compiled { set, defs, res }
});

/// Compile the rule set now (see `warm.rs`).
pub(crate) fn warm_set() {
    LazyLock::force(&COMPILED);
}
/// Compile the other fixed detectors now (see `warm.rs`).
pub(crate) fn warm_rest() {
    LazyLock::force(&PII);
    LazyLock::force(&SPACED);
    LazyLock::force(&INSERT);
}

fn chk_ok(chk: Chk, v: &str) -> bool {
    let t = v.trim();
    match chk {
        Chk::None => true,
        Chk::Digit => v.bytes().any(|b| b.is_ascii_digit()),
        Chk::Value => value_ok(t),
        Chk::Mixed => t.bytes().any(|b| b.is_ascii_digit() || b"+/=%~!@#$^&*".contains(&b)) && value_ok(t),
        Chk::Email => email_ok(v),
        Chk::Ip => ip_ok(v),
        Chk::NotRef => !t.is_empty() && !is_ref(t),
        Chk::Default => !t.is_empty() && !t.starts_with(['?', '+', '-', '=']) && value_ok(t),
        Chk::Alnum => t.bytes().any(|b| b.is_ascii_digit()) && t.bytes().any(|b| b.is_ascii_alphabetic()),
        Chk::Literal => {
            let inner = t.trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_matches(['"', '\'', '`']);
            !inner.is_empty() && value_ok(inner)
        }
        Chk::Template => {
            // literal text outside {..} / ${..} / %s placeholders
            let inner = t.trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_matches(['"', '\'', '`']);
            let mut lit = 0;
            let mut depth = 0;
            for ch in inner.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' if depth > 0 => depth -= 1,
                    c if depth == 0 && c.is_alphanumeric() => lit += 1,
                    _ => {}
                }
            }
            lit >= 3
        }
    }
}

const WORDS: &[&str] = &[
    "required", "optional", "string", "true", "false", "null", "none", "nil", "undefined", "value", "empty", "invalid", "missing", "hidden",
    "masked", "redacted", "changeme", "example", "yes", "no", "on", "off", "default", "enabled", "disabled", "basic", "bearer", "digest",
    "token", "password", "secret", "username", "user", "name", "type", "id", "text", "number", "boolean", "object", "array", "any",
];
/// `${X}`, `$X`, `{{ x }}`, `$(cmd)`, `<x>`: a reference, not a value.
pub(crate) fn is_ref(t: &str) -> bool {
    let t = t.trim().trim_matches(['"', '\'']);
    t.starts_with("${") || t.starts_with("{{") || t.starts_with("$(") || t.starts_with("<%") || t.starts_with('{') || (t.len() > 1 && t.starts_with('$') && t[1..].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
}
/// A credential-like value, not a reference (`${X}`, `$X`, `<token>`, `{{ x }}`, `%X%`, `process.env.X`) or a plain word.
static SHELL_REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\$(?:[A-Z_][A-Z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?:[:?+=-][^}]*)?\}|[0-9])$").unwrap());

fn value_ok(t: &str) -> bool {
    if t.len() < 2 || is_masked(t) {
        return false;
    }
    // a quoted reference (`PASSWORD '$APP_PW'`, `--password "$KC_PW"`) is still a reference, not a value
    let b = t.as_bytes();
    // (the whole inner text one upper-case / braced / positional shell variable: `'$ecret99'` stays a value)
    if t.len() >= 3 && matches!(b[0], b'"' | b'\'' | b'`') && b[t.len() - 1] == b[0] && SHELL_REF.is_match(&t[1..t.len() - 1]) {
        return false;
    }
    if t.starts_with(['$', '<', '{', '%', '[', '(', '@', '#']) || t.contains("${") || t.contains("{{") || t.contains("<%") {
        return false;
    }
    let l = t.trim_matches(|c: char| !c.is_alphanumeric()).to_ascii_lowercase();
    !WORDS.contains(&l.as_str())
}

fn email_ok(v: &str) -> bool {
    let Some((local, dom)) = v.rsplit_once('@') else { return false };
    let dl = dom.to_ascii_lowercase();
    let ll = local.to_ascii_lowercase();
    if matches!(ll.as_str(), "git" | "hg" | "svn" | "noreply" | "no-reply" | "donotreply" | "do-not-reply" | "nobody") {
        return false;
    }
    let tld = dl.rsplit('.').next().unwrap_or("");
    const EXT: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ts", "tsx", "jsx", "json", "html", "xml", "yml", "yaml", "md", "txt", "woff", "woff2",
        "ttf", "otf", "eot", "ico", "mp4", "webm", "map", "lock", "sql", "java", "py", "rs", "go", "sh", "scss", "less", "avif", "bmp", "pdf", "zip",
        "gz", "tgz", "jar", "class", "c", "h", "cpp", "hpp", "vue", "svelte", "properties", "toml", "ini", "cfg", "conf", "log", "csv", "tsv",
    ];
    if EXT.contains(&tld) {
        return false;
    }
    let reserved = ["example.com", "example.org", "example.net", "example.edu", "localhost", "users.noreply.github.com", "email.com", "domain.com", "mail.com", "test.com", "foo.com", "bar.com", "acme.com", "company.com", "yourdomain.com", "yourcompany.com", "your-domain.com"];
    if reserved.iter().any(|r| dl == *r || dl.ends_with(&format!(".{r}"))) {
        return false;
    }
    !matches!(tld, "test" | "invalid" | "local" | "localhost" | "example" | "internal" | "lan" | "home")
}

fn luhn(d: &[u8]) -> bool {
    let mut sum = 0;
    for (i, b) in d.iter().rev().enumerate() {
        let mut x = (b - b'0') as u32;
        if i % 2 == 1 {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
    }
    sum % 10 == 0
}
fn card_ok(v: &str) -> bool {
    let d: Vec<u8> = v.bytes().filter(u8::is_ascii_digit).collect();
    if !(13..=19).contains(&d.len()) || d.iter().all(|x| *x == d[0]) {
        return false;
    }
    let p2 = (d[0] - b'0') as u32 * 10 + (d[1] - b'0') as u32;
    let p4 = p2 * 100 + (d[2] - b'0') as u32 * 10 + (d[3] - b'0') as u32;
    let iin = match d[0] {
        b'4' => matches!(d.len(), 13 | 16 | 19),
        b'5' => (51..=55).contains(&p2) && d.len() == 16,
        b'2' => (2221..=2720).contains(&p4) && d.len() == 16,
        b'3' => (matches!(p2, 34 | 37) && d.len() == 15) || (matches!(p2, 35 | 36 | 38 | 39) && (14..=19).contains(&d.len())),
        b'6' => (p4 == 6011 || p2 == 65 || p2 == 62 || (644..=649).contains(&(p4 / 10))) && (16..=19).contains(&d.len()),
        _ => false,
    };
    iin && luhn(&d)
}
fn phone_ok(v: &str) -> bool {
    let n = v.bytes().filter(u8::is_ascii_digit).count();
    (9..=15).contains(&n)
}
fn ip_ok(v: &str) -> bool {
    if v.contains(':') {
        return v.matches(':').count() >= 3 && v.bytes().any(|b| b.is_ascii_digit());
    }
    !matches!(v, "0.0.0.0" | "255.255.255.255") && !v.starts_with("127.")
}

fn rule_re(i: usize) -> Option<&'static Regex> {
    let c = &*COMPILED;
    c.res[i].get_or_init(|| RegexBuilder::new(&c.defs[i].pat).size_limit(1 << 26).build().ok()).as_ref()
}

fn apply(re: &Regex, grp: usize, hint: &str, chk: Chk, s: &str) -> Option<String> {
    let mut out = String::new();
    let mut last = 0;
    let mut changed = false;
    for c in re.captures_iter(s) {
        let Some(m) = c.get(grp) else { continue };
        let v = m.as_str();
        if m.start() < last || is_masked(v) || !chk_ok(chk, v) {
            continue;
        }
        if matches!(chk, Chk::Template | Chk::Literal) && c.get(1).is_some_and(|k| crate::text::name_key_value(k.as_str(), v)) {
            continue;
        }
        if hint == "email" && m.start() > 0 && s.as_bytes()[m.start() - 1] == b'\\' {
            continue; // `\n@router.get(...)` inside an escaped string: a decorator, not an address
        }
        out.push_str(&s[last..m.start()]);
        out.push_str(&mask(hint));
        last = m.end();
        changed = true;
        hit(hint);
    }
    if !changed {
        return None;
    }
    out.push_str(&s[last..]);
    Some(out)
}

/// Provider + generic detectors + the repo's extra rules. None when nothing matched.
pub(crate) fn typed_pass(s: &str) -> Option<String> {
    let c = &*COMPILED;
    let mut cur: Option<String> = None;
    let mut idx: Vec<usize> = c.set.iter().flat_map(|(at, set)| set.matches(s.as_bytes()).into_iter().map(move |i| at + i)).collect();
    idx.sort_unstable();
    for i in idx {
        let d = &c.defs[i];
        let Some(re) = rule_re(i) else { continue };
        let text = cur.as_deref().unwrap_or(s);
        if let Some(n) = apply(re, d.grp, d.hint, d.chk, text) {
            cur = Some(n);
        }
    }
    let cfg = settings();
    for (name, re, g) in &cfg.extra {
        let text = cur.as_deref().unwrap_or(s);
        if let Some(n) = apply(re, *g, name, Chk::None, text) {
            cur = Some(n);
        }
    }
    cur
}

// ---------------------------------------------------------------------------------------------------------
// base64-wrapped secrets, entropy, PII

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}
fn b64_decode(t: &str) -> Option<Vec<u8>> {
    let t = t.trim_end_matches('=');
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for b in t.bytes() {
        acc = (acc << 6) | b64_val(b)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Runs of base64/token characters of at least `min` bytes: (start, end) with `end` after optional `=` padding.
fn runs(s: &str, min: usize) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut v = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'-' | b'+' | b'/') {
            let st = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'-' | b'+' | b'/')) {
                i += 1;
            }
            let mut e = i;
            while e < b.len() && e < i + 2 && b[e] == b'=' {
                e += 1;
            }
            if i - st >= min {
                v.push((st, e));
            }
            i = e.max(i);
        } else {
            i += 1;
        }
    }
    v
}

fn has_secret(text: &str) -> bool {
    if text.len() < 6 {
        return false;
    }
    // typed + keyed layers only (no entropy, no PII, no nested decoding)
    DEPTH.with(|d| d.set(d.get() + 1));
    let r = typed_pass(text).is_some() || crate::text::redact_keyed_only(text) != text;
    DEPTH.with(|d| d.set(d.get() - 1));
    r
}

/// Tokens that decode to text containing a secret.
fn base64_pass(s: &str) -> Option<String> {
    if DEPTH.with(|d| d.get()) > 0 {
        return None;
    }
    let mut out = String::new();
    let mut last = 0;
    for (a, e) in runs(s, 16) {
        let tok = &s[a..e];
        if tok.len() > 4096 || is_masked(tok) || tok.contains("/") && tok.matches('/').count() > 4 && !tok.ends_with('=') {
            continue;
        }
        let Some(d) = b64_decode(tok) else { continue };
        if d.len() < 10 || d.iter().filter(|b| (0x20..0x7f).contains(*b) || matches!(b, b'\n' | b'\t' | b'\r')).count() * 10 < d.len() * 9 {
            continue;
        }
        let Ok(text) = String::from_utf8(d) else { continue };
        if has_secret(&text) || (text.split_once(':').is_some_and(|(u, p)| (1..40).contains(&u.len()) && p.len() >= 6 && !u.contains(' ') && !p.contains(' ') && tok.len() >= 16 && text.bytes().all(|b| (0x21..0x7f).contains(&b)) && b64_looks_basic(tok))) {
            out.push_str(&s[last..a]);
            out.push_str(&mask("base64-secret"));
            last = e;
            hit("base64-secret");
        }
    }
    if last == 0 {
        return None;
    }
    out.push_str(&s[last..]);
    Some(out)
}
/// `user:password` base64 pairs only count with padding or a mixed-case body (plain words decode to garbage anyway).
fn b64_looks_basic(tok: &str) -> bool {
    tok.ends_with('=') || tok.bytes().any(|b| b.is_ascii_digit()) && tok.bytes().any(|b| b.is_ascii_uppercase())
}

const LINE_SKIP: &[&str] = &["integrity", "checksum", "sha512-", "sha256-", "sha384-", "sha1-", "h1:", "data:image", "data:font", "data:application", "base64,", "resolved", "sha256:", "sha512:", "etag"];

fn entropy(t: &[u8]) -> f64 {
    let mut cnt = [0u32; 256];
    for b in t {
        cnt[*b as usize] += 1;
    }
    let n = t.len() as f64;
    cnt.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// Fraction of the token made of dictionary-shaped runs (`word`, `Word`, `WORD`): identifiers, slugs, constants.
fn wordiness(t: &[u8]) -> f64 {
    let mut in_word = 0;
    let mut i = 0;
    while i < t.len() {
        let st = i;
        let mut j = i;
        if t[j].is_ascii_uppercase() && j + 1 < t.len() && t[j + 1].is_ascii_lowercase() {
            j += 1;
        }
        let ls = j;
        let capped = j > st;
        while j < t.len() && t[j].is_ascii_lowercase() {
            j += 1;
        }
        if j - ls >= if capped { 3 } else { 4 } {
            in_word += j - st;
            i = j;
            continue;
        }
        let us = i;
        let mut k = i;
        while k < t.len() && t[k].is_ascii_uppercase() {
            k += 1;
        }
        if k - us >= 4 {
            in_word += k - us;
            i = k;
            continue;
        }
        i = st + 1;
    }
    in_word as f64 / t.len() as f64
}

fn token_is_secretlike(t: &str) -> bool {
    let b = t.as_bytes();
    let body = t.trim_end_matches('=');
    let bb = body.as_bytes();
    let (mut lo, mut up, mut dg, mut sy) = (0, 0, 0, 0);
    for c in bb {
        match c {
            b'a'..=b'z' => lo += 1,
            b'A'..=b'Z' => up += 1,
            b'0'..=b'9' => dg += 1,
            _ => sy += 1,
        }
    }
    if dg == 0 || lo + up == 0 {
        return false; // digit-less strings are identifiers/words; digit-only are numbers
    }
    if bb.iter().all(|c| c.is_ascii_hexdigit()) {
        return false; // hashes, git SHAs
    }
    if up == 0 && !body.contains(['+', '/']) {
        return false; // lowercase slugs, hex-ish, kebab/snake identifiers
    }
    let classes = (lo > 0) as u8 + (up > 0) as u8 + (dg > 0) as u8 + (sy > 0) as u8;
    if classes < 3 && !t.ends_with('=') {
        return false;
    }
    // uuid
    if body.len() == 36 && bb[8] == b'-' && bb[13] == b'-' && bb[18] == b'-' && bb[23] == b'-' {
        return false;
    }
    if wordiness(bb) >= 0.45 {
        return false;
    }
    let asc = bb.windows(2).filter(|w| w[1] == w[0] + 1).count();
    if asc * 100 > bb.len() * 30 {
        return false; // alphabets
    }
    let h = entropy(bb);
    let _ = b;
    if bb.len() < 32 {
        h >= 3.4
    } else {
        h >= 3.9
    }
}

const HEX_WORDS: &[&str] = &["commit", "sha", "hash", "checkout", "digest", "rev", "merge", "cherry", "blob", "tree", "parent", "HEAD", "image", "md5", "git ", "lock"];

/// Legacy opaque-run detector: leave lockfile digests, data: URIs, commit hashes next to their label and
/// identifiers (CamelCase, snake_case, CONSTANTS) alone.
pub(crate) fn skip_opaque(line: &str, tok: &str) -> bool {
    if LINE_SKIP.iter().any(|m| line.contains(m)) {
        return true;
    }
    let t = tok.trim_end_matches('=');
    let hex = t.bytes().all(|b| b.is_ascii_hexdigit());
    if matches!(t.len(), 32 | 40 | 64 | 128) && hex && HEX_WORDS.iter().any(|w| line.contains(w)) {
        return true;
    }
    // a commit pin: `uses: owner/repo@<40 hex>`, `git+https://host/x.git#<sha>`
    if matches!(t.len(), 40 | 64) && hex && (line.contains(&format!("@{t}")) || line.contains(&format!("#{t}")) || line.trim_start().trim_start_matches("- ").starts_with("uses:")) {
        return true;
    }
    // SVG path data (`M98 696v193h391v385h185-385`)
    if t.len() >= 24 && t.bytes().all(|b| b.is_ascii_digit() || b"MmLlHhVvCcSsQqTtAaZz.-".contains(&b)) && t.bytes().filter(|b| b.is_ascii_alphabetic()).count() >= 4 {
        return true;
    }
    // a slash-separated path of words (`/users/Gojo/friends/all-of-them`, `${dir}/webjars/META-INF/resources`)
    if t.matches('/').count() >= 2 && !t.contains('+') && !tok.ends_with('=') {
        let segs: Vec<&str> = t.split('/').filter(|x| !x.is_empty()).collect();
        let plain = segs.iter().filter(|x| !x.bytes().any(|b| b.is_ascii_digit())).count();
        if segs.len() >= 2 && plain * 10 >= segs.len() * 7 {
            return true;
        }
    }
    !t.contains(['+', '/']) && wordiness(t.as_bytes()) >= 0.5
}

fn entropy_pass(s: &str) -> Option<String> {
    if s.len() < 20 || LINE_SKIP.iter().any(|m| s.contains(m)) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = String::new();
    let mut last = 0;
    for (a, e) in runs(s, 20) {
        if a > 0 && matches!(b[a - 1], b'.' | b'@' | b'#' | b'\\') || e < b.len() && matches!(b[e], b'.') && b.get(e + 1).is_some_and(|c| c.is_ascii_alphabetic()) {
            continue; // file names, hosts, colours, escapes
        }
        let tok = &s[a..e];
        if is_masked(tok) {
            continue;
        }
        let mut cands: Vec<(usize, usize)> = vec![];
        if tok.contains('/') && !tok.contains('+') && !tok.ends_with('=') {
            let mut off = a;
            for seg in tok.split('/') {
                if seg.len() >= 20 {
                    // a path segment between slashes is a file/dir name unless it looks random
                    cands.push((off, off + seg.len()));
                }
                off += seg.len() + 1;
            }
            // paths: only flag a segment when the whole run is not shaped like a path of words
            if wordiness(tok.as_bytes()) >= 0.35 {
                cands.clear();
            }
        } else {
            cands.push((a, e));
        }
        for (x, y) in cands {
            if y - x >= 20 && token_is_secretlike(&s[x..y]) {
                out.push_str(&s[last..x]);
                out.push_str(&mask("high-entropy"));
                last = y;
                hit("high-entropy");
            }
        }
    }
    if last == 0 {
        return None;
    }
    out.push_str(&s[last..]);
    Some(out)
}

struct Pii {
    email: Regex,
    phone: Vec<Regex>,
    card: Regex,
    ip4: Regex,
    ip6: Regex,
}
static PII: LazyLock<Pii> = LazyLock::new(|| Pii {
    email: Regex::new(r"(?-u:\b)[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?-u:\b)").unwrap(),
    phone: vec![
        Regex::new(r"\+[0-9]{1,3}[ .-]?\(?[0-9]{1,4}\)?(?:[ .-]?[0-9]{2,4}){2,4}(?-u:\b)").unwrap(),
        Regex::new(r"(?-u:\b)09[0-9]{2}[ .-]?[0-9]{3}[ .-]?[0-9]{4}(?-u:\b)").unwrap(),
        Regex::new(r"\(0[0-9]{1,2}\)[ .-]?[0-9]{3,4}[ .-]?[0-9]{4}(?-u:\b)").unwrap(),
        Regex::new(r"(?-u:\b)\(?[0-9]{3}\)[ .-]?[0-9]{3}[ .-][0-9]{4}(?-u:\b)").unwrap(),
        Regex::new(r"(?-u:\b)[0-9]{3}[-.][0-9]{3}[-.][0-9]{4}(?-u:\b)").unwrap(),
    ],
    card: Regex::new(r"(?-u:\b)[0-9](?:[ -]?[0-9]){12,18}(?-u:\b)").unwrap(),
    ip4: Regex::new(r"(?-u:\b)(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?-u:\b)").unwrap(),
    ip6: Regex::new(r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){2,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,4})?").unwrap(),
});

fn pii_pass(s: &str) -> Option<String> {
    let p = &*PII;
    let mut cur: Option<String> = None;
    let get = |c: &Option<String>| -> String { c.clone().unwrap_or_else(|| s.to_string()) };
    let b = s.as_bytes();
    if b.contains(&b'@') {
        if let Some(n) = apply(&p.email, 0, "email", Chk::Email, cur.as_deref().unwrap_or(s)) {
            cur = Some(n);
        }
    }
    let ndig = b.iter().filter(|c| c.is_ascii_digit()).count();
    if ndig >= 9 {
        let text = get(&cur);
        // card: digits not glued to a longer number/decimal
        let mut out = String::new();
        let mut last = 0;
        for m in p.card.find_iter(&text) {
            let tb = text.as_bytes();
            let glued = m.start() > 0 && matches!(tb[m.start() - 1], b'.' | b'-' | b'_' | b'/') || m.end() < tb.len() && matches!(tb[m.end()], b'.' | b'_' | b'/');
            if !glued && card_ok(m.as_str()) {
                out.push_str(&text[last..m.start()]);
                out.push_str(&mask("card"));
                last = m.end();
                hit("card");
            }
        }
        if last > 0 {
            out.push_str(&text[last..]);
            cur = Some(out);
        }
        for re in &p.phone {
            let text = get(&cur);
            if !text.bytes().any(|c| c.is_ascii_digit()) {
                break;
            }
            let tb = text.as_bytes();
            let mut out = String::new();
            let mut last = 0;
            for m in re.find_iter(&text) {
                let before = if m.start() > 0 { tb[m.start() - 1] } else { b' ' };
                let after = tb.get(m.end()).copied().unwrap_or(b' ');
                if before.is_ascii_alphanumeric() || matches!(before, b'.' | b'-' | b'_' | b'/' | b'+') && !m.as_str().starts_with('+') || after.is_ascii_alphanumeric() || matches!(after, b'.' | b'_' | b'/') && tb.get(m.end() + 1).is_some_and(|c| c.is_ascii_digit()) {
                    continue;
                }
                if phone_ok(m.as_str()) && !is_masked(m.as_str()) {
                    out.push_str(&text[last..m.start()]);
                    out.push_str(&mask("phone"));
                    last = m.end();
                    hit("phone");
                }
            }
            if last > 0 {
                out.push_str(&text[last..]);
                cur = Some(out);
            }
        }
    }
    if settings().ip {
        if ndig >= 4 {
            if let Some(n) = apply(&p.ip4, 0, "ip", Chk::Ip, cur.as_deref().unwrap_or(s)) {
                cur = Some(n);
            }
        }
        if s.matches(':').count() >= 3 {
            if let Some(n) = apply(&p.ip6, 0, "ip", Chk::Ip, cur.as_deref().unwrap_or(s)) {
                cur = Some(n);
            }
        }
    }
    cur
}

/// Layers 1 (before the keyed detectors of `text`): provider + generic typed detectors.
pub(crate) fn pre(s: &str) -> Cow<'_, str> {
    let sql = if s.len() > 20 && s.contains("INSERT") | s.contains("insert") | s.contains("Insert") { sql_insert_pass(s) } else { None };
    let base = sql.as_deref().unwrap_or(s);
    match typed_pass(base) {
        Some(n) => Cow::Owned(n),
        None => match sql {
            Some(n) => Cow::Owned(n),
            None => Cow::Borrowed(s),
        },
    }
}

static INSERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(INSERT[ \t]+(?:OR[ \t]+[A-Za-z]+[ \t]+)?(?:IGNORE[ \t]+)?INTO[ \t]+[\w.`"\[\]]+[ \t]*\()([^)]*)(\)[ \t]*VALUES[ \t]*)(.*)$"#).unwrap()
});

/// `INSERT INTO users (id, name, password_hash) VALUES (1, 'bob', 'x')`: the value in the credential-named column.
fn sql_insert_pass(s: &str) -> Option<String> {
    const CRED: &[&str] = &["password", "passwd", "pwd", "passphrase", "secret", "token", "api_key", "apikey", "api-key", "credential", "private_key", "access_key", "pass"];
    let c = INSERT.captures(s)?;
    let cols: Vec<String> = c[2].split(',').map(|x| x.trim().trim_matches(['`', '"', '\'', '[', ']']).to_ascii_lowercase()).collect();
    let idx: Vec<usize> = cols.iter().enumerate().filter(|(_, n)| CRED.iter().any(|w| n.contains(w))).map(|(i, _)| i).collect();
    if idx.is_empty() {
        return None;
    }
    let rest = c.get(4)?.as_str();
    let b = rest.as_bytes();
    let mut out = String::new();
    let (mut i, mut last) = (0usize, 0usize);
    let mut changed = false;
    while i < b.len() {
        if b[i] != b'(' {
            i += 1;
            continue;
        }
        // one tuple: split on top-level commas, quotes respected
        i += 1;
        let (mut depth, mut k, mut start) = (0i32, 0usize, i);
        let mut q = 0u8;
        let mut spans: Vec<(usize, usize)> = vec![];
        while i < b.len() {
            let ch = b[i];
            if q != 0 {
                if ch == b'\\' {
                    i += 1;
                } else if ch == q {
                    if b.get(i + 1) == Some(&q) {
                        i += 1;
                    } else {
                        q = 0;
                    }
                }
            } else if ch == b'\'' || ch == b'"' {
                q = ch;
            } else if ch == b'(' {
                depth += 1;
            } else if ch == b')' {
                if depth == 0 {
                    spans.push((start, i));
                    break;
                }
                depth -= 1;
            } else if ch == b',' && depth == 0 {
                spans.push((start, i));
                start = i + 1;
                k += 1;
            }
            i += 1;
        }
        let _ = k;
        for &ci in &idx {
            if let Some(&(a, e)) = spans.get(ci) {
                let raw = &rest[a..e];
                let t = raw.trim();
                let l = t.to_ascii_lowercase();
                let inner = t.trim_matches(['\'', '"']);
                if inner.is_empty() || l == "null" || l == "default" || t == "?" || t.starts_with(['$', ':', '%', '@']) || !(t.starts_with(['\'', '"']) || t.bytes().any(|x| x.is_ascii_digit())) || is_masked(t) {
                    continue;
                }
                let lead = raw.len() - raw.trim_start().len();
                out.push_str(&rest[last..a + lead]);
                let qc = if t.starts_with('\'') { "'" } else if t.starts_with('"') { "\"" } else { "" };
                out.push_str(&format!("{qc}{}{qc}", mask("sql-secret")));
                last = a + lead + t.len();
                changed = true;
                hit("sql-secret");
            }
        }
        i += 1;
    }
    if !changed {
        return None;
    }
    out.push_str(&rest[last..]);
    Some(format!("{}{}{}{}{}", &s[..c.get(0)?.start()], &c[1], &c[2], &c[3], out))
}

/// Layers 3-5 (after the keyed detectors): base64-wrapped secrets, entropy, PII.
pub(crate) fn post(s: String) -> String {
    let mut cur = s;
    if let Some(n) = base64_pass(&cur) {
        cur = n;
    }
    if let Some(n) = entropy_pass(&cur) {
        cur = n;
    }
    if let Some(n) = pii_pass(&cur) {
        cur = n;
    }
    // user masks run last and only add masks
    if let Some(n) = crate::masks::apply(&cur) {
        cur = n;
    }
    cur
}

// ---------------------------------------------------------------------------------------------------------
// multi-line constructs: Kubernetes Secret data blocks, Ansible vault payloads

/// Mask what only a neighbouring line reveals; the line count is unchanged. Borrowed when nothing applies.
pub(crate) fn prepass(text: &str) -> Cow<'_, str> {
    let k8s = text.contains("Secret") && (text.contains("data") || text.contains("Data"));
    let vault = text.contains("ANSIBLE_VAULT");
    if !k8s && !vault {
        return Cow::Borrowed(text);
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    let mut changed = false;
    if k8s {
        // documents: split at `---` lines
        let mut start = 0;
        let mut docs = vec![];
        for (i, l) in lines.iter().enumerate() {
            if l.trim_end() == "---" {
                docs.push((start, i));
                start = i + 1;
            }
        }
        docs.push((start, lines.len()));
        for (a, e) in docs {
            let is_secret = lines[a..e].iter().any(|l| {
                let t = l.trim().trim_end_matches(',');
                t.strip_prefix("kind:").is_some_and(|v| v.trim().trim_matches(['"', '\'']) == "Secret") || (t.contains("Secret") && t.replace(' ', "").contains("\"kind\":\"Secret\""))
            });
            if !is_secret {
                continue;
            }
            let mut i = a;
            while i < e {
                let l = lines[i];
                let t = l.trim();
                let ind = l.len() - l.trim_start().len();
                let is_hdr = ["data:", "stringData:", "binaryData:"].contains(&t);
                if is_hdr {
                    let mut j = i + 1;
                    while j < e {
                        let lj = lines[j];
                        if lj.trim().is_empty() {
                            j += 1;
                            continue;
                        }
                        let ij = lj.len() - lj.trim_start().len();
                        if ij <= ind {
                            break;
                        }
                        if let Some((k, _)) = lj.split_once(':') {
                            out[j] = format!("{k}: {}", mask("k8s-secret"));
                        } else {
                            out[j] = format!("{}{}", &lj[..ij], mask("k8s-secret"));
                        }
                        hit("k8s-secret");
                        changed = true;
                        j += 1;
                    }
                    i = j;
                    continue;
                }
                // JSON, everything on one line: ..."data":{"a":"b"}...
                if !t.starts_with("\"data\"") && !t.starts_with("\"stringData\"") && (l.contains("\"data\"") || l.contains("\"stringData\"")) {
                    let mut o = String::new();
                    let mut rest = l;
                    let mut any = false;
                    while let Some(p) = ["\"data\"", "\"stringData\""].iter().filter_map(|k| rest.find(k).map(|x| (x, k.len()))).min() {
                        let after = &rest[p.0 + p.1..];
                        match (after.find('{'), after.find('}')) {
                            (Some(a), Some(c)) if c > a && after[..a].trim() == ":" => {
                                o.push_str(&rest[..p.0 + p.1 + a + 1]);
                                o.push_str(&mask("k8s-secret"));
                                rest = &after[c..];
                                any = true;
                            }
                            _ => {
                                o.push_str(&rest[..p.0 + p.1]);
                                rest = after;
                            }
                        }
                    }
                    if any {
                        o.push_str(rest);
                        out[i] = o;
                        changed = true;
                        hit("k8s-secret");
                    }
                }
                if (t.starts_with("\"data\"") || t.starts_with("\"stringData\"")) && t.contains('{') {
                    if let (Some(o), Some(c)) = (l.find('{'), l.rfind('}')) {
                        if c > o + 1 {
                            out[i] = format!("{}{}{}", &l[..=o], mask("k8s-secret"), &l[c..]);
                            changed = true;
                            hit("k8s-secret");
                        } else if c <= o {
                            // object continues on the following lines until `}`
                            let mut j = i + 1;
                            while j < e && !lines[j].contains('}') {
                                if let Some((k, _)) = lines[j].split_once(':') {
                                    out[j] = format!("{k}: {}", mask("k8s-secret"));
                                    changed = true;
                                    hit("k8s-secret");
                                }
                                j += 1;
                            }
                            i = j;
                        }
                    }
                }
                i += 1;
            }
        }
    }
    if vault {
        let mut i = 0;
        while i < lines.len() {
            if lines[i].contains("$ANSIBLE_VAULT;") {
                let mut j = i + 1;
                while j < lines.len() && {
                    let t = lines[j].trim();
                    t.len() >= 16 && t.bytes().all(|b| b.is_ascii_hexdigit())
                } {
                    let ind = lines[j].len() - lines[j].trim_start().len();
                    out[j] = format!("{}{}", &lines[j][..ind], mask("vault-blob"));
                    changed = true;
                    j += 1;
                }
                hit("vault-blob");
                i = j;
                continue;
            }
            i += 1;
        }
    }
    if changed {
        Cow::Owned(out.join("\n"))
    } else {
        Cow::Borrowed(text)
    }
}

// ---------------------------------------------------------------------------------------------------------
// `aix redact-test`

/// Read stdin, print the redacted text to stdout and the rule hits to stderr. `hash` prints an allow-list hash.
pub fn redact_test(hash: Option<&str>) -> std::io::Result<()> {
    use std::io::{Read, Write};
    if let Some(h) = hash {
        println!("{}", hash_allow(h));
        return Ok(());
    }
    let mut input = String::new();
    std::io::stdin().take(64 << 20).read_to_string(&mut input)?;
    crate::strip_stdin_bom(&mut input);
    let (out, hits) = redact_with_hits(&input);
    let mut so = std::io::stdout().lock();
    so.write_all(out.as_bytes())?;
    if !out.ends_with('\n') && !out.is_empty() {
        so.write_all(b"\n")?;
    }
    let total: usize = hits.iter().map(|h| h.1).sum();
    let list = hits.iter().map(|(n, c)| format!("{n} x{c}")).collect::<Vec<_>>().join(", ");
    let mut err = String::new();
    // every changed line: the rules that fired on it and the allow-list entries that would keep a false positive readable
    let (ol, nl): (Vec<&str>, Vec<&str>) = (input.split('\n').collect(), out.split('\n').collect());
    let mut shown = 0;
    let mut changed = 0;
    for (i, (a, b)) in ol.iter().zip(nl.iter()).enumerate() {
        if a == b {
            continue;
        }
        changed += 1;
        if shown >= 40 {
            continue;
        }
        shown += 1;
        let (_, lh) = redact_with_hits(a);
        let rules = if lh.is_empty() { "multi-line context (the neighbouring lines decide)".to_string() } else { lh.iter().map(|(n, c)| if *c > 1 { format!("{n} x{c}") } else { n.clone() }).collect::<Vec<_>>().join(", ") };
        err.push_str(&format!("  line {}: {rules}\n", i + 1));
        let mut cands: Vec<&str> = vec![];
        for t in a.split(|c: char| c.is_whitespace() || "\"'`,;()<>[]{}".contains(c)) {
            for v in [t, t.split_once(['=', ':']).map_or("", |x| x.1)] {
                if v.len() >= 4 && !cands.contains(&v) && !b.contains(v) {
                    cands.push(v);
                }
            }
        }
        for v in cands.iter().take(3) {
            let head: String = v.chars().take(2).collect();
            err.push_str(&format!("      keep readable: {}   (token of {} chars starting \"{head}\"; add it to [redact] allow in .aix/config.toml)\n", hash_allow(v), v.chars().count()));
        }
    }
    if changed > shown {
        err.push_str(&format!("  ... and {} more changed line(s)\n", changed - shown));
    }
    eprint!("aix redact-test: {total} mask(s){}{list}{}\n{err}", if total > 0 { ": " } else { "" }, if changed > 0 { format!("; {changed} line(s) changed") } else { String::new() });
    Ok(())
}
