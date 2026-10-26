//! User masks: regexes (or exact strings, stored only as slow salted hashes: PBKDF2-HMAC-SHA256) that must never
//! appear in anything aix shows or stores. Global masks live in `~/.config/aix/masks.toml`, repo masks in `<repo>/.aix/masks.toml` (mode 0600, kept
//! out of git). They run AFTER the built-in redactor and only ever add masks.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const MAX_MASKS: usize = 200;
const MAX_PATTERN: usize = 500;
const SIZE_LIMIT: usize = 1 << 18;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaskDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
    /// regex masks
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern: String,
    /// literal masks: PBKDF2-HMAC-SHA256(salt, text) as hex (legacy masks: sha1(salt + text)), plus the length of the text
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
    /// legacy only: a fast fingerprint of the whole text
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fp: String,
    #[serde(default)]
    pub len: usize,
    /// "pbkdf2-sha256" for current literal masks (empty: legacy sha1)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kdf: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub iters: u32,
    /// match case-insensitively (the text is stored and compared lower-cased)
    #[serde(default, skip_serializing_if = "is_false")]
    pub icase: bool,
    /// salted fingerprint of the first characters (pre-filter, `pre_len` characters): the slow hash only runs where it matches
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pre: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pre_len: u32,
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}
fn is_false(b: &bool) -> bool {
    !*b
}
impl MaskDef {
    pub fn is_literal(&self) -> bool {
        self.pattern.is_empty()
    }
    pub fn is_legacy(&self) -> bool {
        self.is_literal() && self.kdf.is_empty()
    }
    pub fn label(&self) -> &str {
        if self.hint.is_empty() { &self.name } else { &self.hint }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct MaskFile {
    #[serde(default)]
    salt: String,
    #[serde(default)]
    mask: Vec<MaskDef>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scope {
    Repo,
    Global,
}

pub fn file_path(scope: Scope, repo: &Path) -> Option<PathBuf> {
    match scope {
        Scope::Repo => Some(repo.join(".aix/masks.toml")),
        Scope::Global => crate::home().map(|h| h.join(".config/aix/masks.toml")),
    }
}

fn read_file(p: &Path) -> MaskFile {
    std::fs::read_to_string(p).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

fn write_file(p: &Path, f: &MaskFile) -> Result<(), String> {
    use std::io::Write;
    let dir = p.parent().ok_or("no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if dir.file_name().is_some_and(|n| n == ".aix") && !dir.join(".gitignore").exists() {
        let _ = std::fs::write(dir.join(".gitignore"), "*\n");
    }
    let text = toml::to_string(f).map_err(|e| e.to_string())?;
    let tmp = p.with_extension("toml.tmp");
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(&tmp).and_then(|mut h| h.write_all(text.as_bytes())).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())
}

pub fn list(repo: &Path) -> Vec<(Scope, MaskDef)> {
    let mut v = vec![];
    for sc in [Scope::Global, Scope::Repo] {
        if let Some(p) = file_path(sc, repo) {
            v.extend(read_file(&p).mask.into_iter().map(|m| (sc, m)));
        }
    }
    v
}

fn fnv(salt: &str, s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in salt.bytes().chain(std::iter::once(0)).chain(s.bytes()) {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    h
}
fn sha(salt: &str, s: &str) -> String {
    sha1_smol::Sha1::from(format!("{salt}\0{s}")).digest().to_string()
}
fn new_salt() -> String {
    use std::io::Read;
    let mut b = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok() {
        return b.iter().map(|x| format!("{x:02x}")).collect();
    }
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let addr = &n as *const _ as usize;
    sha1_smol::Sha1::from(format!("{n}:{}:{addr}", std::process::id())).digest().to_string()[..32].to_string()
}

/// PBKDF2 iterations for new literal masks (OWASP 2023 for HMAC-SHA256). `AIX_MASK_KDF_ITERS` lowers it for tests only
/// (never below 1000); the count used is stored with each mask.
const KDF_ITERS: u32 = 600_000;
fn kdf_iters() -> u32 {
    std::env::var("AIX_MASK_KDF_ITERS").ok().and_then(|v| v.parse::<u32>().ok()).map_or(KDF_ITERS, |n| n.clamp(1000, KDF_ITERS))
}

fn kdf(salt: &str, iters: u32, text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(text.as_bytes(), salt.as_bytes(), iters, &mut out);
    out
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut o = [0u8; 32];
    for (i, c) in o.iter_mut().enumerate() {
        *c = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(o)
}
/// Salted fast fingerprint of the first `k` characters (case-folded when `icase`): the pre-filter key.
fn pre_key(salt: &str, chars: &[char], k: usize, icase: bool) -> u64 {
    let s: String = chars.iter().take(k).map(|c| if icase { fold(*c) } else { *c }).collect();
    fnv(salt, &s)
}
fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}
fn fold_str(s: &str) -> String {
    s.chars().map(fold).collect()
}
fn pre_len_for(n: usize) -> usize {
    (n / 3).clamp(2, 3)
}

fn clean_name(s: &str) -> String {
    s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).take(32).collect()
}

/// Sample lines a mask is timed and sanity-checked against.
fn corpus() -> Vec<String> {
    let base = [
        "fn main() { println!(\"hello {}\", name); }", "const x = await fetch(`/api/users/${id}`);", "SELECT id, name FROM users WHERE id = 42;",
        "2024-05-01T10:15:30.123Z INFO request completed in 31ms status=200", "    at com.example.service.UserService.find(UserService.java:142)",
        "export default function Page() { return <div className=\"a\">Hello</div>; }", "password_hash varchar(255) NOT NULL,", "# Heading",
        "the quick brown fox jumps over the lazy dog", "", "   ", "a", "ab", "{\"a\": 1, \"b\": [1,2,3]}", "https://example.com/a/b?c=d&e=f",
    ];
    let mut v: Vec<String> = base.iter().map(|s| s.to_string()).collect();
    for i in 0..60 {
        v.push(format!("line {i}: value_{i} = compute(x{i}, \"label {i}\") // note about item {i} and more text"));
    }
    v.push("lorem ipsum dolor sit amet ".repeat(400));
    v
}

/// Compile a user regex or say why it is refused.
pub fn validate_regex(pat: &str) -> Result<Regex, String> {
    if pat.trim().is_empty() {
        return Err("empty pattern".into());
    }
    if pat.len() > MAX_PATTERN {
        return Err(format!("pattern longer than {MAX_PATTERN} characters"));
    }
    let re = RegexBuilder::new(pat).size_limit(SIZE_LIMIT).dfa_size_limit(1 << 22).build().map_err(|e| format!("not a valid (linear-time) regex, or too complex: {e}"))?;
    if re.is_match("") {
        return Err("matches the empty string".into());
    }
    let corp = corpus();
    // matches (nearly) every line, or wipes whole lines: refused
    let lines: Vec<&String> = corp.iter().filter(|l| !l.trim().is_empty() && l.len() < 200).collect();
    let hit = lines.iter().filter(|l| re.is_match(l)).count();
    let whole = lines.iter().filter(|l| re.find(l).is_some_and(|m| m.as_str().len() * 10 >= l.len() * 9)).count();
    if hit * 2 > lines.len() || whole * 4 > lines.len() {
        return Err("matches most ordinary text (like `.*` or `\\w+`); make it specific".into());
    }
    let t = std::time::Instant::now();
    for _ in 0..3 {
        for l in &corp {
            std::hint::black_box(re.replace_all(l, "***x***"));
        }
    }
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    if ms > 150.0 {
        return Err(format!("too slow: {ms:.0} ms over the sample corpus (limit 150 ms); simplify it"));
    }
    Ok(re)
}

/// Add a mask. Returns the stored definition (a literal's text is never stored).
pub fn add(scope: Scope, repo: &Path, text: &str, name: Option<&str>, hint: Option<&str>, literal: bool) -> Result<MaskDef, String> {
    add_ex(scope, repo, text, name, hint, literal, false)
}

/// Prefixes of public credential shapes: the built-in detectors already mask these (by type, for every value).
const PUBLIC_PREFIXES: &[&str] = &[
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-", "sk_live_", "sk_test_", "rk_live_", "rk_test_",
    "pk_live_", "pk_test_", "whsec_", "sk-", "AKIA", "ASIA", "AIza", "ya29.", "SG.", "npm_", "pypi-", "hf_", "eyJ", "-----BEGIN", "shpat_", "dapi", "hvs.", "hvb.",
    "AGE-SECRET-KEY", "dckr_pat_", "sq0atp-", "lin_api_", "sbp_", "Bearer ", "Basic ",
];

/// Add a mask (`icase`: a literal also matches in any letter case and percent-encoded). A literal's text is never stored.
pub fn add_ex(scope: Scope, repo: &Path, text: &str, name: Option<&str>, hint: Option<&str>, literal: bool, icase: bool) -> Result<MaskDef, String> {
    if text.is_empty() {
        return Err("empty value".into());
    }
    let path = file_path(scope, repo).ok_or("no HOME for the global masks file")?;
    let mut f = read_file(&path);
    let total = list(repo).len();
    if total >= MAX_MASKS {
        return Err(format!("at most {MAX_MASKS} masks"));
    }
    let raw_hint = hint.unwrap_or("");
    // a hint is shown in every masked answer: it must not hold (or look like) a secret
    if !raw_hint.is_empty() {
        let (red, hits) = crate::redact::redact_with_hits(raw_hint);
        if red != raw_hint || !hits.is_empty() {
            return Err("the hint looks like a secret (the redactor changes it); use a plain label such as 'customer'".into());
        }
        if literal && !text.is_empty() && fold_str(raw_hint).contains(&fold_str(text)) {
            return Err("the hint contains the text being masked".into());
        }
    }
    let hint = clean_name(raw_hint);
    let mut def = MaskDef { hint, ..Default::default() };
    if literal {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() < 6 {
            return Err("a literal mask needs at least 6 characters (a shorter one would mask ordinary words; use a regex with context)".into());
        }
        if let Some(p) = PUBLIC_PREFIXES.iter().find(|p| text.starts_with(**p)) {
            return Err(format!("'{p}...' is a public credential shape: the built-in detectors already mask every value of it by type; a literal would only fingerprint this one"));
        }
        let (mut red, mut hits) = crate::redact::redact_with_hits(text);
        if icase && red != text && !hits.is_empty() {
            // the same text is already a case-sensitive literal mask of yours: upgrade it to case-insensitive
            let old: Vec<String> = list(repo).into_iter().filter(|(_, m)| m.is_literal() && !m.icase && m.len == chars.len() && hits.iter().any(|h| h.0 == m.label())).map(|(_, m)| m.name).collect();
            if !old.is_empty() {
                for n in &old {
                    remove(repo, n)?;
                }
                install(repo);
                f = read_file(&path);
                (red, hits) = crate::redact::redact_with_hits(text);
            }
        }
        if red != text && !hits.is_empty() {
            let user: Vec<String> = list(repo).into_iter().map(|(_, m)| m.label().to_string()).collect();
            let (mine, builtin): (Vec<&str>, Vec<&str>) = hits.iter().map(|h| h.0.as_str()).partition(|n| user.iter().any(|u| u == n));
            return Err(if builtin.is_empty() && !mine.is_empty() {
                format!("already masked by your mask '{}' (aix mask list; remove it first to replace it); no new mask needed", mine.join("', '"))
            } else {
                format!("already masked by the built-in redactor ({}); no mask needed", builtin.join(", "))
            });
        }
        if f.salt.is_empty() {
            f.salt = new_salt();
        }
        let stored = if icase { fold_str(text) } else { text.to_string() };
        let iters = kdf_iters();
        def.kdf = "pbkdf2-sha256".into();
        def.iters = iters;
        def.icase = icase;
        def.hash = hex(&kdf(&f.salt, iters, &stored));
        def.len = chars.len();
        def.pre_len = pre_len_for(chars.len()) as u32;
        def.pre = format!("{:016x}", pre_key(&f.salt, &chars, def.pre_len as usize, icase));
        def.name = clean_name(name.unwrap_or(&format!("literal-{}", &def.hash[..6])));
        if fold_str(&def.name).contains(&fold_str(&clean_name(text))) {
            return Err("the name or hint contains the text being masked".into());
        }
    } else {
        validate_regex(text)?;
        def.pattern = text.to_string();
        def.name = clean_name(name.unwrap_or(&format!("mask-{}", &sha("n", text)[..6])));
    }
    if def.name.is_empty() {
        return Err("empty name".into());
    }
    let shown = if def.hint.is_empty() { def.name.clone() } else { def.hint.clone() };
    if crate::redact::builtin_names().iter().any(|b| *b == def.name || *b == shown) {
        return Err(format!("'{shown}' is the name of a built-in redaction rule (a mask labelled that way would be mistaken for it); pick another --name/--hint"));
    }
    if list(repo).iter().any(|(_, m)| m.name == def.name) {
        return Err(format!("a mask named '{}' exists (aix mask rm {} first)", def.name, def.name));
    }
    f.mask.push(def.clone());
    write_file(&path, &f)?;
    Ok(def)
}

/// Remove by name from either scope. True when one was removed.
pub fn remove(repo: &Path, name: &str) -> Result<bool, String> {
    let mut any = false;
    for sc in [Scope::Repo, Scope::Global] {
        if let Some(p) = file_path(sc, repo) {
            let mut f = read_file(&p);
            let n = f.mask.len();
            f.mask.retain(|m| m.name != name);
            if f.mask.len() != n {
                write_file(&p, &f)?;
                any = true;
            }
        }
    }
    Ok(any)
}

// ---------------------------------------------------------------------------------------------------------
// the installed set

/// A current (PBKDF2) literal mask, ready to match.
struct KLit {
    label: String,
    len: usize,
    iters: u32,
    icase: bool,
    hash: [u8; 32],
}
/// Literals of one masks file (one salt): found by the salted fingerprint of their first characters, then verified
/// with the slow hash on the window of their exact length.
struct KGroup {
    salt: String,
    /// pre-filter lengths in use (2 or 3)
    pre_lens: BTreeSet<usize>,
    by_pre: HashMap<(usize, bool, u64), Vec<KLit>>,
}
/// Legacy (sha1) literals: fixed lengths, whole-window fingerprint.
struct Lit {
    label: String,
    hash: String,
}
struct LitGroup {
    salt: String,
    lens: BTreeSet<usize>,
    by_fp: HashMap<u64, Vec<Lit>>,
}
#[derive(Default)]
struct Installed {
    res: Vec<(String, Regex)>,
    set: Option<regex::bytes::RegexSet>,
    lits: Vec<LitGroup>,
    klits: Vec<KGroup>,
}
static INSTALLED: LazyLock<RwLock<Arc<Installed>>> = LazyLock::new(|| RwLock::new(Arc::new(Installed::default())));

/// Load the global and repo mask files and make them active for this process.
pub fn install(repo: &Path) {
    let mut inst = Installed::default();
    let mut pats = vec![];
    for sc in [Scope::Global, Scope::Repo] {
        let Some(p) = file_path(sc, repo) else { continue };
        let f = read_file(&p);
        let mut group = LitGroup { salt: f.salt.clone(), lens: BTreeSet::new(), by_fp: HashMap::new() };
        let mut kg = KGroup { salt: f.salt.clone(), pre_lens: BTreeSet::new(), by_pre: HashMap::new() };
        for m in f.mask.into_iter().take(MAX_MASKS) {
            if m.is_literal() && !m.is_legacy() {
                if let (Ok(pre), Some(hash), true) = (u64::from_str_radix(&m.pre, 16), unhex(&m.hash), m.len > 0 && m.pre_len > 0) {
                    kg.pre_lens.insert(m.pre_len as usize);
                    kg.by_pre.entry((m.pre_len as usize, m.icase, pre)).or_default().push(KLit { label: m.label().to_string(), len: m.len, iters: m.iters.max(1), icase: m.icase, hash });
                }
            } else if m.is_literal() {
                if let (Ok(fp), true) = (u64::from_str_radix(&m.fp, 16), m.len > 0) {
                    group.lens.insert(m.len);
                    group.by_fp.entry(fp).or_default().push(Lit { label: m.label().to_string(), hash: m.hash.clone() });
                }
            } else if let Ok(re) = RegexBuilder::new(&m.pattern).size_limit(SIZE_LIMIT).build() {
                pats.push(m.pattern.clone());
                inst.res.push((m.label().to_string(), re));
            }
        }
        if !group.by_fp.is_empty() {
            inst.lits.push(group);
        }
        if !kg.by_pre.is_empty() {
            inst.klits.push(kg);
        }
    }
    // byte-mode ASCII prefilter; patterns with non-ASCII literals fall back to running every regex
    inst.set = regex::bytes::RegexSetBuilder::new(&pats).unicode(false).size_limit(1 << 26).build().ok();
    if let Ok(mut g) = INSTALLED.write() {
        *g = Arc::new(inst);
    }
}

pub fn count() -> usize {
    INSTALLED.read().map(|g| g.res.len() + g.lits.iter().map(|l| l.by_fp.values().map(Vec::len).sum::<usize>()).sum::<usize>() + g.klits.iter().map(|l| l.by_pre.values().map(Vec::len).sum::<usize>()).sum::<usize>()).unwrap_or(0)
}

fn star(label: &str) -> String {
    format!("***{label}***")
}

/// Mask what the installed user masks match. None when nothing did (or none are installed).
pub fn apply(s: &str) -> Option<String> {
    let inst = INSTALLED.read().ok()?.clone();
    if inst.res.is_empty() && inst.lits.is_empty() && inst.klits.is_empty() {
        return None;
    }
    let mut cur: Option<String> = None;
    let idx: Vec<usize> = match &inst.set {
        Some(set) => set.matches(s.as_bytes()).into_iter().collect(),
        None => (0..inst.res.len()).collect(),
    };
    for i in idx {
        let (label, re) = &inst.res[i];
        let text = cur.as_deref().unwrap_or(s);
        if re.is_match(text) {
            let m = star(label);
            let n = re.replace_all(text, |_: &regex::Captures| m.clone()).into_owned();
            crate::redact::note_hit(label);
            cur = Some(n);
        }
    }
    for g in &inst.lits {
        let text = cur.as_deref().unwrap_or(s);
        if let Some(n) = apply_literals(g, text) {
            cur = Some(n);
        }
    }
    for g in &inst.klits {
        let text = cur.as_deref().unwrap_or(s);
        if let Some(n) = apply_kliterals(g, text) {
            cur = Some(n);
        }
    }
    cur
}

/// Results of the slow hash for windows seen before: (salt, iterations, window) -> hash.
static KDF_CACHE: LazyLock<std::sync::Mutex<HashMap<String, [u8; 32]>>> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
fn kdf_cached(salt: &str, iters: u32, window: &str) -> [u8; 32] {
    let key = format!("{salt}\0{iters}\0{window}");
    if let Ok(c) = KDF_CACHE.lock() {
        if let Some(h) = c.get(&key) {
            return *h;
        }
    }
    let h = kdf(salt, iters, window);
    if let Ok(mut c) = KDF_CACHE.lock() {
        if c.len() >= 8192 {
            c.clear();
        }
        c.insert(key, h);
    }
    h
}

/// The characters of `s` with the byte span each stands for in `s`; a `%XX` escape of a printable ASCII character is one
/// character (spanning its three bytes), so a literal is found inside a percent-encoded value too.
fn view(s: &str) -> Vec<(char, usize, usize)> {
    let b = s.as_bytes();
    let mut v = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(x) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()).filter(|x| (0x20..0x7f).contains(x)) {
                v.push((x as char, i, i + 3));
                i += 3;
                continue;
            }
        }
        let c = s[i..].chars().next().unwrap_or('\0');
        v.push((c, i, i + c.len_utf8().max(1)));
        i += c.len_utf8().max(1);
    }
    v
}

/// Every occurrence at any offset (inside words, adjacent repeats, overlapping), case-insensitive masks in any case.
fn apply_kliterals(g: &KGroup, s: &str) -> Option<String> {
    let v = view(s);
    if v.len() < 6 {
        return None;
    }
    let chars: Vec<char> = v.iter().map(|x| x.0).collect();
    let mut spans: Vec<(usize, usize, String)> = vec![];
    for i in 0..chars.len() {
        for &k in &g.pre_lens {
            if i + k > chars.len() {
                continue;
            }
            for icase in [false, true] {
                let key = (k, icase, pre_key(&g.salt, &chars[i..], k, icase));
                let Some(cands) = g.by_pre.get(&key) else { continue };
                for l in cands {
                    if i + l.len > chars.len() {
                        continue;
                    }
                    let w: String = chars[i..i + l.len].iter().map(|c| if l.icase { fold(*c) } else { *c }).collect();
                    if kdf_cached(&g.salt, l.iters, &w) == l.hash {
                        spans.push((v[i].1, v[i + l.len - 1].2, l.label.clone()));
                    }
                }
            }
        }
    }
    if spans.is_empty() {
        return None;
    }
    spans.sort_by_key(|f| (f.0, std::cmp::Reverse(f.1)));
    let mut out = String::new();
    let mut last = 0;
    let mut merged: Vec<(usize, usize, String)> = vec![];
    for (a, e, label) in spans {
        match merged.last_mut() {
            Some(m) if a < m.1 => m.1 = m.1.max(e),
            _ => merged.push((a, e, label)),
        }
    }
    for (a, e, label) in merged {
        out.push_str(&s[last..a]);
        out.push_str(&star(&label));
        crate::redact::note_hit(&label);
        last = e;
    }
    out.push_str(&s[last..]);
    Some(out)
}

fn apply_literals(g: &LitGroup, s: &str) -> Option<String> {
    // window starts: the beginning, and after any non-alphanumeric character
    let starts: Vec<usize> = std::iter::once(0)
        .chain(s.char_indices().filter(|(_, c)| !c.is_alphanumeric()).map(|(i, c)| i + c.len_utf8()))
        .filter(|i| *i < s.len())
        .take(4096)
        .collect();
    let mut found: Vec<(usize, usize, String)> = vec![];
    for &st in &starts {
        let mut ends = s[st..].char_indices().map(|(i, c)| st + i + c.len_utf8());
        let mut n = 0usize;
        let maxlen = *g.lens.iter().next_back()?;
        let mut e_at: Vec<(usize, usize)> = vec![]; // (char count, end byte)
        while n < maxlen {
            match ends.next() {
                Some(e) => {
                    n += 1;
                    if g.lens.contains(&n) {
                        e_at.push((n, e));
                    }
                }
                None => break,
            }
        }
        for (_, e) in e_at {
            let w = &s[st..e];
            if let Some(c) = g.by_fp.get(&fnv(&g.salt, w)) {
                let h = sha(&g.salt, w);
                if let Some(l) = c.iter().find(|l| l.hash == h) {
                    found.push((st, e, l.label.clone()));
                }
            }
        }
    }
    if found.is_empty() {
        return None;
    }
    found.sort_by_key(|f| (f.0, std::cmp::Reverse(f.1)));
    let mut out = String::new();
    let mut last = 0;
    for (a, e, label) in found {
        if a < last {
            continue;
        }
        out.push_str(&s[last..a]);
        out.push_str(&star(&label));
        crate::redact::note_hit(&label);
        last = e;
    }
    out.push_str(&s[last..]);
    Some(out)
}
