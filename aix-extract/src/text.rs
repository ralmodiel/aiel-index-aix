//! Text helpers: redaction of secrets, clipping, severity/status parsing.

use std::sync::LazyLock;

use regex::Regex;

static JWT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*").unwrap());
static OPAQUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{40,}={0,2}").unwrap());
static SECRETY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)passw|(?-u:\b)pw(?-u:\b)|secret|token|credential|api[_-]?key").unwrap());
static PATH_SEG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:/[A-Za-z0-9_.-]+)+").unwrap());
static MASK_SPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*\*\*[a-z0-9-]{1,32}\*\*\*").unwrap());
static BACKTICK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`[^`\n]{1,80}`").unwrap());
static KV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)((?:password|passwd|pw|secret|token|api[_-]?key)[ \t]*[:=][ \t]*)(\S+)").unwrap());
static MIXED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:\b)[A-Za-z0-9_]{5,}\d{2,}(?-u:\b)").unwrap());
/// Well-known credential shapes, redacted wherever they appear (cloud keys, provider tokens, private keys).
static KNOWN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)",                 // AWS access key id
        r"|(?-u:\b)sk-(?:live-|test-|proj-|ant-)?[A-Za-z0-9_-]{16,}", // OpenAI/Stripe/Anthropic-style secret keys
        r"|(?-u:\b)(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}", // GitHub tokens
        r"|(?-u:\b)xox[abprs]-[A-Za-z0-9-]{10,}",                // Slack tokens
        r"|(?-u:\b)AIza[0-9A-Za-z_-]{35}",                       // Google API keys
        r"|(?i:(?-u:\b)bearer\s+)[A-Za-z0-9._~+/-]{16,}=*",      // bearer tokens
        r"|(?-u:\b)[sprk]k_(?:live|test)_[A-Za-z0-9]{8,}",       // Stripe secret/publishable/restricted keys
        r"|(?-u:\b)glpat-[A-Za-z0-9_-]{16,}",                    // GitLab personal access tokens
        r"|(?-u:\b)SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",  // SendGrid API keys
        r"|(?-u:\b)(?:AC|SK)[0-9a-fA-F]{32}(?-u:\b)",                  // Twilio account / API key SIDs
        r"|(?-u:\b)npm_[A-Za-z0-9]{30,}|(?-u:\b)hf_[A-Za-z0-9]{30,}|(?-u:\b)dop_v1_[a-f0-9]{40,}", // npm, Hugging Face, DigitalOcean
    ))
    .unwrap()
});
/// `"password": "x"`, `smtp.pass=x`, `db_password: x`, `apiKey = 'x'`, `private_key: x`, `access_key=x`, quoted or not;
/// also keys that continue after the word (`client_secret_value`, `token_a`, `secretKey`, `passwordHash`).
static KV2: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)((?:(?-u:\b)[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|psk|preshared[_-]?key|credentials?|signing[_-]?key|encryption[_-]?key|master[_-]?key|hmac[_-]?key)(?P<suf>(?:[._-]|(?-i:[A-Z]))[A-Za-z0-9_.-]*)?|"#,
        r#"(?-u:\b)(?:[A-Za-z0-9_.-]*[._-])?(?:pass|pwd|pw|psk|key[._-]value))["']?[ \t]*[:=][ \t]*)"#,
        r#"(?P<val>"[^"\n]*"|'[^'\n]*'|[^\s"',;&)}\]]+|["'][^\n]*)"#,
    ))
    .unwrap()
});
/// Upper-case env style names that are credentials by their last word: `API="x"`, `KEY=x`, `MY_AUTH=x`.
static ENV_KV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"((?-u:\b)(?:[A-Z0-9]+_)*(?:API|KEY|AUTH|PSK|DSN|CREDS?)["']?[ \t]*=[ \t]*["']?)("[^"\n]*"|'[^'\n]*'|[^\s"',;&)}\]]+)"#,
    )
    .unwrap()
});
/// URL-encoded `password%3Dhunter2%26user%3Dx` (the value runs to the next `&` / `%26`).
static ENC_KV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)((?-u:\b)[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|pass|pwd)[A-Za-z0-9_.-]*%3[da])(\S*)").unwrap()
});
/// True when the text after a credential-ish key is code, not a value: an identifier or member chain (`token`,
/// `this.token`, `request.getHeader(`) that is called, compared, combined with `&&`/`||`/`?`, or simply the
/// same word passed through (`this.password = password;`), or a keyword (`null`, `true`). `val` is the value
/// text as matched, `rest` what follows it on the line. Literals (quoted, numbers, anything with a digit, opaque
/// words) are never "code", so `password: s3cretVal` and `token = "abc"` are still masked.
fn is_expression(key: &str, val: &str, rest: &str) -> bool {
    let v = val.trim();
    let end = v.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))).unwrap_or(v.len());
    let ident = &v[..end];
    if ident.is_empty() || !ident.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$') || ident.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut cut = rest.len().min(200);
    while !rest.is_char_boundary(cut) {
        cut -= 1;
    }
    let tail = format!("{}{}", &v[end..], &rest[..cut]); // bounded: a 1 MB line must not cost O(n) per match
    let t = tail.trim_start();
    // arithmetic / boolean combination with spaces around the operator (`now + timedelta(...)`, `a or b`): code
    if tail.starts_with(char::is_whitespace)
        && ["+ ", "- ", "* ", "/ ", "% ", "< ", "> ", "<= ", ">= ", "| ", "& ", "and ", "or ", "not ", "if ", "else ", "in ", "is "].iter().any(|op| t.starts_with(op))
    {
        return true;
    }
    // `token = settings.TOKEN_FIELD`: a dotted member chain assigned with `=` is a reference, not a value
    if key.trim_end().ends_with('=') && !key.trim_end().ends_with("==") && ident.contains('.') && !ident.ends_with('.') && !ident.contains("..") {
        return true;
    }
    let lower = ident.to_ascii_lowercase();
    if matches!(lower.as_str(), "null" | "true" | "false" | "this" | "self" | "undefined" | "none" | "nil") {
        return true;
    }
    if ["(", "[", "!=", "==", "&&", "||", "?", "->", "=>", ")"].iter().any(|op| t.starts_with(op)) || t.starts_with('.') && !t.starts_with("..") {
        return true;
    }
    // `this.token = token;`, `password = password,`: the value is the same word as the key (or ends the key)
    let base = ident.rsplit('.').next().unwrap_or(ident).to_ascii_lowercase();
    let k = key.to_ascii_lowercase();
    base.len() >= 3 && k.contains(&base) && (t.is_empty() || t.starts_with([';', ',', ')', '}']))
}
/// `${DB_PASSWORD}`, `$DB_PASSWORD`, `{{ .Values.x }}`, `<your-password>`, `%PASSWORD%`, `$(cmd)`: a reference, not a value.
fn is_placeholder(v: &str) -> bool {
    let b = v.as_bytes();
    v.starts_with("${") || v.starts_with("{{") || v.starts_with("$(") || v.starts_with("<%") || (v.starts_with('<') && v.ends_with('>'))
        || (v.starts_with('%') && v.ends_with('%') && v.len() > 2)
        || (b.len() > 1 && b[0] == b'$' && (b[1].is_ascii_uppercase() || b[1] == b'_') && b[1..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_'))
}
/// A key continuing with a word that says "this names something" (`TOKEN_HEADER`, `passwordField`, `secretName`).
fn name_like_suffix(suf: &str) -> bool {
    const NAMES: &[&str] = &[
        "header", "field", "name", "label", "type", "param", "params", "attribute", "attr", "claim", "cookie", "column", "prefix", "path", "url", "uri",
        "endpoint", "regex", "pattern", "format", "policy", "message", "msg", "error", "hint", "text", "title", "placeholder", "description", "desc",
        "expired", "invalid", "required", "missing", "mismatch", "label", "scheme", "kind", "class", "id", "ref", "var", "env", "config", "setting",
    ];
    let mut word = String::new();
    let mut words: Vec<String> = vec![];
    let mut prev_lower = false;
    for ch in suf.chars() {
        if matches!(ch, '.' | '_' | '-') || (ch.is_ascii_uppercase() && prev_lower) {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        }
        if ch.is_alphanumeric() {
            word.push(ch.to_ascii_lowercase());
        }
        prev_lower = ch.is_ascii_lowercase();
    }
    if !word.is_empty() {
        words.push(word);
    }
    words.iter().any(|w| NAMES.contains(&w.as_str()))
}
/// Letters, spaces and `._-:` only, no digits: a name or a sentence, not a credential.
fn wordish(v: &str) -> bool {
    !v.is_empty() && v.len() <= 60 && v.chars().all(|c| c.is_alphabetic() || matches!(c, '.' | '_' | '-' | ':' | ' '))
}
const SOFT_VALUES: &[&str] = &["true", "false", "null", "none", "nil", "yes", "no", "on", "off", "required", "optional"];
/// SQL column definitions: `api_token text DEFAULT 'x'`, `ALTER COLUMN pass SET DEFAULT 'x'` (the literal is the credential).
static SQL_DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)((?-u:\b)[A-Za-z0-9_"`.]*(?:password|passwd|passphrase|secret|token|api_?key|access_?key|private_?key|pwd|pass|credential)[A-Za-z0-9_"`]*\s+[^,;]*?(?-u:\b)DEFAULT\s+)('(?:[^']|'')*'|"[^"]*")"#).unwrap()
});
/// `--password hunter2`, `--token abc`
static LONGFLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(--(?:password|passwd|pass|passphrase|token|secret|api-?key|auth-?token)\s+)(?:'[^']*'|"[^"]*"|\S+)"#).unwrap()
});
/// Prose: `the password is hunter2`, `password was: x`
static PROSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)((?:password|passwd|passphrase|passcode|pin|secret|token|api[ _-]?key)\s+(?:is|was|are|=|:)\s*:?\s*)(\S+)").unwrap()
});
/// Commit-subject prose without is/was: `change password to hunter2`, `set token as abc`.
static PROSE_TO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)((?:password|passwd|passphrase|passcode|secret|token|api[ _-]?key)\s+(?:to|as)\s+)(\S+)").unwrap()
});
const NOT_A_SECRET: &[&str] = &[
    "required", "invalid", "incorrect", "wrong", "too", "not", "empty", "valid", "expired", "set", "missing", "changed", "hashed",
    "stored", "reset", "optional", "correct", "weak", "strong", "mandatory", "case-sensitive", "sent", "used", "now", "never", "a",
    "an", "the", "at", "in", "of", "to", "and", "or", "verified", "rejected", "accepted", "updated", "unchanged", "disabled", "be", "default", "reset", "access", "authenticate", "log", "login", "verify", "all", "each", "every",
    "this", "that", "it", "your", "our", "their", "its", "see", "send", "match", "expire", "expires", "refresh", "rotate",
    "stale", "revoked", "leaked", "compromised", "fresh", "long", "short", "random", "private", "public", "opaque", "generated", "unused", "unique", "keep", "fix", "prevent", "avoid", "ensure", "make", "use", "get", "check", "allow", "do", "handle", "protect", "hide", "show", "body", "query", "header", "headers", "param", "parameter", "argument", "input", "output", "string", "text", "json", "field", "form", "cookie",
    // function words of a sentence that continues ("each token is one command", "the secret is only read once")
    "one", "two", "three", "first", "second", "last", "same", "only", "just", "also", "still", "per", "no", "any", "some",
    "many", "more", "less", "being", "been", "then", "always", "usually", "already", "where", "when", "what", "which", "how",
    "why", "for", "from", "with", "without", "by", "on", "as", "so", "if", "unless", "here", "there",
];

/// The leading alphabetic word of a value, lower-cased (`required")).toBeVisible()` -> `required`).
fn first_word(v: &str) -> String {
    v.trim_start_matches(|ch: char| !ch.is_alphanumeric()).chars().take_while(|ch| ch.is_alphabetic()).collect::<String>().to_ascii_lowercase()
}

const TYPE_WORDS: &[&str] = &[
    "str", "int", "float", "bool", "bytes", "string", "number", "boolean", "any", "unknown", "void", "object", "typeof", "undefined", "datetime", "date",
    "uuid", "decimal", "list", "dict", "optional", "secretstr", "emailstr", "never", "bigint", "symbol", "await", "async", "new", "function", "lambda",
    "def", "return", "import", "from", "class", "const", "let", "var", "self", "cls",
];
const CRED_WORDS: &[&str] = &["password", "passwd", "passphrase", "secret", "token", "api_key", "apikey", "pwd", "hash", "key", "pass"];

/// A value that is code or a type, not a credential: types and keywords (`str`, `int`, `typeof`, `await`), a lone letter,
/// an object/call/array start, a reference (`${X}`, `{{ x }}`, `$(cmd)`), an empty string, a closing quote, a snake_case or
/// dotted name that is itself credential-named (`password_reset_token`, `settings.FIRST_SUPERUSER_PASSWORD`), or GitHub's
/// `id-token: write`. `raw` is the value as matched, `inner` without its quotes.
fn benign_value(key: &str, raw: &str, inner: &str) -> bool {
    let raw = raw.trim();
    let quoted = raw.starts_with(['"', '\'']);
    if raw.len() == 1 && quoted || inner.trim().is_empty() {
        return true; // `?token=` closing the string, `password: ""`
    }
    let kl = key.to_ascii_lowercase();
    if kl.contains("id-token") {
        return true;
    }
    if crate::redact::is_ref(inner) || inner.starts_with('%') && inner.ends_with('%') && inner.len() > 2 {
        return true;
    }
    if inner.starts_with("`${") {
        return true; // a template literal built around a variable: `${base}/oauth/token`
    }
    static GENERIC_TYPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:&'?[a-z]* ?)?[A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*<[A-Za-z0-9_<>, :&'\[\]]*>;?$").unwrap());
    if GENERIC_TYPE.is_match(raw) {
        return true; // a declared type: `static TOKEN_RE: LazyLock<Regex> = ...`, `secrets: HashMap<String, Key>`
    }
    if quoted {
        return false;
    }
    let lower = inner.to_ascii_lowercase();
    if inner.starts_with(['(', '[', '{', '?', '+']) || is_tag_start(inner) || TYPE_WORDS.contains(&lower.as_str()) {
        return true;
    }
    let ident = inner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.') && inner.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
    if ident {
        if inner.len() == 1 || (inner.starts_with('_') && inner.len() <= 40) {
            return true;
        }
        if (inner.contains('_') || inner.contains('.')) && !inner.ends_with('.') && !inner.bytes().any(|b| b.is_ascii_digit()) && CRED_WORDS.iter().any(|w| lower.contains(w)) {
            return true; // a reference to another credential variable, not a value
        }
    }
    false
}

/// `<input`, `</label>`: markup after a label such as `Password:`, not a value.
fn is_tag_start(v: &str) -> bool {
    let mut c = v.chars();
    c.next() == Some('<') && matches!(c.next(), Some(x) if x.is_ascii_alphabetic() || x == '/')
}

/// A backtick span that names something (an env var, a file, an identifier) rather than holding a password.
fn benign_span(s: &str) -> bool {
    static SPAN_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|\.[A-Za-z0-9_-]+|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9]{1,5})+|[A-Za-z0-9_./-]*/[A-Za-z0-9_./-]*)$").unwrap());
    // a flag (`--fix`, `-x`), a path (`~/dir`, `./a`, `/etc/x`) or a lowercase command phrase (`aix update`) names something
    static SPAN_FLAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:--?[A-Za-z][A-Za-z0-9-]*(?:=[A-Za-z0-9_./-]*)?|(?:~|\.{1,2})?/[A-Za-z0-9_.~/@+-]*|[a-z][a-z-]*(?: (?:--?[a-z][a-z0-9-]*|[a-z][a-z./_-]*)){1,5})$").unwrap());
    // letters and path/name punctuation, no digit and nothing mixed-case inside a word run: prose naming a thing, not a value
    static SPAN_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^0-9`!#$%^&]{1,80}$").unwrap());
    // an aix command line (a continuation footer, a suggestion): subcommand, flags, names, numbers, quoted patterns
    static SPAN_AIX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"^aix(?: --?[a-z][a-z0-9-]*(?:=[A-Za-z0-9_./:,-]*)?)* [a-z][a-z-]*(?: (?:--?[a-z][a-z0-9-]*(?:=[A-Za-z0-9_./:,-]*)?|[A-Za-z0-9_.:/@#*,~<>|-]+|'[^'`]*'|"[^"`]*"))*$"#).unwrap()
    });
    if s == "~" || s.contains("***") {
        return true;
    }
    if SPAN_AIX.is_match(s) && !s.split([' ', '\'', '"']).any(|w| w.len() > 48) {
        return true;
    }
    (SPAN_ID.is_match(s) || SPAN_FLAG.is_match(s) || (SPAN_NAME.is_match(s) && s.bytes().any(|b| b.is_ascii_alphabetic()))) && !s.bytes().all(|b| b.is_ascii_digit())
}

/// Used by the typed rules: `tokenUrl = f"{base}/login/access-token"` names an endpoint.
pub(crate) fn name_key_value(key: &str, v: &str) -> bool {
    let sfx = key_suffix(key.trim_end_matches(|c: char| !c.is_alphanumeric()));
    !sfx.is_empty() && name_like_suffix(sfx) && (wordish(v.trim_matches(['"', '\''])) || v.contains('/') || v.starts_with(['f', 'F']))
}
/// `curl -u user:pass`, `--user user:pass`
static CURL_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)((?:\s-u|--user)[\s=]\s*['"]?[^\s:'"]+:)(?:[^\s'"]+)"#).unwrap()
});
/// Tools whose `-p` flag takes a password (not a port or a mkdir flag).
static PW_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(?:mysql|mysqldump|mysqladmin|mariadb|sshpass|mongo|mongosh|mongodump|mongorestore|rar|7z|7za|zip|unzip|smbclient|lftp|ftp|openssl)(?-u:\b)").unwrap()
});
static PW_FLAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(\s-p\s*)(?:'[^']*'|"[^"]*"|[^\s-]\S*)"#).unwrap());
/// `Authorization: Basic abc==`, `"Authorization": "Bearer x"`
static AUTHZ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(authorization["']?\s*[:=]\s*["'`]?(?:basic|bearer|digest|token|negotiate)?\s*)[^\s"'`]+"#).unwrap()
});
static TWILIO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)twilio").unwrap());
static HEX32: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u:\b)[0-9a-fA-F]{32}(?-u:\b)").unwrap());
static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

static KEY_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*(?:-\s+)?["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credentials?|signing[_-]?key|encryption[_-]?key|master[_-]?key|(?:^|[._-])(?:pass|pwd|pw))[A-Za-z0-9_.-]*["']?[ \t]*(?P<op>:)[ \t]*(?P<blk>[|>][+-]?)?[ \t]*$"#).unwrap()
});
/// `- name: DB_PASSWORD` / `name: "X-Api-Key"`: the next lines may hold its `value:`.
static NAME_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*(?:-\s+)?["']?name["']?\s*:\s*["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|pwd|psk|session|sid|csrf|xsrf|jwt|bearer|cookie)[A-Za-z0-9_.-]*["']?\s*,?\s*$"#).unwrap()
});
static VALUE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s*(?:-\s+)?["']?value["']?\s*:[ \t]*(?P<v>\S.*?)\s*,?\s*$"#).unwrap());
fn is_masked_value(v: &str) -> bool {
    v.contains("***") || v.contains("[redacted]")
}
static MAPPING_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s*(?:-\s+)?["']?[A-Za-z0-9_.-]+["']?\s*:(\s|$)"#).unwrap());

/// The file text for line selection and the text to print: (original lines, redacted lines), one per line. A
/// search selects on the original (a token the redactor masks is still found, a mask label never matches) and prints
/// the redacted line. A leading UTF-8 BOM is dropped (as rg does: `^` matches line 1).
pub fn select_and_show(text: &str) -> (Vec<&str>, Vec<String>) {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let red = redact_lines(text);
    let raw: Vec<&str> = text.lines().collect();
    if raw.len() != red.len() {
        // never select on text that cannot be paired with what is printed
        return (vec![], red);
    }
    (raw, red)
}

/// Does `re` match `raw` outside its redacted spans? A line whose every match lies inside text the redactor masks
/// (a secret value, a masked token) is not a hit: a guessed secret cannot be confirmed (no oracle), and a mask label
/// never matches either (selection is on `raw`). A match counts when its text is still visible in `red`.
pub fn visible_match(re: &regex::Regex, raw: &str, red: &str) -> bool {
    if raw == red {
        return re.is_match(raw);
    }
    re.find_iter(raw).any(|m| visible_text(m.as_str(), red))
}

/// Is (part of) this matched text visible in the printed line? Its text as a whole, or one of its words (2+ word
/// characters) as a word of the printed line: a match that also covers visible text (`@Path("/api/keys/<masked>")`)
/// is a hit, one that lies wholly inside a mask (`hStub15` masked as a token, a secret value) is not.
pub fn visible_text(m: &str, red: &str) -> bool {
    if m.is_empty() || red.contains(m) {
        return true;
    }
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let printed: std::collections::HashSet<&str> = red.split(|c: char| !word(c)).filter(|w| w.len() >= 2).collect();
    m.split(|c: char| !word(c)).any(|w| w.len() >= 2 && printed.contains(w))
}

/// A matched fragment (`grep -o`, a capture) as it may be printed: itself when its line is printed unredacted or the
/// redacted line still holds it, else a mask (the fragment touches a redacted span).
pub fn shown_fragment(raw_line: &str, red_line: &str, frag: &str) -> String {
    if raw_line == red_line || red_line.contains(frag) {
        frag.to_string()
    } else {
        "***masked***".to_string()
    }
}

/// Redact text line by line, keeping the line count (so line numbers stay true), with the constructs that
/// span lines: a PEM private key body (everything between BEGIN and END), a YAML key whose value is on the
/// next line (or a `|` / `>` block), after which the value line(s) are replaced.
pub fn redact_lines(text: &str) -> Vec<String> {
    let text = &*crate::redact::prepass(text); // k8s Secret data, Ansible vault payloads
    let mut out = Vec::new();
    let mut in_pem = false;
    let mut in_cert = false; // certificates / public keys / CSRs are public: their base64 body is not a secret
    let mut name_pending: Option<(usize, u8)> = None; // `- name: DB_PASSWORD` seen: (indent, lines left to look at `value:`)
    let mut pending: Option<(usize, bool)> = None; // (key indent, block scalar)
    for l in text.lines() {
        let indent = l.len() - l.trim_start().len();
        if in_cert {
            if l.contains("-----END") {
                in_cert = false;
            }
            out.push(l.to_string());
            continue;
        }
        if l.contains("-----BEGIN") && !l.contains("PRIVATE KEY") && (l.contains("CERTIFICATE") || l.contains("PUBLIC KEY")) {
            in_cert = !l.contains("-----END");
            out.push(l.to_string());
            continue;
        }
        if in_pem {
            if l.contains("-----END") {
                in_pem = false;
            }
            out.push("***private-key***".to_string());
            continue;
        }
        if l.contains("-----BEGIN") && l.contains("PRIVATE KEY") && !l.contains("-----END") {
            in_pem = true;
            crate::redact::note_hit("private-key");
            out.push("***private-key***".to_string());
            continue;
        }
        if let Some((kind, block)) = pending {
            if block {
                if l.trim().is_empty() {
                    out.push(String::new());
                    continue;
                }
                if indent > kind {
                    crate::redact::note_hit("yaml-block-value");
                    out.push("***".to_string());
                    continue;
                }
                pending = None;
            } else if !l.trim().is_empty() {
                pending = None;
                if !MAPPING_LINE.is_match(l) {
                    crate::redact::note_hit("yaml-next-line");
                    out.push(format!("{}***", &l[..indent]));
                    continue;
                }
            } else {
                out.push(String::new());
                continue;
            }
        }
        if let Some(c) = KEY_ONLY.captures(l) {
            pending = Some((indent, c.name("blk").is_some()));
        }
        // k8s env / compose / CI: `name: X_PASSWORD` on one line, `value: abc` on the next
        if let Some((ni, left)) = name_pending {
            name_pending = if left > 1 { Some((ni, left - 1)) } else { None };
            if let Some(c) = VALUE_LINE.captures(l) {
                let v = c.name("v").map_or("", |m| m.as_str()).trim();
                if indent + 2 >= ni && !v.is_empty() && !v.starts_with(['|', '>']) && !is_placeholder(v.trim_matches(['"', '\''])) && !is_masked_value(v) {
                    name_pending = None;
                    crate::redact::note_hit("name-value");
                    out.push(format!("{}***", &l[..c.name("v").map_or(l.len(), |m| m.start())]));
                    continue;
                }
                name_pending = None;
            }
        }
        if let Some(c) = NAME_LINE.captures(l) {
            let _ = c;
            name_pending = Some((indent, 2));
        }
        out.push(redact_one(l));
    }
    out
}

/// Indexed text never carries credentials: long opaque strings, JWTs, and values on password-ish lines.
pub fn redact(s: &str) -> String {
    crate::redact::redact_block(s)
}

/// The engine behind [`redact`] and `redact::redact_block`.
pub(crate) fn redact_inner(s: &str) -> String {
    if s.contains('\n') {
        let mut v = redact_lines(s);
        if s.ends_with('\n') {
            v.push(String::new());
        }
        return v.join("\n");
    }
    redact_one(s)
}

fn redact_one(s: &str) -> String {
    crate::redact::guard(s, &redact_core)
}

/// The keyed detectors alone (the base64 layer decodes a token and asks whether it holds a credential).
pub(crate) fn redact_keyed_only(s: &str) -> String {
    let t = redact_keyed(s);
    mask_expr_literals(&t).into_owned()
}

fn redact_core(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let s = crate::redact::pre(s);
    let s = if JWT.is_match(&s) {
        crate::redact::note_hit("jwt-legacy");
        JWT.replace_all(&s, "[redacted]").into_owned().into()
    } else {
        s
    };
    let s = if KNOWN.is_match(&s) {
        crate::redact::note_hit("known-token");
        KNOWN.replace_all(&s, "[redacted]").into_owned().into()
    } else {
        s
    };
    let s = redact_keyed(&s);
    let s = mask_expr_literals(&s);
    let s = mask_call_args(&s);
    // opaque runs not glued to path/word chars, unless they are plain lowercase words/paths
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let b = s.as_bytes();
    for m in OPAQUE.find_iter(&s) {
        if crate::redact::skip_opaque(&s, m.as_str()) {
            continue; // lockfile digests, data: URIs, commit hashes next to their label, CamelCase / snake_case names
        }
        let glued_before = m.start() > 0 && {
            let c = b[m.start() - 1] as char;
            c.is_alphanumeric() || "_/.-".contains(c)
        };
        let glued_after = m.end() < b.len() && {
            let c = b[m.end()] as char;
            c.is_alphanumeric() || "_/.-".contains(c)
        };
        let plain = m.as_str().chars().all(|c| c.is_ascii_lowercase() || "_/-".contains(c));
        if !glued_before && !glued_after && !plain {
            crate::redact::note_hit("opaque-token");
            out.push_str(&s[last..m.start()]);
            out.push_str("[redacted]");
            last = m.end();
        }
    }
    out.push_str(&s[last..]);
    // the words inside our own masks (`***github-token***`) must not make the rest of the line look credential-ish
    // (`tokenize`, `tokenizer`: a text-processing word, not a credential)
    // a URL/file path (`"/users/2/settings/password"`, `src/secrets/`) names a route or a file, not a credential:
    // it alone does not make the line's other tokens (`hStub15`) look like secrets. `/password=x`, `?token=x` and a
    // path that itself holds a mixed token (`/token/abc123def456`) still do.
    let secrety_of = |t: &str| {
        let low = t.to_ascii_lowercase();
        let t = if low.contains("tokeniz") { std::borrow::Cow::Owned(low.replace("tokeniz", "tkniz")) } else { std::borrow::Cow::Borrowed(t) };
        let t = if t.contains('/') {
            std::borrow::Cow::Owned(
                PATH_SEG
                    .replace_all(&t, |c: &regex::Captures| {
                        let end = c.get(0).unwrap().end();
                        if matches!(t[end..].chars().next(), Some('=' | ':')) || MIXED.is_match(&c[0]) { c[0].to_string() } else { "/".to_string() }
                    })
                    .into_owned(),
            )
        } else {
            t
        };
        SECRETY.is_match(&t)
    };
    let secrety = if out.contains("***") { secrety_of(&MASK_SPAN.replace_all(&out, "")) } else { secrety_of(&out) };
    if secrety {
        let t = BACKTICK.replace_all(&out, |c: &regex::Captures| {
            if c[0].contains("${") || benign_span(&c[0][1..c[0].len() - 1]) {
                c[0].to_string()
            } else {
                crate::redact::note_hit("backtick");
                "`***`".to_string()
            }
        });
        let t = KV.replace_all(&t, |c: &regex::Captures| {
            let st = c.get(0).unwrap().start();
            let glued = t[..st].ends_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_');
            if (glued && is_count(&c[2], &t[c.get(0).unwrap().end()..])) || c[2].contains("***") || is_placeholder(&c[2]) || c[2].starts_with(['=', '>']) || is_expression(&c[1], &c[2], &t[c.get(0).unwrap().end()..]) || t[..c.get(0).unwrap().start()].to_ascii_lowercase().ends_with("id-") || benign_value(&c[1], c[2].trim_end_matches([';', ',', ')', '}', ']']), c[2].trim_end_matches([';', ',', ')', '}', ']']).trim_matches(['"', '\''])) {
                c[0].to_string()
            } else {
                crate::redact::note_hit("kv");
                format!("{}***", &c[1])
            }
        });
        let t = MIXED.replace_all(&t, |c: &regex::Captures| {
            let w = &c[0];
            if w.chars().any(|x| x.is_ascii_alphabetic()) {
                crate::redact::note_hit("mixed-token");
                "***".to_string()
            } else {
                w.to_string()
            }
        });
        return crate::redact::post(t.into_owned());
    }
    crate::redact::post(out)
}

/// A credential-named key followed by `=`, `:`, `==`, `!==`...: the operator and what follows to the end of the
/// expression (`,` `;` `}` `]` or an unbalanced `)` at depth 0).
static KEYOP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:(?-u:\b)[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|authorization)(?:[._-][A-Za-z0-9_.-]*|(?-i:[A-Z0-9])[A-Za-z0-9_.-]*)?"#,
        r#"|(?-u:\b)(?:[A-Za-z0-9_.-]*[._-])?(?:pass|pwd|pw))["']?[ \t]*(?:[!=]==?|[:=])[ \t]*"#,
    ))
    .unwrap()
});

/// Quoted literals inside the expression after a credential key (`a || 'lit'`, `a ?? "lit"`, ternary arms,
/// `"Bearer " + (t || "tok")`, default parameters `pw = "lit"`) are values, not code: `is_expression` keeps the
/// identifier part of such a line readable, this masks the literals in it (8+ characters or with a digit; the sole
/// argument of a getter such as `getItem('access_token')` is a name and stays).
fn mask_expr_literals(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(['"', '\'']) {
        return std::borrow::Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out = String::new();
    let mut last = 0;
    let mut pos = 0;
    while let Some(m) = KEYOP.find_at(s, pos) {
        pos = m.end();
        if b.get(m.end()).is_some_and(|c| *c == b'>') || s[..m.end()].ends_with("=>") {
            continue;
        }
        if s.get(m.end()..).is_some_and(is_tag_start) {
            continue; // JSX / HTML: `<label>Password: <input type="password" />`
        }
        // the key sits inside a quoted string (`-H "Authorization: Bearer x" https://h`): its value is the rest of that
        // string (the typed rules mask it), and the closing quote is not the start of a literal
        let before = &s[..m.start()];
        if before.matches('"').count() % 2 == 1 || (before.matches('\'').count() % 2 == 1 && !before.contains('"')) {
            continue;
        }
        // scan the expression
        let (mut i, mut depth) = (m.end(), 0i32);
        let mut lits: Vec<(usize, usize)> = vec![];
        while i < b.len() {
            match b[i] {
                b'"' | b'\'' | b'`' => {
                    let q = b[i];
                    let st = i;
                    i += 1;
                    while i < b.len() && b[i] != q {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i = (i + 1).min(b.len());
                    if q != b'`' {
                        lits.push((st, i));
                    }
                    continue;
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                b',' | b';' if depth == 0 => break,
                _ => {}
            }
            i += 1;
        }
        let end = i.min(b.len());
        for (a, e) in lits {
            if e > end || e - a < 3 || !s.is_char_boundary(a) || !s.is_char_boundary(e) {
                continue;
            }
            // an unterminated literal runs to the line end (which may be inside a multi-byte character): no closing quote
            let close = if b[e - 1] == b[a] { e - 1 } else { e };
            let inner = s[a + 1..close].trim();
            if inner.contains("***") || inner.contains("[redacted]") || crate::redact::is_ref(inner) {
                continue;
            }
            if inner.contains('{') && inner.contains('}') && {
                let mut d = 0;
                let rest: String = inner.chars().filter(|ch| match ch { '{' => { d += 1; false } '}' => { d -= 1; false } _ => d == 0 }).collect();
                matches!(rest.trim().to_ascii_lowercase().as_str(), "" | "bearer" | "basic" | "token" | "digest")
            } {
                continue; // `f"Bearer {token}"`: a template around a variable
            }
            if matches!(inner, "function" | "string" | "number" | "object" | "boolean" | "undefined" | "symbol" | "bigint") || m.as_str().to_ascii_lowercase().contains("id-token") {
                continue; // `typeof token === 'function'`
            }
            let has_digit = inner.chars().any(|c| c.is_ascii_digit());
            if !has_digit && name_like_suffix(key_suffix(m.as_str())) && wordish(inner) {
                continue; // `TOKEN_HEADER = "Authorization"`, `"auth.token.expired": "Your session has expired"`
            }
            if !(has_digit || inner.chars().count() >= 8) {
                continue;
            }
            if !has_digit && sole_getter_arg(s, a, e) {
                continue;
            }
            if !has_digit && inner.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') && {
                let l = inner.to_ascii_lowercase();
                CRED_WORDS.iter().any(|w| l.contains(w))
            } {
                continue; // `no symbol 'hash_password'`, `key: 'refresh_token'`: a name with a credential word in it
            }
            if regex_ctor_arg(s, a) {
                continue; // `Regex::new(r"...")`, `re.compile("...")`: a pattern, not a value
            }
            if string_method_arg(s, a) {
                continue; // `pw = pw.replace("x1y2", "")`: what a string method searches for is not a value
            }
            out.push_str(&s[last..a]);
            out.push_str("***");
            crate::redact::note_hit("expr-literal");
            last = e;
        }
        pos = pos.max(end.min(s.len()));
        if pos >= s.len() {
            break;
        }
    }
    if last == 0 && out.is_empty() {
        return std::borrow::Cow::Borrowed(s);
    }
    out.push_str(&s[last..]);
    std::borrow::Cow::Owned(out)
}

/// A call whose name is a credential (`setPassword("x")`, `update_token('x')`), a login-like call (`login(user, "x")`)
/// or a credential-named parameter holding a tuple (`auth=("user", "x")`): its secret-looking string arguments are values.
static CALL_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?-u:\b)(?P<cred>[A-Za-z0-9_.]*(?:password|passwd|passphrase|secret|token|api_?key|credential)s?\s*\()",
        r"|(?-u:\b)(?P<login>(?:[A-Za-z0-9_]+\.)?(?:log_?in|sign_?in|authenticate|basic_?auth|http_?basic_?auth|auth)\s*\()",
        r"|(?-u:\b)(?P<tuple>(?:auth|credentials?|basic_?auth)\s*=\s*\()",
    ))
    .unwrap()
});

fn mask_call_args(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains(['"', '\'']) || !s.contains('(') || !CALL_OPEN.is_match(s) {
        return std::borrow::Cow::Borrowed(s);
    }
    let b = s.as_bytes();
    let mut out = String::new();
    let mut last = 0;
    let mut pos = 0;
    while let Some(c) = CALL_OPEN.captures_at(s, pos) {
        let m = c.get(0).unwrap();
        pos = m.end();
        let name = m.as_str().to_ascii_lowercase();
        let callee = name.trim_end_matches(|ch: char| ch == '(' || ch.is_whitespace());
        let base = callee.rsplit('.').next().unwrap_or(callee);
        if c.name("cred").is_some() && ["get", "has", "read", "load", "fetch", "find", "lookup", "require", "env", "remove", "delete", "resolve", "is", "check", "validate", "verify", "decode", "parse", "t", "gettext"].iter().any(|p| base.starts_with(p) && !base.starts_with("token") && !base.starts_with("secret") && !base.starts_with("password")) {
            continue;
        }
        let only_after_first = c.name("cred").is_none();
        // split the top-level arguments (bounded)
        let (mut i, mut depth, mut start, mut idx) = (m.end(), 0i32, m.end(), 0usize);
        let lim = (m.end() + 600).min(b.len());
        let mut args: Vec<(usize, usize)> = vec![];
        while i < lim {
            match b[i] {
                b'"' | b'\'' => {
                    let q = b[i];
                    i += 1;
                    while i < lim && b[i] != q {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    if depth == 0 {
                        args.push((start, i));
                        break;
                    }
                    depth -= 1;
                }
                b',' if depth == 0 => {
                    args.push((start, i));
                    start = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        for (a0, e0) in args {
            idx += 1;
            if only_after_first && idx == 1 {
                continue;
            }
            if !s.is_char_boundary(a0) || !s.is_char_boundary(e0) || a0 < last {
                continue;
            }
            let seg = &s[a0..e0];
            let t = seg.trim();
            let lead = seg.len() - seg.trim_start().len();
            let q = t.chars().next().unwrap_or(' ');
            if t.len() < 3 || !(q == '"' || q == '\'') || !t.ends_with(q) || t[1..t.len() - 1].contains(q) {
                continue;
            }
            let inner = &t[1..t.len() - 1];
            let has_digit = inner.chars().any(|ch| ch.is_ascii_digit());
            if inner.contains("***") || inner.contains("[redacted]") || crate::redact::is_ref(inner) || is_placeholder(inner) || !(has_digit || inner.chars().count() >= 8) {
                continue;
            }
            if !has_digit && (inner.contains(' ') || inner.contains('/') && !inner.contains(char::is_uppercase)) {
                continue; // a sentence or a path/endpoint
            }
            let (a, e) = (a0 + lead, a0 + lead + t.len());
            out.push_str(&s[last..a]);
            out.push_str("***");
            crate::redact::note_hit("call-arg");
            last = e;
        }
        pos = pos.max(m.end());
    }
    if last == 0 && out.is_empty() {
        return std::borrow::Cow::Borrowed(s);
    }
    out.push_str(&s[last..]);
    std::borrow::Cow::Owned(out)
}

/// What follows the last credential word of a key (`auth.token.expired` -> `.expired`).
fn key_suffix(key: &str) -> &str {
    let l = key.to_ascii_lowercase();
    let mut best = None;
    for w in ["password", "passwd", "passphrase", "secret", "token", "api_key", "api-key", "apikey", "access_key", "private_key", "auth_key", "pwd", "pass"] {
        if let Some(p) = l.rfind(w) {
            let e = p + w.len();
            if best.is_none_or(|b| e > b) {
                best = Some(e);
            }
        }
    }
    best.map_or("", |e| key.get(e..).unwrap_or(""))
}

/// `getItem('access_token')`, `env("DB_URL")`: the literal is the only argument of a lookup call.
fn sole_getter_arg(s: &str, a: usize, e: usize) -> bool {
    let before = s[..a].trim_end();
    let after = s[e..].trim_start();
    if before.ends_with('[') && after.starts_with(']') {
        return true; // `os.environ["X"]`, `request.form['x']`: an index is a name
    }
    if !before.ends_with('(') || !after.starts_with(')') {
        return false;
    }
    let name: String = before[..before.len() - 1].chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<Vec<_>>().into_iter().rev().collect();
    let l = name.to_ascii_lowercase();
    ["get", "has", "read", "load", "fetch", "find", "lookup", "require", "env", "remove", "delete", "resolve"].iter().any(|p| l.starts_with(p))
}

/// Is the literal at `a` (with an optional raw/bytes prefix) the pattern argument of a regex constructor?
fn regex_ctor_arg(s: &str, a: usize) -> bool {
    let before = s[..a].trim_end_matches(['r', 'b', 'R', '#']).trim_end();
    let Some(b) = before.strip_suffix('(') else { return false };
    let b = b.trim_end();
    ["Regex::new", "RegexBuilder::new", "Regex::from", "re.compile", "regex.compile", "RegExp", "Pattern.compile", "regexp.MustCompile", "regexp.Compile", "re.match", "re.search", "re.sub", "re.fullmatch"].iter().any(|c| b.ends_with(c))
}

/// Is the literal at `a` an argument of a string method (`.replace(`, `.split(`, `.startsWith(` ...)? Its text is a
/// pattern or a separator the code searches for, not the credential's value.
fn string_method_arg(s: &str, a: usize) -> bool {
    let b = s.as_bytes();
    let (mut i, mut depth) = (a, 0i32);
    // back to the unmatched `(` that opens the argument list (quotes skipped roughly: a literal holding `(` is rare)
    while i > 0 {
        i -= 1;
        match b[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth > 0 => depth -= 1,
            b'(' => break,
            b'[' | b'{' | b';' | b'\n' => return false,
            _ => {}
        }
    }
    if b.get(i) != Some(&b'(') {
        return false;
    }
    let before = s[..i].trim_end();
    let name: String = before.chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<Vec<_>>().into_iter().rev().collect();
    if !before[..before.len() - name.len()].ends_with('.') {
        return false;
    }
    let l = name.to_ascii_lowercase();
    [
        "replace", "replaceall", "replace_all", "replacen", "replacefirst", "split", "splitn", "rsplit", "split_once", "rsplit_once", "strip",
        "lstrip", "rstrip", "strip_prefix", "strip_suffix", "trim_start_matches", "trim_end_matches", "trim_matches", "startswith",
        "endswith", "starts_with", "ends_with", "contains", "includes", "indexof", "lastindexof", "find", "rfind", "matches", "count",
        "partition", "rpartition", "join", "removeprefix", "removesuffix", "padstart", "padend",
    ]
    .contains(&l.as_str())
}

/// A count of things after a credential-named key (`== generateToken: 3 commits`, `token: 12 callers`): a short number
/// followed by a lowercase word is a tally, not a value.
fn is_count(val: &str, rest: &str) -> bool {
    val.len() <= 6 && !val.is_empty() && val.bytes().all(|b| b.is_ascii_digit()) && rest.starts_with(' ') && rest[1..].starts_with(|ch: char| ch.is_ascii_lowercase())
}

/// `replace_all` behind a DFA `is_match` (capture-group matching is an order of magnitude slower than a plain scan).
fn repl<'a>(re: &Regex, x: &'a str, f: impl FnMut(&regex::Captures) -> String) -> std::borrow::Cow<'a, str> {
    if re.is_match(x) {
        re.replace_all(x, f)
    } else {
        std::borrow::Cow::Borrowed(x)
    }
}

/// `re.replace_all(x, "${1}***")`, except where what follows group 1 is already a mask (`***aws-key***`).
fn star_after<'a>(re: &Regex, x: &'a str, rule: &str) -> std::borrow::Cow<'a, str> {
    repl(re, x, |c: &regex::Captures| {
        let (all, g1) = (&c[0], &c[1]);
        let v = &all[g1.len()..];
        if v.contains("***") || is_placeholder(v) || benign_value(g1, v, v.trim_matches(['"', '\''])) {
            all.to_string()
        } else {
            crate::redact::note_hit(rule);
            format!("{g1}***")
        }
    })
}

/// Credentials identified by the word next to them (key names, flags, headers, prose) rather than by shape.
fn redact_keyed(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let mut t: Cow<str> = Cow::Borrowed(s);
    let apply = |t: &mut Cow<str>, f: &dyn Fn(&str) -> Cow<str>| {
        let n = match f(t) {
            Cow::Owned(o) => Some(o),
            Cow::Borrowed(_) => None,
        };
        if let Some(o) = n {
            *t = Cow::Owned(o);
        }
    };
    apply(&mut t, &|x| {
        repl(&KV2, x, |c: &regex::Captures| {
            let key = c[1].trim_end_matches(|ch: char| matches!(ch, ' ' | '\t' | ':' | '=' | '"' | '\'')).to_ascii_lowercase();
            let glued = !matches!(key.as_str(), "password" | "passwd" | "passphrase" | "secret" | "token" | "pw" | "pwd" | "pass" | "psk" | "api_key" | "apikey" | "api-key");
            if (glued && is_count(&c["val"], &x[c.get(0).unwrap().end()..])) || c["val"].contains("***") || c["val"].starts_with(['=', '>']) || is_placeholder(&c["val"]) || is_expression(&c[1], &c["val"], &x[c.get(0).unwrap().end()..]) {
                return c[0].to_string();
            }
            if benign_value(&c[1], &c["val"], c["val"].trim_matches(|ch: char| ch == '"' || ch == '\'')) {
                return c[0].to_string();
            }
            // `password_required: true`, `token_ttl: 60`: a flag or number after a key that merely continues the word stays
            let raw = &c["val"];
            let inner = raw.trim_matches(|ch: char| ch == '"' || ch == '\'');
            let v = inner.to_ascii_lowercase();
            if let Some(suf) = c.name("suf") {
                if SOFT_VALUES.contains(&v.as_str()) || v.parse::<f64>().is_ok() || (name_like_suffix(suf.as_str()) && (wordish(inner) || inner.contains('/') || raw.starts_with(['f', 'F']))) {
                    return c[0].to_string();
                }
            }
            crate::redact::note_hit("kv");
            match raw.chars().next() {
                Some(q @ ('"' | '\'')) if raw.len() >= 2 && raw.ends_with(q) => format!("{}{q}***{q}", &c[1]),
                _ => format!("{}***", &c[1]),
            }
        })
    });
    apply(&mut t, &|x| {
        repl(&ENV_KV, x, |c: &regex::Captures| {
            // `API_KEY = os.environ.get('X') or 'lit'`: the lookup stays readable, its literal fallback is masked later
            if c[2].contains("***") || is_expression(&c[1], &c[2], &x[c.get(0).unwrap().end()..]) || benign_value(&c[1], &c[2], c[2].trim_matches(['"', '\''])) {
                c[0].to_string()
            } else {
                crate::redact::note_hit("env-key");
                format!("{}***", &c[1])
            }
        })
    });
    apply(&mut t, &|x| {
        repl(&ENC_KV, x, |c: &regex::Captures| {
            let v = &c[2];
            let end = [v.find('&'), v.to_ascii_lowercase().find("%26")].into_iter().flatten().min().unwrap_or(v.len());
            crate::redact::note_hit("url-encoded-kv");
            format!("{}***{}", &c[1], &v[end..])
        })
    });
    if t.contains("DEFAULT") || t.contains("default") {
        apply(&mut t, &|x| star_after(&SQL_DEFAULT, x, "sql-default"));
    }
    apply(&mut t, &|x| star_after(&AUTHZ, x, "authz-header"));
    apply(&mut t, &|x| star_after(&LONGFLAG, x, "cli-flag"));
    apply(&mut t, &|x| star_after(&CURL_USER, x, "curl-user"));
    apply(&mut t, &|x| {
        repl(&PROSE, x, |c: &regex::Captures| {
            if c[1].contains(['=', ':']) && (c[2].starts_with(['=', '>']) || is_expression(&c[1], &c[2], &x[c.get(0).unwrap().end()..]) || benign_value(&c[1], &c[2], c[2].trim_matches(['"', '\''])) ) {
                return c[0].to_string();
            }
            let v = first_word(&c[2]);
            if c[2].contains("***") || NOT_A_SECRET.contains(&v.as_str()) {
                c[0].to_string()
            } else {
                crate::redact::note_hit("prose");
                format!("{}***", &c[1])
            }
        })
    });
    apply(&mut t, &|x| {
        repl(&PROSE_TO, x, |c: &regex::Captures| {
            let v = first_word(&c[2]);
            if c[2].contains("***") || NOT_A_SECRET.contains(&v.as_str()) {
                c[0].to_string()
            } else {
                crate::redact::note_hit("prose");
                format!("{}***", &c[1])
            }
        })
    });
    if PW_TOOL.is_match(&t) {
        apply(&mut t, &|x| star_after(&PW_FLAG, x, "cli-flag"));
    }
    if TWILIO.is_match(&t) {
        apply(&mut t, &|x| HEX32.replace_all(x, "[redacted]"));
    }
    t
}

/// Collapse whitespace and cut to `n` chars with an ellipsis.
pub fn clip(s: &str, n: usize) -> String {
    let s = WS.replace_all(s, " ");
    let s = s.trim();
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(n.saturating_sub(1)).collect();
        o.push('…');
        o
    }
}

static SEV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(P0|P1|P2|P3|critical|blocker|high|medium|med|low)\b|🔴|🟠|🟡|🟢").unwrap());

pub fn severity_of(texts: &[&str]) -> String {
    for t in texts {
        if let Some(c) = SEV.captures(t) {
            let k = c.get(1).map(|m| m.as_str()).unwrap_or_else(|| c.get(0).unwrap().as_str()).to_lowercase();
            let mapped = match k.as_str() {
                "🔴" => "high",
                "🟠" => "medium",
                "🟡" | "🟢" => "low",
                "med" => "medium",
                "blocker" => "critical",
                x => x,
            }
            .to_string();
            return if k.starts_with('p') { mapped.to_uppercase() } else { mapped };
        }
    }
    String::new()
}

static REJ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)false positive|not a bug|wontfix|won't fix").unwrap());
static FIXED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[x\]|✅|(?i:\bfixed\b|\bdone\b|\bresolved\b|\bshipped\b)").unwrap());
static DEFER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)defer|later|backlog|needs design").unwrap());
static OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[ \]|(?i:\bopen\b|\btodo\b)").unwrap());

pub fn status_of(t: &str) -> &'static str {
    if REJ.is_match(t) {
        "rejected"
    } else if FIXED.is_match(t) {
        "fixed"
    } else if DEFER.is_match(t) {
        "deferred"
    } else if OPEN.is_match(t) {
        "open"
    } else {
        ""
    }
}

/// Line lookup by byte offset.
pub struct Lines {
    starts: Vec<usize>,
}
impl Lines {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Self { starts }
    }
    /// 1-based line of byte offset `off`.
    pub fn at(&self, off: usize) -> u32 {
        self.starts.partition_point(|&s| s <= off) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts() {
        assert_eq!(redact("password: hunter22x"), "password: ***");
        assert!(redact("token eyJabcdefghijk.abcdefghijkl.xyz here").contains("***jwt***"));
        assert_eq!(redact("plain text"), "plain text");
        for leak in ["AKIAABCDEFGHIJKLMNOP", "sk-live-abcdef0123456789abcdef", "ghp_abcdefghijklmnopqrstuvwxyz0123",
                     "postgres://app:hunter2@db/x", "Authorization: Bearer abcdefghijklmnop1234", "password=SuperSecret123"] {
            let r = redact(&format!("x {leak} y"));
            assert!(!r.contains("hunter2") && !r.contains("SuperSecret") && !r.contains("ABCDEFGHIJKLMNOP")
                && !r.contains("0123456789abcdef") && !r.contains("abcdefghijklmnop"), "{leak} -> {r}");
        }
        assert_eq!(
            redact("path/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "path/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(redact("key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD!"), "key [redacted]!");
    }
    #[test]
    fn redacts_keyed_and_provider_secrets() {
        // (input, secret that must not survive)
        let cases: &[(&str, &str)] = &[
            (r#"{"password": "Zq81xKvPlm"}"#, "Zq81xKvPlm"),
            (r#"{"apiKey": "k9Dd8s7Fh2"}"#, "k9Dd8s7Fh2"),
            (r#"{ "db_password":"p4ssw0rdZ" }"#, "p4ssw0rdZ"),
            ("access_key = AbCd1234Efgh", "AbCd1234Efgh"),
            ("smtp.pass=mailPw77", "mailPw77"),
            ("pwd: s3cretVal", "s3cretVal"),
            ("pass: s3cretVal2", "s3cretVal2"),
            ("private_key: MIIEvQIBADANBgk", "MIIEvQIBADANBgk"),
            ("passphrase = 'correct horse'", "correct horse"),
            ("the password is Tr0ub4dor", "Tr0ub4dor"),
            ("Password: Tr0ub4dor&3", "Tr0ub4dor"),
            ("curl -u admin:Sup3rSecret https://x/y", "Sup3rSecret"),
            ("curl --user 'admin:Sup3rSecret2' https://x", "Sup3rSecret2"),
            ("mysql -u root -pHunterTwo db", "HunterTwo"),
            ("sshpass -p hunterThree ssh host", "hunterThree"),
            ("mysql -p 'hunter Four'", "hunter Four"),
            ("curl --password hunterFive", "hunterFive"),
            ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
            (r#"headers: {"Authorization": "Bearer abc"}"#, "Bearer abc"),
            ("pk_live_51HabcdEFGH12345678", "51HabcdEFGH12345678"),
            ("sk_live_51HabcdEFGH12345678", "51HabcdEFGH12345678"),
            ("rk_test_51HabcdEFGH12345678", "51HabcdEFGH12345678"),
            ("glpat-abcdEFGH1234567890xy", "abcdEFGH1234567890xy"),
            ("SG.abcdEFGH1234567890xy.abcdEFGH1234567890zw-_", "abcdEFGH1234567890xy"),
            ("TWILIO_SID=AC0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
            ("twilio auth 0123456789abcdef0123456789abcdee", "0123456789abcdef0123456789abcdee"),
        ];
        for (i, secret) in cases {
            let r = redact(i);
            assert!(!r.contains(secret), "{i} -> {r}");
        }
        // innocent text and flags stay readable
        for keep in ["mkdir -p build/out", "docker run -p 8080:80 img", "psql -p 5432 db", "the password is required", "bypass: true", "see the token docs"] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
        assert_eq!(redact("curl -u admin:Sup3rSecret x"), "curl -u admin:*** x");
    }
    #[test]
    fn masks_values_not_identifiers() {
        for keep in [
            "boolean objectToken = token != null && !token.isEmpty();",
            "if (token != null) {",
            "this.token = token;",
            "const password = getPassword();",
            "String secret = config.getSecret();",
            "token = request.getHeader(AUTH);",
            "password: null",
            "let t = token ? token.trim() : null;",
        ] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
        for (i, secret) in [
            ("String password = \"Zq81xKvPlm\";", "Zq81xKvPlm"),
            ("token = 'abcdefghij'", "abcdefghij"),
            ("password = hunter2", "hunter2"),
            ("secret=s3cretVal", "s3cretVal"),
            ("password: hunter", "hunter"),
        ] {
            assert!(!redact(i).contains(secret), "{i}");
        }
    }
    #[test]
    fn masks_literals_after_expressions() {
        let leaks: &[(&str, &str)] = &[
            ("const password = cfg.pw || 'pa55word-literal-xyz'", "pa55word-literal"),
            ("const password2 = cfg.pw || \"pa55word-literal-dq\"", "pa55word-literal-dq"),
            ("const apiKey2 = env.K || 'sq-singlequote-secret-1'", "sq-singlequote"),
            ("const token = opts.token ? \"tok_live_1234567890abcdef\" : null", "tok_live_123"),
            ("const token2 = x ? \"tok_live_2222222222abcdef\" : null", "tok_live_222"),
            ("const secret2 = process.env.S ?? 'nullish-secret-value-9'", "nullish-secret"),
            ("const authToken = process.env.T || fallbackFn(\"abc-literal-arg-1234\")", "abc-literal-arg"),
            ("const dbPassword = getenv(\"DB\") || \"pg-pass-literal-1\"", "pg-pass-literal"),
            ("const password3 = a.b ? a.b : \"ternary-else-secret-3\"", "ternary-else"),
            ("const cfg = { password: process.env.P || \"obj-literal-secret-5\", token: \"tok_obj_6666666666\" }", "obj-literal"),
            ("const cfg = { password: process.env.P || \"obj-literal-secret-5\", token: \"tok_obj_6666666666\" }", "tok_obj"),
            ("headers.Authorization = \"Bearer \" + (t || \"bearer-literal-secret-7\")", "bearer-literal"),
            ("headers.Authorization = \"Bearer \" + \"tok1234567890ab\"", "tok1234567890ab"),
            ("let pwd = isDev ? \"dev-pwd-literal-8\" : prodPwd", "dev-pwd-literal"),
            ("if (token != null && token === \"cmp-literal-secret-10\") {}", "cmp-literal"),
            ("const clientSecret = String(x || \"\") || \"client-secret-literal-11\"", "client-secret-literal"),
            ("function login(user, pw = \"defaultPw99\") {", "defaultPw99"),
            ("function login(user, password = 'changeme-now') {", "changeme-now"),
        ];
        for (i, secret) in leaks {
            let r = redact(i);
            assert!(!r.contains(secret), "{i} -> {r}");
        }
        assert_eq!(redact("if (token === 'x') {}"), "if (token === 'x') {}");
        assert!(redact("if (token === 'abcdefghij') {}").contains("token === ***"), "{}", redact("if (token === 'abcdefghij') {}"));
        for keep in [
            "if (token != null) {",
            "if (token !== undefined) {",
            "const token = localStorage.getItem('access_token');",
            "const secret = env.get(\"SECRET_NAME\");",
            "const label = cfg.name || 'Default label text';",
            "const handler = token => fetch(\"https://example.com/api\");",
        ] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
    }
    #[test]
    fn redaction_gaps_round2() {
        let cases: &[(&str, &str)] = &[
            // URL password containing / or @
            ("postgres://app:pa/ss@word@db.internal:5432/x", "pa/ss"),
            ("postgres://app:pa/ss@word@db.internal:5432/x", "word@"),
            ("mongodb://u:p@ss@host/db", "p@ss"),
            // client_secret_value / *_secret_* / *_token_* / *_key_value
            ("client_secret_value: Hq81zzKd", "Hq81zzKd"),
            ("my_secret_thing = 'Abc9Zq'", "Abc9Zq"),
            ("refresh_token_a=Zx81kLmn", "Zx81kLmn"),
            ("stripe_key_value: Qw12ErTy", "Qw12ErTy"),
            ("clientSecretValue: Gh77Jk88", "Gh77Jk88"),
            // URL-encoded key=value
            ("https://x/cb?password%3Dhunter2%26user%3Dbob", "hunter2"),
            ("redirect=a%3Fapi_key%3DAbCd1234Zz", "AbCd1234Zz"),
            // API="..." env assignments
            ("API=\"abc-123-def\"", "abc-123-def"),
            ("export MY_KEY=zz99Top", "zz99Top"),
            // commit subjects without is/was
            ("change password to hunter2", "hunter2"),
            ("set token as Zz9Yy8", "Zz9Yy8"),
        ];
        for (i, secret) in cases {
            let r = redact(i);
            assert!(!r.contains(secret), "{i} -> {r}");
        }
        // multi-line: key on one line, value on the next; block scalar; PEM with a short last body line
        let y = redact("db:\n  password:\n    hunter2Value\n  user: bob\n");
        assert!(!y.contains("hunter2Value") && y.contains("user: bob") && y.ends_with('\n'), "{y}");
        let y = redact("secret: |\n  line1Secret\n  line2Secret\nnext: ok\n");
        assert!(!y.contains("Secret") && y.contains("next: ok"), "{y}");
        let pem = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1\nab12\n-----END RSA PRIVATE KEY-----\nb";
        let r = redact(pem);
        assert!(!r.contains("MIIE") && !r.contains("ab12") && r.lines().count() == pem.lines().count(), "{r}");
        assert!(r.starts_with("a\n") && r.ends_with("\nb"), "{r}");
        // single-line PEM (joined paragraph) and a truncated one
        assert!(!redact("k -----BEGIN PRIVATE KEY----- MIIEabc d -----END PRIVATE KEY----- z").contains("MIIEabc"));
        assert!(!redact("k -----BEGIN PRIVATE KEY----- MIIEabc d").contains("MIIEabc"));
        // line-preserving for per-line callers
        assert_eq!(redact_lines("a\nsecret:\n  zzTop9\nb").len(), 4);
        // still readable
        for keep in ["mkdir -p a/b", "docker run -p 8080:80 x", "password_required: true", "token_ttl: 60", "API_URL=http://x", "pin to top", "reset password to default",
                     "https://user@host/path?email=a@b.c"] {
            assert_eq!(redact(keep), keep, "{keep}");
        }
    }
    #[test]
    fn sev_status() {
        assert_eq!(severity_of(&["a P2 thing"]), "P2");
        assert_eq!(severity_of(&["", "🔴 bad"]), "high");
        assert_eq!(status_of("- [x] done"), "fixed");
        assert_eq!(status_of("- [ ] x"), "open");
        assert_eq!(clip("a   b", 10), "a b");
        assert_eq!(Lines::new("a\nb\nc").at(2), 2);
    }

    #[test]
    fn expressions_stay_literals_go() {
        assert_eq!(redact("token_expiration = now + timedelta(seconds=expires_in)"), "token_expiration = now + timedelta(seconds=expires_in)");
        assert_eq!(redact("self.token_expiration = now + timedelta(seconds=3600)"), "self.token_expiration = now + timedelta(seconds=3600)");
        let r = redact("SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'");
        assert!(r.contains("os.environ.get('SECRET_KEY')") && !r.contains("never-guess"), "{r}");
        let r = redact("const secret = process.env.APP_SECRET || \"dev-secret-value\";");
        assert!(!r.contains("dev-secret-value"), "{r}");
        let r = redact("const secret = process.env.APP_SECRET ?? 'literal-fallback';");
        assert!(!r.contains("literal-fallback"), "{r}");
        let r = redact("secret = ENV.fetch('APP_SECRET') { 'fallback-secret' }");
        assert!(!r.contains("fallback-secret"), "{r}");
        let r = redact("password: hunterhunter");
        assert!(!r.contains("hunterhunter"), "{r}");
        let r = redact("password=hunterhunter");
        assert!(!r.contains("hunterhunter"), "{r}");
        let r = redact("password = hunter_two");
        assert!(r.contains("***"), "{r}");
        // a reference to another credential variable stays readable
        assert_eq!(redact("password = token_hex"), "password = token_hex");
        let r = redact("db_password varchar(100) DEFAULT 'changeme123' NOT NULL,");
        assert!(!r.contains("changeme123"), "{r}");
        let r = redact("ALTER TABLE users ADD COLUMN api_token text DEFAULT 'abcdef'");
        assert!(!r.contains("abcdef"), "{r}");
    }
}

/// Compile every fixed pattern of this module now (see `warm.rs`).
pub(crate) fn warm() {
    for r in [&JWT, &OPAQUE, &SECRETY, &MASK_SPAN, &BACKTICK, &KV, &MIXED, &KNOWN, &KV2, &ENV_KV, &ENC_KV, &SQL_DEFAULT, &LONGFLAG, &PROSE, &PROSE_TO, &CURL_USER, &PW_TOOL, &PW_FLAG, &AUTHZ, &TWILIO, &HEX32, &WS, &KEY_ONLY, &NAME_LINE, &VALUE_LINE, &MAPPING_LINE, &KEYOP, &CALL_OPEN, &SEV, &REJ, &FIXED, &DEFER, &OPEN] {
        LazyLock::force(r);
    }
}
