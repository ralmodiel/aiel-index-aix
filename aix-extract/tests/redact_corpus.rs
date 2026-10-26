//! Measured redaction: a generated recall corpus (every secret is built at run time from parts, so the repo never
//! holds a real-looking key), a false-positive corpus, adversarial inputs and timing.
//! `cargo test --release -p aix-extract --test redact_corpus -- --nocapture` prints the tables.

use aix_extract::redact::{redact_block, redact_line};
use std::collections::BTreeMap;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn pick(&mut self, set: &str, n: usize) -> String {
        let b = set.as_bytes();
        (0..n).map(|_| b[(self.next() % b.len() as u64) as usize] as char).collect()
    }
    fn ud(&mut self, n: usize) -> String {
        self.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n)
    }
    fn b62(&mut self, n: usize) -> String {
        loop {
            let s = self.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", n);
            if s.bytes().any(|b| b.is_ascii_digit()) && s.bytes().any(|b| b.is_ascii_uppercase()) && s.bytes().any(|b| b.is_ascii_lowercase()) {
                return s;
            }
        }
    }
    fn hex(&mut self, n: usize) -> String {
        self.pick("0123456789abcdef", n)
    }
    fn b64u(&mut self, n: usize) -> String {
        self.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", n)
    }
    fn b64s(&mut self, n: usize) -> String {
        self.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", n)
    }
    /// a password-looking value: mixed letters and digits
    fn pw(&mut self) -> String {
        let n = 10 + (self.next() % 5) as usize;
        loop {
            let s = self.pick("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789", n);
            if s.bytes().any(|b| b.is_ascii_digit()) && s.bytes().any(|b| b.is_ascii_alphabetic()) {
                return s;
            }
        }
    }
}

fn b64enc(d: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

struct Case {
    family: String,
    syntax: String,
    text: String,
    /// substrings that must not survive
    cores: Vec<String>,
}

/// (family, secret value, the part that must vanish)
fn providers(r: &mut Rng) -> Vec<(&'static str, String, String)> {
    let mut v: Vec<(&'static str, String, String)> = vec![];
    let mut add = |f: &'static str, pre: &str, body: String, post: &str| {
        v.push((f, format!("{pre}{body}{post}"), body));
    };
    add("aws-key", "AKI", format!("A{}", r.ud(16)), "");
    add("aws-key", "AS", format!("IA{}", r.ud(16)), "");
    add("gcp-api-key", "AIza", r.pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", 35), "");
    add("gcp-oauth", "ya29.", r.b64u(60), "");
    add("gcp-oauth", "GOCSPX-", r.b64u(28), "");
    for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        add("github", p, r.b62(36), "");
    }
    add("github", "github_pat_", format!("{}_{}", r.b62(22), r.b62(59)), "");
    add("gitlab", "glpat-", r.b64u(20), "");
    add("gitlab", "glrt-", r.b64u(20), "");
    for p in ["xoxb", "xoxp", "xoxa", "xoxs", "xoxr"] {
        add("slack", &format!("{p}-"), format!("{}-{}-{}", r.pick("0123456789", 12), r.pick("0123456789", 12), r.b62(24)), "");
    }
    add("slack", "xapp-1-", format!("A{}-{}-{}", r.ud(10), r.pick("0123456789", 13), r.hex(64)), "");
    add("slack", "https://hooks.slack.com/services/", format!("T{}/B{}/{}", r.ud(8), r.ud(10), r.b62(24)), "");
    for p in ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_", "whsec_"] {
        add("stripe", p, r.b62(24), "");
    }
    add("twilio", "SK", r.hex(32), "");
    add("twilio", "AC", r.hex(32), "");
    add("sendgrid", "SG.", format!("{}.{}", r.b64u(22), r.b64u(43)), "");
    add("mailgun", "key-", r.hex(32), "");
    add("mailgun", "", format!("{}-{}-{}", r.hex(32), r.hex(8), r.hex(8)), "");
    add("mailchimp", "", r.hex(32), "-us12");
    add("npm", "npm_", r.b62(36), "");
    add("pypi", "pypi-AgEIcHlwaS5vcmc", r.b64u(70), "");
    add("docker", "dckr_pat_", r.b64u(27), "");
    add("huggingface", "hf_", r.b62(34), "");
    add("anthropic", "sk-ant-api03-", r.b64u(93), "");
    add("openai", "sk-proj-", r.b64u(48), "");
    add("openai", "sk-", r.b62(48), "");
    add("openai", "sk-svcacct-", r.b64u(60), "");
    add("shopify", "shpat_", r.hex(32), "");
    add("square", "sq0atp-", r.b64u(22), "");
    add("databricks", "dapi", r.hex(32), "");
    add("digitalocean", "dop_v1_", r.hex(64), "");
    add("atlassian", "ATATT3", r.b64u(180), "");
    add("postman", "PMAK-", format!("{}-{}", r.hex(24), r.hex(34)), "");
    add("newrelic", "NRAK-", r.ud(27), "");
    add("vault", "hvs.", r.b64u(90), "");
    add("terraform", "", format!("{}.atlasv1.{}", r.b62(14), r.b64u(70)), "");
    add("age", "AGE-SECRET-KEY-1", r.pick("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58), "");
    add("grafana", "glsa_", format!("{}_{}", r.b62(32), r.hex(8)), "");
    add("linear", "lin_api_", r.b62(40), "");
    add("supabase", "sbp_", r.hex(40), "");
    add("notion", "secret_", r.b62(43), "");
    add("telegram", "", format!("{}:AA{}", r.pick("0123456789", 10), r.b64u(33)), "");
    add("sentry", "sntrys_", r.b64s(60), "");
    add("azure-secret", "", format!("{}8Q~{}", r.b62(3), r.b64u(34)), "");
    add("bearer", "Bearer ", r.b62(40), "");
    add("bcrypt", "$2b$12$", r.pick("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 53), "");
    add("sha512crypt", "$6$", format!("{}${}", r.b62(8), r.b64u(86)), "");
    add("sops", "ENC[AES256_GCM,data:", format!("{},iv:{},tag:{},type:str", r.b64s(24), r.b64s(32), r.b64s(24)), "]");
    for _ in 0..3 {
        let hdr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = b64enc(format!("{{\"sub\":\"{}\",\"iat\":{}}}", r.b62(10), 1_700_000_000 + r.next() % 1000).as_bytes()).trim_end_matches('=').replace('+', "-").replace('/', "_");
        let sig = r.b64u(43);
        v.push(("jwt", format!("{hdr}.{payload}.{sig}"), sig));
    }
    v
}

/// neutral contexts (no credential word next to the value): the provider detector alone must catch it
const NEUTRAL: &[(&str, &str)] = &[
    ("prose", "please use {V} for the call"),
    ("json", "{\"value\": \"{V}\", \"n\": 1}"),
    ("yaml", "foo: {V}"),
    ("python", "x = \"{V}\""),
    ("url-query", "https://host.invalid/p?x={V}&y=2"),
    ("log", "[INFO] 2024-01-01 got {V} ok"),
    ("crlf", "line one {V}\r"),
    ("json-escaped", "{\"msg\": \"{\\\"v\\\": \\\"{V}\\\"}\"}"),
    ("markdown", "see `{V}` above"),
    ("shell", "echo {V} | tee out"),
    ("toml", "data = \"{V}\""),
    ("comment", "// {V}"),
];

fn gen_cases(seed: u64) -> Vec<Case> {
    let mut r = Rng(seed);
    let mut out = vec![];
    for (fam, val, core) in providers(&mut r) {
        for (syn, t) in NEUTRAL {
            // a bearer value only means something after the word
            out.push(Case { family: format!("provider/{fam}"), syntax: syn.to_string(), text: t.replace("{V}", &val), cores: vec![core.clone()] });
        }
    }
    // credential-named keys in many syntaxes
    let keys = ["password", "passwd", "secret", "api_key", "apiKey", "access_token", "client_secret", "db_password", "auth_token", "private_key"];
    let syn: &[(&str, &str)] = &[
        ("env", "{K}={V}"),
        ("export", "export {K}={V}"),
        ("yaml", "{K}: {V}"),
        ("yaml-quoted", "  {K}: \"{V}\""),
        ("json", "{\"{K}\": \"{V}\"}"),
        ("json-spaced", "{ \"{K}\" : \"{V}\", \"x\": 1 }"),
        ("properties", "{K} = {V}"),
        ("toml", "{K} = \"{V}\""),
        ("ini-spaced", "{K}  =  {V}"),
        ("xml-element", "<{K}>{V}</{K}>"),
        ("xml-attr", "<add key=\"{K}\" value=\"{V}\" />"),
        ("xml-entry", "<entry key=\"{K}\">{V}</entry>"),
        ("hcl", "  {K} = \"{V}\""),
        ("python", "{K} = \"{V}\""),
        ("python-dict", "cfg = {'{K}': '{V}'}"),
        ("python-fstring", "{K} = f\"{V}-{user}\""),
        ("python-getenv", "{K} = os.getenv(\"{K}\", \"{V}\")"),
        ("python-or", "{K} = os.environ.get('{K}') or '{V}'"),
        ("js-const", "const {K} = '{V}';"),
        ("js-object", "const config = { {K}: \"{V}\" };"),
        ("js-or", "const {K} = process.env.{K} || \"{V}\";"),
        ("js-nullish", "const {K} = process.env.{K} ?? '{V}';"),
        ("js-template", "const {K} = `{V}-${x}`;"),
        ("java", "String {K} = \"{V}\";"),
        ("go-define", "{K} := \"{V}\""),
        ("ruby-rocket", "'{K}' => '{V}'"),
        ("php", "${K} = '{V}';"),
        ("shell-quoted", "{K}='{V}'"),
        ("shell-default", "{K}=\"${{K}_ENV:-{V}}\""),
        ("spring-default", "app.{K}=${{K}_ENV:{V}}"),
        ("json-in-string", "\"{\\\"{K}\\\": \\\"{V}\\\"}\""),
        ("docker-env", "docker run -e {K}={V} img"),
        ("comment", "# {K}={V}"),
        ("crlf", "{K}={V}\r"),
        ("urlencoded", "https://x.invalid/cb?{K}%3D{V}%26user%3Dbob"),
        ("prose", "the {K} is {V}"),
    ];
    for k in keys {
        for (sname, tpl) in syn {
            let v = r.pw();
            let text = tpl.replace("{K}", k).replace("{V}", &v);
            out.push(Case { family: "keyed".into(), syntax: sname.to_string(), text, cores: vec![v] });
        }
    }
    // keys where the value is split by concatenation: both halves must go
    for k in &keys[..6] {
        let (a, b) = (r.pw(), r.pw());
        for (sname, tpl) in [("concat-plus", "{K} = \"{A}\" + \"{B}\""), ("concat-dot", "${K} = '{A}' . '{B}'"), ("concat-implicit", "{K} = (\"{A}\" \"{B}\")")] {
            let text = tpl.replace("{K}", k).replace("{A}", &a).replace("{B}", &b);
            out.push(Case { family: "keyed-split".into(), syntax: sname.to_string(), text, cores: vec![a.clone(), b.clone()] });
        }
    }
    // flags and tools
    for _ in 0..4 {
        let v = r.pw();
        for (s, t) in [("curl-u", "curl -u admin:{V} https://x.invalid"), ("flag", "tool --password {V} run"), ("flag-eq", "tool --token={V} run"), ("mysql-p", "mysql -u root -p{V} db"), ("sshpass", "sshpass -p {V} ssh host"), ("k8s-literal", "kubectl create secret generic s --from-literal=k={V}")] {
            out.push(Case { family: "cli".into(), syntax: s.into(), text: t.replace("{V}", &v), cores: vec![v.clone()] });
        }
    }
    // connection strings and URLs
    for _ in 0..4 {
        let p = r.pw();
        let host = "db.internal.invalid";
        for (s, t) in [
            ("postgres", format!("postgres://app:{p}@{host}:5432/x")),
            ("mysql", format!("mysql://root:{p}@{host}/x?ssl=1")),
            ("mongodb", format!("mongodb+srv://u:{p}@{host}/x?retryWrites=true")),
            ("redis", format!("redis://:{p}@{host}:6379/0")),
            ("amqp", format!("amqps://guest:{p}@{host}:5671/vh")),
            ("jdbc-ado", format!("Server={host};Database=d;User Id=sa;Password={p};Encrypt=true")),
            ("https-basic", format!("https://deploy:{p}@git.invalid/org/repo.git")),
            ("git-credentials", format!("https://user:{p}@github.invalid")),
            ("pw-with-slash", format!("postgres://app:{}/{}@{host}/x", &p[..4], &p[4..])),
            ("pw-with-at", format!("postgres://app:{}@{}@{host}/x", &p[..4], &p[4..])),
        ] {
            let core = if s == "pw-with-slash" || s == "pw-with-at" { vec![p[..4].to_string(), p[4..].to_string()] } else { vec![p.clone()] };
            out.push(Case { family: "conn-string".into(), syntax: s.into(), text: t, cores: core });
        }
    }
    let ak = r.b64s(88);
    out.push(Case { family: "conn-string".into(), syntax: "azure-storage".into(), text: format!("DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={ak}==;EndpointSuffix=core.windows.net"), cores: vec![ak.clone()] });
    let sas = r.b64s(44);
    out.push(Case { family: "conn-string".into(), syntax: "azure-sas".into(), text: format!("https://acct.blob.core.windows.net/c?sv=2020-08-04&se=2030-01-01&sig={}", sas.replace('+', "%2B").replace('/', "%2F")), cores: vec![sas[..20].replace('+', "%2B").replace('/', "%2F")] });
    let sb = r.b64s(44);
    out.push(Case { family: "conn-string".into(), syntax: "servicebus".into(), text: format!("Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey={sb}="), cores: vec![sb] });
    // headers, cookies, files
    for _ in 0..4 {
        let t = r.b62(40);
        let c = r.hex(32);
        let b = b64enc(format!("alice:{}", r.pw()).as_bytes());
        for (s, tx, core) in [
            ("authz-bearer", format!("Authorization: Bearer {t}"), t.clone()),
            ("authz-basic", format!("Authorization: Basic {b}"), b.clone()),
            ("authz-json", format!("{{\"Authorization\": \"Bearer {t}\"}}"), t.clone()),
            ("authz-curl", format!("curl -H 'Authorization: token {t}' https://x.invalid"), t.clone()),
            ("proxy-authz", format!("Proxy-Authorization: Basic {b}"), b.clone()),
            ("cookie", format!("Cookie: theme=dark; sessionid={c}; lang=en"), c.clone()),
            ("set-cookie", format!("Set-Cookie: sid={c}; Path=/; HttpOnly"), c.clone()),
            ("x-api-key", format!("X-API-Key: {t}"), t.clone()),
            ("curl-cookie", format!("curl -b 'sid={c}' https://x.invalid"), c.clone()),
            ("npmrc", format!("//registry.invalid/:_authToken={t}"), t.clone()),
            ("netrc", format!("machine git.invalid login bob password {}", &t[..16]), t[..16].to_string()),
            ("pypirc", format!("password = {t}"), t.clone()),
            ("docker-config", format!("\"auth\": \"{b}\""), b.clone()),
        ] {
            out.push(Case { family: "header-file".into(), syntax: s.into(), text: tx, cores: vec![core] });
        }
    }
    // multi-line blocks
    for kind in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
        let body: Vec<String> = (0..5).map(|_| r.b64s(64)).collect();
        let text = format!("before\n-----BEGIN {kind}-----\n{}\n-----END {kind}-----\nafter", body.join("\n"));
        out.push(Case { family: "private-key".into(), syntax: "multiline".into(), text, cores: body.iter().map(|b| b[..30].to_string()).collect() });
        let one = format!("k: -----BEGIN {kind}----- {} -----END {kind}----- z", body.join(" "));
        out.push(Case { family: "private-key".into(), syntax: "one-line".into(), text: one, cores: vec![body[2][..30].to_string()] });
        let esc = format!("{{\"private_key\": \"-----BEGIN {kind}-----\\n{}\\n-----END {kind}-----\\n\"}}", body.join("\\n"));
        out.push(Case { family: "private-key".into(), syntax: "json-escaped".into(), text: esc, cores: vec![body[1][..30].to_string()] });
        let crlf = format!("-----BEGIN {kind}-----\r\n{}\r\n-----END {kind}-----\r\n", body.join("\r\n"));
        out.push(Case { family: "private-key".into(), syntax: "crlf".into(), text: crlf, cores: vec![body[3][..30].to_string()] });
        let trunc = format!("-----BEGIN {kind}-----\n{}\n", body[..2].join("\n"));
        out.push(Case { family: "private-key".into(), syntax: "truncated".into(), text: trunc, cores: vec![body[1][..30].to_string()] });
    }
    for _ in 0..3 {
        let (u, p) = (r.b64s(40), r.b64s(40));
        let t = format!("apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ntype: Opaque\ndata:\n  username: {u}\n  password: {p}\n  tls.crt: {}\nimmutable: true\n", r.b64s(50));
        out.push(Case { family: "k8s-secret".into(), syntax: "yaml".into(), text: t, cores: vec![u, p] });
        let (a, b) = (r.b64s(30), r.b64s(30));
        let t = format!("kind: Secret\nmetadata:\n  name: s\nstringData:\n  config.json: {a}\n  token-x: {b}\n");
        out.push(Case { family: "k8s-secret".into(), syntax: "stringData".into(), text: t, cores: vec![a, b] });
        let a = r.b64s(30);
        let t = format!("{{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"data\":{{\"k\":\"{a}\"}}}}");
        out.push(Case { family: "k8s-secret".into(), syntax: "json".into(), text: t, cores: vec![a] });
        let (h1, h2) = (r.hex(80), r.hex(80));
        let t = format!("db_pass: !vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          {}\n          {}\nnext: ok\n", &h1, &h2);
        out.push(Case { family: "vault-blob".into(), syntax: "ansible".into(), text: t, cores: vec![h1[..40].to_string(), h2[..40].to_string()] });
    }
    // GCP service account JSON, one line
    let pk = r.b64s(64);
    out.push(Case { family: "gcp-sa".into(), syntax: "json".into(), text: format!("{{\"type\": \"service_account\", \"private_key_id\": \"{}\", \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{pk}\\n-----END PRIVATE KEY-----\\n\"}}", r.hex(40)), cores: vec![pk[..30].to_string()] });
    // SQL accounts, name/value pairs, CI log commands, argv lists, setProperty, tables, psk, spaced keys, bare tokens near a key word
    for _ in 0..4 {
        let v = r.pw();
        let t32 = loop {
            let t = r.pick("abcdefghijklmnopqrstuvwxyz0123456789", 32);
            if t.bytes().any(|b| b.is_ascii_digit()) && t.bytes().any(|b| b.is_ascii_alphabetic()) {
                break t;
            }
        };
        let rows: Vec<(&str, &str, String)> = vec![
            ("sql-identified", "CREATE USER 'app'@'%' IDENTIFIED BY '{V}';", v.clone()),
            ("sql-identified-with", "CREATE USER app IDENTIFIED WITH mysql_native_password BY '{V}'", v.clone()),
            ("sql-with-password", "CREATE ROLE svc LOGIN WITH PASSWORD '{V}';", v.clone()),
            ("sql-password-fn", "SET PASSWORD FOR 'u'@'h' = PASSWORD('{V}');", v.clone()),
            ("sql-insert", "INSERT INTO users (id, name, password_hash) VALUES (1, 'bob', '{V}');", v.clone()),
            ("sql-insert-multi", "INSERT INTO accounts (name, api_token) VALUES ('a', '{V}'), ('b', 'zzz');", v.clone()),
            ("har-header", "{\"name\":\"X-Api-Key\",\"value\":\"{V}\"}", v.clone()),
            ("har-cookie", "{\"name\": \"session\", \"value\": \"{V}\", \"path\": \"/\"}", v.clone()),
            ("har-reversed", "{\"value\":\"{V}\",\"name\":\"Authorization\"}", v.clone()),
            ("yaml-flow", "env: [{ name: API_TOKEN, value: {V} }]", v.clone()),
            ("add-mask", "echo \"::add-mask::{V}\"", v.clone()),
            ("argv-list", "args = [\"--api-key\", \"{V}\"]", v.clone()),
            ("argv-go", "cmd := []string{\"run\", \"--password\", \"{V}\"}", v.clone()),
            ("set-property", "System.setProperty(\"javax.net.ssl.keyStorePassword\", \"{V}\");", v.clone()),
            ("md-table", "| password | {V} |", v.clone()),
            ("psk", "wifi psk={V}", v.clone()),
            ("psk-yaml", "preshared_key: {V}", v.clone()),
            ("spaced-key", "p a s s w o r d = {V}", v.clone()),
            ("dotted-key", "s.e.c.r.e.t: {V}", v.clone()),
            ("token32-after", "service token for billing is {V}", t32.clone()),
            ("token32-before", "{V} <- the api key", t32.clone()),
        ];
        for (sname, tpl, core) in rows {
            let text = tpl.replace("{V}", &if core == t32 { t32.clone() } else { v.clone() });
            out.push(Case { family: "sql-structured".into(), syntax: sname.into(), text, cores: vec![core] });
        }
        // two-line forms (k8s env, compose, JSON on separate lines)
        out.push(Case { family: "sql-structured".into(), syntax: "k8s-env-two-line".into(), text: format!("env:\n  - name: DB_PASSWORD\n    value: {v}\n  - name: LOG_LEVEL\n    value: debug\n"), cores: vec![v.clone()] });
        out.push(Case { family: "sql-structured".into(), syntax: "json-two-line".into(), text: format!("{{\n  \"name\": \"X-Auth-Token\",\n  \"value\": \"{v}\"\n}}"), cores: vec![v.clone()] });
    }
    // aws secret with its own context
    for _ in 0..4 {
        let s = r.b64s(40);
        out.push(Case { family: "aws-secret".into(), syntax: "env".into(), text: format!("AWS_SECRET_ACCESS_KEY={s}"), cores: vec![s.clone()] });
        out.push(Case { family: "aws-secret".into(), syntax: "ini".into(), text: format!("aws_secret_access_key = {s}"), cores: vec![s.clone()] });
        out.push(Case { family: "aws-secret".into(), syntax: "json".into(), text: format!("{{\"SecretAccessKey\": \"{s}\"}}"), cores: vec![s.clone()] });
    }
    out
}

/// Transforms: the secret reaches the text encoded or disguised. Reported separately.
fn transform_cases(seed: u64) -> Vec<Case> {
    let mut r = Rng(seed ^ 0xabcdef);
    let mut out = vec![];
    for _ in 0..12 {
        let p = r.pw();
        let tok = format!("ghp_{}", r.b62(36));
        // base64 of a key=value line and of a bare provider token
        let kv = b64enc(format!("password={p}").as_bytes());
        out.push(Case { family: "transform".into(), syntax: "base64-keyvalue".into(), text: format!("blob: {kv}"), cores: vec![kv.trim_end_matches('=').to_string()] });
        let bt = b64enc(tok.as_bytes());
        out.push(Case { family: "transform".into(), syntax: "base64-token".into(), text: format!("data = \"{bt}\""), cores: vec![bt.trim_end_matches('=')[..24].to_string()] });
        let basic = b64enc(format!("svc:{p}").as_bytes());
        out.push(Case { family: "transform".into(), syntax: "base64-userpass".into(), text: format!("auth {basic} end"), cores: vec![basic.trim_end_matches('=').to_string()] });
        // percent-encoded key and token
        out.push(Case { family: "transform".into(), syntax: "urlenc-key".into(), text: format!("x?%70assword={p}&a=1"), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "urlenc-token".into(), text: format!("x?q=%67hp_{}", &tok[4..]), cores: vec![tok[4..].to_string()] });
        // unicode look-alikes and invisible characters in the key
        out.push(Case { family: "transform".into(), syntax: "cyrillic-key".into(), text: format!("p\u{430}ssword = \"{p}\""), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "fullwidth-key".into(), text: format!("\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}: {p}"), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "zero-width-key".into(), text: format!("pass\u{200b}word={p}"), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "u-escape-key".into(), text: format!("{{\"\\u0070assword\": \"{p}\"}}"), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "html-entity-key".into(), text: format!("&#112;assword: {p}"), cores: vec![p.clone()] });
        out.push(Case { family: "transform".into(), syntax: "cyrillic-token".into(), text: format!("\u{0261}hp_{}", &tok[4..]), cores: vec![tok[4..].to_string()] }); // not a real lookalike for g: documented limit
        // split provider token across a concatenation, no credential word
        let (a, b) = tok.split_at(20);
        out.push(Case { family: "transform".into(), syntax: "split-token-no-key".into(), text: format!("x = \"{a}\" + \"{b}\""), cores: vec![a[4..].to_string()] });
        out.push(Case { family: "transform".into(), syntax: "split-token-key".into(), text: format!("token = \"{a}\" + \"{b}\""), cores: vec![a[4..].to_string(), b.to_string()] });
    }
    out
}

/// Bare high-entropy tokens with no provider shape and no credential word.
fn entropy_cases(seed: u64) -> Vec<Case> {
    let mut r = Rng(seed ^ 0x1234);
    let mut out = vec![];
    for i in 0..60 {
        let (syn, t): (&str, String) = match i % 6 {
            0 => ("b62-32", r.b62(32)),
            1 => ("b62-24", r.b62(24)),
            2 => ("b64-44", format!("{}=", r.b64s(43))),
            3 => ("b64url-43", r.b64u(43)),
            4 => ("b62-48", r.b62(48)),
            _ => ("b62-22", r.b62(22)),
        };
        out.push(Case { family: "entropy".into(), syntax: syn.into(), text: format!("value is {t} end"), cores: vec![t] });
    }
    out
}

fn survives(out: &str, cores: &[String]) -> bool {
    cores.iter().any(|c| out.contains(c.as_str()))
}

fn run(cases: &[Case]) -> BTreeMap<String, (usize, usize, Vec<String>)> {
    let mut m: BTreeMap<String, (usize, usize, Vec<String>)> = BTreeMap::new();
    for c in cases {
        let o = redact_block(&c.text);
        let e = m.entry(c.family.clone()).or_default();
        e.0 += 1;
        if survives(&o, &c.cores) {
            e.1 += 1;
            if e.2.len() < 40 {
                e.2.push(format!("{} :: {}", c.syntax, c.text.chars().take(0).collect::<String>()));
            }
        }
    }
    m
}

fn report(title: &str, cases: &[Case]) -> (usize, usize, BTreeMap<String, (usize, usize)>) {
    let mut per: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut by_syntax: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let (mut n, mut miss) = (0, 0);
    for c in cases {
        let o = redact_block(&c.text);
        let leaked = survives(&o, &c.cores);
        let fam = c.family.split('/').next().unwrap().to_string();
        let e = per.entry(if c.family.starts_with("provider/") { c.family.clone() } else { fam }).or_default();
        e.0 += 1;
        let s = by_syntax.entry(format!("{}:{}", c.family.split('/').next().unwrap(), c.syntax)).or_default();
        s.0 += 1;
        n += 1;
        if leaked {
            if std::env::var_os("SHOW_MISS").is_some() {
                println!("   MISS {}:{} :: {} => {}", c.family, c.syntax, c.text.replace('\r', "\\r"), o.replace('\r', "\\r"));
            }
            e.1 += 1;
            s.1 += 1;
            miss += 1;
        }
    }
    println!("== {title}: {} cases, {} leaked, recall {:.2}%", n, miss, 100.0 * (n - miss) as f64 / n.max(1) as f64);
    for (f, (t, l)) in &per {
        println!("   {f:<28} {t:>4} cases  recall {:>6.1}%{}", 100.0 * (t - l) as f64 / *t as f64, if *l > 0 { format!("   ({l} leaked)") } else { String::new() });
    }
    for (f, (t, l)) in &by_syntax {
        if *l > 0 {
            println!("   miss by syntax {f:<34} {l}/{t}");
        }
    }
    (n, miss, per)
}

#[test]
fn recall_deterministic_families() {
    let cases = gen_cases(0x5eed);
    assert!(cases.len() >= 500, "{}", cases.len());
    let (n, miss, per) = report("deterministic families", &cases);
    for (f, (t, l)) in &per {
        let recall = (t - l) as f64 / *t as f64;
        assert!(recall >= 0.99, "family {f} recall {recall:.3} ({l}/{t} leaked)");
    }
    assert!(miss * 100 <= n, "overall recall");
}

#[test]
fn recall_other_seeds() {
    for seed in [1u64, 2, 3, 42, 999] {
        let cases = gen_cases(seed);
        let miss = cases.iter().filter(|c| survives(&redact_block(&c.text), &c.cores)).count();
        println!("seed {seed}: {} cases, {} leaked", cases.len(), miss);
        assert!(miss * 100 <= cases.len(), "seed {seed}: {miss} leaked of {}", cases.len());
    }
}

#[test]
fn recall_transforms_and_entropy() {
    let t = transform_cases(7);
    let (_, _, per) = report("transforms (encoded / disguised)", &t);
    let _ = per;
    let e = entropy_cases(7);
    let (n, miss, _) = report("bare high-entropy tokens", &e);
    assert!(miss * 100 <= n * 15, "entropy recall under 85%");
    let _ = run;
}

#[test]
fn idempotent_and_no_partial_values() {
    for c in gen_cases(11).iter().take(400) {
        let a = redact_block(&c.text);
        let b = redact_block(&a);
        assert_eq!(a, b, "not idempotent: {:?}", c.syntax);
        // no first/last characters of the value kept next to a mask
        for core in &c.cores {
            if core.len() >= 12 {
                assert!(!a.contains(&core[..8]) && !a.contains(&core[core.len() - 8..]), "partial value kept: {} -> {a}", c.syntax);
            }
        }
    }
}

// ----------------------------------------------------------------------------------------------------------
// false positives

fn benign_static() -> Vec<String> {
    let lines = r#"
if (token != null && !token.isEmpty()) {
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
permissions:
  id-token: write
password: str
SECRET_KEY: str
access_token: string;
password: str = Field(min_length=8, max_length=128)
new_password: data.new_password,
current_user.hashed_password = hashed_password
token=password_reset_token
tokenUrl=f"{settings.API_V1_STR}/login/access-token"
repoToken: "${{ secrets.GITHUB_TOKEN }}"
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?Variable not set}
SMTP_PASSWORD: ${SMTP_PASSWORD:-}
MYSQL_ALLOW_EMPTY_PASSWORD=true
export type NewPasswordData = {
const ChangePassword = () => {
Set `SECRET_KEY` and `FIRST_SUPERUSER_PASSWORD` before deploying.
Copy it to `.env` and edit the passwords.
requestPath: "/users/Gojo/friends/all-of-them/and/more",
<glyph unicode="+" d="M98 696v193h391v385h185v-385h391v-193h-391v-389h-185v3" />
import UserInformation from "@/components/UserSettings/UserInformation"
<includePath>${project.build.directory}/webjars/META-INF/resources/webjars/bootstrap/</includePath>
const password = getPassword();
String secret = config.getSecret();
this.token = token;
if (secretsEnabled) {
passwordPolicy.minLength = 12
if (passwordPolicy.minLength > 8) return false;
const t = getToken();
<input key={item.id} type="text" />
{items.map(item => <Row key={item.id} {...item} />)}
color: #ff00aa;
background: #1a2b3c url(img/bg.png);
border-color: #a1b2c3d4;
"version": "1.2.3",
version = "2.14.0-rc.1"
const id = "550e8400-e29b-41d4-a716-446655440000";
const userId = '123e4567-e89b-12d3-a456-426614174000';
git checkout 3f786850e387550fdab836ed7e6dc881de23001b
commit 9fceb02d0ae598e95dc970b74767f19372d61af8
password_hash varchar(255) NOT NULL,
password_changed_at timestamp,
token_expires_at timestamp NOT NULL DEFAULT now(),
ALTER TABLE users ADD COLUMN password_reset_token text;
CREATE INDEX idx_users_token ON users (token);
tokenizer = AutoTokenizer.from_pretrained(name)
max_tokens = 4096
const maxTokens = 2048;
public static final String TOKEN_HEADER = "Authorization";
public static final String PASSWORD_FIELD = "password";
@Column(name = "password_hash", nullable = false)
private String passwordHash;
validatePassword(password, user.passwordHash)
if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
async function refreshToken() { return await api.post('/auth/refresh'); }
headers: { Authorization: `Bearer ${token}` },
const secretKey = process.env.SECRET_KEY;
SECRET_KEY = os.environ["SECRET_KEY"]
api_key = settings.API_KEY
password = request.form['password']
password: ${DB_PASSWORD}
token: {{ .Values.token }}
password: <your-password-here>
export API_URL=https://api.example.com/v1
import { useAuth } from '@/hooks/useAuth';
const url = `${API_BASE}/users/${userId}/sessions`;
class UserPasswordResetTokenService {
def get_access_token(self, code):
the quick brown fox jumps over the lazy dog
Reset your password by clicking the link below.
Forgot password? Enter your email address and we will send you a link.
password must be at least 8 characters
<Label htmlFor="password">Password</Label>
placeholder="Enter your password"
t('auth.password.required')
"auth.token.expired": "Your session has expired"
user@example.com
Contact: support@example.org
git@github.com:org/repo.git
image@2x.png
Co-Authored-By: Claude <noreply@anthropic.com>
Server listening on http://localhost:8080
const MAX = 1700000000000;
timestamp: 1700000000
const pageSize = 25;
private static final long serialVersionUID = 1234567890123456789L;
SELECT id, name FROM users WHERE id = 42;
at com.example.service.UserService.findByEmail(UserService.java:142)
ERROR 2024-05-01T10:15:30.123Z request failed: timeout after 30000ms
src/main/java/io/example/service/ReportCardCalculationService.java
packages/shared/components/forms/StudentEnrollmentWizardStep2.tsx
node_modules/@types/react/index.d.ts
const veryLongFunctionNameForProcessingStudentGrades2024 = () => {};
function calculateQuarterlyAverageForAllSubjects(studentId) {}
export const SECTION_ENROLLMENT_STATUS_PENDING_APPROVAL = 'PENDING';
test_generates_report_card_for_student_with_missing_grades_2024
a1b2c3d4-e5f6-7890-abcd-ef1234567890
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"integrity": "sha512-Q2lj1l2P9h0X4a5s6d7f8g9h0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q==",
"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
checksum = "ba7a8c0f1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e"
h1:abcdEFGH1234ijklMNOP5678qrstUVWX90ab=
<svg width="24" height="24" viewBox="0 0 24 24" fill="none">
<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor"/>
Math.floor(Math.random() * 1000000)
const re = /^[A-Za-z0-9._%+-]+$/;
logger.info("Loaded {} students for section {}", count, sectionId);
Phone number must be 11 digits (09XX XXX XXXX)
Call (02) 8123 for help
Build 2024.10.23.1 passed
const port = 5432;
1.2.3.4
10.0.0.1
latency=12.5ms p99=45.2ms
total: 1,234,567.89
ISBN 978-3-16-148410-0
coverage 87.3% (1234/1412)
rev-parse HEAD -> 3f786850
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Cache-Control: no-cache
X-Request-Id: req-123
Set-Cookie: ; Path=/
const keyboardShortcut = 'Ctrl+K';
primaryKey: true,
foreignKey: 'user_id',
sortKey = "name"
cache_key = f"report:{school_id}:{quarter}"
redis.get(`token:${userId}`)
KEYCLOAK_URL=https://auth.example.com
Authorization header is required
"The token has expired."
passwordless login is enabled
const secretary = new Person('Ana');
const author = users.find(u => u.id === authorId);
authorization.can('read', Report)
tokenize(input)
my_tokenizer.encode(text)
pass: true
passed = 12
bypass: true
passport: required
compass = Compass.north
"""#;
    lines.lines().map(|s| s.to_string()).filter(|s| !s.is_empty()).collect()
}

fn benign_generated() -> Vec<String> {
    let mut r = Rng(77);
    let mut v = vec![];
    for _ in 0..200 {
        let integ = format!("\"integrity\": \"sha512-{}==\",", r.b64s(86));
        v.push(integ);
        v.push(format!("    resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#{}\"", r.hex(40)));
        v.push(format!("checksum = \"{}\"", r.hex(64)));
        v.push(format!("const id = '{}-{}-{}-{}-{}';", r.hex(8), r.hex(4), r.hex(4), r.hex(4), r.hex(12)));
        v.push(format!("commit {}", r.hex(40)));
        v.push(format!("background: #{};", r.hex(6)));
        v.push(format!("version \"{}.{}.{}\"", r.next() % 30, r.next() % 30, r.next() % 30));
        v.push(format!("<img src=\"data:image/png;base64,{}\" />", r.b64s(200)));
        v.push(format!("@font-face {{ src: url(data:font/woff2;base64,{}) }}", r.b64s(160)));
        v.push(format!("h1:{}=", r.b64s(43)));
        let camel: String = (0..4).map(|_| ["Process", "Student", "Grade", "Report", "Enrollment", "Section", "Quarter", "Handler"][(r.next() % 8) as usize]).collect();
        v.push(format!("const {camel}2024 = new {camel}();"));
        v.push(format!("test_{}_should_{}_for_{}_2024", "calculates_grade", "return_zero", "empty_section"));
    }
    v
}

#[test]
fn false_positive_rate() {
    let mut lines = benign_static();
    let nstatic = lines.len();
    lines.extend(benign_generated());
    let mut changed: Vec<String> = vec![];
    let mut changed_static = 0;
    for (i, l) in lines.iter().enumerate() {
        let o = redact_line(l);
        if o != *l {
            if i < nstatic {
                changed_static += 1;
            }
            changed.push(format!("{l}  =>  {o}"));
        }
    }
    let rate = changed.len() as f64 / lines.len() as f64;
    println!("== false positives: {} of {} benign lines changed ({:.2}%); static realistic set {} of {}", changed.len(), lines.len(), rate * 100.0, changed_static, nstatic);
    for c in changed.iter().take(40) {
        println!("   FP: {}", c.chars().take(200).collect::<String>());
    }
    assert!(changed_static * 100 <= nstatic * 3, "static FP rate");
    assert!(rate <= 0.01, "FP rate {rate}");
}

// ----------------------------------------------------------------------------------------------------------
// PII

fn luhn_complete(prefix: &str, len: usize, r: &mut Rng) -> String {
    let mut d: Vec<u32> = prefix.bytes().map(|b| (b - b'0') as u32).collect();
    while d.len() < len - 1 {
        d.push((r.next() % 10) as u32);
    }
    let mut sum = 0;
    for (i, x) in d.iter().rev().enumerate() {
        let mut x = *x;
        if i % 2 == 0 {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
    }
    d.push((10 - sum % 10) % 10);
    d.iter().map(|x| char::from(b'0' + *x as u8)).collect()
}

#[test]
fn pii() {
    let mut r = Rng(5);
    let mut miss = vec![];
    let mut n = 0;
    let mut check = |what: &str, text: String, core: &str| {
        n += 1;
        if redact_line(&text).contains(core) {
            miss.push(format!("{what}: {text}"));
        }
    };
    for i in 0..20 {
        let u = r.pick("abcdefghijklmnopqrstuvwxyz", 6);
        check("email", format!("contact {u}.x{i}@company-{i}.io today"), &format!("{u}.x{i}"));
        check("email", format!("\"email\": \"{u}{i}+tag@mail.school-{i}.edu.ph\""), &format!("{u}{i}+tag"));
        let (a, m, b) = (r.pick("0123456789", 2), r.pick("0123456789", 3), r.pick("0123456789", 4));
        check("phone-ph", format!("call 09{a} {m} {b} now"), &b);
        check("phone-ph", format!("mobile: +63 9{a} {m} {b}"), &b);
        check("phone-ph", format!("tel (02) 8{m}-{b}"), &b);
        check("phone-ph", format!("\"phone\": \"09{a}{m}{b}\""), &b);
        let c = luhn_complete("4", 16, &mut r);
        check("card", format!("card {c} exp 12/30"), &c);
        check("card", format!("card {}-{}-{}-{}", &c[..4], &c[4..8], &c[8..12], &c[12..]), &c[4..8]);
        let c = luhn_complete("37", 15, &mut r);
        check("card-amex", format!("amex {c}"), &c);
        let c = luhn_complete("55", 16, &mut r);
        check("card-mc", format!("\"pan\": \"{c}\""), &c);
        let id = r.pick("0123456789", 12);
        check("national-id", format!("sss: {}-{}-{}", &id[..2], &id[2..9], &id[9..]), &id[2..9]);
        check("national-id", format!("{{\"national_id\": \"{id}\"}}"), &id);
        check("national-id", format!("applicant SSN {}-{}-{} on file", &id[..3], &id[3..5], &id[5..9]), &id[5..9]);
        check("national-id", format!("social security number is {} {} {}", &id[..3], &id[3..5], &id[5..9]), &id[3..5]);
    }
    println!("== PII: {} cases, {} leaked", n, miss.len());
    for m in miss.iter().take(10) {
        println!("   leaked {m}");
    }
    assert!(miss.len() * 100 <= n, "PII recall: {miss:?}");
    // not PII
    for keep in ["order 1234567890123", "id=4111111111111112", "build 20241023", "0.1.2", "ts 1700000000.123456", "a@b.c", "see v2@2x.png"] {
        assert_eq!(redact_line(keep), keep, "{keep}");
    }
}

// ----------------------------------------------------------------------------------------------------------
// safety

#[test]
fn adversarial_inputs_are_fast_and_safe() {
    let t0 = std::time::Instant::now();
    let big = "password=x ".repeat(100_000); // 1.1 MB, 100k matches
    let o = redact_line(&big);
    assert!(!o.is_empty());
    let d1 = t0.elapsed();
    let cases: Vec<(&str, String)> = vec![
        ("1MB single token", "A".repeat(1 << 20)),
        ("1MB b64", "Ab3+/".repeat(210_000)),
        ("1MB quotes", "\"'`".repeat(350_000)),
        ("1MB equals", "key=".repeat(260_000)),
        ("1MB colons", ":::::::".repeat(150_000)),
        ("1MB slashes", "a/".repeat(500_000)),
        ("1MB percent", "%41".repeat(350_000)),
        ("1MB at", "a@".repeat(500_000)),
        ("1MB begin", "-----BEGIN PRIVATE KEY----- ".repeat(40_000)),
        ("1MB dollar-brace", "${a_password:-x}".repeat(70_000)),
        ("1MB concat", "token = \"a\" + ".repeat(80_000)),
        ("1MB urls", "https://u:p@h/ ".repeat(70_000)),
        ("1MB digits", "4111 1111 1111 1111 ".repeat(55_000)),
        ("1MB unicode", "\u{430}\u{200b}pass".repeat(150_000)),
        ("1MB newlines", "x\n".repeat(500_000)),
        ("1MB xml", "<password>".repeat(100_000)),
        ("1MB json-esc", "\\\"password\\\": \\\"".repeat(60_000)),
        ("invalid-ish", "\u{0}\u{1}\u{ffff}\u{10ffff}".repeat(100_000)),
    ];
    let mut worst = (std::time::Duration::ZERO, "");
    for (name, input) in &cases {
        let t = std::time::Instant::now();
        let o = redact_block(input);
        let d = t.elapsed();
        assert!(!o.is_empty() || input.is_empty(), "{name}");
        println!("   adversarial {name:<20} {} bytes -> {:?}", input.len(), d);
        if d > worst.0 {
            worst = (d, name);
        }
    }
    let limit = if cfg!(debug_assertions) { 30.0 } else { 3.0 };
    println!("== adversarial: 1.1MB secret-dense line {:?}, worst case {:?} ({})", d1, worst.0, worst.1);
    assert!(d1.as_secs_f64() < limit * 2.0, "dense line {d1:?}");
    assert!(worst.0.as_secs_f64() < limit * 3.0, "{} took {:?}", worst.1, worst.0);
}

#[test]
fn per_line_latency() {
    let mut lines = benign_static();
    lines.extend(benign_generated().into_iter().take(400));
    let _ = redact_line("warm up password: x");
    // cold: the first sight of each line (lazy-DFA states are built as new byte patterns appear)
    let mut cold: Vec<f64> = lines.iter().map(|l| {
        let t = std::time::Instant::now();
        std::hint::black_box(redact_line(l));
        t.elapsed().as_secs_f64() * 1e6
    }).collect();
    cold.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("== cold first pass over {} lines: p50 {:.1} us  p95 {:.1} us  max {:.1} us", cold.len(), cold[cold.len() / 2], cold[cold.len() * 95 / 100], cold[cold.len() - 1]);
    let mut times: Vec<f64> = vec![];
    let mut slow: Vec<(f64, String)> = vec![];
    for _ in 0..5 {
        for l in &lines {
            let t = std::time::Instant::now();
            std::hint::black_box(redact_line(l));
            let us = t.elapsed().as_secs_f64() * 1e6;
            times.push(us);
            if us > 40.0 {
                slow.push((us, l.chars().take(90).collect()));
            }
        }
    }
    slow.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    if std::env::var_os("SHOW_SLOW").is_some() {
        for (us, l) in slow.iter().take(25) {
            println!("   slow {us:.0} us: {l}");
        }
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| times[((times.len() as f64 * q) as usize).min(times.len() - 1)];
    println!("== per-line latency over {} typical lines: p50 {:.1} us  p95 {:.1} us  p99 {:.1} us  max {:.1} us", lines.len(), p(0.5), p(0.95), p(0.99), times[times.len() - 1]);
    let limit = if cfg!(debug_assertions) { 1500.0 } else { 50.0 };
    assert!(p(0.95) < limit, "p95 {} us", p(0.95));
}
