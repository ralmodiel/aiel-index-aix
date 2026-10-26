//! QA 4-B redaction fixes: an empty value masks nothing (even across a newline), a placeholder, type, reference or
//! pin is not a credential, and the new structures (SQL accounts, name/value pairs, argv lists...) are masked.
//! Secrets are built at run time.

use aix_extract::redact::{redact_block, redact_with_hits};

fn pw(seed: u64) -> String {
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    (0..12)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"[(x.wrapping_mul(0x2545F4914F6CDD1D) % 55) as usize] as char
        })
        .collect::<String>()
        + "7"
}

#[test]
fn empty_value_masks_nothing_and_never_the_next_line() {
    let t = "A_PASSWORD=\nB_NAME=keepme\nMYSQL_ALLOW_EMPTY_PASSWORD=true\nC_TOKEN=\n";
    assert_eq!(redact_block(t), t);
    let t = "services:\n  db:\n    environment:\n      - MYSQL_ROOT_PASSWORD=\n      - MYSQL_ALLOW_EMPTY_PASSWORD=true\n";
    assert_eq!(redact_block(t), t);
    // a YAML key with its value on the next line still masks that value
    let r = redact_block(&format!("db:\n  password:\n    {}\n  user: bob\n", pw(1)));
    assert!(!r.contains(&pw(1)) && r.contains("user: bob"), "{r}");
    assert_eq!(redact_block("password: \"\"\ntoken: ''\n"), "password: \"\"\ntoken: ''\n");
}

#[test]
fn not_credentials() {
    for keep in [
        "- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
        "id-token: write",
        "password: str",
        "SECRET_KEY: str",
        "access_token: string;",
        "ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8",
        "password: str = Field(min_length=8, max_length=128)",
        "current_user.hashed_password = hashed_password",
        "token=password_reset_token",
        "\"current_password\": new_password,",
        "tokenUrl=f\"{settings.API_V1_STR}/login/access-token\"",
        "repoToken: \"${{ secrets.GITHUB_TOKEN }}\"",
        "POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?Variable not set}",
        "SMTP_PASSWORD: ${SMTP_PASSWORD:-}",
        "export type NewPasswordData = {",
        "const ChangePassword = () => {",
        "const token = await getAuthToken(auth, options.auth);",
        "Set `SECRET_KEY` and `FIRST_SUPERUSER_PASSWORD` before deploying.",
        "requestPath: \"/users/Gojo/friends/all-of-them/and/more\",",
        "import UserInformation from \"@/components/UserSettings/UserInformation\"",
        "DATABASE_URL=postgresql://postgres:${POSTGRES_PASSWORD}@localhost:5432/app",
    ] {
        assert_eq!(redact_block(keep), keep, "{keep}");
    }
    // but a value that merely looks similar is still masked
    for (i, v) in [("password: Hunter2024x", "Hunter2024x"), ("SECRET_KEY=abc123xyz789", "abc123xyz789")] {
        assert!(!redact_block(i).contains(v), "{i}");
    }
}

#[test]
fn new_structures_are_masked() {
    let v = pw(7);
    let cases = [
        format!("CREATE USER 'app'@'%' IDENTIFIED BY '{v}';"),
        format!("ALTER ROLE svc WITH PASSWORD '{v}'"),
        format!("INSERT INTO users (id, name, password_hash) VALUES (1, 'bob', '{v}');"),
        format!("INSERT INTO t (name, api_token) VALUES ('a', '{v}'), ('b', '{v}');"),
        format!("{{\"name\":\"X-Api-Key\",\"value\":\"{v}\"}}"),
        format!("{{\"name\":\"sessionid\",\"value\":\"{v}\"}}"),
        format!("- name: DB_PASSWORD\n  value: {v}\n"),
        format!("echo \"::add-mask::{v}\""),
        format!("[\"--api-key\", \"{v}\"]"),
        format!("System.setProperty(\"db.password\", \"{v}\");"),
        format!("| password | {v} |"),
        format!("wifi psk={v}"),
        format!("p a s s w o r d = {v}"),
    ];
    for c in cases {
        let r = redact_block(&c);
        assert!(!r.contains(&v), "{c} -> {r}");
    }
    // the next env entry after a masked name/value pair is untouched
    let r = redact_block(&format!("env:\n  - name: DB_PASSWORD\n    value: {v}\n  - name: LOG_LEVEL\n    value: debug\n"));
    assert!(r.contains("value: debug") && !r.contains(&v), "{r}");
}

#[test]
fn rules_that_fired_are_named() {
    let (_, h) = redact_with_hits("password: Hunter2024x\nuses: x\n");
    assert!(h.iter().any(|(n, _)| n == "kv"), "{h:?}");
    let tok: String = ["Zq81xKvPlm", "Qw3rTy9uIoPa5sDf7gHj"].concat();
    let (o, h) = redact_with_hits(&format!("blob {tok}"));
    assert!(o.contains("***") || o.contains("[redacted]"), "{o}");
    assert!(!h.is_empty(), "every rule that changed text is reported: {o}");
}
