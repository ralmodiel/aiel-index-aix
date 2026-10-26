//! Redaction fixes (FIX-5P): prose and flags stay readable, call arguments are masked. Secrets built at run time.

use aix_extract::redact::{redact_block, redact_line};

fn pw() -> String {
    ["Zq8x", "N2mK", "7vRt4Lp"].concat()
}

#[test]
fn prose_flags_paths_and_jsx_stay_readable() {
    for keep in [
        "see `--fix` for the secret token option and `~/path/secret` here",
        "Run `aix --fix` when a token is stale; the secret store is `~/.config/x`",
        "the `key`, `secret`, `credential` or `password` columns and `apiKey`/`private_key`",
        "<label>Password: <input type=\"password\" /></label>",
        "const tokenUrl = `${base}/oauth/token`;",
        "tokenUrl = f\"{base}/oauth/token\"",
        "redacted (`~` for home, secret-looking components as `***`)",
        "getToken(\"access_token\")",
        "login(user, password)",
    ] {
        assert_eq!(redact_line(keep), keep);
    }
}

#[test]
fn credential_call_arguments_are_masked() {
    let p = pw();
    for (src, keep) in [
        (format!("setPassword(\"{p}\");"), "setPassword("),
        (format!("client.setPassword('{p}')"), "client.setPassword("),
        (format!("r = requests.get(url, auth=(\"alice\",\"{p}\"))"), "auth=(\"alice\","),
        (format!("requests.post(url, auth=(\"alice\", \"{p}\"), timeout=5)"), "timeout=5"),
        (format!("login(user, \"{p}\")"), "login(user, "),
        (format!("session.login(\"alice\", \"correct-horse-{p}\")"), "session.login(\"alice\", "),
        (format!("update_token(\"{p}{p}\")"), "update_token("),
    ] {
        let o = redact_line(&src);
        assert!(!o.contains(&p[..6]) && o.contains(keep) && o.contains("***"), "{src} -> {o}");
    }
    let o = redact_block(&format!("a\nsetPassword(\"{p}\")\nb"));
    assert_eq!(o.lines().count(), 3);
}
