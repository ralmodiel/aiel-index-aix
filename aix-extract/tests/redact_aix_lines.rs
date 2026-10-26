//! aix's own output lines about credential-named symbols stay readable (continuation footers, counts), and an ordinary
//! string-method call on a credential variable is code, not a value; real values next to the same words are still
//! masked.

use aix_extract::redact::redact_line;

#[test]
fn footers_and_counts_of_credential_named_symbols_are_kept() {
    for l in [
        "next `aix callers get_token --page 2`",
        "(page 1 of 10 (rows 1-3 of 30): next `aix callers get_token --head 3 --page 2`)",
        "(… 3 more: next `aix grep password_hash --head 20 --page 2`)",
        "== generateToken: 3 commits, 0 fix-like",
        "get_token: 12 callers",
        "== callers of hash_password: none (index has no symbol 'hash_password')",
    ] {
        assert_eq!(redact_line(l), l, "{l}");
    }
}

#[test]
fn a_string_method_argument_is_not_a_value() {
    for l in ["pw = pw.replace(\"x1y2z3\", \"\")", "token = token.split(\"abc123\")[0]", "secret = raw.strip_prefix(\"v1:abcdef\")",
        "  {m: mGET, r: \"/users/2/settings/password\", h: hStub15},",
        "static SCRIPT_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r\"(?:^|\\s)(\\w+\\.sh)\").unwrap());",
    ] {
        assert_eq!(redact_line(l), l, "{l}");
    }
}

#[test]
fn values_next_to_the_same_words_are_still_masked() {
    for l in [
        "password: 1234 hunter",
        "secret: 99 bottles",
        "the token is `ghp_abcdefghijklmnopqrstuvwxyz0123456789`",
        "pw = \"x1y2z3\" + suffix",
        "token = 123456",
        "url = \"https://example.com/api/token/abc123def456\"",
    ] {
        assert!(redact_line(l).contains("***"), "{l} -> {}", redact_line(l));
    }
}
