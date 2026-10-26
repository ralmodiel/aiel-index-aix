//! Redaction at the edges: `aix redact-test`, repo config (extra rules, hashed allow-list), `aix sql` cells,
//! error messages that echo an argument. All secrets are built at run time from parts.

use std::io::Write;
use std::process::{Command, Stdio};

fn aix(repo: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (String, String, bool) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo).env("AIX_MASK_KDF_ITERS", "2000").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(ch.stdin.take());
    }
    let o = ch.wait_with_output().unwrap();
    (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned(), o.status.success())
}

fn fake_token() -> String {
    ["gh", "p_", "Qw3rTy9uIoPa5sDf7gHj1kLz4xCv6bNm8Aq2"].concat()
}

fn repo() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    for a in [vec!["init", "-q", "-b", "main"]] {
        assert!(Command::new("git").arg("-C").arg(d.path()).args(a).status().unwrap().success());
    }
    d
}

#[test]
fn redact_test_masks_and_reports() {
    let d = repo();
    let t = fake_token();
    let input = format!("token in a log: {t}\nplain line\nDB=postgres://app:{}@db.internal/x\n", ["Zq81", "xKvP"].concat());
    let (out, err, ok) = aix(d.path(), &["redact-test"], Some(&input));
    assert!(ok, "{err}");
    assert!(out.contains("***github-token***") && out.contains("plain line") && out.contains("***db-password***"), "{out}");
    assert!(!out.contains(&t[4..]) && !out.contains("Zq81"), "{out}");
    assert!(err.contains("github-token x1") && err.contains("db-password x1"), "{err}");
}

#[test]
fn config_adds_rules_and_hashed_allow_list_but_cannot_disable_builtins() {
    let d = repo();
    let fp = ["changeme", "-example-", "Zx81Qw"].concat();
    let (hash, _, _) = aix(d.path(), &["redact-test", "--hash", &fp], None);
    let hash = hash.trim().to_string();
    assert!(hash.starts_with("sha1:") && !hash.contains(&fp));
    std::fs::create_dir_all(d.path().join(".aix")).unwrap();
    let cfg = format!(
        "[redact]\nallow = [\"{hash}\", \"plain-text-entry\"]\nip = true\n[[redact.rules]]\nname = \"acme-id\"\npattern = \"ACME-[0-9]{{8}}\"\n\n[[redact.rules]]\nname = \"broken\"\npattern = \"(\"\n"
    );
    std::fs::write(d.path().join(".aix/config.toml"), cfg).unwrap();
    let t = fake_token();
    let input = format!("key={fp}\nid ACME-12345678 at 10.20.30.40\n{t}\n");
    let (out, err, _) = aix(d.path(), &["redact-test"], Some(&input));
    assert!(out.contains(&fp), "allow-listed false positive stays: {out}");
    assert!(out.contains("***acme-id***") && out.contains("***ip***"), "{out}");
    assert!(out.contains("***github-token***") && !out.contains(&t[4..]), "built-ins stay on: {out}");
    assert!(err.contains("must be hashes") && err.contains("'broken' ignored"), "{err}");
    // the allow-list is not the plain text
    assert!(!std::fs::read_to_string(d.path().join(".aix/config.toml")).unwrap().contains(&fp));
}

#[test]
fn sql_cells_and_errors_are_redacted() {
    let d = repo();
    let t = fake_token();
    let (out, _, ok) = aix(d.path(), &["sql", &format!("SELECT '{t}' AS a, 'postgres://u:{}@h/db' AS b", ["Hunt", "er99xZ"].concat())], None);
    assert!(ok);
    assert!(!out.contains(&t[4..]) && !out.contains("Hunter99xZ") && out.contains("***github-token***"), "{out}");
    // a bad flag echoes its value: clap's message is redacted
    let (_, err, ok) = aix(d.path(), &[&format!("--nope={t}")], None);
    assert!(!ok && !err.contains(&t[4..]), "{err}");
    // an unknown command echoes its name
    let (_, err, ok) = aix(d.path(), &[&t], None);
    assert!(!ok && !err.contains(&t[4..]), "{err}");
}

fn committed_repo(files: &[(&str, &str)]) -> tempfile::TempDir {
    let d = repo();
    for (p, t) in files {
        let f = d.path().join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    let g = |a: &[&str]| assert!(Command::new("git").arg("-C").arg(d.path()).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(a).status().unwrap().success());
    g(&["add", "-A"]);
    g(&["commit", "-q", "-m", "init"]);
    d
}

#[test]
fn user_masks_apply_everywhere_retroactively_and_literals_are_hashed() {
    let d = committed_repo(&[("README.md", "# Notes\n\nOur customer Initech Corp asked for ticket ZX-4412 to be fixed on host billing01.corp.invalid.\n"), ("src/a.ts", "export const x = 1; // call Initech Corp\n")]);
    let p = d.path();
    let (_, e, ok) = aix(p, &["update"], None);
    assert!(ok, "{e}");
    let (before, _, _) = aix(p, &["sql", "SELECT text FROM entries WHERE text LIKE '%Initech%'"], None);
    assert!(before.contains("Initech") || before.lines().count() < 3, "{before}"); // stored unmasked at first (when indexed)
    // regex mask: retroactive over stored rows
    let (o, e, ok) = aix(p, &["mask", "add", "Initech( Corp)?", "--hint", "customer"], None);
    assert!(ok, "{o} {e}");
    assert!(o.contains("re-masked"), "{o}");
    let (after, _, _) = aix(p, &["sql", "SELECT count(*) FROM entries WHERE text LIKE '%Initech%'"], None);
    assert!(after.lines().any(|l| l.trim() == "0"), "{after}");
    // literal mask: only a salted hash is stored
    let (o, e, ok) = aix(p, &["mask", "add", "--literal", "billing01.corp.invalid", "--hint", "host"], None);
    assert!(ok, "{o} {e}");
    let toml = std::fs::read_to_string(p.join(".aix/masks.toml")).unwrap();
    assert!(!toml.contains("billing01") && toml.contains("salt") && toml.contains("hash"), "{toml}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(p.join(".aix/masks.toml")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let (out, _, _) = aix(p, &["mask", "test", "see Initech Corp and ticket ZX-4412 on billing01.corp.invalid"], None);
    assert!(out.contains("***customer***") && out.contains("***host***") && !out.contains("billing01"), "{out}");
    // output path: sql cells and `grep` over the stored/ingested text
    let (out, _, _) = aix(p, &["sql", "SELECT 'x Initech Corp y billing01.corp.invalid z'"], None);
    assert!(out.contains("***customer***") && out.contains("***host***"), "{out}");
    let (j, _, _) = aix(p, &["--json", "sql", "SELECT 'Initech Corp'"], None);
    assert!(!j.contains("Initech") && j.contains("***customer***"), "{j}");
    // new ingest is masked too
    std::fs::write(p.join("NOTES.md"), "# More\n\nInitech Corp again, host billing01.corp.invalid\n").unwrap();
    let (_, e, ok) = aix(p, &["update", "--full"], None);
    assert!(ok, "{e}");
    let (c, _, _) = aix(p, &["sql", "SELECT count(*) FROM entries WHERE text LIKE '%Initech%' OR text LIKE '%billing01%'"], None);
    assert!(c.lines().any(|l| l.trim() == "0"), "{c}");
    // built-ins cannot be weakened by masks
    let t = fake_token();
    let (out, _, _) = aix(p, &["mask", "test", &format!("{t} Initech")], None);
    assert!(out.contains("***github-token***") && !out.contains(&t[4..]), "{out}");
    // list / rm
    let (l, _, _) = aix(p, &["mask", "list"], None);
    assert!(l.contains("customer") && l.contains("literal") && !l.contains("billing01"), "{l}");
    let name = l.lines().find(|x| x.contains("literal")).unwrap().split(' ').next().unwrap().to_string();
    let (o, _, ok) = aix(p, &["mask", "rm", &name], None);
    assert!(ok && o.contains("stay masked") && o.contains("aix update --full") && o.contains("--purge"), "{o}");
    let (o, _, ok) = aix(p, &["mask", "rm", "customer", "--purge"], None);
    assert!(!ok || o.contains("re-ingesting") || o.contains("no mask named"), "{o}");
}

#[test]
fn user_mask_validation_refusals() {
    let d = repo();
    for bad in [".*", ".+", "\\w+", "a*", "(", "", "x{1000}{1000}", "(a|b|c|d|e|f)*"] {
        let (o, e, ok) = aix(d.path(), &["mask", "add", bad], None);
        assert!(!ok, "{bad:?} should be refused: {o}{e}");
    }
    let (_, e, ok) = aix(d.path(), &["mask", "add", "--literal", "ab"], None);
    assert!(!ok && e.contains("6 characters"), "{e}");
    let (_, _, ok) = aix(d.path(), &["mask", "add", "Zebra-[0-9]{4}", "--name", "zebra"], None);
    assert!(ok);
    let (_, e, ok) = aix(d.path(), &["mask", "add", "Giraffe-[0-9]{4}", "--name", "zebra"], None);
    assert!(!ok && e.contains("exists"), "{e}");
    // a mask may not wear a built-in rule's name
    let (_, e, ok) = aix(d.path(), &["mask", "add", "Okapi-[0-9]{4}", "--hint", "aws-key"], None);
    assert!(!ok && e.contains("built-in"), "{e}");
    // short and public-shape literals are refused
    let (_, e, ok) = aix(d.path(), &["mask", "add", "--literal", "abc12"], None);
    assert!(!ok && e.contains("6 characters"), "{e}");
    let (_, e, ok) = aix(d.path(), &["mask", "add", "--literal", &fake_token()], None);
    assert!(!ok && e.contains("public credential shape"), "{e}");
}

#[test]
fn new_output_shapes_are_redacted() {
    let t = fake_token();
    let d = committed_repo(&[("notes.txt", &format!("deploy with {t} now\n"))]);
    let p = d.path();
    aix(p, &["update"], None);
    for args in [
        vec!["grep", "ghp_[A-Za-z0-9]+", "--group-by", "match"],
        vec!["--json", "grep", "ghp_[A-Za-z0-9]+", "--group-by", "match"],
        vec!["--jsonl", "grep", "ghp_[A-Za-z0-9]+"],
        vec!["grep", "ghp_[A-Za-z0-9]+", "--plan"],
        vec!["grep", "ghp_[A-Za-z0-9]+", "--count"],
        vec!["grep", "ghp_[A-Za-z0-9]+", "--exists"],
    ] {
        let (o, e, _) = aix(p, &args, None);
        assert!(!o.contains(&t[4..]) && !e.contains(&t[4..]), "{args:?}: {o}");
    }
}

#[test]
fn redact_test_names_every_rule_and_offers_the_allow_list_hash() {
    let d = repo();
    let input = "fine line\npassword = Hunter2024x\nSECRET_KEY: Zq81xKvPlmAb9\n";
    let (out, err, ok) = aix(d.path(), &["redact-test"], Some(input));
    assert!(ok && out.contains("password = ***"), "{out} {err}");
    assert!(err.contains("2 line(s) changed") && err.contains("line 2: kv") && err.contains("line 3:"), "{err}");
    assert!(err.contains("keep readable: sha1:") && !err.contains("Hunter2024x"), "{err}");
    // the hash it offers really keeps the text readable
    let h = err.lines().find(|l| l.contains("sha1:")).unwrap().split("sha1:").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    assert_eq!(h.len(), 40, "{h}");
}

#[test]
fn a_secret_in_a_file_path_is_masked_in_json_fields_too() {
    let t = fake_token();
    let name = format!("deploy-{t}.txt");
    let d = committed_repo(&[(name.as_str(), "needle line here\n"), ("ok.txt", "needle too\n")]);
    let p = d.path();
    aix(p, &["update", "--full"], None);
    for args in [vec!["--json", "grep", "needle"], vec!["--jsonl", "grep", "needle"], vec!["grep", "needle", "--json"], vec!["--json", "grep", "needle", "--page", "1"]] {
        let (o, e, _) = aix(p, &args, None);
        assert!(!o.contains(&t[4..]) && !e.contains(&t[4..]), "{args:?}: {o}");
    }
    let (o, _, _) = aix(p, &["--json", "grep", "needle"], None);
    assert!(o.contains("ok.txt"), "{o}");
}
