//! Literal masks: every occurrence at any offset, adjacent repeats, inside words, case and percent-encoded variants
//! with --icase; slow salted fingerprints; short, public-shape and built-in-named masks refused; hints never carry secrets.

use aix_extract::{masks, redact};

#[test]
fn literal_masks_match_everywhere_and_refuse_weak_ones() {
    let d = std::env::temp_dir().join(format!("aixlit{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let repo = d.as_path();
    std::env::set_var("HOME", repo);
    std::env::set_var("AIX_MASK_KDF_ITERS", "1000");
    let secret = ["Zeta", "-Quartz-", "4417"].concat();
    let other = ["north", "wind", "-gate"].concat();
    let def = masks::add_ex(masks::Scope::Repo, repo, &secret, Some("cust"), Some("customer"), true, false).unwrap();
    assert!(!def.hash.contains(&secret) && def.kdf == "pbkdf2-sha256" && def.iters == 1000 && def.hash.len() == 64);
    masks::add_ex(masks::Scope::Repo, repo, &other, Some("gate"), Some("gate"), true, true).unwrap();
    let file = std::fs::read_to_string(repo.join(".aix/masks.toml")).unwrap();
    assert!(!file.contains(&secret) && !file.contains(&other), "{file}");
    masks::install(repo);
    // case-sensitive: any offset, adjacent repeats, inside larger words
    let t = format!("a {secret} b|{secret}{secret}|x{secret}y|pre{secret}");
    assert_eq!(redact::redact_line(&t), "a ***customer*** b|***customer******customer***|x***customer***y|pre***customer***");
    // other case does not match a case-sensitive literal
    assert_eq!(redact::redact_line(&secret.to_lowercase()), secret.to_lowercase());
    // icase: any case, percent-encoded, inside words
    let up = other.to_uppercase();
    let enc = other.replace('-', "%2D");
    let t = format!("{other} {up} q={enc}&z w{up}w");
    assert_eq!(redact::redact_line(&t), "***gate*** ***gate*** q=***gate***&z w***gate***w");
    // refusals
    let short = masks::add(masks::Scope::Repo, repo, "abc12", None, None, true);
    assert!(short.unwrap_err().contains("at least 6"));
    let gh = ["ghp", "_", "abcdefghijklmnopqrstuvwxyz0123456789"].concat();
    assert!(masks::add(masks::Scope::Repo, repo, &gh, None, None, true).unwrap_err().contains("public credential shape"));
    let ak = ["AK", "IA", "ABCDEFGHIJKLMNOP"].concat();
    assert!(masks::add(masks::Scope::Repo, repo, &ak, None, None, true).is_err());
    assert!(masks::add(masks::Scope::Repo, repo, "some-internal-thing", Some("aws-key"), None, true).unwrap_err().contains("built-in"));
    assert!(masks::add(masks::Scope::Repo, repo, "some-internal-thing", None, Some("jwt"), true).unwrap_err().contains("built-in"));
    // hints are redacted: a hint that is (or contains) a secret is refused
    let tok = ["gh", "p_", "Qw3rTy9uIoPa5sDf7gHj1kLz4xCv6bNm8Aq2"].concat();
    assert!(masks::add(masks::Scope::Repo, repo, "some-internal-thing", None, Some(&tok), true).unwrap_err().contains("hint"));
    assert!(masks::add(masks::Scope::Repo, repo, "some-internal-thing", None, Some("some-internal-thing"), true).unwrap_err().contains("hint"));
    let _ = std::fs::remove_dir_all(&d);
}
