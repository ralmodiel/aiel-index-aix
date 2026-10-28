// `stats --savings` shows the measurement window and, when a weekly allocation is configured (user config, repo
// config or AIX_WEEKLY_TOKENS / AIX_PLAN), the tokens saved as a share of it.
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git").arg("-C").arg(repo).args(args).env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@example.com").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@example.com").status().unwrap().success();
    assert!(ok, "git {args:?}");
}

struct Env {
    d: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let (repo, home) = (d.path().join("proj"), d.path().join("home"));
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let body: String = (0..400).map(|i| format!("def load_{i}(x):\n    return x + {i}\n")).collect();
    std::fs::write(repo.join("main.py"), body).unwrap();
    std::fs::write(repo.join(".gitignore"), ".aix/\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    Env { d, repo, home }
}

impl Env {
    fn aix(&self, args: &[&str], envs: &[(&str, &str)]) -> String {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&self.repo).args(args).env("AIX_EMBED_URL", "").env("HOME", &self.home).env("AIX_LOCK_DIR", self.d.path().join("locks"))
            .env_remove("AIX_WEEKLY_TOKENS").env_remove("AIX_PLAN");
        for (k, v) in envs {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    fn savings_line(&self, envs: &[(&str, &str)]) -> String {
        let s = self.aix(&["stats", "--savings"], envs);
        s.lines().find(|l| l.trim_start().starts_with("measured ")).unwrap_or_else(|| panic!("no measured line in:\n{s}")).to_string()
    }
}

#[test]
fn savings_show_the_window_and_a_share_of_the_configured_allocation() {
    let e = env();
    for w in ["load_1", "load_2", "load_3"] {
        e.aix(&["grep", w], &[]);
    }
    let plain = e.savings_line(&[]);
    assert!(plain.contains("set AIX_WEEKLY_TOKENS=N"), "{plain}");
    // user config, also read when a repo config exists (the plan is the user's)
    std::fs::create_dir_all(e.home.join(".config/aix")).unwrap();
    std::fs::write(e.home.join(".config/aix/config.toml"), "plan = \"Team\"\nweekly_tokens = 1_000\n").unwrap();
    std::fs::create_dir_all(e.repo.join(".aix")).unwrap();
    std::fs::write(e.repo.join(".aix/config.toml"), "code_cap = 60\n").unwrap();
    let cfg = e.aix(&["stats", "--savings"], &[]);
    assert!(cfg.contains("a week is assumed to be ~1K tokens for the Team plan (an estimate, not your real limit)"), "{cfg}");
    // the allocation is shared by every project; the saving is this repo's only
    let full = e.aix(&["stats", "--savings"], &[]);
    assert!(full.contains("tokens saved (this repo only)"), "{full}");
    // the measured line closes the report
    assert!(full.trim_end().lines().last().is_some_and(|l| l.trim_start().starts_with("measured ")), "{full}");
    // env overrides the config
    let env_l = e.aix(&["stats", "--savings"], &[("AIX_WEEKLY_TOKENS", "2_000"), ("AIX_PLAN", "Pro")]);
    assert!(env_l.contains("a week is assumed to be ~2K tokens for the Pro plan"), "{env_l}");
    let j = e.aix(&["stats", "--savings", "--json"], &[]);
    assert!(j.contains("\"pct_of_week\"") && j.contains("\"plan\":\"Team\""), "{j}");
}

#[test]
fn currentweek_relates_the_saving_to_this_weeks_usage() {
    let e = env();
    for w in ["load_1", "load_2", "load_3"] {
        e.aix(&["grep", w], &[]);
    }
    let w = [("AIX_WEEKLY_TOKENS", "1_000")];
    let s = e.aix(&["stats", "--savings", "--currentweek", "28%"], &w);
    assert!(s.contains("You have used 28% of your week") && s.contains("% of your usage; ~") && s.contains("if only half of these lookups would have been asked without aix): without aix you would be at ~"), "{s}");
    assert!(s.contains("  how: each answer is counted as bytes returned x K"), "{s}");
    assert!(s.contains("  calibration: the ratios were measured on ") && s.contains("  cross-check: first reading recorded"), "{s}");
    assert!(s.contains("measured ") && s.contains(" (estimate): ~"), "{s}");
    assert!(s.contains("add their points to get the total aix saved you"), "{s}");
    assert!(s.trim_end().lines().last().is_some_and(|l| l.trim_start().starts_with("measured ")), "the measured line stays last: {s}");
    let j = e.aix(&["stats", "--savings", "--currentweek", "28", "--json"], &w);
    assert!(j.contains("\"pct_of_usage\"") && j.contains("\"pct_without_aix\""), "{j}");
    let bad = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&e.repo).args(["stats", "--savings", "--currentweek", "abc"]).env("HOME", &e.home).output().unwrap();
    assert!(bad.status.code() == Some(2) && String::from_utf8_lossy(&bad.stderr).contains("takes a percentage between 0 and 100"), "{bad:?}");
}

#[test]
fn week_start_is_the_most_recent_matching_moment() {
    use aix_core::last_week_start as ws;
    let sun = 3 * 86400; // 1970-01-04 00:00 UTC was a Sunday
    let h = 3600;
    // after the start on the day itself: today 16:00
    assert_eq!(ws("Sun 16:00", sun + 21 * h + 1800, 0), Some(sun + 16 * h));
    // exactly at the start counts
    assert_eq!(ws("sun 16:00", sun + 16 * h, 0), Some(sun + 16 * h));
    // before the start on the day: last week's
    assert_eq!(ws("Sun 16:00", sun + 15 * h, 0), Some(sun + 16 * h - 7 * 86400));
    // mid-week: the Sunday before
    assert_eq!(ws("Sunday 16:00", sun + 3 * 86400 + 10 * h, 0), Some(sun + 16 * h));
    // a zone 8 h east of UTC: local Sunday 21:30 -> local Sunday 16:00 = 08:00 UTC
    assert_eq!(ws("Sun 16:00", sun + 13 * h + 1800, 8 * h), Some(sun + 8 * h));
    for bad in ["", "Sun", "Funday 16:00", "Sun 25:00", "Sun 16:00 extra"] {
        assert_eq!(ws(bad, sun, 0), None, "{bad}");
    }
}

#[test]
fn savings_measure_from_the_week_start_when_set() {
    let e = env();
    e.aix(&["grep", "load_1"], &[]);
    let s = e.aix(&["stats", "--savings"], &[("AIX_WEEK_START", "Sun 16:00"), ("AIX_WEEKLY_TOKENS", "1_000")]);
    assert!(s.contains("(week start Sun 16:00)") && s.contains("queries this week") && s.contains("all time:"), "{s}");
    let bad = e.aix(&["stats", "--savings"], &[("AIX_WEEK_START", "someday")]);
    assert!(bad.contains("not understood"), "{bad}");
}
