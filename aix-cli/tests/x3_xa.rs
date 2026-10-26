//! Usability fixes from an agent-usability QA round: history of a class or function name, brief's capped endpoint
//! list says it is capped, `impact main` says main is also a branch, refusals of logs/paste exit 1, `files --lines
//! --sort size` orders by the lines it shows (and its footer names each flag once), and `grep --count-by match` on a
//! data set counts the matches.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn write(r: &Path, p: &str, t: &str) {
    let f = r.join(p);
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(f, t).unwrap();
}

struct Fx {
    _d: tempfile::TempDir,
    repo: PathBuf,
    db: PathBuf,
}

impl Fx {
    fn new() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let repo = d.path().join("repo");
        write(&repo, "src/main/java/acme/OwnerController.java", "package acme;\n\npublic class OwnerController {\n    public String list() {\n        return \"owners\";\n    }\n}\n");
        write(&repo, "src/main/java/acme/App.java", "package acme;\n\npublic class App {\n    public static void main(String[] args) {\n        new OwnerController().list();\n    }\n}\n");
        let mut routes = String::from("const router = require('express').Router();\n");
        for i in 1..=11 {
            routes.push_str(&format!("router.get('/api/r{i}', function h{i}(req, res) {{ res.json({i}); }});\n"));
        }
        routes.push_str("router.get('/api/r1/sub', function hs(req, res) { res.json(0); });\n");
        routes.push_str("module.exports = router;\n");
        write(&repo, "src/routes/items.js", &routes);
        write(&repo, "src/util/tokens.js", "function makeToken(u) {\n  return u + 'x';\n}\nmodule.exports = { makeToken };\n");
        write(&repo, "src/main/java/acme/Names.java", "package acme;\n\npublic class Names {\n    static void check() {\n        throw new IllegalStateException(\"name has already been taken\");\n    }\n}\n");
        write(&repo, "src/test/java/acme/OwnerControllerTests.java", "package acme;\n\nclass OwnerControllerTests {\n    void t() {\n        new OwnerController().list();\n    }\n}\n");
        write(&repo, ".gitignore", "node_modules/\n");
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        write(&repo, "src/main/java/acme/OwnerController.java", "package acme;\n\npublic class OwnerController {\n    public String list() {\n        return \"all owners\";\n    }\n}\n");
        write(&repo, "src/util/tokens.js", "function makeToken(u) {\n  return u + 'y';\n}\nmodule.exports = { makeToken };\n");
        git(&repo, &["commit", "-q", "-am", "fix: owner list text"]);
        let db = d.path().join("ix.db");
        Fx { _d: d, repo, db }
    }
    fn aix(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&self.repo).arg("--db").arg(&self.db).args(args).env("AIX_EMBED_URL", "").env("HOME", self.repo.parent().unwrap());
        c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut ch = c.spawn().unwrap();
        {
            use std::io::Write;
            let mut i = ch.stdin.take().unwrap();
            i.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
        }
        ch.wait_with_output().unwrap()
    }
    fn run(&self, args: &[&str]) -> (i32, String) {
        let o = self.aix(args, None);
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string())
    }
}

#[test]
fn history_of_a_class_or_function_name() {
    let f = Fx::new();
    let (rc, o) = f.run(&["history", "OwnerController"]);
    assert_eq!(rc, 0, "{o}");
    assert!(o.contains("OwnerController.java: 2 commits"), "{o}");
    let (rc, o) = f.run(&["history", "makeToken"]);
    assert_eq!(rc, 0, "{o}");
    assert!(o.contains("makeToken (src/util/tokens.js:1-3): 2 commits changed its lines"), "{o}");
}

#[test]
fn brief_says_its_endpoint_list_is_capped() {
    let f = Fx::new();
    let (_, o) = f.run(&["brief", "src/routes/items.js"]);
    assert!(o.contains("== endpoints (8 of 12; `aix brief src/routes/items.js --full` lists all)"), "{o}");
    let (_, o) = f.run(&["brief", "src/routes/items.js", "--full"]);
    assert!(o.contains("== endpoints (12)"), "{o}");
    // a method and a full path: that endpoint, the family under it named
    let (_, o) = f.run(&["endpoint", "GET /api/r1"]);
    assert!(o.contains("(exact match; 1 more endpoints under /api/r1/") && !o.contains("/api/r1/sub ->"), "{o}");
}

#[test]
fn impact_of_a_word_that_is_also_a_branch_says_so() {
    let f = Fx::new();
    let (_, o) = f.run(&["impact", "main"]);
    assert!(o.contains("== impact of App.main") && o.contains("`main` is also a git revision") && o.contains("aix impact main..HEAD"), "{o}");
}

#[test]
fn refusals_of_logs_and_paste_exit_1() {
    let f = Fx::new();
    assert_eq!(f.run(&["paste", "errors", "paste:7"]).0, 1);
    assert_eq!(f.run(&["logs", "errors"]).0, 1);
}

#[test]
fn files_lines_sort_size_orders_by_lines_and_names_each_flag_once() {
    let f = Fx::new();
    let (_, o) = f.run(&["files", "*.js", "--lines", "--sort", "size", "--head", "1", "--bare"]);
    let first = o.lines().next().unwrap_or("");
    assert!(first.starts_with("src/routes/items.js:"), "{o}");
    let foot = o.lines().last().unwrap_or("");
    assert_eq!(foot.matches("--bare").count(), 1, "{foot}");
    assert_eq!(foot.matches("--head").count(), 1, "{foot}");
}

#[test]
fn set_grep_count_by_match_counts_the_matches() {
    let f = Fx::new();
    assert!(f.aix(&["put", "app", "-"], Some("slow query 12 ms\nslow query 40 ms\nok\nslow query 12 ms\n")).status.success());
    for flag in ["--count-by", "--group-by"] {
        let (rc, o) = f.run(&["grep", "-o", "slow query [0-9]+", "@app", flag, "match"]);
        assert_eq!(rc, 0, "{o}");
        assert!(o.contains("2  slow query 12") && o.contains("1  slow query 40"), "{flag}: {o}");
    }
    let (rc, o) = f.run(&["grep", "--bogus", "x", "@app"]);
    assert_eq!(rc, 2);
    assert!(!o.contains("grep --bogus"), "{o}");
}

#[test]
fn text_falls_back_to_a_literal_search_and_brief_names_the_tests() {
    let f = Fx::new();
    let (_, o) = f.run(&["text", "has already been taken"]);
    assert!(o.contains("== literal 'has already been taken' in non-test source (1;") && o.contains("src/main/java/acme/Names.java:5"), "{o}");
    let (_, o) = f.run(&["brief", "src/main/java/acme/OwnerController.java"]);
    assert!(o.contains("tests: src/test/java/acme/OwnerControllerTests.java"), "{o}");
}

#[test]
fn callers_head_keeps_the_header_first_and_wc_gets_a_hint() {
    let f = Fx::new();
    let (_, o) = f.run(&["callers", "OwnerController.list", "--head", "1"]);
    assert!(o.find("== callers of").unwrap() < o.find(" defined: ").unwrap(), "{o}");
    let e = f.aix(&["wc", "-l", "src/routes/items.js"], None);
    assert!(String::from_utf8_lossy(&e.stderr).contains("aix files F --lines"));
}

#[test]
fn count_by_dir_without_a_depth_splits_at_the_first_useful_level() {
    let f = Fx::new();
    let (_, o) = f.run(&["files src | count by dir"]);
    assert!(o.contains("src/routes") && o.contains("src/main"), "{o}");
}
