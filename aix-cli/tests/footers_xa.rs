//! Continuation footers: every cut answer names the exact command for the rest (head/tail of a data set, a filter cut
//! by --head, grep's --bare footer), and output options are never spliced into data rows that quote an aix command.

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
        for i in 1..=12 {
            write(&repo, &format!("src/r{i}.py"), "from app import get_token\n\ndef h(u):\n    return get_token(u)\n");
        }
        // a source line that quotes an aix footer
        write(&repo, "src/foot.rs", "fn f() {\n    let s = format!(\"next `aix {} --page {}`\", a, b);\n}\n");
        write(&repo, ".gitignore", "target/\n");
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "init"]);
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
    fn text(&self, args: &[&str]) -> String {
        let o = self.aix(args, None);
        String::from_utf8_lossy(&o.stdout).to_string()
    }
}

#[test]
fn head_and_tail_of_a_set_name_the_rest() {
    let f = Fx::new();
    let data: String = (1..=300).map(|i| format!("line {i}\n")).collect();
    assert!(f.aix(&["put", "big", "-"], Some(&data)).status.success());
    let h = f.text(&["head", "-n", "3", "@big"]);
    assert!(h.contains("more: aix code @big:4-63 (lines 4-300 remain)"), "{h}");
    let t = f.text(&["tail", "-n", "2", "@big"]);
    assert!(t.contains("earlier: aix code @big:239-298"), "{t}");
    // a whole set: no footer
    let all = f.text(&["head", "-n", "400", "@big"]);
    assert!(!all.contains("more:") && !all.contains("earlier:"), "{all}");
}

#[test]
fn a_filter_cut_by_head_names_the_exact_command() {
    let f = Fx::new();
    let data: String = (1..=300).map(|i| format!("line {i}\n")).collect();
    assert!(f.aix(&["put", "big", "-"], Some(&data)).status.success());
    let o = f.text(&["grep line @big | filter --grep 7", "--head", "2"]);
    assert!(o.contains("everything with `aix 'grep line @big | filter --grep 7' --head "), "{o}");
}

#[test]
fn bare_grep_footer_is_a_runnable_command() {
    let f = Fx::new();
    let o = f.text(&["grep", "get_token", "--head", "3", "--bare"]);
    let last = o.lines().last().unwrap_or("");
    assert!(last.starts_with('\u{2026}') && last.contains("everything with `aix grep get_token --head 24 --bare`"), "{o}");
}

#[test]
fn output_flags_are_never_spliced_into_data_rows() {
    let f = Fx::new();
    let o = f.text(&["code", "src/foot.rs:2", "--width", "0"]);
    assert!(o.contains("format!(\"next `aix {} --page {}`\", a, b);"), "{o}");
    let o = f.text(&["grep", "next `aix", "src", "--head", "5", "--width", "300"]);
    assert!(o.contains("next `aix {} --page {}`") && !o.contains("{} --head 5"), "{o}");
}

#[test]
fn output_contract_fixes() {
    let f = Fx::new();
    // global flags before sql are output options, not SQL text
    let o = f.text(&["--max-tokens", "60", "sql", "select 1 as x"]);
    assert!(o.contains('1') && !o.contains("read-only"), "{o}");
    // `.` is the whole repo: a miss is 0 matches, not "path not found"
    let o = f.text(&["grep", "zzznomatch", "."]);
    assert!(!o.contains("path not found"), "{o}");
    // an in-call grep stage tests the row as printed (path:line:text)
    let o = f.text(&["grep get_token | grep -c r1.py"]);
    assert_eq!(o.trim(), "2", "{o}");
    // shell flags after howto are words, not CLI flags
    assert!(f.aix(&["howto", "ls", "-la"], None).status.success());
}
