//! Round-5 QA (composition): rows of every language in pipes and pages, set pipes past the 64 KB answer ceiling,
//! exit status of the one-argument and `aix pipe` forms, continuation footers that run, `sql` with output options,
//! paths with spaces in row consumers, shell operators inside the quotes, CSV records in the SQL view, strict flags
//! on `sets rm` / `count`, `filter --where` field errors, BRE alternation in filter, identical ranges in a sequence,
//! the 8 MB stdin cut.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn write(r: &Path, rel: &str, body: &str) {
    let p = r.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn aix_in(r: &Path, args: &[&str], stdin: Option<&[u8]>) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(r).args(args).env("AIX_EMBED_URL", "").env("HOME", r).env("AIX_LOCK_DIR", r.join(".locks"));
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(b) = stdin {
        let mut w = ch.stdin.take().unwrap();
        let b = b.to_vec();
        std::thread::spawn(move || {
            let _ = w.write_all(&b);
        });
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn aix(r: &Path, args: &[&str]) -> (i32, String, String) {
    aix_in(r, args, None)
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".env*\n.DS_Store\n.aix/\n.locks/\n");
    for (p, b) in files {
        write(&r, p, b);
    }
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    aix(&r, &["update"]);
    (d, r)
}

fn langs() -> (tempfile::TempDir, PathBuf) {
    repo(&[("a.rb", "e = 1\n"), ("b.cs", "e = 1\n"), ("c.py", "e = 1\n"), ("d.py", "x = 1 # defined in cfg\n")])
}

#[test]
fn rows_of_every_language_survive_pipes_and_pages() {
    let (_d, r) = langs();
    let (_, out, _) = aix(&r, &["grep \"= 1\" | wc -l"]);
    assert_eq!(out.trim(), "4", "{out}");
    let (_, out, _) = aix(&r, &["grep -l \"= 1\" | count"]);
    assert_eq!(out.trim(), "4", "{out}");
    let (_, out, _) = aix(&r, &["grep", "= 1", "--page", "1", "--per-page", "10"]);
    assert!(out.contains("rows 1-4 of 4"), "{out}");
}

#[test]
fn exit_status_of_the_one_argument_and_pipe_forms() {
    let (_d, r) = langs();
    assert_eq!(aix(&r, &["grep", "ZZ_NONE_1"]).0, 1);
    assert_eq!(aix(&r, &["grep ZZ_NONE_1"]).0, 1);
    assert_eq!(aix(&r, &["pipe", "symbol zz_none"]).0, 1);
    assert_eq!(aix(&r, &["grep ZZ_NONE_1", "--bare"]).0, 1);
    assert_eq!(aix(&r, &["grep e"]).0, 0);
}

#[test]
fn shell_operators_inside_the_quotes_are_refused() {
    let (_d, r) = langs();
    for q in ["grep e || true", "grep e && grep x", "grep e |count", "grep e| count", "grep $(echo e)"] {
        let (c, out, _) = aix(&r, &[q]);
        assert_eq!(c, 2, "{q}: {out}");
    }
    // a regex alternation without spaces and a quoted `||` stay regex text
    assert_eq!(aix(&r, &["grep e|x | count"]).0, 0);
    let (c, out, _) = aix(&r, &["grep 'unterminated"]);
    assert_eq!(c, 2, "{out}");
}

#[test]
fn continuation_footers_name_the_whole_pipe() {
    let (_d, r) = repo(&[("a.py", "# TODO 1\n# TODO 2\n# TODO 3\n"), ("b.py", "# TODO 4\n"), ("c.rb", "# TODO 5\n")]);
    let (_, out, _) = aix(&r, &["grep TODO | head -n 4", "--head", "1"]);
    let next = out.split("next `").nth(1).and_then(|s| s.split('`').next()).expect(&out).to_string();
    assert!(next.starts_with("aix pipe 'grep TODO | head -n 4'"), "{next}");
    let words = shell_words(&next);
    let w: Vec<&str> = words.iter().skip(1).map(String::as_str).collect();
    let (c, out2, _) = aix(&r, &w);
    assert_eq!(c, 0, "{next}: {out2}");
    let (_, out, _) = aix(&r, &["grep TODO | count by file", "--head", "1"]);
    let next = out.split("next `").nth(1).and_then(|s| s.split('`').next()).expect(&out).to_string();
    assert!(next.starts_with("aix pipe 'grep TODO | count by file'"), "{next}");
    let words = shell_words(&next);
    let w: Vec<&str> = words.iter().skip(1).map(String::as_str).collect();
    let (c, out2, _) = aix(&r, &w);
    assert!(c == 0 && out2.contains("3 groups"), "{next}: {out2}");
}

fn shell_words(s: &str) -> Vec<String> {
    let mut v = vec![];
    let mut cur = String::new();
    let mut q: Option<char> = None;
    let mut any = false;
    for c in s.chars() {
        match q {
            Some(x) if c == x => q = None,
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => {
                q = Some(c);
                any = true
            }
            None if c.is_whitespace() => {
                if !cur.is_empty() || any {
                    v.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() || any {
        v.push(cur);
    }
    v
}

#[test]
fn sql_takes_the_output_options() {
    let (_d, r) = langs();
    for a in [vec!["sql", "select path from files", "--bare"], vec!["sql", "select path from files", "--head", "1"], vec!["--head", "1", "sql", "select path from files"]] {
        let (c, out, err) = aix(&r, &a);
        assert_eq!(c, 0, "{a:?}: {out}{err}");
    }
    let (c, out, _) = aix(&r, &["sql", "select path from files order by path", "--offset", "3"]);
    assert!(c == 0 && out.contains("d.py") && !out.contains("a.rb"), "{out}");
}

#[test]
fn paths_with_spaces_in_row_consumers() {
    let (_d, r) = repo(&[("docs/my notes.md", "A TODO here\n"), ("src/x.py", "# TODO two\n"), ("src/y.py", "print(1)\n")]);
    let (_, out, _) = aix(&r, &["grep TODO | count by file"]);
    assert!(out.contains("2 in 2 groups") && out.contains("docs/my notes.md"), "{out}");
    let (_, bare, _) = aix(&r, &["grep", "TODO", "--bare"]);
    let (_, out, _) = aix_in(&r, &["count", "by", "file", "-"], Some(bare.as_bytes()));
    assert!(out.contains("2 in 2 groups"), "{out}");
    // git's C-quoted path is unquoted
    let (_, out, _) = aix_in(&r, &["count", "by", "file", "-"], Some(b"\"docs/my notes.md\":1:A TODO here\n"));
    assert!(out.contains("docs/my notes.md") && !out.contains('"'), "{out}");
}

#[test]
fn data_sets_pipes_sql_and_strict_flags() {
    let (_d, r) = langs();
    let big: String = (1..=20000).map(|i| format!("line {i}\n")).collect();
    let half: String = (1..=20000).filter(|i| i % 2 == 0).map(|i| format!("line {i}\n")).collect();
    assert_eq!(aix_in(&r, &["put", "big", "-"], Some(big.as_bytes())).0, 0);
    assert_eq!(aix_in(&r, &["put", "half", "-"], Some(half.as_bytes())).0, 0);
    let (_, out, _) = aix(&r, &["grep . @big | count"]);
    assert_eq!(out.trim(), "20000", "{out}");
    let (_, out, _) = aix(&r, &["grep -v -x -F -f @half @big | count"]);
    assert_eq!(out.trim(), "10000", "{out}");
    // a CSV record with a quoted newline is one row of the SQL view
    write(&r, "m.csv", "id,name,role\n1,\"multi\nline\",student\n2,x,teacher\n");
    assert_eq!(aix(&r, &["put", "mcsv", &r.join("m.csv").to_string_lossy()]).0, 0);
    let (_, out, _) = aix(&r, &["sql", "SELECT count(*) FROM @mcsv", "--bare"]);
    assert!(out.lines().any(|l| l.trim() == "2"), "{out}");
    // `@a.b` and `@a-b` are two views
    assert_eq!(aix_in(&r, &["put", "a.b", "-"], Some(b"x\n")).0, 0);
    assert_eq!(aix_in(&r, &["put", "a-b", "-"], Some(b"y\n")).0, 0);
    let (c, out, _) = aix(&r, &["sql", "SELECT (SELECT count(*) FROM @a.b) + (SELECT count(*) FROM @a-b)", "--bare"]);
    assert!(c == 0 && out.lines().any(|l| l.trim() == "2"), "{out}");
    // an unknown flag on sets rm removes nothing; --dry-run is a dry run; a missing set is exit 1
    assert_eq!(aix(&r, &["sets", "rm", "half", "--frobnicate"]).0, 2);
    assert_eq!(aix(&r, &["sets", "rm", "half", "--dry-run"]).0, 0);
    assert!(aix(&r, &["sets"]).1.contains("@half "));
    assert_eq!(aix(&r, &["sets", "rm", "nosuchset"]).0, 1);
    assert_eq!(aix(&r, &["sets", "show", "nosuchset"]).0, 2);
    // ttl and size checks
    assert_eq!(aix_in(&r, &["put", "t1", "-", "--ttl", "-5d"], Some(b"x\n")).0, 2);
    assert_eq!(aix_in(&r, &["put", "t2", "-", "--ttl", "0"], Some(b"x\n")).0, 2);
    assert_eq!(aix_in(&r, &["put", "t3", "-", "--max-mb", "0"], Some(b"x\n")).0, 2);
    assert_ne!(aix(&r, &["put", "t4", &r.join(".git/config").to_string_lossy()]).0, 0);
    // filter --where names an unknown field
    assert_eq!(aix_in(&r, &["put", "kvs", "-", "--kv"], Some(b"k=1\nk=2\n")).0, 0);
    let (c, out, err) = aix(&r, &["filter", "--where", "nosuch=1", "@kvs"]);
    assert!(c == 2 && (out + &err).contains("nosuch"), "{c}");
}

#[test]
fn row_commands_strict_flags_bre_and_stdin_cut() {
    let (_d, r) = langs();
    assert_eq!(aix_in(&r, &["count", "by", "file", "--frobnicate", "-"], Some(b"a.py:1:x\n")).0, 2);
    let (_, out, _) = aix_in(&r, &["filter", "--grep", "a\\|b", "-"], Some(b"a\nb\nc\n"));
    assert!(out.lines().any(|l| l == "a") && out.lines().any(|l| l == "b") && !out.lines().any(|l| l == "c"), "{out}");
    // past the 8 MB kept, the input is still counted to its end (exact), and the note says it was long
    let cap = 8 * 1024 * 1024;
    let fill = "c.py:1:x\n";
    let mut s = fill.repeat(cap / fill.len());
    s.push_str("c.py:13:compute\nc.py:13:compute\n");
    let (_, out, _) = aix_in(&r, &["count", "-"], Some(s.as_bytes()));
    assert!(out.starts_with(&format!("{}\n", cap / fill.len() + 2)) && out.contains("over the 8 MB kept"), "{out}");
    // a breakdown is read from the kept part: a lower bound
    let (_, out, _) = aix_in(&r, &["count", "by", "file", "-"], Some(s.as_bytes()));
    assert!(out.contains(">="), "{out}");
}

#[test]
fn identical_range_in_a_sequence_is_shown_once() {
    let (_d, r) = repo(&[("src/x.py", "# TODO two\nprint(1)\n")]);
    let (_, out, _) = aix(&r, &["code src/x.py:1-1 ; code src/x.py:1-1"]);
    assert_eq!(out.matches("TODO two").count(), 1, "{out}");
    assert!(out.contains("shown above"), "{out}");
}

#[test]
fn more_exit_codes_and_the_count_by_match_fast_path() {
    let (_d, r) = repo(&[("a.py", "alpha beta alpha\nbeta gamma\n"), ("b.py", "alpha\n")]);
    assert_eq!(aix_in(&r, &["dedup", "-"], Some(b"")).0, 1);
    assert_eq!(aix_in(&r, &["code", "-"], Some(b"a.py:999:x\n")).0, 2);
    assert_eq!(aix(&r, &["code", "@nosuchset:1-3"]).0, 2);
    // every match is counted (not a sample of rows), the same as --count-by match
    let (_, out, _) = aix(&r, &["grep -o \"[a-z]+\" | count by match"]);
    assert!(out.contains("3  alpha") && out.contains("2  beta") && out.contains("1  gamma"), "{out}");
    // a set answer cut at 64 KB names a continuation the set commands take
    let big: String = (1..=20000).map(|i| format!("line {i}\n")).collect();
    assert_eq!(aix_in(&r, &["put", "big", "-"], Some(big.as_bytes())).0, 0);
    let (_, out, _) = aix(&r, &["grep", ".", "@big", "--head", "10000"]);
    let next = out.lines().find(|l| l.contains("output truncated")).and_then(|l| l.split("continue with aix ").nth(1)).and_then(|t| t.split(" (").next()).expect(&out).to_string();
    let w = shell_words(&next);
    let w: Vec<&str> = w.iter().map(String::as_str).collect();
    let (c, out2, _) = aix(&r, &w);
    assert!(c == 0 && out2.contains("@big:"), "{next}: {out2}");
}
