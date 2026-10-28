//! Shell counterparts, builder C: typed rows (`-` input), --bare/--head/--width, `files`/`ls` (find, ls, wc -l),
//! `count`, `filter`, in-call pipes and sequences. Differential tests run the real tool on the same fixture tree and
//! require identical results for the accepted forms.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
}

const FILES: &[(&str, &str)] = &[
    ("src/a.rs", "fn alpha() {}\nfn beta() {\n    alpha(); // TODO one\n}\n"),
    ("src/b.rs", "fn gamma() { /* TODO two */ }"), // no trailing newline: wc -l says 0
    ("src/x/c.ts", "export function c() { return 1 }\n"),
    ("src/x/.hidden.rs", "fn h() {}\n"),
    ("src/x-y/d.py", "def d():\n    return 2  # TODO three\n"),
    ("docs/readme.md", "# Readme\nTODO docs\n"),
    ("tests/t_a.rs", "fn t() { alpha(); }\n"),
    ("Makefile", "all:\n\techo hi\n"),
    (".gitignore", "*.log\n"),
    ("ignored.log", "TODO ignored\n"),
];

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("shop");
    for (p, t) in FILES {
        let f = r.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "Initial"]);
    (d, r)
}

fn aix_in(repo: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let db = repo.parent().unwrap().join("index.db");
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).arg("--db").arg(&db).args(args).current_dir(repo).env("AIX_EMBED_URL", "").env("HOME", repo.parent().unwrap());
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let o = ch.wait_with_output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    // the first call builds the index and says so
    let text = text.lines().filter(|l| !l.starts_with("(index refreshed")).collect::<Vec<_>>().join("\n");
    (o.status.code().unwrap_or(-1), text)
}

fn aix(repo: &Path, args: &[&str]) -> String {
    let (c, o) = aix_in(repo, args, None);
    assert!(c == 0, "aix {args:?} exit {c}: {o}");
    o
}

fn sh(repo: &Path, cmd: &str, stdin: Option<&str>) -> String {
    let mut c = Command::new("sh");
    c.arg("-c").arg(cmd).current_dir(repo).env("LC_ALL", "C").stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    String::from_utf8_lossy(&ch.wait_with_output().unwrap().stdout).into_owned()
}

/// (stdout and stderr are merged by aix_in: the stderr note naming tracked files of unindexed types is not a row)
fn not_indexed_note(l: &str) -> bool {
    l.starts_with('(') && l.contains("not indexed")
}

fn sorted(s: &str, f: impl Fn(&str) -> String) -> Vec<String> {
    let mut v: Vec<String> = s.lines().filter(|l| !not_indexed_note(l)).map(|l| f(l)).filter(|l| !l.is_empty()).collect();
    v.sort();
    v
}

/// find's view of the indexed tree: .git/.aix pruned, the files aix does not index (Makefile, dotfile config,
/// gitignored) left out; `./x` printed as `x`.
fn norm_find(l: &str) -> String {
    let l = l.strip_prefix("./").unwrap_or(l);
    if l.is_empty() { ".".into() } else { l.trim_end_matches('/').to_string() }
}

#[test]
fn files_find_primaries_match_gnu_find() {
    let (_d, r) = repo();
    aix(&r, &["files", "--count"]); // build the index
    let not_indexed = "! -name Makefile ! -name .gitignore ! -name ignored.log";
    let cases: &[&str] = &[
        "-name '*.rs'",
        "-iname '*.RS'",
        "-path '*/x/*'",
        "-path './src/*' -name '*.rs'",
        "-type d",
        "-type f -maxdepth 1",
        "-maxdepth 2 -type d",
        "-mindepth 2 -name '*.py'",
        "-not -name '*.rs' -type f",
        "! -path '*/x*' -type f",
        "-name '[ab].rs'",
        "-name '*'",
        "-name '.*'",
        "-type f -newer src/a.rs",
    ];
    for c in cases {
        for start in ["", "src", "src/", "."] {
            if start.is_empty() && c.contains("'./") {
                continue;
            }
            let find = sh(&r, &format!("find {} \\( -path ./.git -o -path ./.aix \\) -prune -o {c} {not_indexed} -print", if start.is_empty() { "." } else { start }), None);
            let words: Vec<String> = Command::new("sh").arg("-c").arg(format!("printf '%s\\n' {start} {c}")).output().map(|o| String::from_utf8_lossy(&o.stdout).lines().map(str::to_string).collect()).unwrap();
            let mut args: Vec<&str> = vec!["files"];
            args.extend(words.iter().map(String::as_str));
            args.extend(["--bare", "--limit", "100000"]);
            let (code, out) = aix_in(&r, &args, None);
            let want = sorted(&find, norm_find);
            let got = sorted(&out, |l| if l.starts_with('\u{2026}') { String::new() } else { norm_find(l) });
            assert_eq!(got, want, "find {start} {c}: aix exit {code}\n{out}");
            assert_eq!(code, if want.is_empty() { 1 } else { 0 }, "{c}");
        }
    }
    // unsupported primaries are refused with the find command to run
    let (c, o) = aix_in(&r, &["files", "-name", "*.rs", "-o", "-name", "*.ts"], None);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("run it with find: find"), "{o}");
    let (c, _) = aix_in(&r, &["files", "-exec", "rm", "{}", ";"], None);
    assert_eq!(c, 2);
}

#[test]
fn files_lines_match_wc_l_and_ls_matches_ls() {
    let (_d, r) = repo();
    let out = aix(&r, &["files", "--lines", "--bare", "--ext", "rs,ts,py,md"]);
    for l in out.lines() {
        let (p, n) = l.rsplit_once(':').unwrap();
        let wc = sh(&r, &format!("wc -l < {p}"), None);
        assert_eq!(n, wc.trim(), "{p}");
    }
    assert!(out.contains("src/b.rs:0"), "{out}");
    // ls: one level, dot names only with -a / -A
    for (dir, flag) in [("src", ""), ("src/x", ""), ("src/x", "-A"), (".", "")] {
        let want = sorted(&sh(&r, &format!("ls -1 {flag} {dir}"), None), |l| l.to_string());
        let mut args = vec!["ls", dir, "--bare"];
        if !flag.is_empty() {
            args.push(flag);
        }
        let got = sorted(&aix(&r, &args), |l| l.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string());
        let want: Vec<String> = want.into_iter().filter(|w| !matches!(w.as_str(), "Makefile" | "ignored.log")).collect();
        assert_eq!(got, want, "ls {flag} {dir}");
    }
    // test -f / -e
    assert_eq!(aix_in(&r, &["files", "src/a.rs", "--exists"], None).0, 0);
    assert_eq!(aix_in(&r, &["files", "src/zz.rs", "--exists"], None).0, 1);
    // a gitignored file: not listed, and the answer says why
    let (c, o) = aix_in(&r, &["files", "ignored.log"], None);
    assert_eq!(c, 1);
    assert!(o.contains("exists but is not indexed"), "{o}");
    let o = aix(&r, &["files", "src"]);
    assert!(o.contains("gitignored") && o.contains("find"), "{o}");
    // glob (gitignore rules), regex, substring
    assert_eq!(sorted(&aix(&r, &["files", "*.rs", "--bare"]), |l| l.to_string()), vec!["src/a.rs", "src/b.rs", "src/x/.hidden.rs", "tests/t_a.rs"]);
    assert_eq!(aix(&r, &["files", r"\.py$", "--bare"]).trim(), "src/x-y/d.py");
    assert_eq!(aix(&r, &["files", "--group-by", "dir:2", "--bare"]).trim(), "2\tsrc\n2\tsrc/x\n1\tdocs\n1\tsrc/x-y\n1\ttests");
    assert_eq!(aix(&r, &["files", "--count", "--bare"]).trim(), "7");
}

#[test]
fn files_changed_and_members() {
    let (_d, r) = repo();
    aix(&r, &["files", "--count"]);
    std::fs::write(r.join("src/a.rs"), "fn alpha() {}\nfn beta() {\n    alpha(); // TODO one, changed\n}\n").unwrap();
    std::fs::write(r.join("src/new.rs"), "fn fresh() {}\n").unwrap();
    std::fs::write(r.join("src/untracked.rs"), "fn loose() {}\n").unwrap();
    git(&r, &["add", "src/new.rs"]);
    std::fs::remove_file(r.join("src/b.rs")).unwrap();
    let o = aix(&r, &["files", "--changed", "--bare"]);
    let want = sorted(&sh(&r, "git diff --name-only HEAD; git ls-files -o --exclude-standard", None), |l| l.to_string());
    assert_eq!(sorted(&o, |l| l.to_string()), want, "{o}");
    let m = aix(&r, &["files", "--changed", "--members"]);
    assert!(m.contains("src/a.rs:2-4") && m.contains("beta") && !m.contains("alpha"), "{m}");
    assert!(m.contains("fresh"), "{m}");
    assert!(o.contains("src/untracked.rs") && aix(&r, &["files", "--changed"]).contains("(untracked, not indexed)"));
}

#[test]
fn count_sort_uniq_cut_match_gnu() {
    let (_d, r) = repo();
    let data = "b x\na 10\n3 apples\na 10\nsrc/a.rs:12:5:z\nsrc/a.rs:3\n  indented\nb x\n";
    for (pipe, gnu) in [
        ("sort - | uniq -c", "sort | uniq -c"),
        ("sort -r -", "sort -r"),
        ("sort -n -k2 -", "sort -n -k2"),
        ("sort -t: -k2 -", "sort -t: -k2"),
        ("sort -u -", "sort -u"),
        ("uniq -c -", "uniq -c"),
        ("cut -d: -f1 -", "cut -d: -f1"),
        ("cut -c1-4 -", "cut -c1-4"),
        ("tail -n +3 - | head -2", "tail -n +3 | head -2"),
        ("sort - | uniq -d", "sort | uniq -d"),
    ] {
        let (c, got) = aix_in(&r, &["pipe", pipe, "--bare"], Some(data));
        let want = sh(&r, gnu, Some(data));
        assert_eq!(got.trim_end(), want.trim_end(), "{pipe} (exit {c})");
    }
    // wc -l and grep -c totals
    let (_, n) = aix_in(&r, &["count", "-", "--bare"], Some(data));
    assert_eq!(n.trim(), "8");
    let (c, n) = aix_in(&r, &["count", "-"], Some(""));
    assert_eq!((c, n.trim()), (1, "0"));
    // count by line = sort | uniq -c, sorted by count
    let (_, g) = aix_in(&r, &["count", "by", "line", "-", "--bare"], Some(data));
    assert_eq!(g.lines().next().unwrap(), "2\ta 10");
    // count by field N = awk '{print $N}' | sort | uniq -c
    let (_, g) = aix_in(&r, &["count", "by", "field", "1", "-", "--bare"], Some("x 1\ny 2\nx 3\n"));
    assert_eq!(g.trim(), "2\tx\n1\ty");
}

#[test]
fn rows_round_trip_aix_and_foreign_output() {
    let (_d, r) = repo();
    // aix grep (decorated), --jsonl, --bare, GNU grep -rn, git grep -n: the same per-file counts
    let per_file = |s: &str| sorted(s, |l| l.to_string());
    let want = per_file(&aix(&r, &["grep", "-c", "TODO", "--bare"]));
    assert!(want.contains(&"src/a.rs:1".to_string()), "{want:?}");
    for args in [vec!["grep", "TODO"], vec!["grep", "TODO", "--jsonl"], vec!["grep", "TODO", "--bare"]] {
        let src = aix(&r, &args);
        let (_, c) = aix_in(&r, &["count", "by", "file", "-", "--bare"], Some(&src));
        let got = per_file(&c.lines().map(|l| { let (n, k) = l.split_once('\t').unwrap(); format!("{k}:{n}") }).collect::<Vec<_>>().join("\n"));
        assert_eq!(got, want, "{args:?}\n{src}");
    }
    for gnu in ["grep -rn TODO src docs tests", "git grep -n TODO -- src docs tests", "grep -rn --color=never TODO src docs tests | sed 's#^#./#'"] {
        let src = sh(&r, gnu, None);
        let (_, c) = aix_in(&r, &["count", "by", "file", "-", "--bare"], Some(&src));
        let got = per_file(&c.lines().map(|l| { let (n, k) = l.split_once('\t').unwrap(); format!("{k}:{n}") }).collect::<Vec<_>>().join("\n"));
        assert_eq!(got, want, "{gnu}\n{src}");
    }
    // CRLF and a Windows drive path under the repo name
    let win = "C:\\work\\shop\\src\\a.rs:3:x\r\nsrc\\b.rs:1:y\r\n";
    let (_, c) = aix_in(&r, &["count", "by", "file", "-", "--bare"], Some(win));
    assert_eq!(sorted(&c, |l| l.to_string()), vec!["1\tsrc/a.rs", "1\tsrc/b.rs"], "{c}");
    // aix code / outline output back into rows
    let code = aix(&r, &["code", "src/a.rs:1-4"]);
    let (_, n) = aix_in(&r, &["count", "-", "--bare"], Some(&code));
    assert_eq!(n.trim(), "4", "{code}");
    let ol = aix(&r, &["outline", "src/a.rs"]);
    let (_, n) = aix_in(&r, &["count", "-", "--bare"], Some(&ol));
    assert_eq!(n.trim(), "2", "{ol}");
    // rg, when installed
    if Command::new("rg").arg("--version").output().is_ok() {
        let src = sh(&r, "rg -n --column --no-heading TODO src docs tests", None);
        let (_, c) = aix_in(&r, &["count", "by", "file", "-", "--bare"], Some(&src));
        assert_eq!(c.lines().count(), want.len(), "{src}");
    }
    // lines that name no file are counted, never silently dropped
    let (_, o) = aix_in(&r, &["count", "by", "file", "-"], Some("src/a.rs:1:x\nmake: *** Error 2\n"));
    assert!(o.contains("1 input line named no file"), "{o}");
}

#[test]
fn global_output_options() {
    let (_d, r) = repo();
    let plain = aix(&r, &["grep", "TODO"]);
    assert!(plain.contains("  src/a.rs:3: alpha(); // TODO one"), "{plain}");
    let bare = aix(&r, &["grep", "TODO", "--bare"]);
    assert!(bare.lines().filter(|l| !not_indexed_note(l)).all(|l| !l.starts_with(' ') && !l.starts_with("==") && !l.starts_with('(')), "{bare}");
    // grep --bare is the GNU engine (grepx.rs): the line verbatim, as `grep -rn` prints it
    assert!(bare.contains("src/a.rs:3:    alpha(); // TODO one"), "{bare}");
    // the global flag before the command works too
    assert_eq!(aix(&r, &["--bare", "grep", "TODO"]), bare);
    let head = aix(&r, &["grep", "TODO", "--head", "2"]);
    assert!(head.contains("--head 2 --page 2 --gen "), "{head}");
    let next = aix(&r, &["grep", "TODO", "--head", "2", "--page", "2"]);
    assert!(next.contains("rows 3-4"), "{next}");
    let w = aix(&r, &["grep", "TODO", "--width", "6", "--bare"]);
    let l = w.lines().find(|l| l.starts_with("src/a.rs:3:")).unwrap_or_else(|| panic!("{w}"));
    assert!(l.ends_with('\u{2026}') && l["src/a.rs:3:".len()..].chars().count() == 7, "{w}");
    // a sectioned answer: the first N rows and the exact rest
    let code = aix(&r, &["code", "src/a.rs:1-4", "--head", "2"]);
    assert!(code.contains("the rest: `aix code src/a.rs:3-4`"), "{code}");
    let (c, e) = aix_in(&r, &["grep", "TODO", "--head", "x"], None);
    assert_eq!(c, 2, "{e}");
}

#[test]
fn filter_bounds_and_redacts_text() {
    let (_d, r) = repo();
    let log: String = (1..=300).map(|i| format!("line {i}\n")).collect::<String>() + "password=hunter2secret\nERROR boom\n";
    let (_, o) = aix_in(&r, &["filter", "-"], Some(&log));
    assert!(o.contains("line 1\n") && o.contains("ERROR boom") && o.contains("lines omitted"), "{o}");
    assert!(!o.contains("hunter2secret") && o.contains("redacted"), "{o}");
    let (_, o) = aix_in(&r, &["filter", "--grep", "ERROR|line 7$", "--not", "line", "-"], Some(&log));
    assert!(o.contains("ERROR boom") && !o.contains("line 7"), "{o}");
    let (_, o) = aix_in(&r, &["filter", "--between", "^line 10$", "^line 12$", "-", "--bare"], Some(&log));
    assert_eq!(o.trim(), "line 10\nline 11\nline 12");
    let (c, _) = aix_in(&r, &["filter", "--tail", "2", "-"], Some(&log));
    assert_eq!(c, 0);
}

#[test]
fn in_call_pipes_mix_with_existing_commands() {
    let (_d, r) = repo();
    // callers -> code of each calling function, once
    let o = aix(&r, &["callers alpha | code -"]);
    // code reads `-` natively (readcmd.rs): the rows are injected once, the calling function's lines shown
    assert!(o.contains("fn beta()") && !o.contains("ran `aix code <row>`"), "{o}");
    // outline rows filtered by text
    let o = aix(&r, &["pipe", "outline src/a.rs | grep beta", "--bare"]);
    assert_eq!(o.lines().count(), 1, "{o}");
    assert!(o.starts_with("src/a.rs:2-4:"), "{o}");
    // grep -> count by dir (grep's own exact grouping)
    let o = aix(&r, &["grep TODO | count by dir", "--bare"]);
    assert_eq!(o.trim(), "3\tsrc\n1\tdocs", "{o}");
    // a count over a partial stream never prints a bare number
    let (_, o) = aix_in(&r, &["pipe", "grep TODO | sort | count"], None);
    assert!(o.trim().parse::<u32>().is_ok(), "{o}");
    // find -> head -> code
    let o = aix(&r, &["find alpha | head 1 | code -"]);
    assert!(o.contains("fn alpha()"), "{o}");
    // stdin rows into a file-taking command (CLI `-`)
    let (c, o) = aix_in(&r, &["outline", "-"], Some("src/a.rs:3:x\nsrc/a.rs:1:y\n"));
    assert_eq!(c, 0, "{o}");
    assert_eq!(o.matches("== outline src/a.rs").count(), 1, "{o}");
    // grep RE -: only the input's files
    let (_, o) = aix_in(&r, &["grep", "TODO", "-"], Some("src/b.rs\n"));
    assert!(o.contains("src/b.rs") && !o.contains("src/a.rs:"), "{o}");
    // files reading rows
    let o = aix(&r, &["pipe", "grep -l TODO | files --lines -", "--bare"]);
    assert!(o.contains("src/a.rs:4"), "{o}");
    // a usage error in any stage is exit 2
    assert_eq!(aix_in(&r, &["grep TODO | sort -z"], None).0, 2);
    assert_eq!(aix_in(&r, &["grep TODO | nosuchcmd"], None).0, 2);
    // a source after a stage must take `-`
    assert_eq!(aix_in(&r, &["grep TODO | sql SELECT 1"], None).0, 2);
}

#[test]
fn sequences_run_in_one_call() {
    let (_d, r) = repo();
    let o = aix(&r, &["outline src/a.rs ; code alpha ; grep -c TODO"]);
    for h in ["== aix outline src/a.rs", "== aix code alpha", "== aix grep -c TODO"] {
        assert!(o.contains(h), "{h}\n{o}");
    }
    let b = aix(&r, &["batch", "outline src/a.rs", "code alpha"]);
    assert!(b.contains("== aix outline src/a.rs") && b.contains("== aix code alpha"), "{b}");
    // the default output of each command is unchanged inside a sequence
    let alone = aix(&r, &["code", "alpha"]);
    assert!(b.contains(alone.lines().next().unwrap()), "{b}");
    let (c, _) = aix_in(&r, &["code alpha ; grep TODO | sort -z"], None);
    assert_eq!(c, 2);
}

#[test]
fn mcp_pipe_batch_and_output_options() {
    let (_d, r) = repo();
    aix(&r, &["files", "--count"]);
    let db = r.parent().unwrap().join("index.db");
    let mut ch = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .arg("--db")
        .arg(&db)
        .arg("mcp")
        .env("AIX_EMBED_URL", "")
        .env("HOME", r.parent().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let calls = [
        serde_json::json!({"command": "pipe", "args": "grep TODO | count by dir", "bare": true}),
        serde_json::json!({"command": "batch", "commands": ["outline src/a.rs", "code alpha"]}),
        serde_json::json!({"command": "files", "args": "-name '*.ts'", "bare": true}),
        serde_json::json!({"command": "grep", "args": "TODO", "head": 1}),
        serde_json::json!({"command": "count", "args": "-"}),
    ];
    {
        let mut w = ch.stdin.take().unwrap();
        writeln!(w, "{}", serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})).unwrap();
        writeln!(w, "{}", serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).unwrap();
        for (i, a) in calls.iter().enumerate() {
            writeln!(w, "{}", serde_json::json!({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": {"name": "aix", "arguments": a}})).unwrap();
        }
        w.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(3000));
    }
    let _ = ch.kill();
    let out = String::from_utf8_lossy(&ch.wait_with_output().unwrap().stdout).into_owned();
    let mut res = std::collections::HashMap::new();
    for l in out.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
            if let Some(id) = v["id"].as_i64() {
                res.insert(id, (v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string(), v["result"]["isError"].as_bool().unwrap_or(false)));
            }
        }
    }
    assert_eq!(res[&10].0.trim(), "3\tsrc\n1\tdocs", "{:?}", res[&10]);
    assert!(res[&11].0.contains("== aix outline src/a.rs") && res[&11].0.contains("== aix code alpha"), "{:?}", res[&11]);
    assert_eq!(res[&12].0.trim(), "src/x/c.ts");
    assert!(res[&13].0.contains("--head 1 --page 2"), "{:?}", res[&13]);
    // MCP has no stdin: `-` is a usage error naming the pipe command
    assert!(res[&14].1 && res[&14].0.contains("pipe"), "{:?}", res[&14]);
}

const ROUTES_JS: &str = "const express = require('express');\nconst fees = require('./fees');\nconst router = express.Router();\nrouter.get('/api/fees', (req, res) => {\n  res.json(fees.listFees());\n});\nrouter.post('/api/fees', (req, res) => {\n  fees.saveFee(req.body);\n  res.sendStatus(201);\n});\nmodule.exports = router;\n";
const FEES_JS: &str = "function listFees() {\n  return [];\n}\nfunction saveFee(fee) {\n  validate(fee);\n  return fee;\n}\nfunction validate(fee) {\n  if (!fee) throw new Error('no fee');\n}\nmodule.exports = { listFees, saveFee };\n";
const GRADES_TSX: &str = "import React from 'react';\nexport function Grades() {\n  const save = () => fetch('/api/fees', { method: 'POST' });\n  return <button onClick={save}>Save grades</button>;\n}\n";

fn web_repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("fees");
    for (p, t) in [("server/routes.js", ROUTES_JS), ("server/fees.js", FEES_JS), ("web/src/Grades.tsx", GRADES_TSX)] {
        let f = r.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "Initial"]);
    (d, r)
}

#[test]
fn query_commands_as_sources_and_consumers() {
    let (_d, r) = web_repo();
    // endpoint rows -> the handlers' code
    let o = aix(&r, &["endpoint /api/fees | code -"]);
    // each handler's member; adjacent ranges of one file share one header (readcmd.rs)
    assert!(o.contains("server/routes.js:4-") && o.contains("fees.listFees()") && o.contains("fees.saveFee(req.body)"), "{o}");
    // callers -> the calling function's code (the definition row is not a caller)
    let o = aix(&r, &["callers saveFee | code -"]);
    assert!(o.contains("fees.saveFee(req.body)") && !o.contains("server/fees.js:4-7"), "{o}");
    // a UI string -> the brief of the file that holds it
    let o = aix(&r, &["text \"Save grades\" | brief -"]);
    // a raw fetch call is labelled by its verb (`api.post POST /api/fees`) since the answer-accuracy fix
    assert!(o.contains("file web/src/Grades.tsx") && o.contains("api.post POST /api/fees"), "{o}");
    // impact rows keep their section as the kind
    let o = aix(&r, &["impact saveFee --conf name | count by kind", "--bare"]);
    assert_eq!(o.trim(), "1\tendpoint", "{o}");
    // the diff's files, with their lines (scope rows name no file: every changed file)
    std::fs::write(r.join("server/fees.js"), format!("{FEES_JS}// changed\n")).unwrap();
    let o = aix(&r, &["scope | files --changed --lines", "--bare"]);
    assert_eq!(o.trim(), "server/fees.js:12", "{o}");
    let o = aix(&r, &["pipe", "files --changed | outline -"]);
    assert!(o.contains("== outline server/fees.js"), "{o}");
}
