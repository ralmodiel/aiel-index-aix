//! The read surface (builder A): multi-target `code`, row input from any aix command, the adaptive cap, `cat` / `head`
//! / `tail` / `sed` with GNU semantics (differential tests against the real tools where GNU ones are installed), the
//! `sed s///` preview, `--raw` anchors, `anchor` / `--check-unique`, read-through of unindexed files, `diff`, and MCP.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn write(r: &Path, rel: &str, body: &str) {
    let p = r.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn cmd(repo: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.current_dir(repo).arg("--repo").arg(repo).env("AIX_EMBED_URL", "").env("HOME", repo);
    c
}

/// (exit status, stdout, stderr)
fn run(repo: &Path, args: &[&str]) -> (i32, String, String) {
    run_in(repo, args, None)
}

fn run_in(repo: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let mut c = cmd(repo);
    c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    {
        let mut i = ch.stdin.take().unwrap();
        if let Some(s) = stdin {
            i.write_all(s.as_bytes()).unwrap();
        }
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn ok(repo: &Path, args: &[&str]) -> String {
    let (c, o, e) = run(repo, args);
    assert_eq!(c, 0, "aix {args:?}: {e}{o}");
    o
}

/// `aix A... | aix B...`
fn pipe(repo: &Path, a: &[&str], b: &[&str]) -> (i32, String) {
    let (_, first, _) = run(repo, a);
    let (c, o, e) = run_in(repo, b, Some(&first));
    (c, format!("{o}{e}"))
}

fn big_ts() -> String {
    let mut s = String::from("export function big(items: number[]) {\n  let t = 0;\n");
    for i in 0..300 {
        s.push_str(&format!("  t += items[{i}] ?? {i}; // step {i}\n"));
    }
    s.push_str("  return t;\n}\n");
    s
}

const SMALL: &str = "export function small() {\n  return 1;\n}\n\nexport class Foo {\n  bar(x: number) {\n    return x + 1;\n  }\n  baz() {\n    return this.bar(2);\n  }\n}\n";
const README: &str = "# Title\n\nintro\n\n## Install\n\nrun it\nmore\n\n## Usage\n\nuse it\n";

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, "src/big.ts", &big_ts());
    write(&r, "src/small.ts", SMALL);
    write(&r, "src/use.ts", "import { Foo } from './small';\nexport function useIt() {\n  const f = new Foo();\n  return f.bar(3);\n}\n");
    write(&r, "docs/README.md", README);
    write(&r, "src/conf.ts", "export const a = 1;\nconst password = \"Zq81xKvPlmHunterQ\";\nexport const b = 2;\n");
    write(&r, ".gitignore", "build/\n.env\n");
    let log: String = (1..=50).map(|i| format!("log line {i}\n")).collect();
    write(&r, "build/out.log", &log);
    write(&r, ".env", "SECRET_TOKEN=supersecretvalue1\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    ok(&r, &["update"]);
    (d, r)
}

/// The GNU build of a tool (`gnuhead` where uutils is the default), or None when only a non-GNU one is installed.
fn gnu(tool: &str) -> Option<String> {
    for name in [format!("gnu{tool}"), tool.to_string()] {
        if let Ok(o) = Command::new(&name).arg("--version").output() {
            if String::from_utf8_lossy(&o.stdout).contains("GNU") {
                return Some(name);
            }
        }
    }
    None
}

fn shell(repo: &Path, tool: &str, args: &[&str]) -> String {
    // Windows: through bash, as Claude Code's Bash tool runs them (a Git for Windows tool started from a native process
    // glob-expands its arguments, which eats the `\` of `\(`)
    let o = if cfg!(windows) {
        let q: Vec<String> = std::iter::once(tool).chain(args.iter().copied()).map(|a| format!("'{}'", a.replace('\'', r"'\''"))).collect();
        Command::new("bash").arg("-c").arg(q.join(" ")).current_dir(repo).output().unwrap()
    } else {
        Command::new(tool).current_dir(repo).args(args).output().unwrap()
    };
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn head_tail_cat_sed_match_gnu_byte_for_byte() {
    let (_d, r) = repo();
    let cases: &[(&str, &[&str])] = &[
        ("head", &["-n", "5", "src/big.ts"]),
        ("head", &["-3", "src/big.ts"]),
        ("head", &["-n", "-300", "src/big.ts"]),
        ("head", &["src/big.ts", "src/small.ts"]),
        ("head", &["-q", "-n", "2", "src/big.ts", "src/small.ts"]),
        ("head", &["-v", "-n", "1", "src/small.ts"]),
        ("head", &["-n", "0", "src/small.ts"]),
        ("tail", &["-n", "4", "src/big.ts"]),
        ("tail", &["-n", "+300", "src/big.ts"]),
        ("tail", &["-n", "2", "src/small.ts", "docs/README.md"]),
        ("tail", &["+3", "src/small.ts"]),
        ("tail", &["-3", "src/small.ts"]),
        ("tail", &["src/big.ts"]),
        ("tail", &["-n", "+0", "src/small.ts"]),
        ("cat", &["src/small.ts", "docs/README.md"]),
        ("cat", &["-n", "src/small.ts", "docs/README.md"]),
        ("sed", &["-n", "10,20p", "src/big.ts"]),
        ("sed", &["-n", "5p", "src/big.ts"]),
        ("sed", &["-n", "$p", "src/big.ts"]),
        ("sed", &["-n", "/step 10$/,/step 12$/p", "src/big.ts"]),
        ("sed", &["-n", "/step 5$/,+3p", "src/big.ts"]),
        ("sed", &["-n", "-e", "1,3p", "-e", "2p", "src/big.ts"]),
        ("sed", &["-ne", "2,4p", "src/small.ts"]),
        ("sed", &["5q", "src/big.ts"]),
        ("sed", &["-n", "2,4p", "src/small.ts", "docs/README.md"]),
        ("sed", &["-n", "-s", "2,4p", "src/small.ts", "docs/README.md"]),
        ("sed", &["-n", r"/re\(tu\)\{1\}rn/p", "src/small.ts"]),
        ("sed", &["-nE", r"/(bar|baz)\(/p", "src/small.ts"]),
        ("sed", &["-n", "/^## /,/^$/p", "docs/README.md"]),
        ("sed", &["-n", "0,/Foo/p", "src/small.ts"]),
        ("sed", &["-n", "3,1p", "src/small.ts"]),
        ("sed", &["-n", "/return/=", "src/small.ts"]),
        ("sed", &["-n", "s/return/yield/p", "src/small.ts"]),
        ("sed", &["-n", "/step 7$/!d;p", "src/big.ts"]),
    ];
    let mut compared = 0;
    for (tool, args) in cases {
        let Some(g) = gnu(tool) else {
            eprintln!("skip {tool}: no GNU build installed");
            continue;
        };
        let want = shell(&r, &g, args);
        let mut a: Vec<&str> = vec![tool];
        a.extend_from_slice(args);
        a.push("--bare");
        let (c, got, e) = run(&r, &a);
        assert_eq!(got, want, "aix {a:?} (exit {c}, {e}) differs from {g} {args:?}");
        compared += 1;
    }
    eprintln!("{compared} forms compared byte for byte with the GNU tools");
    // stdin (text, redacted)
    let (_, o, _) = run_in(&r, &["tail", "-n", "2", "-", "--bare"], Some(SMALL));
    assert_eq!(o, "  }\n}\n");
}

#[test]
fn refused_forms_exit_2_naming_the_shell_command() {
    let (_d, r) = repo();
    for a in [
        &["head", "-c", "5", "src/small.ts"][..],
        &["tail", "-f", "build/out.log"],
        &["cat", "-A", "src/small.ts"],
        &["sed", "-n", "/a/{p}", "src/small.ts"],
        &["sed", "-n", r"/\(a\)\1/p", "src/small.ts"],
        &["sed", "s/a/b/w out", "src/small.ts"],
        &["sed", "1i hello", "src/small.ts"],
        &["sed", r"s/a/\U&/", "src/small.ts"],
        &["diff", "-y", "src/small.ts", "src/use.ts"],
    ] {
        let (c, o, e) = run(&r, a);
        assert_eq!(c, 2, "{a:?}: {o}{e}");
        assert!(o.contains("not supported") || o.contains("shell") || o.contains("logs tail"), "{a:?}: {o}");
    }
}

#[test]
fn sed_substitution_is_a_preview_that_applies_to_what_gnu_sed_writes() {
    let (d, r) = repo();
    let Some(g) = gnu("sed") else { return };
    let before = std::fs::read_to_string(r.join("src/small.ts")).unwrap();
    for (script, file) in [
        ("s/return/yield/", "src/small.ts"),
        ("s/x + 1/x + 2/;/baz/d", "src/small.ts"),
        (r"s/\(step\) \([0-9]*\)/\2 \1/g", "src/big.ts"),
        ("s/Title/T\\nitle/", "docs/README.md"),
        ("2,4s/^/# /", "src/small.ts"),
        ("$d", "src/small.ts"),
        ("/^$/d", "docs/README.md"),
    ] {
        let (c, diff, e) = run(&r, &["sed", "-i", script, file, "--bare"]);
        assert_eq!(c, 0, "{script}: {e}{diff}");
        // apply the preview to a copy and compare with GNU sed's output
        let copy = d.path().join("copy");
        let _ = std::fs::remove_dir_all(&copy);
        write(&copy, file, &std::fs::read_to_string(r.join(file)).unwrap());
        let mut p = Command::new("patch").current_dir(&copy).args(["-s", "-p1"]).stdin(Stdio::piped()).spawn().unwrap();
        p.stdin.take().unwrap().write_all(diff.as_bytes()).unwrap();
        assert!(p.wait().unwrap().success(), "{script}: patch refused {diff}");
        let want = shell(&r, &g, &[script, file]);
        assert_eq!(std::fs::read_to_string(copy.join(file)).unwrap(), want, "{script}");
    }
    // never written; -i says so in the decorated form
    assert_eq!(std::fs::read_to_string(r.join("src/small.ts")).unwrap(), before);
    assert!(ok(&r, &["sed", "-i", "s/return/yield/", "src/small.ts"]).contains("aix never writes"));
    // a hunk on a masked line is refused
    let (c, o, _) = run(&r, &["sed", "s/password/pw/", "src/conf.ts"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("hunk touches masked") && !o.contains("Zq81xKvPlmHunterQ"), "{o}");
    // nothing to change: exit 1
    assert_eq!(run(&r, &["sed", "s/nomatch/x/", "src/small.ts"]).0, 1);
}

#[test]
fn several_targets_in_one_call_grouped_per_file() {
    let (_d, r) = repo();
    let o = ok(&r, &["code", "src/small.ts:1-3", "src/small.ts:2-4", "Foo.baz", "docs/README.md#install", "src/big.ts:10-12,20-21"]);
    assert_eq!(o.matches("== lines src/small.ts:1-4 (4 lines)").count(), 1, "{o}");
    assert!(o.contains("Foo.baz src/small.ts:9-11"), "{o}");
    assert!(o.contains("== section docs/README.md:5-9") && o.contains("run it"), "{o}");
    assert!(o.contains("src/big.ts:10-12,20-21 (5 lines)") && o.contains("…"), "{o}");
    // the order of the targets is kept
    let (a, b) = (o.find("src/small.ts:1-4").unwrap(), o.find("Foo.baz").unwrap());
    assert!(a < b && b < o.find("docs/README.md").unwrap(), "{o}");
    // a pattern range
    let p = ok(&r, &["code", "src/big.ts:/step 10$/,/step 12$/"]);
    assert!(p.contains("13-15 (3 lines)") && p.contains("step 11"), "{p}");
    // a heading that does not exist lists the headings
    let (c, h, _) = run(&r, &["code", "docs/README.md#nope"]);
    assert_eq!(c, 1);
    assert!(h.contains("Install") && h.contains("Usage"), "{h}");
}

#[test]
fn adaptive_cap_whole_up_to_200_then_outline_and_exact_continuation() {
    let (_d, r) = repo();
    let o = ok(&r, &["code", "src/big.ts:1-180", "src/small.ts:1-3"]);
    assert!(o.contains("step 177") && !o.contains("more lines"), "{o}");
    // beyond the cap: first part + continuation that, run as printed, shows the rest whole
    let o = ok(&r, &["code", "src/big.ts:1-290", "src/small.ts:1-3"]);
    assert!(o.contains("(290 lines, 120 shown)"), "{o}");
    let cont = o.lines().find(|l| l.contains("more lines")).unwrap();
    assert!(cont.contains("aix code src/big.ts:121-290"), "{cont}");
    let next = ok(&r, &["code", "src/big.ts:121-290"]);
    assert!(next.contains("step 286") && !next.contains("more lines"), "{next}");
    // bare: the text, then one footer line with the exact next command
    let (_, b, _) = run(&r, &["head", "-n", "260", "src/big.ts", "--bare"]);
    let last = b.lines().last().unwrap();
    assert!(last.contains("aix code src/big.ts:121-260 --bare"), "{last}");
    assert_eq!(b.lines().count(), 121);
    // --max / --full
    assert!(ok(&r, &["code", "src/big.ts:1-290", "src/small.ts:1-3", "--full"]).contains("step 286"));
    assert!(ok(&r, &["cat", "src/big.ts", "--max", "5"]).contains("(304 lines, 5 shown)"));
}

#[test]
fn rows_from_any_aix_command_feed_code() {
    let (_d, r) = repo();
    // callers -> the call sites with context; --function -> each caller's member once
    let (c, o) = pipe(&r, &["callers", "bar", "--all"], &["code", "-"]);
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("src/use.ts") && o.contains("f.bar(3)") && o.contains("src/small.ts"), "{o}");
    let (_, f) = pipe(&r, &["callers", "bar", "--all"], &["code", "-", "--function", "--dedup"]);
    assert!(f.contains("export function useIt") && f.contains("baz()"), "{f}");
    // the bare rows (`path:line:text`, what `--bare` and grep -n print) give the same members
    let rows = "src/use.ts:4:  return f.bar(3);\nsrc/small.ts:10:    return this.bar(2);\nsrc/small.ts:10:    return this.bar(2);\n";
    let (_, b, _) = run_in(&r, &["code", "-", "--function"], Some(rows));
    assert!(b.contains("export function useIt") && b.matches("baz()").count() == 1, "{b}");
    // outline -> the members' ranges
    let (_, o2) = pipe(&r, &["outline", "src/small.ts"], &["code", "-"]);
    assert!(o2.contains("src/small.ts:") && o2.contains("return this.bar(2)"), "{o2}");
    // grep -l -> the files; --around prints snippets around the matches
    let (_, g) = pipe(&r, &["grep", "-l", "bar"], &["code", "-", "--around", r"\.bar\(", "-C", "0"]);
    assert!(g.contains("return this.bar(2);") && g.contains("return f.bar(3);") && !g.contains("export class Foo"), "{g}");
    // a bare member name
    let (_, m, _) = run_in(&r, &["code", "-"], Some("Foo.baz\n"));
    assert!(m.contains("return this.bar(2)"), "{m}");
    // --json answers (structured cites)
    let (_, j) = pipe(&r, &["callers", "bar", "--all", "--json"], &["code", "-", "--function"]);
    assert!(j.contains("export function useIt"), "{j}");
    // cat - takes file rows; diff - compares them with HEAD
    let (_, cat) = pipe(&r, &["grep", "-l", "useIt"], &["cat", "-"]);
    assert!(cat.contains("== file src/use.ts"), "{cat}");
    // unknown lines are counted, not guessed
    let (_, u, _) = run_in(&r, &["code", "-"], Some("hello there\nsrc/small.ts:2\n"));
    assert!(u.contains("1 input line named no file") && u.contains("return 1;"), "{u}");
}

#[test]
fn rows_from_endpoint_answers() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    write(&r, "backend/src/main/java/com/acme/api/OrderResource.java", "package com.acme.api;\n\nimport jakarta.ws.rs.*;\n\n@Path(\"/api/orders\")\npublic class OrderResource {\n    @GET\n    public String list() {\n        return \"[]\";\n    }\n}\n");
    write(&r, "frontend/src/api.ts", "export const ordersApi = {\n  list: () => api.get('/orders'),\n}\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    ok(&r, &["update"]);
    let (c, o) = pipe(&r, &["endpoint", "/api/orders"], &["code", "-"]);
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("OrderResource.java") && o.contains("public String list()"), "{o}");
}

#[test]
fn raw_prints_exact_text_and_refuses_masked_anchor_lines() {
    let (_d, r) = repo();
    let (c, o, _) = run(&r, &["code", "src/small.ts:6-8", "--raw"]);
    assert_eq!((c, o.as_str()), (0, "  bar(x: number) {\n    return x + 1;\n  }\n"));
    let (c, o, _) = run(&r, &["code", "src/conf.ts:1-3", "--raw"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("aix: masked line src/conf.ts:2") && !o.contains("Zq81xKvPlmHunterQ") && !o.contains("***"), "{o}");
    assert!(o.starts_with("export const a = 1;\n"), "{o}");
    // anchors
    let (c, o, _) = run(&r, &["anchor", "src/small.ts", "return", "  return 1;", "nothing here"]);
    assert_eq!(c, 1);
    assert!(o.contains("NOT unique: 3 occurrences (lines 2, 7, 10)") && o.contains("unique (1 occurrence, line 2)") && o.contains("0 occurrences"), "{o}");
    assert_eq!(run(&r, &["anchor", "src/small.ts", "  bar(x: number) {\n    return x + 1;"]).0, 0);
    let (c, o, _) = run(&r, &["anchor", "src/conf.ts", "const password = \"***\""]);
    assert_eq!(c, 2);
    assert!(o.contains("masked (redacted) text") && !o.contains("Zq81xKvPlmHunterQ"), "{o}");
    let (c, o, _) = run(&r, &["anchor", "src/conf.ts", "const password = \"Zq81xKvPlmHunterQ\""]);
    assert_eq!(c, 1, "a secret typed as an anchor is never confirmed: {o}");
    assert_eq!(run(&r, &["code", "src/small.ts:6-8", "--check-unique"]).0, 0);
    assert_eq!(run(&r, &["code", "src/conf.ts:1-3", "--check-unique"]).0, 2);
}

#[test]
fn unindexed_files_under_the_repo_are_read_from_disk_and_secrets_never() {
    let (d, r) = repo();
    let o = ok(&r, &["tail", "-n", "2", "build/out.log"]);
    assert!(o.contains("log line 49") && o.contains("log line 50") && o.contains("(not indexed: read from disk)"), "{o}");
    assert!(ok(&r, &["code", "build/out.log:10-11"]).contains("log line 10"));
    assert!(ok(&r, &["sed", "-n", "3p", "build/out.log", "--bare"]) == "log line 3\n");
    std::fs::write(d.path().join("outside.txt"), "OUTSIDE_MARK\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(d.path().join("outside.txt"), r.join("build/link.txt")).unwrap();
    for a in [&["cat", ".env"][..], &["head", ".git/config"], &["cat", "../outside.txt"], &["cat", "/etc/hostname"], &["cat", "build/link.txt"], &["code", ".env:1"]] {
        // the symlink and /etc cases are Unix only
        if cfg!(not(unix)) && matches!(a[1], "/etc/hostname" | "build/link.txt") {
            continue;
        }
        let (c, o, _) = run(&r, a);
        assert_eq!(c, 2, "{a:?}: {o}");
        assert!(!o.contains("supersecretvalue") && !o.contains("OUTSIDE_MARK"), "{a:?}: {o}");
    }
    // a missing file: exit 1
    assert_eq!(run(&r, &["cat", "build/missing.log"]).0, 1);
}

#[test]
fn diff_two_files_against_head_and_revisions_bounded_and_redacted() {
    let (_d, r) = repo();
    write(&r, "build/small2.ts", &SMALL.replace("return 1", "return 2"));
    let (c, o, _) = run(&r, &["diff", "src/small.ts", "build/small2.ts", "--bare"]);
    assert_eq!(c, 0, "{o}");
    if let Some(_g) = gnu("diff") {
        let want = shell(&r, "diff", &["-u", "src/small.ts", "build/small2.ts"]);
        let hunks = |s: &str| s.lines().filter(|l| !l.starts_with("diff --git") && !l.starts_with("index ") && !l.starts_with("--- ") && !l.starts_with("+++ ")).collect::<Vec<_>>().join("\n");
        assert_eq!(hunks(&o), hunks(&want));
    }
    assert_eq!(run(&r, &["diff", "src/small.ts", "src/small.ts"]).0, 1);
    // vs HEAD, redacted
    write(&r, "src/conf.ts", "export const a = 1;\nconst password = \"Yy71aKvPlmOtherQ\";\nexport const b = 2;\n");
    let o = ok(&r, &["diff", "src/conf.ts"]);
    assert!(o.contains("-const password") && !o.contains("Yy71aKvPlmOtherQ") && !o.contains("Zq81xKvPlmHunterQ"), "{o}");
    let (c, raw, _) = run(&r, &["diff", "src/conf.ts", "--raw"]);
    assert_eq!(c, 2, "{raw}");
    assert!(ok(&r, &["diff", "HEAD", "--stat"]).contains("src/conf.ts"));
    assert!(ok(&r, &["diff", "--name-only"]).contains("src/conf.ts"));
    // revisions and a per-file cap with the exact continuation
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "two"]);
    write(&r, "src/big.ts", &big_ts().replace("step", "STEP"));
    git(&r, &["commit", "-q", "-am", "three"]);
    let o = ok(&r, &["diff", "HEAD~1..HEAD"]);
    assert!(o.contains("more lines of src/big.ts: aix diff --full HEAD~1..HEAD -- src/big.ts"), "{o}");
    assert!(ok(&r, &["diff", "--full", "HEAD~1..HEAD", "--", "src/big.ts"]).contains("STEP 299"));
    assert!(ok(&r, &["diff", "HEAD~2", "HEAD", "--name-only"]).contains("src/conf.ts"));
    // a secret path is refused
    assert_eq!(run(&r, &["diff", ".env", "src/small.ts"]).0, 2);
}

struct Mcp {
    c: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
}

impl Mcp {
    fn start(r: &Path) -> Mcp {
        let mut c = cmd(r).arg("mcp").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let stdin = c.stdin.take().unwrap();
        let lines = BufReader::new(c.stdout.take().unwrap()).lines();
        let mut m = Mcp { c, stdin, lines };
        m.send(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}));
        m.recv(1);
        m.send(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        m
    }
    fn send(&mut self, v: serde_json::Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }
    fn recv(&mut self, id: i64) -> serde_json::Value {
        loop {
            let l = self.lines.next().expect("server closed").unwrap();
            let v: serde_json::Value = serde_json::from_str(&l).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }
    fn call(&mut self, id: i64, command: &str, args: &str) -> (String, bool) {
        self.send(serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "aix", "arguments": {"command": command, "args": args}}}));
        let v = self.recv(id);
        (v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string(), v["result"]["isError"].as_bool().unwrap_or(false))
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.c.kill();
        let _ = self.c.wait();
    }
}

#[test]
fn the_same_commands_over_mcp() {
    let (_d, r) = repo();
    let mut m = Mcp::start(&r);
    let (t, e) = m.call(2, "sed", "-n '2,3p' src/small.ts --bare");
    assert!(!e && t.ends_with("  return 1;\n}"), "{t}");
    let (t, _) = m.call(3, "code", "src/small.ts:1-3 Foo.baz");
    assert!(t.contains("src/small.ts:1-3") && t.contains("Foo.baz"), "{t}");
    let (t, _) = m.call(4, "tail", "-n 1 build/out.log");
    assert!(t.contains("log line 50"), "{t}");
    let (t, e) = m.call(5, "code", "src/conf.ts:1-3 --raw");
    assert!(e && t.contains("masked line"), "{t}");
    // stdin is the protocol there: `-` is refused with the in-call pipe named
    let (t, e) = m.call(6, "code", "-");
    assert!(e && t.contains("in-call pipe"), "{t}");
    let (t, e) = m.call(7, "anchor", "src/small.ts 'return 1;'");
    assert!(!e && t.contains("unique"), "{t}");
}
