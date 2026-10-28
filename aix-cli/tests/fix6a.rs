//! FIX-6A: options in any position, paths in any spelling, exit codes, find cut-offs, hints agreement, credential-named
//! files, `-x` / `--` in grep, outline footer, curated `howto`.

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
    c.arg("--repo").arg(repo).env("AIX_EMBED_URL", "").env("HOME", repo);
    c
}

/// (exit status, stdout, stderr)
fn run(repo: &Path, args: &[&str]) -> (i32, String, String) {
    let o = cmd(repo).args(args).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn ok(repo: &Path, args: &[&str]) -> String {
    let (c, o, e) = run(repo, args);
    assert_eq!(c, 0, "aix {args:?}: {e}{o}");
    o
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    for (p, b) in files {
        write(&r, p, b);
    }
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    ok(&r, &["update"]);
    (d, r)
}

fn base() -> Vec<(String, String)> {
    let mut v = vec![
        ("frontend/src/App.tsx".to_string(), "export function main() { return helper(); }\nexport function helper() { return 1; }\nclass Widget {\n  render() { return main(); }\n}\n".to_string()),
        ("frontend/src/pages/Home.tsx".to_string(), "export function Home() { return main(); }\n".to_string()),
        ("scripts/list.sh".to_string(), "#!/bin/sh\n# list things\necho list\n".to_string()),
        ("TODO.md".to_string(), "# T\n- [ ] open one\n- [x] done\n- [ ] open two\n- [ ] open three\n- [ ] open four\n".to_string()),
    ];
    let mut big = String::new();
    for i in 1..=100 {
        big.push_str(&format!("line {i} needle\n"));
    }
    v.push(("docs/big.txt".to_string(), big));
    for i in 0..30 {
        v.push((format!("src/n{i}.md"), format!("# zebra note {i}\nfindme zebra\n")));
    }
    v
}

fn base_repo() -> (tempfile::TempDir, PathBuf) {
    let b = base();
    let refs: Vec<(&str, &str)> = b.iter().map(|(a, c)| (a.as_str(), c.as_str())).collect();
    repo(&refs)
}

#[test]
fn options_are_read_in_any_position_and_unknown_ones_are_errors() {
    let (_d, r) = base_repo();
    // a trailing --limit is the limit, not part of the symbol
    for args in [&["callers", "main", "--limit", "3"][..], &["callers", "main", "--max", "3"], &["callers", "--limit", "3", "main"], &["callers", "main", "--limit=3"], &["symbol", "main", "--limit", "2"], &["callees", "main", "--limit", "2"]] {
        let o = ok(&r, args);
        assert!(!o.contains(": none"), "{args:?}: {o}");
        assert!(o.contains("App.tsx"), "{args:?}: {o}");
    }
    let t = ok(&r, &["tasks", "open", "--limit", "3"]);
    assert!(t.contains("== tasks (open) (the 3 newest of 4)") && t.contains("(1 older: aix tasks open --limit 3 --page 2"), "{t}");
    assert_eq!(t.matches("[open task]").count(), 3, "{t}");
    // code ... --count is the member's header, not a false none
    let c = ok(&r, &["code", "main", "--count"]);
    assert!(c.contains("function main frontend/src/App.tsx:1-1 (1 lines)") && !c.contains("export function main()"), "{c}");
    // --full on a listing, --repo after the query
    ok(&r, &["tasks", "open", "--full"]);
    let rr = r.to_str().unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).args(["callers", "main", "--repo", rr]).env("AIX_EMBED_URL", "").env("HOME", &r).current_dir(std::env::temp_dir()).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("call sites"), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    // an unknown --flag is an error naming the supported ones
    for args in [&["callers", "main", "--bogus"][..], &["tasks", "open", "--nope", "3"], &["code", "main", "--wat"], &["outline", "frontend/src/App.tsx", "--zzz"]] {
        let (c, o, e) = run(&r, args);
        assert_eq!(c, 2, "{args:?}: {o}{e}");
        assert!(format!("{o}{e}").contains("unknown option") && format!("{o}{e}").contains("--limit N"), "{args:?}: {o}{e}");
    }
    let (c, o, e) = run(&r, &["callers", "main", "--limit", "x"]);
    assert_eq!(c, 2, "{o}{e}");
    // documented flags keep working
    assert_eq!(run(&r, &["callers", "main", "--exists"]).0, 0);
    assert!(ok(&r, &["trace", "main", "--up", "--depth", "2"]).len() > 0);
}

#[test]
fn grep_takes_limit_max_full_and_mcp_limit_is_honoured() {
    let (_d, r) = base_repo();
    let files = |o: &str| o.lines().filter(|l| l.starts_with("  src/n")).count();
    let d = ok(&r, &["grep", "findme"]);
    assert_eq!(files(&d), 15, "{d}");
    for args in [&["grep", "findme", "--limit", "3"][..], &["grep", "findme", "--max", "3"], &["grep", "--limit=3", "findme"]] {
        let o = ok(&r, args);
        assert_eq!(files(&o), 3, "{args:?}: {o}");
    }
    let f = ok(&r, &["grep", "findme", "--full"]);
    assert_eq!(files(&f), 30, "{f}");
    // after -- everything is the pattern
    let (c, o, _) = run(&r, &["grep", "--", "--limit"]);
    assert_eq!(c, 1, "{o}");
    // MCP: the limit argument and the in-string flags
    let mut m = Mcp::start(&r);
    let v = m.call(2, serde_json::json!({"command": "grep", "args": "findme", "limit": 4}));
    assert_eq!(files(v["result"]["content"][0]["text"].as_str().unwrap()), 4, "{v}");
    let v = m.call(3, serde_json::json!({"command": "grep", "args": "findme --limit 2"}));
    assert_eq!(files(v["result"]["content"][0]["text"].as_str().unwrap()), 2, "{v}");
    let v = m.call(4, serde_json::json!({"command": "callers", "args": "main --limit 3"}));
    assert!(v["result"]["content"][0]["text"].as_str().unwrap().contains("call sites"), "{v}");
    let v = m.call(5, serde_json::json!({"command": "callers", "args": "main --bogus"}));
    assert_eq!(v["result"]["isError"], true, "{v}");
}

#[test]
fn paths_in_any_spelling_and_path_not_found() {
    let (_d, r) = base_repo();
    let want = "== outline frontend/src/App.tsx";
    for p in ["./frontend/src/App.tsx", "frontend\\src\\App.tsx", "frontend//src/App.tsx", "frontend/src/App.tsx", "App.tsx"] {
        assert!(ok(&r, &["outline", p]).contains(want), "outline {p}");
    }
    for p in ["./frontend/src/App.tsx:1-2", "frontend\\src\\App.tsx:1-2", "frontend//src//App.tsx:1-2"] {
        assert!(ok(&r, &["code", p]).contains("frontend/src/App.tsx:1-2"), "code {p}");
    }
    // history of a bare basename
    assert!(ok(&r, &["history", "App.tsx"]).contains("== frontend/src/App.tsx: 1 commits"));
    assert!(ok(&r, &["history", "./frontend/src/App.tsx"]).contains("1 commits"));
    // grep paths: ./x, x\y, x//y, trailing slash
    for p in ["./frontend/src/pages", "frontend\\src\\pages", "frontend//src/pages", "frontend/src/pages/"] {
        let o = ok(&r, &["grep", "main", p]);
        assert!(o.contains("frontend/src/pages/Home.tsx:1") && !o.contains("App.tsx"), "grep {p}: {o}");
    }
    // relative to a subdirectory working directory
    let sub = r.join("frontend/src");
    let sh = |args: &[&str]| {
        let o = cmd(&r).args(args).current_dir(&sub).output().unwrap();
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let (c, o) = sh(&["grep", "main", "pages"]);
    assert!(c == 0 && o.contains("pages/Home.tsx:1") && !o.contains("App.tsx"), "{o}");
    let (c, o) = sh(&["outline", "./App.tsx"]);
    assert!(c == 0 && o.contains(want), "{o}");
    // a path that matches nothing says so, with status 1
    for args in [&["grep", "main", "nope/dir"][..], &["outline", "nope/File.tsx"], &["history", "nope/File.tsx"], &["history", "Nothing.tsx"], &["code", "nope/File.tsx:1-3"], &["code", "nope/File.tsx"]] {
        let (c, o, e) = run(&r, args);
        assert_eq!(c, 1, "{args:?}: {o}{e}");
        assert!(o.contains("path not found: "), "{args:?}: {o}");
        assert!(!o.contains("0 matching"), "{args:?}: {o}");
    }
}

#[test]
fn code_of_a_plain_file_takes_max_and_full() {
    let (_d, r) = base_repo();
    // 100 lines: under the soft cap (200), shown whole
    let c = ok(&r, &["code", "docs/big.txt"]);
    assert!(c.contains("docs/big.txt:1-100 (100 lines)") && c.contains("line 100 needle") && !c.contains("more lines"), "{c}");
    let c = ok(&r, &["code", "docs/big.txt", "--max", "60"]);
    assert!(c.contains("docs/big.txt:1-100 (100 lines, 60 shown)") && c.contains("more lines") && c.contains("--max 100 / --full"), "{c}");
    let m = ok(&r, &["code", "docs/big.txt", "--max", "10"]);
    assert!(m.contains("(100 lines, 10 shown)") && m.contains("line 10 needle") && !m.contains("line 11 needle"), "{m}");
    let f = ok(&r, &["code", "docs/big.txt", "--full"]);
    assert!(f.contains("line 100 needle") && !f.contains("more lines"), "{f}");
    // the form the footer suggests
    let m2 = ok(&r, &["code", "docs/big.txt:1-100", "--max", "5"]);
    assert!(m2.contains("(100 lines, 5 shown)"), "{m2}");
}

#[test]
fn exit_codes_are_0_found_1_none_2_error() {
    let (_d, r) = base_repo();
    assert_eq!(run(&r, &["callers", "main"]).0, 0);
    assert_eq!(run(&r, &["grep", "needle"]).0, 0);
    for args in [&["callers", "nosuchsymbolzz"][..], &["symbol", "nosuchsymbolzz"], &["grep", "qqqqnotthere"], &["find", "qqqqnotthere"], &["tasks", "done", "qqqqnotthere"], &["code", "nosuchsymbolzz"], &["endpoint", "/nope"]] {
        let (c, o, e) = run(&r, args);
        assert_eq!(c, 1, "{args:?}: {o}{e}");
    }
    // usage and refusals are 2
    for args in [&["sql", "drop table files"][..], &["sql", "select from"], &["brief"], &["code"], &["grep"], &["grep", "-x"], &["grep", "[unclosed"], &["callers", "x", "--bogus"]] {
        let (c, o, e) = run(&r, args);
        assert_eq!(c, 2, "{args:?}: {o}{e}");
    }
    // an unknown subcommand piped into head: no SIGPIPE status, quiet stderr
    // bash words: '/' separators (an unquoted \ is an escape in Git Bash)
    let (exe, rs) = (env!("CARGO_BIN_EXE_aix").replace('\\', "/"), r.display().to_string().replace('\\', "/"));
    let sh = format!("set -o pipefail; {exe} --repo {rs} nosuchcommand 2>&1 | head -1; echo status=${{PIPESTATUS[0]}}");
    let o = Command::new("bash").args(["-c", &sh]).env("HOME", &r).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("status=2") && !s.contains("141") && !s.contains("panicked"), "{s}");
    let sh = format!("set -o pipefail; {exe} --repo {rs} grep -i . 2>&1 | head -1; echo status=${{PIPESTATUS[0]}}");
    let o = Command::new("bash").args(["-c", &sh]).env("HOME", &r).output().unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(!s.contains("141") && !s.contains("panicked") && !s.contains("Broken pipe"), "{s}");
    // MCP: errors are isError, none is a structured marker
    let mut m = Mcp::start(&r);
    let e = m.call(2, serde_json::json!({"command": "sql", "args": "drop table files"}));
    assert_eq!(e["result"]["isError"], true, "{e}");
    let n = m.call(3, serde_json::json!({"command": "symbol", "args": "nosuchsymbolzz"}));
    assert!(n["result"]["isError"] != true, "{n}");
    assert_eq!(n["result"]["structuredContent"]["none"], true, "{n}");
    let f = m.call(4, serde_json::json!({"command": "symbol", "args": "main"}));
    assert!(f["result"]["structuredContent"].is_null(), "{f}");
    let u = m.call(5, serde_json::json!({"command": "grep", "args": "-x"}));
    assert_eq!(u["result"]["isError"], true, "{u}");
}

#[test]
fn find_says_when_it_is_cut_off_and_marks_json_truncated() {
    let (_d, r) = base_repo();
    let o = ok(&r, &["find", "zebra"]);
    assert!(o.contains("(20 of 30 hits; next: aix find zebra --page 2 --gen "), "{o}");
    let p2 = ok(&r, &["find", "zebra", "--page", "2"]);
    assert!(p2.contains("page 2 of 2"), "{p2}");
    let j = ok(&r, &["find", "zebra", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(v["truncated"], true, "{j}");
    let l = ok(&r, &["find", "zebra", "--jsonl"]);
    let last: serde_json::Value = serde_json::from_str(l.lines().last().unwrap()).unwrap();
    assert_eq!(last["summary"]["truncated"], true, "{l}");
    // nothing cut off: no note, truncated false/absent
    let s = ok(&r, &["find", "zebra", "--limit", "30"]);
    assert!(!s.contains("hits; next:"), "{s}");
    let l = ok(&r, &["find", "zebra", "--limit", "30", "--jsonl"]);
    let last: serde_json::Value = serde_json::from_str(l.lines().last().unwrap()).unwrap();
    assert_eq!(last["summary"]["truncated"], false, "{l}");
}

#[test]
fn hints_all_agrees_across_exists_count_and_limit() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("webapp");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/webapp"), &r);
    // a page whose read call a visible role cannot make: a role-gap lead (see cli.rs)
    let app = r.join("frontend/src/App.tsx");
    let a = std::fs::read_to_string(&app).unwrap();
    let a = a
        .replace("const Reports =", "const Ledger = lazy(() => import('./pages/Ledger'))\nconst Reports =")
        .replace("        <Route path=\"reports\"", "        <Route path=\"ledger\" element={<ProtectedRoute requiredRoles={['clerk', 'auditor']}><Ledger /></ProtectedRoute>} />\n        <Route path=\"reports\"");
    std::fs::write(&app, a).unwrap();
    write(&r, "frontend/src/pages/Ledger.tsx", "import { ordersApi } from '../lib/api'\nexport default function Ledger() {\n  ordersApi.list('open')\n  return <div>Ledger</div>\n}\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    ok(&r, &["update"]);
    let all = ok(&r, &["hints", "all"]);
    let rows = all.lines().filter(|l| l.starts_with("  ") && l.contains(" | ")).count();
    assert!(rows >= 1, "{all}");
    // --exists, --count and the listing agree
    let e = ok(&r, &["hints", "all", "--exists"]);
    assert!(e.starts_with("yes (first: /"), "{e}");
    let c = ok(&r, &["hints", "all", "--count"]);
    assert!(c.contains(&format!("{rows} rows")), "{rows}: {c}");
    let l = ok(&r, &["hints", "all", "--limit", "1"]);
    assert_eq!(l.lines().filter(|l| l.starts_with("  ") && l.contains(" | ")).count(), 1, "{l}");
    // no leads: --exists says no with status 1 and --count says 0 rows
    let (_d2, r2) = base_repo();
    let (c, o, _) = run(&r2, &["hints", "all", "--exists"]);
    assert!(c == 1 && o.starts_with("no"), "{o}");
    assert!(run(&r2, &["hints", "all", "--count"]).1.contains("0 rows"));
    assert_eq!(run(&r2, &["hints", "all", "--limit", "3"]).0, 1);
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let t = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

#[test]
fn a_credential_looking_file_name_never_masks_its_path_line_prefix() {
    let (_d, r) = repo(&[
        ("frontend/src/pages/ChangePasswordModal.tsx", "export function ChangePasswordModal() {\n  const label = 'Change password';\n  return label;\n}\n"),
        ("frontend/src/secret_token_form.ts", "export function tokenForm() {\n  return 'token form';\n}\n"),
    ]);
    for (args, want) in [
        (vec!["grep", "label"], "ChangePasswordModal.tsx:2"),
        (vec!["grep", "-l", "label"], "ChangePasswordModal.tsx"),
        (vec!["find", "Change password"], "ChangePasswordModal.tsx:2"),
        (vec!["outline", "ChangePasswordModal.tsx"], "== outline frontend/src/pages/ChangePasswordModal.tsx"),
        (vec!["code", "frontend/src/pages/ChangePasswordModal.tsx:1-3"], "ChangePasswordModal.tsx:1-3"),
        (vec!["code", "ChangePasswordModal"], "ChangePasswordModal.tsx:1-"),
        (vec!["text", "Change password"], "ChangePasswordModal.tsx:2"),
        (vec!["brief", "frontend/src/pages/ChangePasswordModal.tsx"], "ChangePasswordModal.tsx"),
        (vec!["symbol", "tokenForm"], "secret_token_form.ts:1"),
        (vec!["grep", "token form"], "secret_token_form.ts:2"),
    ] {
        let (c, o, e) = run(&r, &args);
        assert!(c == 0 || c == 1, "{args:?}: {o}{e}");
        assert!(!o.contains(".tsx:***") && !o.contains(".ts:***") && !o.contains(":***:"), "{args:?}: {o}");
        assert!(o.contains(want), "{args:?} should contain {want}: {o}");
    }
    // the same through MCP (it used to redact the finished text a second time)
    let mut m = Mcp::start(&r);
    let v = m.call(2, serde_json::json!({"command": "grep", "args": "label"}));
    let t = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(t.contains("ChangePasswordModal.tsx:2") && !t.contains(":***"), "{t}");
    // a real secret in the row text is still masked
    let (_d2, r2) = repo(&[("frontend/ChangePasswordModal.tsx", "const password = 'hunter2hunter2';\n")]);
    let g = ok(&r2, &["grep", "password"]);
    assert!(g.contains("ChangePasswordModal.tsx:1:") && !g.contains("hunter2hunter2"), "{g}");
}

#[test]
fn grep_dashes_and_x_are_the_same_in_the_cli_and_mcp() {
    let (_d, r) = base_repo();
    // `--` makes the rest literal: a pattern that starts with -x searches for it
    write(&r, "dash.txt", "use -x here\nplain\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "dash"]);
    ok(&r, &["update"]);
    let cli = ok(&r, &["grep", "--", "-x"]);
    assert!(cli.contains("dash.txt:1: use -x here"), "{cli}");
    let mut m = Mcp::start(&r);
    let v = m.call(2, serde_json::json!({"command": "grep", "args": "-- -x"}));
    let t = v["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(v["result"]["isError"].as_bool().unwrap_or(false), false, "{v}");
    assert_eq!(t.lines().filter(|l| l.contains("dash.txt:1")).count(), 1, "{t}");
    // a bare -x with no pattern is a usage error in both
    assert_eq!(run(&r, &["grep", "-x"]).0, 2);
    let v = m.call(3, serde_json::json!({"command": "grep", "args": "-x"}));
    assert_eq!(v["result"]["isError"], true, "{v}");
    // -x followed by a kind / glob list excludes; otherwise it is the whole-line flag; --line-regexp always is
    let (c, ex, _) = run(&r, &["grep", "needle", "-x", "docs"]);
    assert!(c == 1 && (ex.contains("no match") || ex.contains("0 matching")), "{ex}");
    let wl = ok(&r, &["grep", "-x", "plain"]);
    assert!(wl.contains("dash.txt:2"), "{wl}");
    let lr = ok(&r, &["grep", "--line-regexp", "plain"]);
    assert!(lr.contains("dash.txt:2"), "{lr}");
    assert!(run(&r, &["grep", "--line-regexp", "plai"]).1.contains("0 matching"));
    // the help names both meanings
    let (_, h, e) = run(&r, &["grep", "--bogus-flag", "x"]);
    assert!(format!("{h}{e}").contains("--line-regexp") && format!("{h}{e}").contains("whole line"), "{h}{e}");
}

#[test]
fn outline_footer_names_the_member_body_command() {
    let (_d, r) = base_repo();
    let o = ok(&r, &["outline", "frontend/src/App.tsx"]);
    assert!(o.contains("(a member's body: aix code ") && o.contains("aix code frontend/src/App.tsx:"), "{o}");
}

#[test]
fn howto_answers_common_tasks_with_the_exact_command_first() {
    let (_d, r) = base_repo();
    let tasks: [(&str, &str); 15] = [
        ("list scripts", "aix script"),
        ("show me the existing scripts for deploys", "aix script"),
        ("file history", "aix history"),
        ("what commits touched this file", "aix history"),
        ("who calls this function", "aix callers"),
        ("find all callers of a method", "aix callers"),
        ("read a whole file", "aix code <file> --full"),
        ("read lines 40-80 of a file", "aix code <file>:A-B"),
        ("open tasks", "aix tasks open"),
        ("what is still on the todo list", "aix tasks open"),
        ("find a config property", "aix grep"),
        ("where is this setting defined", "aix grep"),
        ("find files by name", "aix find"),
        ("list the methods of a class file", "aix outline"),
        ("show the method body", "aix code <Class.method"),
    ];
    for (q, want) in tasks {
        let o = ok(&r, &["howto", q]);
        let first = o.lines().nth(1).unwrap_or("");
        assert!(first.trim_start().starts_with(want), "howto {q:?}: first row should start with {want}: {o}");
    }
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
    fn call(&mut self, id: i64, args: serde_json::Value) -> serde_json::Value {
        self.send(serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "aix", "arguments": args}}));
        self.recv(id)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.c.kill();
        let _ = self.c.wait();
    }
}

#[test]
fn endpoint_accepts_a_concrete_url() {
    let java = "import jakarta.ws.rs.*;\n@Path(\"/api/years\")\npublic class YearResource {\n  @GET @Path(\"/{id}\") public String get(@PathParam(\"id\") String id) { return id; }\n}\n";
    let (_d, r) = repo(&[("src/YearResource.java", java)]);
    let o = ok(&r, &["endpoint", "GET /api/years/01ABC"]);
    assert!(o.contains("GET /api/years/{id}"), "{o}");
}
