//! Clones and worktrees of an indexed repo: the first query copies the parent's index (no setup, no full build), the
//! parent's .gitignore acceptance carries over (also with a symlinked node_modules), and the PreToolUse hook names the
//! exact one-time command in a checkout with no index instead of a query that cannot answer; repeated reads of one
//! file get the bounded alternative; `stats --hooks` says which nudges were followed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

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

fn aix_in(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    aix_env(home, args, stdin, &[])
}

fn aix_env(home: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    for (k, v) in env {
        c.env(k, v);
    }
    c.args(args)
        .env("AIX_EMBED_URL", "")
        .env("HOME", home)
        .env("TMPDIR", home)
        .env_remove("AIX_HOOK")
        .env_remove("AIX_ACCEPT_IGNORE")
        .env_remove("AIX_SEED")
        .env_remove("AIX_DB")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    {
        use std::io::Write;
        let mut i = ch.stdin.take().unwrap();
        i.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
    }
    ch.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// A small Node+Rust-ish repo whose .gitignore has findings (so the first build asks), accepted and indexed.
fn parent(d: &Path) -> PathBuf {
    let r = d.join("proj");
    for i in 1..=12 {
        write(&r, &format!("src/m{i}.rs"), &format!("pub fn f{i}(x: i32) -> i32 {{\n    x + {i}\n}}\n"));
    }
    write(&r, "frontend/package.json", "{}\n");
    write(&r, "frontend/src/app.ts", "export const app = 1;\n");
    write(&r, ".gitignore", "**/node_modules/\n.scratch/\n");
    std::fs::create_dir_all(r.join("frontend/node_modules/x")).unwrap();
    write(&r, "frontend/node_modules/x/index.js", "module.exports = 1;\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    let rs = r.display().to_string();
    // the first build stops for the user's decision; the user accepts once
    let o = aix_in(d, &["--repo", &rs, "stats"], None);
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("STOP"), "{}", out(&o));
    let o = aix_in(d, &["--repo", &rs, "--accept-ignore", "stats"], None);
    assert!(o.status.success(), "{}", out(&o));
    r
}

#[test]
fn a_clone_answers_its_first_query_from_the_parent_index() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let p = parent(d);
    let c = d.join("clone");
    let o = Command::new("git").args(["clone", "-q"]).arg(&p).arg(&c).output().unwrap();
    assert!(o.status.success());
    // a change only the clone has: the copied index must not answer with the parent's text
    write(&c, "src/m3.rs", "pub fn f3(x: i32) -> i32 {\n    x * 33\n}\n");
    let cs = c.display().to_string();
    let o = aix_in(d, &["--repo", &cs, "grep", "x \\* 33|x \\+ 3$"], None);
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("copied from"), "seeded from the parent: {s}");
    assert!(s.contains("src/m3.rs:2") && s.contains("x * 33") && !s.contains("x + 3\n"), "{s}");
    assert!(c.join(".aix/index.db").is_file() && c.join(".aix/.gitignore").is_file());
    // the parent's index is untouched and still its own
    let o = aix_in(d, &["--repo", &p.display().to_string(), "grep", "x \\* 33"], None);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    // a second query is an ordinary one
    let o = aix_in(d, &["--repo", &cs, "outline", "src/m3.rs"], None);
    assert!(o.status.success() && !out(&o).contains("copied from"), "{}", out(&o));
    // opting out builds from scratch
    let c2 = d.join("clone2");
    assert!(Command::new("git").args(["clone", "-q"]).arg(&p).arg(&c2).status().unwrap().success());
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aix"));
    let o = cmd.args(["--repo", &c2.display().to_string(), "stats"]).env("HOME", d).env("TMPDIR", d).env("AIX_SEED", "0").env("AIX_EMBED_URL", "").output().unwrap();
    assert!(o.status.success() && !out(&o).contains("copied from"), "{}", out(&o));
}

// a symlinked directory: needs admin or developer mode on Windows
#[cfg(unix)]
#[test]
fn a_worktree_with_a_symlinked_node_modules_keeps_the_parent_acceptance() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let p = parent(d);
    let w = d.join("wt");
    git(&p, &["worktree", "add", "-q", &w.display().to_string()]);
    // the usual way to give a worktree its dependencies: a symlink to the main tree's (untracked: `node_modules/`
    // matches directories only)
    std::os::unix::fs::symlink(p.join("frontend/node_modules"), w.join("frontend/node_modules")).unwrap();
    let ws = w.display().to_string();
    let o = aix_in(d, &["--repo", &ws, "ignore-check"], None);
    assert!(!out(&o).contains("node_modules/ (present, untracked)"), "{}", out(&o));
    let o = aix_in(d, &["--repo", &ws, "outline", "src/m2.rs"], None);
    let s = out(&o);
    assert!(o.status.success() && !s.contains("STOP"), "{s}");
    assert!(s.contains("f2"), "{s}");
}

fn bash_ev(cwd: &Path, sid: &str, cmd: &str) -> String {
    json!({"session_id": sid, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd.display().to_string()}).to_string()
}

fn hook(d: &Path, project: &Path, ev: &str) -> String {
    // nudges only (the deny-with-answer path has its own tests)
    let o = aix_env(d, &["--repo", &project.display().to_string(), "hook", "pretool"], Some(ev), &[("AIX_HOOK_DENY", "0")]);
    assert!(o.status.success());
    let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if s.is_empty() {
        return s;
    }
    let v: Value = serde_json::from_str(&s).expect("one JSON object");
    v["hookSpecificOutput"]["additionalContext"].as_str().unwrap_or("").to_string()
}

#[test]
fn the_hook_names_the_one_time_index_command_in_an_unindexed_checkout() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let p = parent(d);
    // a scratch clone under the project (its .scratch/ is ignored, so the project's index cannot answer there)
    let k = p.join(".scratch/k");
    assert!(Command::new("git").args(["clone", "-q"]).arg(&p).arg(&k).status().unwrap().success());
    // native separators throughout (on Windows `join(".scratch/k")` keeps the '/'), as aix prints the checkout
    let ks = k.display().to_string().replace('/', std::path::MAIN_SEPARATOR_STR);
    // a bash command spells it with '/' (an unquoted \ is an escape in Git Bash)
    let cmd = format!("cd {} && sed -n 1,3p src/m1.rs", ks.replace('\\', "/"));
    let s = hook(d, &p, &bash_ev(&p, "s1", &cmd));
    assert!(s.contains(&format!("aix --repo {ks} stats")) || s.contains(&format!("aix --repo '{ks}' stats")), "{s}");
    assert!(s.contains("copies that index") && s.contains("aix code src/m1.rs:1-3"), "{s}");
    // once per session
    assert_eq!(hook(d, &p, &bash_ev(&p, "s1", &cmd.replace("m1", "m2"))), "");
    // the named command works and then the ordinary steering applies, with the clone's own index
    let o = aix_in(d, &["--repo", &ks, "stats"], None);
    assert!(o.status.success(), "{}", out(&o));
    let s = hook(d, &p, &bash_ev(&p, "s1", &cmd));
    assert!(s.contains("aix code src/m1.rs:1-3") && !s.contains("no index yet"), "{s}");
    // a repo that is nobody's clone: the build command with its size (no .gitignore findings to stop on)
    let o = d.join("other");
    write(&o, "lib/a.py", "def a():\n    return 1\n");
    write(&o, ".gitignore", ".env*\n.DS_Store\n__pycache__/\n*.pyc\n.venv/\nvenv/\n.pytest_cache/\n.mypy_cache/\n.ruff_cache/\nbuild/\ndist/\n*.egg-info/\n.tox/\n.coverage\nhtmlcov/\n");
    git(&o, &["init", "-q", "-b", "main"]);
    git(&o, &["add", "-A"]);
    git(&o, &["commit", "-q", "-m", "init"]);
    let os = o.display().to_string().replace('\\', "/");
    let s = hook(d, &p, &bash_ev(&p, "s2", &format!("cd {os} && cat lib/a.py")));
    assert!(s.contains("has no index yet"), "{s}");
    assert!((s.contains("builds it (2 tracked files") && s.contains("aix cat lib/a.py")) || s.contains("ignore-check"), "{s}");
    // a non-lookup in an unindexed checkout: silent
    assert_eq!(hook(d, &p, &bash_ev(&p, "s3", &format!("cd {os} && git status"))), "");
}

#[test]
fn repeated_reads_name_the_bounded_way_and_stats_count_followed_nudges() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let p = parent(d);
    let ev = |sid: &str, c: &str| bash_ev(&p, sid, c);
    let a = hook(d, &p, &ev("r", "sed -n 1,2p src/m5.rs"));
    assert!(a.contains("aix code src/m5.rs:1-2") && !a.contains("read 3 times"), "{a}");
    let b = hook(d, &p, &ev("r", "sed -n 2,3p src/m5.rs"));
    assert!(!b.contains("times in this session"), "{b}");
    let c = hook(d, &p, &ev("r", "cat src/m5.rs"));
    assert!(c.contains("src/m5.rs read 3 times in this session") && c.contains("aix outline src/m5.rs") && c.contains("KB of output so far"), "{c}");
    // another session starts from zero
    assert!(!hook(d, &p, &ev("other", "cat src/m5.rs")).contains("times in this session"));
    // the session then uses aix: its nudges count as followed; the other session's is still open
    hook(d, &p, &ev("r", "aix outline src/m5.rs"));
    let o = aix_in(d, &["--repo", &p.display().to_string(), "stats", "--hooks"], None);
    let s = out(&o);
    assert!(s.contains("nudges followed: 3") && s.contains("open: 1"), "{s}");
}

#[test]
fn a_query_over_a_saved_set_needs_no_index_and_so_no_gitignore_decision() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let r = d.join("proj");
    write(&r, "src/m1.rs", "pub fn f1() {}\n");
    write(&r, "frontend/src/app.ts", "export const app = 1;\n");
    write(&r, "frontend/node_modules/x/index.js", "module.exports = 1;\n"); // tracked: the first build must stop
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    let rs = r.display().to_string();
    let o = aix_in(d, &["--repo", &rs, "put", "t", "-"], Some("alpha\nbeta needle\n"));
    assert!(o.status.success(), "{}", out(&o));
    let o = aix_in(d, &["--repo", &rs, "grep", "needle", "@t"], None);
    assert!(o.status.success() && out(&o).contains("beta needle") && !out(&o).contains("STOP"), "{}", out(&o));
    // the set query built nothing: a repo query still waits for the user's decision
    let o = aix_in(d, &["--repo", &rs, "grep", "f1"], None);
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
}
