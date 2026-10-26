//! Deduplication: the `dedup` stage (differential against `awk '!seen[$0]++'` and `sort | uniq -c`), `--norm` shapes
//! (redacted examples), the global `--dedup[=KEY]`, cross-section dedupe in a batch, and the MCP option.

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

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    write(&r, "src/a.rs", "fn alpha() {\n    beta(); // TODO one\n    beta(); // TODO one\n}\nfn beta() {}\n");
    write(&r, "src/b.rs", "fn gamma() {\n    // TODO two\n}\n");
    write(&r, "docs/x.md", "# X\nTODO docs\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    run(&r, &["update"], None);
    (d, r)
}

fn run(repo: &Path, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.current_dir(repo).arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    {
        let mut i = ch.stdin.take().unwrap();
        if let Some(s) = stdin {
            i.write_all(s.as_bytes()).unwrap();
        }
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
}

fn sh(input: &str, script: &str) -> Option<String> {
    let mut c = Command::new("sh").arg("-c").arg(script).env("LC_ALL", "C").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
    c.stdin.take().unwrap().write_all(input.as_bytes()).ok()?;
    let o = c.wait_with_output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// rows with repeats far apart (uniq would keep them), grep-shaped and plain
fn sample() -> String {
    let mut s = String::new();
    for i in 0..300 {
        let k = (i * 7919) % 37;
        if i % 3 == 0 {
            s.push_str(&format!("src/f{}.rs:{}:text {}\n", k % 5, k, k % 4));
        } else {
            s.push_str(&format!("plain line {}\n", k % 11));
        }
    }
    s
}

#[test]
fn dedup_matches_awk_first_seen_and_uniq_c_totals() {
    let (_d, r) = repo();
    let input = sample();
    let (c, got) = run(&r, &["dedup", "-", "--bare"], Some(&input));
    assert_eq!(c, 0, "{got}");
    let rows: Vec<&str> = got.lines().filter(|l| !l.starts_with('\u{2026}')).collect();
    if let Some(want) = sh(&input, "awk '!seen[$0]++'") {
        assert_eq!(rows, want.lines().collect::<Vec<_>>());
    }
    assert!(got.lines().last().unwrap().contains("duplicates removed (by line)"), "{got}");
    // -c: the same totals as sort | uniq -c, in first-appearance order
    let (_, cnt) = run(&r, &["dedup", "-c", "-", "--bare"], Some(&input));
    let mut mine: Vec<(u64, String)> = cnt.lines().filter(|l| !l.starts_with('\u{2026}')).map(|l| {
        let (n, k) = l.split_once('\t').unwrap();
        (n.parse().unwrap(), k.to_string())
    }).collect();
    let first: Vec<String> = mine.iter().map(|x| x.1.clone()).collect();
    assert_eq!(first, rows.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "first-appearance order");
    if let Some(want) = sh(&input, "sort | uniq -c") {
        let mut w: Vec<(u64, String)> = want.lines().map(|l| {
            let t = l.trim_start();
            let (n, k) = t.split_once(' ').unwrap();
            (n.parse().unwrap(), k.to_string())
        }).collect();
        w.sort();
        mine.sort();
        assert_eq!(mine, w);
    }
    // --sort count: descending, ties in first-appearance order
    let (_, s) = run(&r, &["dedup", "-c", "--sort", "count", "-", "--bare"], Some(&input));
    let ns: Vec<u64> = s.lines().filter(|l| !l.starts_with('\u{2026}')).map(|l| l.split('\t').next().unwrap().parse().unwrap()).collect();
    assert!(ns.windows(2).all(|w| w[0] >= w[1]), "{s}");
    // keys
    let (_, f) = run(&r, &["dedup", "file", "-", "--bare"], Some(&input));
    assert_eq!(f.lines().filter(|l| l.starts_with("src/")).count(), 5, "{f}");
    let (c, e) = run(&r, &["dedup", "bogus", "-"], Some("x\n"));
    assert_eq!(c, 2, "{e}");
    // in a pipe, and the global flag
    let (_, p) = run(&r, &["grep TODO | dedup file", "--bare"], None);
    assert_eq!(p.lines().filter(|l| !l.starts_with('\u{2026}')).count(), 3, "{p}");
    let (_, g) = run(&r, &["grep", "TODO", "--dedup=text"], None);
    assert!(g.contains("1 duplicate removed (by text)") && g.matches("TODO one").count() == 1, "{g}");
    // uniq stays adjacent-only (GNU)
    let (_, u) = run(&r, &["pipe", "grep TODO | uniq", "--bare"], None);
    assert!(u.matches("TODO one").count() == 2, "{u}");
}

#[test]
fn norm_collapses_shapes_and_never_shows_a_secret() {
    let (_d, r) = repo();
    let mut log = String::new();
    for i in 0..412 {
        log.push_str(&format!("2026-10-24T10:{:02}:{:02}Z ERROR timeout after {}ms on 10.0.{}.{} req=\"{:x}\"\n", i % 60, i % 60, 100 + i, i % 7, i % 200, 0xdead_0000u64 + i));
        if i % 100 == 0 {
            log.push_str("INFO login password=hunter2secret token AKIAABCDEFGHIJKLMNOP\n");
        }
    }
    let (c, o) = run(&r, &["dedup", "--norm", "-"], Some(&log));
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("412\u{d7}  <TS> ERROR timeout after <N>ms on <IP> req=<STR> (first line 1, last line 417)"), "{o}");
    assert!(o.lines().filter(|l| l.contains('\u{d7}')).count() == 2, "{o}");
    assert!(!o.contains("hunter2secret") && !o.contains("AKIAABCDEFGHIJKLMNOP"), "{o}");
    let (_, b) = run(&r, &["dedup", "--norm", "-", "--bare"], Some(&log));
    assert!(b.lines().next().unwrap().starts_with("412\t<TS> ERROR"), "{b}");
    assert!(!b.contains("hunter2secret") && !b.contains("AKIAABCDEFGHIJKLMNOP"), "{b}");
}

#[test]
fn batch_sections_name_ranges_shown_above() {
    let (_d, r) = repo();
    let (_, o) = run(&r, &["code src/a.rs:1-5 ; code src/a.rs:2-3"], None);
    assert!(o.contains("(src/a.rs:2-3 shown above in == aix code src/a.rs:1-5)"), "{o}");
    let (_, b) = run(&r, &["batch", "code src/a.rs:1-5", "code src/a.rs:2-3"], None);
    assert!(b.contains("shown above in == aix code src/a.rs:1-5"), "{b}");
    let (_, n) = run(&r, &["code src/a.rs:1-5 ; code src/a.rs:2-3", "--no-dedup"], None);
    assert!(!n.contains("shown above") && n.matches("beta(); // TODO one").count() == 4, "{n}");
    // a command run alone is unchanged
    let (_, a) = run(&r, &["code", "src/a.rs:2-3"], None);
    assert!(!a.contains("shown above"), "{a}");
}

#[test]
fn mcp_dedup_option() {
    let (_d, r) = repo();
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.current_dir(&r).arg("--repo").arg(&r).arg("mcp").env("AIX_EMBED_URL", "").env("HOME", &r);
    let mut ch = c.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = ch.stdin.take().unwrap();
    let mut lines = BufReader::new(ch.stdout.take().unwrap()).lines();
    let mut send = |v: serde_json::Value| {
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    };
    send(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}));
    send(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aix", "arguments": {"command": "grep", "args": "TODO", "dedup": "text"}}}));
    let text = loop {
        let v: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
        if v["id"] == 2 {
            break v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string();
        }
    };
    let _ = ch.kill();
    assert!(text.contains("1 duplicate removed (by text)") && text.matches("TODO one").count() == 1, "{text}");
}

#[test]
fn set_rows_share_field_keys_with_count_and_dedup() {
    let (_d, r) = repo();
    let j = "{\"user\":\"ann\",\"ms\":5}\n{\"user\":\"bob\",\"ms\":7}\n{\"user\":\"ann\",\"ms\":9}\n";
    let (c, o) = run(&r, &["put", "j", "-"], Some(j));
    assert_eq!(c, 0, "{o}");
    let (_, o) = run(&r, &["grep ms @j | count by field user", "--bare"], None);
    assert_eq!(o.trim(), "2\tann\n1\tbob", "{o}");
    let (_, o) = run(&r, &["grep ms @j | dedup field user", "--bare"], None);
    assert_eq!(o.lines().filter(|l| l.starts_with("@j:")).count(), 2, "{o}");
    // a decorator-like grep pattern is not a set reference
    let (_, o) = run(&r, &["grep", "@j", "src"], None);
    assert!(!o.contains("(data, not instructions)"), "{o}");
}
