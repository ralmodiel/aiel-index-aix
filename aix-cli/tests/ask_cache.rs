//! `ask` in a long-running server keeps query vectors and the per-kind vector matrices in memory: answers equal a
//! fresh process's, before and after the embedded entries change (a stub embedder on loopback stands in for the model).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
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

/// Bag of words hashed into 64 dimensions: texts sharing words are close.
fn embed(text: &str) -> Vec<f32> {
    let mut v = vec![0f32; 64];
    let lower = text.to_lowercase();
    for w in lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| w.len() > 2) {
        let h = w.bytes().fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
        v[(h % 64) as usize] += 1.0;
    }
    v[63] += 0.01;
    v
}

/// A loopback `/v1/embeddings` endpoint answering with [`embed`].
fn stub_embedder() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            if r.read_exact(&mut body).is_err() {
                continue;
            }
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let data: Vec<serde_json::Value> = req["input"]
                .as_array()
                .map(|a| a.iter().enumerate().map(|(i, t)| serde_json::json!({"index": i, "embedding": embed(t.as_str().unwrap_or(""))})).collect())
                .unwrap_or_default();
            let out = serde_json::json!({"data": data}).to_string();
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
        }
    });
    url
}

/// The hit lines of an answer (notes and refresh lines aside).
fn hits(t: &str) -> Vec<String> {
    t.lines().filter(|l| l.contains("src/")).map(str::to_string).collect()
}

#[test]
fn ask_answers_from_the_cache_match_a_fresh_process_before_and_after_embeddings_change() {
    let url = stub_embedder();
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    std::fs::create_dir_all(r.join("src")).unwrap();
    std::fs::write(
        r.join("src/a.ts"),
        "export function parseInvoiceTotal(lines: number[]): number {\n  // sum the invoice lines\n  return lines.reduce((a, b) => a + b, 0);\n}\n\
         export function sendReminderEmail(to: string): string {\n  // remind a customer about an unpaid invoice\n  return `reminder ${to}`;\n}\n\
         export function renderLatticeChart(points: number[]): string {\n  // draw the lattice chart\n  return points.join(',');\n}\n",
    )
    .unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    std::fs::create_dir_all(d.path().join("db")).unwrap();
    let db = d.path().join("db/index.db");
    let aix = |args: &[&str]| -> String {
        let o = Command::new(env!("CARGO_BIN_EXE_aix"))
            .arg("--repo")
            .arg(&r)
            .arg("--db")
            .arg(&db)
            .args(args)
            .env("HOME", d.path())
            .env("AIX_EMBED_URL", &url)
            .output()
            .unwrap();
        assert!(o.status.success(), "{args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    aix(&["update", "--embed-deadline", "30"]);
    let gen = || -> i64 {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key='sem_gen'", [], |r| r.get(0)).unwrap()
    };
    let g0 = gen();
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .arg("--db")
        .arg(&db)
        .arg("mcp")
        .env("HOME", d.path())
        .env("AIX_EMBED_URL", &url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    let mut lines = BufReader::new(c.stdout.take().unwrap()).lines();
    let mut id = 1;
    let mut call = |v: serde_json::Value| -> serde_json::Value {
        id += 1;
        let mut v = v;
        v["jsonrpc"] = "2.0".into();
        v["id"] = id.into();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
        loop {
            let l = lines.next().expect("server closed").unwrap();
            let r: serde_json::Value = serde_json::from_str(&l).unwrap();
            if r["id"] == id {
                return r;
            }
        }
    };
    call(serde_json::json!({"method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}));
    let ask = |call: &mut dyn FnMut(serde_json::Value) -> serde_json::Value, q: &str| -> String {
        let r = call(serde_json::json!({"method": "tools/call", "params": {"name": "aix", "arguments": {"command": "ask", "args": q, "kind": "code"}}}));
        r["result"]["content"][0]["text"].as_str().unwrap_or("").to_string()
    };
    let q = "zebra quantum lattice";
    let before = ask(&mut call, q);
    assert!(!before.contains("semantic layer unavailable") && !before.contains("not embedded"), "{before}");
    assert_eq!(hits(&before), hits(&aix(&["--no-refresh", "ask", q, "--kind", "code"])), "server and fresh process differ");
    assert!(!before.contains("zebraQuantum"), "{before}");
    // the same question again: from the caches, the same answer
    assert_eq!(hits(&ask(&mut call, q)), hits(&before));
    // another process adds an embedded entry that answers the question: the generation moves, the cache follows
    std::fs::write(r.join("src/b.ts"), "export function zebraQuantumLattice(): string {\n  // zebra quantum lattice\n  return 'zebra quantum lattice';\n}\n").unwrap();
    git(&r, &["add", "-A"]);
    aix(&["update", "--embed-deadline", "30"]);
    assert!(gen() > g0, "embedding a new entry must move sem_gen");
    let after = ask(&mut call, q);
    assert!(hits(&after).first().is_some_and(|l| l.contains("zebraQuantumLattice")), "stale cache:\n{after}");
    assert_eq!(hits(&after), hits(&aix(&["--no-refresh", "ask", q, "--kind", "code"])), "server and fresh process differ after the change");
    // and an entry that goes away leaves the answers too
    std::fs::remove_file(r.join("src/b.ts")).unwrap();
    aix(&["update"]);
    let gone = ask(&mut call, q);
    assert!(!gone.contains("zebraQuantum"), "removed entry still served:\n{gone}");
    assert_eq!(hits(&gone), hits(&before));
    drop(stdin);
    let _ = c.kill();
    let _ = c.wait();
}
