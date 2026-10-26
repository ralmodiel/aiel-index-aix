//! The MCP server answers queries in parallel (one SQLite handle per worker) and refreshes alone: while files change
//! under parallel readers, every answer is the old state's or the new state's, never a half-applied update.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};

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

/// State `n` of the repo: `target` has n+1 callers in `a.ts`, and `b.ts` calls the newest one.
fn source(n: usize) -> (String, String) {
    let mut a = String::from("export function target(): number {\n  return 1;\n}\n");
    for i in 0..=n {
        a.push_str(&format!("export function caller{i}(): number {{\n  return target() + {i};\n}}\n"));
    }
    (a, format!("import {{ caller{n} }} from './a';\nexport function user(): number {{\n  return caller{n}();\n}}\n"))
}

/// Replace a file in one step (a reader of the tree never sees it half written).
fn put(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp~");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

struct Client {
    stdin: Mutex<std::process::ChildStdin>,
    next: Mutex<i64>,
    done: Mutex<HashMap<i64, String>>,
    cv: Condvar,
}

impl Client {
    fn call(&self, command: &str, args: &str) -> String {
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        let msg = serde_json::json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "aix", "arguments": {"command": command, "args": args}}});
        {
            let mut w = self.stdin.lock().unwrap();
            writeln!(w, "{msg}").unwrap();
            w.flush().unwrap();
        }
        let mut done = self.done.lock().unwrap();
        loop {
            if let Some(t) = done.remove(&id) {
                // the refresh note says when this call refreshed; the answer is what follows it
                return t.lines().filter(|l| !l.starts_with("(index refreshed")).collect::<Vec<_>>().join("\n");
            }
            done = self.cv.wait(done).unwrap();
        }
    }
}

#[test]
fn parallel_reads_during_updates_see_the_old_or_the_new_state() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    std::fs::create_dir_all(r.join("src")).unwrap();
    let (a, b) = source(0);
    std::fs::write(r.join("src/a.ts"), a).unwrap();
    std::fs::write(r.join("src/b.ts"), b).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    std::fs::create_dir_all(d.path().join("db")).unwrap();
    let db = d.path().join("db/index.db");
    let aix = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).arg("--db").arg(&db).args(args).env("HOME", d.path()).env("AIX_EMBED_URL", "").output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    aix(&["update"]);
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .arg("--db")
        .arg(&db)
        .arg("mcp")
        .env("HOME", d.path())
        .env("AIX_EMBED_URL", "")
        .env("AIX_MCP_READERS", "4")
        // queries dawdle between their freshness check and their reads: a refresh that could start in between would
        // be read half-applied (the gate makes it wait for them)
        .env("AIX_MCP_TEST_PAUSE_MS", "40")
        // and an update takes its time between its committed stages
        .env("AIX_TEST_STAGE_PAUSE_MS", "60")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let cl = Arc::new(Client { stdin: Mutex::new(c.stdin.take().unwrap()), next: Mutex::new(10), done: Mutex::new(HashMap::new()), cv: Condvar::new() });
    {
        let cl = cl.clone();
        let out = c.stdout.take().unwrap();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                let Ok(l) = l else { break };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) else { continue };
                if let Some(id) = v["id"].as_i64() {
                    let t = v["result"]["content"][0]["text"].as_str().unwrap_or("").to_string();
                    cl.done.lock().unwrap().insert(id, t);
                    cl.cv.notify_all();
                }
            }
        });
    }
    {
        let mut w = cl.stdin.lock().unwrap();
        writeln!(w, "{}", serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}})).unwrap();
        writeln!(w, "{}", serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).unwrap();
        w.flush().unwrap();
    }
    let queries: [(&str, &str); 3] = [("callers", "target"), ("outline", "src/a.ts"), ("callees", "user")];
    let snapshot = |cl: &Client| -> Vec<String> { queries.iter().map(|(c, a)| cl.call(c, a)).collect() };
    let mut states: Vec<Vec<String>> = vec![snapshot(&cl)];
    assert!(states[0][0].contains("caller0"), "{}", states[0][0]);
    const ROUNDS: usize = 4;
    for n in 1..=ROUNDS {
        // readers run in parallel while the files change and the first caller to notice refreshes
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen: Arc<Mutex<Vec<(usize, String)>>> = Arc::default();
        let readers: Vec<_> = (0..4)
            .map(|k| {
                let (cl, stop, seen) = (cl.clone(), stop.clone(), seen.clone());
                std::thread::spawn(move || {
                    let mut i = k;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) || i < k + 6 {
                        let q = i % queries.len();
                        let t = cl.call(queries[q].0, queries[q].1);
                        seen.lock().unwrap().push((q, t));
                        i += 1;
                    }
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(150));
        let (a, b) = source(n);
        put(&r.join("src/a.ts"), &a);
        put(&r.join("src/b.ts"), &b);
        std::thread::sleep(std::time::Duration::from_millis(400));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in readers {
            t.join().unwrap();
        }
        let new = snapshot(&cl);
        assert!(new[0].contains(&format!("caller{n}")), "round {n}: {}", new[0]);
        assert_ne!(new, states[n - 1], "round {n}: the update changed nothing");
        // (a refresh between the two writes indexes new a.ts with old b.ts: callers/outline read a.ts only and are
        // new, `callees user` still names caller{n-1}, which new a.ts keeps where it was: the old answer)
        for (q, t) in seen.lock().unwrap().iter() {
            // a file edited while another caller holds the update lock: code/outline read it as it is now (the
            // members and ranges of the new state, with a note), never the old ranges over the new text
            let ranges = |x: &str| -> Vec<String> { x.lines().filter(|l| l.starts_with('L')).map(|l| l.split(" |").next().unwrap_or("").to_string()).collect() };
            let fresh = t.contains("changed since it was indexed") && ranges(t) == ranges(&new[*q]);
            let ok = t == &states[n - 1][*q] || t == &new[*q] || fresh;
            assert!(ok, "round {n}: answer to {:?} is neither the old nor the new state:\n{t}\n--- old\n{}\n--- new\n{}", queries[*q], states[n - 1][*q], new[*q]);
        }
        states.push(new);
    }
    drop(cl);
    let _ = c.kill();
    let _ = c.wait();
}
