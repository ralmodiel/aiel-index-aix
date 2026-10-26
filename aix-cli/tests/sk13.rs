//! SK-13: robustness and correctness fixes from QA round 1: `code` ranges, deeply nested source, `endpoint` paths,
//! LIKE wildcards, `patterns add` refusals, the sql guard, MCP errors and annotations, extractor nits.

use std::io::{BufRead, BufReader, Write};
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

fn cmd(repo: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).env("AIX_EMBED_URL", "").env("HOME", repo);
    c
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let o = cmd(repo).args(args).output().unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 2), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
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
    sk(&r, &["update"]);
    (d, r)
}

#[test]
fn code_ranges_never_panic() {
    let long = format!("const x = '{}';\n", "y".repeat(1000));
    let (_d, r) = repo(&[("a.ts", &format!("export const a = 1;\nexport const b = 2;\n{long}export const c = 3;\n"))]);
    let rev = sk(&r, &["code", "a.ts:4-2"]);
    assert!(rev.contains("a.ts:2-4") && rev.contains("export const b"), "{rev}");
    let past = sk(&r, &["code", "a.ts:500-600"]);
    assert!(past.contains("a.ts has 4 lines") && !past.contains("panicked"), "{past}");
    let clamp = sk(&r, &["code", "a.ts:3-900"]);
    assert!(clamp.contains("a.ts:3-4"), "{clamp}");
    let wide = sk(&r, &["code", "a.ts:3-3"]);
    assert!(wide.contains("more chars]") && wide.lines().all(|l| l.chars().count() < 400), "{wide}");
}

#[test]
fn deeply_nested_files_are_skipped_not_fatal() {
    let n = 5000;
    let mut files: Vec<(String, String)> = vec![("ok.ts".into(), "export function okFn() { return fetch('/api/ok'); }\n".into())];
    files.push(("plus.ts".into(), format!("export const x = {};\n", vec!["1"; n].join("+"))));
    files.push(("arr.ts".into(), format!("export const x = {}{};\n", "[".repeat(n), "]".repeat(n))));
    files.push(("call.ts".into(), format!("export const x = {}{};\n", "f(".repeat(n), ")".repeat(n))));
    files.push(("tern.ts".into(), format!("export const x = {}2;\n", "a ? 1 : ".repeat(n))));
    files.push(("tpl.ts".into(), format!("export const x = {}1{};\n", "`${".repeat(n), "}`".repeat(n))));
    files.push(("jsx.tsx".into(), format!("export const x = ({}{});\n", "<div>".repeat(n), "</div>".repeat(n))));
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (_d, r) = repo(&refs); // `repo` runs `update`, which asserts a clean exit
    assert!(sk(&r, &["symbol", "okFn"]).contains("ok.ts:1"));
    let notes = sk(&r, &["sql", "select file from notes where kind='extract-skipped' order by file"]);
    for f in ["arr.ts", "call.ts", "jsx.tsx", "plus.ts", "tern.ts", "tpl.ts"] {
        assert!(notes.contains(f), "{f} not recorded: {notes}");
    }
    let text = sk(&r, &["sql", "select text from notes where kind='extract-skipped' limit 1"]);
    assert!(text.contains("extract skipped: too deep"), "{text}");
}

#[test]
fn endpoint_literal_path_then_api_prefix_and_literal_ids() {
    let jax = "package p;\nimport jakarta.ws.rs.*;\n@Path(\"/jax\")\npublic class Jax {\n    @GET\n    @Path(\"/{id}\")\n    public String one(@PathParam(\"id\") long id) { return \"\"; }\n    @POST\n    public String make() { return \"\"; }\n}\n";
    let ts = "const BASE = 'http://x';\nexport async function load() {\n  await fetch('/jax/5');\n  await fetch(`${BASE}/jax`, { method: 'POST' });\n  await fetch('https://api.example.com/jax/3fa85f64-5717-4562-b3fc-2c963f66afa6');\n}\n";
    let (_d, r) = repo(&[("Jax.java", jax), ("c.ts", ts)]);
    let e = sk(&r, &["endpoint", "/jax/5"]);
    assert!(e.contains("GET /jax/{id} -> Jax.java:5") && e.contains("direct uses: c.ts:3, c.ts:5"), "{e}");
    let p = sk(&r, &["endpoint", "POST /jax"]);
    assert!(p.contains("POST /jax -> Jax.java:8") && p.contains("c.ts:4"), "{p}");
    // typed with the /api prefix the app does not have: still found
    assert!(sk(&r, &["endpoint", "/api/jax/5"]).contains("GET /jax/{id}"));
}

#[test]
fn server_routes_are_not_client_calls_and_fetch_reads_the_method() {
    let ts = "export function s() {\n  app.get('/health', (req, res) => res.send('ok'));\n  router.post('/items', auth, createItem);\n  api.get('/real/1');\n  fetch('/del/1', { method: 'DELETE' });\n  fetch('/plain');\n}\n";
    let (_d, r) = repo(&[("srv.ts", ts)]);
    let q = sk(&r, &["sql", "select line, method, path from api_calls order by line"]);
    assert!(!q.contains("/health") && !q.contains("/items"), "{q}");
    assert!(q.contains("4 | GET | /real/1") && q.contains("5 | DELETE | /del/1") && q.contains("6 | GET | /plain"), "{q}");
}

#[test]
fn like_wildcards_in_user_input_are_literal() {
    let tsx = "export function P() {\n  return (<div><p>Save changes now</p><p>Progress 100% done</p></div>);\n}\n";
    let (_d, r) = repo(&[("P.tsx", tsx)]);
    assert!(sk(&r, &["text", "Save changes"]).contains("P.tsx:2"));
    assert!(sk(&r, &["text", "%"]).contains("100% done") && !sk(&r, &["text", "%"]).contains("Save changes now"));
    for q in ["_av"] {
        let t = sk(&r, &["text", q]);
        assert!(!t.contains("Save changes now") && t.contains("no UI string contains"), "{q}: {t}");
    }
}

#[test]
fn patterns_add_refuses_bad_input() {
    let (_d, r) = repo(&[("a.ts", "export const needle = 1;\n")]);
    for bad in ["add foo", "add foo ''", "add foo '.*'", "add foo 'x*'"] {
        let o = sk(&r, &["patterns", bad]);
        assert!(o.contains("not added"), "{bad}: {o}");
    }
    assert!(sk(&r, &["patterns", "add my-name 'needle'"]).contains("invalid name 'my-name'"));
    assert!(sk(&r, &["patterns", "add my.name 'needle'"]).contains("invalid name"));
    assert!(sk(&r, &["patterns", "add good_name 'needle'"]).contains("pat:good_name"));
    let dup = sk(&r, &["patterns", "add good_name 'other'"]);
    assert!(dup.contains("not added") && dup.contains("already used"), "{dup}");
    // same name, same regex is idempotent
    assert!(sk(&r, &["patterns", "add good_name 'needle'"]).contains("pat:good_name"));
    // one outer quote pair is stripped, quotes that belong to the regex stay
    assert!(sk(&r, &["patterns", "add quoted '\"needle\"'"]).contains("/\"needle\"/"));
}

#[test]
fn sql_guard_ignores_literals() {
    let (_d, r) = repo(&[("a.ts", "export const a = 1;\n")]);
    let ok = sk(&r, &["sql", "select 'update; delete' as k, replace('abc','b','c') as r, \"x\" as q"]);
    assert!(ok.contains("update; delete | acc"), "{ok}");
    assert!(sk(&r, &["sql", "select 1; select 2"]).contains("read-only"));
    assert!(sk(&r, &["sql", "select 1; drop table files"]).contains("read-only"));
    assert!(sk(&r, &["sql", "with x as (select 1) delete from files"]).contains("read-only"));
}

#[test]
fn extractor_nits() {
    let a = "export namespace Billing {\n  export function charge(x: number) { return x; }\n}\ndeclare module \"foo\" {\n  export function bar(): void;\n}\nexport abstract class Base {\n  abstract run(x: number): void;\n  concrete() {}\n}\nexport function over(a: string): void;\nexport function over(a: number): void;\nexport function over(a: any) {}\n";
    let rec = "package p;\npublic record Point(int x, int y) {\n    public Point {\n        if (x < 0) throw new IllegalArgumentException();\n    }\n}\n";
    let ep = "package p;\n@Path(\"/ep\")\npublic class Ep {\n    @RolesAllowed({\"a\", \"b\"})\n    @Path(\"/x\")\n    @GET\n    public String get() { return \"\"; }\n}\n";
    let (_d, r) = repo(&[
        ("a.ts", a),
        ("R.java", rec),
        ("Ep.java", ep),
        ("fa.txt", "needle in a\n"),
        ("fb.txt", "needle in b\n"),
        ("nulbyte.txt", "needle a\0b\n"),
    ]);
    let o = sk(&r, &["outline", "a.ts"]);
    for want in ["ns namespace Billing", "fn charge", "ns namespace foo", "fn bar", "method run(x: number)", "fn over(a: string)", "fn over(a: number)"] {
        assert!(o.contains(want), "{want}: {o}");
    }
    assert!(sk(&r, &["symbol", "Billing"]).contains("a.ts:1 namespace"));
    assert!(sk(&r, &["outline", "R.java"]).contains("ctor Point(int x, int y)"));
    let e = sk(&r, &["outline", "Ep.java"]);
    assert!(e.contains("@RolesAllowed @Path @GET") && !e.contains("@\"b\""), "{e}");
    let g = sk(&r, &["grep", "needle", "fa.txt", "fb.txt"]);
    assert!(g.contains("fa.txt:1") && g.contains("fb.txt:1") && g.contains("(in fa.txt, fb.txt)") && !g.contains("nulbyte.txt"), "{g}");
    assert!(sk(&r, &["grep", "needle", "nulbyte.txt"]).contains("needle a\\0b"));
}

#[test]
fn utf16_files_are_searchable() {
    let (_d, r) = repo(&[("a.ts", "export const a = 1;\n")]);
    let mut b = vec![0xff, 0xfe];
    for u in "wide needle here\n".encode_utf16() {
        b.extend(u.to_le_bytes());
    }
    std::fs::write(r.join("w.txt"), b).unwrap();
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "wide"]);
    let g = sk(&r, &["grep", "needle"]);
    assert!(g.contains("w.txt:1: wide needle here"), "{g}");
}

struct Mcp {
    c: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::io::Lines<BufReader<std::process::ChildStdout>>,
}

impl Mcp {
    fn start(r: &Path) -> Mcp {
        Mcp::start_env(r, &[])
    }
    fn start_env(r: &Path, env: &[(&str, &str)]) -> Mcp {
        let mut c = cmd(r).arg("mcp").envs(env.iter().copied()).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
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
fn mcp_errors_types_and_annotations() {
    let (_d, r) = repo(&[("a.ts", "export const a = 1;\nexport const b = 2;\n")]);
    let mut m = Mcp::start(&r);
    m.send(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let t = m.recv(2);
    assert_eq!(t["result"]["tools"][0]["annotations"]["readOnlyHint"], true, "{t}");
    // the schema is paid on every turn: kept small
    let n = t["result"].to_string().len();
    assert!(n <= 4096, "tools/list is {n} bytes");
    // wrong argument types: invalid params
    for (i, args) in [
        serde_json::json!({"command": 5}),
        serde_json::json!({"command": "brief", "args": 7}),
        serde_json::json!({"command": "brief", "limit": "ten"}),
        serde_json::json!({"command": "brief", "json": "yes"}),
        serde_json::json!({"args": "x"}),
    ]
    .into_iter()
    .enumerate()
    {
        let v = m.call(10 + i as i64, args.clone());
        assert_eq!(v["error"]["code"], -32602, "{args}: {v}");
    }
    // usage / refusals / errors set isError
    let u = m.call(20, serde_json::json!({"command": "brief"}));
    assert_eq!(u["result"]["isError"], true, "{u}");
    let s = m.call(21, serde_json::json!({"command": "sql", "args": "drop table files"}));
    assert_eq!(s["result"]["isError"], true, "{s}");
    let c = m.call(22, serde_json::json!({"command": "code", "args": "a.ts:99-100"}));
    assert_eq!(c["result"]["isError"], true, "{c}");
    // a good call is not an error, and the server still answers after all that
    let ok = m.call(23, serde_json::json!({"command": "code", "args": "a.ts:2-1"}));
    assert!(ok["result"]["isError"] != true && ok["result"]["content"][0]["text"].as_str().unwrap().contains("export const b"), "{ok}");
}

/// AIX_MCP_TOOLS=intent: the intent-named tools and a slim generic one, within the same 4 KB; a named tool runs its command.
#[test]
fn mcp_intent_tools_fit_and_run() {
    let (_d, r) = repo(&[("a.ts", "export function alpha() { return beta(); }\nexport function beta() { return 1; }\n")]);
    let mut m = Mcp::start_env(&r, &[("AIX_MCP_TOOLS", "intent")]);
    m.send(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let t = m.recv(2);
    let n = t["result"].to_string().len();
    let names: Vec<&str> = t["result"]["tools"].as_array().unwrap().iter().filter_map(|x| x["name"].as_str()).collect();
    assert!(n <= 4096 && names.contains(&"aix_callers") && names.contains(&"aix"), "{n} {names:?}");
    m.send(serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aix_callers", "arguments": {"symbol": "beta"}}}));
    let c = m.recv(3);
    assert!(c["result"]["content"][0]["text"].as_str().is_some_and(|x| x.contains("a.ts:1")), "{c}");
}
