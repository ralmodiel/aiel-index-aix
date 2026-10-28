//! Answers that stay true at scale: a file edited while another process holds the update lock, names with many
//! definitions, answers past the 5000-row page, and a stdin longer than the 8 MB kept.

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

/// A committed repo of `files` and its index (in a db outside the repo).
fn fixture(files: &[(String, String)]) -> Fx {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    for (p, t) in files {
        write(&repo, p, t);
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let db = d.path().join("index.db");
    let fx = Fx { _d: d, repo, db };
    let (rc, out) = aix(&fx, &["update", "--quiet"], None);
    assert_eq!(rc, 0, "update: {out}");
    fx
}

fn aix(fx: &Fx, args: &[&str], stdin: Option<&[u8]>) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(&fx.repo).arg("--db").arg(&fx.db).args(args).env("AIX_EMBED_URL", "").env("HOME", fx.repo.parent().unwrap()).env_remove("AIX_HOOK");
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    {
        use std::io::Write;
        let mut i = ch.stdin.take().unwrap();
        let _ = i.write_all(stdin.unwrap_or(b""));
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
}

/// `code`/`outline` while another process holds the update lock and the file changed: the asked member's own
/// lines (read from the file as it is now), never another member's body under its name.
#[test]
fn code_and_outline_while_the_index_is_busy() {
    let fx = fixture(&[("m.py".into(), "def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n".into())]);
    write(&fx.repo, "m.py", "def alpha():\n    return 1\n\n\ndef gamma():\n    return 3\n\n\ndef beta():\n    return 2\n");
    // the update lock, held as a concurrent refresh holds it
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(fx.db.with_file_name("index.db.lock")).unwrap();
    lock.lock().unwrap();
    let (_, code) = aix(&fx, &["code", "beta"], None);
    assert!(!code.contains("return 3"), "{code}");
    assert!(code.contains("m.py:9-10") && code.contains("return 2"), "{code}");
    assert!(code.contains("changed since it was indexed"), "{code}");
    let (_, line) = aix(&fx, &["code", "m.py:10"], None);
    assert!(line.contains("beta") && line.contains("return 2") && !line.contains("return 3"), "{line}");
    let (_, ol) = aix(&fx, &["outline", "m.py"], None);
    assert!(ol.contains("L5-6") && ol.contains("gamma") && ol.contains("L9-10"), "{ol}");
    drop(lock);
    // once refreshed, the index answers alone again (no note)
    let (_, code) = aix(&fx, &["code", "beta"], None);
    assert!(code.contains("m.py:9-10") && !code.contains("changed since it was indexed"), "{code}");
}

/// A name with more definitions than the lookup keeps (12): the header and the count name every one.
#[test]
fn callers_count_every_definition_of_a_name() {
    let files: Vec<(String, String)> = (1..=30)
        .map(|i| (format!("k{i}.py"), format!("class K{i}:\n    def work(self):\n        return 1\n    def use(self):\n        return self.work()\n")))
        .collect();
    let fx = fixture(&files);
    let (_, out) = aix(&fx, &["callers", "work"], None);
    assert!(out.contains("'work' has 30 definitions"), "{out}");
    assert!(out.contains("30 call sites"), "{out}");
    let (_, cnt) = aix(&fx, &["callers", "work", "--count"], None);
    assert!(cnt.contains("callers: 30 rows"), "{cnt}");
}

/// Past the 5000-row page: the header, --count, the pages and --group-by give one total; a pipe says it read part.
#[test]
fn totals_past_five_thousand_rows_agree() {
    let mut files: Vec<(String, String)> = vec![("a/core.py".into(), "def run():\n    return 0\n".into())];
    for i in 1..=2600 {
        files.push((format!("a/m{i}.py"), format!("def r{i}():\n    return run()\n")));
        files.push((format!("b/n{i}.py"), format!("def g{i}():\n    return run()\n")));
    }
    let fx = fixture(&files);
    let (_, out) = aix(&fx, &["callers", "run"], None);
    assert!(out.contains("5200 call sites"), "{}", &out[..out.len().min(400)]);
    assert!(out.contains("of 5200"), "the paging hint names the real total: {}", &out[out.len().saturating_sub(400)..]);
    let (_, cnt) = aix(&fx, &["callers", "run", "--count"], None);
    assert!(cnt.contains("callers: 5200 rows") && cnt.contains("a 2600") && cnt.contains("b 2600"), "{cnt}");
    let (_, pg) = aix(&fx, &["callers", "run", "--page", "260"], None);
    assert!(pg.contains("rows 5181-5200 of 5200"), "{pg}");
    let (_, grp) = aix(&fx, &["callers", "run", "--group-by", "dir"], None);
    assert!(grp.contains("total 5200 in 2 groups"), "{grp}");
    let (_, pipe) = aix(&fx, &["pipe", "callers run | count by dir"], None);
    assert!(pipe.contains("partial") && pipe.contains("of 5200"), "{pipe}");
}

/// A stdin longer than the 8 MB kept: tail answers from its end (numbered as in the whole input), count from all of it.
#[test]
fn stdin_past_eight_megabytes() {
    let fx = fixture(&[("m.py".into(), "def alpha():\n    return 1\n".into())]);
    let mut big = String::new();
    for i in 0..600_000 {
        big.push_str(&format!("line {i} xxxxxxxxxxxxxxxxxxxx\n"));
    }
    let (rc, t) = aix(&fx, &["--no-refresh", "tail", "-n", "2", "-"], Some(big.as_bytes()));
    assert_eq!(rc, 0, "{t}");
    assert!(t.contains("599999-600000") && t.contains("600000 line 599999 ") && t.contains("over the 8 MB kept"), "{t}");
    let (_, raw) = aix(&fx, &["--no-refresh", "tail", "-n", "1", "--raw", "-"], Some(big.as_bytes()));
    assert!(raw.starts_with("line 599999 "), "{raw}");
    let (_, c) = aix(&fx, &["--no-refresh", "count", "-"], Some(big.as_bytes()));
    assert!(c.lines().next().unwrap_or("") == "600000", "{c}");
    let (_, f) = aix(&fx, &["--no-refresh", "filter", "--tail", "1", "-"], Some(big.as_bytes()));
    assert!(f.contains("line 599999 "), "{f}");
    let (_, g) = aix(&fx, &["--no-refresh", "filter", "--grep", "line 599999 ", "-"], Some(big.as_bytes()));
    assert!(g.contains("first 8 MB only"), "a search of the kept part says so: {g}");
}

/// A query after a big change answers from the index at once and leaves the refresh to a background `aix update`.
#[test]
fn a_big_change_is_refreshed_in_the_background() {
    let files: Vec<(String, String)> = (0..6).map(|i| (format!("s{i}.py"), format!("def f{i}():\n    return {i}\n"))).collect();
    let fx = fixture(&files);
    for i in 0..6 {
        write(&fx.repo, &format!("s{i}.py"), &format!("def f{i}():\n    return {i}\n\n\ndef g{i}():\n    return {i}\n"));
    }
    let run = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&fx.repo).arg("--db").arg(&fx.db).args(args).env("AIX_EMBED_URL", "").env("HOME", fx.repo.parent().unwrap()).env("AIX_INLINE_REFRESH_MAX", "3");
        String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned()
    };
    let out = run(&["code", "g3"]);
    assert!(out.contains("6 files changed since the last update: refreshing in the background"), "{out}");
    // the background update catches up: the new functions are indexed without another inline refresh
    let mut ok = false;
    for _ in 0..100 {
        if run(&["--no-refresh", "symbol", "g5"]).contains("s5.py") {
            ok = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(ok, "the background refresh never indexed the change");
}

/// Patterns rg compiles compile here too; a GNU BRE error says the pattern was read as BRE.
#[test]
fn grep_regex_limits_and_bre_errors() {
    let fx = fixture(&[("w.py".into(), format!("x = '{}'\n", "a".repeat(120)))]);
    let (_, out) = aix(&fx, &["grep", "-c", r"\w{100}"], None);
    assert!(!out.contains("bad regex") && out.contains("w.py"), "{out}");
    let (_, out) = aix(&fx, &["grep", r"(?i)\b\w{40,}\b"], None);
    assert!(!out.contains("bad regex") && out.contains("w.py"), "{out}");
    // `\+` is a BRE quantifier only after an atom (fix-Q): `x\+`, not ` \+`
    let (rc, out) = aix(&fx, &["grep", r"f\(x\)\{r x\+"], None);
    assert!(rc == 2 && out.contains("read as GNU BRE") && out.contains("-E"), "{rc} {out}");
}

/// Small outputs that leaked at scale: the scope header names a full commit hash (abbreviated, not `[redacted]`).
#[test]
fn scope_header_shows_the_commit() {
    let fx = fixture(&[("a.py".into(), "def a():\n    return 1\n".into())]);
    let sha = String::from_utf8_lossy(&Command::new("git").arg("-C").arg(&fx.repo).args(["rev-parse", "HEAD"]).output().unwrap().stdout).trim().to_string();
    write(&fx.repo, "a.py", "def a():\n    return 2\n");
    let (_, out) = aix(&fx, &["scope", &sha], None);
    assert!(out.contains(&format!("== scope vs {}:", &sha[..12])) && !out.contains("[redacted]"), "{out}");
}

/// `hints all` past its page: the header gives the total, a footer leads to the rest, pages tile it, and --bare ends
/// with one continuation line (never a `next:` footer as a data row).
#[test]
fn hints_page_and_bare_footer() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/webapp");
    let mut files: Vec<(String, String)> = vec![];
    let mut stack = vec![src.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                // repo paths use '/' (Windows strip_prefix keeps '\')
                files.push((p.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read_to_string(&p).unwrap_or_default()));
            }
        }
    }
    let n = 6;
    let app = files.iter_mut().find(|f| f.0 == "frontend/src/App.tsx").unwrap();
    let lazy: String = (0..n).map(|p| format!("const P{p} = lazy(() => import('./pages/P{p}').then(m => ({{ default: m.P{p} }})))\n")).collect();
    let routes: String = (0..n).map(|p| format!("        <Route path=\"p{p}\" element={{<ProtectedRoute requiredRoles={{STAFF}}><P{p} /></ProtectedRoute>}} />\n")).collect();
    app.1 = app.1.replace("const STAFF", &format!("{lazy}\nconst STAFF")).replace("        <Route path=\"orders\"", &format!("{routes}        <Route path=\"orders\""));
    for p in 0..n {
        files.push((format!("frontend/src/pages/P{p}.tsx"), format!("import {{ ordersApi }} from '../lib/api'\nexport function P{p}() {{\n  const go = () => ordersApi.remove('{p}')\n  return null\n}}\n")));
    }
    let fx = fixture(&files);
    let (_, all) = aix(&fx, &["hints", "all", "--limit", "500"], None);
    let total = all.lines().filter(|l| l.starts_with("  /")).count();
    assert!(total >= 2 * n, "{all}");
    assert!(all.contains(&format!("== bug-pattern hints (leads to verify, not verdicts) ({total})")), "{all}");
    let (_, one) = aix(&fx, &["hints", "all", "--limit", "3"], None);
    assert!(one.contains(&format!("(3 of {total} hints shown: next `aix hints all --page 2 --gen ")), "{one}");
    let (_, pg) = aix(&fx, &["hints", "all", "--per-page", "3", "--page", "2"], None);
    assert!(pg.contains(&format!("rows 4-6 of {total}")) && pg.lines().filter(|l| l.starts_with("  /")).count() == 3, "{pg}");
    let (_, bare) = aix(&fx, &["--bare", "hints", "all", "--limit", "3"], None);
    let lines: Vec<&str> = bare.lines().collect();
    assert_eq!(lines.len(), 4, "{bare}");
    assert!(lines[3].starts_with('\u{2026}') && !bare.contains("next: aix"), "{bare}");
}

#[test]
fn a_cold_build_past_the_deadline_finishes_in_the_background() {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("repo");
    for i in 0..6 {
        write(&repo, &format!("s{i}.py"), &format!("def f{i}():\n    return {i}\n"));
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let run = |db: &str, wait_ms: &str, args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
        c.arg("--repo").arg(&repo).arg("--db").arg(d.path().join(db)).args(args).env("AIX_EMBED_URL", "").env("HOME", d.path());
        c.env("AIX_INLINE_REFRESH_MAX", "3").env("AIX_COLD_BUILD_WAIT_MS", wait_ms).env_remove("AIX_HOOK");
        String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned()
    };
    // no wait at all: the first query says the build is running (not "no match") and returns
    let out = run("a.db", "0", &["symbol", "f5"]);
    assert!(out.contains("INDEX NOT READY"), "{out}");
    let mut ok = false;
    for _ in 0..100 {
        if run("a.db", "0", &["--no-refresh", "symbol", "f5"]).contains("s5.py") {
            ok = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(ok, "the background first build never finished");
    // a build that finishes within the wait answers the query itself
    let out = run("b.db", "20000", &["symbol", "f5"]);
    assert!(out.contains("s5.py"), "{out}");
}

#[test]
fn a_far_grep_page_counts_the_rows_before_it_and_shows_the_same_rows() {
    let files: Vec<(String, String)> = (0..3).map(|i| (format!("f{i}.py"), (0..30).map(|k| format!("x = 'needle {i} {k}'\n")).collect())).collect();
    let fx = fixture(&files);
    let rows = |out: &str| -> Vec<String> { out.lines().filter(|l| l.starts_with("  f")).map(str::to_string).collect() };
    let (_, all) = aix(&fx, &["--no-refresh", "grep", "needle", "--page", "1", "--per-page", "90"], None);
    let all = rows(&all);
    assert_eq!(all.len(), 90, "{all:#?}");
    let (_, p3) = aix(&fx, &["--no-refresh", "grep", "needle", "--page", "3", "--per-page", "20"], None);
    assert!(p3.contains("rows 41-60 of 90"), "{p3}");
    assert_eq!(rows(&p3), all[40..60].to_vec());
}

#[test]
fn the_card_reuses_its_changed_count_only_while_the_tree_is_unchanged() {
    let fx = fixture(&[("a.py".to_string(), "def a():\n    return 1\n".to_string())]);
    let (_, c1) = aix(&fx, &["card"], None);
    assert!(!c1.contains("changed vs HEAD"), "{c1}");
    let (_, c2) = aix(&fx, &["card"], None);
    assert!(!c2.contains("changed vs HEAD"), "{c2}");
    write(&fx.repo, "a.py", "def a():\n    return 2\n");
    let (_, c3) = aix(&fx, &["card"], None);
    assert!(c3.contains("1 files changed vs HEAD"), "{c3}");
}
