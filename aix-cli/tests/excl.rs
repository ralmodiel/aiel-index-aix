//! The exclusion vocabulary end to end: -x / --only / --conf / --hide / --skip / --order / --sort, defaults (config and
//! env), --count, --page, --exists, --group-by / --having, and the compact JSON forms. Generic fixture only.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("webapp");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/webapp"), &r);
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "Initial webapp"]);
    let u = run(&r, &["update", "--full"], &[]);
    assert!(u.status.success());
    (d, r)
}

fn run(repo: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo).env_remove("AIX_EXCLUDE");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

fn sk_err(repo: &Path, args: &[&str]) -> String {
    let o = run(repo, args, &[]);
    assert_eq!(o.status.code(), Some(2), "aix {args:?} should exit 2: {}", String::from_utf8_lossy(&o.stdout));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let o = run(repo, args, &[]);
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn exclude_only_and_grep_x_ambiguity() {
    let (_d, r) = repo();
    let all = sk(&r, &["grep", "cancel"]);
    assert!(all.contains("docs/checkout-flows.md") && all.contains("e2e/specs/clerk.json"), "{all}");
    let x = sk(&r, &["grep", "cancel", "-x", "docs,tests"]);
    assert!(!x.contains("docs/") && !x.contains("e2e/specs") && x.contains("OrderResource.java"), "{x}");
    // globs
    let g = sk(&r, &["grep", "cancel", "--exclude", "**/*.tsx,docs/**"]);
    assert!(!g.contains(".tsx") && !g.contains("docs/") && g.contains("api.ts"), "{g}");
    // --only is the positive counterpart
    let o = sk(&r, &["grep", "cancel", "--only", "docs"]);
    assert!(o.contains("docs/checkout-flows.md") && !o.contains("OrderResource.java"), "{o}");
    // grep's own -x (whole line) is untouched when no pattern would be left
    let line = sk(&r, &["grep", "-x", "docs"]);
    assert!(line.contains("0 matching lines") || line.contains("no match"), "{line}");
    // the index-backed commands share the vocabulary
    let t = sk(&r, &["find", "cancel", "-x", "tests"]);
    assert!(!t.contains("e2e/specs") && t.contains("OrderResource.java"), "{t}");
    let base = sk(&r, &["find", "cancel"]);
    assert!(base.contains("e2e/specs"), "{base}");
    let tx = sk(&r, &["text", "Cancel order", "-x", "docs,tests"]);
    assert!(tx.contains("Orders.tsx:21"), "{tx}");
}

#[test]
fn sections_skip_fields_hide_and_order() {
    let (_d, r) = repo();
    let b = sk(&r, &["brief", "/orders"]);
    assert!(b.contains("== past findings") && b.contains("== open DECISIONs"), "{b}");
    let s = sk(&r, &["brief", "/orders", "--skip", "bugs,decisions,hints"]);
    assert!(!s.contains("== past findings") && !s.contains("== open DECISIONs") && s.contains("api ("), "{s}");
    let f = sk(&r, &["brief", "/orders", "--fields", "api"]);
    assert!(f.contains("api (") && !f.contains("e2e (") && !f.contains("== recent fix"), "{f}");
    // unknown section: one line naming the sections
    let u = sk(&r, &["brief", "/orders", "--skip", "nope"]);
    assert!(u.contains("unknown section") && u.contains("decisions"), "{u}");
    // --hide is POST: rows are removed after ranking, a tally says what went
    let h = sk(&r, &["grep", "cancel", "--hide", "docs,tests"]);
    assert!(!h.contains("docs/") && h.contains("(hid ") && h.contains("docs"), "{h}");
    // --order puts sections first
    let o = sk(&r, &["brief", "/orders", "--order", "decisions,fixes"]);
    let (d, a) = (o.find("== open DECISIONs").unwrap(), o.find("api (").unwrap());
    assert!(d < a, "{o}");
    // table sections are real arguments
    let t = sk(&r, &["table", "orders", "--skip", "migrations,readers,writers,endpoints"]);
    assert!(!t.contains("migration history"), "{t}");
}

#[test]
fn default_excludes_config_env_and_note() {
    let (_d, r) = repo();
    let plain = sk(&r, &["grep", "cancel"]);
    assert!(plain.contains("docs/checkout-flows.md") && !plain.contains("default excludes"));
    std::fs::write(r.join(".aix/config.toml"), "default_excludes = [\"docs\"]\n").unwrap();
    let d = sk(&r, &["grep", "cancel"]);
    assert!(!d.contains("docs/checkout-flows.md") && d.contains("(default excludes: docs; --no-default-excludes to include)"), "{d}");
    let n = sk(&r, &["grep", "cancel", "--no-default-excludes"]);
    assert!(n.contains("docs/checkout-flows.md") && !n.contains("default excludes"), "{n}");
    std::fs::remove_file(r.join(".aix/config.toml")).unwrap();
    let o = run(&r, &["grep", "cancel"], &[("AIX_EXCLUDE", "tests")]);
    let e = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(!e.contains("e2e/specs") && e.contains("default excludes: tests"), "{e}");
    // the envelope reports what was dropped
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "callers", "ordersApi.cancel", "-x", "tests"])).unwrap();
    assert_eq!(j["excluded"]["criteria"]["exclude"][0], "tests", "{j}");
}

#[test]
fn count_pages_exists_and_json_forms() {
    let (_d, r) = repo();
    let c = sk(&r, &["grep", "cancel", "--plan"]);
    assert!(c.contains("== count grep: 14 rows") && c.contains("kinds:") && c.contains("next:"), "{c}");
    // pages union exactly to the full set, in a stable order
    let mut paged: Vec<String> = vec![];
    for p in 1..=12 {
        let out = sk(&r, &["find", "cancel", "--limit", "100", "--page", &p.to_string(), "--per-page", "3"]);
        assert!(out.contains(&format!("page {p} of ")), "{out}");
        paged.extend(out.lines().filter(|l| l.starts_with('[')).map(str::to_string));
        if !out.contains("next `aix") {
            break;
        }
    }
    let every = sk(&r, &["find", "cancel", "--limit", "100", "--page", "1", "--per-page", "1000"]);
    let want: Vec<String> = every.lines().filter(|l| l.starts_with('[')).map(str::to_string).collect();
    assert!(want.len() > 6);
    assert_eq!(paged, want);
    // --exists: one line and the exit status
    let y = run(&r, &["callers", "ordersApi.cancel", "--exists"], &[]);
    assert!(y.status.success());
    assert!(String::from_utf8_lossy(&y.stdout).starts_with("yes (first: "), "{}", String::from_utf8_lossy(&y.stdout));
    let n = run(&r, &["callers", "ordersApi.cancel", "--exists", "-x", "frontend/**"], &[]);
    assert_eq!(n.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&n.stdout).starts_with("no (1 filters applied)") || String::from_utf8_lossy(&n.stdout).starts_with("no ("), "{}", String::from_utf8_lossy(&n.stdout));
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "grep", "cancel", "--exists"])).unwrap();
    assert_eq!(j["exists"], true);
    assert!(j["first"]["file"].is_string());
    // compact JSON has no empty fields; --pretty keeps them; --jsonl ends with a summary
    let compact = sk(&r, &["--json", "callers", "ordersApi.cancel"]);
    let pretty = sk(&r, &["--json", "--pretty", "callers", "ordersApi.cancel"]);
    assert!(compact.len() < pretty.len() && !compact.contains("\n ") && !compact.contains("\"\""), "{compact}");
    let jl = sk(&r, &["--jsonl", "callers", "ordersApi.cancel"]);
    let last: serde_json::Value = serde_json::from_str(jl.lines().last().unwrap()).unwrap();
    assert!(last["summary"]["n"].as_u64().unwrap() >= 1, "{jl}");
}

#[test]
fn group_by_having() {
    let (_d, r) = repo();
    let g = sk(&r, &["grep", "cancel", "--group-by", "dir:1", "--having", "count>=2", "--sort", "count"]);
    assert!(g.lines().next().unwrap().trim_start().starts_with(|c: char| c.is_ascii_digit()), "{g}");
    assert!(g.contains("frontend") && !g.contains("e2e") && g.contains("(total 14 in "), "{g}");
    let m = sk(&r, &["grep", "@Path", "--group-by", "match", "--sort", "count"]);
    assert!(m.contains("@Path") && m.contains("groups by match"), "{m}");
    let c = sk(&r, &["callers", "ordersApi.cancel", "--group-by", "caller-class", "--having", "count>=1"]);
    assert!(c.contains("(total "), "{c}");
    let bad = sk_err(&r, &["grep", "cancel", "--group-by", "dir", "--having", "count>5; drop table files"]);
    assert!(bad.contains("--having: count>N"), "{bad}");
    let nokey = sk_err(&r, &["grep", "cancel", "--group-by", "role"]);
    assert!(nokey.contains("not available for grep"), "{nokey}");
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "grep", "cancel", "--group-by", "kind"])).unwrap();
    assert_eq!(j["total"], 14);
    assert!(j["groups"].as_array().unwrap().iter().any(|x| x["key"] == "docs"), "{j}");
}

#[test]
fn card_and_hints_teach_the_vocabulary() {
    use std::io::Write;
    use std::process::Stdio;
    let (_d, r) = repo();
    let card = sk(&r, &["card"]);
    // the card names the question each command answers (AIX_CARD_STYLE=classic: the older command list)
    assert!(card.contains("who calls X? `aix callers") && card.contains("--exists") && card.contains("--group-by"), "{card}");
    let classic = String::from_utf8_lossy(&run(&r, &["card"], &[("AIX_CARD_STYLE", "classic")]).stdout).into_owned();
    assert!(classic.contains("say what you do NOT need") && classic.contains("--plan"), "{classic}");
    assert!(card.lines().count() <= 13, "{card}");
    let ev = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "grep -rnE \"Cancel.*order|zzqq\" frontend"}});
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(&r)
        .args(["hook", "pretool"])
        .env("HOME", &r)
        .env("AIX_HOOK_DENY", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(ev.to_string().as_bytes()).unwrap();
    let out = String::from_utf8(c.wait_with_output().unwrap().stdout).unwrap();
    // the exact translation of the command (same scope, same pattern)
    assert!(out.contains("aix grep 'Cancel.*order|zzqq' frontend"), "{out}");
}

#[test]
fn sort_orders_rows_with_path_tiebreak() {
    let (_d, r) = repo();
    let o = sk(&r, &["find", "cancel", "--sort", "path", "--limit", "100"]);
    let paths: Vec<String> = o.lines().filter(|l| l.starts_with('[')).filter_map(|l| l.split_whitespace().nth(1)).map(|p| p.to_string()).collect();
    assert!(paths.len() > 5);
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "{o}");
    // grep spends its file cap in the requested order
    let g = sk(&r, &["grep", "cancel", "--sort", "size", "-l"]);
    assert!(g.contains("matching lines"), "{g}");
}

// ───────────────────────────── QA 4-B: paging tiles the whole result, errors are not "no", hide and labels agree ─────────────────────────────

fn rows_of(t: &str) -> Vec<String> {
    t.lines()
        .filter(|l| {
            let first = l.split_whitespace().next().unwrap_or("");
            let ctx = first.ends_with('-') && first.trim_end_matches('-').rsplit('-').next().is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            !l.starts_with("==") && !l.starts_with('(') && !l.trim().is_empty() && !l.contains(" defined: ") && first != "--" && !ctx
        })
        .map(str::to_string)
        .collect()
}

fn page_union(r: &Path, q: &[&str]) -> (Vec<String>, Vec<String>, usize) {
    let mut full_args: Vec<&str> = q.to_vec();
    // (rows compared line by line: no group-by-file layout on either side)
    full_args.extend(["--per-page", "100000", "--no-group"]);
    let full = rows_of(&sk(r, &full_args));
    let (mut all, mut p) = (vec![], 1);
    let mut total = 0;
    loop {
        let ps = p.to_string();
        let mut a: Vec<&str> = q.to_vec();
        a.extend(["--page", &ps, "--per-page", "3", "--no-group"]);
        let t = sk(r, &a);
        let got = rows_of(&t);
        if got.is_empty() {
            break;
        }
        if let Some(l) = t.lines().find(|l| l.contains(" of ") && l.contains("rows ")) {
            total = l.rsplit(" of ").next().unwrap().trim_end_matches([')', ':']).split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap_or(0);
        }
        all.extend(got);
        p += 1;
        assert!(p < 400, "runaway paging");
    }
    (all, full, total)
}

#[test]
fn pages_tile_the_whole_result_text_and_json() {
    let (_d, r) = repo();
    for q in [vec!["grep", "cancel"], vec!["grep", "-i", "order"], vec!["grep", "e", "-C", "1"], vec!["callers", "cancel"], vec!["text", "Cancel"], vec!["find", "cancel"]] {
        let (all, full, total) = page_union(&r, &q);
        assert_eq!(all, full, "{q:?}: the pages are not the whole result");
        assert!(total == 0 || total == full.len() || q[0] == "find" || q[0] == "text" || q[0] == "callers", "{q:?}: footer total {total} vs {} rows", full.len());
    }
    // totals agree with the header and with --plan / --count, for grep
    let plain = sk(&r, &["grep", "cancel", "--per-page", "100000"]);
    let head: usize = plain.lines().find(|l| l.contains(" matching lines in ")).unwrap().split(" matching lines in ").next().unwrap().rsplit(' ').next().unwrap().parse().unwrap();
    let plan = sk(&r, &["grep", "cancel", "--plan"]);
    assert!(plan.contains(&format!("{head} rows")), "{plan}");
    assert_eq!(rows_of(&plain).len(), head, "{plain}");
    // ... also after the pattern auto-materializes
    for _ in 0..4 {
        sk(&r, &["grep", "cancel"]);
    }
    sk(&r, &["update", "--full"]);
    let (all, full, _) = page_union(&r, &["grep", "cancel"]);
    assert_eq!(all, full);
    assert_eq!(full.len(), head, "materialized answer has {} rows, live had {head}", full.len());
    assert!(sk(&r, &["grep", "cancel", "--plan"]).contains(&format!("{head} rows")));
    // --json hits and --jsonl follow the page; a huge --per-page shows everything
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "grep", "cancel", "--page", "2", "--per-page", "2"])).unwrap();
    assert_eq!(j["hits"].as_array().unwrap().len(), 2, "{j}");
    let jl = sk(&r, &["--jsonl", "grep", "cancel", "--per-page", "3"]);
    assert_eq!(jl.lines().count(), 4, "3 hits and the summary: {jl}");
    let all_j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "grep", "cancel", "--per-page", "9999"])).unwrap();
    assert_eq!(all_j["hits"].as_array().unwrap().len(), head);
    // out of range
    let far = sk(&r, &["grep", "cancel", "--page", "99"]);
    assert!(far.contains("past the end") && far.contains("the last is --page"), "{far}");
}

#[test]
fn errors_are_not_no_and_global_flags_follow_the_pattern() {
    let (_d, r) = repo();
    for args in [vec!["grep", "(", "--exists"], vec!["grep", "(", "--plan"], vec!["grep", "("], vec!["grep", "cancel", "--sort", "bogus"], vec!["grep", "cancel", "--conf", "maybe"], vec!["callers", "cancel", "--order", "nope"], vec!["grep", "cancel", "--group-by", "dir:zero"]] {
        let t = sk_err(&r, &args);
        assert!(t.lines().count() <= 3 && !t.starts_with("no"), "{args:?}: {t}");
    }
    // --json / --jsonl / --no-refresh after the pattern work like before it
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["grep", "cancel", "--json"])).unwrap();
    assert!(j["hits"].as_array().is_some_and(|h| !h.is_empty()));
    assert!(sk(&r, &["grep", "cancel", "--jsonl", "--no-refresh"]).lines().last().unwrap().contains("summary"));
    // `aix card --json` is JSON
    let c: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "card"])).unwrap();
    assert!(c["card"].as_str().is_some_and(|t| !t.is_empty()) && c["lines"].is_array());
    // a grep -x followed by a word that is no exclusion list gets a hint
    let h = sk(&r, &["grep", "cancel", "-x", "bogus"]);
    assert!(h.contains("--exclude"), "{h}");
}

#[test]
fn group_by_match_uses_the_whole_match_and_hide_reaches_the_counts() {
    let (_d, r) = repo();
    let g = sk(&r, &["grep", "Cancel (order)", "--group-by", "match"]);
    assert!(g.contains("Cancel order") && !g.lines().any(|l| l.trim_end().ends_with("  order")), "{g}");
    let g1 = sk(&r, &["grep", "Cancel (order)", "--group-by", "match:1"]);
    assert!(g1.lines().any(|l| l.trim_end().ends_with("  order")), "{g1}");
    assert!(sk_err(&r, &["grep", "Cancel (order)", "--group-by", "match:5"]).contains("capture group"));
    // callers: the plan counts the call sites the answer lists, not the definitions above them; footers name real directories
    let p = sk(&r, &["callers", "cancel", "--plan"]);
    assert!(p.contains("2 rows") && !p.contains("<dir>"), "{p}");
    // --hide is in the counts, the existence check and the grouped shape
    let plain = sk(&r, &["grep", "cancel", "--plan"]);
    let hid = sk(&r, &["grep", "cancel", "--plan", "--hide", "docs,tests"]);
    assert!(hid.contains("hid ") && hid != plain, "{hid}");
    let row = |t: &str| -> usize { t.lines().next().unwrap().split(' ').find_map(|w| w.parse().ok()).unwrap_or(0) };
    assert!(row(&hid) < row(&plain), "{plain} / {hid}");
    let none = run(&r, &["grep", "cancel", "--exists", "--hide", "docs,tests,source,data"], &[]);
    assert_eq!(none.status.code(), Some(1), "everything hidden: no");
    assert!(String::from_utf8_lossy(&none.stdout).starts_with("no"));
    assert!(sk(&r, &["grep", "cancel", "--exists", "--hide", "docs"]).starts_with("yes"));
    let kinds = sk(&r, &["grep", "cancel", "--group-by", "kind"]);
    assert!(kinds.contains("docs") && !kinds.contains(" doc\n"), "kind labels match -x / --only: {kinds}");
}
