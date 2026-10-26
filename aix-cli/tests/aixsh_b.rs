//! `aix grep` with GNU grep's flags: differential tests against GNU grep on a fixture tree (the same set of
//! `path:line:text` rows, order normalised, with `--bare --width 0`), plus aix's own additions (--and/--not, --body,
//! --member, --count-by, --total, exact -c/-l, row input `-`, refusals, context cap, width).

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
    (
        "src/app/main.ts",
        "import { save } from \"../lib/store\";\nexport function main(a: number) {\n  const foo = 1; // foo bar\n  if (a > 0) {\n    save(\"foo-bar\", a);\n  }\n  return foobar(a) + foo_bar;\n}\nfunction foobar(x: number) { return x * 2; }\n// TODO: café naïve résumé\nconst FOO = \"Foo foo FOO\";\nexport const re = /a|b/;\n",
    ),
    (
        "src/lib/store.ts",
        "export function save(key: string, v: number) {\n  console.log(\"save\", key, v);\n  audit(key);\n}\nfunction audit(k: string) {\n  // TODO audit trail\n  return k;\n}\nexport function load(key: string) { return key; }\n",
    ),
    ("src/lib/util.py", "def helper(x):\n    # TODO: helper\n    return x + 1\n\ndef foo(a, b):\n    return a|b\n\nclass Store:\n    def save(self, k):\n        print(\"save\", k)\n"),
    ("tests/store.test.ts", "import { save } from \"../src/lib/store\";\ntest(\"save works\", () => { save(\"k\", 1); });\n// foo in test\n"),
    ("docs/guide.md", "# Guide\nUse foo to save. Ünïcödé line: Straße STRASSE\n- foo-bar item\n- a-b item and x-a-b-y\n"),
    (
        "src/app/Main.java",
        "public class Main {\n    @RolesAllowed(\"admin\")\n    public void run() {\n        int foo = 1;\n        System.out.println(\"foo\" + foo);\n    }\n    @RolesAllowed({\"admin\", \"user\"})\n    public void stop() {}\n}\n",
    ),
];

struct Fx {
    _d: tempfile::TempDir,
    repo: PathBuf,
    db: PathBuf,
}

fn fixture(extra: &[(String, String)]) -> Fx {
    let d = tempfile::tempdir().unwrap();
    let repo = d.path().join("shop");
    let all: Vec<(String, String)> = FILES.iter().map(|(a, b)| (a.to_string(), b.to_string())).chain(extra.iter().cloned()).collect();
    for (p, t) in &all {
        let f = repo.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    let db = d.path().join("ix.db");
    Fx { _d: d, repo, db }
}

fn aix_in(fx: &Fx, args: &[&str], stdin: Option<&str>) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.current_dir(&fx.repo).arg("--db").arg(&fx.db).args(args).env("AIX_EMBED_URL", "").env("HOME", &fx.repo).stdout(Stdio::piped()).stderr(Stdio::piped());
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn aix(fx: &Fx, args: &[&str]) -> (i32, String) {
    aix_in(fx, args, None)
}

/// GNU grep, if installed (the differential tests skip without it).
#[cfg(unix)]
fn gnu() -> Option<String> {
    for g in ["/usr/bin/grep", "/bin/grep", "grep"] {
        if let Ok(o) = Command::new(g).arg("--version").output() {
            if String::from_utf8_lossy(&o.stdout).contains("GNU grep") {
                return Some(g.to_string());
            }
        }
    }
    None
}

fn norm(s: &str, drop_zero: bool) -> Vec<String> {
    let mut v: Vec<String> = s
        .lines()
        .filter(|l| *l != "--" && !l.is_empty())
        .filter(|l| !(drop_zero && l.ends_with(":0")))
        .map(|l| l.strip_prefix("./").unwrap_or(l).to_string())
        .collect();
    v.sort();
    v
}

/// (aix grep args; GNU gets the same plus `-rnH --exclude-dir=.git` and `.` unless the case names paths)
#[cfg(unix)]
const CASES: &[(&[&str], bool)] = &[
    (&["foo"], false),
    (&["-i", "foo"], false),
    (&["-w", "foo"], false),
    (&["-x", "-F", "export const re = /a|b/;"], false),
    (&["-F", "a|b"], false),
    (&["save\\|audit"], false),
    (&["-E", "save|audit"], false),
    (&["\\(foo\\)\\+bar"], false),
    (&["-E", "x{2}|a+b"], false),
    (&["^ *//"], false),
    (&["foo$"], false),
    (&["-v", "foo", "src/lib"], true),
    (&["-v", "-A1", "foo", "src/lib/store.ts"], true),
    (&["-v", "-m2", "-A1", "foo", "src/lib/store.ts"], true),
    (&["-A2", "save"], false),
    (&["-B1", "-A1", "TODO"], false),
    (&["-C", "3", "audit"], false),
    (&["-5", "audit", "src/lib/store.ts"], true),
    (&["-o", "fo[a-z]*"], false),
    (&["-o", "-i", "foo"], false),
    (&["-ow", "foo"], false),
    (&["-o", "Roles[A-Za-z]*"], false),
    (&["-m1", "foo"], false),
    (&["-m1", "-A2", "foo"], false),
    (&["-m2", "-A3", "save"], false),
    (&["-l", "foo"], false),
    (&["-l", "-v", "foo"], false),
    (&["-L", "foo"], false),
    (&["-c", "foo"], false),
    (&["-vc", "foo", "src/lib/store.ts"], true),
    (&["-c", "zzz", "src/lib/store.ts"], true),
    (&["--include=*.ts", "foo"], false),
    (&["--include=*.ts", "--include=*.py", "TODO"], false),
    (&["--exclude=*.ts", "foo"], false),
    (&["--exclude-dir=tests", "foo"], false),
    (&["--exclude-dir=lib", "--include=*.ts", "save"], false),
    (&["-i", "straße"], false),
    (&["ü"], false),
    (&["-w", "a-b"], false),
    (&["-w", "--", "-bar"], false),
    (&["-e", "foo", "-e", "save"], false),
    (&["-rnI", "foo", "src", "docs"], true),
    (&["-in", "foo", "src/app/main.ts", "src/lib/util.py"], true),
    (&["-h", "foo", "src/lib"], true),
    (&["-x", "-i", "# guide"], false),
];

// Unix only: Git for Windows ships GNU grep 3.0 (no trailing context after the -m-th match), the reference here is
// current GNU grep
#[cfg(unix)]
#[test]
fn differential_vs_gnu_grep() {
    let Some(g) = gnu() else {
        eprintln!("GNU grep not installed: differential test skipped");
        return;
    };
    let fx = fixture(&[]);
    let mut fails = vec![];
    for (args, has_paths) in CASES {
        let mut ga: Vec<&str> = vec!["-rnH", "--exclude-dir=.git"];
        ga.extend(args.iter());
        if !has_paths {
            ga.push(".");
        }
        let go = Command::new(&g).current_dir(&fx.repo).env("LC_ALL", "C.UTF-8").args(&ga).output().unwrap();
        let gs = String::from_utf8_lossy(&go.stdout).to_string();
        let mut aa: Vec<&str> = vec!["grep", "--bare", "--width", "0"];
        aa.extend(args.iter());
        let (code, out) = aix(&fx, &aa);
        let count = args.iter().any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'));
        let (ge, ae) = (norm(&gs, count && !has_paths), norm(&out, false));
        if ge != ae {
            fails.push(format!("grep {args:?}\n  GNU: {ge:?}\n  aix: {ae:?}"));
        }
        // the exit status follows GNU's (0 a line was selected, 1 none)
        if go.status.code() != Some(code) {
            fails.push(format!("grep {args:?}: exit GNU {:?} aix {code}", go.status.code()));
        }
    }
    assert!(fails.is_empty(), "{} of {} cases differ:\n{}", fails.len(), CASES.len(), fails.join("\n"));
}

#[test]
fn counts_and_lists_are_exact_and_untruncated() {
    let extra: Vec<(String, String)> = (0..40).map(|i| (format!("src/many/f{i:02}.ts"), format!("// marker {i}\nconst x{i} = 1; // marker\n"))).collect();
    let fx = fixture(&extra);
    let (code, out) = aix(&fx, &["grep", "-c", "marker"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("== 80 matching lines in 40 files"), "{out}");
    assert_eq!(out.lines().filter(|l| l.ends_with(": 2")).count(), 40, "{out}");
    assert!(!out.contains("Too broad"), "{out}");
    let (_, out) = aix(&fx, &["grep", "-l", "marker", "--bare"]);
    assert_eq!(out.lines().count(), 40, "{out}");
    let (_, out) = aix(&fx, &["grep", "--total", "marker", "--bare"]);
    assert_eq!(out.trim(), "80");
    let (_, out) = aix(&fx, &["grep", "-l", "marker", "--head", "5"]);
    assert!(out.contains("35 more files not shown") && out.contains("--head 40"), "{out}");
}

#[test]
fn and_not_count_by_body_member() {
    let fx = fixture(&[]);
    let (_, out) = aix(&fx, &["grep", "save", "--not", "test", "--and", "\\(", "--bare"]);
    let v = norm(&out, false);
    assert!(v.iter().all(|l| !l.contains("test") && l.contains('(')), "{v:?}");
    assert!(v.iter().any(|l| l.starts_with("src/lib/util.py:10:")), "{v:?}");
    let (_, out) = aix(&fx, &["grep", "-n", "save", "--not-in", "tests/", "--bare", "-l"]);
    assert!(!out.contains("tests/store.test.ts") && out.contains("src/lib/store.ts"), "{out}");
    let (_, out) = aix(&fx, &["grep", "-o", "fo[a-z]*", "--count-by", "match", "--bare"]);
    assert_eq!(out.lines().next(), Some("12\tfoo"), "{out}");
    let (_, out) = aix(&fx, &["grep", "-o", "@(Roles)([A-Za-z]+)", "--group", "2", "--bare"]);
    assert_eq!(norm(&out, false), vec!["src/app/Main.java:2:Allowed", "src/app/Main.java:7:Allowed"]);
    let (_, out) = aix(&fx, &["grep", "TODO", "--count-by", "ext", "--bare"]);
    assert_eq!(out.trim(), "2\tts\n1\tpy", "{out}");
    let (_, out) = aix(&fx, &["grep", "audit", "--body"]);
    assert!(out.contains("== src/lib/store.ts:1-4 function save") && out.contains("src/lib/store.ts-7-   return k;"), "{out}");
    let (_, out) = aix(&fx, &["grep", "audit", "--member", "--bare"]);
    assert_eq!(norm(&out, false), vec!["src/lib/store.ts:1-4\tfunction save\t1", "src/lib/store.ts:5-8\tfunction audit\t2"]);
}

#[test]
fn row_input_scopes_files_and_ranges() {
    let fx = fixture(&[]);
    let (_, callers) = aix(&fx, &["callers", "audit"]);
    let (code, out) = aix_in(&fx, &["grep", "TODO", "-", "--bare"], Some(&callers));
    assert_eq!((code, out.trim()), (0, "src/lib/store.ts:6:  // TODO audit trail"), "{callers}");
    // --within: only lines inside the input rows' members (a call site widens to its enclosing function)
    let (_, out) = aix_in(&fx, &["grep", "log", "-", "--within", "--bare"], Some("src/lib/store.ts:3:  audit(key);\n"));
    assert_eq!(out.trim(), "src/lib/store.ts:2:  console.log(\"save\", key, v);");
    let (code, _) = aix_in(&fx, &["grep", "TODO", "-", "--within", "--bare"], Some("src/lib/store.ts:3:  audit(key);\n"));
    assert_eq!(code, 1);
    // outline rows (`L5-8 ...` under the file header), GNU rows from another tool, Windows paths, CRLF
    let (_, ol) = aix(&fx, &["outline", "src/lib/store.ts"]);
    let (_, out) = aix_in(&fx, &["grep", "-c", "TODO", "-", "--bare"], Some(&ol));
    assert_eq!(out.trim(), "src/lib/store.ts:1", "{ol}");
    let (_, out) = aix_in(&fx, &["grep", "-l", "foo", "-", "--bare"], Some("C:\\work\\shop\\src\\lib\\util.py:5:def foo\r\n./docs/guide.md\r\n"));
    assert_eq!(norm(&out, false), vec!["docs/guide.md", "src/lib/util.py"]);
    // -l rows chain: files having both
    let (_, l) = aix(&fx, &["grep", "-l", "save", "--bare"]);
    let (_, out) = aix_in(&fx, &["grep", "-l", "TODO", "-", "--bare"], Some(&l));
    assert_eq!(norm(&out, false), vec!["src/app/main.ts", "src/lib/store.ts", "src/lib/util.py"]);
    // no row input: a usage error, never a silent repo-wide search for "foo -"
    let (code, out) = aix(&fx, &["grep", "foo", "-"]);
    assert!(code != 0 && !out.contains("src/"), "{out}");
    let (code, out) = aix(&fx, &["grep", "foo", "--within"]);
    assert_eq!(code, 2, "{out}");
}

#[test]
fn refusals_caps_and_width() {
    let long = format!("const s = \"{}\"; // needle\n", "x".repeat(400));
    let fx = fixture(&[("src/long.ts".to_string(), long.clone())]);
    for f in ["-P", "-z", "-f", "--null", "--label=x", "-b"] {
        let (code, out) = aix(&fx, &["grep", f, "foo"]);
        assert_eq!(code, 2, "{f}: {out}");
        assert!(out.contains("unsupported flag") && out.contains("`grep "), "{f}: {out}");
    }
    let (code, out) = aix(&fx, &["grep", "-o", "-A", "2", "foo"]);
    assert_eq!(code, 2, "{out}");
    let (code, out) = aix(&fx, &["grep", "(a)\\1"]);
    assert_eq!(code, 2, "{out}");
    // context above 5 is honoured, above 30 capped with a note
    let (_, out) = aix(&fx, &["grep", "-A", "8", "export function save", "src/lib/store.ts"]);
    assert!(out.contains("src/lib/store.ts-9- export function load"), "{out}");
    let (_, out) = aix(&fx, &["grep", "-A", "40", "audit", "src/lib/store.ts"]);
    assert!(out.contains("context capped at 30"), "{out}");
    // width: default 200 with an ellipsis, 0 = the whole line, indentation kept
    let (_, out) = aix(&fx, &["grep", "needle", "--bare"]);
    let row = out.lines().next().unwrap();
    assert!(row.ends_with('…') && row.chars().count() == "src/long.ts:1:".len() + 201, "{row}");
    let (_, out) = aix(&fx, &["grep", "needle", "--bare", "--width", "0"]);
    assert_eq!(out.trim_end(), format!("src/long.ts:1:{}", long.trim_end()));
    let (_, out) = aix(&fx, &["grep", "-n", "console.log", "src/lib/store.ts", "--bare"]);
    assert_eq!(out.trim_end(), "src/lib/store.ts:2:  console.log(\"save\", key, v);");
    // -q: nothing printed, the status is the answer
    let (code, out) = aix(&fx, &["grep", "-q", "foo"]);
    assert_eq!((code, out.as_str()), (0, ""));
    let (code, _) = aix(&fx, &["grep", "-q", "zzzz_none"]);
    assert_eq!(code, 1);
    // aix's own --exclude kinds still work next to GNU --exclude=GLOB
    let (_, out) = aix(&fx, &["grep", "-l", "save", "--exclude", "tests", "--bare"]);
    assert!(!out.contains("tests/"), "{out}");
}
