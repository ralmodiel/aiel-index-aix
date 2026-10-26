//! Round-5 QA (correctness): grep selects on the file's text (prints it redacted), `--` after a flag, an explicit
//! --head lifts the byte budget, output options do not re-quote paths, outline of a path with a space, code files
//! named like keys are indexed, partial and skipped-file notes in every form, missing paths are errors, `F:A-A` is
//! one line, one-argument --bare rows verbatim, `-t` for every language, a BOM before `^`.

use std::path::{Path, PathBuf};
use std::process::Command;

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

fn aix_env(r: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(r).args(args).env("AIX_EMBED_URL", "").env("HOME", r).env("AIX_LOCK_DIR", r.join(".locks"));
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn aix(r: &Path, args: &[&str]) -> (i32, String, String) {
    aix_env(r, args, &[])
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    let w = |rel: &str, body: &[u8]| {
        let p = r.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    w(".gitignore", b".aix/\n.locks/\n");
    w("src/plain.ts", b"alpha one\nbeta two\nalpha three\n\tTabbed alpha\n");
    w("src/with space.ts", b"export function spaced() {\n  return 1;\n}\n");
    w("src/p(1).ts", b"export function parenFn() {\n  return 1;\n}\n");
    w("src/with.ts", b"export function other() {\n  return 2;\n}\n");
    w("app/models/api_key.rb", b"class ApiKey\n  def owner\n  end\nend\n");
    w("src/table.go", b"  {m: mGET, r: \"/users/2/settings/password\", h: hStub15, k: []string{\"id\"}},\n");
    w("src/creds.go", b"  {m: mPOST, pw: pStub27, k: 1},\n");
    w("docs/bench.md", b"Measurement modes are identified by their configuration,\n");
    w("src/Bom.cs", b"\xef\xbb\xbfusing System;\nusing System.Text;\n");
    w("src/cls.ts", b"class C {\n  a() {\n    return 1;\n  }\n}\n");
    let many: String = (0..3000).map(|i| format!("export const value_{i:05} = \"padding padding padding\";\n")).collect();
    w("src/many.ts", many.as_bytes());
    let big: String = (0..40000).map(|i| format!("export const big_{i:06} = 1; // filler filler filler\n")).collect();
    w("src/big.ts", big.as_bytes());
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    aix(&r, &["update"]);
    (d, r)
}

#[test]
fn grep_correctness_round5() {
    let (_d, r) = fixture();
    // selection on the file text: a token the redactor masks is found, a mask label never matches
    // a match only inside a redacted span is no hit (no oracle); a visible match on the same line is
    let (c, out, _) = aix(&r, &["grep", "-c", "pStub27", "--bare"]);
    assert!(c == 1 && out.trim().is_empty(), "{out}");
    // a route path naming `password` does not make the line's other tokens secrets
    let (_, out, _) = aix(&r, &["grep", "-c", "hStub15", "--bare"]);
    assert_eq!(out.trim(), "src/table.go:1", "{out}");
    let (_, out, _) = aix(&r, &["grep", "-c", "mGET", "--bare"]);
    assert_eq!(out.trim(), "src/table.go:1", "{out}");
    let (c, out, _) = aix(&r, &["grep", "-c", "password", "docs/bench.md", "--bare"]);
    assert!(c == 1 && out.trim() == "docs/bench.md:0", "{c} {out}");
    // a flag before `--`
    let (_, out, _) = aix(&r, &["--bare", "grep", "-c", "--", "alpha", "src/plain.ts"]);
    assert_eq!(out.trim(), "src/plain.ts:3", "{out}");
    // an explicit --head N is N rows in --bare
    let (_, out, _) = aix(&r, &["grep", "value_", "src/many.ts", "--bare", "--head", "3000"]);
    assert_eq!(out.lines().filter(|l| !l.starts_with('\u{2026}')).count(), 3000);
    // budget-cut and skipped files are said in --bare too
    let (c, _, err) = aix_env(&r, &["grep", "-c", "export", "--bare"], &[("AIX_GREP_BUDGET_MS", "0")]);
    assert!(err.contains("partial") && c == 2, "{c} {err}");
    let (_, out, err) = aix(&r, &["grep", "-l", "export const", "--bare"]);
    assert!(err.contains("src/big.ts") && !out.contains("src/big.ts"), "{err}");
    // a missing path among real ones: the real ones are searched, the status is 2
    let (c, out, err) = aix(&r, &["grep", "-c", "alpha", "src/plain.ts", "nosuch.ts", "--bare"]);
    assert!(c == 2 && out.trim() == "src/plain.ts:3" && err.contains("nosuch.ts"), "{c} {out} {err}");
    let (c, out, _) = aix(&r, &["grep", "alpha", "srcc"]);
    assert!(c == 1 && out.contains("path not found"), "{c} {out}");
    // `.` is the repo
    let (c, out, _) = aix(&r, &["grep", "-c", "alpha", ".", "--bare"]);
    assert!(c == 0 && out.contains("src/plain.ts:3"), "{out}");
    // -t for the other indexed languages, a BOM before ^
    for t in ["go", "cs", "rb", "php", "lua", "swift", "c", "cpp", "vue", "toml", "xquery"] {
        assert!(aix(&r, &["grep", "-c", "x", "-t", t, "--bare"]).0 <= 1, "-t {t}");
    }
    let (_, out, _) = aix(&r, &["grep", "-c", "^using", "src/Bom.cs", "--bare"]);
    assert_eq!(out.trim(), "src/Bom.cs:2");
    // the one-argument form prints --bare rows verbatim (leading tab kept)
    let (_, out, _) = aix(&r, &["--bare", "grep -n Tabbed src/plain.ts"]);
    assert!(out.contains(":4:\tTabbed"), "{out:?}");
}

#[test]
fn reads_and_paths_round5() {
    let (_d, r) = fixture();
    for c in ["history", "outline"] {
        assert_eq!(aix(&r, &["--bare", c, "src/p(1).ts"]).0, 0, "{c}");
        assert_eq!(aix(&r, &[c, "src/p(1).ts", "--head", "5"]).0, 0, "{c}");
    }
    assert_eq!(aix(&r, &["code", "src/with space.ts:1-3", "--bare"]).0, 0);
    let (_, out, _) = aix(&r, &["outline", "src/with space.ts"]);
    assert!(out.lines().next().unwrap_or("").contains("with space"), "{out}");
    let (_, out, _) = aix(&r, &["files", "app/models/api_key.rb", "--bare"]);
    assert_eq!(out.trim(), "app/models/api_key.rb");
    let (_, out, _) = aix(&r, &["code", "src/cls.ts:4-4", "--bare"]);
    assert_eq!(out.lines().filter(|l| l.starts_with("src/cls.ts:")).count(), 1, "{out}");
}
