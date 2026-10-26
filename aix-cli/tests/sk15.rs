//! SK-15: code-graph resolution across files and languages: Python imports and packages, TS barrels and tsconfig
//! aliases, Go ranges and receiver types, functions used as values, route handlers, too-deep files, overloads and
//! framework-invoked members.

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
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
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
fn go_ranges_ignore_runes_strings_and_comments() {
    let src = "package p\n\nfunc a() {\n\tr := '{'\n\ts := \"}\"\n\t// }\n\tt := `\n}\n`\n\t_, _ = r, s\n\tb()\n}\n\nfunc b() {}\n\nfunc c() {\n\ta()\n}\n";
    let (_d, r) = repo(&[("p.go", src)]);
    let o = sk(&r, &["outline", "p.go"]);
    assert!(o.contains("L3-12 fn func a()"), "{o}");
    assert!(o.contains("L14-14 fn func b()"), "{o}");
    assert!(o.contains("L16-18 fn func c()"), "{o}");
    let cb = sk(&r, &["callers", "b"]);
    assert!(cb.contains("p.go:11 a"), "{cb}");
    assert!(!cb.contains("(exact)"), "same-package name matches are not exact: {cb}");
}

#[test]
fn go_receiver_types_follow_locals_and_values() {
    let src = "package p\n\ntype T struct{ n int }\n\nfunc (t *T) Run() {}\n\nfunc use(x any) {\n\ta := &T{}\n\ta.Run()\n\tvar b T\n\tb.Run()\n\tc := x.(*T)\n\tc.Run()\n\tgo hold(a.Run)\n}\n\nfunc hold(f func()) {}\n";
    let (_d, r) = repo(&[("p.go", src)]);
    let o = sk(&r, &["--limit", "50", "callers", "T.Run"]);
    for l in ["p.go:9 use (exact)", "p.go:11 use (exact)", "p.go:13 use (exact)", "p.go:14 use used as value (exact)"] {
        assert!(o.contains(l), "missing {l}: {o}");
    }
}

#[test]
fn python_modules_packages_and_relative_imports() {
    let (_d, r) = repo(&[
        ("src/pkg/__init__.py", ""),
        ("src/pkg/crud.py", "def create(*, name):\n    return name\n\ndef get(i):\n    return i\n\nclass Repo:\n    def save(self, x):\n        return self.check(x)\n    def check(self, x):\n        return x\n"),
        ("src/pkg/api.py", "from pkg import crud\nfrom .crud import get as fetch, Repo\nimport pkg.crud as m\n\ndef a():\n    crud.create(name=1)\n    fetch(2)\n    m.get(3)\n    Repo().save(1)\n"),
        ("src/pkg/util.py", "import pkg.crud\n\ndef u():\n    return pkg.crud.get(1)\n"),
    ]);
    let o = sk(&r, &["--limit", "50", "callers", "crud.create"]);
    assert!(o.contains("src/pkg/api.py:6 a (exact)"), "{o}");
    let g = sk(&r, &["--limit", "50", "callers", "get"]);
    for l in ["src/pkg/api.py:7 a (exact)", "src/pkg/api.py:8 a (exact)", "src/pkg/util.py:4 u (exact)"] {
        assert!(g.contains(l), "missing {l}: {g}");
    }
    let s = sk(&r, &["callers", "Repo.check"]);
    assert!(s.contains("src/pkg/crud.py:9 Repo.save (exact)"), "{s}");
    let out = sk(&r, &["outline", "src/pkg/crud.py"]);
    assert!(out.contains("create(*, name)") && !out.contains("def create"), "{out}");
}

#[test]
fn ts_barrels_and_tsconfig_aliases() {
    let (_d, r) = repo(&[
        ("web/tsconfig.json", "{\n  // comment\n  \"compilerOptions\": { \"paths\": { \"@/*\": [\"./src/*\"], }, },\n}\n"),
        ("web/src/client/svc.ts", "export class Svc {\n  static run() { return 1; }\n}\n"),
        ("web/src/client/index.ts", "export * from './svc';\n"),
        ("web/src/lib/index.ts", "export { Svc as Service } from '../client';\n"),
        ("web/src/page.tsx", "import { Svc } from '@/client';\nimport { Service } from '@/lib';\nexport function P() {\n  Svc.run();\n  Service.run();\n  return null;\n}\n"),
    ]);
    let o = sk(&r, &["--limit", "50", "callers", "Svc.run"]);
    assert!(o.contains("web/src/page.tsx:4 P (exact)"), "{o}");
    assert!(o.contains("web/src/page.tsx:5 P (exact)"), "{o}");
}

#[test]
fn functions_used_as_values_and_route_handlers() {
    let (_d, r) = repo(&[(
        "app.ts",
        "import express from 'express';\nconst router = express.Router();\nfunction handleError(e) { return e; }\nfunction mw(req, res, next) { next(); }\nrouter.get('/x', mw, async (req, res) => {\n  const local = await load();\n  res.json(local);\n});\nPromise.reject(1).catch(handleError);\nconst o = { onError: handleError };\nasync function load() { return 1; }\n",
    )]);
    let h = sk(&r, &["--limit", "50", "callers", "handleError"]);
    assert!(h.contains("app.ts:9") && h.contains("app.ts:10") && h.contains("used as value"), "{h}");
    let l = sk(&r, &["callers", "load"]);
    assert!(l.contains("router.get /x handler"), "{l}");
    let o = sk(&r, &["outline", "app.ts"]);
    assert!(o.contains("router.get /x handler") && !o.contains("const local"), "{o}");
}

#[test]
fn too_deep_files_keep_a_flat_symbol_scan_and_say_so() {
    let n = 5000;
    let (_d, r) = repo(&[
        ("deep.ts", &format!("export function first() {{ return 1; }}\nexport class Box {{}}\nexport class Crate {{}}\nexport const x = {};\nexport function last() {{}}\n", vec!["1"; n].join("+"))),
        ("ok.ts", "import { first } from './deep';\nexport function f() { return first(); }\n"),
    ]);
    let o = sk(&r, &["outline", "deep.ts"]);
    assert!(o.contains("deep.ts was skipped: too deep") && o.contains("first") && o.contains("Box") && o.contains("Crate") && o.contains("last"), "{o}");
    let c = sk(&r, &["callers", "f"]);
    assert!(c.contains("deep.ts was skipped: too deep"), "{c}");
}

#[test]
fn overloads_pick_by_argument_count_and_code_lists_them() {
    let (_d, r) = repo(&[
        ("A.java", "public class A {\n  public int get(String a) { return 1; }\n  public int get(String a, int b) { return 2; }\n}\n"),
        ("B.java", "public class B {\n  A a = new A();\n  int one() { return a.get(\"x\"); }\n  int two() { return a.get(\"x\", 1); }\n}\n"),
    ]);
    let one = sk(&r, &["callers", "A.get"]);
    assert!(one.contains("B.java:3 B.one") && one.contains("B.java:4 B.two"), "{one}");
    let code = sk(&r, &["code", "A.get/2"]);
    assert!(code.contains("2 overloads of get") && code.contains("[1 arg]") && code.contains("[2 args]"), "{code}");
    assert!(code.contains("return 2") && !code.contains("return 1"), "{code}");
}

#[test]
fn framework_invoked_members_say_so() {
    let (_d, r) = repo(&[
        ("C.java", "public class C {\n  @InitBinder\n  public void bind() {}\n  public void plain() {}\n}\n"),
        ("api.py", "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/h')\ndef health():\n    return 1\n\ndef plain():\n    return 2\n"),
    ]);
    assert!(sk(&r, &["callers", "C.bind"]).contains("invoked by the framework (@InitBinder)"));
    assert!(!sk(&r, &["callers", "C.plain"]).contains("framework"));
    assert!(sk(&r, &["callers", "health"]).contains("invoked by the framework (@router.get)"));
}
