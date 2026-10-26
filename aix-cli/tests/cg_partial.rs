//! An update resolves the dirty refs against a partial code graph (only the names, import bindings and files they
//! reach). After every kind of edit that moves edges between files (a callee renamed in another file, a file deleted,
//! a method moved to another class, a super type changed, a module function moved), the incremental call graph must
//! equal a full build of the same tree, and the partial graph must really be the one used.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn update(repo: &Path, db: &Path, full: bool) -> String {
    update_env(repo, db, full, None)
}

fn update_env(repo: &Path, db: &Path, full: bool, max_memory: Option<&str>) -> String {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    if let Some(m) = max_memory {
        c.env("AIX_MAX_MEMORY", m).env("AIX_CG_BATCH", "1");
    }
    c.arg("--repo").arg(repo).arg("--db").arg(db).arg("update").env("AIX_PROFILE", "2").env("AIX_EMBED_URL", "");
    if full {
        c.arg("--full");
    }
    let o = c.output().unwrap();
    assert!(o.status.success(), "update: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// call_edges, sym_fanin and import targets by path (row ids differ between builds), as a multiset.
fn graph(db: &Path) -> BTreeMap<String, usize> {
    let c = rusqlite::Connection::open(db).unwrap();
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for sql in [
        "SELECT 'e', f.path, e.line, e.caller_line, g.path, e.callee_line, e.callee, e.cname, e.kind, e.conf FROM call_edges e JOIN files f ON f.rowid=e.fid JOIN files g ON g.rowid=e.cfid",
        "SELECT 'f', file, line, qname, n, files, '', '', '', '' FROM sym_fanin",
        // import targets follow the file list (a deleted or added module re-resolves the imports of unchanged files)
        "SELECT 'i', file, line, name, source, target, '', '', '', '' FROM imports",
    ] {
        let mut st = c.prepare(sql).unwrap();
        let rows = st
            .query_map([], |r| {
                let mut s = vec![];
                for i in 0..10 {
                    s.push(match r.get_ref(i)? {
                        rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                        rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                        _ => String::new(),
                    });
                }
                Ok(s.join("|"))
            })
            .unwrap();
        for r in rows {
            *out.entry(r.unwrap()).or_default() += 1;
        }
    }
    out
}

fn write(r: &Path, p: &str, t: &str) {
    let f = r.join(p);
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(f, t).unwrap();
}

#[test]
fn incremental_call_graph_equals_a_full_build_after_cross_file_edits() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    let j = "src/main/java/app";
    write(&r, &format!("{j}/Shape.java"), "package app;\npublic interface Shape {\n  double area();\n}\n");
    write(&r, &format!("{j}/Circle.java"), "package app;\npublic class Circle implements Shape {\n  public double area() {\n    return 3.0;\n  }\n}\n");
    let square = "package app;\npublic class Square implements Shape {\n  public double area() {\n    return 4.0;\n  }\n  public double side() {\n    return 2.0;\n  }\n}\n";
    write(&r, &format!("{j}/Square.java"), square);
    write(&r, &format!("{j}/Base.java"), "package app;\npublic class Base {\n  public int helper() {\n    return 1;\n  }\n}\n");
    write(&r, &format!("{j}/Other.java"), "package app;\npublic class Other {\n  public int helper() {\n    return 2;\n  }\n}\n");
    write(&r, &format!("{j}/Child.java"), "package app;\npublic class Child extends Base {\n  public int run() {\n    return helper();\n  }\n}\n");
    // reached only through the hierarchy: resolving `g.helper()` needs Child's type, which no dirty ref names
    write(&r, &format!("{j}/GrandChild.java"), "package app;\npublic class GrandChild extends Child {\n  public int extra() {\n    return 3;\n  }\n}\n");
    write(&r, &format!("{j}/Factory.java"), "package app;\npublic class Factory {\n  public static Square make() {\n    return new Square();\n  }\n}\n");
    write(
        &r,
        &format!("{j}/Service.java"),
        "package app;\npublic class Service {\n  public double total(Shape s) {\n    return s.area();\n  }\n  public double sq() {\n    Square q = Factory.make();\n    return q.side();\n  }\n  public int child(Child c) {\n    return c.helper() + c.run();\n  }\n  public int grand(GrandChild g) {\n    return g.helper();\n  }\n}\n",
    );
    write(&r, "web/util.ts", "export function fmt(x: number): string {\n  return String(x);\n}\nexport function parse(x: string): number {\n  return Number(x);\n}\n");
    write(&r, "web/app.ts", "import { fmt } from './util';\nexport function show(): string {\n  return fmt(1);\n}\n");
    write(&r, "web/other.ts", "import * as u from './util';\nexport function go(): number {\n  return u.parse('1');\n}\n");
    write(&r, "py/lib.py", "def compute(x):\n    return x\n\n\nclass Repo:\n    def load(self):\n        return 1\n");
    write(&r, "py/main.py", "from py.lib import compute, Repo\n\n\ndef run():\n    r = Repo()\n    return compute(r.load())\n");
    git(&r, &["init", "-q"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "init"]);
    std::fs::create_dir_all(d.path().join("db")).unwrap();
    let inc = d.path().join("db/inc.db");
    update(&r, &inc, true);
    let base = graph(&inc);
    assert!(base.keys().any(|k| k.starts_with("e|") && k.contains("Circle.java")), "interface call reaches its implementations: {base:#?}");
    let edits: Vec<(&str, Box<dyn Fn(&Path)>)> = vec![
        // a callee renamed in another file: callers in Child and Service lose their edges
        ("rename callee", Box::new(move |r: &Path| write(r, &format!("{j}/Base.java"), "package app;\npublic class Base {\n  public int helperX() {\n    return 1;\n  }\n}\n"))),
        // the super type changes: helper() now comes from Other
        ("change super", Box::new(move |r: &Path| write(r, &format!("{j}/Child.java"), "package app;\npublic class Child extends Other {\n  public int run() {\n    return helper();\n  }\n}\n"))),
        // a method moves to another class in another file
        ("move method out", Box::new(move |r: &Path| write(r, &format!("{j}/Square.java"), "package app;\npublic class Square implements Shape {\n  public double area() {\n    return 4.0;\n  }\n}\n"))),
        ("move method in", Box::new(move |r: &Path| write(r, &format!("{j}/Circle.java"), "package app;\npublic class Circle implements Shape {\n  public double area() {\n    return 3.0;\n  }\n  public double side() {\n    return 1.0;\n  }\n}\n"))),
        // an implementation is deleted: the interface call loses a target
        ("delete file", Box::new(move |r: &Path| std::fs::remove_file(r.join(format!("{j}/Circle.java"))).unwrap())),
        // the factory's return type changes: `q`'s calls re-resolve through it
        ("return type", Box::new(move |r: &Path| write(r, &format!("{j}/Factory.java"), "package app;\npublic class Factory {\n  public static Shape make() {\n    return new Square();\n  }\n}\n"))),
        // TypeScript: the imported function is renamed in its module, then a second module gains it
        ("ts rename", Box::new(|r: &Path| write(r, "web/util.ts", "export function fmt2(x: number): string {\n  return String(x);\n}\nexport function parse(x: string): number {\n  return Number(x);\n}\n"))),
        ("ts new file", Box::new(|r: &Path| {
            write(r, "web/util2.ts", "export function fmt(x: number): string {\n  return 'v' + x;\n}\n");
            write(r, "web/app.ts", "import { fmt } from './util2';\nexport function show(): string {\n  return fmt(1);\n}\n");
        })),
        // the module an unchanged file imports is deleted: its import no longer resolves
        ("ts delete", Box::new(|r: &Path| std::fs::remove_file(r.join("web/util2.ts")).unwrap())),
        // Python: a module function moves to another module, still importable from the old one (resolving it
        // reads the old module's imports, which no dirty ref is in)
        ("py move", Box::new(|r: &Path| {
            write(r, "py/calc.py", "def compute(x):\n    return x * 2\n");
            write(r, "py/lib.py", "from py.calc import compute\n\n\nclass Repo:\n    def load(self):\n        return 1\n");
        })),
        // a method appears in the middle of the hierarchy (GrandChild's call now stops at Child)
        ("override in between", Box::new(move |r: &Path| write(r, &format!("{j}/Child.java"), "package app;\npublic class Child extends Other {\n  public int run() {\n    return helper();\n  }\n  public int helper() {\n    return 9;\n  }\n}\n"))),
        ("restore", Box::new(move |r: &Path| {
            write(r, &format!("{j}/Square.java"), square);
            write(r, &format!("{j}/Circle.java"), "package app;\npublic class Circle implements Shape {\n  public double area() {\n    return 3.0;\n  }\n}\n");
        })),
    ];
    let mut partial = 0;
    for (i, (what, edit)) in edits.iter().enumerate() {
        edit(&r);
        git(&r, &["add", "-A"]);
        let log = update(&r, &inc, false);
        if log.contains("names loaded") {
            partial += 1;
        }
        let full = d.path().join(format!("db/full{i}.db"));
        update(&r, &full, true);
        let (a, b) = (graph(&inc), graph(&full));
        let only_inc: Vec<&String> = a.keys().filter(|k| a.get(*k) != b.get(*k)).collect();
        let only_full: Vec<&String> = b.keys().filter(|k| a.get(*k) != b.get(*k)).collect();
        assert!(a == b, "after '{what}': incremental differs from a full build\nonly/more in incremental: {only_inc:#?}\nonly/more in full: {only_full:#?}");
        // a full build under a memory budget too small for the whole graph resolves in batches of partial graphs
        let lean = d.path().join(format!("db/lean{i}.db"));
        let log = update_env(&r, &lean, true, Some("1"));
        assert!(log.contains("names loaded"), "after '{what}': the budgeted full build did not batch:\n{log}");
        assert!(graph(&lean) == b, "after '{what}': a budgeted (batched) full build differs from a full build");
    }
    assert!(partial >= edits.len() / 2, "the partial graph was used in only {partial} of {} updates", edits.len());
}

#[test]
fn a_c_call_binds_to_the_definition_its_includes_bring_in() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    write(&r, "include/linux/slab.h", "static inline void *kmalloc(int n)\n{\n\treturn 0;\n}\n");
    // the same name defined again in a separate build tree (kernel tools/), and in an unrelated header
    write(&r, "tools/lib/slab.c", "void *kmalloc(int n)\n{\n\treturn 0;\n}\n");
    write(&r, "tools/virtio/kernel.h", "static inline void *kmalloc(int n)\n{\n\treturn 0;\n}\n");
    write(&r, "mm/a.c", "#include <linux/slab.h>\n\nint use_a(void)\n{\n\tkmalloc(1);\n\treturn 0;\n}\n");
    // through one more header
    write(&r, "mm/local.h", "#include <linux/slab.h>\n");
    write(&r, "mm/b.c", "#include \"local.h\"\n\nint use_b(void)\n{\n\tkmalloc(2);\n\treturn 0;\n}\n");
    git(&r, &["init", "-q"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "init"]);
    let db = d.path().join("c.db");
    update(&r, &db, true);
    let edges: Vec<String> = graph(&db).into_keys().filter(|k| k.starts_with("e|mm/")).collect();
    for caller in ["mm/a.c", "mm/b.c"] {
        let mine: Vec<&String> = edges.iter().filter(|k| k.starts_with(&format!("e|{caller}|"))).collect();
        assert!(mine.len() == 1 && mine[0].contains("|include/linux/slab.h|") && mine[0].ends_with("|resolved"), "{caller}: {mine:#?}");
    }
    // the same edges from partial graphs (batched full build): the includes of a header loaded in a later pass count
    let lean = d.path().join("c-lean.db");
    update_env(&r, &lean, true, Some("1"));
    assert!(graph(&lean) == graph(&db), "batched C graph differs from the full one");
}
