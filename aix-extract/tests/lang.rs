//! Language coverage: modern syntax per language version parses without errors and is attributed correctly
//! (members, receivers, imports), the new tree-sitter languages produce the expected code graph, and framework
//! routes / template strings come out right. Fixtures live under `tests/fixtures/lang`.

use std::path::{Path, PathBuf};

use aix_extract::codegraph::{Member, Ref};
use aix_extract::{Rows, SourceFile};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/lang")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(fixture().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Every built-in extractor on one fixture (as the indexer runs them); `as_path` is the path the file pretends to have.
fn run_as(rel: &str, as_path: &str) -> Rows {
    let exts = aix_extract::all();
    aix_extract::extract_file(&fixture(), &exts, &SourceFile::new(as_path, read(rel)))
}

fn run(rel: &str) -> Rows {
    run_as(rel, rel)
}

fn member<'a>(r: &'a Rows, q: &str) -> Vec<&'a Member> {
    r.members.iter().filter(|m| m.qname == q).collect()
}

fn refs<'a>(r: &'a Rows, caller: &str, callee: &str) -> Vec<&'a Ref> {
    r.refs.iter().filter(|x| x.caller == caller && x.callee == callee).collect()
}

/// Number of ERROR / MISSING nodes in the syntax tree of a fixture.
fn syntax_errors(rel: &str) -> usize {
    let ext = rel.rsplit('.').next().unwrap();
    let text = match aix_extract::lang::for_ext(ext).and_then(|l| l.preprocess(&read(rel))) {
        Some(t) => t,
        None => read(rel),
    };
    let lang = match ext {
        "java" => aix_extract::ts_util::java(),
        "ts" => aix_extract::ts_util::typescript(),
        "js" => aix_extract::ts_util::tsx(),
        "py" => aix_extract::ts_util::python(),
        e => aix_extract::lang::for_ext(e).unwrap().language(),
    };
    let mut p = tree_sitter::Parser::new();
    p.set_language(&lang).unwrap();
    let tree = p.parse(&text, None).unwrap();
    let mut n = 0;
    aix_extract::ts_util::walk(tree.root_node(), |x| {
        if x.is_error() || x.is_missing() {
            n += 1;
        }
        true
    });
    n
}

#[test]
fn modern_syntax_parses_cleanly() {
    let files = [
        "java/Modern21.java",
        "kotlin/Modern.kt",
        "ts/modern5.ts",
        "js/es2023.js",
        "py/modern313.py",
        "go/modern.go",
        "rust/modern.rs",
        "cs/Modern.cs",
        "php/modern.php",
        "rb/modern.rb",
        "swift/modern.swift",
        "scala/modern.scala",
        "c/lib.c",
        "cpp/modern.cpp",
        "dart/modern.dart",
        "lua/lib.lua",
    ];
    let bad: Vec<(&str, usize)> = files.iter().map(|f| (*f, syntax_errors(f))).filter(|x| x.1 > 0).collect();
    assert!(bad.is_empty(), "syntax errors: {bad:?}");
}

#[test]
fn java_17_to_21() {
    let r = run("java/Modern21.java");
    assert_eq!(member(&r, "Modern21.Point")[0].kind, "record");
    assert_eq!(member(&r, "Modern21.Point.dist")[0].kind, "method");
    assert!(member(&r, "Modern21.Shape")[0].kind == "interface");
    assert_eq!(member(&r, "Modern21.Circle")[0].kind, "record");
    assert_eq!(member(&r, "Modern21.describe")[0].kind, "method");
    // calls inside a pattern instanceof / switch are attributed to the enclosing method
    assert!(!refs(&r, "Modern21.check", "helper").is_empty());
}

#[test]
fn kotlin_1_9_and_2() {
    let r = run("kotlin/Modern.kt");
    assert_eq!(member(&r, "Circle")[0].kind, "record");
    assert_eq!(member(&r, "Shape")[0].kind, "interface");
    assert_eq!(member(&r, "Service")[0].kind, "class");
    assert_eq!(member(&r, "Service.repo")[0].ret, "Repo");
    assert_eq!(member(&r, "Level.parse").len(), 1, "companion members belong to the enclosing class");
    let c = refs(&r, "Service.load", "find");
    assert!(c.iter().any(|x| x.recv_type == "Repo" && x.conf == "exact"), "{c:?}");
    // `val svc = Service(Repo())` types `svc`
    assert!(refs(&r, "main", "describe").iter().any(|x| x.recv_type == "Service"));
    // a constructor call is a `new`
    assert!(refs(&r, "main", "Service").iter().any(|x| x.kind == "new" && x.argc == 1));
}

#[test]
fn typescript_5_and_js_2023() {
    let r = run("ts/modern5.ts");
    assert!(!member(&r, "Store").is_empty());
    assert!(!member(&r, "Store.list").is_empty());
    assert!(!member(&r, "run").is_empty());
    let j = run("js/es2023.js");
    assert!(!member(&j, "Cache.last").is_empty());
    assert!(!member(&j, "Cache.set").is_empty());
}

#[test]
fn python_3_10_to_3_13() {
    let r = run("py/modern313.py");
    assert!(!member(&r, "Box").is_empty());
    assert!(!member(&r, "Box.get").is_empty());
    assert!(!member(&r, "first").is_empty());
    assert!(!refs(&r, "describe", "helper").is_empty(), "calls inside match cases");
    assert!(!refs(&r, "helper", "get").is_empty());
}

#[test]
fn go_generics_and_range_over_func() {
    let r = run("go/modern.go");
    assert_eq!(member(&r, "Stack")[0].kind, "class");
    assert_eq!(member(&r, "Stack.Push")[0].container.as_deref(), Some("Stack"));
    assert!(!member(&r, "Sum").is_empty());
    assert!(member(&r, "Number")[0].kind == "interface");
    let c = refs(&r, "Use", "Push");
    assert!(c.iter().any(|x| x.recv_type == "Stack" && x.conf == "exact"), "{c:?}");
    assert!(!refs(&r, "Use", "All").is_empty());
}

#[test]
fn rust_2021_and_2024() {
    let r = run("rust/modern.rs");
    assert_eq!(member(&r, "Client")[0].supers, vec!["Fetch"], "impl Trait for Client");
    assert_eq!(member(&r, "Client.fetch")[0].kind, "method");
    assert_eq!(member(&r, "Client.new")[0].ret, "Client", "`-> Self` is the impl type");
    assert!(member(&r, "Client.new")[0].is_static);
    assert_eq!(member(&r, "Fetch.fetch")[0].kind, "method");
    // `self.helper(v)` inside a let-chain; `Client::new()` types `c`
    assert!(refs(&r, "Client.check", "helper").iter().any(|x| x.recv_type == "Client" && x.conf == "exact"));
    assert!(refs(&r, "main", "check").iter().any(|x| x.recv_type == "Client"));
    assert!(refs(&r, "Client.fetch", "get").iter().any(|x| x.recv_type == "HashMap"));
    // the receiver is not an argument
    assert!(member(&r, "Client.check")[0].sig.contains("check(id: u32)"), "{}", member(&r, "Client.check")[0].sig);
}

#[test]
fn csharp_10_to_12() {
    let r = run("cs/Modern.cs");
    assert_eq!(member(&r, "Person")[0].kind, "record");
    assert_eq!(member(&r, "Coord")[0].kind, "record");
    assert_eq!(member(&r, "Service.repo")[0].ret, "IRepo", "primary constructor parameter");
    assert!(refs(&r, "Service.Load", "Find").iter().any(|x| x.recv_type == "IRepo"));
    assert!(refs(&r, "Program.Main", "Load").iter().any(|x| x.recv_type == "Service"));
    assert!(refs(&r, "Program.Main", "Service").iter().any(|x| x.kind == "new" && x.argc == 2));
    assert!(member(&r, "Program.Helper")[0].is_static);
}

#[test]
fn php_8() {
    let r = run("php/modern.php");
    assert_eq!(member(&r, "Status")[0].kind, "enum");
    assert_eq!(member(&r, "Status")[0].supers, vec!["HasLabel"]);
    assert_eq!(member(&r, "Money.amount")[0].kind, "field", "promoted constructor property");
    assert_eq!(member(&r, "Service.run")[0].annos, vec!["Route('/x')"]);
    assert!(refs(&r, "Service.run", "add").iter().any(|x| x.recv_type == "Money"));
    assert!(refs(&r, "Service.run", "boot").iter().any(|x| x.recv_type == "Service"));
}

#[test]
fn ruby_3() {
    let r = run("rb/modern.rb");
    assert_eq!(member(&r, "Service")[0].kind, "class");
    assert_eq!(member(&r, "Service.helper")[0].vis, "private");
    assert!(member(&r, "Service.run")[0].sig.contains("key: 1"));
    // `@repo = Repo.new` types the instance variable
    assert!(refs(&r, "Service.run", "find").iter().any(|x| x.recv_type == "Repo"), "{:?}", refs(&r, "Service.run", "find"));
    assert!(!refs(&r, "Service.run", "helper").is_empty());
}

#[test]
fn symbol_level_languages() {
    let r = run("swift/modern.swift");
    assert_eq!(member(&r, "Cache")[0].kind, "class");
    assert!(refs(&r, "Service.load", "bump").iter().any(|x| x.recv_type == "Cache"));
    let r = run("scala/modern.scala");
    assert_eq!(member(&r, "User")[0].kind, "record");
    assert!(refs(&r, "Service.run", "find").iter().any(|x| x.recv_type == "Repo"));
    let r = run("c/lib.c");
    assert!(!member(&r, "add").is_empty() && !member(&r, "main").is_empty());
    assert!(!refs(&r, "main", "add").is_empty());
    let r = run("cpp/modern.cpp");
    assert!(!member(&r, "Stack.push").is_empty());
    assert!(!member(&r, "Stack.log").is_empty());
    assert!(refs(&r, "main", "push").iter().any(|x| x.recv_type == "Stack"));
    let r = run("dart/modern.dart");
    assert!(refs(&r, "Service.load", "find").iter().any(|x| x.recv_type == "Repo"));
    let r = run("lua/lib.lua");
    assert_eq!(member(&r, "M.add")[0].container.as_deref(), Some("M"));
    assert!(refs(&r, "M.run", "helper").iter().any(|x| x.recv_type == "M"));
}

#[test]
fn vue_and_svelte_scripts_keep_their_lines() {
    let r = run("vue/Hello.vue");
    let g = member(&r, "go");
    assert_eq!(g.len(), 1, "{:?}", r.members.iter().map(|m| (&m.qname, m.line)).collect::<Vec<_>>());
    assert_eq!(g[0].line, 12, "line of `function go` in the component");
    assert!(!refs(&r, "go", "helper").is_empty());
    let s = run("svelte/Hello.svelte");
    assert_eq!(member(&s, "bump")[0].line, 3);
}

#[test]
fn template_strings() {
    let txt = |r: &Rows| -> Vec<String> { r.ui_strings.iter().map(|u| format!("{}:{}", u.kind, u.text)).collect() };
    let v = txt(&run("vue/Hello.vue"));
    assert!(v.contains(&"jsx:Welcome back".to_string()), "{v:?}");
    assert!(v.contains(&"jsx:Save changes".to_string()));
    assert!(v.contains(&"prop:placeholder:Search here".to_string()));
    assert!(!v.iter().any(|s| s.contains("message")), "expressions are not copy: {v:?}");
    let j = txt(&run("templates/page.html.j2"));
    assert!(j.contains(&"jsx:Account settings".to_string()), "{j:?}");
    assert!(j.contains(&"prop:placeholder:Type a name".to_string()));
    assert!(!j.iter().any(|s| s.contains("not shown") || s.contains("user.name")), "{j:?}");
    let e = txt(&run("templates/page.html.erb"));
    assert!(e.contains(&"jsx:Order history".to_string()) && e.contains(&"jsx:Email address".to_string()), "{e:?}");
    let t = txt(&run("templates/th.html"));
    assert!(t.contains(&"jsx:Hello and welcome".to_string()) && t.contains(&"prop:title:Go home".to_string()), "{t:?}");
}

fn eps(r: &Rows) -> Vec<String> {
    r.endpoints.iter().map(|e| format!("{} {} {}.{}", e.method, e.path, e.class, e.handler)).collect()
}

#[test]
fn aspnet_routes() {
    let e = eps(&run("web/Orders.cs"));
    for want in ["GET /api/orders OrdersController.List", "GET /api/orders/{id} OrdersController.Get", "POST /api/orders/submit OrdersController.Submit", "DELETE /api/legacy/{id} OrdersController.Remove"] {
        assert!(e.contains(&want.to_string()), "{want}: {e:?}");
    }
    let r = run("web/Orders.cs");
    assert!(r.endpoints.iter().any(|x| x.handler == "Submit" && x.roles == vec!["public"]));
    assert!(r.endpoints.iter().any(|x| x.handler == "List" && x.roles == vec!["Admin", "Clerk"]));
    let m = eps(&run("web/Program.cs"));
    assert!(m.contains(&"GET /health .(inline)".to_string()), "{m:?}");
    assert!(m.contains(&"POST /api/v1/items .Create".to_string()), "{m:?}");
    assert!(m.contains(&"GET /api/v1/items/{id} .GetItem".to_string()), "{m:?}");
}

#[test]
fn laravel_routes() {
    let e = eps(&run_as("web/routes.php", "routes/web.php"));
    for want in ["GET / HomeController.index", "POST /login AuthController.login", "GET /admin/users/{id} UserController.show", "GET /admin/photos/{photo} PhotoController.show", "GET /orders OrderController.index", "POST /form FormController.handle", "GET /posts PostController.index"] {
        assert!(e.contains(&want.to_string()), "{want}: {e:?}");
    }
    assert!(!e.contains(&"POST /posts PostController.store".to_string()), "->only(['index']): {e:?}");
}

#[test]
fn rails_routes() {
    let e = eps(&run_as("web/routes.rb", "config/routes.rb"));
    for want in ["GET / HomeController.index", "GET /about PagesController.about", "GET /users/{id} UsersController.show", "POST /users/{id}/activate UsersController.activate", "GET /users/{user_id}/posts PostsController.index", "GET /admin/orders Admin::OrdersController.index", "GET /admin/stats Admin::DashboardController.stats", "GET /profile ProfilesController.show"] {
        assert!(e.contains(&want.to_string()), "{want}: {e:?}");
    }
    assert!(!e.iter().any(|x| x.starts_with("DELETE /admin/orders")), "except: [:destroy]");
    assert!(!e.iter().any(|x| x.starts_with("POST /users ")), "only: [:index, :show]");
}

#[test]
fn kotlin_and_rust_routes() {
    let k = eps(&run("web/Api.kt"));
    assert!(k.contains(&"GET /api/users .(inline)".to_string()) && k.contains(&"POST /api/users/{id} .(inline)".to_string()), "{k:?}");
    let s = run("web/Ctl.kt");
    assert!(eps(&s).contains(&"GET /orders/{id} OrderController.get".to_string()), "{:?}", eps(&s));
    assert!(s.endpoints.iter().any(|x| x.handler == "create" && x.roles == vec!["ADMIN"]));
    let r = eps(&run("web/web.rs"));
    for want in ["GET /api/users/{id} .user", "POST /users .create", "GET /api/ping .ping", "GET /items .list", "POST /items .add", "GET /v2/x .x", "GET /base/rocket/{name} .hello"] {
        assert!(r.contains(&want.to_string()), "{want}: {r:?}");
    }
}

#[test]
fn pathologically_deep_files_keep_their_top_level_declarations() {
    // 3000 nested parentheses: the walk refuses the tree, the file keeps a flat list of its declarations and a note
    let deep = |open: &str, close: &str| format!("{}1{}", open.repeat(3000), close.repeat(3000));
    let cases = [
        ("a.go", format!("package p\n\nfunc first() {{}}\n\nvar x = {}\n\nfunc second() {{}}\n", deep("(", ")"))),
        ("a.rs", format!("fn first() {{}}\nconst X: u32 = {};\npub fn second() {{}}\n", deep("(", ")"))),
        ("a.kt", format!("fun first() {{}}\nval x = {}\nfun second() {{}}\n", deep("(", ")"))),
        ("a.cs", format!("class A {{\n  void First() {{}}\n  int x = {};\n}}\n", deep("(", ")"))),
    ];
    let exts = aix_extract::all();
    for (path, text) in cases {
        let r = aix_extract::extract_file(&fixture(), &exts, &SourceFile::new(path, text));
        assert!(r.notes.iter().any(|n| n.kind == "extract-skipped" && n.text.contains("too deep")), "{path}: {:?}", r.notes);
        assert!(!r.members.is_empty() || path == "a.cs", "{path}: no flat members");
    }
}

#[test]
fn truncated_and_garbled_sources_never_panic() {
    let exts = aix_extract::all();
    let root = fixture();
    let mut files = vec![];
    for d in std::fs::read_dir(&root).unwrap().flatten() {
        if d.path().is_dir() {
            for f in std::fs::read_dir(d.path()).unwrap().flatten() {
                if f.path().is_file() {
                    files.push(f.path());
                }
            }
        }
    }
    assert!(files.len() > 25);
    for p in files {
        let text = std::fs::read_to_string(&p).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        for k in 1..12 {
            let mut cut = text.len() * k / 12;
            while !text.is_char_boundary(cut) {
                cut += 1;
            }
            let garbled: String = text[..cut].chars().rev().take(40).collect::<String>() + &text[cut..];
            for t in [&text[..cut], garbled.as_str()] {
                let r = aix_extract::extract_file(&root, &exts, &SourceFile::new(name.clone(), t.to_string()));
                assert!(!r.notes.iter().any(|n| n.text.contains("panic")), "{name} cut at {cut}: panic");
            }
        }
    }
}
