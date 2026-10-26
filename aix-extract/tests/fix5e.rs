//! Extractor fixes (round 5e): macro arguments, routes in comments, Ktor clients, ASP.NET auth, same-line attributes, ...

use aix_extract::{Rows, SourceFile};

fn run(path: &str, text: &str) -> Rows {
    let exts = aix_extract::all();
    aix_extract::extract_file(std::path::Path::new("."), &exts, &SourceFile::new(path, text.to_string()))
}

fn has_ref(r: &Rows, caller: &str, callee: &str) -> bool {
    r.refs.iter().any(|x| x.caller == caller && x.callee == callee)
}

#[test]
fn rust_macro_arguments_are_calls() {
    let r = run(
        "src/a.rs",
        r#"
macro_rules! shout { ($x:expr) => { $x } }
fn go(x: &str) -> String {
    let a = format!("{}", display_path(x));
    anyhow::bail!("bad {}", util::describe(x));
    let v = vec![make_one(), Thing::build(1)];
    assert!(check(x).is_ok(), "{}", x.trim_name());
    shout!(1);
    a
}
"#,
    );
    for c in ["display_path", "describe", "make_one", "build", "check", "trim_name", "shout"] {
        assert!(has_ref(&r, "go", c), "missing {c}: {:?}", r.refs.iter().map(|x| (&x.caller, &x.callee)).collect::<Vec<_>>());
    }
    assert!(!has_ref(&r, "go", "format"));
    let m = r.members.iter().find(|m| m.name == "shout").expect("macro symbol");
    assert_eq!(m.kind, "macro");
}

fn eps(r: &Rows) -> Vec<(String, String, String, Vec<String>)> {
    r.endpoints.iter().map(|e| (e.method.clone(), e.path.clone(), e.handler.clone(), e.roles.clone())).collect()
}

#[test]
fn rust_routes_skip_comments_and_strings() {
    let r = run(
        "src/web.rs",
        r##"use axum::Router;
fn app() -> Router<'static> {
    // .route("/commented", get(h))
    /* .route("/block", get(h)) */
    let doc = r#"x .route("/instring", get(h)) #[get("/inraw")] fn z() {}"#;
    let s = 'a';
    Router::new().route("/real", get(h))
}
"##,
    );
    let e = eps(&r);
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].1, "/real");
}

#[test]
fn ktor_client_calls_are_not_routes() {
    let r = run(
        "src/T.kt",
        r#"import io.ktor.server.routing.*
import io.ktor.client.*
fun Application.module() {
    routing {
        get("/a") { call.respond(1) }
        route("/b") { post("/c") { } }
    }
}
suspend fun t(client: HttpClient) {
    client.get("/x")
    client.post(url) { }
    client.get { url("/y") }
    val r = client.get("/z") { header("a", "b") }
}
fun Route.extra() {
    delete("/d") { }
}
"#,
    );
    let mut e: Vec<String> = eps(&r).into_iter().map(|x| format!("{} {}", x.0, x.1)).collect();
    e.sort();
    assert_eq!(e, vec!["DELETE /d", "GET /a", "POST /b/c"], "{e:?}");
}

#[test]
fn aspnet_authorize_variants() {
    let r = run(
        "src/C.cs",
        r#"using Microsoft.AspNetCore.Mvc;
[Authorize]
public class SecureController : ControllerBase {
    [HttpGet("a")] public IActionResult A() => Ok();
    [HttpGet("b")]
    [Authorize(Roles = "Admin,Ops")]
    public IActionResult B() { return Ok(); }
    [HttpGet("c")]
    [Authorize(Policy = "CanEdit")]
    public IActionResult C() { return Ok(); }
    [HttpGet("d")]
    [Authorize(Roles = Constants.AdminRole)]
    public IActionResult D() { return Ok(); }
    [AllowAnonymous]
    [HttpGet("e")]
    public IActionResult E() { return Ok(); }
    [HttpGet] public IActionResult L() => Ok();
}
public class OpenController : ControllerBase {
    [HttpGet("o")]
    [Authorize]
    public IActionResult O() { return Ok(); }
    [HttpGet("p")]
    public IActionResult P() { return Ok(); }
}
"#,
    );
    let e = eps(&r);
    let by = |h: &str| e.iter().find(|x| x.2 == h).unwrap_or_else(|| panic!("no {h}: {e:?}")).3.clone();
    assert_eq!(by("A"), vec!["authenticated"]);
    assert_eq!(by("B"), vec!["Admin", "Ops"]);
    assert_eq!(by("C"), vec!["policy:CanEdit"]);
    assert_eq!(by("D"), vec!["Constants.AdminRole"]);
    assert_eq!(by("E"), vec!["public"]);
    assert_eq!(by("L"), vec!["authenticated"]);
    assert_eq!(by("O"), vec!["authenticated"]);
    assert!(by("P").is_empty());
}

#[test]
fn aspnet_minimal_api_authorize() {
    let r = run(
        "src/Program.cs",
        r#"var app = builder.Build();
app.MapGet("/m1", [Authorize(Roles = "Admin")] () => "x");
app.MapGet("/m2", [Authorize] () => "x");
app.MapGet("/m3", () => "x").RequireAuthorization();
app.MapGet("/m4", () => "x");
var g = app.MapGroup("/g").RequireAuthorization();
g.MapGet("/in", () => "x");
"#,
    );
    let e = eps(&r);
    let by = |p: &str| e.iter().find(|x| x.1 == p).unwrap_or_else(|| panic!("no {p}: {e:?}")).3.clone();
    assert_eq!(by("/m1"), vec!["Admin"]);
    assert_eq!(by("/m2"), vec!["authenticated"]);
    assert_eq!(by("/m3"), vec!["authenticated"]);
    assert!(by("/m4").is_empty());
    assert_eq!(by("/g/in"), vec!["authenticated"]);
}

#[test]
fn rust_same_line_attributes_and_actix_resources() {
    let r = run(
        "src/h.rs",
        r#"use actix_web::{get, route, web, App};
#[get("/one")] async fn h1() {}
#[route("/p", method="GET", method="POST")]
async fn h2() {}
fn cfg(c: &mut web::ServiceConfig) {
    c.service(web::resource("/res").route(web::post().to(h3)));
}
"#,
    );
    let mut e: Vec<String> = eps(&r).into_iter().map(|x| format!("{} {} {}", x.0, x.1, x.2)).collect();
    e.sort();
    assert_eq!(e, vec!["GET /one h1", "GET /p h2", "POST /p h2", "POST /res h3"], "{e:?}");
}

#[test]
fn laravel_group_prefix_and_auth() {
    let r = run(
        "routes/api.php",
        r#"<?php
Route::group(['prefix' => 'v1', 'middleware' => 'auth:sanctum'], function () {
    Route::get('/me', [MeController::class, 'show']);
});
Route::middleware('auth')->group(function () {
    Route::get('/inner', [A::class, 'x']);
});
Route::get('/open', [B::class, 'y']);
Route::get('/solo', [B::class, 'z'])->middleware('auth');
Route::get('/adm', [B::class, 'w'])->middleware(['auth', 'role:admin']);
"#,
    );
    let e = eps(&r);
    let by = |p: &str| e.iter().find(|x| x.1 == p).unwrap_or_else(|| panic!("no {p}: {e:?}")).3.clone();
    assert_eq!(by("/api/v1/me"), vec!["authenticated"]);
    assert_eq!(by("/api/inner"), vec!["authenticated"]);
    assert!(by("/api/open").is_empty());
    assert_eq!(by("/api/solo"), vec!["authenticated"]);
    assert_eq!(by("/api/adm"), vec!["admin"]);
}

#[test]
fn kotlin_one_line_classes_annotation_class_expect() {
    let r = run(
        "src/K.kt",
        "class A { fun x() {} }\nclass B { fun y() {} }\nannotation class X\nexpect class E { fun e() }\nfun after() {}\nclass C { fun z() {} }\n",
    );
    for q in ["A", "A.x", "B", "B.y", "X", "E", "E.e", "after", "C", "C.z"] {
        assert!(r.members.iter().any(|m| m.qname == q), "missing {q}: {:?}", r.members.iter().map(|m| &m.qname).collect::<Vec<_>>());
    }
}

#[test]
fn rails_member_routes_and_nested_resources() {
    let r = run(
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :posts do\n    get :preview, on: :member\n    get :recent, on: :collection\n    post :publish, on: :member\n    resources :comments\n  end\nend\n",
    );
    let e = eps(&r);
    let has = |m: &str, p: &str| e.iter().any(|x| x.0 == m && x.1 == p);
    assert!(has("GET", "/posts/{id}/preview"), "{e:?}");
    assert!(has("GET", "/posts/recent"), "{e:?}");
    assert!(has("POST", "/posts/{id}/publish"), "{e:?}");
    assert!(has("GET", "/posts/{post_id}/comments"), "{e:?}");
    assert!(has("GET", "/posts/{post_id}/comments/{id}"), "{e:?}");
}

#[test]
fn go_handle_with_method_string() {
    let r = run(
        "main.go",
        "package main\nimport \"net/http\"\nfunc main() {\n\tr := chi.NewRouter()\n\tr.Handle(\"PUT\", \"/h\", hh)\n\tr.Get(\"/g\", gg)\n}\n",
    );
    let e = eps(&r);
    assert!(e.iter().any(|x| x.0 == "PUT" && x.1 == "/h" && x.2 == "hh"), "{e:?}");
}

#[test]
fn ruby_bare_calls_of_same_class_methods() {
    let r = run(
        "app.rb",
        "class Svc\n  def run\n    prepare\n    helper_two 1, 2\n    puts 'x'\n    undefined_thing\n  end\n  def prepare; end\n  def helper_two(a, b); end\nend\n",
    );
    assert!(has_ref(&r, "Svc.run", "prepare"));
    assert!(has_ref(&r, "Svc.run", "helper_two"));
    assert!(!has_ref(&r, "Svc.run", "undefined_thing"));
    let p = r.refs.iter().find(|x| x.callee == "prepare").unwrap();
    assert_eq!(p.recv_type, "Svc");
}

#[test]
fn csharp_destructor_and_operators_swift_deinit_lua_or_function() {
    let r = run("A.cs", "class A {\n ~A() { Dispose(); }\n public static A operator +(A a, A b) { return a; }\n public static implicit operator int(A a) => 1;\n}\n");
    let names: Vec<&str> = r.members.iter().map(|m| m.qname.as_str()).collect();
    for q in ["A.~A", "A.operator +", "A.implicit operator int"] {
        assert!(names.contains(&q), "{q}: {names:?}");
    }
    assert!(has_ref(&r, "A.~A", "Dispose"));
    let r = run("S.swift", "class S {\n deinit { cleanup() }\n subscript(i: Int) -> Int { return i }\n}\n");
    let names: Vec<&str> = r.members.iter().map(|m| m.qname.as_str()).collect();
    assert!(names.contains(&"S.deinit") && names.contains(&"S.subscript"), "{names:?}");
    let r = run("a.lua", "local M = {}\nlocal x = x or function() end\nM.y = M.y or function() end\nreturn M\n");
    let names: Vec<&str> = r.members.iter().map(|m| m.qname.as_str()).collect();
    assert!(names.contains(&"x") && names.contains(&"M.y"), "{names:?}");
}

#[test]
fn vue_options_api_template_uses_and_svelte_reactive() {
    let r = run(
        "src/O.vue",
        "<template>\n  <button @click=\"onClick\" :title=\"fmt(1)\">{{ label(2) }}</button>\n</template>\n<script>\nimport { fmt } from './u';\nexport default {\n  methods: {\n    onClick() { fmt(3); this.save(); },\n    save: function () {}\n  },\n  computed: {\n    label() { return fmt(4); }\n  }\n}\n</script>\n",
    );
    for q in ["O.onClick", "O.save", "O.label"] {
        assert!(r.members.iter().any(|m| m.qname == q), "{q}");
    }
    assert!(has_ref(&r, "O.onClick", "fmt"), "{:?}", r.refs.iter().map(|x| (&x.caller, &x.callee)).collect::<Vec<_>>());
    assert!(has_ref(&r, "O.template", "onClick"));
    assert!(has_ref(&r, "O.template", "fmt"));
    assert!(has_ref(&r, "O.template", "label"));
    let r = run(
        "src/C.svelte",
        "<script>\n  import { other } from './u';\n  let n = 0;\n  $: doubled = twice(n);\n  function twice(x) { return other(x) }\n</script>\n<button on:click={twice}>{doubled}</button>\n",
    );
    assert!(has_ref(&r, "C.$: doubled", "twice"), "{:?}", r.refs.iter().map(|x| (&x.caller, &x.callee)).collect::<Vec<_>>());
    assert!(has_ref(&r, "C.template", "twice"));
}
