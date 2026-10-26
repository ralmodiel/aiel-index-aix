//! FIX-7XB: call-graph and endpoint answers that were wrong while tagged exact/resolved (cross-language edges,
//! Laravel handlers, Rails route DSL, super calls, overloads, modules, Go interfaces) and the coverage gaps around
//! them (framework callbacks, test callers in impact, diff-mode impact). Generic fixtures only.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn run(repo: &Path, args: &[&str]) -> (i32, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo).output().unwrap();
    (o.status.code().unwrap_or(-1), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn aix(repo: &Path, args: &[&str]) -> String {
    let (c, s) = run(repo, args);
    assert!(c <= 1, "aix {args:?}: {s}");
    s
}

fn write(repo: &Path, rel: &str, text: &str) {
    let p = repo.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn commit(r: &Path, msg: &str) {
    git(r, &["add", "-A"]);
    git(r, &["commit", "-qm", msg]);
}

/// A repo from (path, text) pairs, committed and indexed.
fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("app");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    for (p, t) in files {
        write(&r, p, t);
    }
    commit(&r, "init");
    aix(&r, &["update", "--full"]);
    (d, r)
}

#[test]
fn calls_never_bind_to_another_language() {
    let (_d, r) = repo(&[
        ("test/item_test.rb", "class ItemTest\n  def test_x\n    assert item.ok\n  end\nend\n"),
        ("vendor/javascript/lib.js", "function assert(e) { return e }\nexport { assert }\n"),
        ("app/Services/TokenService.php", "<?php\nclass TokenService {\n  public function run() { return $this->cache->get('k'); }\n}\n"),
        ("resources/js/cache.ts", "export class Cache {\n  get(k: string) { return k }\n}\n"),
        ("app/Event.php", "<?php\nclass Event {\n  public function __construct() {}\n}\n"),
        ("resources/js/use.ts", "export function go() {\n  return new Event('click')\n}\n"),
    ]);
    let c = aix(&r, &["callers", "assert", "--all", "--bare"]);
    assert!(!c.contains("item_test.rb"), "{c}");
    let c = aix(&r, &["callers", "Cache.get", "--all", "--bare"]);
    assert!(!c.contains("TokenService.php"), "{c}");
    let c = aix(&r, &["callers", "Event", "--all", "--bare"]);
    assert!(!c.contains("use.ts"), "{c}");
}

#[test]
fn laravel_invokable_controllers_link_by_class() {
    let ctl = |n: &str| format!("<?php\nnamespace App\\Http\\Controllers;\n\nclass {n}\n{{\n    public function __invoke()\n    {{\n        return [];\n    }}\n}}\n");
    let (_d, r) = repo(&[
        ("routes/api.php", "<?php\nuse App\\Http\\Controllers\\OverviewController;\nuse App\\Http\\Controllers\\PingController;\nuse Illuminate\\Support\\Facades\\Route;\n\nRoute::get('/api/overview', OverviewController::class);\nRoute::get('/api/ping', PingController::class);\n"),
        ("app/Http/Controllers/OverviewController.php", &ctl("OverviewController")),
        ("app/Http/Controllers/PingController.php", &ctl("PingController")),
    ]);
    let t = aix(&r, &["trace", "GET /api/overview"]);
    assert!(t.contains("OverviewController.__invoke"), "{t}");
    let t = aix(&r, &["trace", "GET /api/ping"]);
    assert!(t.contains("PingController.__invoke"), "{t}");
}

#[test]
fn rails_routes_are_parsed_as_statements() {
    let routes = "Rails.application.routes.draw do
  namespace :api do
    namespace :v2 do
      resources :things, only: [] do
        resources :parts, only: :show, constraints: {
          number: /x/
        } do
          resources :contents, only: :index
        end
      end
    end
    namespace :v1 do
      resource :api_key, only: %i[show create]
      resources :gems,
        path: 'rubygems',
        only: [:index]
      resources :profiles, only: :show
      get '/status', to: 'status#show'
    end
  end
  scope constraints: { format: :html } do
    resource :profile, only: :show
  end
end
";
    let (_d, r) = repo(&[("config/routes.rb", routes)]);
    let e = aix(&r, &["sql", "select method, path, class, handler from endpoints order by path"]);
    assert!(!e.contains("/api/v2/v1/"), "{e}");
    assert!(e.contains("/api/v1/profiles/{id}"), "{e}");
    assert!(e.contains("/api/v2/things/{thing_id}/parts/{part_id}/contents"), "{e}");
    assert!(!e.contains("api_key/edit"), "{e}");
    assert!(e.contains("/api/v1/api_key | Api::V1::ApiKeysController | show"), "{e}");
    assert!(e.contains("/api/v1/rubygems | Api::V1::GemsController | index"), "{e}");
    assert!(!e.contains("/api/v1/gems"), "{e}");
    assert!(e.contains("/profile | ProfilesController | show"), "{e}");
    assert!(e.contains("/api/v1/status | Api::V1::StatusController | show"), "{e}");
}

#[test]
fn super_calls_reach_the_parent_not_the_override() {
    let (_d, r) = repo(&[
        ("src/p/Base.java", "package p;\npublic class Base {\n  public Integer getId() { return 1; }\n}\n"),
        ("src/p/Child.java", "package p;\npublic class Child extends Base {\n  @Override\n  public Integer getId() { return super.getId() + 1; }\n}\n"),
        ("pkg/core.py", "class Base:\n    def save(self):\n        return 1\n\n\nclass User(Base):\n    def save(self):\n        return super().save()\n"),
        ("web/animal.ts", "export class Animal {\n  speak() { return 1 }\n}\n\nexport class Dog extends Animal {\n  speak() { return super.speak() + 1 }\n}\n"),
        ("kt/Shape.kt", "package k\nopen class Shape {\n  open fun area(): Int { return 1 }\n}\n\nclass Square : Shape() {\n  override fun area(): Int { return super.area() + 1 }\n}\n"),
        ("cs/Pet.cs", "namespace P;\npublic class Pet\n{\n    public virtual int Feed() { return 1; }\n}\n\npublic class Cat : Pet\n{\n    public override int Feed() { return base.Feed() + 1; }\n}\n"),
    ]);
    let c = aix(&r, &["callers", "Child.getId", "--all", "--bare"]);
    assert!(!c.contains("Child.java:4:"), "{c}");
    let c = aix(&r, &["callers", "Base.getId", "--bare"]);
    assert!(c.contains("Child.java:4:"), "{c}");
    let c = aix(&r, &["callers", "User.save", "--all", "--bare"]);
    assert!(!c.contains("core.py:8:"), "{c}");
    let c = aix(&r, &["callers", "Base.save", "--bare"]);
    assert!(c.contains("core.py:8:"), "{c}");
    let c = aix(&r, &["callers", "Animal.speak", "--bare"]);
    assert!(c.contains("animal.ts:6:"), "{c}");
    let c = aix(&r, &["callers", "Dog.speak", "--all", "--bare"]);
    assert!(!c.contains("animal.ts:6:"), "{c}");
    // Kotlin `super.f()` and C# `base.F()`
    for (parent, child, at) in [("Shape.area", "Square.area", "Shape.kt:7:"), ("Pet.Feed", "Cat.Feed", "Pet.cs:9:")] {
        assert!(aix(&r, &["callers", parent, "--bare"]).contains(at), "{parent}");
        assert!(!aix(&r, &["callers", child, "--all", "--bare"]).contains(at), "{child}");
    }
}

#[test]
fn same_arity_overloads_are_told_apart_by_argument_types() {
    let (_d, r) = repo(&[
        ("src/p/Item.java", "package p;\npublic class Item {}\n"),
        ("src/p/Box.java", "package p;\npublic class Box {\n  public Item get(String name) { return null; }\n  public Item get(Integer id) { return null; }\n}\n"),
        ("src/p/Base.java", "package p;\npublic class Base {\n  public Integer getId() { return 1; }\n}\n"),
        ("src/p/Use.java", "package p;\nimport java.util.List;\npublic class Use {\n  void a(Box b) { b.get(\"x\"); }\n  void c(Box b) { b.get(7); }\n  void e(Box b, Integer id) { b.get(id); }\n  void f(Box b) { b.get(pick()); }\n  static <T extends Base> void d(List<T> xs) { for (T t : xs) { t.getId(); } }\n}\n"),
    ]);
    let s = aix(&r, &["callers", "src/p/Box.java:3", "--bare"]);
    assert!(s.contains("Use.java:4:"), "{s}");
    assert!(!s.contains("Use.java:5:") && !s.contains("Use.java:6:"), "{s}");
    let i = aix(&r, &["callers", "src/p/Box.java:4", "--bare"]);
    assert!(i.contains("Use.java:5:") && i.contains("Use.java:6:"), "{i}");
    assert!(!i.contains("Use.java:4:"), "{i}");
    // an argument of unknown type: both overloads, neither exact
    let e = aix(&r, &["sql", "select line, callee_line, conf from call_edges_v where file='src/p/Use.java' and line=7"]);
    assert!(e.contains("7 | 3 | heuristic") && e.contains("7 | 4 | heuristic"), "{e}");
    // `T extends Base`: a T receiver is a Base
    let g = aix(&r, &["callers", "Base.getId", "--bare"]);
    assert!(g.contains("Use.java:8:"), "{g}");
}

#[test]
fn same_fqn_in_two_modules_binds_to_the_callers_module() {
    let store = "package com.example.service\n\nclass Store {\n    fun create(x: String): Int = x.length\n}\n";
    let app = |m: &str| format!("package com.example.app\n\nimport com.example.service.Store\n\nfun run{m}(s: Store) = s.create(\"{m}\")\n");
    let (a, b) = (app("alpha"), app("beta"));
    let (_d, r) = repo(&[
        ("alpha/build.gradle.kts", "plugins { kotlin(\"jvm\") }\n"),
        ("alpha/src/main/kotlin/com/example/service/Store.kt", store),
        ("alpha/src/main/kotlin/com/example/app/App.kt", &a),
        ("beta/src/main/kotlin/com/example/service/Store.kt", store),
        ("beta/src/main/kotlin/com/example/app/App.kt", &b),
    ]);
    let c = aix(&r, &["callers", "alpha/src/main/kotlin/com/example/service/Store.kt:4", "--all", "--bare"]);
    assert!(c.contains("alpha/src/main/kotlin/com/example/app/App.kt:5"), "{c}");
    assert!(!c.contains("beta/"), "{c}");
    let c = aix(&r, &["callers", "beta/src/main/kotlin/com/example/service/Store.kt:4", "--all", "--bare"]);
    assert!(c.contains("beta/src/main/kotlin/com/example/app/App.kt:5") && !c.contains("alpha/"), "{c}");
}

#[test]
fn go_interfaces_closures_and_method_results() {
    let (_d, r) = repo(&[
        ("go.mod", "module example.com/g1\n\ngo 1.22\n"),
        ("repo/repo.go", "package repo\n\ntype Hour struct{ ok bool }\n\nfunc (h *Hour) Cancel() error { h.ok = false; return nil }\n\ntype Factory struct{}\n\nfunc (f Factory) NewHour() (*Hour, error) { return &Hour{}, nil }\n\ntype Repository interface {\n\tUpdate(fn func(h *Hour) error) error\n}\n"),
        ("adapters/mem.go", "package adapters\n\nimport \"example.com/g1/repo\"\n\ntype MemRepo struct{}\n\nfunc (m *MemRepo) Update(fn func(h *repo.Hour) error) error { return fn(&repo.Hour{}) }\n\ntype Other struct{}\n\nfunc (o Other) Update(x int) error { return nil }\nfunc (o Other) Extra() {}\n"),
        ("app/app.go", "package app\n\nimport \"example.com/g1/repo\"\n\ntype handler struct{ r repo.Repository }\n\nfunc (h handler) Handle() error {\n\treturn h.r.Update(func(h *repo.Hour) error {\n\t\treturn h.Cancel()\n\t})\n}\n\nfunc Make(f repo.Factory) error {\n\tx, err := f.NewHour()\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn x.Cancel()\n}\n"),
    ]);
    let c = aix(&r, &["callers", "MemRepo.Update", "--bare"]);
    assert!(c.contains("app/app.go:8"), "{c}");
    let c = aix(&r, &["callers", "Repository.Update", "--bare"]);
    assert!(c.contains("app/app.go:8"), "{c}");
    let c = aix(&r, &["callers", "Hour.Cancel", "--bare"]);
    assert!(c.contains("app/app.go:9") && c.contains("app/app.go:18"), "{c}");
    let c = aix(&r, &["callers", "handler.Cancel", "--all", "--bare"]);
    assert!(!c.contains("app/app.go:9"), "{c}");
}

#[test]
fn framework_callbacks_and_decorators_are_uses() {
    let (_d, r) = repo(&[
        ("app/controllers/application_controller.rb", "class ApplicationController\n  before_action :require_login, only: [:show]\n  rescue_from StandardError, with: :oops\n\n  def require_login\n    true\n  end\n\n  def oops\n    nil\n  end\nend\n"),
        ("app/controllers/items_controller.rb", "class ItemsController < ApplicationController\n  before_action :require_login\n  skip_before_action :other\n\n  def show\n    1\n  end\nend\n"),
        ("app/models/gem_item.rb", "class GemItem\n  after_save :reorder\n\n  def reorder\n    1\n  end\nend\n"),
        ("app/deps.py", "from fastapi import Depends\n\n\ndef require_admin() -> None:\n    return None\n"),
        ("app/routes.py", "from fastapi import APIRouter, Depends\n\nfrom app.deps import require_admin\n\nrouter = APIRouter()\n\n\n@router.delete(\"/users/{user_id}\", dependencies=[Depends(require_admin)])\ndef delete_user(user_id: int) -> None:\n    return None\n"),
        ("pkg/core.py", "def cached(f):\n    return f\n\n\n@cached\ndef load(uid):\n    return uid\n"),
    ]);
    let c = aix(&r, &["callers", "ApplicationController.require_login", "--bare"]);
    assert!(c.contains("application_controller.rb:2") && c.contains("items_controller.rb:2"), "{c}");
    let c = aix(&r, &["callers", "ApplicationController.oops", "--bare"]);
    assert!(c.contains("application_controller.rb:3"), "{c}");
    let c = aix(&r, &["callers", "GemItem.reorder", "--bare"]);
    assert!(c.contains("gem_item.rb:2"), "{c}");
    let c = aix(&r, &["callers", "require_admin", "--bare"]);
    assert!(c.contains("routes.py:8"), "{c}");
    let c = aix(&r, &["callers", "cached", "--bare"]);
    assert!(c.contains("core.py:5"), "{c}");
}

#[test]
fn fastapi_annotated_dependency_aliases_are_auth() {
    let (_d, r) = repo(&[
        ("backend/app/api/deps.py", "from typing import Annotated\n\nfrom fastapi import Depends\n\n\ndef get_db():\n    yield 1\n\n\ndef get_current_user() -> str:\n    return \"u\"\n\n\nSessionDep = Annotated[int, Depends(get_db)]\nCurrentUser = Annotated[str, Depends(get_current_user)]\n"),
        ("backend/app/api/routes/items.py", "from fastapi import APIRouter\n\nfrom app.api.deps import CurrentUser, SessionDep\n\nrouter = APIRouter(prefix=\"/items\")\n\n\n@router.get(\"/\")\ndef read_items(session: SessionDep, current_user: CurrentUser) -> list:\n    return []\n\n\n@router.get(\"/open\")\ndef open_items(session: SessionDep) -> list:\n    return []\n"),
        ("backend/app/main.py", "from fastapi import FastAPI\n\nfrom app.api.routes import items\n\napp = FastAPI()\napp.include_router(items.router)\n"),
    ]);
    let e = aix(&r, &["sql", "select path, roles from endpoints order by path"]);
    assert!(e.contains("/items | auth:get_current_user"), "{e}");
    assert!(!e.contains("dep:"), "{e}");
    assert!(e.contains("/items/open | public"), "{e}");
    assert!(!e.contains("/items/open | auth"), "{e}");
}

#[test]
fn impact_counts_test_callbacks_and_diff_mode_names_endpoints_and_tests() {
    let (_d, r) = repo(&[
        ("package.json", "{\"dependencies\":{\"express\":\"4.0.0\"}}\n"),
        ("src/user.controller.ts", "import { Router } from 'express'\nimport { getUser } from './user.service'\n\nconst router = Router()\n\nrouter.get('/user', async (req, res) => {\n  res.json(await getUser(1))\n})\n\nexport default router\n"),
        ("src/user.service.ts", "export const getUser = async (id: number) => {\n  return { id, ok: true }\n}\n\nexport function add(a: number, b: number) {\n  return a + b\n}\n"),
        ("tests/user.test.ts", "import { getUser, add } from '../src/user.service'\n\ndescribe('user', () => {\n  it('gets', async () => {\n    expect(await getUser(1)).toBeTruthy()\n    expect(add(1, 2)).toBe(3)\n  })\n})\n"),
    ]);
    let i = aix(&r, &["impact", "add"]);
    assert!(i.contains("tests/user.test.ts"), "{i}");
    // trace --up names the same test callers
    let t = aix(&r, &["trace", "--up", "add"]);
    assert!(t.contains("tests reaching it through calls: 1") && t.contains("tests/user.test.ts:"), "{t}");
    write(&r, "src/user.service.ts", "export const getUser = async (id: number) => {\n  return { id, ok: false }\n}\n\nexport function add(a: number, b: number) {\n  return a + b\n}\n");
    commit(&r, "change getUser");
    aix(&r, &["update"]);
    let i = aix(&r, &["impact", "HEAD~1..HEAD"]);
    assert!(i.contains("GET /user"), "{i}");
    assert!(i.contains("tests/user.test.ts"), "{i}");
    assert!(!i.contains("add"), "only the changed member: {i}");
    let s = aix(&r, &["scope", "--commit", "HEAD"]);
    assert!(s.contains("GET /user") && s.contains("tests/user.test.ts"), "{s}");
}

#[test]
fn shared_filters_work_on_impact_scope_and_files_changed() {
    let (_d, r) = repo(&[
        ("src/main/java/p/A.java", "package p;\npublic class A {\n  public int f() { return 1; }\n}\n"),
        ("src/test/java/p/ATest.java", "package p;\npublic class ATest {\n  void t() { new A().f(); }\n}\n"),
    ]);
    write(&r, "src/main/java/p/A.java", "package p;\npublic class A {\n  public int f() { return 2; }\n}\n");
    write(&r, "src/test/java/p/ATest.java", "package p;\npublic class ATest {\n  void t() { new A().f(); }\n}\n// x\n");
    aix(&r, &["update"]);
    let i = aix(&r, &["impact"]);
    assert!(i.contains("tests calling the changed members (1)") && i.contains("src/test/java/p/ATest.java (1 callers)"), "{i}");
    for args in [&["impact", "-x", "tests"][..], &["scope", "-x", "tests"][..], &["files", "--changed", "-x", "tests"][..]] {
        let (c, o) = run(&r, args);
        assert_eq!(c, 0, "{args:?}: {o}");
        assert!(o.contains("A.java") && !o.contains("ATest.java"), "{args:?}: {o}");
    }
    let (c, o) = run(&r, &["impact", "--only", "tests"]);
    assert!(c == 0 && o.contains("ATest.java") && !o.contains("p/A.java"), "{o}");
    for args in [&["impact", "--bogus"][..], &["scope", "--bogus"][..]] {
        let (c, o) = run(&r, args);
        assert_eq!(c, 2, "{args:?}: {o}");
    }
}

#[test]
fn ts_default_reexports_and_symbol_call_sites() {
    let (_d, r) = repo(&[
        ("src/lib/math.ts", "export function add(a: number, b: number) { return a + b }\nexport default function mul(a: number, b: number) { return a * b }\n"),
        ("src/lib/index.ts", "export { add as plus } from './math'\nexport { default as times } from './math'\n"),
        ("src/app/use.ts", "import { plus, times } from '../lib'\nimport product from '../lib/math'\n\nexport const r1 = plus(1, 2)\nexport const r2 = times(2, 3)\nexport const r3 = product(4, 5)\n"),
        ("src/p/Svc.java", "package p;\npublic class Svc {\n  public int go() { return 1; }\n}\n"),
        ("src/p/Use.java", "package p;\npublic class Use {\n  int a(Svc s) { return s.go(); }\n}\n"),
    ]);
    let c = aix(&r, &["callers", "mul", "--bare"]);
    assert!(c.contains("use.ts:5") && c.contains("use.ts:6"), "{c}");
    let s = aix(&r, &["symbol", "Svc.go"]);
    assert!(s.contains("call sites") && s.contains("src/p/Use.java:3"), "{s}");
}

#[test]
fn migration_replay_skips_down_and_applies_renames() {
    let (_d, r) = repo(&[
        ("db/migrate/20200101000000_create_widgets.rb", "class CreateWidgets < ActiveRecord::Migration[4.2]\n  def self.up\n    create_table :widgets do |table|\n      table.string :name\n      table.integer :owner_id\n      table.timestamps\n    end\n  end\n\n  def self.down\n    drop_table :widgets\n  end\nend\n"),
        ("db/migrate/20200201000000_remove_owner_id_from_widgets.rb", "class RemoveOwnerIdFromWidgets < ActiveRecord::Migration[4.2]\n  def self.up\n    remove_column :widgets, :owner_id\n  end\n\n  def self.down\n    add_column :widgets, :owner_id, :integer\n  end\nend\n"),
        ("alembic/versions/001_init.py", "from alembic import op\nimport sqlalchemy as sa\n\nrevision = '001'\ndown_revision = None\n\n\ndef upgrade():\n    op.create_table('account', sa.Column('new_id', sa.Integer(), nullable=False))\n    op.alter_column('account', 'new_id', new_column_name='id')\n"),
    ]);
    let t = aix(&r, &["table", "widgets", "columns"]);
    assert!(t.contains("  name ") && t.contains("created_at") && !t.contains("owner_id"), "{t}");
    let t = aix(&r, &["table", "account", "columns"]);
    assert!(t.contains("  id ") && !t.contains("new_id"), "{t}");
}

#[test]
fn laravel_migrations_define_tables() {
    let (_d, r) = repo(&[
        ("database/migrations/2020_01_01_000000_create_songs_table.php", "<?php\nuse Illuminate\\Database\\Schema\\Blueprint;\nuse Illuminate\\Support\\Facades\\Schema;\n\nreturn new class {\n    public function up(): void\n    {\n        Schema::create('songs', function (Blueprint $table) {\n            $table->id();\n            $table->string('title');\n            $table->string('old')->nullable();\n            $table->timestamps();\n        });\n        Schema::table('songs', function (Blueprint $table) {\n            $table->dropColumn('old');\n        });\n    }\n\n    public function down(): void\n    {\n        Schema::dropIfExists('songs');\n    }\n};\n"),
    ]);
    let t = aix(&r, &["table", "songs", "columns"]);
    assert!(t.contains("  title ") && t.contains("created_at") && !t.contains("  old "), "{t}");
}

#[test]
fn aspnet_ardalis_endpoints_and_razor_pages() {
    let (_d, r) = repo(&[
        ("src/PublicApi/AuthEndpoints/Authenticate.cs", "namespace PublicApi.AuthEndpoints;\n\npublic class Authenticate : EndpointBaseAsync\n    .WithRequest<AuthenticateRequest>\n    .WithActionResult<AuthenticateResponse>\n{\n    [HttpPost(\"api/authenticate\")]\n    public override async Task<ActionResult<AuthenticateResponse>> HandleAsync(AuthenticateRequest request, CancellationToken ct = default)\n    {\n        return null;\n    }\n}\n"),
        ("src/Web/Pages/Basket/Index.cshtml.cs", "namespace Web.Pages.Basket;\n\npublic class IndexModel : PageModel\n{\n    public async Task OnGetAsync()\n    {\n    }\n\n    public async Task<IActionResult> OnPostUpdate(int id)\n    {\n        return Page();\n    }\n}\n"),
    ]);
    let e = aix(&r, &["sql", "select method, path, handler from endpoints order by path"]);
    assert!(e.contains("POST | /api/authenticate | HandleAsync"), "{e}");
    assert!(e.contains("GET | /Basket | OnGetAsync") && e.contains("POST | /Basket?handler=Update | OnPostUpdate"), "{e}");
}

/// `symbol | tbl | rw` rows of the data-access facts, one per line.
fn access(r: &Path) -> String {
    aix(r, &["sql", "select symbol, tbl, rw from data_access order by symbol, tbl, rw"])
}

#[test]
fn active_record_models_access_and_the_schema_dump() {
    let (_d, r) = repo(&[
        ("db/migrate/20200101000000_create_widgets.rb", "class CreateWidgets < ActiveRecord::Migration[7.0]\n  def change\n    create_table :widgets do |t|\n      t.string :name\n    end\n  end\nend\n"),
        ("db/schema.rb", "ActiveRecord::Schema[7.0].define(version: 2020_02_01_000000) do\n  create_table \"widgets\", force: :cascade do |t|\n    t.string \"name\"\n    t.string \"color\", null: false\n  end\nend\n"),
        ("app/models/widget.rb", "class Widget < ApplicationRecord\n  scope :red, -> { where(color: \"red\") }\nend\n"),
        ("app/controllers/widgets_controller.rb", "class WidgetsController < ApplicationController\n  def index\n    @widgets = Widget.where(name: params[:q])\n  end\n\n  def purge\n    Widget.where(color: nil).delete_all\n  end\nend\n"),
        ("test/models/widget_test.rb", "class WidgetTest < ActiveSupport::TestCase\n  def test_x\n    Widget.create!(name: \"a\")\n  end\nend\n"),
    ]);
    // the dump states the table as it stands (the migration never added `color`)
    let t = aix(&r, &["table", "widgets", "columns"]);
    assert!(t.contains("color") && t.contains("showing db)"), "{t}");
    let a = access(&r);
    assert!(a.contains("WidgetsController.index | widgets | r") && a.contains("WidgetsController.purge | widgets | w"), "{a}");
    assert!(a.contains("Widget | widgets | r"), "a scope reads its own table: {a}");
    assert!(!a.contains("WidgetTest"), "test setup is not app access: {a}");
}

#[test]
fn eloquent_efcore_sqlmodel_and_gorm_access() {
    let (_d, r) = repo(&[
        ("app/Models/Song.php", "<?php\nnamespace App\\Models;\n\nclass Song extends Model\n{\n    protected $table = 'tracks';\n}\n"),
        ("app/Services/SongService.php", "<?php\nclass SongService\n{\n    public function hide(array $ids): void\n    {\n        Song::query()\n            ->whereIn('id', $ids)\n            ->update(['hidden' => true]);\n    }\n\n    public function exists(string $id): bool\n    {\n        if (Song::query()->where('id', $id)->exists()) {\n            return true;\n        }\n        return DB::table('plays')->count() > 0;\n    }\n}\n"),
        ("src/Data/ShopContext.cs", "public class ShopContext : DbContext\n{\n    public DbSet<Order> Orders { get; set; }\n    public DbSet<Basket> Baskets { get; set; }\n}\n"),
        ("src/Data/Config/BasketConfiguration.cs", "public class BasketConfiguration : IEntityTypeConfiguration<Basket>\n{\n    public void Configure(EntityTypeBuilder<Basket> builder)\n    {\n        builder.ToTable(\"Cart\");\n    }\n}\n"),
        ("src/Services/OrderService.cs", "public class OrderService\n{\n    private readonly IRepository<Basket> _basketRepository;\n    private readonly ShopContext _dbContext;\n\n    public async Task Place(int id)\n    {\n        var b = await _basketRepository.GetByIdAsync(id);\n        _dbContext.Orders.Add(new Order());\n        await _basketRepository.DeleteAsync(b);\n    }\n\n    public int Count() => _dbContext.Orders.Count();\n}\n"),
        ("app/models.py", "from sqlmodel import Field, SQLModel\n\n\nclass ItemBase(SQLModel):\n    title: str = Field(max_length=255)\n\n\nclass Item(ItemBase, table=True):\n    id: int = Field(primary_key=True)\n"),
        ("app/crud.py", "from sqlmodel import Session, select\nfrom app.models import Item\n\n\ndef create_item(*, session: Session, title: str) -> Item:\n    db_item = Item(title=title)\n    session.add(db_item)\n    session.commit()\n    return db_item\n\n\ndef read_items(session: Session):\n    return session.exec(select(Item)).all()\n"),
        ("store/user.go", "package store\n\nimport \"gorm.io/gorm\"\n\ntype User struct {\n\tgorm.Model\n\tName string\n}\n\nfunc Rename(db *gorm.DB, id uint) {\n\tdb.Model(&User{}).Where(\"id = ?\", id).Update(\"name\", \"x\")\n}\n\nfunc All(db *gorm.DB) []User {\n\tvar users []User\n\tdb.Find(&users)\n\treturn users\n}\n\nfunc Hours(db *sql.DB) {\n\tdb.Query(\"SELECT id FROM hours WHERE day = ?\", 1)\n}\n"),
    ]);
    let a = access(&r);
    for want in [
        "SongService.hide | tracks | w",
        "SongService.exists | tracks | r",
        "SongService.exists | plays | r",
        "OrderService.Place | cart | r",
        "OrderService.Place | cart | w",
        "OrderService.Place | orders | w",
        "OrderService.Count | orders | r",
        "create_item | item | w",
        "read_items | item | r",
        "Rename | users | w",
        "All | users | r",
        "Hours | hours | r",
    ] {
        assert!(a.contains(want), "{want}: {a}");
    }
    assert!(!a.contains("SongService.exists | tracks | w") && !a.contains("baskets"), "{a}");
    let t = aix(&r, &["table", "item", "columns"]);
    assert!(t.contains("title"), "inherited SQLModel field: {t}");
}

#[test]
fn a_changed_default_export_re_resolves_unchanged_importers() {
    let (_d, r) = repo(&[
        ("src/a.ts", "export default function foo() {\n  return 1\n}\n\nexport function bar() {\n  return 2\n}\n"),
        ("src/b.ts", "import run from './a'\n\nexport function main() {\n  return run()\n}\n"),
    ]);
    assert!(aix(&r, &["callers", "foo", "--bare"]).contains("src/b.ts:4:"));
    write(&r, "src/a.ts", "function foo() {\n  return 1\n}\n\nexport function bar() {\n  return 2\n}\n\nexport default bar\n");
    commit(&r, "default is bar");
    aix(&r, &["update"]);
    assert!(!aix(&r, &["callers", "foo", "--bare"]).contains("src/b.ts:4:"));
    assert!(aix(&r, &["callers", "bar", "--bare"]).contains("src/b.ts:4:"));
}

#[test]
fn a_function_handed_to_a_user_macro_is_used_there() {
    let (_d, r) = repo(&[(
        "src/lib.rs",
        "macro_rules! ext_impl {\n    ($ty:ident, $f:path) => {\n        pub struct $ty;\n        impl $ty { pub fn run(&self, x: u32) -> u32 { $f(x) } }\n    };\n}\n\next_impl!(Rails, rails);\n\nfn rails(x: u32) -> u32 {\n    x + 1\n}\n\nfn other(count: u32) -> u32 {\n    my_log!(count);\n    count\n}\n\nfn count() {}\n",
    )]);
    assert!(aix(&r, &["callers", "rails", "--bare"]).contains("src/lib.rs:8:"));
    // a parameter handed to a macro is a variable, not the function of that name
    assert!(!aix(&r, &["callers", "count", "--bare"]).contains("src/lib.rs:15:"));
}

#[test]
fn java_lambda_parameters_are_collection_elements() {
    let (_d, r) = repo(&[
        ("src/p/BaseEntity.java", "package p;\npublic class BaseEntity {\n  public Integer getId() { return 1; }\n}\n"),
        ("src/p/Visit.java", "package p;\npublic class Visit extends BaseEntity {\n}\n"),
        ("src/p/Pet.java", "package p;\nimport java.util.List;\npublic class Pet extends BaseEntity {\n  public List<Visit> getVisits() { return null; }\n}\n"),
        ("src/p/T.java", "package p;\nimport java.util.List;\nimport static org.assertj.core.api.Assertions.assertThat;\npublic class T {\n  void a(List<Visit> vs) {\n    vs.stream().filter(v -> v.getId() != null).count();\n  }\n  void b(Pet pet7) {\n    assertThat(pet7.getVisits())\n      .hasSize(1)\n      .allMatch(value -> value.getId() != null);\n  }\n  void c(Pet pet7) {\n    pet7.getVisits().forEach(x -> x.getId());\n  }\n}\n"),
    ]);
    let c = aix(&r, &["callers", "BaseEntity.getId", "--bare"]);
    for at in ["T.java:6:T.a (resolved)", "T.java:11:T.b (resolved)", "T.java:14:T.c (resolved)"] {
        assert!(c.contains(at), "{at}: {c}");
    }
}

#[test]
fn rails_callbacks_reach_methods_on_associated_models() {
    let (_d, r) = repo(&[
        ("app/models/version.rb", "class Version < ApplicationRecord\n  belongs_to :rubygem\n  has_one :owner, class_name: \"User\"\n  after_commit :bump\n  after_destroy { rubygem.recalc }\n\n  def bump\n    rubygem.touch_count\n    owner.notify\n  end\nend\n"),
        ("app/models/rubygem.rb", "class Rubygem < ApplicationRecord\n  def touch_count\n    3\n  end\n\n  def recalc\n    4\n  end\nend\n"),
        ("app/models/user.rb", "class User < ApplicationRecord\n  def notify\n    5\n  end\nend\n"),
    ]);
    assert!(aix(&r, &["callers", "Rubygem.touch_count", "--bare"]).contains("version.rb:8:Version.bump (exact)"));
    assert!(aix(&r, &["callers", "Rubygem.recalc", "--bare"]).contains("version.rb:5:"));
    assert!(aix(&r, &["callers", "User.notify", "--bare"]).contains("version.rb:9:Version.bump (exact)"));
}
