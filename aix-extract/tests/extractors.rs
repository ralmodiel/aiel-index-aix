//! Extractor unit tests on the fixture repo under `tests/fixtures/webapp`.

use std::path::{Path, PathBuf};

use aix_extract::{self as sx, Extractor, Rows, SourceFile};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/webapp")
}

fn src(rel: &str) -> SourceFile {
    let text = std::fs::read_to_string(fixture().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    SourceFile::new(rel, text)
}

fn run(e: &dyn Extractor, rel: &str) -> Rows {
    assert!(e.handles(rel), "{} should handle {rel}", e.name());
    e.extract(&fixture(), &[src(rel)])
}

#[test]
fn typescript_symbols_strings_api() {
    let r = run(&sx::typescript::TypeScript, "frontend/src/pages/Orders.tsx");
    let orders = r.symbols.iter().find(|s| s.name == "Orders").expect("Orders symbol");
    assert_eq!(orders.kind, "component");
    assert!(orders.exported);
    let texts: Vec<(&str, &str)> = r.ui_strings.iter().map(|u| (u.kind.as_str(), u.text.as_str())).collect();
    for want in [
        ("jsx", "Open orders"),
        ("prop:placeholder", "Search orders"),
        ("prop:aria-label", "Search orders"),
        ("prop:title", "Reload the list"),
        ("jsx", "Refresh"),
        ("confirm", "Cancel this order?"),
        ("confirm", "The customer is notified by email. This cannot be undone."),
        ("toast", "Order cancelled"),
    ] {
        assert!(texts.contains(&want), "missing {want:?} in {texts:?}");
    }
    assert!(r.ui_strings.iter().all(|u| u.component.as_deref() == Some("Orders")));
    let calls: Vec<(&str, &str)> = r.calls.iter().map(|c| (c.object.as_str(), c.member.as_str())).collect();
    assert!(calls.contains(&("ordersApi", "list")) && calls.contains(&("ordersApi", "cancel")));
    assert!(r.imports.iter().any(|i| i.name == "ordersApi" && i.source == "../lib/api"));
}

#[test]
fn typescript_api_client() {
    let r = run(&sx::typescript::TypeScript, "frontend/src/lib/api.ts");
    let got: Vec<(String, String, String)> = r
        .api_calls
        .iter()
        .map(|a| {
            (
                format!("{}.{}", a.object.clone().unwrap_or_default(), a.name.clone().unwrap_or_default()),
                a.method.clone(),
                a.norm_path.clone(),
            )
        })
        .collect();
    assert!(got.contains(&("ordersApi.list".into(), "GET".into(), "/api/orders".into())), "{got:?}");
    assert!(got.contains(&("ordersApi.cancel".into(), "POST".into(), "/api/orders/{}/cancel".into())), "{got:?}");
    assert!(got.contains(&("ordersApi.remove".into(), "DELETE".into(), "/api/orders/{}".into())), "{got:?}");
}

#[test]
fn typescript_fetch_and_consts() {
    let r = run(&sx::typescript::TypeScript, "frontend/src/pages/Reports.tsx");
    assert!(r.api_calls.iter().any(|a| a.norm_path == "/api/reports/monthly"));
    assert!(r.ui_strings.iter().any(|u| u.kind == "prop:subtitle" && u.text == "Monthly sales by store"));
    let r = run(&sx::typescript::TypeScript, "frontend/src/App.tsx");
    let staff = r.consts.iter().find(|c| c.name == "STAFF").expect("STAFF const");
    assert_eq!(staff.values, vec!["clerk", "@ADMIN_ROLES"]);
    assert!(r.imports.iter().any(|i| i.name == "Orders" && i.source == "./pages/Orders"), "lazy import");
}

#[test]
fn react_router_routes_and_menu() {
    let rr = sx::router::ReactRouter;
    assert!(rr.detect(&fixture()), "react-router-dom in frontend/package.json");
    let r = run(&rr, "frontend/src/App.tsx");
    let find = |p: &str| r.routes.iter().find(|x| x.path == p).unwrap_or_else(|| panic!("route {p}: {:?}", r.routes));
    let orders = find("/orders");
    assert_eq!(orders.component.as_deref(), Some("Orders"));
    assert_eq!(orders.roles, vec!["clerk", "@ADMIN_ROLES"]);
    assert_eq!(orders.role_expr, "STAFF");
    let reports = find("/reports");
    assert_eq!(reports.roles, vec!["manager"]);
    assert_eq!(reports.feature, "reports");
    assert!(r.routes.iter().any(|x| x.path == "/" && x.redirect == "/orders"), "index redirect");
    let r = run(&rr, "frontend/src/components/layout/Sidebar.tsx");
    assert_eq!(r.menu.len(), 2, "{:?}", r.menu);
    let o = &r.menu[0];
    assert_eq!((o.label.as_str(), o.path.as_str(), o.group.as_deref()), ("Orders", "/orders", Some("Sales")));
    assert_eq!(o.group_roles, vec!["clerk", "admin", "manager"]);
    assert_eq!(o.nav, "navigationGroups");
    assert_eq!(r.menu[1].tabs, vec!["Monthly=monthly"]);
}

#[test]
fn java_endpoints_roles_symbols() {
    let r = run(&sx::java::Java, "backend/src/main/java/com/acme/api/OrderResource.java");
    let eps: Vec<(&str, &str, &str, Vec<String>)> = r
        .endpoints
        .iter()
        .map(|e| (e.method.as_str(), e.norm_path.as_str(), e.handler.as_str(), e.roles.clone()))
        .collect();
    let staff = vec!["@Roles.CLERK".to_string(), "@Roles.ADMIN".into(), "@Roles.MANAGER".into()];
    assert!(eps.contains(&("GET", "/api/orders", "list", staff.clone())), "{eps:?}");
    assert!(eps.contains(&("POST", "/api/orders/{}/cancel", "cancel", staff)), "{eps:?}");
    assert!(eps.contains(&("DELETE", "/api/orders/{}", "remove", vec!["@Roles.ADMIN".to_string()])), "{eps:?}");
    assert!(r.symbols.iter().any(|s| s.name == "OrderResource" && s.kind == "class"));
    assert!(r.symbols.iter().any(|s| s.name == "cancel" && s.kind == "method"));
    assert!(!r.symbols.iter().any(|s| s.name == "audit"), "private methods are not symbols");
    let r = run(&sx::java::Java, "backend/src/main/java/com/acme/security/Roles.java");
    assert!(r.consts.iter().any(|c| c.name == "Roles.CLERK" && c.values == vec!["clerk"]));
    let r = run(&sx::java::Java, "backend/src/main/java/com/acme/api/ReportResource.java");
    assert_eq!(r.endpoints[0].roles, vec!["public"]);
}

#[test]
fn python_and_bash_symbols() {
    let r = run(&sx::pybash::Python, "tools/count_orders.py");
    let names: Vec<(&str, &str)> = r.symbols.iter().map(|s| (s.name.as_str(), s.kind.as_str())).collect();
    assert!(
        names.contains(&("Counter", "class"))
            && names.contains(&("add", "method"))
            && names.contains(&("main", "function"))
    );
    let r = run(&sx::pybash::Bash, "scripts/gate.sh");
    assert!(r.symbols.iter().any(|s| s.name == "run_tests"));
}

#[test]
fn scripts_header_usage_refs() {
    let r = run(&sx::scripts::Scripts, "scripts/gate.sh");
    let s = &r.scripts[0];
    assert!(s.header.starts_with("Gate: build, test and lint"), "{}", s.header);
    assert_eq!(s.usage, "Usage: scripts/gate.sh [--fast]");
    assert!(s.flags.contains("--fast"));
    let r = run(&sx::scripts::Scripts, "tools/count_orders.py");
    assert!(r.scripts[0].header.starts_with("Count orders per status"));
}

#[test]
fn markdown_sections_tasks_bugs_flows() {
    let md = sx::markdown::Markdown;
    let r = run(&md, "TASKS.md");
    assert!(r.sections.iter().any(|s| s.heading == "Found (not scheduled)" && s.level == 2));
    let kinds: Vec<(&str, &str)> = r.tasks.iter().map(|t| (t.kind.as_str(), t.status.as_str())).collect();
    assert_eq!(kinds, vec![("task", "open"), ("task", "done"), ("DECISION", "open"), ("Found", "open")]);
    assert_eq!(r.tasks[0].round, "O1");
    assert_eq!(r.bugs.len(), 1, "Found items become bugs");
    let r = run(&md, "docs/qa-findings-round1.md");
    // the checklist line under the finding heading carries the location and severity
    let b = r.bugs.iter().find(|b| b.text.contains("OrderResource.java:19")).expect("finding bullet");
    assert_eq!(b.severity, "P1");
    assert_eq!(b.date, "2026-09-01");
    assert_eq!(b.round, "r1");
    assert!(r.bugs.iter().any(|b| b.status == "fixed" && b.title.contains("Search box")));
    let r = run(&md, "docs/checkout-flows.md");
    let f = &r.features[0];
    assert_eq!((f.kind.as_str(), f.name.as_str(), f.route.as_str()), ("flow", "Cancel an order", "/orders"));
    assert!(f.extra.contains("/api/orders/{id}/cancel"));
}

#[test]
fn e2e_specs() {
    let r = run(&sx::specs::E2eSpecs, "e2e/specs/clerk.json");
    assert_eq!(r.tests.len(), 2);
    let t = &r.tests[0];
    assert_eq!((t.id.as_str(), t.role.as_str()), ("orders-cancel", "clerk"));
    assert_eq!(t.routes, vec!["/orders"]);
    assert!(t.texts.contains(&"Open orders".to_string()));
    assert!(r.test_steps.iter().any(|s| s.kind == "click.name" && s.value == "Cancel order"));
    assert!(r.script_refs.iter().any(|s| s.norm_path == "/api/orders"));
    assert_eq!(r.tests[1].routes, vec!["/orders"], "query string dropped");
    assert!(t.line >= 5);
}

#[test]
fn feature_flags() {
    let r = run(&sx::features::FeatureSources, "backend/src/main/java/com/acme/api/OrderResource.java");
    assert!(r.features.iter().any(|f| f.kind == "flag" && f.name == "refunds"));
}

#[test]
fn git_log_parsing() {
    let c = sx::git::parse_log("\u{1e}a1\u{1f}a\u{1f}2026-10-01\u{1f}Revert \"x\"\n\nf\n");
    assert!(c[0].is_fix && c[0].is_revert);
}

#[test]
fn datamodel_extractor() {
    use aix_extract::datamodel::DataModel;
    let dm = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/datamodel");
    let read = |rel: &str| SourceFile::new(rel, std::fs::read_to_string(dm.join(rel)).unwrap());
    // JPA entity: table, columns, transient, relation, finder
    let r = DataModel.extract(&dm, &[read("backend/src/main/java/com/acme/model/Order.java")]);
    let e = &r.entities[0];
    assert_eq!((e.name.as_str(), e.table.as_str(), e.orm.as_str()), ("Order", "orders", "panache"));
    let f = |n: &str| r.entity_fields.iter().find(|x| x.field == n).unwrap_or_else(|| panic!("{n}"));
    assert_eq!(f("customerName").column, "customer_name");
    assert!(!f("customerName").nullable && f("customerName").flags.contains("len 80"));
    assert!(f("displayLabel").transient && f("displayLabel").column.is_empty());
    assert_eq!((f("owner").column.as_str(), f("owner").rel.as_str()), ("owner_id", "Customer"));
    assert!(f("lines").column.is_empty() && f("lines").flags.contains("1:N"));
    assert!(f("id").pk);
    // Spring Data repository declaration and JPQL
    let r = DataModel.extract(&dm, &[read("backend/src/main/java/com/acme/model/OrderRepository.java")]);
    assert!(r.data_raw.iter().any(|d| d.kind == "repo" && d.target == "OrderRepository" && d.extra == "Customer"));
    assert!(r.data_raw.iter().any(|d| d.kind == "jpql" && d.target == "Customer" && d.op == "r"));
    // native SQL in code
    let r = DataModel.extract(&dm, &[read("backend/src/main/java/com/acme/service/OrderService.java")]);
    assert!(r.data_raw.iter().any(|d| d.target == "order_lines" && d.op == "r" && d.via == "native"));
    assert!(r.data_raw.iter().any(|d| d.target == "audit_log" && d.op == "w"));
    // Flyway migration
    let r = DataModel.extract(&dm, &[read("backend/src/main/resources/db/migration/V1__init.sql")]);
    assert!(r.migrations.iter().all(|m| m.tool == "flyway" && m.version == "1"));
    assert!(r.fks.iter().any(|k| k.from_table == "order_lines" && k.to_table == "orders" && k.from_col == "order_id"));
    // SQLAlchemy
    let r = DataModel.extract(&dm, &[read("py/models.py")]);
    assert_eq!(r.entities.iter().map(|e| e.table.as_str()).collect::<Vec<_>>(), vec!["accounts", "owners"]);
    assert!(r.fks.iter().any(|k| k.to_table == "owners" && k.to_col == "id"));
    let r = DataModel.extract(&dm, &[read("py/service.py")]);
    assert!(r.data_raw.iter().any(|d| d.kind == "entity" && d.target == "Account" && d.op == "r"));
    assert!(r.data_raw.iter().any(|d| d.target == "owners" && d.op == "w"));
}

#[test]
fn datamodel_other_stacks() {
    use aix_extract::datamodel::DataModel;
    let p = Path::new("x");
    // Django model + migration
    let r = DataModel.extract(p, &[SourceFile::new("shop/models.py", "from django.db import models\n\nclass Book(models.Model):\n    title = models.CharField(max_length=80)\n    author = models.ForeignKey('Author', null=True, on_delete=models.CASCADE)\n    tags = models.ManyToManyField('Tag')\n")]);
    assert_eq!(r.entities[0].table, "shop_book");
    let col = |n: &str| r.entity_fields.iter().find(|x| x.field == n).unwrap();
    assert_eq!((col("author").column.as_str(), col("author").nullable), ("author_id", true));
    assert!(col("tags").column.is_empty() && col("id").pk);
    let r = DataModel.extract(p, &[SourceFile::new("shop/migrations/0002_x.py", "from django.db import migrations, models\nclass Migration(migrations.Migration):\n    operations = [\n        migrations.AddField(model_name='book', name='isbn', field=models.CharField(max_length=13)),\n        migrations.RemoveField(model_name='book', name='old'),\n    ]\n")]);
    assert!(r.migrations.iter().any(|m| m.table == "shop_book" && m.op == "add" && m.column == "isbn" && m.version == "0002"));
    assert!(r.migrations.iter().any(|m| m.op == "drop" && m.column == "old"));
    // Alembic
    let r = DataModel.extract(p, &[SourceFile::new("alembic/versions/ab12_add.py", "revision = 'ab12'\ndown_revision = '9f00'\n\ndef upgrade():\n    op.add_column('users', sa.Column('age', sa.Integer(), nullable=False))\n    op.create_table('t', sa.Column('id', sa.Integer(), nullable=False), sa.ForeignKeyConstraint(['uid'], ['users.id']))\n\ndef downgrade():\n    op.drop_column('users', 'age')\n")]);
    assert!(r.migrations.iter().any(|m| m.obj == "revision" && m.detail == "down=9f00"));
    assert!(r.migrations.iter().any(|m| m.table == "users" && m.column == "age" && m.op == "add" && m.detail.contains("not null")));
    assert!(!r.migrations.iter().any(|m| m.op == "drop"), "downgrade is not part of the history");
    assert!(r.fks.iter().any(|k| k.from_table == "t" && k.to_table == "users"));
    // Rails
    let r = DataModel.extract(p, &[SourceFile::new("db/migrate/20240101000000_create_posts.rb", "class CreatePosts < ActiveRecord::Migration[7.0]\n  def change\n    create_table :posts do |t|\n      t.string :title, null: false\n      t.references :user, foreign_key: true\n      t.timestamps\n    end\n    add_index :posts, :title\n  end\nend\n")]);
    assert!(r.migrations.iter().any(|m| m.table == "posts" && m.column == "user_id") && r.migrations.iter().any(|m| m.column == "created_at"));
    assert!(r.migrations.iter().all(|m| m.version == "20240101000000"));
    // Liquibase XML
    let r = DataModel.extract(p, &[SourceFile::new("db/changelog.xml", "<databaseChangeLog>\n<changeSet id=\"1\" author=\"a\">\n<createTable tableName=\"cat\">\n<column name=\"id\" type=\"int\"><constraints primaryKey=\"true\"/></column>\n</createTable>\n</changeSet>\n<changeSet id=\"2\" author=\"a\"><addColumn tableName=\"cat\"><column name=\"lives\" type=\"int\"/></addColumn></changeSet>\n</databaseChangeLog>\n")]);
    assert!(r.migrations.iter().any(|m| m.version == "2" && m.op == "add" && m.column == "lives"));
    assert!(r.migrations.iter().any(|m| m.obj == "constraint" && m.detail == "primary key(id)"));
    // Prisma schema, Drizzle, TypeORM
    let r = DataModel.extract(p, &[SourceFile::new("prisma/schema.prisma", "model User {\n  id    Int    @id\n  email String @unique @map(\"mail\")\n  posts Post[]\n  @@map(\"users\")\n}\nmodel Post {\n  id Int @id\n  authorId Int\n  author User @relation(fields: [authorId], references: [id])\n}\n")]);
    assert_eq!(r.entities.iter().map(|e| e.table.as_str()).collect::<Vec<_>>(), vec!["users", "post"]);
    assert!(r.entity_fields.iter().any(|f| f.field == "email" && f.column == "mail"));
    assert!(r.fks.iter().any(|k| k.from_col == "authorid" && k.to_table == "entity:User"));
    let r = DataModel.extract(p, &[SourceFile::new("src/db/schema.ts", "export const users = pgTable('users', {\n  id: serial('id').primaryKey(),\n  name: text('full_name').notNull(),\n});\nconst x = await db.select().from(users);\n")]);
    assert!(r.entity_fields.iter().any(|f| f.field == "name" && f.column == "full_name" && !f.nullable));
    assert!(r.data_raw.iter().any(|d| d.target == "users" && d.op == "r"));
    let r = DataModel.extract(p, &[SourceFile::new("src/user.entity.ts", "@Entity('app_users')\nexport class User {\n  @PrimaryGeneratedColumn()\n  id: number;\n\n  @Column({ name: 'user_name', nullable: true })\n  name: string;\n}\n")]);
    assert_eq!(r.entities[0].table, "app_users");
    assert!(r.entity_fields.iter().any(|f| f.field == "name" && f.column == "user_name" && f.nullable));
}

#[test]
fn typescript_object_property_copy() {
    let code = r#"
export function notes(a: A) {
  const out = []
  out.push({ tone: 'warn', text: `${a.n} of ${a.total} learners need attention: ${a.names}.` })
  const meta = { Coverage: `${a.g} of ${a.e} learners graded`, Scope: a.place }
  const look = { id: `row-${a.id}`, cls: `px-2 ${a.on ? 'font-bold' : ''}`, url: `/api/x/${a.id}`, kind: 'enum_value' }
  const more = { href: `${base}/the/${a.id}`, keywords: 'clock in clock out of time', '/grades': 'scores of the class' }
  const lower = { label: 'no grades yet', badge: `${a.n} items in the queue`, k: `${a.x}-${a.y}` }
  return [out, meta, look, more, lower]
}
"#;
    let f = SourceFile::new("frontend/src/pages/Notes.tsx", code.to_string());
    let r = sx::typescript::TypeScript.extract(&fixture(), &[f]);
    let texts: Vec<&str> = r.ui_strings.iter().filter(|u| u.kind == "literal").map(|u| u.text.as_str()).collect();
    for want in [
        "${a.n} of ${a.total} learners need attention: ${a.names}.",
        "${a.g} of ${a.e} learners graded",
        "Coverage",
        "no grades yet",
        "${a.n} items in the queue",
    ] {
        assert!(texts.contains(&want), "missing {want:?} in {texts:?}");
    }
    for bad in ["warn", "enum_value", "clock in clock out of time", "scores of the class", "Scope"] {
        assert!(!texts.contains(&bad), "unexpected {bad:?} in {texts:?}");
    }
    assert!(!texts.iter().any(|t| t.contains("row-") || t.contains("px-2") || t.contains("/api/") || t.contains("/the/") || t.contains("-${")), "{texts:?}");
}

#[test]
fn typescript_ternary_props_are_ui_text() {
    let code = "export function B({ busy }) {\n  return <button title={busy ? 'Capturing screenshot' : 'Report a bug'} placeholder={busy && 'Please wait here'}>x</button>;\n}\n";
    let r = sx::typescript::TypeScript.extract(&fixture(), &[SourceFile::new("frontend/src/B.tsx", code)]);
    for t in ["Capturing screenshot", "Report a bug", "Please wait here"] {
        assert!(r.ui_strings.iter().any(|u| u.text == t && u.kind.starts_with("prop:")), "{t}: {:?}", r.ui_strings);
    }
}

#[test]
fn typescript_multiword_name_values_are_ui_text() {
    let code = "export const GROUPS = [{ name: 'Reports & Analysis', items: ['Grade Book'] }, { name: 'reportsTab' }];\n";
    let r = sx::typescript::TypeScript.extract(&fixture(), &[SourceFile::new("frontend/src/G.tsx", code)]);
    assert!(r.ui_strings.iter().any(|u| u.text == "Reports & Analysis"), "{:?}", r.ui_strings);
    assert!(!r.ui_strings.iter().any(|u| u.text == "reportsTab"));
}
