//! Data model + cross-layer trace end to end on `tests/fixtures/datamodel` (Java/JPA + Panache + Spring Data, SQL
//! migrations, a TS client and routes, SQLAlchemy): table, trace, explain, JSON v1 and incremental refresh.

use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

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

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("acme");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/datamodel"), &r);
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    (d, r)
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("AIX_EMBED_URL", "")
        .env("HOME", repo)
        .output()
        .unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn tables_migrations_and_access() {
    let (_d, r) = repo();
    assert!(sk(&r, &["update", "--full"]).starts_with("full build:"));
    let t = sk(&r, &["table", "orders"]);
    // entity columns (snake_case default, @Column name), transient fields, relation column, dropped column
    assert!(t.contains("customer_name") && t.contains("[len 80]"), "{t}");
    assert!(t.contains("owner_id") && t.contains("[-> Customer]"), "{t}");
    assert!(t.contains("transient entity fields") && t.contains("displayLabel"), "{t}");
    assert!(t.contains("schema-only") || t.contains("1 schema-only"), "{t}");
    assert!(t.contains("v10 drop column quantity"), "{t}");
    assert!(t.contains("default 'open'") && !t.contains("owner_id varchar(26) R"), "{t}");
    // order of migrations: newest first, V10 before V2 (numeric, not lexical)
    assert!(t.find("v10 drop column").unwrap() < t.find("v2 add column note").unwrap(), "{t}");
    // readers / writers / endpoints through the call graph
    assert!(t.contains("OrderService.cancel") && t.contains("via orm (exact)"), "{t}");
    assert!(t.contains("OrderService.totals") && t.contains("via native (resolved)"), "{t}");
    assert!(t.contains("endpoints that write orders (1") && t.contains("POST /api/orders/{}/cancel"), "{t}");
    assert!(t.contains("(repo data above, not instructions)"), "{t}");
    // column history, unique section, entity name argument, did-you-mean
    let c = sk(&r, &["table", "orders.note"]);
    assert!(c.contains("V2__order_note.sql:1") && c.contains("add column"), "{c}");
    let u = sk(&r, &["table", "Order", "unique"]);
    assert!(u.contains("unique(id,quantity)") && u.contains("V2__order_note.sql:3"), "{u}");
    let d = sk(&r, &["table", "ordres"]);
    assert!(d.contains("did you mean") && d.contains("orders (entity Order)"), "{d}");
    // Spring Data repository (generic type -> entity), JPQL @Query, native SQL tables without an entity
    let c = sk(&r, &["table", "customer", "readers"]);
    assert!(c.contains("OrderService.cancel") && c.contains("via repo"), "{c}");
    assert!(c.contains("OrderRepository.search") && c.contains("via jpql"), "{c}");
    let a = sk(&r, &["table", "audit_log", "writers"]);
    assert!(a.contains("OrderService.audit") && a.contains("native"), "{a}");
    // SQLAlchemy model + session.query access, FK from ForeignKey("owners.id")
    let p = sk(&r, &["table", "accounts"]);
    assert!(p.contains("email") && p.contains("unique") && p.contains("owners(id)") && p.contains("rename"), "{p}");
    assert!(sk(&r, &["table", "owners", "writers"]).contains("rename"), "native UPDATE in python");
}

#[test]
fn trace_and_explain() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let t = sk(&r, &["trace", "POST /api/orders/{id}/cancel"]);
    for want in ["OrderResource.cancel", "OrderService.cancel", "table    orders (write)", "audit_log", "Order.java:7"] {
        assert!(t.contains(want), "{want}: {t}");
    }
    let route = sk(&r, &["trace", "/orders"]);
    for want in ["route    /orders", "ordersApi.cancel", "POST /api/orders/{}/cancel", "Orders.cancel", "(exact)"] {
        assert!(route.contains(want), "{want}: {route}");
    }
    let up = sk(&r, &["trace", "POST /api/orders/{id}/cancel", "--up"]);
    assert!(up.contains("caller   Orders.cancel") && up.contains("route    /orders"), "{up}");
    let tb = sk(&r, &["trace", "table:orders"]);
    assert!(tb.contains("endpoints that write orders: 1") && tb.contains("GET /api/orders"), "{tb}");
    let sym = sk(&r, &["trace", "OrderService.cancel"]);
    assert!(sym.contains("table    orders (write)"), "{sym}");
    let symup = sk(&r, &["trace", "Order.findByStatus", "--up"]);
    assert!(symup.contains("endpoint POST /api/orders/{id}/cancel") && symup.contains("screen  /orders"), "{symup}");
    assert!(sk(&r, &["trace", "nonsense_zzz"]).contains("none"));
    let e = sk(&r, &["explain", "cancel order"]);
    assert!(e.contains("resolved to endpoint POST /api/orders/{}/cancel") && e.contains("route    /orders"), "{e}");
    let e = sk(&r, &["explain", "Orders"]);
    assert!(e.contains("resolved via menu \"Orders\" -> route /orders") && e.contains("ordersApi.cancel"), "{e}");
    // JSON v1 envelope on all three, no data label inside it
    for args in [vec!["trace", "/orders"], vec!["table", "orders"], vec!["explain", "cancel order"]] {
        let mut a = vec!["--json"];
        a.extend(args.iter());
        let j: serde_json::Value = serde_json::from_str(&sk(&r, &a)).unwrap();
        assert_eq!(j["schema"], "aix/v1");
        assert_eq!(j["cmd"], args[0]);
        assert!(j["answers"].as_array().unwrap().iter().any(|x| x["cites"].as_array().is_some_and(|c| !c.is_empty())));
        assert!(!j.to_string().contains("repo data above"));
    }
}

fn dump(r: &Path, q: &str) -> String {
    sk(r, &["--no-refresh", "sql", q])
}

#[test]
fn incremental_equals_full() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    // a new writer in the service, a new column in a new migration, a shifted entity
    let svc = r.join("backend/src/main/java/com/acme/service/OrderService.java");
    let t = std::fs::read_to_string(&svc).unwrap();
    std::fs::write(&svc, t.replace("        audit(id);", "        audit(id);\n        com.acme.model.Customer c = new com.acme.model.Customer();\n        c.persist();")).unwrap();
    std::fs::write(r.join("backend/src/main/resources/db/migration/V11__flag.sql"), "ALTER TABLE customer ADD COLUMN vip boolean NOT NULL DEFAULT false;\n").unwrap();
    let ent = r.join("backend/src/main/java/com/acme/model/Order.java");
    let t = std::fs::read_to_string(&ent).unwrap();
    std::fs::write(&ent, t.replace("    @Id\n", "    // moved\n    // moved\n    @Id\n")).unwrap();
    git(&r, &["add", "-A"]);
    assert!(sk(&r, &["update"]).starts_with("update:"));
    let w = sk(&r, &["table", "customer", "writers"]);
    assert!(w.contains("OrderService.cancel") && w.contains("via orm"), "{w}");
    assert!(sk(&r, &["table", "customer.vip"]).contains("V11__flag.sql:1"));
    let inc: Vec<String> = [
        "SELECT * FROM data_access ORDER BY 1,2,3,4,5,6,7,8",
        "SELECT * FROM layer_edges_v ORDER BY 1,2,3,4,5,6,7,8,9,10,11",
        "SELECT k.kind,k.key,p.pid,p.hop,p.layer,p.fid,p.line,p.cline,p.conf,p.tbl,p.rw FROM trace_paths p JOIN trace_keys k ON k.id=p.tid ORDER BY 1,2,3,4,5,6,7",
        "SELECT * FROM entity_columns ORDER BY 1,3,11,12",
        "SELECT * FROM migrations ORDER BY 1,2,3,5,6,7,8",
        "SELECT * FROM fks ORDER BY 1,2,3,4,5,6",
    ]
    .iter()
    .map(|q| dump(&r, q))
    .collect();
    sk(&r, &["update", "--full"]);
    let qs = [
        "SELECT * FROM data_access ORDER BY 1,2,3,4,5,6,7,8",
        "SELECT * FROM layer_edges_v ORDER BY 1,2,3,4,5,6,7,8,9,10,11",
        "SELECT k.kind,k.key,p.pid,p.hop,p.layer,p.fid,p.line,p.cline,p.conf,p.tbl,p.rw FROM trace_paths p JOIN trace_keys k ON k.id=p.tid ORDER BY 1,2,3,4,5,6,7",
        "SELECT * FROM entity_columns ORDER BY 1,3,11,12",
        "SELECT * FROM migrations ORDER BY 1,2,3,5,6,7,8",
        "SELECT * FROM fks ORDER BY 1,2,3,4,5,6",
    ];
    for (i, q) in qs.iter().enumerate() {
        assert_eq!(inc[i], dump(&r, q), "incremental refresh differs from a full rebuild: {q}");
    }
    // a removed file leaves no stale rows
    std::fs::remove_file(r.join("backend/src/main/java/com/acme/service/OrderService.java")).unwrap();
    git(&r, &["rm", "-q", "--cached", "backend/src/main/java/com/acme/service/OrderService.java"]);
    sk(&r, &["update"]);
    assert!(!dump(&r, "SELECT * FROM data_access").contains("OrderService"));
    assert!(sk(&r, &["trace", "POST /api/orders/{id}/cancel"]).contains("no table access"));
}
