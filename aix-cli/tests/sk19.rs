//! Accuracy fixes: roles wording, Go group prefixes, SQLAlchemy 2.0 + Alembic batch ops, redaction of raw lines,
//! foreign `--db` refusal, `brief` on a backend path. Generic fixtures built in a temp git repo.

use std::path::{Path, PathBuf};
use std::process::Command;

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

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("shop");
    for (p, t) in files {
        let f = r.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "Initial shop"]);
    (d, r)
}

fn run(repo: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_aix"))
        .arg("--repo")
        .arg(repo)
        .args(args)
        .env("AIX_EMBED_URL", "")
        .env("HOME", repo)
        .output()
        .unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let (ok, o) = run(repo, args);
    assert!(ok, "aix {args:?}: {o}");
    o
}

const MAIN_GO: &str = r#"package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.Default()
	v1 := r.Group("/api")
	shop.OpenRegister(v1.Group("/catalog"))
	v1.Use(shop.AuthMiddleware(true))
	shop.OrdersRegister(v1.Group("/orders"))
}
"#;
const ROUTES_GO: &str = r#"package shop
import "github.com/gin-gonic/gin"
func OpenRegister(router *gin.RouterGroup) {
	router.GET("/:sku", Show)
	router.GET("/:sku/", Show)
}
func OrdersRegister(router *gin.RouterGroup) {
	router.POST("/", Create)
	router.DELETE("/:id", Remove)
}
func StrayRegister(router *gin.RouterGroup) {
	router.GET("/health", Health)
}
"#;

#[test]
fn go_group_prefixes_roles_and_unresolved() {
    let (_d, r) = repo(&[("main.go", MAIN_GO), ("shop/routes.go", ROUTES_GO)]);
    sk(&r, &["update", "--full"]);
    let e = sk(&r, &["sql", "select method, path, roles from endpoints order by path, method"]);
    assert!(e.contains("GET | /api/catalog/:sku | public"), "{e}");
    assert!(e.contains("POST | /api/orders | auth:AuthMiddleware(true)"), "{e}");
    assert!(e.contains("DELETE | /api/orders/:id | auth:AuthMiddleware(true)"), "{e}");
    assert_eq!(e.matches("/api/catalog/:sku").count(), 1, "trailing-slash duplicate: {e}");
    // a registrar nobody calls: path is only the group-local part and the roles are unknown, not public
    let ep = sk(&r, &["endpoint", "/health"]);
    assert!(ep.contains("(relative: group prefix unresolved)"), "{ep}");
    assert!(ep.contains("no auth declared (public or unknown)"), "{ep}");
}

#[test]
fn express_and_flask_defaults() {
    let (_d, r) = repo(&[
        (
            "src/app.js",
            "const express = require('express');\nconst items = require('./items');\nconst app = express();\napp.use('/api', requireAuth, items);\napp.get('/health', (req, res) => res.send('ok'));\n",
        ),
        (
            "src/items.js",
            "const { Router } = require('express');\nconst router = Router();\nrouter.get('/', (req, res) => res.json([]));\nmodule.exports = router;\n",
        ),
        (
            "web/app.py",
            "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@app.route('/login', methods=['GET', 'POST'])\ndef login():\n    pass\n\n@app.route('/me')\n@login_required\ndef me():\n    pass\n",
        ),
    ]);
    sk(&r, &["update", "--full"]);
    let e = sk(&r, &["sql", "select method, path, roles from endpoints order by path, method"]);
    assert!(e.contains("GET | /health | public"), "{e}");
    // mounted behind `requireAuth`: not public
    assert!(e.contains("GET | /api | auth:requireAuth"), "{e}");
    assert!(e.contains("GET | /login | public"), "{e}");
    assert!(e.contains("POST | /login | public"), "{e}");
    assert!(e.contains("GET | /me | auth:login_required"), "{e}");
}

#[test]
fn sqlalchemy_two_models_and_alembic_batch() {
    let (_d, r) = repo(&[
        (
            "app/models.py",
            "import sqlalchemy as sa\nimport sqlalchemy.orm as so\nfrom app import db\n\nclass Order(db.Model):\n    id: so.Mapped[int] = so.mapped_column(primary_key=True)\n    sku: so.Mapped[str] = so.mapped_column(sa.String(32), index=True)\n    note: so.Mapped[str | None]\n    customer_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(Customer.id))\n\nclass Customer(db.Model):\n    __tablename__ = 'customer'\n    id: so.Mapped[int] = so.mapped_column(primary_key=True)\n",
        ),
        (
            "migrations/versions/aaa111_orders.py",
            "revision = 'aaa111'\ndown_revision = None\nimport sqlalchemy as sa\nfrom alembic import op\n\ndef upgrade():\n    op.create_table('order', sa.Column('id', sa.Integer(), nullable=False), sa.Column('sku', sa.String(32), nullable=False))\n\ndef downgrade():\n    op.drop_table('order')\n",
        ),
        (
            "migrations/versions/bbb222_note.py",
            "revision = 'bbb222'\ndown_revision = 'aaa111'\nimport sqlalchemy as sa\nfrom alembic import op\n\ndef upgrade():\n    with op.batch_alter_table('order', schema=None) as batch_op:\n        batch_op.add_column(sa.Column('note', sa.String(80), nullable=True))\n        batch_op.create_index(batch_op.f('ix_order_sku'), ['sku'], unique=False)\n\ndef downgrade():\n    with op.batch_alter_table('order', schema=None) as batch_op:\n        batch_op.drop_column('note')\n",
        ),
    ]);
    sk(&r, &["update", "--full"]);
    let t = sk(&r, &["table", "order"]);
    assert!(t.contains("entity Order"), "{t}");
    assert!(t.contains("note") && t.contains("add column note"), "{t}");
    assert!(t.contains("index ix_order_sku(sku)"), "{t}");
    assert!(!t.contains("schema only: no entity field maps it"), "{t}");
}

#[test]
fn raw_lines_keep_expressions_and_hide_literals() {
    let (_d, r) = repo(&[(
        "config.py",
        "import os\nSECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-fallback-value'\ntoken_expiration = now + timedelta(seconds=3600)\n",
    ), ("schema.sql", "CREATE TABLE users (id int, api_token text DEFAULT 'abcdef');\n")]);
    sk(&r, &["update", "--full"]);
    let g = sk(&r, &["grep", "SECRET_KEY|token_expiration|api_token"]);
    assert!(!g.contains("dev-fallback-value"), "{g}");
    assert!(!g.contains("abcdef"), "{g}");
    assert!(g.contains("token_expiration = now + timedelta(seconds=3600)"), "{g}");
    assert!(g.contains("os.environ.get('SECRET_KEY')"), "{g}");
}

#[test]
fn foreign_db_is_refused_and_brief_falls_back_to_endpoint() {
    let (_d, a) = repo(&[("app.py", "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/ping')\ndef ping():\n    pass\n")]);
    let (_d2, b) = repo(&[("other.py", "x = 1\n")]);
    sk(&a, &["update", "--full"]);
    let db = a.join(".aix/index.db");
    let (ok, o) = run(&b, &["--db", db.to_str().unwrap(), "update"]);
    assert!(!ok && o.contains("indexes another repository"), "{o}");
    let (ok, o) = run(&b, &["--db", db.to_str().unwrap(), "--no-refresh", "stats"]);
    assert!(!ok && o.contains("indexes another repository"), "{o}");
    // the index survived
    assert!(sk(&a, &["endpoint", "/ping"]).contains("GET /ping"));
    let br = sk(&a, &["brief", "/ping"]);
    assert!(br.contains("backend endpoint") && br.contains("GET /ping"), "{br}");
}
