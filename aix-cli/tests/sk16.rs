//! SK-16: router composition across files (Express, FastAPI, Django, Flask), handler links for `trace`,
//! file-based frontend routes, Prisma tables, and stack-aware wording.

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

fn ep(r: &Path) -> Vec<String> {
    sk(r, &["sql", "select method || ' ' || path || ' ' || handler from endpoints order by 1", "--limit", "200"])
        .lines()
        .skip(1)
        .map(String::from)
        .collect()
}

#[test]
fn express_fastapi_django_flask_compose() {
    let (_d, r) = repo(&[
        ("package.json", "{\"dependencies\":{\"express\":\"4\"}}"),
        ("src/main.ts", "import express from 'express';\nimport routes from './routes';\nconst app = express();\napp.use('/api', routes);\n"),
        ("src/routes.ts", "import { Router } from 'express';\nimport users from './users';\nexport default Router().use('/users', users);\n"),
        ("src/users.ts", "import { Router } from 'express';\nimport { listUsers } from './svc';\nconst router = Router();\nrouter.get('/', requireAuth, listUsers);\nrouter.get('/:id', (req, res) => { listUsers(); });\nexport default router;\n"),
        ("src/svc.ts", "export function listUsers() { return []; }\n"),
        ("py/main.py", "from fastapi import FastAPI\nfrom app.api import items\napp = FastAPI()\napp.include_router(items.router, prefix=API)\nAPI = '/v1'\n"),
        ("py/app/api/items.py", "from fastapi import APIRouter\nrouter = APIRouter(prefix='/items')\n@router.get('/{id}')\ndef read_item(id: int):\n    return id\n"),
        ("dj/proj/urls.py", "from django.urls import path, include\nurlpatterns = [path('api/', include('shop.urls'))]\n"),
        ("dj/shop/urls.py", "from django.urls import path\nfrom . import views\nurlpatterns = [path('cart/<int:pk>/', views.CartView.as_view())]\n"),
        ("dj/shop/views.py", "from django.views import View\nclass CartView(View):\n    def get(self, request, pk): pass\n    def delete(self, request, pk): pass\n"),
        ("fl/app/__init__.py", "from flask import Flask\ndef create():\n    app = Flask(__name__)\n    from app.main import bp\n    app.register_blueprint(bp, url_prefix='/shop')\n    return app\n"),
        ("fl/app/main.py", "from flask import Blueprint\nbp = Blueprint('main', __name__)\n@bp.route('/cart', methods=['POST'])\ndef cart(): pass\n"),
    ]);
    let e = ep(&r);
    for want in [
        "GET /api/users listUsers",
        "GET /api/users/:id router.get /:id handler",
        "GET /v1/items/{id} read_item",
        "GET /api/cart/{pk} CartView",
        "DELETE /api/cart/{pk} CartView",
        "POST /shop/cart cart",
    ] {
        assert!(e.contains(&want.to_string()), "missing {want:?} in {e:#?}");
    }
    // the mount bookkeeping never reaches search
    assert!(!sk(&r, &["find", "ep:mount"]).contains("\"lang\""));
    // trace: endpoint -> handler (imported function in another file) for a final composed path
    let t = sk(&r, &["trace", "GET /api/users"]);
    assert!(t.contains("handler") && t.contains("listUsers") && t.contains("src/svc.ts"), "{t}");
    let t = sk(&r, &["trace", "GET /v1/items/{id}"]);
    assert!(t.contains("read_item"), "{t}");
    // incremental: editing the mount file re-composes the other files' endpoints
    write(&r, "src/main.ts", "import express from 'express';\nimport routes from './routes';\nconst app = express();\napp.use('/v2', routes);\n");
    sk(&r, &["update"]);
    let e = ep(&r);
    assert!(
        e.contains(&"GET /v2/users listUsers".to_string()) && !e.iter().any(|x| x.contains("/api/users")),
        "{e:#?}"
    );
    sk(&r, &["update", "--full"]);
    assert!(ep(&r).contains(&"GET /v2/users listUsers".to_string()));
}

#[test]
fn nextjs_prisma_and_stack_aware_output() {
    let (_d, r) = repo(&[
        ("package.json", "{\"dependencies\":{\"next\":\"14\",\"@prisma/client\":\"5\"}}"),
        ("app/api/posts/route.ts", "import { prisma } from '@/lib/db';\nexport async function GET() { return prisma.post.findMany(); }\nexport async function POST() { return prisma.post.create({}); }\n"),
        ("app/posts/page.tsx", "export default function Posts() { return null }\n"),
        ("prisma/schema.prisma", "model Post {\n  id Int @id\n  title String\n}\n"),
        ("lib/db.ts", "export const prisma = {} as any;\n"),
    ]);
    assert_eq!(ep(&r), vec!["GET /api/posts GET", "POST /api/posts POST"]);
    assert!(sk(&r, &["route", "/posts"]).contains("Posts"));
    let t = sk(&r, &["table", "post"]);
    assert!(t.contains("title") && t.contains("prisma"), "{t}");
    let tr = sk(&r, &["trace", "POST /api/posts"]);
    assert!(tr.contains("post (write)"), "{tr}");
    let card = sk(&r, &["card"]);
    assert!(!card.contains(" 0 ") && card.contains("2 endpoints") && card.contains("1 routes"), "{card}");
}

#[test]
fn no_endpoint_extractor_is_said_not_implied() {
    let (_d, r) = repo(&[
        ("lib/util.py", "def helper():\n    return 1\n"),
        ("lib/use.py", "from util import helper\ndef run():\n    return helper()\n"),
    ]);
    let up = sk(&r, &["trace", "--up", "helper"]);
    assert!(up.contains("no endpoint extractor ran for this stack"), "{up}");
    let imp = sk(&r, &["impact", "helper"]);
    assert!(imp.contains("no endpoint extractor ran for this stack"), "{imp}");
    let card = sk(&r, &["card"]);
    assert!(!card.contains("0 routes") && !card.contains("0 endpoints") && !card.contains("0 e2e"), "{card}");
}
