//! SK-16: endpoint and frontend-route extractors per framework, on small inline fixtures.

use std::path::Path;

use aix_extract::frameworks::{
    express::Express, frontend::FrontendRoutes, gohttp::GoHttp, next::NextRoutes, pyweb::PyWeb, spring::Spring,
};
use aix_extract::{Extractor, Rows, SourceFile};

fn run(e: &dyn Extractor, path: &str, text: &str) -> Rows {
    assert!(e.handles(path), "{} should handle {path}", e.name());
    e.extract(Path::new("."), &[SourceFile::new(path, text)])
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sk16-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn eps(r: &Rows) -> Vec<String> {
    r.endpoints
        .iter()
        .map(|e| format!("{} {} {}.{} [{}]", e.method, e.path, e.class, e.handler, e.roles.join(",")))
        .collect()
}

#[test]
fn spring_mappings_prefix_arrays_and_roles() {
    let r = run(
        &Spring,
        "src/main/java/com/x/UserController.java",
        r#"
@RestController
@RequestMapping("/api/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserController {
    private static final String BASE = "/items";
    @GetMapping
    public List<User> list() { return null; }
    @GetMapping(value = {"/{id}", "/by-id/{id}"})
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public User get(@PathVariable Long id) { return null; }
    @RequestMapping(path = BASE + "/x", method = {RequestMethod.POST, RequestMethod.PUT})
    public void save() {}
    @DeleteMapping("/{id}")
    @Secured({"ROLE_ROOT"})
    public void del() {}
}
"#,
    );
    let e = eps(&r);
    for want in [
        "GET /api/users UserController.list [ADMIN]",
        "GET /api/users/{id} UserController.get [USER,ADMIN]",
        "GET /api/users/by-id/{id} UserController.get [USER,ADMIN]",
        "POST /api/users/items/x UserController.save [ADMIN]",
        "PUT /api/users/items/x UserController.save [ADMIN]",
        "DELETE /api/users/{id} UserController.del [ROOT]",
    ] {
        assert!(e.contains(&want.to_string()), "missing {want:?} in {e:#?}");
    }
    assert_eq!(e.len(), 6, "{e:#?}");
}

#[test]
fn spring_skips_feign_clients() {
    let r = run(
        &Spring,
        "A.java",
        "@FeignClient(name=\"x\")\n@RequestMapping(\"/v\")\ninterface C { @GetMapping(\"/a\") String a(); }\n",
    );
    assert!(r.endpoints.is_empty());
}

#[test]
fn express_routes_chains_middleware_and_mounts() {
    let r = run(
        &Express,
        "src/routes/users.ts",
        r#"
import { Router } from 'express';
import { requireAuth, authorize } from '../auth';
import * as ctrl from './ctrl';
const router = Router();
router.get('/', ctrl.list);
router.post('/', requireAuth, authorize('ADMIN'), async (req, res) => { res.json({}); });
router.route('/:id').get(ctrl.get).delete(requireAuth, ctrl.remove);
router.use('/:id/posts', postsRouter);
export default router;
"#,
    );
    let e = eps(&r);
    for want in [
        "GET / ctrl.list [public]",
        "POST / .router.post / handler [auth:requireAuth,ADMIN]",
        "GET /:id ctrl.get [public]",
        "DELETE /:id ctrl.remove [auth:requireAuth]",
    ] {
        assert!(e.contains(&want.to_string()), "missing {want:?} in {e:#?}");
    }
    let c = run(&Express, "src/c.ts", "import { Router } from 'express';\nconst router = Router();\nrouter.route('/c').put(async (req, res) => { res.json({}); });\n");
    assert!(c.members.iter().any(|m| m.name == "PUT /c" && m.annos.contains(&"route-handler".to_string())));
    let app = run(&Express, "src/app.js", "const express = require('express');\nconst users = require('./routes/users');\nconst app = express();\napp.use('/api/users', users);\napp.get('/health', (req, res) => res.send('ok'));\n");
    let mount = app.notes.iter().find(|n| n.kind == "ep:mount").expect("mount note");
    assert!(
        mount.reference.contains("\"pre\":\"/api/users\"") && mount.reference.contains("./routes/users"),
        "{}",
        mount.reference
    );
    assert_eq!(app.endpoints.len(), 1);
}

#[test]
fn nextjs_app_pages_and_routes() {
    let d = tmp("next");
    std::fs::write(d.join("package.json"), "{\"dependencies\":{\"next\":\"14\"}}").unwrap();
    let ex = |p: &str, t: &str| NextRoutes.extract(&d, &[SourceFile::new(p, t)]);
    let r = ex("app/api/users/[id]/route.ts", "export async function GET() {}\nexport const POST = async () => {};\n");
    assert_eq!(eps(&r), vec!["GET /api/users/{id} .GET []", "POST /api/users/{id} .POST []"]);
    let r =
        ex("pages/api/hello.ts", "export default function handler(req, res) {\n  if (req.method === 'POST') {}\n}\n");
    assert_eq!(eps(&r), vec!["POST /api/hello .handler []"]);
    let r = ex("app/(shop)/cart/page.tsx", "export default function CartPage() { return null }\n");
    assert_eq!((r.routes[0].path.as_str(), r.routes[0].component.as_deref()), ("/cart", Some("CartPage")));
    let r = ex("pages/blog/[slug].tsx", "export default function Post() {}\n");
    assert_eq!(r.routes[0].path, "/blog/{slug}");
    // no next in package.json: nothing
    let none = tmp("none");
    assert!(NextRoutes
        .extract(&none, &[SourceFile::new("pages/Home.tsx", "export default function Home() {}")])
        .routes
        .is_empty());
}

#[test]
fn fastapi_flask_blueprints() {
    let r = run(
        &PyWeb,
        "app/routes/items.py",
        r#"
from fastapi import APIRouter, Depends
from app.deps import get_current_user
router = APIRouter(prefix="/items", tags=["items"])

@router.get("/{id}")
def read_item(id: int, user = Depends(get_current_user)):
    pass

@router.post("/", dependencies=[Depends(get_current_active_superuser)])
async def create_item():
    pass
"#,
    );
    assert_eq!(
        eps(&r),
        vec![
            "GET /items/{id} .read_item [auth:get_current_user]",
            "POST /items .create_item [auth:get_current_active_superuser]"
        ]
    );
    let f = run(
        &PyWeb,
        "app/main.py",
        r#"
from flask import Flask, Blueprint
from flask_login import login_required
bp = Blueprint('main', __name__, url_prefix='/shop')

@bp.route('/cart/<int:cart_id>', methods=['GET', 'POST'])
@login_required
def cart(cart_id):
    pass

app = Flask(__name__)
@app.get('/ping')
def ping(): pass
app.register_blueprint(bp, url_prefix='/v2')
"#,
    );
    let e = eps(&f);
    assert!(e.contains(&"GET /shop/cart/{cart_id} .cart [auth:login_required]".to_string()), "{e:#?}");
    assert!(e.contains(&"POST /shop/cart/{cart_id} .cart [auth:login_required]".to_string()));
    assert!(e.contains(&"GET /ping .ping [public]".to_string()));
    assert!(f.notes.iter().any(|n| n.kind == "ep:mount" && n.reference.contains("\"pre\":\"/v2\"")));
}

#[test]
fn django_urls_and_views() {
    let r = run(
        &PyWeb,
        "shop/urls.py",
        r#"
from django.urls import path, re_path, include
from . import views
urlpatterns = [
    path('items/<int:pk>/', views.item_detail),
    re_path(r'^search/(?P<q>\w+)/$', views.search),
    path('cart/', views.CartView.as_view()),
    path('api/', include('shop.api.urls')),
]
"#,
    );
    let e = eps(&r);
    assert!(e.contains(&"ANY /items/{pk} views.item_detail []".to_string()), "{e:#?}");
    assert!(e.contains(&"ANY /search/{q} views.search []".to_string()), "{e:#?}");
    assert!(e.contains(&"ANY /cart .CartView []".to_string()), "{e:#?}");
    assert!(r.notes.iter().any(|n| n.kind == "ep:mount"
        && n.reference.contains("shop.api.urls")
        && n.reference.contains("\"pre\":\"api/\"")));
    let v = run(&PyWeb, "shop/views.py", "from django.views import View\nclass CartView(View):\n    def get(self, request): pass\n    def post(self, request): pass\n");
    let note = v.notes.iter().find(|n| n.kind == "ep:view").expect("view note");
    assert!(note.reference.contains("GET") && note.reference.contains("POST"));
}

#[test]
fn go_chi_gin_net_http() {
    let r = run(
        &GoHttp,
        "main.go",
        r#"package main
import ("net/http"; "github.com/go-chi/chi/v5")
func routes() http.Handler {
	r := chi.NewRouter()
	r.Use(AuthMiddleware)
	r.Get("/", home)
	r.Route("/users", func(r chi.Router) {
		r.Get("/", h.List)
		r.Route("/{id}", func(r chi.Router) {
			r.Delete("/", h.Delete)
		})
	})
	r.Mount("/admin", adminRouter())
	// r.Get("/commented", nope)
	return r
}
func adminRouter() chi.Router { r := chi.NewRouter(); r.Get("/stats", stats); return r }
func mux() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping/{id}", ping)
	http.HandleFunc("/legacy", legacy)
}
"#,
    );
    let e = eps(&r);
    for want in [
        "GET / .home [auth:AuthMiddleware]",
        "GET /users h.List [auth:AuthMiddleware]",
        "DELETE /users/{id} h.Delete [auth:AuthMiddleware]",
        "GET /stats .stats [public]",
        "GET /v1/ping/{id} .ping [public]",
        "ANY /legacy .legacy [public]",
    ] {
        assert!(e.contains(&want.to_string()), "missing {want:?} in {e:#?}");
    }
    assert!(!e.iter().any(|x| x.contains("commented")));
    assert!(r
        .notes
        .iter()
        .any(|n| n.kind == "ep:mount" && n.reference.contains("adminRouter") && n.reference.contains("/admin")));
    let g = run(&GoHttp, "api.go", "package api\nimport \"github.com/gin-gonic/gin\"\nfunc Setup(r *gin.Engine) {\n\tv1 := r.Group(\"/v1\", AuthRequired())\n\tv1.GET(\"/me\", me)\n\tv1.POST(\"/items/:id\", Create)\n}\n");
    let e = eps(&g);
    assert!(e.contains(&"GET /v1/me .me [auth:AuthRequired]".to_string()), "{e:#?}");
    assert!(e.contains(&"POST /v1/items/:id .Create [auth:AuthRequired]".to_string()), "{e:#?}");
}

#[test]
fn react_router_objects_and_vue_router() {
    let r = run(
        &FrontendRoutes,
        "src/router.tsx",
        r#"
import { createBrowserRouter } from 'react-router-dom';
export const router = createBrowserRouter([
  { path: '/', element: <Layout />, children: [
      { index: true, element: <Home /> },
      { path: 'users/:id', element: <UserPage />, handle: { roles: ['admin'] } },
      { path: 'old', element: <Navigate to="/users/1" /> },
  ]},
  { path: '/login', Component: Login },
]);
"#,
    );
    let got: Vec<(String, Option<String>)> = r.routes.iter().map(|x| (x.path.clone(), x.component.clone())).collect();
    for want in [("/", Some("Layout")), ("/users/:id", Some("UserPage")), ("/login", Some("Login"))] {
        assert!(got.contains(&(want.0.to_string(), want.1.map(String::from))), "{got:?}");
    }
    assert!(r.routes.iter().any(|x| x.path == "/users/:id" && x.roles == vec!["admin"]));
    assert!(r.routes.iter().any(|x| x.path == "/old" && x.redirect == "/users/1"));
    let v = run(
        &FrontendRoutes,
        "src/router/index.ts",
        "import { createRouter, createWebHistory } from 'vue-router'\nconst routes = [\n { path: '/', component: Home },\n { path: '/about', component: () => import('../views/AboutView.vue'), meta: { roles: ['staff'] } },\n { path: '/u', component: Layout, children: [ { path: ':id', component: User } ] },\n]\nexport default createRouter({ history: createWebHistory(), routes })\n",
    );
    let got: Vec<String> =
        v.routes.iter().map(|x| format!("{} {}", x.path, x.component.clone().unwrap_or_default())).collect();
    for want in ["/ Home", "/about AboutView", "/u/:id User"] {
        assert!(got.contains(&want.to_string()), "{got:?}");
    }
}

#[test]
fn prisma_models_relations_and_ids() {
    use aix_extract::datamodel::DataModel;
    let r = DataModel.extract(
        Path::new("."),
        &[SourceFile::new(
            "prisma/schema.prisma",
            "enum Role {\n  USER\n  ADMIN\n}\nmodel Member {\n  orgId  Int\n  userId Int\n  role   Role @default(USER)\n  user   User @relation(fields: [userId], references: [id])\n  @@id([orgId, userId])\n  @@map(\"members\")\n}\nmodel User {\n  id Int @id @default(autoincrement())\n  members Member[]\n}\n",
        )],
    );
    assert_eq!(
        r.entities.iter().map(|e| (e.name.as_str(), e.table.as_str())).collect::<Vec<_>>(),
        vec![("Member", "members"), ("User", "user")]
    );
    let pks: Vec<&str> = r.entity_fields.iter().filter(|f| f.pk).map(|f| f.field.as_str()).collect();
    assert!(pks.contains(&"orgId") && pks.contains(&"userId") && pks.contains(&"id"), "{pks:?}");
    assert!(r.entity_fields.iter().any(|f| f.entity == "Member" && f.field == "role" && !f.nullable));
    assert!(r.fks.iter().any(|f| f.from_col == "userid"));
}
