//! ACC-2: state flow across endpoints, helper writes inside the caller's transaction, mock receivers, interface dispatch
//! wording and roles-sized explain, on the shared datamodel fixture plus a few generic extra files (orders / invoices).

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

fn write(r: &Path, rel: &str, body: &str) {
    let p = r.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn sk(repo: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo).output().unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn repo() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("acme");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/datamodel"), &r);
    let j = "backend/src/main/java/com/acme";
    // two more endpoints that move an order through a review state, written as Panache update fragments
    write(
        &r,
        &format!("{j}/api/OrderReviewResource.java"),
        r#"package com.acme.api;

import com.acme.security.Roles;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.*;
import jakarta.transaction.Transactional;

@Path("/api/orders")
@RolesAllowed({Roles.CLERK, Roles.ADMIN, Roles.MANAGER})
public class OrderReviewResource {
    @jakarta.inject.Inject
    com.acme.service.OrderReviewService service;

    @POST
    @Path("/{id}/submit")
    @Transactional
    public String submit(@PathParam("id") String id) {
        service.submit(id);
        return id;
    }

    @POST
    @Path("/{id}/approve")
    @Transactional
    @RolesAllowed({Roles.ADMIN})
    public String approve(@PathParam("id") String id) {
        service.approve(id);
        return id;
    }

    @POST
    @Path("/{id}/touch")
    @Transactional
    public String touch(@PathParam("id") String id) {
        recalc(id);
        return id;
    }

    private void recalc(String id) {
        com.acme.model.Order order = com.acme.model.Order.findById(id);
        order.quantity = 1;
    }
}
"#,
    );
    write(
        &r,
        &format!("{j}/service/OrderReviewService.java"),
        r#"package com.acme.service;

import com.acme.model.Order;

public class OrderReviewService {
    public void submit(String id) {
        long n = Order.update("status = 'pending_review' where id = ?1 and status = 'open'", id);
    }

    public void approve(String id) {
        long n = Order.update("status = 'approved' where id = ?1 and status = 'pending_review'", id);
    }
}
"#,
    );
    // interface dispatch
    write(&r, &format!("{j}/service/Notifier.java"), "package com.acme.service;\n\npublic interface Notifier {\n    void send(String id);\n}\n");
    write(&r, &format!("{j}/service/EmailNotifier.java"), "package com.acme.service;\n\npublic class EmailNotifier implements Notifier {\n    public void send(String id) {}\n}\n");
    write(&r, &format!("{j}/service/SmsNotifier.java"), "package com.acme.service;\n\npublic class SmsNotifier implements Notifier {\n    public void send(String id) {}\n}\n");
    write(
        &r,
        &format!("{j}/service/Alerts.java"),
        "package com.acme.service;\n\npublic class Alerts {\n    Notifier notifier;\n\n    public void alert(String id) {\n        notifier.send(id);\n    }\n}\n",
    );
    // a mock-based test
    write(
        &r,
        "backend/src/test/java/com/acme/service/OrderServiceTest.java",
        r#"package com.acme.service;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OrderServiceTest {
    OrderService service;

    void cancels() {
        service.cancel("x");
        verify(this.service).cancel("x");
    }

    void stubs() {
        when(service.totals()).thenReturn(null);
    }
}
"#,
    );
    // client wrappers, a nested handler in a dialog component and an approvals page
    write(
        &r,
        "frontend/src/lib/api.ts",
        r#"import axios from 'axios'
export const api = axios.create({ baseURL: '/api' })

export const ordersApi = {
  list: (status?: string) => api.get('/orders', { params: { status } }),
  cancel: (id: string, reason: string) => api.post(`/orders/${id}/cancel`, { reason }),
  remove: (id: string) => api.delete(`/orders/${id}`),
  submit: (id: string) => api.post(`/orders/${id}/submit`),
  approve: (id: string) => api.post(`/orders/${id}/approve`),
}
"#,
    );
    write(
        &r,
        "frontend/src/components/SubmitDialog.tsx",
        "import { ordersApi } from '../lib/api'\n\nexport function SubmitDialog({ id }: { id: string }) {\n  const send = async () => {\n    await ordersApi.submit(id)\n  }\n  return <button onClick={send}>Submit for review</button>\n}\n",
    );
    write(
        &r,
        "frontend/src/pages/Orders.tsx",
        r#"import { useState } from 'react'
import { ordersApi } from '../lib/api'
import { SubmitDialog } from '../components/SubmitDialog'

export function Orders() {
  const [rows, setRows] = useState([])
  const load = () => ordersApi.list('open').then(r => setRows(r.data))
  const cancel = async (id: string) => {
    await ordersApi.cancel(id, 'customer request')
  }
  return (
    <div>
      <h1>Open orders</h1>
      <button title="Reload the list" onClick={load}>Refresh</button>
      {rows.map((r: any) => <button key={r.id} onClick={() => cancel(r.id)}>Cancel order</button>)}
      <SubmitDialog id="1" />
    </div>
  )
}
"#,
    );
    write(
        &r,
        "frontend/src/pages/Approvals.tsx",
        "import { ordersApi } from '../lib/api'\n\nexport function Approvals() {\n  const approve = (id: string) => ordersApi.approve(id)\n  return <button onClick={() => approve('1')}>Approve order</button>\n}\n",
    );
    let app = std::fs::read_to_string(r.join("frontend/src/App.tsx")).unwrap();
    let app = app
        .replace("const Reports =", "const Approvals = lazy(() => import('./pages/Approvals').then(m => ({ default: m.Approvals })))\nconst Reports =")
        .replace("        <Route path=\"reports\"", "        <Route path=\"approvals\" element={<ProtectedRoute requiredRoles={['admin']}><Approvals /></ProtectedRoute>} />\n        <Route path=\"reports\"");
    write(&r, "frontend/src/App.tsx", &app);
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    (d, r)
}

#[test]
fn state_flow_links_setters_to_actors_and_screens() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let e = sk(&r, &["explain", "submit order"]);
    assert!(e.contains("resolved to endpoint POST /api/orders/{}/submit"), "{e}");
    assert!(e.contains("state flow: orders.status 'open' -> 'pending_review' is set by POST /api/orders/{}/submit"), "{e}");
    assert!(e.contains("acts on 'pending_review': POST /api/orders/{}/approve moves it to 'approved'"), "{e}");
    assert!(e.contains("-> screen /approvals"), "{e}");
    // a word the index does not know does not stop it (most words matched, the full match still preferred)
    let e2 = sk(&r, &["explain", "submit order quickly"]);
    assert!(e2.contains("resolved to endpoint POST /api/orders/{}/submit"), "{e2}");
    // the dialog's nested handler is reached through its component, so the endpoint's own screens include /orders
    let up = sk(&r, &["trace", "POST /api/orders/{id}/submit", "--up", "--sites"]);
    assert!(up.contains("SubmitDialog.send") && up.contains("-> screen /orders"), "{up}");
    // the same literal in JSON
    let j: serde_json::Value = serde_json::from_str(&sk(&r, &["--json", "explain", "submit order"])).unwrap();
    assert!(j["answers"].as_array().unwrap().iter().any(|a| a["kind"] == "state" && !a["cites"].as_array().unwrap().is_empty()));
}

#[test]
fn helper_writes_belong_to_the_calling_endpoint() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let t = sk(&r, &["trace", "POST /api/orders/{id}/touch"]);
    assert!(t.contains("OrderReviewResource.recalc") && t.contains("table    orders (write)"), "{t}");
}

#[test]
fn mock_receivers_are_typed_and_labelled() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let c = sk(&r, &["callers", "OrderService.cancel"]);
    assert!(c.contains("OrderServiceTest.cancels (heuristic)") && c.contains("receiver is a mock wrapper"), "{c}");
}

#[test]
fn interface_dispatch_is_named() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let c = sk(&r, &["callees", "Alerts.alert"]);
    assert!(c.contains("via interface Notifier: impls EmailNotifier, SmsNotifier") || c.contains("via interface Notifier: impls SmsNotifier, EmailNotifier"), "{c}");
    assert!(c.contains("implements Notifier"), "{c}");
}

#[test]
fn explain_is_sized_to_the_question() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let roles = sk(&r, &["explain", "approve order roles"]);
    assert!(roles.contains("== roles for POST /api/orders/{}/approve"), "{roles}");
    assert!(roles.contains("roles admin") && roles.contains("route    /approvals") && roles.contains("mismatch") || roles.contains("no mismatch"), "{roles}");
    assert!(!roles.contains("table    orders (write)") && !roles.contains("== docs"), "{roles}");
    let all = sk(&r, &["explain", "approve order roles", "--all"]);
    assert!(all.contains("table    orders (write)") || all.contains("state flow"), "{all}");
    assert!(all.len() > roles.len(), "--all must be the larger answer");
    // a roles question about a screen: the endpoint hops with their roles, no data trace
    let screen = sk(&r, &["explain", "orders menu roles"]);
    assert!(screen.contains("menu     \"Orders\"") && screen.contains("roles clerk,admin,manager") && !screen.contains("table    orders (write)"), "{screen}");
}

#[test]
fn state_rows_follow_incremental_updates() {
    let (_d, r) = repo();
    sk(&r, &["update", "--full"]);
    let q = "select 'refs', tbl, col, op, val, from_vals from state_refs order by 2,3,4,5,6";
    let f = "select 'flow', k.key, s.op, s.tbl, s.col, s.val, s.from_vals, s.depth from state_flow s join trace_keys k on k.id=s.tid order by 2,3,4,5,6,7,8";
    let before = format!("{}{}", sk(&r, &["--no-refresh", "sql", q]), sk(&r, &["--no-refresh", "sql", f]));
    assert!(before.contains("pending_review"), "{before}");
    let p = r.join("backend/src/main/java/com/acme/service/OrderReviewService.java");
    let src = std::fs::read_to_string(&p).unwrap().replace("pending_review", "in_review");
    std::fs::write(&p, src).unwrap();
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "rename state"]);
    sk(&r, &["update"]);
    let inc = format!("{}{}", sk(&r, &["--no-refresh", "sql", q]), sk(&r, &["--no-refresh", "sql", f]));
    assert!(inc.contains("in_review") && !inc.contains("pending_review"), "{inc}");
    sk(&r, &["update", "--full"]);
    let full = format!("{}{}", sk(&r, &["--no-refresh", "sql", q]), sk(&r, &["--no-refresh", "sql", f]));
    assert_eq!(inc, full, "incremental update must equal a full rebuild");
}
