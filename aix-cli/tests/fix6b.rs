//! FIX-6B: scope by changed exports, trace without the auth noise (and into SQL functions, with every endpoint of a page),
//! role model (roles that see everything, unknown roles, guards in the page), menu definitions, fixed findings,
//! class uses, role-aware explain. Generic fixtures only.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let o = Command::new("git").arg("-C").arg(repo).args(["-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"]).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
}

fn aix(repo: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo).output().unwrap();
    assert!(o.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}{}", String::from_utf8_lossy(&o.stderr), String::from_utf8_lossy(&o.stdout));
    String::from_utf8_lossy(&o.stdout).to_string()
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

fn init(r: &Path) {
    std::fs::create_dir_all(r).unwrap();
    git(r, &["init", "-q", "-b", "main"]);
}

fn api_ts() -> String {
    let mut s = String::from("import axios from 'axios'\nconst api = axios.create({ baseURL: '/api' })\n\n");
    for i in 0..8 {
        s += &format!("export interface Filler{i}Dto {{\n  id: string\n}}\n\n");
    }
    s += "export interface ItemDto {\n  id: string\n  name: string\n}\n\n";
    s += "export interface OtherDto {\n  id: string\n}\n\n";
    s += "export const itemsApi = {\n  list: () => api.get<ItemDto[]>('/items'),\n  remove: (id: string) => api.delete(`/items/${id}`),\n}\n\n";
    s += "export const otherApi = {\n  get: () => api.get<OtherDto>('/other'),\n  put: (id: string) => api.put(`/other/${id}`, {}),\n}\n";
    s
}

fn page(name: &str, imports: &str, body: &str) -> String {
    format!("{imports}\nexport default function {name}() {{\n{body}  return <div>{name}</div>\n}}\n")
}

fn webapp() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("app");
    init(&r);
    write(&r, "frontend/package.json", "{\"dependencies\":{\"react-router-dom\":\"6.0.0\",\"axios\":\"1.0.0\"}}\n");
    write(&r, "frontend/src/lib/api.ts", &api_ts());
    write(&r, "frontend/src/pages/Alpha.tsx", &page("Alpha", "import { ItemDto } from '../lib/api'", "  const x: ItemDto | null = null\n"));
    write(&r, "frontend/src/pages/Beta.tsx", &page("Beta", "import { itemsApi } from '../lib/api'", "  itemsApi.list()\n"));
    write(&r, "frontend/src/pages/Gamma.tsx", &page("Gamma", "import { otherApi } from '../lib/api'", "  otherApi.get()\n"));
    write(&r, "frontend/src/pages/Delta.tsx", &page("Delta", "", ""));
    write(&r, "frontend/src/pages/Fees.tsx", &page("Fees", "import { otherApi } from '../lib/api'\nimport { hasAnyRole } from '../lib/roles'", "  const isOfficer = hasAnyRole(user.roles, ['officer'])\n  useEffect(() => {\n    if (!isOfficer) return\n    otherApi.put('1')\n  }, [isOfficer])\n"));
    write(&r, "frontend/src/lib/roles.ts", "export const hasAnyRole = (r: string[], l: string[]) => r.some(x => l.includes(x))\n");
    write(
        &r,
        "frontend/src/App.tsx",
        "import { Routes, Route } from 'react-router-dom'\nimport { ProtectedRoute } from './components/ProtectedRoute'\nimport Alpha from './pages/Alpha'\nimport Beta from './pages/Beta'\nimport Gamma from './pages/Gamma'\nimport Delta from './pages/Delta'\nimport Fees from './pages/Fees'\n\
         export default function App() {\n  return (\n    <Routes>\n\
         \x20     <Route path=\"/alpha\" element={<ProtectedRoute requiredRoles={['clerk']}><Alpha /></ProtectedRoute>} />\n\
         \x20     <Route path=\"/beta\" element={<ProtectedRoute requiredRoles={['clerk']}><Beta /></ProtectedRoute>} />\n\
         \x20     <Route path=\"/gamma\" element={<ProtectedRoute requiredRoles={['clerk']}><Gamma /></ProtectedRoute>} />\n\
         \x20     <Route path=\"/delta\" element={<ProtectedRoute requiredRoles={['clerk']}><Delta /></ProtectedRoute>} />\n\
         \x20     <Route path=\"/fees\" element={<ProtectedRoute requiredRoles={['clerk', 'officer']}><Fees /></ProtectedRoute>} />\n\
         \x20   </Routes>\n  )\n}\n",
    );
    write(
        &r,
        "frontend/src/components/ProtectedRoute.tsx",
        "const SUPER_ROLES = ['root_admin']\nexport function ProtectedRoute({ requiredRoles, children }: any) {\n  const userRoles: string[] = []\n  const isSuper = userRoles.some((r) => SUPER_ROLES.includes(r))\n  const ok = isSuper || requiredRoles.some((role: string) => userRoles.includes(role))\n  return ok ? children : null\n}\n",
    );
    write(
        &r,
        "frontend/src/components/layout/Sidebar.tsx",
        "export const navigationGroups = [\n  {\n    title: 'Main',\n    items: [\n      { name: 'Alpha desk', href: '/alpha', roles: ['clerk'] },\n      { name: 'Beta list', href: '/beta', roles: ['clerk'] },\n    ],\n  },\n]\nexport function exportsOnlyNavItems(userRoles: string[]) {\n  const has = (...rs: string[]) => rs.some(r => userRoles.includes(r))\n  const items = [{ name: 'Gamma view', href: '/gamma' }]\n  if (has('officer')) items.push({ name: 'Fees desk', href: '/fees' })\n  return items\n}\n",
    );
    commit(&r, "init");
    (d, r)
}

#[test]
fn scope_follows_changed_exports_not_every_importer() {
    let (_d, r) = webapp();
    aix(&r, &["update", "--full"]);
    // one field of ItemDto: Alpha imports it, Beta only calls itemsApi.list() (returns it); Gamma and Delta cannot see it
    let a = std::fs::read_to_string(r.join("frontend/src/lib/api.ts")).unwrap();
    write(&r, "frontend/src/lib/api.ts", &a.replace("  name: string\n}", "  name: string\n  note?: string\n}"));
    commit(&r, "ItemDto note");
    aix(&r, &["update"]);
    let s = aix(&r, &["scope", "--commit", "HEAD"]);
    assert!(s.contains("-> 2 of 5 routes"), "{s}");
    assert!(s.contains("ItemDto"), "{s}");
    assert!(s.contains("alpha") && s.contains("beta") && !s.contains("gamma") && !s.contains("delta"), "{s}");
    // top-level code (the import line) is not attributable: every importer stays in
    write(&r, "frontend/src/lib/api.ts", &a.replace("import axios from 'axios'", "import axios from 'axios' // x"));
    commit(&r, "import");
    aix(&r, &["update"]);
    let s = aix(&r, &["scope", "--commit", "HEAD"]);
    assert!(s.contains("-> 4 of 5 routes") && s.contains("alpha") && s.contains("gamma") && s.contains("fees"), "{s}");
    assert!(!s.contains("exported symbol(s)"), "{s}");
}

#[test]
fn roles_that_see_everything_unknown_roles_and_alternate_menus() {
    let (_d, r) = webapp();
    aix(&r, &["update", "--full"]);
    let b = aix(&r, &["brief", "/alpha"]);
    assert!(b.contains("root_admin see every page"), "{b}");
    // a super role sees every menu row; a name that is no role is said to be none, with a suggestion
    let f = aix(&r, &["feature", "root_admin"]);
    assert!(f.contains("super role: sees every page") && f.contains("Gamma view") && f.contains("Alpha desk"), "{f}");
    let u = aix(&r, &["feature", "root_adminn"]);
    assert!(u.contains("no such role 'root_adminn'") && u.contains("root_admin"), "{u}");
    let c = aix(&r, &["feature", "clerk"]);
    assert!(c.contains("menu items visible to clerk") && c.contains("Alpha desk"), "{c}");
    // the menu built for officers shows its own filter, not roles=all
    let g = aix(&r, &["brief", "/gamma"]);
    assert!(g.contains("'Gamma view' roles=officer"), "{g}");
    let ff = aix(&r, &["brief", "/fees"]);
    assert!(ff.contains("'Fees desk' roles=officer"), "{ff}");
}

#[test]
fn text_of_a_menu_label_cites_the_menu_definition() {
    let (_d, r) = webapp();
    aix(&r, &["update", "--full"]);
    let t = aix(&r, &["text", "Alpha desk"]);
    assert!(t.contains("== menu definition"), "{t}");
    assert!(t.contains("frontend/src/components/layout/Sidebar.tsx:5 [menu navigationGroups/Main] Alpha desk -> /alpha"), "{t}");
    let src: Vec<&str> = t.lines().skip_while(|l| !l.starts_with("== source")).collect();
    assert!(src.get(1).is_some_and(|l| l.contains("Sidebar.tsx:5 [menu] Alpha desk")), "{t}");
}

#[test]
fn page_guards_keep_role_gap_hints_honest() {
    let (_d, r) = webapp();
    aix(&r, &["update", "--full"]);
    // Fees lets clerk in, calls PUT /other behind `if (!isOfficer) return`; the endpoint (below) allows officers only
    write(
        &r,
        "backend/src/main/java/com/acme/OtherResource.java",
        "package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n@Path(\"/api/other\")\npublic class OtherResource {\n  @PUT\n  @Path(\"/{id}\")\n  @RolesAllowed({\"officer\"})\n  public void put(@PathParam(\"id\") String id) {}\n  @GET\n  @RolesAllowed({\"officer\"})\n  public String get() { return \"\"; }\n}\n",
    );
    commit(&r, "backend");
    aix(&r, &["update"]);
    let f = aix(&r, &["brief", "/fees"]);
    assert!(!f.contains("role gap: clerk sees /fees"), "guarded call must not be a role gap:\n{f}");
    // the same call on an unguarded page is one
    let g = aix(&r, &["brief", "/gamma"]);
    assert!(g.contains("role gap: clerk sees /gamma"), "{g}");
}

#[test]
fn sql_functions_are_followed_and_listed_and_auth_is_one_line() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("be");
    init(&r);
    write(&r, "backend/src/main/resources/db/migration/V1__init.sql", "CREATE TABLE users (id text primary key);\nCREATE TABLE things (id text primary key, name text);\nCREATE TABLE thing_tags (thing_id text, tag text);\n");
    write(
        &r,
        "backend/src/main/resources/db/migration/R__fn_thing_summary.sql",
        "CREATE OR REPLACE FUNCTION fn_thing_summary(p_school text)\nRETURNS TABLE (id text, name text)\nLANGUAGE sql STABLE AS $$\n  SELECT t.id, t.name FROM things t JOIN thing_tags g ON g.thing_id = t.id WHERE t.id = p_school\n$$;\n",
    );
    write(&r, "backend/src/main/java/com/acme/User.java", "package com.acme;\nimport jakarta.persistence.*;\n@Entity\n@Table(name = \"users\")\npublic class User extends io.quarkus.hibernate.orm.panache.PanacheEntityBase {\n  @Id public String id;\n}\n");
    write(&r, "backend/src/main/java/com/acme/Ctx.java", "package com.acme;\npublic class Ctx {\n  public User currentUser() {\n    return User.findById(\"me\");\n  }\n}\n");
    // 110 endpoints share the auth lookup, one reads through the SQL function
    let mut res = String::from("package com.acme;\nimport jakarta.ws.rs.*;\n@Path(\"/api/things\")\npublic class ThingResource {\n  Ctx ctx;\n  jakarta.persistence.EntityManager em;\n");
    for i in 0..110 {
        res += &format!("  @GET\n  @Path(\"/e{i}\")\n  public String e{i}() {{\n    ctx.currentUser();\n    return \"\";\n  }}\n");
    }
    res += "  @GET\n  @Path(\"/summary\")\n  public Object summary() {\n    ctx.currentUser();\n    return em.createNativeQuery(\"SELECT id, name \" +\n      \"FROM fn_thing_summary(?1)\").setParameter(1, \"s\").getResultList();\n  }\n}\n";
    write(&r, "backend/src/main/java/com/acme/ThingResource.java", &res);
    commit(&r, "init");
    aix(&r, &["update", "--full"]);
    let t = aix(&r, &["trace", "GET /api/things/summary"]);
    assert!(t.contains("table    things (read)") && t.contains("table    thing_tags (read)"), "{t}");
    assert!(t.contains("via sql function fn_thing_summary"), "{t}");
    assert!(t.contains("auth: Ctx.currentUser") && t.contains("hidden") && t.contains("--all"), "{t}");
    assert!(!t.contains("table    users (read)"), "auth chain should be one line:\n{t}");
    let all = aix(&r, &["trace", "GET /api/things/summary", "--all"]);
    assert!(all.contains("table    users (read)"), "{all}");
    let rd = aix(&r, &["table", "things", "readers"]);
    assert!(rd.contains("sql function fn_thing_summary") && rd.contains("R__fn_thing_summary.sql:1"), "{rd}");
}

#[test]
fn a_page_trace_lists_every_endpoint_and_findings_get_a_status() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("pg");
    init(&r);
    let mut api = String::from("import axios from 'axios'\nconst api = axios.create({ baseURL: '/api' })\nexport const bigApi = {\n");
    let mut be = String::from("package com.acme;\nimport jakarta.ws.rs.*;\n@Path(\"/api/big\")\npublic class BigResource {\n");
    for i in 0..14 {
        api += &format!("  m{i}: () => api.get('/big/m{i}'),\n");
        be += &format!("  @GET\n  @Path(\"/m{i}\")\n  public String m{i}() {{ return \"\"; }}\n");
    }
    api += "}\n";
    be += "}\n";
    write(&r, "frontend/package.json", "{\"dependencies\":{\"react-router-dom\":\"6.0.0\",\"axios\":\"1.0.0\"}}\n");
    write(&r, "frontend/src/lib/api.ts", &api);
    write(&r, "backend/src/main/java/com/acme/BigResource.java", &be);
    let mut calls = String::new();
    for i in 0..13 {
        calls += &format!("  const h{i} = () => bigApi.m{i}()\n");
    }
    // the last one is only called from a lazily loaded modal
    write(&r, "frontend/src/components/LateModal.tsx", "import { bigApi } from '../lib/api'\nexport default function LateModal() {\n  bigApi.m13()\n  return <div>late</div>\n}\n");
    write(
        &r,
        "frontend/src/pages/Big.tsx",
        &format!("import {{ lazy }} from 'react'\nimport {{ bigApi }} from '../lib/api'\nconst LateModal = lazy(() => import('../components/LateModal'))\nexport default function Big() {{\n{calls}  return <LateModal />\n}}\n"),
    );
    write(&r, "frontend/src/App.tsx", "import { Routes, Route } from 'react-router-dom'\nimport Big from './pages/Big'\nexport default function App() {\n  return (\n    <Routes>\n      <Route path=\"/big\" element={<Big />} />\n    </Routes>\n  )\n}\n");
    write(&r, "docs/audit.md", "# Audit\n\n- [ ] **HIGH** BigResource.java m3 returns stale totals when the ledger rounds half cents\n- [ ] **LOW** BigResource.java m4 prints the wrong receipt heading\n");
    commit(&r, "init");
    write(&r, "backend/src/main/java/com/acme/BigResource.java", &be.replace("m3() { return \"\"; }", "m3() { return \"x\"; }"));
    commit(&r, "Fix stale totals in BigResource m3: ledger rounds half cents correctly");
    aix(&r, &["update", "--full"]);
    let t = aix(&r, &["trace", "/big"]);
    for i in 0..14 {
        assert!(t.contains(&format!("/big/m{i}")), "endpoint m{i} missing:\n{t}");
    }
    // finding m3 is likely fixed by the later commit (same file, same topic): shown tagged, never hidden; m4 stays open
    let shown = aix(&r, &["bugs", "BigResource.java"]);
    assert!(shown.contains("[likely fixed by ") && shown.contains("stale totals"), "{shown}");
    assert!(!shown.contains("likely fixed by") || shown.lines().filter(|l| l.contains("likely fixed")).all(|l| !l.contains("receipt heading")), "{shown}");
    let st = aix(&r, &["sql", "SELECT line, status FROM bugs WHERE file='docs/audit.md' AND kind='doc' ORDER BY line"]);
    assert!(st.contains("3 | likely-fixed") && !st.contains("4 | likely-fixed"), "{st}");
}

#[test]
fn class_uses_count_injected_fields() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("cl");
    init(&r);
    write(&r, "src/main/java/com/acme/FooService.java", "package com.acme;\npublic class FooService {\n  public void run() {}\n}\n");
    for i in 0..3 {
        write(&r, &format!("src/main/java/com/acme/User{i}.java"), &format!("package com.acme;\npublic class User{i} {{\n  @jakarta.inject.Inject FooService foo;\n  void go() {{ foo.run(); }}\n}}\n"));
    }
    write(&r, "src/main/java/com/acme/Maker.java", "package com.acme;\npublic class Maker {\n  Object make() { return new FooService(); }\n}\n");
    commit(&r, "init");
    aix(&r, &["update", "--full"]);
    let c = aix(&r, &["callers", "FooService"]);
    assert!(c.contains("uses: 3 injected"), "{c}");
    assert!(c.contains("1 constructed") || c.contains("constructed"), "{c}");
}

#[test]
fn explain_prefers_the_flow_more_roles_reach() {
    let (_d, r) = webapp();
    // two flows answer "ledger report": an officer-only page and a page every clerk, officer and auditor reaches
    write(&r, "frontend/src/pages/LedgerReportDesigner.tsx", &page("LedgerReportDesigner", "", ""));
    write(&r, "frontend/src/pages/LedgerReport.tsx", &page("LedgerReport", "", ""));
    let app = std::fs::read_to_string(r.join("frontend/src/App.tsx")).unwrap();
    write(
        &r,
        "frontend/src/App.tsx",
        &app.replace("import Fees from './pages/Fees'\n", "import Fees from './pages/Fees'\nimport LedgerReportDesigner from './pages/LedgerReportDesigner'\nimport LedgerReport from './pages/LedgerReport'\n").replace(
            "    </Routes>",
            "      <Route path=\"/admin/ledger-report-designer\" element={<ProtectedRoute requiredRoles={['officer']}><LedgerReportDesigner /></ProtectedRoute>} />\n      <Route path=\"/portal/ledger-report\" element={<ProtectedRoute requiredRoles={['clerk', 'officer', 'auditor']}><LedgerReport /></ProtectedRoute>} />\n    </Routes>",
        ),
    );
    commit(&r, "more pages");
    aix(&r, &["update", "--full"]);
    let e = aix(&r, &["explain", "ledger report"]);
    assert!(e.contains("-> route /portal/ledger-report"), "{e}");
    assert!(e.contains("also matches (top 2)") && e.contains("/admin/ledger-report-designer"), "{e}");
}

#[test]
fn role_flags_in_branches_jsx_handlers_and_child_components_guard_calls() {
    let (_d, r) = webapp();
    write(
        &r,
        "frontend/src/pages/Fees.tsx",
        "import { otherApi, itemsApi } from '../lib/api'\nimport { hasAnyRole } from '../lib/roles'\nimport { Panel } from '../components/Panel'\n\nexport default function Fees() {\n  const isOfficer = hasAnyRole(user.roles, ['officer'])\n  const load = async () => {\n    if (isOfficer) {\n      await itemsApi.list()\n    } else {\n      await otherApi.get()\n    }\n  }\n  const save = async () => {\n    await otherApi.put('1')\n  }\n  return (\n    <div>\n      {isOfficer && (\n        <button onClick={() => save()}>Save</button>\n      )}\n      {!isOfficer && <Panel id=\"1\" />}\n    </div>\n  )\n}\n",
    );
    write(
        &r,
        "frontend/src/components/Panel.tsx",
        "import { itemsApi } from '../lib/api'\n\nexport function Panel({\n  id,\n}: { id: string }) {\n  const drop = async () => {\n    await itemsApi.remove(id)\n  }\n  return <button onClick={drop}>Drop</button>\n}\n",
    );
    write(
        &r,
        "backend/src/main/java/com/acme/OtherResource.java",
        "package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n@Path(\"/api/other\")\npublic class OtherResource {\n  @PUT\n  @Path(\"/{id}\")\n  @RolesAllowed({\"officer\"})\n  public void put(@PathParam(\"id\") String id) {}\n  @GET\n  @RolesAllowed({\"clerk\"})\n  public String get() { return \"\"; }\n}\n",
    );
    write(
        &r,
        "backend/src/main/java/com/acme/ItemResource.java",
        "package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n@Path(\"/api/items\")\npublic class ItemResource {\n  @GET\n  @RolesAllowed({\"officer\"})\n  public String list() { return \"\"; }\n  @DELETE\n  @Path(\"/{id}\")\n  @RolesAllowed({\"officer\"})\n  public void remove(@PathParam(\"id\") String id) {}\n}\n",
    );
    commit(&r, "guards");
    aix(&r, &["update", "--full"]);
    let h = aix(&r, &["hints", "/fees"]);
    // guarded: list (if isOfficer), get (else branch, officer excluded), put (isOfficer && JSX via the handler)
    assert!(!h.contains("GET /api/items") && !h.contains("GET /api/other") && !h.contains("PUT /api/other"), "{h}");
    // Panel renders under !isOfficer: a clerk reaches its DELETE and gets 403 (still a gap)
    assert!(h.contains("role gap: clerk sees /fees but gets 403 on 1 write call: DELETE /api/items/{}"), "{h}");
}
