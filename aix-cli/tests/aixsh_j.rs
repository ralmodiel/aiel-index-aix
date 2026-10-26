//! Round-4 QA gaps: history --head and commit hashes, endpoint footers / filters / bare rows / build profiles, set pipes
//! (cat, dedup -c, grep -h -o, filter --where, grep -f), shell habits in quoted pipes, impact flags, likely-fixed
//! tags that need the fix to touch the cited code, script references, role-gap hints (early returns, ternaries,
//! state flags, flags that let a refused role through), path misses, history of a member. Generic fixtures only.

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

fn aix(r: &Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(r).args(args).env("AIX_EMBED_URL", "").env("HOME", r).output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn commit(r: &Path, msg: &str) {
    git(r, &["add", "-A"]);
    git(r, &["commit", "-q", "-m", msg]);
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".env*\n.DS_Store\n.aix/\n");
    for (p, b) in files {
        write(&r, p, b);
    }
    commit(&r, "init");
    aix(&r, &["update"]);
    (d, r)
}

/// A resource with `n` GET endpoints (every third one for `clerk` too), a POST approve, and a dev-only resource.
fn api_repo(n: usize) -> (tempfile::TempDir, PathBuf) {
    let mut java = String::from("package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n\n@Path(\"/api/things\")\npublic class ThingResource {\n");
    for i in 0..n {
        let roles = if i % 3 == 0 { "\"admin\", \"clerk\"" } else { "\"admin\"" };
        java.push_str(&format!("    @GET\n    @Path(\"/e{i}\")\n    @RolesAllowed({{{roles}}})\n    public String e{i}() {{ return \"\"; }}\n\n"));
    }
    java.push_str("    @POST\n    @Path(\"/{id}/approve\")\n    @RolesAllowed({\"admin\", \"clerk\"})\n    public void approve(@PathParam(\"id\") String id) { }\n}\n");
    let dev = "package com.acme;\nimport io.quarkus.arc.profile.IfBuildProfile;\nimport jakarta.ws.rs.*;\n\n@Path(\"/api/devtools\")\n@IfBuildProfile(\"dev\")\npublic class DevToolsResource {\n    @POST\n    @Path(\"/reset/{id}\")\n    public void reset(@PathParam(\"id\") String id) { }\n}\n";
    let script = "import os\nAPI = \"http://localhost:8080\"\ndef call(m, p):\n    return None\nr = {\"id\": \"1\"}\ncall(\"POST\", f\"/api/things/{r['id']}/approve\")\n";
    repo(&[("src/main/java/com/acme/ThingResource.java", &java), ("src/main/java/com/acme/DevToolsResource.java", dev), ("scripts/check-things.py", script)])
}

#[test]
fn history_head_lists_commits_and_keeps_hashes() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".aix/\n");
    for (i, msg) in ["first", "Settings: puts password and alerts first (password y 621 to 285 on a phone)", "third"].iter().enumerate() {
        write(&r, "src/page.ts", &format!("export const v = {i};\n"));
        commit(&r, msg);
    }
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["history", "src/page.ts", "--head", "2"]);
    let rows = out.lines().filter(|l| l.starts_with("  ") && l.split_whitespace().nth(1).is_some_and(|d| d.starts_with("20"))).count();
    assert_eq!(rows, 2, "{out}");
    assert!(out.contains("--head 2: 1 more row"), "{out}");
    let (_, out, _) = aix(&r, &["history", "src/page.ts"]);
    assert!(!out.contains("***"), "a commit hash is never masked: {out}");
    let pw = out.lines().find(|l| l.contains("Settings:")).unwrap_or_default();
    assert!(pw.trim_start().chars().take(7).all(|c| c.is_ascii_hexdigit()), "{pw}");
}

#[test]
fn grep_whole_line_flag_with_an_unknown_set() {
    let (_d, r) = repo(&[("notes.txt", "ab\n")]);
    let (c, out, _) = aix(&r, &["grep", "-x", "ab", "@unknownset"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("unknown data set @unknownset"), "{out}");
}

#[test]
fn endpoint_says_what_it_cut_and_bare_is_one_row_per_endpoint() {
    let (_d, r) = api_repo(22);
    let (_, out, _) = aix(&r, &["endpoint", "/api/things"]);
    assert!(out.contains("(+3 more endpoints: aix endpoint /api/things --limit 23)"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--jsonl"]);
    assert!(out.lines().last().unwrap_or("").contains("\"truncated\":true"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--bare"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 21, "{out}");
    assert!(lines[..20].iter().all(|l| l.contains("ThingResource.java:") && l.contains(" roles=")), "{out}");
    assert!(lines[20].starts_with('\u{2026}') && lines[20].contains("--limit 23"), "{out}");
    // a page keeps each endpoint's roles under it, and counts endpoints (not card lines)
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--per-page", "2"]);
    assert_eq!(out.matches("  roles: ").count(), 2, "{out}");
    assert!(out.contains("(rows 1-2 of 23)"), "{out}");
}

#[test]
fn endpoint_filters_profiles_and_pipe_rows() {
    let (_d, r) = api_repo(6);
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--role", "clerk", "--count-by", "method"]);
    assert!(out.contains("== 3 endpoints matching '/api/things' (--role clerk) by method"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--method", "POST", "--bare"]);
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.contains("POST /api/things/{id}/approve roles=admin,clerk scripts=scripts/check-things.py"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/things", "--untested", "--bare"]);
    assert_eq!(out.lines().count(), 6, "the approve endpoint has a script: {out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/devtools"]);
    assert!(out.contains("no auth declared") && out.contains("profile: only in the dev build (@IfBuildProfile)"), "{out}");
    // in a pipe an endpoint row carries its roles and scripts
    let (_, out, _) = aix(&r, &["endpoint /api/things | grep -c clerk"]);
    assert_eq!(out.trim(), "3", "{out}");
    let (_, out, _) = aix(&r, &["endpoint /api/things | grep -c check-things"]);
    assert_eq!(out.trim(), "1", "{out}");
}

#[test]
fn script_refs_keep_subscripts_printf_and_helper_paths() {
    let (_d, r) = api_repo(1);
    write(
        &r,
        "scripts/regress/more.py",
        "def call(m, p, b=None):\n    return None\nids = [1, 2]\ncall(\"POST\", \"/api/things/%s/approve\" % ids[0])\ncall(\"POST\", f\"/things/{ids[1]}/approve\", {\"why\": \"x\"})\n",
    );
    commit(&r, "more");
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["endpoint", "POST", "/api/things/{id}/approve"]);
    assert!(out.contains("scripts/check-things.py") && out.contains("scripts/regress/more.py"), "{out}");
}

#[test]
fn files_glob_ending_in_dot_star() {
    let (_d, r) = repo(&[("src/a.test.ts", "1\n"), ("src/b.test.tsx", "2\n"), ("src/c.ts", "3\n")]);
    let (c, out, _) = aix(&r, &["files", "*.test.*", "--count"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.starts_with("2 "), "{out}");
    let (_, out, _) = aix(&r, &["files", "src/**/*.test.*", "--count"]);
    assert!(out.starts_with("2 "), "{out}");
}

#[test]
fn set_pipes_read_every_row() {
    let rows: String = (1..=141).map(|i| format!("row number {i}\n")).collect();
    let people: String = (0..5).map(|i| format!("Alice|change {i}\n")).collect();
    let log = "2026-10-23 14:46:02 INFO  [a.b.Start] (main) started\n2026-10-23 14:46:03 WARN  [a.b.Db] (main) slow query\n2026-10-23 14:46:04 INFO  [a.b.Api] (main) ready\n2026-10-23 14:46:05 ERROR [a.b.Api] (main) failed call\n";
    let (_d, r) = repo(&[("rows.txt", &rows), ("people.txt", &people), ("app.log", log), ("all.txt", "a.py\nb.py\nc.py\n"), ("ran.txt", "b.py\n")]);
    for (n, f) in [("rows", "rows.txt"), ("people", "people.txt"), ("all", "all.txt"), ("ran", "ran.txt")] {
        let (c, _, e) = aix(&r, &["put", n, &r.join(f).to_string_lossy()]);
        assert_eq!(c, 0, "{e}");
    }
    let (c, _, e) = aix(&r, &["put", "applog", &r.join("app.log").to_string_lossy(), "--format", "log"]);
    assert_eq!(c, 0, "{e}");
    let (_, out, _) = aix(&r, &["cat @rows --bare | count"]);
    assert_eq!(out.trim(), "141", "{out}");
    let (_, out, _) = aix(&r, &["cat @rows @rows --bare --full | dedup text -c | count"]);
    assert_eq!(out.trim(), "141", "distinct rows: {out}");
    let (_, out, _) = aix(&r, &["grep -h -o -E '^Alice' @people | count by match"]);
    assert!(out.contains("5 in 1 groups") && out.contains("5  Alice"), "{out}");
    let (_, out, _) = aix(&r, &["filter", "--where", "level=INFO", "@applog"]);
    assert_eq!(out.matches("@applog:").count(), 2, "{out}");
    let (c, out, _) = aix(&r, &["filter --where level=INFO @applog | count"]);
    assert_eq!((c, out.trim()), (0, "2"), "{out}");
    // a set difference: rows of @all that are not lines of @ran
    let (_, out, _) = aix(&r, &["grep", "-v", "-F", "-x", "-f", "@ran", "@all", "--bare"]);
    assert_eq!(out.trim(), "@all:1:a.py\n@all:3:c.py", "{out}");
    // a filter before another stage passes every matching row (its 20 + 60 window is for reading)
    let (_, out, _) = aix(&r, &["grep -h . @rows | filter -i row | count"]);
    assert_eq!(out.trim(), "141", "{out}");
}

#[test]
fn quoted_pipes_take_shell_habits() {
    let (_d, r) = repo(&[("scripts/gate.sh", "#!/bin/sh\n# gate\necho gate\necho gate two\n")]);
    let (c, out, _) = aix(&r, &["grep -c gate scripts/gate.sh 2>&1"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("scripts/gate.sh: 3"), "{out}");
    let (c, out, _) = aix(&r, &["grep -c gate scripts/gate.sh > out.txt"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("do not redirect to files"), "{out}");
    let (c, out, _) = aix(&r, &["grep -c gate scripts/gate.sh --jsonl"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("put it before the quotes"), "{out}");
    let (c, out, _) = aix(&r, &["grep gate scripts/gate.sh --json | count"]);
    assert_eq!((c, out.trim()), (0, "3"), "{out}");
    let (_, out, _) = aix(&r, &["--jsonl", "grep -c gate scripts/gate.sh ; files scripts/gate.sh --count"]);
    let l: Vec<&str> = out.lines().collect();
    assert_eq!(l.len(), 3, "one answer per command and a summary: {out}");
    assert!(l[0].contains("\"cmd\":\"grep -c gate scripts/gate.sh\"") && l[1].contains("\"cmd\":\"files scripts/gate.sh --count\""), "{out}");
    let (_, out, _) = aix(&r, &["--bare", "grep -c gate scripts/gate.sh ; files scripts/gate.sh --count"]);
    assert!(!out.contains("== aix"), "{out}");
    let (c, out, _) = aix(&r, &["grep gate scripts/gate.sh | awk 1"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("unknown pipe stage 'awk'") && out.contains("Row stages:"), "{out}");
}

#[test]
fn impact_reads_its_flags_anywhere_and_bad_revisions_exit_2() {
    let svc = "package com.acme;\npublic class Svc {\n    public int run(int x) { return x + 1; }\n}\n";
    let caller = "package com.acme;\npublic class Caller {\n    private Svc svc = new Svc();\n    public int go() { return svc.run(1); }\n}\n";
    let (_d, r) = repo(&[("src/main/java/com/acme/Svc.java", svc), ("src/main/java/com/acme/Caller.java", caller)]);
    let (_, plain, _) = aix(&r, &["impact", "Svc.run"]);
    assert!(plain.starts_with("== impact of Svc.run"), "{plain}");
    for f in [&["--limit", "5"][..], &["--max", "5"], &["--full"]] {
        let mut a = vec!["impact", "Svc.run"];
        a.extend_from_slice(f);
        let (_, out, _) = aix(&r, &a);
        assert_eq!(out.lines().next(), plain.lines().next(), "{f:?}: {out}");
    }
    let (c, out, _) = aix(&r, &["scope", "notarev"]);
    assert_eq!(c, 2, "{out}");
    let (_, out, _) = aix(&r, &["history", "Svc.run"]);
    assert!(out.contains("== Svc.run (src/main/java/com/acme/Svc.java:3-3): 1 commits changed its lines"), "{out}");
}

#[test]
fn likely_fixed_needs_the_fix_to_touch_the_cited_lines() {
    let mut svc = String::from("package com.acme;\npublic class PlanService {\n");
    for i in 0..30 {
        svc.push_str(&format!("    int f{i}() {{ return {i}; }}\n"));
    }
    svc.push_str("}\n");
    let tasks = "# Tasks\n\n- [ ] Found (r1 plans): copyPlan reactivates plan rows an admin removed (PlanService.java:20-24)\n- [ ] Found (r1 plans): deletePlan ignores closed years (PlanService.java:4-5)\n";
    let (_d, r) = repo(&[("src/main/java/com/acme/PlanService.java", &svc), ("TASKS.md", tasks)]);
    let fixed = svc.replace("    int f2() { return 2; }\n", "    int f2() { return -2; }\n");
    write(&r, "src/main/java/com/acme/PlanService.java", &fixed);
    commit(&r, "Fix(plans): copyPlan and deletePlan refuse closed years");
    aix(&r, &["update"]);
    let (_, out, _) = aix(&r, &["bugs", "PlanService", "--all"]);
    let line = |w: &str| out.lines().find(|l| l.contains(w)).unwrap_or_default().to_string();
    assert!(line("copyPlan reactivates").contains("Found") && !line("copyPlan reactivates").contains("likely fixed"), "the fix did not touch lines 20-24: {out}");
    assert!(line("deletePlan ignores").contains("[likely fixed by"), "the fix changed line 4: {out}");
}

/// A small React app: a page whose calls are kept from roles by an early return, a ternary and a state flag, and a
/// role flag that lists a role the endpoint refuses.
#[test]
fn role_gap_hints_follow_early_returns_ternaries_and_state() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("app");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".aix/\n");
    write(&r, "frontend/package.json", "{\"dependencies\":{\"react-router-dom\":\"6.0.0\",\"axios\":\"1.0.0\"}}\n");
    write(
        &r,
        "frontend/src/lib/api.ts",
        "import axios from 'axios'\nconst api = axios.create({ baseURL: '/api' })\n\nexport const itemsApi = {\n  list: () => api.get('/items'),\n}\n\nexport const otherApi = {\n  put: (id: string) => api.put(`/other/${id}`, {}),\n}\n",
    );
    write(&r, "frontend/src/lib/roles.ts", "export const hasAnyRole = (r: string[], l: string[]) => r.some(x => l.includes(x))\n");
    write(
        &r,
        "frontend/src/pages/Desk.tsx",
        "import { useEffect, useState } from 'react'\nimport { itemsApi, otherApi } from '../lib/api'\nimport { hasAnyRole } from '../lib/roles'\n\n\
         export default function Desk() {\n  const isOfficer = hasAnyRole(user.roles, ['officer', 'auditor'])\n  const isClerk = hasAnyRole(user.roles, ['clerk'])\n  const [confirming, setConfirming] = useState<string | null>(null)\n\
         \x20 useEffect(() => {\n    if (isClerk) return\n    itemsApi.list()\n  }, [isClerk])\n\
         \x20 const save = async (id: string) => {\n    await otherApi.put(id)\n    setConfirming(null)\n  }\n\
         \x20 return (\n    <div>\n      {isOfficer ? (\n        <button onClick={() => setConfirming('1')}>Save</button>\n      ) : (\n        <span>read only</span>\n      )}\n\
         \x20     {confirming && <Modal onConfirm={() => save(confirming)} />}\n    </div>\n  )\n}\n",
    );
    write(
        &r,
        "frontend/src/App.tsx",
        "import { Routes, Route } from 'react-router-dom'\nimport { ProtectedRoute } from './components/ProtectedRoute'\nimport Desk from './pages/Desk'\n\
         export default function App() {\n  return (\n    <Routes>\n\
         \x20     <Route path=\"/desk\" element={<ProtectedRoute requiredRoles={['clerk', 'officer']}><Desk /></ProtectedRoute>} />\n\
         \x20   </Routes>\n  )\n}\n",
    );
    write(&r, "frontend/src/components/ProtectedRoute.tsx", "export function ProtectedRoute({ requiredRoles, children }: any) {\n  return requiredRoles ? children : null\n}\n");
    write(
        &r,
        "backend/src/main/java/com/acme/ItemResource.java",
        "package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n@Path(\"/api/items\")\npublic class ItemResource {\n  @GET\n  @RolesAllowed({\"officer\", \"auditor\"})\n  public String list() { return \"\"; }\n}\n",
    );
    write(
        &r,
        "backend/src/main/java/com/acme/OtherResource.java",
        "package com.acme;\nimport jakarta.annotation.security.RolesAllowed;\nimport jakarta.ws.rs.*;\n@Path(\"/api/other\")\npublic class OtherResource {\n  @PUT\n  @Path(\"/{id}\")\n  @RolesAllowed({\"officer\"})\n  public void put(@PathParam(\"id\") String id) {}\n}\n",
    );
    commit(&r, "init");
    aix(&r, &["update", "--full"]);
    let (_, h, _) = aix(&r, &["hints", "/desk"]);
    // `if (isClerk) return` keeps the clerk out of the list call; the PUT runs from a modal that only the officer
    // flag opens (ternary, then a state flag)
    assert!(!h.contains("role gap: clerk"), "{h}");
    // the officer flag also lets 'auditor' reach the PUT, which only 'officer' may call
    assert!(h.contains("role flag gap: isOfficer let auditor reach 1 call the endpoint refuses") && h.contains("PUT /api/other/{}"), "{h}");
}

#[test]
fn path_misses_name_the_nearest_file() {
    let (_d, r) = repo(&[("frontend/src/components/layout/Sidebar.tsx", "export const s = 1;\n")]);
    for cmd in ["cat", "head", "code"] {
        let (c, out, _) = aix(&r, &[cmd, "frontend/src/components/Sidebar.tsx"]);
        assert_eq!(c, 1, "{cmd}: {out}");
        assert!(out.contains("did you mean: frontend/src/components/layout/Sidebar.tsx"), "{cmd}: {out}");
    }
    let (_, out, _) = aix(&r, &["sed", "-n", "1p", "frontend/src/components/Sidebar.tsx"]);
    assert!(out.contains("did you mean") && !out.contains("no line selected"), "{out}");
    let (_, out, _) = aix(&r, &["grep", "-c", "s", "frontend/src/components/Sidebar.tsx"]);
    assert!(out.contains("did you mean: frontend/src/components/layout/Sidebar.tsx"), "{out}");
}

#[test]
fn bare_grep_keeps_its_notes_on_stderr_and_and_needs_a_regex() {
    let (_d, r) = repo(&[("src/a.ts", "create table x\n")]);
    let (c, out, err) = aix(&r, &["grep", "-c", "-i", "create table", "-g", "**/db/nope/**", "--bare"]);
    assert_eq!(c, 1);
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("the scope matched no indexed file"), "{err}");
    let (c, out, _) = aix(&r, &["grep", "--and", "table", "src/a.ts"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("--and/--not add a condition"), "{out}");
}

#[test]
fn put_stores_a_shell_script_as_text() {
    let (_d, r) = repo(&[("run.sh", "#!/bin/sh\n# Step one\necho a\n# Step two\necho b\n")]);
    let (_, out, _) = aix(&r, &["put", "runsh", &r.join("run.sh").to_string_lossy()]);
    assert!(out.contains("(text)"), "{out}");
}

#[test]
fn help_and_howto_name_the_new_forms() {
    let (_d, r) = repo(&[("a.txt", "x\n")]);
    let (_, g, _) = aix(&r, &["grep", "--help"]);
    assert!(g.contains("--and RE") && g.contains("--not RE") && g.contains("--body"), "{g}");
    let (_, p, _) = aix(&r, &["pipe", "--help"]);
    assert!(p.contains("Row stages") && p.contains("put NAME"), "{p}");
    let (_, f, _) = aix(&r, &["filter", "--help"]);
    assert!(f.contains("--where"), "{f}");
    let (_, h, _) = aix(&r, &["howto", "grep lines that match two patterns"]);
    assert!(h.lines().nth(1).unwrap_or("").contains("--and"), "{h}");
    let (_, h, _) = aix(&r, &["howto", "which endpoints have no test"]);
    assert!(h.lines().nth(1).unwrap_or("").contains("--untested"), "{h}");
    // a bare command name: its usage line (the MCP description points here)
    let (_, h, _) = aix(&r, &["howto", "put"]);
    assert!(h.contains("aix put <name>"), "{h}");
}

#[test]
fn code_of_a_big_class_is_its_head_and_member_outline() {
    let mut src = String::from("export class Big {\n  private n = 0;\n");
    for i in 0..30 {
        src.push_str(&format!("  m{i}(x: number): number {{\n    const y = x + {i};\n    this.n += y;\n    return y;\n  }}\n"));
    }
    src.push_str("}\n");
    let (_d, r) = repo(&[("src/big.ts", src.as_str())]);
    let (_, o, _) = aix(&r, &["code", "Big"]);
    assert!(o.contains("members:") && o.contains("Big.m0") && o.contains("aix code src/big.ts:1-153 --full"), "{o}");
    assert!(!o.contains("this.n += y"), "no method body: {o}");
    let (_, f, _) = aix(&r, &["code", "Big", "--full"]);
    assert!(f.contains("this.n += y"), "{f}");
    // the savings estimate of a code answer is at least what a Read of the same span would print
    let (_, ok, _) = aix(&r, &["sql", "SELECT est_bytes >= bytes_out FROM savings WHERE cmd='code' ORDER BY rowid DESC LIMIT 1", "--bare"]);
    assert_eq!(ok.trim().lines().last(), Some("1"), "{ok}");
}

#[test]
fn put_does_not_hold_the_store_lock_while_its_input_is_still_coming() {
    use std::io::Write;
    let (_d, r) = repo(&[("a.ts", "export function a() { return b(); }\nexport function b() { return 1; }\nexport function c() { return a(); }\n")]);
    // a long-running producer piping into `aix put slow -` (its stdin stays open)
    let mut slow = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).args(["put", "slow", "-"]).env("HOME", &r).env("AIX_STORE_BUSY_MS", "300")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let mut sin = slow.stdin.take().unwrap();
    sin.write_all(b"first line\n").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let fast = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&r).args(["put", "fast", "-"]).env("HOME", &r).env("AIX_STORE_BUSY_MS", "300")
        .stdin(std::process::Stdio::piped()).output_with(b"x\n");
    assert!(fast.0 == 0 && fast.1.contains("stored @fast"), "{fast:?}");
    sin.write_all(b"last line\n").unwrap();
    drop(sin);
    let o = slow.wait_with_output().unwrap();
    assert!(o.status.success() && String::from_utf8_lossy(&o.stdout).contains("stored @slow: 1 item(s), 2 lines"), "{o:?}");
    // `callers A B`: one section per symbol
    let (_, c, _) = aix(&r, &["callers", "a", "b"]);
    assert!(c.contains("callers of a") && c.contains("callers of b"), "{c}");
}

trait OutputWith {
    fn output_with(&mut self, input: &[u8]) -> (i32, String, String);
}
impl OutputWith for Command {
    fn output_with(&mut self, input: &[u8]) -> (i32, String, String) {
        use std::io::Write;
        let mut c = self.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        c.stdin.take().unwrap().write_all(input).unwrap();
        let o = c.wait_with_output().unwrap();
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
    }
}
