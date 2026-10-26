//! Round-3 QA gaps: sequences keep their words, escaped quotes in pipes, pipe-stage grep flags, unknown data sets,
//! the reader line clip and --width, leading stages over files and data sets.

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

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("proj");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    write(&r, ".gitignore", ".env*\n.DS_Store\n.aix/\n");
    for (p, b) in files {
        write(&r, p, b);
    }
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    aix(&r, &["update"]);
    (d, r)
}

const API: &str = "import javax.ws.rs.*;\n\n@Path(\"/api/items\")\npublic class ItemResource {\n    @POST\n    @Path(\"/{id}/approve\")\n    public void approve(@PathParam(\"id\") long id) { }\n\n    @GET\n    @Path(\"/check\")\n    public String check() { return \"ok\"; }\n}\n";

fn base() -> (tempfile::TempDir, PathBuf) {
    let long = format!("// {}\n", "y".repeat(300));
    repo(&[
        ("src/ItemResource.java", API),
        ("src/a.ts", &format!("export const a = 'alpha';\nexport const b = 'say \"hi\"';\n{long}export const c = 'alpha beta';\n")),
        ("src/GradeA.ts", "export const g = 1;\n"),
        ("src/GradeB.ts", "export const h = 2;\n"),
        ("src/Other.ts", "export const o = 3;\n"),
        ("notes.txt", "one fix\ntwo\nthree fix\nfour fix\n"),
    ])
}

#[test]
fn sequence_passes_words_unquoted() {
    let (_d, r) = base();
    let (c, out, _) = aix(&r, &["endpoint \"POST /api/items/{id}/approve\" ; endpoint GET /api/items/check"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("ItemResource.java:5") && out.contains("ItemResource.java:9"), "{out}");
    assert!(!out.contains("no endpoint matches"), "{out}");
    let (_, one, _) = aix(&r, &["endpoint", "POST /api/items/{id}/approve"]);
    assert!(one.contains("ItemResource.java:5"), "{one}");
}

#[test]
fn escaped_and_open_quotes_in_a_pipe() {
    let (_d, r) = base();
    // `\"` inside double quotes does not end the quote: the stage boundary is still found
    let (c, out, _) = aix(&r, &[r#"grep -c "say \"hi" src/a.ts | count"#]);
    assert_eq!((c, out.trim()), (0, "1"), "{out}");
    let (c, out, _) = aix(&r, &[r#"grep -c "say src/a.ts | count"#]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("unbalanced \" quote"), "{out}");
}

#[test]
fn pipe_grep_stage_counts_and_refuses_unknown_flags() {
    let (_d, r) = base();
    let (c, out, _) = aix(&r, &["files src/* --bare | grep -c Grade"]);
    assert_eq!((c, out.trim()), (0, "2"), "{out}");
    let (_, out, _) = aix(&r, &["files src/* --bare | grep -o 'Grade[AB]'"]);
    assert!(out.contains("GradeA") && out.contains("GradeB") && !out.contains("src/"), "{out}");
    let (c, out, _) = aix(&r, &["files src/* --bare | grep -l Grade"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("flag -l is not supported"), "{out}");
}

#[test]
fn grep_unknown_data_set_is_an_error() {
    let (_d, r) = base();
    let (c, out, _) = aix(&r, &["grep", "-c", "fix", "@nosuchset"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("unknown data set @nosuchset"), "{out}");
    // an annotation as the pattern is still a pattern
    let (c, _, _) = aix(&r, &["grep", "-c", "@Path"]);
    assert_eq!(c, 0);
}

#[test]
fn data_set_grep_then_count_and_leading_stages() {
    let (_d, r) = base();
    let (c, _, e) = aix(&r, &["put", "notes", &r.join("notes.txt").to_string_lossy()]);
    assert_eq!(c, 0, "{e}");
    let (c, out, _) = aix(&r, &["grep -i fix @notes | count"]);
    assert_eq!((c, out.trim()), (0, "3"), "{out}");
    let (_, out, _) = aix(&r, &["sed -n 2,3p @notes"]);
    assert!(out.contains("two") && out.contains("three fix") && !out.contains("four"), "{out}");
    let (_, out, _) = aix(&r, &["sed", "-n", "4p", "@notes"]);
    assert!(out.contains("four fix") && !out.contains("three"), "{out}");
    let (_, out, _) = aix(&r, &["head -n 1 src/a.ts"]);
    assert!(out.contains("alpha") && !out.contains("needs rows"), "{out}");
    let (_, out, _) = aix(&r, &["sed -n 1,2p src/a.ts | count"]);
    assert_eq!(out.trim(), "2", "{out}");
}

#[test]
fn reader_clip_names_the_flag_and_width_lifts_it() {
    let (_d, r) = base();
    let (_, out, _) = aix(&r, &["sed", "-n", "3p", "src/a.ts"]);
    assert!(out.contains("more chars] (--width 0 shows them)"), "{out}");
    for w in ["0", "1000"] {
        let (_, out, _) = aix(&r, &["sed", "-n", "3p", "src/a.ts", "--width", w]);
        assert!(out.contains(&"y".repeat(300)) && !out.contains("more chars"), "--width {w}: {out}");
        let (_, out, _) = aix(&r, &["code", "src/a.ts:3", "--width", w]);
        assert!(out.contains(&"y".repeat(300)), "code --width {w}: {out}");
    }
}

#[test]
fn outline_two_words_naming_two_members_lists_both() {
    let mut body = String::from("export class Store {\n  createItem(x: number) { return x + 1; }\n  updateItem(x: number) { const create = 1; return x + create; }\n  removeItem(x: number) { return x; }\n");
    for i in 0..30 {
        body.push_str(&format!("  helper{i}(x: number) {{ return x * {i}; }}\n"));
    }
    body.push_str("}\n");
    let (_d, r) = repo(&[("src/store.ts", &body)]);
    let (_, out, _) = aix(&r, &["outline", "src/store.ts", "create update"]);
    assert!(out.contains("createItem") && out.contains("updateItem") && !out.contains("removeItem"), "{out}");
    let (_, out, _) = aix(&r, &["outline", "src/store.ts"]);
    assert!(out.contains("more members: aix outline src/store.ts --limit"), "{out}");
}

const ROLES: &str = "import javax.ws.rs.*;\nimport jakarta.annotation.security.RolesAllowed;\n\n@Path(\"/api/docs\")\npublic class DocResource {\n    @DELETE\n    @Path(\"/{id}\")\n    @RolesAllowed({\"r_one\", \"r_two\", \"r_three\", \"r_four\", \"r_five\", \"r_six\", \"r_seven\", \"r_eight\"})\n    public void remove(@PathParam(\"id\") long id) { }\n}\n";

#[test]
fn endpoint_roles_whole_under_full_and_json() {
    let (_d, r) = repo(&[("src/DocResource.java", ROLES)]);
    let (_, out, _) = aix(&r, &["endpoint", "DELETE /api/docs/{id}"]);
    assert!(out.contains(",+2"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "DELETE /api/docs/{id}", "--full"]);
    assert!(out.contains("r_seven,r_eight") && !out.contains(",+2"), "{out}");
    let (_, out, _) = aix(&r, &["--json", "endpoint", "DELETE /api/docs/{id}"]);
    assert!(out.contains("\"roles\":[\"r_one\"") && out.contains("\"r_eight\"]") && !out.contains(",+2"), "{out}");
}

#[test]
fn query_commands_refuse_unknown_flags() {
    let (_d, r) = repo(&[("src/a.tsx", "export function A() { return <p>Late arrivals</p>; }\n")]);
    for f in ["-w", "--bogus", "--exact"] {
        let (c, out, _) = aix(&r, &["text", "Late", f]);
        assert_eq!(c, 2, "text Late {f}: {out}");
        assert!(out.contains("unknown option"), "{out}");
    }
    let (c, out, _) = aix(&r, &["ask", "late", "--kind", "method"]);
    assert_eq!(c, 2, "{out}");
    assert!(out.contains("unknown --kind method"), "{out}");
    let (c, _, _) = aix(&r, &["ask", "late", "-t", "java"]);
    assert_eq!(c, 2);
    // after `--` a dash word is a query word
    let (c, out, _) = aix(&r, &["text", "--", "-w"]);
    assert!(c <= 1 && !out.contains("unknown option"), "{out}");
    let (c, out, _) = aix(&r, &["text", "Late"]);
    assert_eq!(c, 0, "{out}");
}

#[test]
fn jsx_text_cites_its_own_line() {
    let page = "export function P({ busy }: { busy: boolean }) {\n  return (\n    <button>\n      {busy ? <span /> : <i />}\n      Save the record\n    </button>\n  );\n}\n";
    let (_d, r) = repo(&[("src/P.tsx", page)]);
    let (_, out, _) = aix(&r, &["text", "Save the record"]);
    assert!(out.contains("src/P.tsx:5"), "{out}");
}

#[test]
fn capped_menus_and_set_reads_name_the_rest() {
    let mut nav = String::from("export const navigationGroups = [\n  {\n    title: 'Main',\n    items: [\n");
    for i in 0..45 {
        nav.push_str(&format!("      {{ name: 'Item{i}', href: '/item{i}', roles: ['clerk'] }},\n"));
    }
    nav.push_str("    ],\n  },\n]\n");
    let nums: String = (1..=141).map(|i| format!("{i}\n")).collect();
    let (_d, r) = repo(&[("frontend/package.json", "{\"dependencies\":{\"react-router-dom\":\"6.0.0\"}}\n"), ("frontend/src/components/layout/Sidebar.tsx", &nav), ("nums.txt", &nums)]);
    let (_, out, _) = aix(&r, &["feature", "clerk"]);
    assert!(out.contains("menu items visible to clerk (45"), "{out}");
    assert!(out.contains("(+5 more menu items: aix feature clerk --limit 45)"), "{out}");
    aix(&r, &["put", "nums", &r.join("nums.txt").to_string_lossy()]);
    let (_, out, _) = aix(&r, &["cat", "@nums", "--bare"]);
    let last = out.lines().last().unwrap_or("");
    assert!(last.starts_with('\u{2026}') && last.contains("aix code @nums:61-") && last.contains("--full"), "{out}");
}

#[test]
fn grep_separators_follow_gnu_and_more_names_full() {
    let body: String = (1..=30).map(|i| if i % 3 == 0 { format!("hit {i}\n") } else { format!("x{i}\n") }).collect();
    let (_d, r) = repo(&[("a.txt", &body)]);
    let (_, out, _) = aix(&r, &["grep", "-n", "hit", "a.txt"]);
    assert!(!out.lines().any(|l| l.trim() == "--"), "{out}");
    assert!(out.contains("more (add --full for all 10)"), "{out}");
    let (_, out, _) = aix(&r, &["grep", "-n", "hit", "a.txt", "--full"]);
    assert_eq!(out.lines().filter(|l| l.contains(": hit ")).count(), 10, "{out}");
    // with context, `--` stands between groups only (as GNU grep prints it)
    let (_, out, _) = aix(&r, &["grep", "-A1", "hit", "a.txt", "--bare"]);
    let gnu = Command::new("grep").args(["-A1", "hit", "a.txt"]).current_dir(&r).output().unwrap();
    let seps = |s: &str| s.lines().filter(|l| l.trim() == "--").count();
    assert_eq!(seps(&out), seps(&String::from_utf8_lossy(&gnu.stdout)), "{out}");
}

#[test]
fn dedup_drops_the_context_of_dropped_rows() {
    let (_d, r) = repo(&[("a.txt", "x\nfoo\nctxA\ny\nfoo\nctxB\nz\nbar foo\nctxC\n")]);
    for bare in [false, true] {
        let mut a = vec!["grep", "-A1", "foo", "a.txt", "--dedup=text"];
        if bare {
            a.push("--bare");
        }
        let (_, out, _) = aix(&r, &a);
        assert!(out.contains("ctxA") && out.contains("ctxC") && !out.contains("ctxB"), "bare={bare}: {out}");
        assert!(!out.lines().collect::<Vec<_>>().windows(2).any(|w| w[0].trim() == "--" && w[1].trim() == "--"), "{out}");
    }
}

#[test]
fn code_ranges_print_in_the_order_asked() {
    let body: String = (1..=40).map(|i| format!("line{i}\n")).collect();
    let (_d, r) = repo(&[("a.txt", &body)]);
    let (_, out, _) = aix(&r, &["code", "a.txt:30-31", "a.txt:2-3"]);
    let (p30, p2) = (out.find("line30").unwrap(), out.find("line2\n").or_else(|| out.find("line2 ")).unwrap_or(usize::MAX));
    assert!(p30 < p2, "{out}");
    let (_, out, _) = aix(&r, &["code", "a.txt:2-3", "a.txt:30-31"]);
    assert!(out.contains("a.txt:2-3,30-31"), "{out}");
}

#[test]
fn prose_words_after_token_are_not_masked() {
    let (_d, r) = repo(&[("c.ts", "// each token is one command\nconst token = \"zz9x8c7v6b5n4m3l2k1j\";\n// the token is hunter2x\n")]);
    let (_, out, _) = aix(&r, &["code", "c.ts"]);
    assert!(out.contains("each token is one command"), "{out}");
    assert!(!out.contains("zz9x8c7v6b5n4m3l2k1j") && !out.contains("hunter2x"), "{out}");
}

#[test]
fn callees_stay_in_the_callers_language() {
    let (_d, r) = repo(&[
        ("src/main/java/a/Payment.java", "package a;\npublic class Payment {\n    public Payment() { }\n}\n"),
        ("src/main/java/a/Service.java", "package a;\npublic class Service {\n    public Payment record() {\n        return new Payment();\n    }\n}\n"),
        ("web/api.ts", "export interface Payment { id: number }\nexport class Payment2 {}\n"),
    ]);
    let (_, out, _) = aix(&r, &["callees", "Service.record"]);
    assert!(out.contains("Payment.java") && !out.contains("api.ts"), "{out}");
}

#[test]
fn ignore_check_reads_templates_and_migrations_named_like_secrets() {
    let (_d, r) = repo(&[]);
    write(&r, ".gitignore", ".env*\n!.env.example\n.DS_Store\n.aix/\n");
    write(&r, ".env.example", "DB_PASSWORD=\nAPI_TOKEN=changeme\nSECRET_KEY=<your-secret>\n");
    write(&r, "db/migration/V3__add_password_reset_token.sql", "ALTER TABLE users ADD COLUMN reset_token TEXT;\n");
    write(&r, "scripts/rebuild.sh", "#!/bin/bash\nKC_PASSWORD=\"$ADMIN_PW\"\npsql -c \"ALTER USER app PASSWORD '$APP_PW'\"\nkc config credentials --password \"$KC_PW\"\n");
    git(&r, &["add", "-f", "--", ".gitignore", ".env.example", "db", "scripts"]);
    git(&r, &["commit", "-q", "-m", "t"]);
    let (_, out, _) = aix(&r, &["ignore-check"]);
    assert!(out.contains("0 finding(s)"), "{out}");
    let (_, out, _) = aix(&r, &["code", "scripts/rebuild.sh"]);
    assert!(out.contains("'$APP_PW'") && out.contains("\"$KC_PW\""), "{out}");
    // a template holding a real-looking value is still a finding
    write(&r, ".env.sample", "DB_PASSWORD=Xk29vLq8mZ\n");
    git(&r, &["add", "-f", "--", ".env.sample"]);
    git(&r, &["commit", "-q", "-m", "s"]);
    let (_, out, _) = aix(&r, &["ignore-check"]);
    assert!(out.contains(".env.sample") && !out.contains(".env.example"), "{out}");
}

#[test]
fn misses_suggest_the_nearest_endpoint_and_file() {
    let api = "import javax.ws.rs.*;\n\n@Path(\"/api/orders/fulfillment\")\npublic class FulfillmentResource {\n    @POST\n    @Path(\"/fulfill\")\n    public void fulfillAll() { }\n}\n";
    let (_d, r) = repo(&[("src/FulfillmentResource.java", api), ("web/OrderSubmission.tsx", "export function OrderSubmission() { return null; }\n")]);
    let (c, out, _) = aix(&r, &["endpoint", "/api/orders/fulfill"]);
    assert_eq!(c, 1, "{out}");
    assert!(out.contains("did you mean: POST /api/orders/fulfillment/fulfill"), "{out}");
    let (_, out, _) = aix(&r, &["outline", "web/OrderSubmision.tsx"]);
    assert!(out.contains("did you mean: web/OrderSubmission.tsx"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "zzzq"]);
    assert!(!out.contains("did you mean"), "{out}");
}

#[test]
fn fk_on_delete_cascade_makes_the_parent_delete_a_writer() {
    let sql = "CREATE TABLE bills (id BIGINT PRIMARY KEY, note TEXT);\nCREATE TABLE payments (\n    id BIGINT PRIMARY KEY,\n    bill_id BIGINT NOT NULL REFERENCES bills(id) ON DELETE CASCADE,\n    memo_id BIGINT REFERENCES memos(id),\n    amount NUMERIC\n);\nCREATE TABLE memos (id BIGINT PRIMARY KEY);\n";
    let bill = "package a;\nimport jakarta.persistence.*;\nimport io.quarkus.hibernate.orm.panache.PanacheEntityBase;\n@Entity\n@Table(name = \"bills\")\npublic class Bill extends PanacheEntityBase {\n    @Id public Long id;\n    public String note;\n}\n";
    let pay = "package a;\nimport jakarta.persistence.*;\nimport io.quarkus.hibernate.orm.panache.PanacheEntityBase;\n@Entity\n@Table(name = \"payments\")\npublic class Payment extends PanacheEntityBase {\n    @Id public Long id;\n    public Long billId;\n}\n";
    let res = "package a;\nimport javax.ws.rs.*;\n@Path(\"/api/bills\")\npublic class BillResource {\n    @DELETE\n    @Path(\"/{id}\")\n    public void deleteBill(@PathParam(\"id\") long id) {\n        Bill.deleteById(id);\n    }\n}\n";
    let (_d, r) = repo(&[("db/migration/V1__init.sql", sql), ("src/main/java/a/Bill.java", bill), ("src/main/java/a/Payment.java", pay), ("src/main/java/a/BillResource.java", res)]);
    let (_, out, _) = aix(&r, &["table", "payments"]);
    assert!(out.contains("fk bill_id -> bills(id) on delete cascade"), "{out}");
    assert!(out.contains("fk memo_id -> memos(id)  "), "the next column's clause is not this fk's: {out}");
    assert!(out.contains("via fk cascade from bills"), "{out}");
    let (_, out2, _) = aix(&r, &["trace", "table:payments", "--up"]);
    assert!(out.contains("DELETE /api/bills/{}") && out.contains("via fk cascade from bills (BillResource.deleteBill)"), "{out}");
    assert!(out2.contains("fk cascade from bills"), "{out2}");
}

#[test]
fn history_of_a_directory_and_put_as_the_last_stage() {
    let (_d, r) = repo(&[("svc/a.ts", "export const a = 1;\n"), ("svc/b.ts", "export const b = 1;\n"), ("other/c.ts", "export const c = 1;\n")]);
    write(&r, "svc/a.ts", "export const a = 2;\n");
    git(&r, &["commit", "-qam", "fix: a in svc"]);
    write(&r, "other/c.ts", "export const c = 2;\n");
    git(&r, &["commit", "-qam", "c only"]);
    aix(&r, &["update"]);
    let (c, out, _) = aix(&r, &["history", "svc"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("svc/ (directory): 2 commits") && out.contains("fix: a in svc") && !out.contains("c only"), "{out}");
    let (c, out, _) = aix(&r, &["files svc/* --bare | put svcfiles ; grep -c ts @svcfiles"]);
    assert_eq!(c, 0, "{out}");
    assert!(out.contains("stored @svcfiles") && out.contains("@svcfiles:2"), "{out}");
    let (c, out, _) = aix(&r, &["files svc/* --bare | put x | count"]);
    assert_eq!(c, 2, "{out}");
}

#[test]
fn small_ux_fixes_find_filter_howto_braces_scope_count_by() {
    let api = "import javax.ws.rs.*;\nimport jakarta.annotation.security.RolesAllowed;\n@Path(\"/api/fees\")\npublic class FeeResource {\n    @GET\n    @RolesAllowed({\"admin\", \"clerk\"})\n    public String list() { return \"\"; }\n    @POST\n    @RolesAllowed({\"admin\"})\n    public void add() { }\n    @DELETE\n    @Path(\"/{id}\")\n    @RolesAllowed({\"admin\", \"clerk\"})\n    public void drop(@PathParam(\"id\") long id) { }\n    public boolean referenceExistsInYear(String r) { return false; }\n}\n";
    let (_d, r) = repo(&[("src/FeeResource.java", api), ("conf/a.yaml", "a: 1\n"), ("conf/b.yml", "b: 1\n"), ("conf/c.json", "{}\n"), ("e2e/x.ts", "foo\n")]);
    let (_, out, _) = aix(&r, &["find", "referenceExistsInYear"]);
    assert!(out.contains("[symbol] src/FeeResource.java:15"), "{out}");
    let (_, out, _) = aix(&r, &["files", "conf/*.{yaml,yml}", "--count"]);
    assert!(out.starts_with("2 "), "{out}");
    let (_, out, _) = aix(&r, &["howto", "save a list and reuse it"]);
    assert!(out.contains("aix put"), "{out}");
    let (_, out, _) = aix(&r, &["grep", "--glob", "*.spec.*", "foo", "e2e"]);
    assert!(out.contains("the scope matched no indexed file"), "{out}");
    let (_, out, _) = aix(&r, &["files conf/* --bare | filter -i A.YAML"]);
    assert!(out.contains("conf/a.yaml") && !out.contains("b.yml"), "{out}");
    let (_, out, _) = aix(&r, &["endpoint", "/api/fees", "--count-by", "role"]);
    assert!(out.contains("3  admin  (2 writes)") && out.contains("2  clerk  (1 write)"), "{out}");
    let (c, out, _) = aix(&r, &["endpoint", "/api/fees", "--count-by", "file"]);
    assert_eq!(c, 2, "{out}");
}

#[test]
fn a_filtered_out_symbol_is_not_called_unknown() {
    let (_d, r) = repo(&[("src/svc.ts", "export function approve(x: number) { return x; }\nexport function run() { return approve(1); }\n")]);
    let (_, out, _) = aix(&r, &["callers", "approve", "--only", "test"]);
    assert!(out.contains("none in the selected rows (the symbol exists"), "{out}");
    let (_, out, _) = aix(&r, &["callers", "nosuchthing", "--only", "test"]);
    assert!(out.contains("index has no symbol"), "{out}");
}
