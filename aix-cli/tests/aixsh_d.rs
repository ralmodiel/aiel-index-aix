//! Hook steering + measurement (builder D): table-driven cases from real agent commands (paths renamed to a
//! fixture), deny-with-answer byte-identity against the real tools, never-deny guarantees, the event log and
//! `stats --hooks`, and `hook classify`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

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

fn write(r: &Path, p: &str, t: &str) {
    let f = r.join(p);
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(f, t).unwrap();
}

/// A repo shaped like the evidence (Java backend, TS frontend, scripts, e2e, docs) with an ignored node_modules and a
/// large saved log under an ignored .scratch.
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    let java = |n: usize| {
        let mut s = String::from("package io.acme.shop.api;\n\n");
        for i in 3..=n {
            s.push_str(&if i % 50 == 0 { format!("    // line {i} teacher record StudentRosterDto @GET @Path\n") } else { format!("    int v{i} = {i};\n") });
        }
        s
    };
    write(&r, "backend/src/main/java/io/acme/shop/api/StudentResource.java", &java(900));
    write(&r, "backend/src/main/java/io/acme/shop/api/FeesResource.java", &java(700));
    write(&r, "backend/src/main/java/io/acme/shop/service/OrderFinalizationService.java", &java(400));
    let mut api = String::new();
    for i in 1..=2600 {
        api.push_str(&if i % 100 == 0 { format!("export const a{i} = () => fetch('/api/x{i}'); // guardiansOf useAuth\n") } else { format!("const k{i} = {i};\n") });
    }
    write(&r, "frontend/src/lib/api.ts", &api);
    write(&r, "frontend/src/pages/Dashboard.tsx", "import { useAuth } from '../lib/api';\nexport function Dashboard() {\n  const pendingCount = 1;\n  return null;\n}\n");
    write(&r, "frontend/src/pages/OrderFees.tsx", "export function OrderFees() {\n  async function recordPayment() {}\n  // Quick fill\n  return null;\n}\n");
    write(&r, "frontend/src/pages/parent/ParentAlerts.tsx", "function Switch() {\n  return null;\n}\n");
    write(&r, "frontend/vite.config.ts", "export default {\n  server: { proxy: {} },\n};\n");
    write(&r, "frontend/src/index.css", ".bottom-bar { color: red; }\n");
    write(&r, "scripts/api.sh", "#!/bin/sh\n# Calls the API.\ncurl \"$@\"\n");
    write(&r, "scripts/regress/d52-grades.py", "# grades regress\nprint('ok')\n");
    write(&r, "e2e/sim/run-sim.mjs", "async function step() {\n  return 1;\n}\n");
    write(&r, "TASKS.md", "# Tasks\n- [ ] DECISION one\n- [x] DECISION two\n");
    write(&r, "docs/guide.md", "# Guide\nSome text.\n");
    write(&r, ".gitignore", "node_modules/\n.scratch/\n");
    write(&r, "frontend/node_modules/x/index.js", "useAuth\n");
    let mut log = String::new();
    for i in 0..2000 {
        log.push_str(&format!("2026-10-24 INFO line {i} ERROR maybe\n"));
    }
    write(&r, ".scratch/fin.log", &log);
    // edge cases for byte identity: no final newline, CRLF, unicode, blank lines, one line
    let mut a = String::new();
    for i in 1..=40 {
        a.push_str(&format!("line {i} of a\n"));
    }
    write(&r, "src/edge/a.ts", &a);
    write(&r, "src/edge/nonl.ts", "one\ntwo\nthree");
    write(&r, "src/edge/crlf.ts", "alpha\r\nbeta\r\ngamma\r\n");
    write(&r, "src/edge/uni.ts", "héllo wörld\n\n\nçà va 🎉\nend\n");
    write(&r, "src/edge/one.ts", "single\n");
    write(&r, "src/edge/secret.ts", "const k = 'AKIAABCDEFGHIJKLMNOP';\nconst ok = 1;\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    let o = aix(&r, &["update", "--quiet"], None, &[]);
    assert!(o.status.success(), "update: {}", String::from_utf8_lossy(&o.stderr));
    (d, r)
}

fn aix(repo: &Path, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo.parent().unwrap()).env_remove("AIX_HOOK").env_remove("AIX_HOOK_DENY").env_remove("AIX_HOOK_DENY_GREP");
    for (k, v) in env {
        c.env(k, v);
    }
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    {
        use std::io::Write;
        let mut i = ch.stdin.take().unwrap();
        i.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
    }
    ch.wait_with_output().unwrap()
}

/// (cwd under the repo, command as an agent typed it, class, intent, the aix line or the silent reason). `/R` is the
/// repo's absolute path. Real shapes from the transcript evidence with paths renamed; the expected lines were
/// reviewed by hand (exact flag semantics, the file's real tail, silence outside the index).
const CASES: &[(&str, &str, &str, &str, &str)] = &[
    (".", "grep -n \"teacher\" backend/src/main/java/io/acme/shop/api/StudentResource.java | head -30", "miss", "bash:grep|head", "aix grep teacher backend/src/main/java/io/acme/shop/api/StudentResource.java --head 30"),
    ("backend/src/main/java", "grep -n \"teacher\" io/acme/shop/api/StudentResource.java | head -30", "miss", "bash:grep|head", "aix grep teacher io/acme/shop/api/StudentResource.java --head 30"),
    (".", "grep -n \"bottom-bar\" /R/frontend/src/index.css | head -3", "miss", "bash:grep|head", "aix grep bottom-bar frontend/src/index.css --head 3"),
    ("backend/src/main/java/io/acme/shop", "sed -n 316,319p service/OrderFinalizationService.java", "miss", "bash:sed-range", "aix code service/OrderFinalizationService.java:316-319"),
    (".", "sed -n 120,160p backend/src/main/java/io/acme/shop/api/StudentResource.java", "miss", "bash:sed-range", "aix code backend/src/main/java/io/acme/shop/api/StudentResource.java:120-160"),
    (".", "grep -n \"proxy\" -A8 /R/frontend/vite.config.ts | head -20", "miss", "bash:grep|head", "aix grep -A 8 proxy frontend/vite.config.ts --head 20"),
    ("backend/src/main/java/io/acme/shop", "grep -n \"record StudentRosterDto\" -A30 service/OrderFinalizationService.java | head -60", "miss", "bash:grep|head", "aix grep -A 30 'record StudentRosterDto' service/OrderFinalizationService.java --head 60"),
    ("frontend/src", "sed -n 2150,2260p lib/api.ts | cut -c1-260", "miss", "bash:sed-range", "aix code lib/api.ts:2150-2260 --width 260"),
    (".", "sed -n 780,830p backend/src/main/java/io/acme/shop/api/StudentResource.java | cut -c1-220", "miss", "bash:sed-range", "aix code backend/src/main/java/io/acme/shop/api/StudentResource.java:780-830 --width 220"),
    (".", "ls frontend/src/pages/parent | head -30", "miss", "bash:ls", "aix ls frontend/src/pages/parent --head 30"),
    ("frontend/src", "ls pages/parent | head -30", "miss", "bash:ls", "aix ls pages/parent --head 30"),
    ("frontend", "grep -n \"guardiansOf\" src/lib/api.ts", "miss", "bash:grep", "aix grep guardiansOf src/lib/api.ts"),
    (".", "grep -n \"pendingCount\\|canSeeRecheck\\|useTodayQueue\" frontend/src/pages/Dashboard.tsx", "miss", "bash:grep", "aix grep 'pendingCount|canSeeRecheck|useTodayQueue' frontend/src/pages/Dashboard.tsx"),
    (".", "ls e2e", "miss", "bash:ls", "aix ls e2e"),
    (".", "ls /R/frontend/node_modules/x", "silent", "bash:ls", "not-indexed"),
    ("frontend/src", "grep -rln \"useAuth\\|Start here\" pages lib --include=*.ts --include=*.tsx 2>/dev/null", "miss", "bash:grep-r", "aix grep -l --include '*.ts' --include '*.tsx' 'useAuth|Start here' pages lib"),
    ("frontend/src", "grep -rln \"resolutionNotes\" pages lib | head", "miss", "bash:grep-r|head", "aix grep -l resolutionNotes pages lib --head 10"),
    (".", "cat scripts/api.sh | head -12", "miss", "bash:cat|head", "aix code scripts/api.sh:1-3"),
    (".", "grep -n \"interface StudentRosterDto\" -A14 frontend/src/lib/api.ts", "miss", "bash:grep", "aix grep -A 14 'interface StudentRosterDto' frontend/src/lib/api.ts"),
    ("frontend/src", "cat pages/Dashboard.tsx pages/OrderFees.tsx", "miss", "bash:cat", "aix cat pages/Dashboard.tsx pages/OrderFees.tsx"),
    (".", "ls frontend/src/lib | grep -i \"grade\\|standard\"", "miss", "bash:ls|filter", "aix ls frontend/src/lib --bare | grep -i 'grade\\|standard'"),
    (".", "ls frontend/src/pages | grep -i -E \"regist|enrol\"", "miss", "bash:ls|filter", "aix ls frontend/src/pages --bare | grep -i -E 'regist|enrol'"),
    (".", "wc -l frontend/src/pages/{Dashboard,OrderFees}.tsx", "miss", "bash:wc-l", "aix files frontend/src/pages/{Dashboard,OrderFees}.tsx"),
    (".", "wc -l frontend/src/pages/$f.tsx", "silent", "bash:wc-l", "var"),
    (".", "sed -n 110,135p frontend/src/lib/api.ts | head -5", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:110-135 --head 5"),
    (".", "sed -n 1,50p /R/backend/src/main/java/io/acme/shop/api/FeesResource.java | head -5", "miss", "bash:sed-range", "aix code backend/src/main/java/io/acme/shop/api/FeesResource.java:1-50 --head 5"),
    ("frontend/src", "grep -n \"needsMeasure\\|missing\" pages/Dashboard.tsx | cut -c1-220", "miss", "bash:grep|cut-c", "aix grep 'needsMeasure|missing' pages/Dashboard.tsx --width 220"),
    (".", "grep -n \"@GET\\|@POST\" $f | cut -c1-200 | head -60", "silent", "bash:grep", "var"),
    ("backend/src/main/java/io/acme/shop/api", "grep -nE \"RolesAllowed|@(GET|POST|PUT|DELETE)|@Path\" FeesResource.java", "miss", "bash:grep", "aix grep 'RolesAllowed|@(GET|POST|PUT|DELETE)|@Path' FeesResource.java"),
    ("frontend/src", "grep -rn \"TestPaperUpload\\|papers\" pages --include=*.tsx | grep -v \"^pages/teacher\" | head", "miss", "bash:grep-r|grep-v|head", "aix grep --include '*.tsx' 'TestPaperUpload|papers' pages --not '^pages/teacher' --head 10"),
    (".", "grep -rn \"schoolRealmUserId\" backend/src/main/java | head -3 | cut -c1-140", "miss", "bash:grep-r|head", "aix grep schoolRealmUserId backend/src/main/java --head 3 --width 140"),
    (".", "grep -n 'api/' scripts/api.sh | head -20 | cut -c1-200", "miss", "bash:grep|head", "aix grep api/ scripts/api.sh --head 20 --width 200"),
    (".", "head -6 scripts/regress/d52-grades.py 2>/dev/null", "miss", "bash:head", "aix code scripts/regress/d52-grades.py:1-2"),
    (".", "grep -n \"path=\" frontend/src/lib/api.ts | grep -iE \"attend|grad\" | head -30", "miss", "bash:grep", "aix grep path= frontend/src/lib/api.ts --bare | grep -iE 'attend|grad' | head -30"),
    (".", "grep -rn \"\\.type\" backend/src/main/java --include=*.java | grep -i \"checklist\" | head", "miss", "bash:grep-r", "aix grep --include '*.java' '\\.type' backend/src/main/java --bare | grep -i checklist | head"),
    (".", "sed -n 5,25p frontend/src/lib/api.ts | grep -n \"useAuth\"", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:5-25 --bare | grep -n useAuth"),
    (".", "grep -c 'useAuth' frontend/src/lib/api.ts", "miss", "bash:grep", "aix grep -c useAuth frontend/src/lib/api.ts"),
    (".", "grep -n \"isEnded\\|active\" frontend/src/pages/Dashboard.tsx | sed -n 1,40p", "miss", "bash:grep", "aix grep 'isEnded|active' frontend/src/pages/Dashboard.tsx --bare | sed -n 1,40p"),
    (".", "grep -rln \"parent/dashboard\\|absence\" e2e --include=*.ts --exclude-dir=node_modules", "miss", "bash:grep-r", "aix grep -l --include '*.ts' 'parent/dashboard|absence' e2e"),
    (".", "grep -rn \"input-lock\\|inputLock\" backend/src/main/java -l", "miss", "bash:grep-r", "aix grep -l 'input-lock|inputLock' backend/src/main/java"),
    (".", "grep -rl -i \"book\" e2e --include=*.mjs -r 2>/dev/null | grep -v node_modules | head", "miss", "bash:grep-r", "aix grep -i -l --include '*.mjs' book e2e --bare | grep -v node_modules | head"),
    (".", "grep -n \"feeItem\" -A25 frontend/src/pages/OrderFees.tsx | sed -n 1,40p", "miss", "bash:grep", "aix grep -A 25 feeItem frontend/src/pages/OrderFees.tsx --bare | sed -n 1,40p"),
    (".", "ls scripts/regress | wc -l", "miss", "bash:ls|wc-l", "aix 'ls scripts/regress | count'"),
    (".", "find backend/src/main -name \"*Finaliz*\" 2>/dev/null", "miss", "bash:find", "aix files backend/src/main -name '*Finaliz*'"),
    (".", "find . -name \"*.py\" -not -path \"*/node_modules/*\" -not -path \"./.scratch/*\" | head -8", "miss", "bash:find", "aix files -name '*.py' -not -path '*/node_modules/*' -not -path './.scratch/*' --head 8"),
    (".", "cat frontend/src/pages/Dashboard.tsx | sed -n 1,60p", "miss", "bash:cat|sed-range", "aix code frontend/src/pages/Dashboard.tsx:1-5"),
    (".", "grep -rn \"Save changes\" frontend/src --include=*.tsx | wc -l", "miss", "bash:grep-r|wc-l", "aix grep --include '*.tsx' -c --total 'Save changes' frontend/src"),
    (".", "rg -n 'useAuth' frontend/src | wc -l", "miss", "bash:grep-r|wc-l", "aix grep -c --total useAuth frontend/src"),
    (".", "grep -n \"Quick fill\" -B6 -A3 frontend/src/pages/OrderFees.tsx | cut -c1-260", "miss", "bash:grep|cut-c", "aix grep -B 6 -A 3 'Quick fill' frontend/src/pages/OrderFees.tsx --width 260"),
    (".", "grep -n \"function Switch\" -A18 frontend/src/pages/parent/ParentAlerts.tsx | cut -c1-240", "miss", "bash:grep|cut-c", "aix grep -A 18 'function Switch' frontend/src/pages/parent/ParentAlerts.tsx --width 240"),
    (".", "grep -rn \"PromotionGuard\\.\" backend/src/main --include=*.java | grep -v \"^backend/src/main/java/io/acme/shop/service/PromotionGuard\" | cut -c1-200", "miss", "bash:grep-r|grep-v|cut-c", "aix grep --include '*.java' 'PromotionGuard\\.' backend/src/main --not '^backend/src/main/java/io/acme/shop/service/PromotionGuard' --width 200"),
    (".", "grep -n \"function Switch\" -A45 frontend/src/pages/parent/ParentAlerts.tsx | cut -c1-240", "miss", "bash:grep|cut-c", "aix grep -A 45 'function Switch' frontend/src/pages/parent/ParentAlerts.tsx --width 240"),
    (".", "tail -3 /R/.scratch/fin.log", "silent", "bash:tail", "log"),
    (".", "grep -n \"notification_preferences\" backend/src/main/resources/db/migration/*.sql | grep -i \"foreign\"", "silent", "bash:grep", "not-indexed"),
    (".", "grep -n \"async function recordPayment\\|const recordPayment\" -A160 frontend/src/pages/OrderFees.tsx | cut -c1-300 | head -110", "silent", "bash:grep", "flag:context>120"),
    (".", "find frontend/src/pages -name '*.tsx' | wc -l", "miss", "bash:find|wc-l", "aix 'files frontend/src/pages -name \"*.tsx\" | count'"),
    (".", "grep -rln 'useAuth' --include=*.tsx . | wc -l", "miss", "bash:grep-r|wc-l", "aix 'grep -l --include \"*.tsx\" useAuth | count'"),
    (".", "grep -rln \"useAuth\" frontend/src | wc -l", "miss", "bash:grep-r|wc-l", "aix 'grep -l useAuth frontend/src | count'"),
    (".", "wc -l frontend/src/pages/*.tsx 2>/dev/null | tail -25", "miss", "bash:wc-l", "aix files frontend/src/pages/*.tsx --bare | tail -25"),
    (".", "cat frontend/src/pages/OrderFees.tsx | cut -c1-240", "miss", "bash:cat", "aix cat frontend/src/pages/OrderFees.tsx --width 240"),
    (".", "grep -rn \"requireNotClosed\" . | grep -v \"YearWritePolicy.requireNotClosed\"", "miss", "bash:grep-r|grep-v", "aix grep requireNotClosed --not YearWritePolicy.requireNotClosed"),
    (".", "grep -n \"persistBatch\" -r backend/src/main | grep -v \"abstract\"", "miss", "bash:grep-r|grep-v", "aix grep persistBatch backend/src/main --not abstract"),
    (".", "grep -n -o 'f\"/api/[^\"]*\"' scripts/regress/d52-grades.py | sort -u | head", "miss", "bash:grep", "aix grep -o 'f\"/api/[^\"]*\"' scripts/regress/d52-grades.py --bare | sort -u | head"),
    (".", "grep -oE \"\\b[a-zA-Z]+Api\\.[a-zA-Z]+\" frontend/src/pages/*.tsx | sort -u | head", "miss", "bash:grep", "aix grep -o '\\b[a-zA-Z]+Api\\.[a-zA-Z]+' frontend/src/pages/*.tsx --bare | sort -u | head"),
    (".", "grep -n \"DECISION\" TASKS.md | grep -v \"\\[x\\]\" | wc -l", "miss", "bash:grep|grep-v", "aix grep DECISION TASKS.md --not '\\[x\\]' --bare | wc -l"),
    (".", "sed -n \"${a},${b}p\" $f | cut -c1-150", "silent", "bash:sed-range", "sed-script"),
    (".", "sed -n '/def r2/,/^def r[^2]/p' scripts/regress/d52-grades.py | head -80", "silent", "bash:sed-pattern", "no-counterpart"),
    (".", "[ -f frontend/src/pages/Dashboard.tsx ]", "miss", "bash:test-f", "aix files frontend/src/pages/Dashboard.tsx --exists"),
    (".", "test -f frontend/src/lib/api.ts && echo yes", "miss", "bash:test-f", "aix files frontend/src/lib/api.ts --exists"),
    (".", "python3 -c \"import json;print(1)\"", "other", "", ""),
    (".", "grep -n \"feesApi\\.\\w*\" -o frontend/src/pages/OrderFees.tsx | sort | uniq -c | sort -rn | head -30", "miss", "bash:grep|sort|uniq-c|head", "aix grep 'feesApi\\.\\w*' frontend/src/pages/OrderFees.tsx --count-by match --head 30"),
    (".", "grep -rho 'useAuth' frontend/src | sort | uniq -c | sort -rn", "miss", "bash:grep-r|sort|uniq-c", "aix grep -h useAuth frontend/src --count-by match"),
    (".", "grep -rh useAuth frontend/src | awk '!seen[$0]++'", "miss", "bash:grep-r|awk-seen", "aix grep -h useAuth frontend/src --dedup"),
    (".", "grep -rh useAuth frontend/src | sort -u", "miss", "bash:grep-r|sort-u", "aix grep -h useAuth frontend/src --dedup"),
    (".", "grep -rh useAuth frontend/src | sort | uniq", "miss", "bash:grep-r|sort-u", "aix grep -h useAuth frontend/src --dedup"),
    (".", "grep -rh useAuth frontend/src | sort | uniq -c | sort -rn", "miss", "bash:grep-r|sort|uniq-c", "aix 'grep -h useAuth frontend/src | count by line'"),
    (".", "ls backend/src/main/java/io/acme/shop/api | tr '\\n' ' '", "miss", "bash:ls|filter", "aix ls backend/src/main/java/io/acme/shop/api --bare | tr '\\n' ' '"),
    (".", "grep -rn 'allFinalized' frontend/src e2e --include=*.ts --include=*.tsx --include=*.mjs -l | grep -v node_modules", "miss", "bash:grep-r", "aix grep -l --include '*.ts' --include '*.tsx' --include '*.mjs' allFinalized frontend/src e2e --bare | grep -v node_modules"),
    (".", "grep -rl \"useAuth\" frontend/src | xargs grep -n \"pendingCount\"", "miss", "bash:grep-r|xargs-grep", "aix 'grep -l useAuth frontend/src | grep pendingCount -'"),
    (".", "grep -rl \"useAuth\" frontend/src | xargs sed -n '1,3p'", "miss", "bash:grep-r|xargs-sed", "aix 'grep -l useAuth frontend/src | sed -n 1,3p -'"),
    (".", "grep -rl \"Switch\" frontend/src | xargs wc -l", "miss", "bash:grep-r|xargs-wc", "aix 'grep -l Switch frontend/src | files -'"),
    (".", "find frontend/src -name '*.tsx' | xargs grep -l \"useAuth\"", "miss", "bash:find|xargs-grep", "aix grep -l useAuth frontend/src --include '*.tsx'"),
    (".", "find frontend/src -name '*.tsx' -exec grep -n \"useAuth\" {} +", "miss", "bash:find|xargs-grep", "aix grep useAuth frontend/src --include '*.tsx'"),
    (".", "git grep -n useAuth -- frontend", "miss", "bash:git-grep-r", "aix grep useAuth frontend"),
    (".", "git ls-files frontend/src/pages | head", "miss", "bash:git-ls-files", "aix files frontend/src/pages --head 10"),
    (".", "rg --files frontend/src | grep -i fees", "miss", "bash:rg-files|filter", "aix files frontend/src --bare | grep -i fees"),
    (".", "grep -n \"teacher\" backend/src/main/java/io/acme/shop/api/StudentResource.java; sed -n 10,40p frontend/src/lib/api.ts; grep -rn guardiansOf frontend/src | head", "miss", "bash:grep+bash:sed-range+bash:grep-r|head", "aix 'grep teacher backend/src/main/java/io/acme/shop/api/StudentResource.java ; code frontend/src/lib/api.ts:10-40 ; grep guardiansOf frontend/src --head 10'"),
    (".", "cd frontend && grep -rn \"useAuth\" src/pages | head -5", "miss", "bash:grep-r|head", "aix grep useAuth src/pages --head 5"),
    (".", "cd /tmp && grep -rn \"useAuth\" . | head -5", "silent", "bash:grep-r", "outside-repo"),
    (".", "tail -n 20 backend/src/main/java/io/acme/shop/api/StudentResource.java", "miss", "bash:tail", "aix code backend/src/main/java/io/acme/shop/api/StudentResource.java:881-900"),
    (".", "tail -n +880 backend/src/main/java/io/acme/shop/api/StudentResource.java", "miss", "bash:tail", "aix code backend/src/main/java/io/acme/shop/api/StudentResource.java:880-900"),
    (".", "head -40 frontend/src/lib/api.ts", "miss", "bash:head", "aix code frontend/src/lib/api.ts:1-40"),
    (".", "head -n -10 frontend/src/pages/Dashboard.tsx", "silent", "bash:head", "empty-range"),
    (".", "tail -f /R/.scratch/fin.log", "silent", "bash:tail-f", "log"),
    (".", "sed -n '455p' frontend/src/lib/api.ts", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:455-455"),
    (".", "sed -n -e '10,20p' -e '30,35p' frontend/src/lib/api.ts", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:10-20 frontend/src/lib/api.ts:30-35"),
    (".", "sed -n '10,+5p' frontend/src/lib/api.ts", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:10-15"),
    (".", "sed -i 's/a/b/' frontend/src/lib/api.ts", "other", "", ""),
    (".", "sed -i '' 's/a/b/' frontend/src/lib/api.ts", "other", "", ""),
    (".", "sed -E -n '1,5p' frontend/src/lib/api.ts", "miss", "bash:sed-range", "aix code frontend/src/lib/api.ts:1-5"),
    (".", "cat frontend/src/pages/Dashboard.tsx > /tmp/x.tsx", "other", "", ""),
    (".", "grep -rnP 'use(?=Auth)' frontend/src", "silent", "bash:grep", "flag:-P"),
    (".", "grep -rn \"useAuth\" frontend/src --include=*.tsx -C 140", "silent", "bash:grep", "flag:context>120"),
    (".", "grep -rnw useAuth frontend/src -m 2 -h", "miss", "bash:grep-r", "aix grep -w -m 2 -h useAuth frontend/src"),
    (".", "grep -rnq useAuth frontend/src", "miss", "bash:grep-r-q", "aix grep useAuth frontend/src --exists"),
    (".", "grep -n useAuth frontend/src/pages/*.tsx", "miss", "bash:grep", "aix grep useAuth frontend/src/pages/*.tsx"),
    (".", "grep -rn 'a|b' frontend/src", "miss", "bash:grep-r", "aix grep 'a[|]b' frontend/src"),
    (".", "egrep -rn 'a|b' frontend/src", "miss", "bash:grep-r", "aix grep 'a|b' frontend/src"),
    (".", "fgrep -rn 'a.b' frontend/src", "miss", "bash:grep-r", "aix grep -F a.b frontend/src"),
    (".", "grep -rn -e foo -e bar frontend/src", "miss", "bash:grep-r", "aix grep '(?:foo)|(?:bar)' frontend/src"),
    (".", "grep -rn useAuth docs/missing", "silent", "bash:grep-r", "not-indexed"),
    (".", "grep -rn useAuth ~/.claude", "silent", "bash:grep-r", "outside-repo"),
    (".", "grep -n 'Weekly' /opt/other/.claude/projects/x/memory/MEMORY.md", "silent", "bash:grep", "outside-repo"),
    (".", "grep -n ERROR /R/.aix/refresh.log", "silent", "bash:grep", "log"),
    (".", "diff frontend/src/pages/Dashboard.tsx frontend/src/pages/OrderFees.tsx", "miss", "bash:diff", "aix diff frontend/src/pages/Dashboard.tsx frontend/src/pages/OrderFees.tsx"),
    (".", "stat -c '%s %n' frontend/src/lib/api.ts", "miss", "bash:stat", "aix files frontend/src/lib/api.ts"),
    (".", "stat -f '%z %N' frontend/src/lib/api.ts", "miss", "bash:stat", "aix files frontend/src/lib/api.ts"),
    (".", "cargo test 2>&1 | tail -30", "data", "data:cargo|filter", "cargo test 2>&1 | aix put cargo-test -"),
    (".", "./gradlew test 2>&1 | grep -E 'FAIL|ERROR'", "data", "data:gradlew|filter", "./gradlew test 2>&1 | aix put gradlew-test -"),
    (".", "npm run build 2>&1 | head -40", "data", "data:npm|filter", "npm run build 2>&1 | aix put npm-run-build -"),
    (".", "AIX_HOOK=off sed -n 1,5p frontend/src/lib/api.ts", "silent", "bash:sed-range", "bypass"),
    (".", "bash -c \"grep -rn useAuth frontend/src | head -3\"", "miss", "bash:grep-r|head", "aix grep useAuth frontend/src --head 3"),
    (".", "aix grep useAuth", "aix", "aix", ""),
    (".", "$A --repo . grep useAuth", "aix", "aix", ""),
    (".", "cd frontend && aix code src/lib/api.ts:1-20", "aix", "aix", ""),
    (".", "powershell -Command \"Select-String -Pattern 'useAuth' -Path frontend/src/lib/api.ts\"", "miss", "ps:sls", "aix grep -i useAuth frontend/src/lib/api.ts"),
    (".", "pwsh -c \"Select-String 'useAuth' frontend/src/lib/api.ts -CaseSensitive -Context 2,3\"", "miss", "ps:sls", "aix grep -B 2 -A 3 useAuth frontend/src/lib/api.ts"),
    (".", "pwsh -NoProfile -Command \"Get-Content frontend/src/lib/api.ts -TotalCount 40\"", "miss", "ps:gc", "aix code frontend/src/lib/api.ts:1-40"),
    (".", "pwsh -c \"Get-Content frontend/src/lib/api.ts -Tail 20\"", "miss", "ps:gc", "aix code frontend/src/lib/api.ts:2581-2600"),
    (".", "pwsh -c \"gc frontend/src/lib/api.ts | Select-Object -Skip 99 -First 20\"", "miss", "ps:gc", "aix code frontend/src/lib/api.ts:100-119"),
    (".", "pwsh -c \"Get-ChildItem -Path frontend/src -Recurse -Filter *.tsx\"", "miss", "ps:gci-r", "aix files frontend/src -name '*.tsx'"),
    (".", "pwsh -c \"gci frontend/src -Recurse -Include *.ts,*.tsx | Select-String 'useAuth'\"", "miss", "ps:gci|sls", "aix grep -i useAuth frontend/src --include '*.ts' --include '*.tsx'"),
    (".", "pwsh -c \"Get-ChildItem frontend/src -Recurse -Force\"", "silent", "ps:gci", "flag"),
    (".", "pwsh -c \"(Get-Content frontend/src/lib/api.ts | Measure-Object -Line).Lines\"", "other", "", ""),
    (".", "pwsh -c \"gc frontend/src/lib/api.ts | Measure-Object -Line\"", "miss", "ps:gc|measure", "aix files frontend/src/lib/api.ts"),
    (".", "pwsh -c \"Compare-Object (gc frontend/src/pages/Dashboard.tsx) (gc frontend/src/pages/OrderFees.tsx)\"", "miss", "ps:compare-object", "aix diff frontend/src/pages/Dashboard.tsx frontend/src/pages/OrderFees.tsx"),
    (".", "pwsh -c \"gc package.json | ConvertFrom-Json\"", "silent", "ps:gc", "not-indexed"),
    (".", "pwsh -c \"Select-String -Pattern 'useAuth' -Path frontend/src/lib/api.ts -Encoding utf8\"", "silent", "ps:sls", "flag"),
    (".", "cmd /c findstr /s /i useAuth *.tsx", "miss", "cmd:findstr", "aix grep -i --include '*.tsx' -F useAuth"),
    (".", "cmd /c findstr /s /n /c:\"Quick fill\" *.tsx", "miss", "cmd:findstr", "aix grep --include '*.tsx' -F 'Quick fill'"),
    (".", "cmd /c findstr /s \"useAuth Switch\" *.tsx", "miss", "cmd:findstr", "aix grep --include '*.tsx' 'useAuth|Switch'"),
    (".", "cmd /c findstr /s /r \"^import.*api\" *.tsx", "miss", "cmd:findstr", "aix grep --include '*.tsx' '^import.*api'"),
    (".", "cmd /c findstr /s \"a.b\" *.tsx", "silent", "cmd:findstr", "ambiguous"),
    (".", "cmd /c type frontend\\src\\pages\\Dashboard.tsx", "silent", "cmd:type", "not-indexed"),
    (".", "cmd /c dir /s /b *.tsx", "miss", "cmd:dir-s", "aix files -name '*.tsx'"),
    (".", "cmd /c dir /s *.tsx", "silent", "cmd:dir", "no-counterpart"),
    (".", "cmd /c find /c \"useAuth\" frontend\\src\\lib\\api.ts", "silent", "cmd:find", "not-indexed"),
    (".", "cmd /c fc frontend\\src\\pages\\Dashboard.tsx frontend\\src\\pages\\OrderFees.tsx", "silent", "cmd:fc", "not-indexed"),
    (".", "cmd /c where /r . *.mjs", "miss", "cmd:where", "aix files -name '*.mjs'"),
    (".", "cmd /c where git", "other", "", ""),
    (".", "cmd /c \"type frontend\\src\\pages\\Dashboard.tsx\"", "miss", "cmd:type", "aix cat frontend/src/pages/Dashboard.tsx"),
    (".", "cmd /c \"find /c \\\"useAuth\\\" frontend\\src\\lib\\api.ts\"", "miss", "cmd:find", "aix grep -c -F useAuth frontend/src/lib/api.ts"),
    (".", "cmd /c \"fc frontend\\src\\pages\\Dashboard.tsx frontend\\src\\pages\\OrderFees.tsx\"", "miss", "cmd:fc", "aix diff frontend/src/pages/Dashboard.tsx frontend/src/pages/OrderFees.tsx"),
    (".", "cat .gitignore", "silent", "bash:gitignore", "gitignore"),
    (".", "echo node_modules/ >> .gitignore", "silent", "bash:gitignore", "gitignore"),
    (".", "grep -n ERROR .scratch/fin.log | head", "data", "data:grep", "aix put fin /R/.scratch/fin.log"),
    (".", "grep -c ERROR .scratch/fin.log", "data", "data:grep", "aix put fin /R/.scratch/fin.log"),
];

fn classify_lines(r: &Path, events: &[Value]) -> Vec<Vec<String>> {
    let input: String = events.iter().map(|e| format!("{e}\n")).collect();
    let o = aix(r, &["hook", "classify"], Some(&input), &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.starts_with('#')).map(|l| l.split('\t').map(str::to_string).collect()).collect()
}

#[test]
fn table_of_real_command_shapes() {
    assert!(CASES.len() >= 80);
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    // a bash command spells the repo with '/' (an unquoted \ is an escape in Git Bash); the event's cwd stays native
    let rsh = rs.replace('\\', "/");
    let events: Vec<Value> = CASES
        .iter()
        .enumerate()
        .map(|(i, (cwd, cmd, ..))| json!({"ts": format!("c{i}"), "tool_name": "Bash", "tool_input": {"command": cmd.replace("/R/", &format!("{rsh}/"))}, "cwd": if *cwd == "." { rs.clone() } else { format!("{rs}/{cwd}") }}))
        .collect();
    let got = classify_lines(&r, &events);
    assert_eq!(got.len(), CASES.len());
    let mut bad = vec![];
    for ((cwd, cmd, class, intent, what), g) in CASES.iter().zip(&got) {
        let gw = g.get(4).cloned().unwrap_or_default().replace(&rs, "/R").replace(&rsh, "/R");
        if g[2] != *class || g[3] != *intent || gw != *what {
            bad.push(format!("[{cwd}] {cmd}\n   want {class} {intent} {what}\n   got  {} {} {gw}", g[2], g[3]));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), CASES.len(), bad.join("\n"));
}

/// Built-in tools: Grep / Glob / Read / PowerShell tool / Edit / Write.
#[test]
fn builtin_tools_table() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let cases: Vec<(Value, &str, &str)> = vec![
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "useAuth", "path": format!("{rs}/frontend/src")}}), "miss", "aix grep -l useAuth frontend/src"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "useAuth", "output_mode": "content", "-i": true, "-C": 2, "glob": "*.tsx"}}), "miss", "aix grep -i -C 2 --include '*.tsx' useAuth"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "useAuth", "output_mode": "count", "type": "ts", "head_limit": 5}}), "miss", "aix grep -c -t ts useAuth --head 5"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "a.b", "multiline": true}}), "silent", "flag:multiline"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "useAuth("}}), "silent", "bad-regex"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/etc"}}), "silent", "outside-repo"),
        (json!({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": format!("{rs}/frontend/node_modules")}}), "silent", "not-indexed"),
        (json!({"tool_name": "Glob", "tool_input": {"pattern": "frontend/src/**/*.tsx"}}), "miss", "aix files frontend/src -name '*.tsx'"),
        (json!({"tool_name": "Glob", "tool_input": {"pattern": "**/*.ts", "path": format!("{rs}/src")}}), "miss", "aix files src -name '*.ts'"),
        (json!({"tool_name": "Glob", "tool_input": {"pattern": "src/*/a.ts"}}), "silent", "glob-shape"),
        (json!({"tool_name": "Read", "tool_input": {"file_path": format!("{rs}/frontend/src/lib/api.ts")}}), "miss", "aix outline frontend/src/lib/api.ts"),
        (json!({"tool_name": "Read", "tool_input": {"file_path": format!("{rs}/frontend/src/lib/api.ts"), "offset": 10, "limit": 20}}), "silent", "range"),
        (json!({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}), "silent", "outside-repo"),
        (json!({"tool_name": "PowerShell", "tool_input": {"command": "Select-String -Pattern 'useAuth' -Path frontend/src/lib/api.ts"}}), "miss", "aix grep -i useAuth frontend/src/lib/api.ts"),
        (json!({"tool_name": "PowerShell", "tool_input": {"command": "Get-Content frontend\\src\\lib\\api.ts -Tail 20"}}), "miss", "aix code frontend/src/lib/api.ts:2581-2600"),
        (json!({"tool_name": "PowerShell", "tool_input": {"command": "Select-String \"it's\" frontend/src/lib/api.ts"}}), "miss", "aix grep -i 'it''s' frontend/src/lib/api.ts"),
        (json!({"tool_name": "Edit", "tool_input": {"file_path": format!("{rs}/frontend/src/lib/api.ts"), "old_string": "a", "new_string": "b"}}), "other", ""),
        (json!({"tool_name": "Write", "tool_input": {"file_path": format!("{rs}/x.ts"), "content": "x"}}), "other", ""),
    ];
    let events: Vec<Value> = cases
        .iter()
        .map(|(e, ..)| {
            let mut e = e.clone();
            e["cwd"] = json!(rs);
            e
        })
        .collect();
    let got = classify_lines(&r, &events);
    for ((e, class, what), g) in cases.iter().zip(&got) {
        assert_eq!((g[2].as_str(), g.get(4).map(String::as_str).unwrap_or("")), (*class, *what), "{e}");
    }
}

/// The scope additions: chained lookups -> ONE aix line with ` ; ` and ` | `; fan-outs -> the pipe form; data files
/// read twice and long command output piped into filters -> `aix put` once, then `@name`.
#[test]
fn combined_lines_fanouts_and_data_sets() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let ev = |c: &str| json!({"tool_name": "Bash", "tool_input": {"command": c}, "cwd": rs});
    let cases = [
        ("grep -n X frontend/src/pages/Dashboard.tsx; sed -n 10,40p frontend/src/lib/api.ts; grep -rn useAuth frontend/src | head", "miss", "aix 'grep X frontend/src/pages/Dashboard.tsx ; code frontend/src/lib/api.ts:10-40 ; grep useAuth frontend/src --head 10'"),
        ("grep -rl useAuth frontend/src | xargs sed -n '1,3p'", "miss", "aix 'grep -l useAuth frontend/src | sed -n 1,3p -'"),
        ("grep -rl useAuth frontend/src | xargs grep -n pendingCount", "miss", "aix 'grep -l useAuth frontend/src | grep pendingCount -'"),
        ("grep -rl \"it's\" frontend/src | xargs grep -n pendingCount", "miss", "aix grep -l 'it'\\''s' frontend/src --bare | aix grep pendingCount -"),
        ("sed -n 1,5p frontend/src/lib/api.ts && grep -n \"a b\" frontend/src/lib/api.ts", "miss", "aix 'code frontend/src/lib/api.ts:1-5 ; grep \"a b\" frontend/src/lib/api.ts'"),
        ("grep -n X frontend/src/pages/*.tsx; sed -n 1,2p TASKS.md", "miss", "aix grep X frontend/src/pages/*.tsx; aix code TASKS.md:1-2"),
        ("grep -n ERROR .scratch/fin.log | tail -5", "silent", "log"),
        ("grep -n ERROR .scratch/fin.log | head -5", "data", "aix put fin /R/.scratch/fin.log"),
        ("cargo test 2>&1 | grep -E 'FAILED|panicked'", "data", "cargo test 2>&1 | aix put cargo-test -"),
    ];
    let got = classify_lines(&r, &cases.iter().map(|c| ev(c.0)).collect::<Vec<_>>());
    for ((cmd, class, what), g) in cases.iter().zip(&got) {
        assert_eq!((g[2].as_str(), g.get(4).map(|s| s.replace(&rs, "/R").replace(&rs.replace('\\', "/"), "/R")).unwrap_or_default()), (*class, what.to_string()), "{cmd}");
    }
}

fn pretool(r: &Path, ev: &Value, env: &[(&str, &str)]) -> Option<Value> {
    let o = aix(r, &["hook", "pretool"], Some(&ev.to_string()), env);
    assert!(o.status.success());
    let s = String::from_utf8_lossy(&o.stdout).to_string();
    (!s.trim().is_empty()).then(|| serde_json::from_str(s.trim()).expect("hook stdout is one JSON object"))
}

fn bash_ev(r: &Path, sid: &str, cmd: &str) -> Value {
    json!({"session_id": sid, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": r.display().to_string()})
}

/// The text between the answer markers of a deny reason.
fn answer_of(out: &Value) -> Option<String> {
    let h = &out["hookSpecificOutput"];
    if h["permissionDecision"] != "deny" {
        return None;
    }
    let reason = h["permissionDecisionReason"].as_str()?;
    let (a, after) = reason.split_once("<<<aix-answer\n")?.1.split_once("aix-answer>>>")?;
    // the note after the closing marker says the line break before it is not part of the output
    Some(if after.starts_with("\n(the output ends without a newline") { a.strip_suffix('\n').unwrap_or(a).to_string() } else { a.to_string() })
}

fn real(r: &Path, cmd: &str) -> String {
    let o = Command::new("bash").arg("-c").arg(cmd).current_dir(r).output().unwrap();
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn deny_answers_are_byte_identical_to_the_real_tools() {
    let (_d, r) = fixture();
    let cmds = [
        "sed -n '10,20p' src/edge/a.ts",
        "sed -n 5p src/edge/a.ts",
        "sed -n '38,$p' src/edge/a.ts",
        "sed -n '30,+4p' src/edge/a.ts",
        "sed -n '20,10p' src/edge/a.ts",
        "sed -n -e '1,3p' -e '2,4p' src/edge/a.ts",
        "sed -n '1,2p;7p' src/edge/a.ts",
        "sed -n '1,5p;5q' src/edge/a.ts",
        "sed -n '35,99p' src/edge/a.ts",
        "sed -n '2,3p' src/edge/nonl.ts",
        "sed -n '3p;3p' src/edge/nonl.ts",
        "sed -n '$p' src/edge/nonl.ts",
        "sed -n '2,3p' src/edge/crlf.ts",
        "sed -E -n '1,4p' src/edge/uni.ts",
        "head -n 3 src/edge/a.ts",
        "head -5 src/edge/nonl.ts",
        "head src/edge/a.ts",
        "head -n 100 src/edge/one.ts",
        "tail -n 3 src/edge/a.ts",
        "tail -2 src/edge/nonl.ts",
        "tail src/edge/uni.ts",
        "tail -n +38 src/edge/a.ts",
        "tail -n 5 src/edge/crlf.ts",
        "cat src/edge/nonl.ts",
        "cat src/edge/crlf.ts src/edge/uni.ts",
        "cat src/edge/nonl.ts src/edge/one.ts",
        "head -n 2 src/edge/a.ts; echo ---; tail -n 2 src/edge/uni.ts",
        "sed -n 1,3p src/edge/a.ts && sed -n 1,2p src/edge/crlf.ts",
        "cat frontend/src/pages/Dashboard.tsx",
        // a `cd` into a repo directory, pure filters after a read, grep on files, a loop over literal files
        "cd src && cat edge/a.ts",
        "cd src/edge; sed -n 3,4p a.ts; head -n 1 one.ts",
        "head -n 30 src/edge/a.ts | grep -nE 'line [0-9]+ of' | tail -2",
        "sed -n 1,20p src/edge/a.ts | grep -c 'line 1' ",
        "cat src/edge/a.ts | grep -v line | wc -l",
        "grep -n 'line 1[0-5] ' src/edge/a.ts",
        "grep -c line src/edge/a.ts src/edge/one.ts",
        "sed -n 3,6p src/edge/a.ts | cut -c1-7",
        "sed -n 3,6p src/edge/a.ts | cut -c5-",
        "head -n 4 src/edge/a.ts | cut -c3",
        "grep -n 'line 1[0-5] ' src/edge/a.ts | cut -c -9 | head -2",
        "grep -ni 'LINE 3\\|line 7 ' src/edge/a.ts | head -1",
        "for f in src/edge/a.ts src/edge/one.ts; do echo \"== $f\"; head -n 2 $f; done",
    ];
    for (i, c) in cmds.iter().enumerate() {
        let out = pretool(&r, &bash_ev(&r, &format!("s{i}"), c), &[]).unwrap_or_else(|| panic!("no output for {c}"));
        let a = answer_of(&out).unwrap_or_else(|| panic!("not denied: {c}: {out}"));
        assert_eq!(a, real(&r, c), "answer differs from the real tool for `{c}`");
    }
}

#[test]
fn grep_and_glob_tool_answers_match_grep_and_find() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let deny = |input: Value| -> String {
        let mut ti = input.clone();
        ti.as_object_mut().unwrap().remove("_tool");
        let ev = json!({"session_id": format!("g{input}"), "tool_name": input["_tool"].as_str().unwrap_or("Grep"), "tool_input": ti, "cwd": rs});
        // Grep/Glob are answered by default
        // (the answer budget is lifted: under load a slow walk would nudge instead and the test would flake)
        let out = pretool(&r, &ev, &[("AIX_HOOK_DENY_MS", "60000")]).expect("output");
        let reason = out["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap_or("");
        // labelled as aix's answer, never as the tool's bytes
        assert!(reason.starts_with("Answered by aix") && !reason.contains("byte-identical"), "{reason}");
        answer_of(&out).unwrap_or_else(|| panic!("not denied: {out}"))
    };
    // AIX_HOOK_DENY_GREP=0: a nudge, never a deny
    let ev = json!({"session_id": "dflt", "tool_name": "Grep", "tool_input": {"pattern": "line [0-9]+ of", "path": format!("{rs}/src"), "output_mode": "content"}, "cwd": rs});
    assert!(pretool(&r, &ev, &[("AIX_HOOK_DENY_GREP", "0")]).is_some_and(|o| o["hookSpecificOutput"]["permissionDecision"].is_null()));
    // the rows, as paths relative to the cwd (as Grep prints them), without Grep's header and footer lines
    // (the reference is GNU grep/find; on Windows the Grep tool is ripgrep and Git Bash's grep strips CR, so there
    // only the deny itself is checked for the directory-wide rows)
    let sorted = |s: String| {
        let mut v: Vec<String> = s.lines().filter(|l| !l.is_empty() && !l.starts_with("Found ")).map(|l| l.strip_prefix(&format!("{rs}/")).unwrap_or(l).to_string()).collect();
        v.sort();
        if cfg!(windows) { vec![] } else { v }
    };
    // content, files, count: the same rows as GNU grep over the same directory
    let a = deny(json!({"pattern": "line [0-9]+ of", "path": format!("{rs}/src"), "output_mode": "content"}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("grep -rnE 'line [0-9]+ of' {rs}/src"))));
    let a = deny(json!({"pattern": "^[a-z]+\\r?$|É", "path": format!("{rs}/src/edge"), "output_mode": "content", "-i": true}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("grep -rniP '^[a-z]+\\r?$|É' {rs}/src/edge"))));
    // a matched line with a secret: the row is answered, its text redacted
    let a = deny(json!({"pattern": "const", "path": format!("{rs}/src/edge"), "output_mode": "content"}));
    assert!(a.contains("src/edge/secret.ts:1:") && a.contains("***") && a.contains("src/edge/secret.ts:2:const ok = 1"), "{a}");
    let a = deny(json!({"pattern": "e", "path": format!("{rs}/src")}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("grep -rlE 'e' {rs}/src"))));
    let a = deny(json!({"pattern": "e", "path": format!("{rs}/src"), "output_mode": "count"}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("grep -rcE 'e' {rs}/src | grep -v ':0$'"))));
    // context lines and group separators, one file
    let a = deny(json!({"pattern": "line (5|9|20) ", "path": format!("{rs}/src/edge/a.ts"), "output_mode": "content", "-C": 2}));
    assert_eq!(a, real(&r, "grep -HnE -C 2 'line (5|9|20) ' src/edge/a.ts"));
    let a = deny(json!({"pattern": "line 1[0-9] ", "path": format!("{rs}/src/edge/a.ts"), "output_mode": "content", "-n": false, "-A": 1}));
    assert_eq!(a, real(&r, "grep -HE -A 1 'line 1[0-9] ' src/edge/a.ts"));
    // a glob filter
    let a = deny(json!({"pattern": "useAuth", "path": format!("{rs}/frontend/src"), "glob": "*.tsx"}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("grep -rl --include='*.tsx' useAuth {rs}/frontend/src"))));
    // Glob: the same file set as find
    let a = deny(json!({"_tool": "Glob", "pattern": "src/**/*.ts"}));
    assert_eq!(sorted(a), sorted(real(&r, &format!("find {rs}/src -name '*.ts'"))));
}

#[test]
fn never_denied_reads_writes_side_effects_or_unproven_answers() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let f = format!("{rs}/src/edge/a.ts");
    let mut evs: Vec<Value> = vec![
        json!({"tool_name": "Read", "tool_input": {"file_path": f}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": format!("{rs}/frontend/src/lib/api.ts")}}),
        json!({"tool_name": "Edit", "tool_input": {"file_path": f, "old_string": "line 1", "new_string": "x"}}),
        json!({"tool_name": "Write", "tool_input": {"file_path": f, "content": "x"}}),
        json!({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": f, "new_source": "x"}}),
    ];
    for c in [
        "sed -i 's/a/b/' src/edge/a.ts",
        "sed -i '' 's/a/b/' src/edge/a.ts",
        "cat src/edge/a.ts > /dev/stdout2",
        "head -n 3 src/edge/a.ts | tee out.txt",
        "touch x; cat src/edge/a.ts",
        "cat src/edge/a.ts && git commit -qm x",
        "rm -f src/edge/a.ts; cat src/edge/one.ts",
        "sed -n 1,3p src/edge/a.ts || echo none",
        "cat src/edge/a.ts &",
        "FOO=1 cat src/edge/a.ts",
        "cat src/edge/secret.ts",
        "cat frontend/src/lib/api.ts",
        "cat /etc/hostname",
        "cat .scratch/fin.log",
        "AIX_HOOK=off cat src/edge/one.ts",
        "cat -n src/edge/one.ts",
        "cat src/edge/*.ts",
        "sed -n 1,3p $F",
        "grep -rn line src/edge",
        "grep -n zzz src/edge/a.ts && cat src/edge/one.ts",
        "grep -no line src/edge/a.ts",
        "cd /tmp && cat a.ts",
        "for f in src/edge/*.ts; do head -n 1 $f; done",
        "for f in a b; do rm $f; done",
    ] {
        evs.push(json!({"tool_name": "Bash", "tool_input": {"command": c}}));
    }
    for (i, mut e) in evs.into_iter().enumerate() {
        e["cwd"] = json!(rs);
        e["session_id"] = json!(format!("n{i}"));
        if let Some(out) = pretool(&r, &e, &[]) {
            assert_ne!(out["hookSpecificOutput"]["permissionDecision"], "deny", "{e} -> {out}");
            assert!(out["hookSpecificOutput"]["additionalContext"].is_string(), "{out}");
        }
    }
    // the switch, staleness, and repeat-to-bypass
    let c = "cat src/edge/one.ts";
    assert!(pretool(&r, &bash_ev(&r, "sw", c), &[("AIX_HOOK_DENY", "0")]).is_some_and(|o| o["hookSpecificOutput"]["permissionDecision"].is_null()));
    assert!(answer_of(&pretool(&r, &bash_ev(&r, "rep", c), &[]).unwrap()).is_some(), "first call is answered");
    assert!(pretool(&r, &bash_ev(&r, "rep", c), &[]).is_none(), "the identical call right after a denial runs");
    std::thread::sleep(std::time::Duration::from_millis(20));
    write(&r, "src/edge/one.ts", "changed\n");
    let o = pretool(&r, &bash_ev(&r, "stale", c), &[]);
    assert!(o.as_ref().is_some_and(|o| o["hookSpecificOutput"]["permissionDecision"].is_null()), "stale file: nudge only: {o:?}");
}

#[test]
fn event_log_and_stats() {
    let (_d, r) = fixture();
    let _ = pretool(&r, &bash_ev(&r, "a", "sed -n 1,3p src/edge/a.ts"), &[]);
    let _ = pretool(&r, &bash_ev(&r, "a", "grep -rn useAuth frontend/src | wc -l"), &[]);
    let _ = pretool(&r, &bash_ev(&r, "a", "grep -rn useAuth frontend/src | wc -l"), &[]); // throttled
    let _ = pretool(&r, &bash_ev(&r, "a", "grep -n 'password=hunter2secret' /etc/x"), &[]);
    let _ = pretool(&r, &bash_ev(&r, "a", "aix grep useAuth"), &[]);
    let log = std::fs::read_to_string(r.join(".aix/hook-events.jsonl")).unwrap();
    let rows: Vec<Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let dec: Vec<&str> = rows.iter().map(|r| r["decision"].as_str().unwrap()).collect();
    assert_eq!(dec, ["deny", "nudge", "silent", "silent", "aix"], "{log}");
    assert_eq!(rows[2]["reason"], "throttled");
    assert_eq!(rows[3]["reason"], "outside-repo");
    assert!(!log.contains("hunter2secret"), "commands are redacted in the log: {log}");
    let o = aix(&r, &["stats", "--hooks", "--since", "1h"], None, &[]);
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("5 decisions: 1 nudged, 1 answered (deny), 2 silent, 1 aix calls") && s.contains("bash:grep-r|wc-l"), "{s}");
}

#[test]
fn classify_reads_claude_code_transcripts() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let t = [
        json!({"type": "assistant", "cwd": rs, "timestamp": "t1", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "grep -rn useAuth frontend/src"}}]}}),
        json!({"type": "assistant", "cwd": rs, "timestamp": "t2", "message": {"content": [{"type": "text", "text": "x"}, {"type": "tool_use", "name": "Bash", "input": {"command": "aix grep useAuth"}}]}}),
        json!({"type": "assistant", "cwd": rs, "timestamp": "t3", "message": {"content": [{"type": "tool_use", "name": "mcp__aix__aix", "input": {"command": "grep"}}]}}),
        json!({"type": "user", "message": {"content": [{"type": "tool_result", "content": "..."}]}}),
    ];
    let input: String = t.iter().map(|e| format!("{e}\n")).collect();
    let o = aix(&r, &["hook", "classify", "--summary"], Some(&input), &[]);
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(s.contains("miss 1, aix 2") && s.contains("rate 33.3%"), "{s}");
}

/// Every suggestion the TABLE produces is real syntax after the merge: run it on the fixture (from the case's cwd);
/// it exits 0 (found) or 1 (none), never 2 (usage).
#[test]
fn table_suggestions_are_runnable() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let bin = env!("CARGO_BIN_EXE_aix");
    let mut bad = vec![];
    for (cwd, _, class, _, what) in CASES {
        if *class != "miss" || !what.starts_with("aix ") {
            continue;
        }
        let dir = if *cwd == "." { r.clone() } else { r.join(cwd) };
        // the aix part only (a trailing `| sort -u | head` is the shell's); a quoted pipe is one aix argument
        let mut cmd = what.to_string();
        if !what.starts_with("aix '") {
            if let Some(i) = what.find(" --bare | ") {
                cmd = what[..i + 7].to_string();
            }
        }
        let script = format!("{} --no-refresh {}", shell_quote(bin), &cmd[4..]);
        let o = Command::new("bash").arg("-c").arg(&script).current_dir(&dir).env("AIX_EMBED_URL", "").env("HOME", r.parent().unwrap()).env_remove("AIX_HOOK").stdin(Stdio::null()).output().unwrap();
        let code = o.status.code().unwrap_or(-1);
        if !(code == 0 || code == 1) {
            bad.push(format!("[{cwd}] {what}\n   exit {code}: {}{}", String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or(""), String::from_utf8_lossy(&o.stdout).lines().find(|l| l.contains("aix ")).unwrap_or("")));
        }
    }
    let _ = rs;
    assert!(bad.is_empty(), "{} suggestions do not run:\n{}", bad.len(), bad.join("\n"));
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[test]
fn aix_scripts_are_aix_and_a_small_log_grepped_twice_is_a_data_nudge() {
    let (_d, r) = fixture();
    let rs = r.display().to_string();
    let ev = |c: &str| json!({"session_id": "q", "tool_name": "Bash", "tool_input": {"command": c}, "cwd": rs});
    let got = classify_lines(&r, &[ev("aix-init --allow-data --accept-ignore 2>&1 | tail -2; aix-refresh --full 2>&1 | tail -1"), ev("bash scripts/x.sh; aix-watch.sh --stop")]);
    assert_eq!(got[0][2], "aix", "{got:?}");
    // a 6 KB log under the repo: silent on the first grep, the save-it-once nudge on the second
    let log: String = (0..300).map(|i| format!("step {i} VERIFY ok\n")).collect();
    write(&r, ".scratch/small-gate.log", &log);
    let first = pretool(&r, &bash_ev(&r, "q", "grep -E 'VERIFY|FAIL' .scratch/small-gate.log | head"), &[]);
    assert!(first.is_none() || !first.as_ref().unwrap().to_string().contains("aix put"), "{first:?}");
    let second = pretool(&r, &bash_ev(&r, "q", "grep -c FAIL .scratch/small-gate.log"), &[]).expect("a nudge");
    assert!(second.to_string().contains("aix put small-gate"), "{second}");
}

#[test]
fn symbol_search_is_answered_with_the_call_graph() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("repo");
    write(&r, "src/main/java/a/Svc.java", "package a;\npublic class Svc {\n    public static int cancelOnLeave(String id) {\n        return 1;\n    }\n}\n");
    write(&r, "src/main/java/a/Api.java", "package a;\npublic class Api {\n    public void dropStudent() {\n        // cancelOnLeave in a comment\n        Svc.cancelOnLeave(\"x\");\n    }\n}\n");
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "init"]);
    assert!(aix(&r, &["update", "--quiet"], None, &[]).status.success());
    let rs = r.display().to_string();
    let env = [("AIX_HOOK_DENY_MS", "60000")];
    let grep = |sid: &str, input: Value| pretool(&r, &json!({"session_id": sid, "tool_name": "Grep", "tool_input": input, "cwd": rs}), &env).unwrap();
    // a camelCase name the index has call sites for: its callers with the enclosing method, labelled as not grep
    let o = grep("c1", json!({"pattern": "cancelOnLeave", "output_mode": "content"}));
    let reason = o["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap();
    let a = answer_of(&o).unwrap();
    assert!(a.contains("Api.dropStudent") && reason.contains("NOT grep output") && reason.contains("Repeat the identical call"), "{reason}");
    // `Class.method` and `name\(` too; a recursive Bash grep for it as well
    assert!(answer_of(&grep("c2", json!({"pattern": "Svc\\.cancelOnLeave\\("}))).unwrap().contains("Api.dropStudent"));
    let b = pretool(&r, &bash_ev(&r, "c3", "grep -rn cancelOnLeave src"), &env).unwrap();
    assert!(answer_of(&b).is_some_and(|a| a.contains("Api.dropStudent")), "{b}");
    // case-insensitive, or a name with no call site in the index: Grep's own rows
    let a = answer_of(&grep("c4", json!({"pattern": "cancelonleave", "-i": true, "output_mode": "content"}))).unwrap();
    assert!(a.contains("Api.java:4:") && !a.contains("dropStudent ("), "{a}");
    let a = answer_of(&grep("c5", json!({"pattern": "dropStudent", "output_mode": "content"}))).unwrap();
    assert!(a.starts_with("src/main/java/a/Api.java:3:"), "{a}");
}

#[test]
fn ignored_nudges_escalate_to_answers() {
    let (_d, r) = fixture();
    let ev = |sid: &str, c: &str| bash_ev(&r, sid, c);
    // two nudges with no aix call after them; the third steerable lookup is answered by its aix line
    let n1 = pretool(&r, &ev("e", "find src -name '*.ts'"), &[]).unwrap();
    let ctx = n1["hookSpecificOutput"]["additionalContext"].as_str().unwrap();
    assert!(ctx.starts_with("Next similar lookup: run `aix "), "{ctx}");
    assert!(pretool(&r, &ev("e", "grep -rn useAuth frontend/src/pages"), &[]).unwrap()["hookSpecificOutput"]["permissionDecision"].is_null());
    let o = pretool(&r, &ev("e", "grep -rln teacher backend"), &[]).unwrap();
    let reason = o["hookSpecificOutput"]["permissionDecisionReason"].as_str().unwrap_or("");
    assert!(reason.starts_with("Answered by running `aix grep") && reason.contains("StudentResource.java") && reason.contains("Run it again unchanged"), "{o}");
    // never with a side effect in the command, and off with AIX_HOOK_ESCALATE=0
    let o = pretool(&r, &ev("e", "grep -rln record backend; touch x"), &[]);
    assert!(o.as_ref().is_none_or(|o| o["hookSpecificOutput"]["permissionDecision"].is_null()), "{o:?}");
    for c in ["find src -name '*.ts'", "grep -rn useAuth frontend/src/pages"] {
        pretool(&r, &ev("f", c), &[("AIX_HOOK_ESCALATE", "0")]);
    }
    let o = pretool(&r, &ev("f", "grep -rln teacher backend"), &[("AIX_HOOK_ESCALATE", "0")]).unwrap();
    assert!(o["hookSpecificOutput"]["permissionDecision"].is_null(), "{o}");
}
