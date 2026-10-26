#!/usr/bin/env python3
"""Score aix-expert answers against an eval file (see bench/expert/example-eval.json for the format).

  score.py --eval <eval.json> --sk <aix> --db <index copy> --repo <git repo> [--items 1,2] [--ids q01,q02]
           [--latency 20] [--build] [--size <orig.db>] [--json out.json]

Per question: precision / recall of cited locations (same file and within +-line_tolerance, or the cited range
contains the ground-truth line). Cite integrity: every claim cite (non-context answer kinds) is checked against the
source -- the cited lines must contain a symbol/table/route/name the answer text claims there -- and a cite that fails
is a wrong cite (counts against precision, never matches ground truth). A cite that is not ground truth is a
"verified extra" (not a precision miss) only when the question's optional `also` list (file:line, same path rules as
`gt`, each verified by reading the code) names it AND it passes the integrity check; they are reported separately.
Other extras count as precision misses. `must` terms, answer bytes versus a scripted `grep -rn` + `sed -n` baseline,
p50/p95 latency of the CLI over N runs. `--build` times a full rebuild into a copy of the index and a one-file
incremental update in a scratch clone of HEAD. The index is only queried through `--db` (a COPY); the repo is
only read. """
import argparse, json, os, re, shutil, sqlite3, statistics, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))

# answer kinds that are context, not claims: never counted against precision unless they hit the ground truth
NEUTRAL_KINDS = {"definition", "doc", "finding", "test", "summary"}
# Per question the eval file carries: "cmd" (aix argv after the global flags), optional "base" (the baseline an agent
# without the index would run: ["grep", term] repo-wide, or ["file", name, regex] in one file, then sed -n windows around
# the ground-truth lines), "file_level" (ground truth is a list of files), "recall_only" (count question: other cites
# are not penalised). Top level: "closures" (argv lists timed separately), "root_dirs" (gt paths starting with one of
# these are repo-relative, others get the "base" prefix), "build_touch_glob" (tracked file the incremental timing edits).
GREP_EXCLUDES = ["--exclude-dir=.git", "--exclude-dir=node_modules", "--exclude-dir=.scratch", "--exclude-dir=.aix",
                 "--exclude-dir=target", "--exclude-dir=dist", "--exclude-dir=build", "--exclude-dir=.claude"]
GREP_INCLUDES = ["--include=*.java", "--include=*.ts", "--include=*.tsx", "--include=*.py", "--include=*.js", "--include=*.jsx"]


def run(cmd, cwd, env=None, timeout=120):
    t = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, timeout=timeout)
    return p, (time.perf_counter() - t) * 1000


def sk_env(home):
    e = dict(os.environ)
    e["AIX_EMBED_URL"] = ""
    e["HOME"] = home  # hermetic: no user config
    return e


def gt_list(ev, q):
    base = ev.get("base", "")
    roots = ev.get("root_dirs", [])
    out = []
    for g in q["gt"]:
        path, _, line = g.rpartition(":")
        if not (roots and re.match(r"^(" + "|".join(map(re.escape, roots)) + r")/", path)):
            path = base + path
        out.append((path, int(line)))
    return out


def matches(cite, gt, tol, file_level):
    f, l, e = cite
    gf, gl = gt
    if f != gf:
        return False
    return True if file_level else (abs(l - gl) <= tol or l <= gl <= e)


STOP = {"call", "calls", "called", "exact", "resolved", "name", "write", "read", "roles", "role", "declared", "line", "entity", "table", "member",
        "handler", "endpoint", "client", "route", "menu", "screen", "page", "chain", "caller", "callers", "defined", "definition", "this", "that", "with",
        "from", "none", "public", "unknown", "accessed", "side", "effect", "auth", "native", "orm", "repo", "jpql", "via", "also", "interface", "impls",
        "impl", "field", "method", "function", "class", "component", "state", "flow", "sets", "acts", "more", "paths", "path", "http", "true", "false",
        "columns", "column", "unique", "endpoints", "outline", "trace", "explain", "callers", "body", "sites", "limit", "write", "transient", "button", "button"}
PATH_RE = re.compile(r"[\w./@-]+\.(?:java|kt|tsx?|jsx?|py|go|rs|sql|md|json|ya?ml|xml|html|css|properties)(?::\d+(?:-\d+)?)?")


def query_tokens(cmd):
    """Names the question itself puts in play (a callee for `callers`, an endpoint for `trace`, a table): a call-site cite
    shows the queried callee, not the calling member the answer text names."""
    out = []
    for a in cmd[1:]:
        if a.startswith("-"):
            continue
        for x in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", a):
            if len(x) >= 4 and x.lower() not in STOP:
                out.append(x)
    return list(dict.fromkeys(out))


VERBS = {"GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "ANY"}


def claim_tokens(text, kind="", cite=None):
    """Symbols/tables/routes an answer text claims at its cite: the label-less head of the line (before roles, confidence,
    provenance), file paths removed, an `entity X.field` name, and for a multi-cite enumeration the identifier written
    right before this cite's `(file:line)`. Returns (long tokens matched as substrings, short whole-word tokens)."""
    long_, short = [], []
    if cite:
        base = re.escape(cite[0].rsplit("/", 1)[-1])
        m = re.search(r"(\w+)\s*\([^()]*?" + base + r":" + str(cite[1]) + r"\b", text)
        if m:
            (long_ if len(m.group(1)) >= 4 else short).append(m.group(1))
    t = PATH_RE.sub(" ", text)
    for ent in re.findall(r"entity ([\w.]+)", t):
        for x in ent.split("."):
            (long_ if len(x) >= 4 else short).append(x)
    head = re.split(r"\s{2}roles |\s\(|\s{2}<-|;|\s->|\svia ", t.strip(), maxsplit=1)[0]
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", head)
    if toks and toks[0].lower() == kind.lower():
        toks = toks[1:]
    for x in toks:
        if x in VERBS:
            short.append(x)
        elif len(x) >= 4 and x.lower() not in STOP:
            long_.append(x)
    return list(dict.fromkeys(long_)), list(dict.fromkeys(short))


_FILE_CACHE = {}


def file_lines(repo, rel):
    if rel not in _FILE_CACHE:
        try:
            _FILE_CACHE[rel] = open(os.path.join(repo, rel), errors="replace").read().split("\n")
        except OSError:
            _FILE_CACHE[rel] = None
    return _FILE_CACHE[rel]


def cite_integrity(repo, cite, text, extra=(), kind=""):
    """True when the cited source lines contain a claimed name: the cited range (up to 8 lines), or one line +-1, extended
    through a leading run of annotations to the declaration they decorate. Long names match as case- and
    underscore-insensitive substrings (`audit_logs` and `AuditLog` both find `@Table(name = "audit_logs")`), short ones and
    HTTP verbs as whole words."""
    f, l, e = cite
    lines = file_lines(repo, f)
    if lines is None or l < 1 or l > len(lines):
        return False
    long_, short = claim_tokens(text, kind, cite)
    long_ += list(extra)
    if not long_ and not short:
        return False
    m = re.search(r"declared at line (\d+)", text)  # a member cited at the line where it calls the next layer: its name is at the declaration
    if m:
        l, e = int(m.group(1)), int(m.group(1))
    a, b = (max(1, l - 1), min(len(lines), l + 1)) if e <= l else (l, min(len(lines), e, l + 7))
    if e <= l:
        k = l
        while k <= len(lines) and lines[k - 1].lstrip().startswith("@") and k < l + 8:
            k += 1
        b = max(b, min(len(lines), k))
    raw = "\n".join(lines[a - 1:b])
    win = raw.lower().replace("_", "")
    return any(t.lower().replace("_", "") in win for t in long_) or any(re.search(r"\b" + re.escape(t) + r"\b", raw) for t in short)


def score_cites(cites, gts, tol, file_level, neutral=(), recall_only=False, also=(), integrity=None):
    """cites: [(file,line,end)], integrity: {cite: bool} (missing = True, e.g. context kinds). Returns
    (precision, recall, claims, gts, detail) where detail lists extras / wrong cites / verified extras."""
    integrity = integrity or {}
    cites = list(dict.fromkeys(cites))
    if file_level:  # compare files only
        cs = list(dict.fromkeys((c[0], 0, 0) for c in cites))
        gs = list(dict.fromkeys((g[0], 0) for g in gts))
        als = list(dict.fromkeys((g[0], 0) for g in also))
        integ = {}
        for c in cites:
            integ[(c[0], 0, 0)] = integ.get((c[0], 0, 0), False) or integrity.get(c, True)
    else:
        cs, gs, als, integ = cites, gts, list(also), {c: integrity.get(c, True) for c in cites}
    neutral = {(c[0], 0, 0) if file_level else c for c in neutral}
    is_gt = lambda c: integ[c] and any(matches(c, g, tol, file_level) for g in gs)
    is_also = lambda c: integ[c] and not is_gt(c) and any(matches(c, g, tol, file_level) for g in als)
    ok_g = [g for g in gs if any(integ[c] and matches(c, g, tol, file_level) for c in cs)]
    gt_c = [c for c in cs if is_gt(c)]
    ver = [c for c in cs if is_also(c)]
    claims = [c for c in cs if c not in neutral or c in gt_c]
    wrong = [c for c in claims if not integ[c]]
    extra = [c for c in claims if integ[c] and c not in gt_c and c not in ver]
    if recall_only:  # unlisted extras are not penalised, wrong cites always are
        claims = gt_c + wrong
    good = len(gt_c) + (0 if recall_only else len(ver))
    p = good / len(claims) if claims else 0.0
    r = len(ok_g) / len(gs) if gs else 0.0
    detail = {"verified_extras": len(ver), "wrong_cites": [f"{c[0]}:{c[1]}" for c in wrong],
              "extras": [] if recall_only else [f"{c[0]}:{c[1]}" for c in extra],
              "missed": [f"{g[0]}:{g[1]}" for g in gs if g not in ok_g]}
    return p, r, len(claims), len(gs), detail


def baseline_bytes(repo, ev, q, gts):
    spec = q.get("base")
    if not spec:
        return None
    t = time.perf_counter()
    if spec[0] == "grep":
        p, _ = run(["grep", "-rn", *GREP_EXCLUDES, *GREP_INCLUDES, "-F", spec[1], "."], repo)
        out = p.stdout
    else:
        path = next(g[0] for g in gts if g[0].endswith(spec[1]))
        p, _ = run(["grep", "-nE", spec[2], path], repo)
        out = p.stdout
    total = len(out.encode())
    # sed -n windows: 5 lines above to 25 below each ground-truth line, merged per file
    wins = {}
    for f, l in gts:
        wins.setdefault(f, []).append((max(1, l - 5), l + 25))
    for f, ws in wins.items():
        ws.sort()
        merged = []
        for a, b in ws:
            if merged and a <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        for a, b in merged:
            p, _ = run(["sed", "-n", f"{a},{b}p", f], repo)
            total += len(p.stdout.encode())
    return total, (time.perf_counter() - t) * 1000


def pctl(xs, p):
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(p * (len(xs) - 1)))))
    return xs[k]


def time_cmd(sk, db, repo, argv, runs, refresh, env):
    base = [sk, "--db", db] + ([] if refresh else ["--no-refresh"])
    run(base + argv, repo, env)  # warm
    ts = []
    for _ in range(runs):
        _, ms = run(base + argv, repo, env)
        ts.append(ms)
    return ts


def build_times(sk, repo, orig_db, scratch, env, touch_glob):
    res = {}
    db = os.path.join(scratch, "build.db")
    shutil.copy(orig_db, db)
    _, ms = run([sk, "--db", db, "update", "--full", "--embed-deadline", "0"], repo, env, 600)
    res["full_rebuild_ms_into_copy"] = round(ms)
    # one-file incremental on a clone of HEAD (the real tree is never modified)
    clone = os.path.join(scratch, "clone")
    os.makedirs(clone)
    arch = subprocess.Popen(["git", "-C", repo, "archive", "HEAD"], stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", clone], stdin=arch.stdout, check=True)
    arch.wait()
    for a in (["init", "-q", "-b", "main"], ["add", "-A"], ["-c", "user.name=b", "-c", "user.email=b@x.test", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", clone, *a], check=True, capture_output=True)
    _, ms = run([sk, "--repo", clone, "update", "--full", "--embed-deadline", "0"], clone, env, 600)
    res["full_build_ms_clone"] = round(ms)
    _, ms = run([sk, "--repo", clone, "update", "--embed-deadline", "0"], clone, env)
    res["noop_update_ms"] = round(ms)
    cand = subprocess.run(["git", "-C", clone, "ls-files", touch_glob], capture_output=True, text=True).stdout.split()[0]
    path = os.path.join(clone, cand)
    inc = []
    for i in range(5):
        with open(path, "a") as f:
            f.write(f"\n// bench {i}\n")
        _, ms = run([sk, "--repo", clone, "update", "--embed-deadline", "0"], clone, env)
        inc.append(ms)
    res["one_file_incremental_ms"] = [round(x) for x in inc]
    res["one_file_incremental_ms_median"] = round(statistics.median(inc))
    return res


def size_report(db, orig):
    def vac(p):
        d = tempfile.mkdtemp()
        q = os.path.join(d, "x.db")
        shutil.copy(p, q)
        c = sqlite3.connect(q)
        c.execute("pragma wal_checkpoint(truncate)")
        c.execute("vacuum")
        tabs = {}
        try:
            for n, s in c.execute("select name, sum(pgsize) from dbstat group by name"):
                tabs[n] = s
        except Exception:
            pass
        c.close()
        return os.path.getsize(q), tabs
    a, _ = vac(orig)
    b, t = vac(db)
    mine = {k: v for k, v in t.items() if re.match(r"^(members|refs|call_edges|sym_fanin|cg_dirty|ce_|refs_|members_|sqlite_autoindex_(members|refs|call_edges|sym_fanin|cg_dirty))", k)}
    dm = {k: v for k, v in t.items() if re.match(r"^(entities|dm_|migrations|entity_columns|fks|data_access|layer_edges|le_|trace_|sqlite_autoindex_(dm_|trace_|migrations|entities|fks|data_access|layer))", k)}
    return {"orig_mb": round(a / 1e6, 1), "new_mb": round(b / 1e6, 1), "growth_mb": round((b - a) / 1e6, 1),
            "growth_pct": round(100 * (b - a) / a, 1), "code_graph_tables_mb": round(sum(mine.values()) / 1e6, 1), "data_model_trace_tables_mb": round(sum(dm.values()) / 1e6, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sk", required=True)
    ap.add_argument("--db", required=True, help="COPY of the repo index")
    ap.add_argument("--repo", required=True, help="git repo (cwd for the queries and the grep baseline)")
    ap.add_argument("--eval", required=True, help="eval JSON (questions, ground truth, commands)")
    ap.add_argument("--items", default="")
    ap.add_argument("--ids", default="")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--latency", type=int, default=0, help="runs per command (0 = skip)")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--size", default="", help="original index (before the rebuild) for the size comparison")
    ap.add_argument("--orig-for-build", default="", help="index to copy for the timed full rebuild")
    ap.add_argument("--json", default="")
    ap.add_argument("--home", default=tempfile.mkdtemp())
    a = ap.parse_args()
    ev = json.load(open(a.eval))
    tol = ev.get("line_tolerance", 3)
    items = {int(x) for x in a.items.split(",") if x}
    ids = {x for x in a.ids.split(",") if x}
    env = sk_env(a.home)
    # every query below runs with --no-refresh: build a missing index once here, and stop with aix's own message when it
    # refuses the index (a copied db still names the repo it was built from), instead of failing each question blank
    if not os.path.exists(a.db):
        print(f"building {a.db} (no index there yet)", file=sys.stderr)
        p, _ = run([a.sk, "--db", a.db, "update", "--embed-deadline", "0"], a.repo, env, 600)
        if p.returncode != 0:
            sys.exit(f"score.py: building the index failed: {(p.stderr or p.stdout).strip()[:300]}")
    p, _ = run([a.sk, "--db", a.db, "--no-refresh", "stats"], a.repo, env)
    if p.returncode != 0:
        sys.exit(f"score.py: aix cannot use --db {a.db} with --repo {a.repo}: {(p.stderr or p.stdout).strip()[:300]}")
    rows, report = [], {"head": ev.get("head", ""), "questions": [], "gate": {"recall": 0.9, "precision": 0.8, "token_cut": 0.4}}
    for q in ev["questions"]:
        if "cmd" not in q or (items and q["item"] not in items) or (ids and q["id"] not in ids):
            continue
        argv = [a.sk, "--db", a.db, "--no-refresh", "--limit", str(a.limit), "--json"] + q["cmd"]
        p, ms = run(argv, a.repo, env)
        if p.returncode != 0:
            print(q["id"], "FAILED:", (p.stderr or p.stdout or f"exit {p.returncode}, no output")[:200])
            continue
        j = json.loads(p.stdout)
        cites = [(c["file"], c["line"], c["end"]) for ans in j["answers"] for c in ans.get("cites", [])]
        neutral = [(c["file"], c["line"], c["end"]) for ans in j["answers"] if ans["kind"] in NEUTRAL_KINDS for c in ans.get("cites", [])]
        integrity = {}
        for ans in j["answers"]:
            if ans["kind"] in NEUTRAL_KINDS:
                continue
            for c in ans.get("cites", []):
                k = (c["file"], c["line"], c["end"])
                integrity[k] = integrity.get(k, False) or cite_integrity(a.repo, k, ans["text"], query_tokens(q["cmd"]), ans["kind"])
        gts = gt_list(ev, q)
        also = gt_list(ev, {"gt": q.get("also", [])})
        pr, rc, nc, ng, detail = score_cites(cites, gts, tol, q.get("file_level"), neutral, q.get("recall_only"), also, integrity)
        text = "\n".join(x["text"] for x in j["answers"])
        must = q.get("must", [])
        miss = [m for m in must if m.lower() not in text.lower()]
        tp, _ = run([a.sk, "--db", a.db, "--no-refresh", "--limit", str(a.limit)] + q["cmd"], a.repo, env)
        sk_bytes = len(tp.stdout.encode())
        bl = baseline_bytes(a.repo, ev, q, gts)
        cut = 1 - sk_bytes / bl[0] if bl else None
        rec = {"id": q["id"], "q": q["q"], "precision": round(pr, 3), "recall": round(rc, 3), "cites": nc, "gt": ng,
               "must_missing": miss, **detail, "sk_bytes": sk_bytes, "baseline_bytes": bl[0] if bl else None,
               "token_cut": round(cut, 3) if cut is not None else None, "baseline_ms": round(bl[1]) if bl else None}
        if a.latency:
            ts = time_cmd(a.sk, a.db, a.repo, ["--limit", str(a.limit)] + q["cmd"], a.latency, False, env)
            rec["p50_ms"], rec["p95_ms"] = round(statistics.median(ts), 1), round(pctl(ts, 0.95), 1)
            ts = time_cmd(a.sk, a.db, a.repo, ["--limit", str(a.limit)] + q["cmd"], max(5, a.latency // 4), True, env)
            rec["p95_ms_with_refresh_check"] = round(pctl(ts, 0.95), 1)
        report["questions"].append(rec)
    if a.latency:
        report["closures"] = []
        for c in ev.get("closures", []):
            ts = time_cmd(a.sk, a.db, a.repo, c, a.latency, False, env)
            report["closures"].append({"cmd": " ".join(c), "p50_ms": round(statistics.median(ts), 1), "p95_ms": round(pctl(ts, 0.95), 1)})
    if a.build:
        report["build"] = build_times(a.sk, a.repo, a.orig_for_build or a.size or a.db, tempfile.mkdtemp(), env, ev.get("build_touch_glob", "*.java"))
    if a.size:
        report["size"] = size_report(a.db, a.size)
    qs = report["questions"]
    if qs:
        report["mean_precision"] = round(statistics.mean(r["precision"] for r in qs), 3)
        report["mean_recall"] = round(statistics.mean(r["recall"] for r in qs), 3)
        cuts = [r["token_cut"] for r in qs if r["token_cut"] is not None]
        report["total_token_cut"] = round(1 - sum(r["sk_bytes"] for r in qs if r["baseline_bytes"]) / sum(r["baseline_bytes"] for r in qs if r["baseline_bytes"]), 3)
    # table
    print(f"{'id':4} {'prec':>5} {'rec':>5} {'cites':>5} {'gt':>3} {'vx':>3} {'sk B':>6} {'base B':>8} {'cut':>6} {'p50':>6} {'p95':>6}  must-missing")
    for r in qs:
        print(f"{r['id']:4} {r['precision']:5.2f} {r['recall']:5.2f} {r['cites']:5d} {r['gt']:3d} {r['verified_extras']:3d} {r['sk_bytes']:6d} {r['baseline_bytes'] or 0:8d} {(r['token_cut'] or 0):6.2f} {r.get('p50_ms', '-'):>6} {r.get('p95_ms', '-'):>6}  {r['must_missing'] or ''}")
    for r in qs:
        for k in ("wrong_cites", "extras", "missed"):
            if r[k]:
                print(f"  {r['id']} {k}: {', '.join(r[k][:12])}")
    for k in ("mean_precision", "mean_recall", "total_token_cut", "closures", "build", "size"):
        if k in report:
            print(k, json.dumps(report[k]))
    if a.json:
        json.dump(report, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
