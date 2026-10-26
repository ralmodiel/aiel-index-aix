#!/usr/bin/env python3
"""Measure the XQuery code graph on cloned MarkLogic repos against an independent, regex-based oracle.

  xquery.py --sk <aix> --repos <dir> --dbs <dir> [--build] [--json out.json] [--repo name,...] [--n 25] [--sample out.tsv]

Oracle (no code shared with aix): `(: … :)` comments are removed (nested ones too) and line breaks kept.
- definitions: every `declare [%ann(…)] [private|updating] function p:name(` line; found when aix has a function
  member of that local name covering the line in that file.
- callers: for functions whose (namespace URI, local name) is declared exactly once in the repo, the call sites are
  `x:name(` / `x:name#N` in any file whose prolog binds some prefix x to that URI (module namespace, import module,
  declare namespace), outside string literals on that line, the declaration itself excluded. N functions are picked
  by hash of the name (the choice does not depend on the tool); aix answers `callers <file>:<line>`. Precision and
  recall are micro-averaged over call sites (a site matches within +-1 line); callers aix finds in .sjs files are
  reported apart (`callers_sjs`), the oracle does not read JavaScript. `--sample` writes the oracle sites of
  the picked functions (file, line, text) for hand checking."""
import argparse, hashlib, json, os, re, sqlite3, subprocess

REPOS = {
    # repo: path filter (files skipped by both sides)
    "roxy": None,
    "ml-gradle": None,
    "ml-unit-test": None,
    "xray": None,
    "marklogic-data-hub": None,
}
EXTS = (".xqy", ".xq", ".xqm", ".xql", ".xquery", ".xqe")
DEF = re.compile(r"\bdeclare\s+(?:%[\w:.-]+(?:\([^)]*\))?\s+|(?:private|public|updating)\s+)*function\s+([\w.-]+:)?([\w.-]+)\s*\(")
BIND = re.compile(r"""\b(?:module\s+namespace|import\s+module\s+namespace|declare\s+namespace)\s+([\w.-]+)\s*=\s*["']([^"']+)["']""")
COMMENT = re.compile(r"\(:(?:(?!\(:|:\)).)*?:\)", re.S)

def strip_comments(t):
    while True:
        u = COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), t)
        if u == t: return u
        t = u

def in_string(line, col):
    """Inside a string literal on this line (quotes before the column are unbalanced)?"""
    before = line[:col]
    return before.count('"') % 2 == 1

ap = argparse.ArgumentParser()
ap.add_argument("--sk", required=True); ap.add_argument("--repos", required=True); ap.add_argument("--dbs", required=True)
ap.add_argument("--build", action="store_true"); ap.add_argument("--json", default=""); ap.add_argument("--repo", default="")
ap.add_argument("--n", type=int, default=25); ap.add_argument("--sample", default="")
a = ap.parse_args()
env = dict(os.environ, AIX_EMBED_URL="", HOME="/nonexistent")
os.makedirs(a.dbs, exist_ok=True)
want = set(a.repo.split(",")) - {""}
sample = open(a.sample, "w") if a.sample else None
results = {}
for repo, skip in REPOS.items():
    if want and repo not in want: continue
    root = os.path.join(a.repos, repo)
    if not os.path.isdir(root): continue
    db = os.path.join(a.dbs, repo + ".db")
    if a.build or not os.path.exists(db):
        if os.path.exists(db): os.remove(db)
        subprocess.run([a.sk, "--repo", root, "--db", db, "update", "--full", "--embed-deadline", "0"], capture_output=True, env=env)
    files = [f for f in subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True).stdout.split("\n")
             if f.endswith(EXTS) and not (skip and re.search(skip, "/" + f))]
    text = {}
    for f in files:
        try: text[f] = strip_comments(open(os.path.join(root, f), errors="replace").read()).split("\n")
        except OSError: pass
    binds = {}  # file -> {prefix: uri}
    defs = []   # (file, line, prefix, local, uri)
    for f, lines in text.items():
        b = {m.group(1): m.group(2) for m in BIND.finditer("\n".join(lines))}
        b.setdefault("local", "http://www.w3.org/2005/xquery-local-functions")
        binds[f] = b
        whole = "\n".join(lines)
        for m in DEF.finditer(whole):  # a declaration may span lines
            p = (m.group(1) or "")[:-1]
            defs.append((f, whole.count("\n", 0, m.start()) + 1, p, m.group(2), b.get(p, "")))
    con = sqlite3.connect(db)
    mem = [m for m in con.execute("SELECT file,line,end_line,name FROM members WHERE kind='function'").fetchall() if m[0] in text]
    byfile = {}
    for m in mem: byfile.setdefault(m[0], []).append(m)
    hit = sum(1 for (f, i, p, n, u) in defs if any(m[3] == n and m[1] - 3 <= i <= m[2] for m in byfile.get(f, [])))
    missed = [(f, i, p, n) for (f, i, p, n, u) in defs if not any(m[3] == n and m[1] - 3 <= i <= m[2] for m in byfile.get(f, []))]
    row = dict(files=len(text), gt_defs=len(defs), defs_found=hit, defs_recall=round(hit / len(defs), 3) if defs else None,
               aix_functions=len(mem), defs_missed=missed[:10])
    # callers
    count = {}
    for d in defs: count[(d[4], d[3])] = count.get((d[4], d[3]), 0) + 1
    cands = []
    for (f, i, p, n, u) in defs:
        if not u or count[(u, n)] != 1: continue
        sites = []
        for g, lines in text.items():
            prefixes = [x for x, uu in binds[g].items() if uu == u]
            if u.endswith("xquery-local-functions") and g != f: continue
            if not prefixes: continue
            rx = re.compile(r"(?<![\w.$:-])(?:" + "|".join(re.escape(x) for x in prefixes) + r"):" + re.escape(n) + r"(?![\w.-])\s*(?:\(|#\d)")
            for k, l in enumerate(lines, 1):
                for m in rx.finditer(l):
                    if (g, k) == (f, i) or in_string(l, m.start()) or DEF.search(l[:m.end() + 1]) or re.search(r"\bfunction\s*$", (lines[k - 2] if k > 1 else "") + " " + l[:m.start()]): continue
                    sites.append((g, k)); break
        if sites: cands.append((hashlib.sha1(f"{u} {n}".encode()).hexdigest(), f, i, p, n, sites))
    cands.sort()
    qs, tp_all, n_all, gt_all, sjs_all = [], 0, 0, 0, 0
    for _, f, i, p, n, sites in cands[:a.n]:
        out = subprocess.run([a.sk, "--repo", root, "--db", db, "--no-refresh", "--limit", "500", "--json", "callers", f"{f}:{i}"], capture_output=True, text=True, env=env).stdout
        try: j = json.loads(out)
        except Exception: qs.append(dict(name=f"{p}:{n}", err=1)); continue
        cs = list(dict.fromkeys((c["file"], c["line"]) for x in j["answers"] if x["kind"] == "caller" for c in x.get("cites", [])))
        # the oracle reads XQuery only: callers in Server-Side JavaScript (`require("/x.xqy")`) are counted apart
        sjs = [c for c in cs if not c[0].endswith(EXTS)]
        cs = [c for c in cs if c[0].endswith(EXTS)]
        sjs_all += len(sjs)
        ok = lambda c, g: c[0] == g[0] and abs(c[1] - g[1]) <= 1
        tp = sum(1 for c in cs if any(ok(c, g) for g in sites))
        rc = sum(1 for g in sites if any(ok(c, g) for c in cs))
        tp_all += tp; n_all += len(cs); gt_all += len(sites); hit_r = rc
        q = dict(name=f"{p}:{n}", file=f, gt=len(sites), n=len(cs), tp=tp, found=rc)
        fp = [c for c in cs if not any(ok(c, g) for g in sites)]
        fn = [g for g in sites if not any(ok(c, g) for c in cs)]
        if fp: q["extra"] = fp[:5]
        if fn: q["missed"] = fn[:5]
        qs.append(q)
        if sample:
            for g in sites: sample.write(f"{repo}\t{p}:{n}\t{g[0]}:{g[1]}\t{text[g[0]][g[1]-1].strip()[:160]}\n")
    found = sum(q.get("found", 0) for q in qs)
    row.update(callers_q=len(qs), callers_sites=gt_all, callers_answers=n_all, callers_sjs=sjs_all,
               callers_p=round(tp_all / n_all, 3) if n_all else None, callers_r=round(found / gt_all, 3) if gt_all else None,
               callers=[q for q in qs if q.get("extra") or q.get("missed") or q.get("err")])
    results[repo] = row
    print(repo, json.dumps(row), flush=True)
if a.json: json.dump(results, open(a.json, "w"), indent=1)
