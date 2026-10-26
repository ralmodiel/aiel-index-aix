#!/usr/bin/env python3
"""Score the code-graph questions in eval.json (see mkeval.py) against one aix binary.

  score.py --sk <aix> --repos <dir> --dbs <dir of <repo>.db> [--build] [--json out.json] [--ids a,b]

Per question: precision / recall of cited lines (same file, within `tol` lines), plus `must` / `mustnot` substrings of the
answer text. `--build` (re)indexes every clone into --dbs first and prints full-build times. Go member ranges are checked
separately against gofmt layout (a top-level `func` ends at the next line that is exactly `}`)."""
import argparse, json, os, re, sqlite3, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--sk", required=True); ap.add_argument("--repos", required=True); ap.add_argument("--dbs", required=True)
ap.add_argument("--eval", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval.json"))
ap.add_argument("--build", action="store_true"); ap.add_argument("--json", default=""); ap.add_argument("--ids", default="")
a = ap.parse_args()
ev = json.load(open(a.eval)); env = dict(os.environ, AIX_EMBED_URL="", HOME="/nonexistent")
repos = sorted({q["repo"] for q in ev["questions"]})
os.makedirs(a.dbs, exist_ok=True)
times = {}
for r in repos:
    db = os.path.join(a.dbs, r + ".db")
    if a.build or not os.path.exists(db):
        if os.path.exists(db): os.remove(db)
        t = time.perf_counter()
        subprocess.run([a.sk, "--repo", os.path.join(a.repos, r), "--db", db, "update", "--full", "--embed-deadline", "0"], capture_output=True, env=env)
        times[r] = round((time.perf_counter() - t) * 1000)

def cites(j, kind):
    out = []
    for ans in j["answers"]:
        if kind == "callers" and ans["kind"] == "caller" and not re.search(r" type \(", ans["text"]): pass
        elif kind == "callees" and ans["kind"] == "callee": pass
        elif kind == "outline" and ans["kind"] == "member": pass
        else: continue
        out += [(c["file"], c["line"]) for c in ans.get("cites", [])]
    return list(dict.fromkeys(out))

res, agg = [], {}
want = set(a.ids.split(",")) - {""}
for q in ev["questions"]:
    if want and q["id"] not in want: continue
    db = os.path.join(a.dbs, q["repo"] + ".db")
    p = subprocess.run([a.sk, "--repo", os.path.join(a.repos, q["repo"]), "--db", db, "--no-refresh", "--limit", "300", "--json"] + q["cmd"], capture_output=True, text=True, env=env)
    if p.returncode: print(q["id"], "FAILED", p.stderr[:200]); continue
    j = json.loads(p.stdout); text = "\n".join(x["text"] for x in j["answers"])
    cs = cites(j, q["kind"]); gt = [(g.rpartition(":")[0], int(g.rpartition(":")[2])) for g in q["gt"]]
    tol = q["tol"]
    ok = lambda c, g: c[0] == g[0] and abs(c[1] - g[1]) <= tol
    okc = [c for c in cs if any(ok(c, g) for g in gt)]
    okg = [g for g in gt if any(ok(c, g) for c in cs)]
    pr = len(okc) / len(cs) if cs else (1.0 if not gt else 0.0)
    rc = len(okg) / len(gt) if gt else None
    musts = {m: (m.lower() in text.lower()) for m in q["must"]}
    nots = {m: (m.lower() not in text.lower()) for m in q["mustnot"]}
    row = dict(id=q["id"], lang=q["lang"], repo=q["repo"], cmd=" ".join(q["cmd"]), p=round(pr, 2), r=None if rc is None else round(rc, 2), n=len(cs), gt=len(gt), must=musts, mustnot=nots)
    res.append(row)
    g = agg.setdefault(q["repo"], dict(p=[], r=[], must=[]))
    g["p"].append(pr)
    if rc is not None: g["r"].append(rc)
    g["must"] += list(musts.values()) + list(nots.values())
    print(f'{q["id"]:4} {q["repo"][:12]:12} p={pr:.2f} r={"-" if rc is None else format(rc, ".2f")} n={len(cs):3} gt={len(gt):3} {"" if all(musts.values()) and all(nots.values()) else "MUST-FAIL " + str({k: v for k, v in {**musts, **nots}.items() if not v})}  {" ".join(q["cmd"])}')

# Go ranges against gofmt layout
bad = tot = 0
for r in repos:
    if r != "chi": continue
    c = sqlite3.connect(os.path.join(a.dbs, r + ".db"))
    for f, line, end, name in c.execute("select file, line, end_line, name from members where file like '%.go' and kind in ('function','method')"):
        src = open(os.path.join(a.repos, r, f), errors="replace").read().split("\n")
        if line > len(src) or not src[line - 1].startswith("func "): continue
        if src[line - 1].rstrip().endswith("}"): true_end = line
        else: true_end = next((i for i in range(line, len(src)) if src[i] == "}"), None); true_end = None if true_end is None else true_end + 1
        if true_end is None: continue
        tot += 1; bad += (true_end != end)
rng = dict(go_members_checked=tot, go_wrong_end=bad)
print("go ranges:", rng)
summ = {r: dict(precision=round(sum(g["p"]) / len(g["p"]), 3), recall=round(sum(g["r"]) / len(g["r"]), 3) if g["r"] else None, must_ok=f'{sum(g["must"])}/{len(g["must"])}') for r, g in agg.items()}
allp = [x for g in agg.values() for x in g["p"]]; allr = [x for g in agg.values() for x in g["r"]]
summ["ALL"] = dict(precision=round(sum(allp) / len(allp), 3), recall=round(sum(allr) / len(allr), 3))
print(json.dumps(summ, indent=1)); print("build_ms", times)
if a.json: json.dump(dict(questions=res, summary=summ, ranges=rng, build_ms=times), open(a.json, "w"), indent=1)
