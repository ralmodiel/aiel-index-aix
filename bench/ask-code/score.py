#!/usr/bin/env python3
"""hit@N for `aix ask --kind code`: does a file the question's ground truth names show up in the top N rows?

  score.py --sk <aix> [--repo <git repo> --db <index copy> --eval <eval.json>] [--n 4] [--min 0.8] [--json out.json]

Without --repo it builds a throw-away git repo from bench/ask-code/corpus (12 small files) and scores bench/ask-code/eval.json
against a fresh index in a temp dir; HOME is a temp dir, so the embedder is used only when AIX_EMBED_URL is set (e.g. http://127.0.0.1:8092); else the keyword fallback is scored.

The eval is a list of {"q": "<plain-English question>", "files": ["<path or path suffix>", ...]}; a question counts as a hit
when any of the top N `[code] file:start-end Name` rows is in one of the listed files (suffix match). The index is only
queried through --db (a COPY of the index); the repo is only read. Exit 1 if hit@N is below --min (default 0)."""
import argparse, json, re, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--sk", required=True)
ap.add_argument("--repo")
ap.add_argument("--db")
ap.add_argument("--eval")
ap.add_argument("--n", type=int, default=4)
ap.add_argument("--min", type=float, default=0.0)
ap.add_argument("--json")
a = ap.parse_args()

import os, shutil, tempfile
here = os.path.dirname(os.path.abspath(__file__))
if not a.repo:
    tmp = tempfile.mkdtemp(prefix="aix-ask-code-")
    a.repo = os.path.join(tmp, "corpus")
    shutil.copytree(os.path.join(here, "corpus"), a.repo)
    for c in (["init", "-q", "-b", "main"], ["add", "-A"],
              ["-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "corpus"]):
        subprocess.run(["git", "-C", a.repo] + c, check=True)
    a.db = os.path.join(tmp, "index.db")
    a.eval = a.eval or os.path.join(here, "eval.json")
    env = dict(os.environ, HOME=tmp, AIX_NO_LINK="1")
    subprocess.run([a.sk, "--repo", a.repo, "--db", a.db, "update", "--full", "--embed-deadline", "120"], check=True, env=env,
                   capture_output=True)
    os.environ.update(HOME=tmp, AIX_NO_LINK="1")
ev = json.load(open(a.eval))
rows_re = re.compile(r"^\[code\] (\S+?):(\d+)-(\d+) (\S+)")
hits, out = 0, []
for q in ev:
    p = subprocess.run([a.sk, "--repo", a.repo, "--db", a.db, "--limit", str(a.n), "ask", q["q"], "--kind", "code"],
                       capture_output=True, text=True, timeout=300)
    got = [m.group(1) for l in p.stdout.splitlines() if (m := rows_re.match(l))][: a.n]
    ok = any(g.endswith(f) for g in got for f in q["files"])
    hits += ok
    out.append({"q": q["q"], "hit": ok, "top": got})
    print(("HIT  " if ok else "MISS ") + q["q"] + ("" if ok else "  -> " + ", ".join(got)))
rate = hits / max(1, len(ev))
print(f"hit@{a.n}: {hits}/{len(ev)} = {rate:.2f}")
if a.json:
    json.dump({"hit": rate, "n": a.n, "questions": out}, open(a.json, "w"), indent=1)
sys.exit(0 if rate >= a.min else 1)
