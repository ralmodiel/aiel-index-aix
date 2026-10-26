#!/usr/bin/env python3
"""Query-level oracle: run the same canned queries with aix and the Python prototype (repoindex) and
compare the facts each answer cites (file:line refs and METHOD /path endpoints), plus output bytes.

Usage: scripts/oracle-queries.py --repo REPO --aix BIN --proto PROTO_PY --queries FILE.json [--db AIX_DB] [--out DIR]
  FILE.json is a list of [command, argument] pairs, e.g. [["brief", "/orders"], ["text", "Place order"], ["symbol", "OrderService"]]
Both run with --no-refresh, so neither index is rebuilt during the comparison.
(Drafted by the local LLM harness via local_ask, then reviewed.)
"""
import argparse
import json
import os
import re
import subprocess

def extract_facts(text):
    facts = set()
    for m in re.finditer(r"([\w./-]+\.\w{1,5}):(\d+)", text):
        facts.add(f"{os.path.basename(m[1])}:{m[2]}")
    for m in re.finditer(r"(GET|POST|PUT|DELETE|PATCH) (/[\w/{}$.:-]+)", text):
        p = re.sub(r"\$\{[^}]*\}", "{}", m[2])
        p = re.sub(r"\{[^}]*\}", "{}", p)
        facts.add(f"{m[1]} {p}")
    return facts


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--aix", required=True)
    ap.add_argument("--proto", required=True)
    ap.add_argument("--queries", required=True, help="JSON list of [command, argument] pairs")
    ap.add_argument("--db")
    ap.add_argument("--out")
    a = ap.parse_args()
    QUERIES = [tuple(q) for q in json.load(open(a.queries))]
    total = 0.0
    for i, (cmd, arg) in enumerate(QUERIES):
        sk = [a.aix, "--repo", a.repo] + (["--db", a.db] if a.db else []) + ["--no-refresh", cmd, arg]
        s_out = run(sk)
        p_out = run(["python3", a.proto, "--repo", a.repo, "--no-refresh", cmd, arg])
        sf, pf = extract_facts(s_out), extract_facts(p_out)
        jac = len(sf & pf) / len(sf | pf) if (sf | pf) else 1.0
        total += jac
        if a.out:
            os.makedirs(a.out, exist_ok=True)
            base = f"{i:02d}-{cmd}"
            open(os.path.join(a.out, base + ".aix.txt"), "w").write(s_out)
            open(os.path.join(a.out, base + ".proto.txt"), "w").write(p_out)
        print(f"{cmd} {arg}: aix={len(sf)} proto={len(pf)} both={len(sf & pf)} jaccard={jac:.2f} "
              f"bytes aix={len(s_out.encode())} proto={len(p_out.encode())}")
    print(f"mean jaccard: {total / len(QUERIES):.2f}")


if __name__ == "__main__":
    main()
