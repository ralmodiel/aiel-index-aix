#!/usr/bin/env python3
"""What do Claude's `scripts/psql.sh` calls look up? Groups them: schema (\\d, information_schema, columns),
row lookups by id/name (SELECT ... WHERE), counts/aggregates, writes, other. Usage: bench/psql-usage.py [--since DATE]"""
import argparse, json, os, re, glob, collections, datetime
ap = argparse.ArgumentParser(); ap.add_argument("--since", default="2026-10-08"); a = ap.parse_args()
since = datetime.datetime.fromisoformat(a.since).timestamp()
cats = collections.Counter(); tables = collections.Counter(); ex = collections.defaultdict(list)
for f in glob.glob(os.path.expanduser("~/.claude/projects/**/*.jsonl"), recursive=True):
    if os.path.getmtime(f) < since: continue
    for line in open(f, errors="replace"):
        if "psql" not in line: continue
        try: ev = json.loads(line)
        except Exception: continue
        for b in (ev.get("message") or {}).get("content") or []:
            if not isinstance(b, dict) or b.get("type") != "tool_use" or b.get("name") != "Bash": continue
            c = (b.get("input") or {}).get("command", "")
            if "psql" not in c: continue
            q = c.lower()
            if re.search(r"\\d|information_schema|pg_catalog|column_name|pg_indexes|\\dt", q): k = "schema"
            elif re.search(r"\b(insert|update|delete)\b", q): k = "write"
            elif re.search(r"\bcount\(|\bsum\(|group by", q): k = "count/aggregate"
            elif re.search(r"\bselect\b.*\bwhere\b", q): k = "row lookup"
            elif "select" in q: k = "select (no where)"
            else: k = "other"
            cats[k] += 1
            for t in re.findall(r"\b(?:from|join|update|into)\s+([a-z_][a-z0-9_]*)", q): tables[t] += 1
            if len(ex[k]) < 4: ex[k].append(re.sub(r"\s+", " ", c)[:160])
print("psql calls by kind:", dict(cats.most_common()))
print("top tables:", ", ".join(f"{t} {n}" for t, n in tables.most_common(20)))
for k, v in ex.items():
    print(f"-- {k}"); [print("   ", x) for x in v]
