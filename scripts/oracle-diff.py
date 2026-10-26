#!/usr/bin/env python3
"""Oracle diff: compare the aix index with the Python prototype's (repoindex) on the same repo.

Usage: scripts/oracle-diff.py PROTO_DB AIX_DB [--show N]
  PROTO_DB     path to the prototype index (read-only)
  AIX_DB  path to the aix index (read-only)
One line per fact family: counts on each side, overlap, agreement %, then a few examples of each side's extras.
(Drafted by the local LLM harness via local_ask, then reviewed and fixed.)
"""
import argparse
import sqlite3
import sys


def get_db(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def roles(s):
    return ",".join(sorted(x for x in (s or "").split(",") if x))


def compare(name, p_set, s_set, n):
    po, so, both = p_set - s_set, s_set - p_set, p_set & s_set
    union = len(p_set | s_set)
    pct = len(both) / union * 100 if union else 100.0
    print(f"{name}: proto={len(p_set)} aix={len(s_set)} both={len(both)} "
          f"only_proto={len(po)} only_aix={len(so)} agree={pct:.1f}%")
    for item in sorted(po, key=str)[:n]:
        print(f"  - proto-only: {item}")
    for item in sorted(so, key=str)[:n]:
        print(f"  + aix-only: {item}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("proto_db")
    ap.add_argument("aix_db")
    ap.add_argument("--show", type=int, default=5)
    a = ap.parse_args()
    try:
        p, s = get_db(a.proto_db), get_db(a.aix_db)
    except Exception as e:
        sys.exit(f"cannot open: {e}")

    def comp(name, p_sql, s_sql, tp=None, ts=None):
        try:
            ps = {tp(r) if tp else tuple(r) for r in p.execute(p_sql)}
            ss = {(ts or tp)(r) if (ts or tp) else tuple(r) for r in s.execute(s_sql)}
            compare(name, ps, ss, a.show)
        except Exception as e:
            print(f"{name}: ERROR {e}")

    comp("routes", "SELECT path, component, file, roles FROM routes",
         "SELECT path, component, page_file, roles FROM routes", lambda r: (r[0], r[1], r[2], roles(r[3])))
    comp("menu", "SELECT label, href FROM menu", "SELECT label, href FROM menu")
    comp("menu_roles", "SELECT label, href, roles, grp_roles FROM menu", "SELECT label, href, roles, grp_roles FROM menu",
         lambda r: (r[0], r[1], roles(r[2] or r[3])))
    comp("endpoints", "SELECT method, norm FROM endpoints", "SELECT method, norm FROM endpoints")
    comp("endpoint_roles", "SELECT method, norm, roles FROM endpoints", "SELECT method, norm, roles FROM endpoints",
         lambda r: (r[0], r[1], roles(r[2])))
    comp("api_client", "SELECT obj, name, method, norm FROM api_client",
         "SELECT obj, name, method, norm FROM api_calls WHERE obj IS NOT NULL")
    comp("e2e", "SELECT file, sid, role FROM e2e_scenarios", "SELECT file, sid, role FROM tests")
    comp("e2e_steps", "SELECT file, line, sid, kind, value FROM e2e_steps", "SELECT file, line, sid, kind, value FROM test_steps")
    comp("scripts", "SELECT path FROM scripts", "SELECT file FROM scripts")
    comp("tasks", "SELECT file, line, status, kind FROM tasks WHERE file LIKE '%TASKS.md'",
         "SELECT file, line, status, kind FROM tasks WHERE file LIKE '%TASKS.md'")
    comp("doc_headings", "SELECT file, line FROM doc_headings", "SELECT file, line FROM sections")
    comp("bugs_docs", "SELECT file, line FROM bugs WHERE kind != 'commit'", "SELECT file, line FROM bugs WHERE kind != 'commit'")
    comp("bugs_commits", "SELECT sha FROM bugs WHERE kind='commit'", "SELECT sha FROM bugs WHERE kind='commit'")
    # aix keeps per-page help that a menu item already covers as kind 'help-menu' (the prototype drops it)
    comp("features", "SELECT kind, name, route FROM features", "SELECT kind, name, route FROM features WHERE kind != 'help-menu'")
    comp("db_tables", "SELECT file, line, tbl, op FROM db_tables", "SELECT file, line, tbl, op FROM db_tables")
    comp("symbols", "SELECT file, name FROM symbols WHERE exported=1", "SELECT file, name FROM symbols WHERE exported=1")
    comp("files", "SELECT path FROM files", "SELECT path FROM files")
    comp("commits", "SELECT sha FROM commits", "SELECT short FROM commits")


if __name__ == "__main__":
    main()
