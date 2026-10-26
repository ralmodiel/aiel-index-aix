#!/usr/bin/env python3
"""Mine Claude Code transcripts for the scripts and lookup commands Claude runs most, and how much output they cost.
Usage: bench/script-usage.py [--since 2026-10-08] [--projects ~/.claude/projects] [--top 40]
Reads every *.jsonl transcript (main sessions + subagents), pairs each Bash tool_use with its tool_result, and groups
commands by the script they run (scripts/*, e2e/*.mjs, bin tools) or by lookup pattern (grep -r,
rg, codemap, repoindex, find, cat/sed of source). Prints count, total and median output size (chars ~ tokens*4)."""
import argparse, json, os, re, glob, statistics, collections, datetime
ap = argparse.ArgumentParser(); ap.add_argument("--since", default="2026-10-08")
ap.add_argument("--projects", default=os.path.expanduser("~/.claude/projects")); ap.add_argument("--top", type=int, default=40)
a = ap.parse_args()
since = datetime.datetime.fromisoformat(a.since).timestamp()
SCRIPT = re.compile(r"((?:\./|bash |python3? |node |bun |sh )?(?:[\w./~-]*/)?(?:scripts|e2e|tools|bin)/[\w./-]+\.(?:sh|py|mjs|js|ts))")
TOOLS = ["codemap", "repoindex", "aix", "llm ", "labq", "outline", "tsg", "testsum", "logdigest", "diffsum", "jqsum", "gh ", "curl ", "psql", "docker "]
def key(cmd):
    c = cmd.strip()
    m = SCRIPT.search(c)
    if m:
        p = m.group(1).split()[-1]
        p = re.sub(r"^.*?/(scripts|e2e|tools|bin)/", r"\1/", p)
        return "script " + p
    for t in TOOLS:
        if re.search(r"(^|[;&|(]\s*|\s)" + re.escape(t.strip()) + r"(\s|$)", c): return "tool " + t.strip()
    if re.search(r"\bgrep\b[^|]*-\w*r|\brg\b", c): return "lookup grep -r/rg"
    if re.search(r"\b(sed -n|cat|head|tail)\b[^|]*\.(java|tsx?|py|md|json)", c): return "lookup read via shell"
    if re.search(r"\bfind\b", c): return "lookup find"
    if re.search(r"\bgit (log|show|diff|blame)\b", c): return "lookup git log/show/diff"
    return None
uses = collections.defaultdict(list)
files = [f for f in glob.glob(os.path.join(a.projects, "**", "*.jsonl"), recursive=True) if os.path.getmtime(f) >= since]
for f in files:
    pending = {}
    try:
        for line in open(f, errors="replace"):
            try: ev = json.loads(line)
            except Exception: continue
            msg = ev.get("message") or {}
            content = msg.get("content")
            if not isinstance(content, list): continue
            for b in content:
                if b.get("type") == "tool_use":
                    nm, inp = b.get("name"), b.get("input") or {}
                    if nm == "Bash":
                        k = key(inp.get("command", ""))
                        if k: pending[b.get("id")] = k
                    elif nm in ("Grep", "Glob"):
                        pending[b.get("id")] = "lookup " + nm + " tool"
                    elif nm == "Read":
                        pending[b.get("id")] = "lookup Read tool"
                    elif nm and nm.startswith("mcp__"):
                        pending[b.get("id")] = "mcp " + nm.split("__", 2)[-1]
                elif b.get("type") == "tool_result" and b.get("tool_use_id") in pending:
                    c = b.get("content")
                    n = len(c) if isinstance(c, str) else sum(len(x.get("text", "")) for x in (c or []) if isinstance(x, dict))
                    uses[pending.pop(b["tool_use_id"])].append(n)
    except OSError: pass
print(f"{len(files)} transcripts since {a.since}")
print(f"{'calls':>6} {'total KB':>9} {'median ch':>9}  what")
for k, v in sorted(uses.items(), key=lambda kv: -sum(kv[1]))[:a.top]:
    print(f"{len(v):6d} {sum(v)/1024:9.0f} {int(statistics.median(v)):9d}  {k}")
