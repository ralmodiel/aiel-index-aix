#!/usr/bin/env python3
"""Which files does Claude read most (Read tool + cat/sed/head/tail in Bash), and how many chars came back?
Usage: bench/read-usage.py [--since DATE] [--top N] [--adoption [--project DIR] [--window N]] — points aix at the files worth summarising/sectioning."""
import argparse, json, os, re, glob, collections, datetime
ap = argparse.ArgumentParser(); ap.add_argument("--since", default="2026-10-08"); ap.add_argument("--top", type=int, default=25)
ap.add_argument("--adoption", action="store_true", help="count aix adoption instead: counts only, no transcript content")
ap.add_argument("--project", help="--adoption: transcript dir (*.jsonl incl. subagents); required with --adoption")
ap.add_argument("--window", type=int, default=5, help="--adoption: an aix call within this many earlier tool calls counts as 'preceded'")
a = ap.parse_args()
if a.adoption and not a.project: ap.error("--adoption requires --project <transcript dir>")
since = datetime.datetime.fromisoformat(a.since).timestamp()
PATH = re.compile(r"(?:sed -n[^|;]*?|cat|head(?: -n? ?\d+)?|tail(?: -n? ?\d+)?)\s+['\"]?([\w./~-]+\.(?:java|tsx?|py|md|json|sql|sh|mjs|properties|yml))")

def adoption():
    """Fraction of repo-search / Read calls that an aix call preceded (within --window tool calls) or replaced.
    Native search = Grep tool, Bash grep -r/rg/ag/ack/git grep, Read. aiel-index call = Bash `aix <cmd>` or an MCP tool
    whose name contains 'aix'. 'replaced' = aix search-type calls / (those + native searches). Prints counts only."""
    SK = re.compile(r"(?:^|[;&|(\s])(?:\S*/)?aix\s+(?!-)([a-z]+)")
    SK_SEARCH = {"grep", "find", "text", "symbol", "code", "endpoint", "ask", "brief", "feature", "table", "script", "history", "bugs", "qa", "hints", "scope"}
    NATIVE = re.compile(r"(?:^|[;&|(\s])(?:rg|ag|ack|git\s+grep|e?grep\s+(?:-\S*[rR]\S*))\b")
    tot = collections.Counter(); sessions = 0; with_sk = 0
    for f in glob.glob(os.path.join(os.path.expanduser(a.project), "**", "*.jsonl"), recursive=True):
        if os.path.getmtime(f) < since: continue
        sessions += 1; calls = []; seen_sk = False
        for line in open(f, errors="replace"):
            try: ev = json.loads(line)
            except Exception: continue
            for b in (ev.get("message") or {}).get("content") or []:
                if not (isinstance(b, dict) and b.get("type") == "tool_use"): continue
                name = b.get("name") or ""; cmd = (b.get("input") or {}).get("command", "") if name == "Bash" else ""
                m = SK.search(cmd) if cmd else None
                if "aix" in name.lower() or m:
                    kind = "sk"; seen_sk = True
                    if "aix" in name.lower() or m.group(1) in SK_SEARCH: tot["sk_search"] += 1
                    tot["sk_total"] += 1
                elif name == "Grep" or (cmd and NATIVE.search(cmd) and "aix" not in cmd): kind = "grep"
                elif name == "Read": kind = "read"
                else: kind = "other"
                if kind in ("grep", "read"):
                    tot[kind] += 1
                    if any(c == "sk" for c in calls[-a.window:]): tot[kind + "_preceded"] += 1
                calls.append("sk" if kind == "sk" else kind)
        with_sk += seen_sk
    n = tot["grep"] + tot["read"]; pre = tot["grep_preceded"] + tot["read_preceded"]
    pct = lambda x, y: f"{100 * x / y:.1f}%" if y else "n/a"
    print(f"sessions={sessions} with_aix={with_sk} ({pct(with_sk, sessions)}) since={a.since} window={a.window}")
    print(f"aix calls={tot['sk_total']} (search-type {tot['sk_search']})")
    print(f"native Grep/grep-r: {tot['grep']}  preceded by aix: {tot['grep_preceded']} ({pct(tot['grep_preceded'], tot['grep'])})")
    print(f"native Read:        {tot['read']}  preceded by aix: {tot['read_preceded']} ({pct(tot['read_preceded'], tot['read'])})")
    print(f"grep+Read preceded by aix: {pre}/{n} ({pct(pre, n)})")
    print(f"replaced: aix search-type {tot['sk_search']} / (aix search-type + native grep) {tot['sk_search'] + tot['grep']} ({pct(tot['sk_search'], tot['sk_search'] + tot['grep'])})")
if a.adoption: adoption(); raise SystemExit
cnt = collections.Counter(); size = collections.Counter(); pend = {}
for f in glob.glob(os.path.expanduser("~/.claude/projects/**/*.jsonl"), recursive=True):
    if os.path.getmtime(f) < since: continue
    for line in open(f, errors="replace"):
        try: ev = json.loads(line)
        except Exception: continue
        for b in (ev.get("message") or {}).get("content") or []:
            if not isinstance(b, dict): continue
            if b.get("type") == "tool_use":
                inp = b.get("input") or {}
                if b.get("name") == "Read" and inp.get("file_path"): pend[b["id"]] = inp["file_path"]
                elif b.get("name") == "Bash":
                    m = PATH.search(inp.get("command", ""))
                    if m: pend[b["id"]] = m.group(1)
            elif b.get("type") == "tool_result" and b.get("tool_use_id") in pend:
                p = re.sub(r"^.*?/(?:workspaces|work|src|repos)/[^/]+/", "", pend.pop(b["tool_use_id"]))
                c = b.get("content"); n = len(c) if isinstance(c, str) else sum(len(x.get("text", "")) for x in (c or []) if isinstance(x, dict))
                cnt[p] += 1; size[p] += n
print(f"{'reads':>6} {'KB':>7}  file")
for p, n in sorted(size.items(), key=lambda kv: -kv[1])[:a.top]: print(f"{cnt[p]:6d} {n/1024:7.0f}  {p}")
