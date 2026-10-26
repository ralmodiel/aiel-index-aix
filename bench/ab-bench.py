#!/usr/bin/env python3
"""A/B benchmark: does aix save Claude tokens and time, or slow it down?
Runs the same lookup tasks through headless Claude Code twice: arm A = plain tools (Read/Grep/Glob/Bash read-only),
arm B = the same tools + the aix MCP server (and one line telling Claude to try it first). Records tokens,
cost, turns, wall time and whether the answer contains the expected facts.
Usage: bench/ab-bench.py --repo REPO --db INDEX_DB --tasks TASKS.json [--model sonnet] [--only id,...] [--out DIR]
The index must already be built (scripts/aix-refresh.sh REPO --db INDEX_DB). Never writes into REPO.
Reported per pair and per arm, as two separately labelled windows (never mixed), with tool calls counted for every
client tool (aix and file tools alike) and quality (expected facts) kept apart from efficiency:
  full-session tokens = everything the session paid (input + cache create + cache read + output, all turns);
  answering tokens    = full-session minus the fixed prefix (system prompt, tool schemas, question) that every turn
                        re-reads: the first turn's input times the number of turns. It is what exploring and answering
                        added, measured from the per-turn usage of the same session.
Ratios are A/B (baseline / aix); N/A when a denominator is 0; no pseudocounts; raw paired counts are printed.
Arm B variants (one lever at a time; all need --isolate): --hooks bin (the hooks of --bin, not the repo's installed
ones), --env K=V (lever switches such as AIX_PREANSWER=off, AIX_MCP_TOOLS=intent), --skill DIR|none, --claude-md FILE
(an instruction block loaded as memory), --no-hint. --arms B --baseline OLD/results.jsonl reuses an earlier run's A
rows (same tasks, same model) instead of paying for arm A again."""
import argparse, json, os, subprocess, sys, time, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True); ap.add_argument("--db", required=True)
ap.add_argument("--tasks", required=True, help="JSON list of {id, q, expect[]}; see bench/ab-tasks.example.json")
ap.add_argument("--model", default="sonnet"); ap.add_argument("--only", default="")
ap.add_argument("--bin", default=str(ROOT / "target/release/aix"))
ap.add_argument("--out", default="/tmp/aix-ab"); ap.add_argument("--max-turns", type=int, default=25)
ap.add_argument("--reps", type=int, default=1)
ap.add_argument("--isolate", action="store_true", help="clean per-arm config dirs (login only); arm A without aix on PATH")
ap.add_argument("--b-mode", choices=["mcp", "cli"], default="mcp", help="arm B reaches aix via the MCP tool or via `aix` on Bash")
ap.add_argument("--arms", choices=["A", "B", "AB"], default="AB", help="which arms to run (B alone: pair with --baseline)")
ap.add_argument("--baseline", help="results.jsonl of an earlier run: its arm A rows (same task ids) are the baseline")
ap.add_argument("--hooks", choices=["project", "bin", "none"], default="bin",
                help="arm B hooks: the repo's own settings (project+local), the hooks of --bin (session card, prompt, pretool), or none")
ap.add_argument("--env", action="append", default=[], help="K=V for arm B (claude, its hooks and the MCP server)")
ap.add_argument("--skill", default=str(ROOT / "integrations/claude-code/skills/aix"), help="skill dir for arm B, or none")
ap.add_argument("--claude-md", help="arm B: this file is loaded as the session's memory (CLAUDE.md)")
ap.add_argument("--no-hint", action="store_true", help="arm B without the appended one-line hint")
a = ap.parse_args()
import shutil
CLAUDE = shutil.which("claude") or "claude"   # absolute: arm A may run with aix's folder off PATH
out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
tasks = json.load(open(a.tasks))
if a.only: tasks = [t for t in tasks if t["id"] in a.only.split(",")]
benv = dict(kv.split("=", 1) for kv in a.env)
mcp_b = out / "mcp-aix.json"; mcp_a = out / "mcp-none.json"
mcp_b.write_text(json.dumps({"mcpServers": {"aix": {"type": "stdio", "command": a.bin, "args": ["mcp"],
                                                         "env": {"AIX_DB": a.db, **benv}}}}))
mcp_a.write_text(json.dumps({"mcpServers": {}}))
# --hooks bin: the three hooks aix ships, run from --bin (the card directly: the shipped session-start script also
# starts the background refresher, which a benchmark must not do)
BASE_TOOLS = ["Read", "Grep", "Glob", "Bash(grep:*)", "Bash(rg:*)", "Bash(git log:*)", "Bash(git show:*)", "Bash(ls:*)", "Bash(find:*)", "Bash(cat:*)", "Bash(head:*)", "Bash(sed -n:*)", "Bash(wc:*)"]
HINT_B_CLI = ("This repo is indexed by `aix` (CLI on PATH; run it with Bash: `aix <command> <args>`): routes, menus, "
              "endpoints+roles, API calls, UI strings, e2e specs, scripts, tasks, QA findings, git history. Run it first "
              "(commands: brief, endpoint, text, symbol, script, tasks, bugs, qa, feature, find, ask, history, impact), "
              "then read code only if needed.")
HINT_B = ("A `aix` MCP tool indexes this repo (routes, menus, endpoints+roles, API calls, UI strings, e2e specs, "
          "scripts, tasks, QA findings, git history). Call it first (commands: brief, endpoint, text, symbol, script, "
          "tasks, bugs, qa, feature, find, ask, history, impact), then read code only if needed.")
def run(task, arm, rep):
    cmd = [CLAUDE, "-p", task["q"], "--model", a.model, "--output-format", "stream-json", "--verbose", "--max-turns", str(a.max_turns),
           "--no-session-persistence", "--strict-mcp-config", "--mcp-config", str(mcp_b if arm == "B" else mcp_a),
           "--permission-mode", "default", "--allowedTools",
           *(BASE_TOOLS + ((["mcp__aix"] if a.b_mode == "mcp" else ["Bash(aix:*)"]) if arm == "B" else []) + (["Skill"] if arm == "B" else []))]
    if arm == "B" and not a.no_hint: cmd += ["--append-system-prompt", HINT_B if a.b_mode == "mcp" else HINT_B_CLI]
    # The repo's .claude/settings.local.json carries the aix hooks (session card, answer-in-hint/deny): arm A must
    # not load it, or the "without aix" arm still gets aix answers. Without --isolate arm B runs with the installed
    # setup; with it, arm B's hooks run the --bin build (below).
    env = dict(os.environ, AIX_DB=a.db, PATH=str(pathlib.Path(a.bin).parent) + os.pathsep + os.environ["PATH"])
    if arm == "B": env.update(benv)
    if a.isolate:
        # both arms: a clean config dir holding only the login, so neither loads the user's CLAUDE.md, plugins,
        # permissions or user hooks; arm A also gets no aix on PATH and no project-local settings (the aix hooks)
        cfg = out / f"config-{arm}"
        cfg.mkdir(exist_ok=True)
        cred = pathlib.Path.home() / ".claude" / ".credentials.json"
        if cred.exists() and not (cfg / ".credentials.json").exists():
            (cfg / ".credentials.json").write_bytes(cred.read_bytes())
            os.chmod(cfg / ".credentials.json", 0o600)
        if arm == "B":
            # what aix ships for Claude Code: the skill (aix-init puts it in the repo's .claude/skills; here it sits
            # in the clean config dir, which is only read with the "user" setting source) and optional memory
            sk = pathlib.Path(a.skill)
            if a.skill != "none" and sk.is_dir() and not (cfg / "skills/aix").exists():
                shutil.copytree(sk, cfg / "skills/aix")
            if a.claude_md and not (cfg / "CLAUDE.md").exists():
                shutil.copy(a.claude_md, cfg / "CLAUDE.md")
        env["CLAUDE_CONFIG_DIR"] = str(cfg)
        if arm == "A":
            cmd += ["--setting-sources", "project"]
        elif a.hooks == "project":   # the repo's local settings: the installed hooks and binary
            cmd += ["--setting-sources", "user,project,local"]
        else:   # the repo's local settings (installed hooks) stay out; --hooks bin brings this build's
            cmd += ["--setting-sources", "user,project"]
            if a.hooks == "bin":
                # the hooks run THIS build (--bin), not whatever is installed: the shipped hook scripts are copied next to
                # an `aix` link to --bin (they put their own folder first on PATH) and passed with --settings; the repo's
                # local settings (the installed hooks) are not loaded. aix-refresh / aix-watch are no-ops here: the
                # index is a fixed copy.
                hb = out / "hooks-B"
                hb.mkdir(exist_ok=True)
                src = pathlib.Path(__file__).resolve().parent.parent / "integrations/claude-code/hooks"
                names = {"SessionStart": "aix-session-start.sh", "UserPromptSubmit": "aix-prompt-submit.sh", "PreToolUse": "aix-pretool-nudge.sh"}
                for n in names.values():
                    (hb / n).write_bytes((src / n).read_bytes()); os.chmod(hb / n, 0o755)
                for n in ("aix-refresh", "aix-watch"):
                    (hb / n).write_text("#!/bin/sh\nexit 0\n"); os.chmod(hb / n, 0o755)
                if (hb / "aix").is_symlink() or (hb / "aix").exists(): (hb / "aix").unlink()
                (hb / "aix").symlink_to(pathlib.Path(a.bin).resolve())
                hooks = {ev: [{**({"matcher": "Bash|PowerShell|Grep|Glob|Read"} if ev == "PreToolUse" else {}),
                               "hooks": [{"type": "command", "command": str(hb / n), "timeout": 20 if ev == "SessionStart" else 5}]}]
                         for ev, n in names.items()}
                (out / "settings-B.json").write_text(json.dumps({"hooks": hooks}))
                cmd += ["--settings", str(out / "settings-B.json")]
        if arm == "A":
            keep = [d for d in os.environ["PATH"].split(os.pathsep) if d and not (pathlib.Path(d) / "aix").exists()]
            env["PATH"] = os.pathsep.join(keep)
    elif arm == "A":
        cmd += ["--setting-sources", "user,project"]
    t0 = time.time()
    if arm == "B" and a.b_mode == "cli": cmd[cmd.index("--mcp-config") + 1] = str(mcp_a)
    p = subprocess.run(cmd, cwd=a.repo, capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL, env=env)
    wall = time.time() - t0
    r, tools, turn_usage, hook_ctx = None, [], {}, []
    for line in p.stdout.splitlines():
        try: ev = json.loads(line)
        except Exception: continue
        if ev.get("type") == "assistant":
            m = ev.get("message") or {}
            if m.get("usage"): turn_usage[m.get("id") or len(turn_usage)] = m["usage"]   # one per turn (blocks repeat it)
            for blk in (ev.get("message") or {}).get("content") or []:
                if blk.get("type") == "tool_use":
                    inp = blk.get("input") or {}
                    arg = inp.get("command") or inp.get("pattern") or inp.get("file_path") or inp.get("args") or inp.get("skill") or inp.get("symbol") or ""
                    nm = blk['name'].replace('mcp__aix__', 'sk:')
                    if nm == "Bash" and str(arg).lstrip().startswith("aix"): nm = "sk-cli"
                    tools.append(f"{nm}({str(arg)[:60]})")
        elif ev.get("type") == "system" and ev.get("subtype") == "hook_response":
            o = ev.get("output") or ""
            if o.strip(): hook_ctx.append(f"{ev.get('hook_event')}:{len(o)}B")
        elif ev.get("type") == "result":
            r = ev
    if r is None: r = {"result": p.stdout[-2000:] + p.stderr[-2000:], "is_error": True}
    u = r.get("usage") or {}
    ans = r.get("result") or ""
    hits = sum(1 for e in task["expect"] if e.lower() in ans.lower())
    full = sum(u.get(k, 0) or 0 for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"))
    turns_u = list(turn_usage.values())
    prefix = 0
    if turns_u:
        f = turns_u[0]
        prefix = sum(f.get(k, 0) or 0 for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")) * len(turns_u)
    answering = max(full - prefix, 0) if turns_u else None   # None: the session exposed no per-turn usage (N/A)
    row = {"id": task["id"], "arm": arm, "rep": rep, "wall_s": round(wall, 1), "turns": r.get("num_turns"),
           "in": u.get("input_tokens", 0), "cache_create": u.get("cache_creation_input_tokens", 0),
           "cache_read": u.get("cache_read_input_tokens", 0), "out": u.get("output_tokens", 0),
           "cost_usd": r.get("total_cost_usd"), "expect_hit": f"{hits}/{len(task['expect'])}",
           "full_tokens": full, "answer_tokens": answering, "tool_calls": len(tools), "error": r.get("is_error"), "tools": tools,
           "aix_calls": sum(1 for t in tools if t.startswith("sk")), "skill_calls": sum(1 for t in tools if t.startswith("Skill(")),
           "hook_ctx": hook_ctx, "answer": ans[:600]}
    with open(out / "results.jsonl", "a") as f: f.write(json.dumps(row) + "\n")
    print(json.dumps({k: v for k, v in row.items() if k not in ("answer", "tools")}), "|", " ".join(tools)[:300], flush=True)
    return row
rows = []
arms = tuple(a.arms)
for rep in range(a.reps):
    for t in tasks:
        for arm in (arms if rep % 2 == 0 else arms[::-1]):   # alternate order: cache warmth evens out
            rows.append(run(t, arm, rep))
if a.baseline and "A" not in arms:
    # the earlier run's A rows for these tasks: the k-th A row of a task is the baseline of this run's k-th B row
    seen = {}
    for l in open(a.baseline):
        r = json.loads(l)
        if r["arm"] != "A" or r["id"] not in {t["id"] for t in tasks}: continue
        r["rep"] = seen.get(r["id"], 0); seen[r["id"]] = r["rep"] + 1
        if r["rep"] < a.reps: rows.append(r)
if {r["arm"] for r in rows} != {"A", "B"}: sys.exit(0)
def tot(arm, k): return sum((r.get(k) or 0) for r in rows if r["arm"] == arm)
def ratio(x, y): return "N/A" if not y else f"{x / y:.2f}"
def pct(x, y): return "N/A" if not x else f"{100 * (x - y) / x:.0f}%"
def hit(arm): return f"{sum(int(r['expect_hit'].split('/')[0]) for r in rows if r['arm'] == arm)}/{sum(int(r['expect_hit'].split('/')[1]) for r in rows if r['arm'] == arm)}"
print("pairs (A = baseline, B = aix): id | full-session A/B | answering A/B | tool calls A/B | aix calls B | quality A/B")
for t in tasks:
    pa = [r for r in rows if r["id"] == t["id"] and r["arm"] == "A"]; pb = [r for r in rows if r["id"] == t["id"] and r["arm"] == "B"]
    for ra, rb in zip(pa, pb):
        aw = "N/A" if ra["answer_tokens"] is None or rb["answer_tokens"] is None else f"{ra['answer_tokens']}/{rb['answer_tokens']}"
        print(f"  {t['id']} | {ra['full_tokens']}/{rb['full_tokens']} | {aw} | {ra['tool_calls']}/{rb['tool_calls']} | {rb.get('aix_calls', 0)} | {ra['expect_hit']} {rb['expect_hit']}")
for win, k in (("full-session", "full_tokens"), ("answering", "answer_tokens")):
    # a window counts only where both arms of every pair report it
    ok = all(r[k] is not None for r in rows)
    if not ok:
        print(f"{win} tokens: N/A (a session did not report per-turn usage)"); continue
    x, y = tot("A", k), tot("B", k)
    print(f"{win} tokens: A {x}  B {y}  ratio A/B {ratio(x, y)}  reduction {pct(x, y)}")
x, y = tot("A", "tool_calls"), tot("B", "tool_calls")
print(f"tool calls: A {x}  B {y}  ratio A/B {ratio(x, y)}  reduction {pct(x, y)}")
nb = sum(1 for r in rows if r["arm"] == "B")
print(f"arm B uptake: aix calls {tot('B', 'aix_calls')} in {nb} sessions ({sum(1 for r in rows if r['arm'] == 'B' and r.get('aix_calls'))} used it), "
      f"Skill calls {tot('B', 'skill_calls')}; quality A {hit('A')}  B {hit('B')}")
if a.reps > 1:   # the spread between repetitions: a ratio inside it is noise, not an effect
    for k in ("full_tokens", "answer_tokens"):
        per = []
        for i in range(a.reps):
            rr = [r for r in rows if r.get("rep", 0) == i]
            xa = sum(r[k] or 0 for r in rr if r["arm"] == "A"); xb = sum(r[k] or 0 for r in rr if r["arm"] == "B")
            per.append(ratio(xa, xb))
        print(f"{k} ratio A/B per rep: {' '.join(per)}")
for arm in ("A", "B"):
    tok = tot(arm, "in") + tot(arm, "cache_create") + tot(arm, "cache_read") + tot(arm, "out")
    print(f"arm {arm}: tasks {sum(1 for r in rows if r['arm']==arm)}  wall {tot(arm,'wall_s'):.0f}s  turns {tot(arm,'turns')}  "
          f"tokens {tok} (new input {tot(arm,'in')+tot(arm,'cache_create')}, cache read {tot(arm,'cache_read')}, out {tot(arm,'out')})  cost ${tot(arm,'cost_usd'):.3f}")
