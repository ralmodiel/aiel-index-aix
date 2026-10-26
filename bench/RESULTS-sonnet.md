# Getting Claude Code on Sonnet to use aix

Question: in headless Claude Code (`claude -p`, Sonnet), an earlier A/B run gave arm B (aix skill + hooks + a one-line
hint) **0 aix calls in 12 sessions**, 0 Skill invocations, 91 ignored PreToolUse nudges, and 12% more tokens than plain
tools. This file records why, and which levers change it.

Setup: `bench/ab-bench.py --isolate --arms B --baseline <earlier run>/results.jsonl`, Sonnet, a ~1300-file Java +
TypeScript web app (index of 801 endpoints, 116 routes), 4 multi-step tasks: endpoints that reach a guard method
(guard-endpoints), endpoints affected by a service method (cancel-impact), trace a UI action to the backend
(unlock-trace), callers of a method (cancel-callers). Baseline A = the earlier run's arm A (plain Read/Grep/Glob/Bash,
2 reps, mean per task). One rep per lever, 2 reps for the combination. PreToolUse behaviour was left as shipped (it is
measured separately).

## 1. The earlier 0-call result was mostly the benchmark setup

Two defects, both now fixed:

- **The skill never loaded.** `--isolate` copied it into the clean config dir (user scope) but ran arm B with
  `--setting-sources project,local`, which skips user-scope skills. The session's init event listed no `aix` skill.
  B now runs with `user,project,local` (the config dir is clean, so "user" holds only what the bench puts there).
- **The session card told the model to use grep.** The scratch checkout has no `.aix/initialized` (its index is
  external, via `AIX_DB`), so the shipped SessionStart script printed "no index for this checkout ... until then use
  grep/Read". `aix-session-start.sh` now treats an existing `AIX_DB` as initialized. The bench's `--hooks bin` runs
  the card, prompt and pretool hooks of the binary under test instead of whatever is installed.

With the setup fixed and nothing else changed (B0), Sonnet used aix in every session.

## 2. Levers, one at a time (arm B, 1 rep, 4 tasks)

Tokens are the sum over the 4 tasks; A/B > 1 means aix is cheaper. Answering = full minus the fixed prefix re-read
each turn. Quality = expected facts found.

| variant | aix calls / session | sessions using aix | Skill calls | full tokens (A/B) | answering (A/B) | cost | turns / session | quality |
|---|---|---|---|---|---|---|---|---|
| A (plain tools, 2 reps) | - | - | - | 633k | 139k | $0.349 | 8.5 | 26/26 |
| earlier B (broken setup) | 0.00 | 0% | 0 | 735k (0.86) | 164k (0.85) | $0.391 | 8.4 | 26/26 |
| B0: setup fixed, CLI, hint | 3.25 | 100% | 0 | 666k (0.95) | 93k (1.50) | $0.364 | 6.0 | 13/13 |
| B0 without the hint | 3.25 | 100% | 0 | 665k (0.95) | 99k (1.41) | $0.379 | 6.0 | 13/13 |
| L1 prompt pre-answer | 1.00 | 50% | 0 | 380k (1.67) | 67k (2.07) | $0.317 | 3.8 | 13/13 |
| B0 over MCP (generic `aix` tool) | 5.25 | 100% | 0 | 631k (1.00) | 103k (1.35) | $0.359 | 8.2 | 13/13 |
| L2 intent-named MCP tools | 3.75 | 100% | 0 | 542k (1.17) | 83k (1.68) | $0.386 | 7.8 | 13/13 |
| L3 rules block, no hint | 3.00 | 100% | 0 | 427k (1.48) | 29k (4.82) | $0.290 | 4.0 | 13/13 |
| L4 skill description by question shape | 3.25 | 100% | 0 | 539k (1.17) | 92k (1.52) | $0.307 | 5.0 | 13/13 |
| L5 question-shaped session card | 1.75 | 100% | 0 | 308k (2.06) | 25k (5.58) | $0.255 | 3.0 | 13/13 |

Readings (one rep each, so differences under ~15% are noise; B0 with and without the hint agree within 7%):

- **L1 pre-answer** (UserPromptSubmit): on the two tasks that name a `Class.method` with a who-calls / which-endpoints
  question, the hook's answer was enough: 1 turn, no tool calls, about 26k tokens against 42-271k for plain tools. On
  the trace task it said nothing (no name it could resolve), as intended. "aix calls" drop because the answer arrives
  before the first turn.
- **L3 rules block** and **L5 card wording** are the strongest single levers on tasks the pre-answer cannot serve:
  the model went straight to `aix impact` / `aix endpoint` / `aix trace` instead of grepping, and on the trace task it
  answered with 2 calls (78k tokens against 123k for plain tools).
- **L2** helps a little: the named tools were picked (`aix_impact`, `aix_callers`), but MCP tools are deferred behind
  ToolSearch in current Claude Code, so every MCP session pays an extra search turn first. Within noise of B0-MCP.
- **L4**: Sonnet did not invoke the Skill tool in any of the 40 sessions of this study, with any description, even
  with the skill loaded and `Skill` allowed. In `-p` mode the skill's description is at most a hint in the listing;
  the instructions in the card or the rules file are what it follows. The description was left as it was.
- The appended hint (a bench artifact) makes no difference once the skill and the real card are present.

## 3. Combination: L1 + L3 + L5, CLI, no hint (2 reps)

| task | A full (2 reps) | B full (2 reps) | B aix calls | quality A / B |
|---|---|---|---|---|
| guard-endpoints | 229,630 / 145,889 | 76,362 / 79,722 | 2 / 2 | 4/4 4/4 |
| cancel-impact | 246,283 / 271,020 | 25,998 / 26,006 | 0 / 0 (pre-answered) | 2/2 2/2 |
| unlock-trace | 123,596 / 122,242 | 117,916 / 117,828 | 3 / 3 | 4/4 4/4 |
| cancel-callers | 41,979 / 85,755 | 25,431 / 25,450 | 0 / 0 (pre-answered) | 3/3 3/3 |

- full-session tokens: A 1,266,394, B 494,713, **ratio A/B 2.56** (per rep 2.61, 2.51)
- answering tokens: A 278,746, B 49,646, **ratio A/B 5.61** (per rep 5.28, 6.05)
- tool calls 60 -> 10, turns 68 -> 18, wall 201 s -> 78 s, cost $0.698 -> $0.368; quality 26/26 on both sides.

## 4. What ships

| lever | state | switch |
|---|---|---|
| L1 pre-answer (`aix hook prompt`) | on | `AIX_PREANSWER=off`, or `preanswer = "off"` in `.aix/config.toml`; `AIX_PREANSWER_MS` (300) |
| L3 rules block | installed by `aix-init` as `.claude/rules/aix.md` (515 bytes; an edited copy is kept, uninstall removes an unmodified one) | delete the file |
| L5 card wording | on | `AIX_CARD_STYLE=classic` restores the command list |
| L2 intent-named MCP tools | off | `AIX_MCP_TOOLS=intent` (7 tools, 2.5 KB of schema, less than the generic tool alone) |
| L4 skill description | unchanged | - |

Pre-answer rules (precision first): it acts only on a typed prompt (no pastes over 12 lines or 2 KB, no slash
commands, no agent/harness markers), only when the question has a known shape (who calls / which endpoints, what
breaks / trace / where is this text) and names something the index resolves to exactly one definition (`Class.method`,
a camelCase method with a single definition, `METHOD /path`, a `*_table` name, a quoted UI string). It runs at most two
queries without refreshing the index (`impact X --depth 4`, `callers X`, `endpoint`, `trace ... --up`, `text`), keeps
1.5 KB of whole lines, labels the block with the exact command, and stays silent on anything else.

## 5. Open points

- `aix impact` stops at depth 3 by default and does not say that callers continue beyond it. On cancel-impact two more
  endpoints sit at depth 4, and sessions without the pre-answer walked the chain call by call (one session: 7 aix calls,
  then grep). The pre-answer uses `--depth 4`; `impact` itself should report the unexplored frontier.
- Re-run the levers with 2+ reps on more task shapes (tables, UI text, routes) before treating the single-rep rows as
  settled.

## 4. Landed build, full run (6 tasks x 2 reps, both arms fresh, --isolate, CLI, rules as memory, no hint)

| | A (plain tools) | B (aix as shipped) | A/B |
|---|---|---|---|
| full-session tokens | 2,196,202 | 869,510 | 2.53 (per rep 2.23 / 2.85) |
| answering tokens | 426,290 | 71,646 | 5.95 (per rep 5.39 / 6.56) |
| tool calls | 107 | 20 | 5.35 |
| turns | 119 | 32 | |
| wall time | 276 s | 112 s | |
| cost | $1.068 | $0.597 | |
| quality (expected facts) | 39/40 | 40/40 | |

B made 15 aix calls in 12 sessions; 5 sessions needed no tool at all (the prompt pre-answer carried the answer).
The Skill tool was never invoked; the pre-answer, the session card, the rules file and the hook answers did the work.
Smallest gain: "which roles see a page but cannot order" (UI reading, ~1.0x); largest: "what breaks if X changes" (6-14x).
