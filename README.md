# aiel-index

A local, always-fresh **project knowledge index** for Claude Code on big repos. One Rust binary, `aix`:
a CLI plus a stdio MCP server. It answers the lookups that eat most tokens on a large codebase in one
bounded call each: which page is behind a menu label and who may see it, which endpoints it calls with what
roles, where a UI string lives and which test quotes it, whether something broke here before, whether a
script already exists, and what the current diff touches.

- Facts are parsed (tree-sitter, line parsers, git), never generated. LLM output is optional and labelled.
- One SQLite file per repo: plain tables for exact joins, FTS5 (porter + unicode61, bm25) for text, f32
  embeddings as BLOBs for meaning-based search, fused with bm25 by reciprocal-rank fusion.
- Incremental: each query stat-checks the tree, re-extracts only changed files (blake3), and refreshes git
  history when HEAD moves. On a 1,260-file repo: full build ~2.5 s, no-op check ~16 ms, one edited file ~0.4 s; on a 60,000-file repo: full build ~80 s, one edited file ~4 s.
  A query that finds more than 300 changed files (a branch switch, a formatter run; `AIX_INLINE_REFRESH_MAX`)
  answers from the index at once and leaves the refresh to a background `aix update`; meanwhile `code` and
  `outline` read a changed file as it is now.
- Memory and disk: a full build peaks at about 0.66 GB of RAM on 40,000 files and 3.2 GB on the Linux kernel
  (72,000 files, 4.7M members; 0.1-0.5 GB up to 4,000 files). `aix update --max-memory 2G` (`AIX_MAX_MEMORY`;
  default: half the available memory) caps workers and SQLite's cache and resolves the code graph in batches when
  it would not fit: the kernel then builds in 1.96 GB with the same edges. The index is about 3-13x the indexed
  source bytes (40 MB for 3,000 files, 450-660 MB for 40,000-60,000, 5.8 GB for the kernel). Numbers per repo:
  `bench/corpus/RESULTS.md`. The first query on a big unindexed repo waits at most 5 s for the build
  (`AIX_COLD_BUILD_WAIT_MS`), then says how far it is; `aix update --progress` prints progress on stderr.
- Private and local: the only network calls go to your own OpenAI-compatible endpoints (embeddings, and
  optionally a chat model for summaries). If the embedder is down, search falls back to keywords and says so.

## Logs, pastes and attached files

`aix logs add <path|dir|glob>` registers log files (repo-local `.aix/logs.toml`, 0600); aix ingests them incrementally (rotation and
copytruncate aware, multi-line stack traces grouped), redacts every line before it is stored (separate `.aix/logs.db`, 0600), groups
messages by template, links stack frames to indexed code and the owning endpoint, and enforces budgets (global/per-log/rows/retention,
oldest and lowest level pruned first, hourly aggregates kept). `aix logs errors|grep|show|tail|mark|since-mark|await|alert*|suggest|prune|rm`;
`aix paste ...` and `aix attach` do the same for pasted blocks and files the user names (UserPromptSubmit hook `aix-hook-prompt`);
`aix wait` waits for indexing. The MCP tool runs read verbs only (list, errors, grep, show, tail, since-mark, alerts, `paste list|show|grep|errors|frames`);
add, rm, prune, watch, unwatch, mark, alert add/rm, attach and `paste add|rm|prune` are CLI-only (`unwatch` is auto-allowed on the CLI, the rest ask).
Privacy guarantees: nothing raw is stored, hashed or printed; paths are checked (owner, no symlink escape, no /etc /proc /sys
~/.ssh ~/.aws ~/.gnupg, no credential-like names, no devices/FIFOs); shell/REPL history files, keyrings, `~/.config/gh|gcloud`, `~/.azure`,
`~/.terraform.d`, browser profiles, password-manager files and mail spools are never attached, registered or tailed; other files under
hidden folders of `$HOME` need `aix attach --allow-dotfile` / `aix logs add --allow-dotfile`. Every path aix shows or stores is
redacted (`~` for home, secret-looking components as `***`). The prompt hook acts only on text you typed: a prompt carrying agent or harness
markers (`<system-reminder>`, `<task-notification>`, `[Subagent hand-back]`, `<agent-message`, `[SYSTEM NOTIFICATION`,
`<cross-session-message`) is never pasted or attached from, and a hidden-folder path in your own prompt only gets a one-line
`aix attach --allow-dotfile` suggestion. Pastes of 4 KB or more are ingested by a worker (payload in a private 0600 temp file,
deleted once read), so the hook stays under ~50 ms; the paste budget is enforced after every ingest. Regexes (`grep`, `errors -x/--only`,
`await`, `alert --when`, `tail --until`) match the message, the entry body, `<LEVEL> <msg>` and `<LEVEL> <logger> <msg>`
(`Started|ERROR`, `^WARN`); retention counts from arrival time. No network listener; local only.

`aix privacy-check [--fix] [--deep] [--json]` scans what aix holds and reports one line per problem with a severity and the fix: stored text
the current redactor would still change (index.db, logs.db, pastes.db), deny-listed or hidden-folder paths, agent-originated pastes, tracked
files that look private (names and `file:line` only; your deny list from `$AIX_PRIVATE_MARKERS` or `~/.config/aix/private-markers`, applied only in a repo that ships `scripts/check-private.sh` or sets `private_markers = true` in `.aix/config.toml`), permissions,
exceeded budgets, watches on files outside the repo; it notes an active `include` option. `include = ["notes/**/*.md", ...]` in `.aix/config.toml` (default empty) indexes gitignored files matching those repo-relative globs (scratch notes, scripts): text types only, 256 KB a file, at most 5000 files (the rest reported as skipped), secret names refused and content redacted as usual, symlinks never followed, never inside `node_modules`/`.git`/`target`/`dist`/`build` or a nested checkout; `files` says when it is on. It never prints a secret. `--fix` purges, chmods and unwatches (every step listed, then a
vacuum); the exit status is 1 while a HIGH finding remains. `aix-init` runs it once, the session card adds one line when something is found,
and each paste, attachment or log ingest checks its new rows.

`aix ignore-check [--json] [--suggest]` is a read-only .gitignore preflight (exit 0 clean, 1 findings): no .gitignore or no git repo, entries normally ignored for the detected stacks (`STACKS` in `aix-core/src/ignorecheck.rs`: `node_modules/`, `target/`, `.env*` ...), untracked build output, caches, logs, data, large and secret-like files (names only), tracked files that should not be. aix never writes .gitignore (`--suggest` prints the lines to append). Until the user decides, `aix-init` exits 3 and the first build in `<repo>/.aix` (or `update --full`) exits 2 with a STOP block; `--accept-ignore` records the decision in `.aix/config` (asked again only for new findings; afterwards a new high one is one line in `aix card` and `stats`). A linked `git worktree`, a local clone (`origin` is a path) or a clone nested inside a checkout of the same remote inherits its parent's acceptance when its findings are the same; a symlinked dependency dir (a worktree's `node_modules` linked to the main tree's) is not a finding.

**Clones and worktrees start from the parent's index**: the first query in such a checkout (no `<repo>/.aix/index.db` yet) copies the parent's index (`VACUUM INTO`, a consistent snapshot) and refreshes only what differs (same content = same hash: a stat and a hash per file, no parse), so `aix --repo $PWD stats` in a fresh scratch clone answers in about the time of one refresh instead of a full build. `AIX_SEED=0` builds from scratch. Not gated: an explicit `--db`/`AIX_DB` outside `<repo>/.aix` (benches, evals, tooling) and `AIX_ACCEPT_IGNORE=1` (CI, test harnesses).

## Setup (two commands)

```sh
git clone <aiel-index> && aiel-index/scripts/install.sh   # once per machine (needs Rust: rustup.rs)
cd your/repo && aix-init                                       # once per repo
```

`aix-init` builds the index, adds the skill, `/brief` `/impact` `/bugs`, the SessionStart and PreToolUse
hooks and allow rules for the read-only `aix <query>` commands (not `install-git-hook`) to `.claude/settings.local.json` (merged, never overwritten;
`--shared` writes `.claude/settings.json` for the whole team), installs a post-commit hook and starts the
auto-refresh watcher. Start Claude Code in the repo and it uses aix from the first prompt.
Options: `--mcp` (also register the MCP server; the CLI measured faster), `--no-git-hook`, `--no-watch`,
`--uninstall` (removes everything it added, including the index). Re-run `install.sh` to upgrade; the clone
can be deleted after installing.

Windows (no bash or python3 needed; Windows PowerShell 5.1 or pwsh 7):

```powershell
git clone <aiel-index>; powershell -ExecutionPolicy Bypass -File aiel-index\scripts\install.ps1   # once per machine
cd your\repo; aix init                                                                             # once per repo
```

`install.ps1` installs `aix.exe` into `%USERPROFILE%\.cargo\bin`, the skill files, and `aix-init` / `aix-refresh` /
`aix-watch` shims (PowerShell, cmd and Git Bash) for the subcommands `aix init`, `aix refresh` and `aix watch`,
which do on every OS what the bash scripts do, with the same options, lock files and records. `aix init`
registers the hooks in exec form (Claude Code runs `aix.exe hook ...` directly, no shell per tool call) and on
Windows also writes the allow rules as `PowerShell(...)` rules. Open a new terminal after a first Rust install.
Data sets (`cmd 2>&1 | aix put gate -`, then `aix grep ERROR @gate`): `aix put` and `aix sets rm` ask first unless the repo opted in with `aix-init --allow-data` (undo: `--no-allow-data`); `aix sets prune` always asks on the CLI (over MCP it follows allow_data like rm).

## Quick start

```sh
cd your/repo
aix-refresh                         # first build if aix-init has not run yet (no embedding; add --embed 30 for an embedder)
aix brief /orders                   # everything about a route before editing it
aix text "Cancel order"             # where a UI string lives + which tests quote it (numbers, amounts, dates and times in a query copied from the screen match `{...}` / `${...}` in the string)
aix impact                          # what your uncommitted diff affects
aix stats --savings                 # what the index holds and what it saved
aix stats --savings --currentweek 28%   # ...and what that is against the 28% of your week you have used so far
```

`stats --savings` also prints the measurement window. Pass `--currentweek N%` (your real usage so far this week, from your
plan's usage page) and the last line says how many points of your week the saving was, what that is as a share of
your usage, and where the week would stand without aix. That needs a week size in tokens; it is an estimate (aix assumes one per plan),
so set your own when you have measured it. The figure covers the repo you run it in: run it in each project and add the points for the total aix saved you. Set it in `~/.config/aix/config.toml` (`plan = "Max 20x"`, `weekly_tokens = 116_000_000`) or with
`AIX_WEEKLY_TOKENS` / `AIX_PLAN`. Providers publish no token figure for subscription plans: measure yours as the new
tokens (input + cache writes + output, not cache reads) your sessions used over a week that ended near 100% of the limit.

The index lives in `<repo>/.aix/index.db` (the directory ignores itself, so git stays clean). Use
`--db PATH` (or `AIX_DB`) to keep it elsewhere, e.g. for a repo you must not write to.

Updates are parallel: worker threads read, hash, extract and redact files while one writer thread fills the
index (one transaction, so a killed update leaves the old index intact), git history is read alongside, and the
code-graph resolution runs on all workers. `AIX_THREADS=n` sets the thread count (default: one per core, at most
16); the watcher and the post-commit refresh run with `AIX_LOW=1` (2 threads, lowered CPU and IO priority).
`AIX_PROFILE=1` prints the time per stage to stderr after an update, and for a query its refresh check, answer and
redaction (`q:*`; `card:*` for the SessionStart card).

### Updating the index: always through `aix-refresh`

Queries refresh changed files on their own. Every other update (git hook, SessionStart hook, cron, agents,
backfills) goes through `scripts/aix-refresh.sh` (installed as `aix-refresh`): one run per index at a
time (flock), low priority, one log line per run in `<db dir>/refresh.log`, and it never fails a hook unless
`--strict`.

```sh
aix-refresh                         # incremental update of the current repo (no embedding)
aix-refresh --embed 120             # ...then embed pending entries for up to 120 s (resumable)
aix-refresh --backfill              # embed in 300 s chunks until nothing is pending
aix-refresh --summaries 120         # ...then one-line local-LLM summaries for up to 120 s
aix-refresh --full --db /tmp/x.db   # full re-extraction into another index file
```

**Auto-refresh:** `aix-watch [REPO]` (scripts/aix-watch.sh) notices file changes on its own and, once
they have been quiet for a short time, runs `aix-refresh --embed 30`. The quiet time adapts to how you edit: the
25th percentile of recent gaps between edits + 0.5 s, kept within 2.5-10.5 s (3.5 s until it has seen 5 gaps), 10.5 s
when a change touches more than 200 files (checkout, rebase), and a refresh at most 30.5 s after the first pending
change even if edits never stop (`--idle SECS` fixes it). A single edit is indexed about 4 s later. Queries refresh
changed files themselves, so this only bounds how stale the background parts can get. It polls `git status` + the
mtimes of dirty files every 0.5 s while changes are pending and every 2 s otherwise (no inotify needed). On slow
storage (a spinning disk, USB stick, SD card, or a network/shared filesystem such as NFS, SMB, sshfs or WSL's `/mnt/c`)
it doubles the quiet times and slows its polls; what it measures wins over the disk type (a median index update over
1.5 s or a change poll over 200 ms counts as slow), `--storage auto|fast|slow` overrides, `--storage-check` prints the
class, and `aix stats` shows the one in use. It keeps one watcher per index, catches up on
edits made while it was not running, and exits after 4 h without changes (`--exit-after 0` to run forever,
`--once` for cron). The SessionStart hook starts it, so nobody has to tell aix that files changed.

The post-commit hook (`aix install-git-hook`) and the SessionStart hook call it when it is on PATH
(`--embed 30` and `--embed 120` in the background). The underlying commands (`aix update | embed |
summarize`) stay available for debugging.

## Queries

Every query refreshes the index first (`--no-refresh` skips that), prints one line per hit with `file:line`,
caps each section at `--limit` (default 20), and prints compact `{lines, hits}` JSON with `--json` (`--pretty` to indent, `--jsonl` for streaming).

| Command | Answers |
|---|---|
| `brief <route\|menu label\|file>` | route, roles, menu entry, purpose, API calls -> endpoints + roles, e2e scenarios, scripts on its endpoints, past findings, fix commits, open decisions. For a non-page file: symbols, endpoints, importers, api calls, quoted UI text, history |
| `impact [rev]` | changed files -> affected routes (reverse import closure), e2e scenarios to run, scripts hitting touched endpoints, removed UI strings that tests still quote |
| `bugs <route\|file\|topic>` | findings naming the files, fix commits touching them, findings by topic (hybrid) |
| `qa <route\|topic>` | e2e scenarios visiting the route, scripts hitting its endpoints, QA assets, decisions, reverts |
| `feature <words\|role>` | feature catalogue (menu pages, tabs, help, flows, flags, tips, deep-link routes); a role lists its menu |
| `text "<ui string>"` | source locations (JSX text, props, toasts/confirms, literals) and e2e steps/tests quoting it |
| `endpoint <[METHOD] /path\|name>` | handler, effective roles, client wrapper, callers, scripts/specs |
| `symbol <name>` | definitions, API client wrapper -> endpoint, callers/uses |
| `script <words>` | existing scripts with header and usage; with `script_dirs` (below) also the scripts in those folders outside the repo (name + usage line only) |
| `tasks [open\|done\|all] [decision\|found\|blocker] [file.md] [words]` | checklist items, newest first |
| `history <file>` | commits touching it (fixes flagged), findings naming it |
| `find <words>` | bm25 over every indexed fact (`--kind ui,bug,task,...`) |
| `ask "<question>"` | hybrid bm25 + cosine (RRF); `--kind features\|bugs\|code\|docs\|qa`; `--answer` adds a short cited answer from the local chat model. `--kind code` searches function/method chunks by meaning and prints `[code] file:start-end Class.method` rows (keyword-only, and says so, without the embedder; `aix embed` or `aix-refresh --embed SECS` embeds new chunks, only changed files are re-chunked) |
| `route <arg>` | the route card alone |
| `grep '<regex>' [--in p] [--scripts]` | regex over the indexed files, 1.5 s budget; says when `rg` or a script is the better tool |
| `grep RE [GNU flags] [path\|glob\|-]...` | GNU grep's flags with GNU semantics (differential tests in `aix-cli/tests/aixsh_b.rs`): `-v -o -m N -c -l -L -q -h -H -s`, `-A/-B/-C N` (up to 30, a note when capped), `--include/--exclude=GLOB/--exclude-dir`, combined short flags, several paths or unexpanded globs; `-c`/`-l`/`-L` are exact (never "too broad"). aix's own: `--and RE` / `--not RE` (the line must / must not also match), `--not-in PART`, `--body` / `--member` (each hit's enclosing member once), `-o --group N` (a capture group), `--count-by match\|file\|dir[:N]\|ext`, `--total`, `-` (scope to the files in piped rows; `--within`: only inside their ranges / enclosing members: `aix callers X \| aix grep RE - --within`), `--bare` (`path:line:text`, `path:N`, `path`), `--width N` (default 200, 0 = never clip). Any other flag exits 2 naming the shell command. The dialect is ERE / Rust regex (as `grep -E`, `rg`); GNU BRE escapes are translated. A plain `aix grep --exclude kinds` keeps the kind meaning; `--exclude=*.min.js` (a file-name glob) is GNU's |
| `patterns [list [words] \| check <regex> \| add <name> <regex> \| rm\|pin\|unpin <name>]` | named regex patterns, materialized in `pattern_hits` (file, line, symbol, container, lang, kind, text) and view `pat_<name>`; capture groups become indexed columns (table `patcap_<name>`); 30 seeded patterns mined by `scripts/mine-regex.py` + auto-promoted after 3 searches; one RegexSet pass per changed file; uses (greps, `sql` on the view) rank them with a 14-day half-life; auto dormant after 14 d unused, seeded after 60 d, over 200k rows least-used first; pinned/hand-added never; >5,000 matches = broad (grep scans live) |
| `code <Class.method\|symbol\|file:line>` | one function's source with its doc comment, numbered |
| `code T...` | several targets per call (`a.ts:10-40 B.method c.ts:15-30,64-75`, `F:/start-re/,/end-re/`, `README.md#Heading`); ranges of one file merged under one header; a range or member is shown whole up to `code_cap` (200) lines, a longer one prints its first part, an outline of the rest and the exact continuation (`--max N` hard cap, `--full`); `-` reads rows from any aix command or grep/rg (`path:line[:text]`, `path:A-B`, paths, `--json` cites, `Class.method`), `--function` prints each hit's enclosing member once, `--around RE -C N` snippets around matches; `--raw` exact text for Edit anchors (a masked line becomes a marker and the exit status is 2), `--check-unique` |
| `cat` / `head` / `tail` / `sed` | GNU semantics for the forms they accept (`cat [-n]`, `head -n N\|-N\|-n -K`, `tail -n N\|-n +K`, `sed -n 'Np\|A,Bp\|A,$p\|/re/p\|/re/,/re2/p\|/re/,+Np'`, `Nq`, `-e`, `-E`, `-s`); `--bare` prints exactly what the tool prints (redacted) plus one footer line when the cap cuts; other flags exit 2 naming the shell command. `sed 's/re/rep/[gNpI]'` and `/re/d` print a unified diff of what `sed -i` would change, never written (a hunk on masked text is refused) |
| `diff A B` / `diff F` / `diff REV[..REV] [-- PATH...]` | git's unified diff (two files, files vs HEAD, revisions; `--stat`, `--name-only`, `-U N`, `-w`), redacted, bounded per file with the exact continuation, secret paths dropped; exit 0 differences, 1 none |
| `anchor F 'text'...` | how many times the exact text occurs and on which lines (counted on the redacted text; an anchor on a masked line exits 2) |

Files under the repo that are not indexed (gitignored scratch, build output, logs) are read from disk by `code`/`cat`/`head`/`tail`/`sed`/`diff`, redacted and labelled `(not indexed: read from disk)`; secret and credential-like files, history/keyring files, `.git`/`.aix`, symlinks and anything outside the repo stay refused.
| `table <db table\|Entity>` | columns from the JPA entity + SQL create/alter |
| `hints [route\|all]` | bug-pattern leads: role gaps, client calls with no backend, fix hot spots |
| `sql "<SELECT ...>"` / `schema` | read-only SQL over the index |
| `stats [--savings]` | table sizes, embeddings, summaries, extractors; the savings meter |
| `update [--full]`, `embed`, `summarize` | maintenance (see above) |

| `files [GLOB\|DIR\|RE] [--lines] [--size] [--count] [--group-by dir[:N]\|ext] [--changed [REV] [--members]] [--exists]` | the indexed files (ls, find, wc -l, test -f, git status/diff --name-only); find(1) primaries `-name -iname -path -ipath -type f\|d -maxdepth -mindepth -newer -not` with GNU semantics (anything else exits 2 naming the find command); `ls` = one level. Gitignored/unindexed files are not listed (the answer says so) |
| `count [by file\|dir[:N]\|ext\|kind\|match\|field N\|line] -` | wc -l / grep -c / sort \| uniq -c over rows on stdin or from the stage before; a partial stream prints `>= N (partial: ...)` |
| `dedup [line\|text\|file\|member\|dir[:N]\|field N\|match] [-c] [--sort count] [--norm] -`, global `--dedup[=KEY]` | awk '!seen[$0]++' (first kept, order kept; `uniq` stays adjacent-only); `-c` prefixes counts; `--norm` folds numbers, ids, timestamps, IPs, quoted strings into one shape per line with first/last example; a `;` sequence or batch names a range an earlier section showed (`--no-dedup` keeps it) |
| `filter [--grep RE] [--not RE] [--head N] [--tail N] [--between A B] -` | bounded, redacted view of non-code text on stdin (build, test, git, psql, curl output) |
| `pipe '<a> \| <b>'`, `pipe 'a ; b'`, `batch a b` | in-call pipes and sequences (below) |

The savings meter logs, per query, the bytes returned and a conservative estimate of the grep + partial
reads it replaced (up to 4 KB for each of at most 15 cited files, plus 1.5 KB per answer section).

### Rows, pipes and output options

- Global output options on every command (CLI and MCP `bare`/`head`/`width`): `--bare` prints machine rows only
  (`path:line:text`, `path`, `path:N`, `N<TAB>key`; a cut answer ends with one `…` line naming the next command),
  `--head N` caps the rows and keeps the exact continuation (`--page 2` on listings, `aix code F:A-B` on code),
  `--locs` prints only `path:line` per hit (implies `--bare`, repeats dropped; MCP `locs`): use it when the location is all you need; when you want the text too, use `--bare` or the plain command.
  `stats --savings` counts each call as the shell lookups it replaces: a number of grep passes (480 B typical, 3.5 KB at p90) and Reads (2.8 KB typical, 8.9 KB at p90), both measured on ~6K real agent shell results; the passes per command are assumptions (`grep` 1+0, `callers` 2+1, `endpoint` 2+2, `impact` 3+2, readers `code`/`cat`/`head`/`tail`/`sed` 0), and an answer never counts for less than its own size. It reports the typical figure with a range up to p90, and assumes the question would have been asked anyway: an estimate, not a measurement of your sessions.
  `--width N` clips the text column (`0` = no clip; `--bare` defaults to 200). Default output is unchanged.
- `-` reads rows from stdin: aix's own output (decorated, `--jsonl`, `--bare`), GNU grep / rg / git grep
  (`path:line[:col]:text`, `path:N`), `path:A-B`, bare paths, Windows paths, CRLF; 8 MB cap, every line redacted;
  lines naming no file are counted in a footer. Commands that take a file or symbol (`code`, `outline`, `brief`,
  `history`, `bugs`, `qa`, `callers`, `callees`, `impact`, `trace`, `symbol`) run once per distinct input row (at
  most 20), `grep RE -` searches only the input's files.
- In-call pipes: `aix 'grep @RolesAllowed --in api | count by dir'`, `aix 'callers Svc.save | code -'`,
  `aix 'endpoint /api/fees | code -'`, `aix 'outline F | grep save'`, `aix 'find refund | head 5 | code -'`; MCP
  `{"command":"pipe","args":"..."}`. A stage boundary is ` | ` outside quotes; stages: any command, `count`,
  `filter`, `sort` (GNU, C locale: `-n -r -u -f -s -b -t C -k N[,M]`), `uniq` (`-c -d -u -i`, adjacent as GNU),
  `head`/`tail` (`-n N`, `-n +K`), `cut` (`-d C -f LIST [-s]`, `-c LIST`), `wc -l`, `grep RE` (filters rows by text).
  Earlier stages read the full answer (5000 rows each); one 3 s budget (`AIX_PIPE_BUDGET_MS`) and a 200k-row
  ceiling mark the stream partial, and the answer says so.
- Sequences: `aix 'brief /fees ; callers Fee.assess ; code Fee.java:120-160'`, `aix batch 'a' 'b'`, MCP command
  `batch` with a `commands` array: one process, one index refresh, one `== aix <command>` header each, one budget
  (`AIX_BATCH_BUDGET_MS`, 10 s). On a 1,261-file repo, 10 typical lookups took about 210 ms batched against
  about 530 ms as 10 processes.
- Data sets (`@name[/item]`) plug in through `rows::SetSource`; `files @name`, `count ... @name`, `filter ... @name`
  and a pipe stage `@name` read them.

### Say what you do not need

One vocabulary on every query command (CLI flags; the MCP tool takes the same names as arguments). Flags may be typed
anywhere in the arguments.

| Flag | Meaning |
|---|---|
| `-x` / `--exclude <kinds\|globs>` | PRE: drop rows in SQL before ranking and `--limit`. Kinds: `docs tests scripts generated fixtures migrations vendor data source` (from the file classification, column `files.class`); globs: `docs/**`, `**/*.test.ts`, `e2e`. In `grep`, `-x` stays "whole line match" unless the next word is a kind/glob list and a pattern remains; `--exclude` is always unambiguous |
| `--only <kinds\|globs>` | PRE: the positive counterpart |
| `--conf exact,resolved` | PRE: drop name-only / heuristic call-graph rows (callers, callees, impact, trace) |
| `--hide <kinds\|globs\|sections>` | POST: applied after ranking and limiting; the output ends with `(hid 12 lines: tests 8, docs 4)`. `--plan`, `--exists` and `--group-by` apply it too; a grep header says `[N hidden by --hide]`. Use `-x` when you know you do not want it, `--hide` when you want the counts but not the rows |
| `--skip` / `--fields <sections>` | sections of brief (`menu api roles e2e scripts bugs fixes decisions hints`), trace and explain (`ui endpoint service tables state docs findings e2e`), table (`columns constraints migrations readers writers endpoints`), callers (`name-only tests`) |
| `--order <sections>` | section order of brief, explain, table; the byte cap is spent in that order |
| `--sort a,b` | `relevance` (default), `path`, `recency` (git last touch), `conf`, `fanin`, `size`; ties by path:line. grep sorts before its file cap; other listings reorder their rows (with `--page`/`--count` that is the whole answer) |
| `--count` / `--plan` | only the breakdown: total, per kind / directory / section / confidence, token estimates, 2-3 ready-to-run narrower commands (grep: `--plan`; its `--count` keeps the rg meaning) |
| `--page N --per-page M` / `--offset K` | stable pages that tile the whole answer (every matching line is a row: grep shows no `... N more` lines in a page; same order and filters, ties by path:line); each ends with `page 2 of 5 (rows 21-40 of 93): next ...`, a page past the end says so. The total equals the grep header and `--plan`. `--json` hits, the aix/v1 answers and `--jsonl` follow the page; a huge `--per-page` shows everything |
| `--exists` | `yes (first: path:line)` or `no` with the number of filters applied; exit status 0 yes, 1 no, **2 for an error** (bad regex, flag or value: the message is printed instead of a quiet `no`); JSON `{"exists":true,"first":{...}}` |
| `--group-by KEY [--having 'count>5 and share>0.1'] [--sort count[:asc]]` | one `count  key` row per group (SQL GROUP BY / HAVING over bound parameters). Keys: `file dir[:N] kind lang`; callers/callees/impact `caller-class callee conf`; brief/trace/endpoint `endpoint method role table op`; history/bugs `month is_fix`; grep `match` (the whole match) or `match:N` (capture group N). `kind` groups spell the kinds as `-x`/`--only` do (`docs`, `scripts`, `tests`). A bad key, depth or `--having` is a one-line error, exit 2 |
| `--no-default-excludes` | ignore the repo defaults |

Options may stand before or after the query on every command: `aix callers main --limit 3`, `aix tasks open --max 5`, `aix code main --count`, `aix grep x --full`, `aix callers main --repo DIR` (`--limit`/`--max` N rows, `--full` all rows or no code cap, `--count` the breakdown). On the single-argument commands (callers callees symbol route endpoint trace explain table hints tasks history outline brief code) an unknown `--flag` is an error naming the supported ones (exit 2), never part of the symbol. Paths are accepted as `./x`, `x\y`, `x//y`, `x/`, a bare basename (`history App.tsx`), or a class or function name (`history OwnerController` = its file's history, `history makeToken` = `git log -L` over its lines) and relative to the working subdirectory; a path that matches nothing prints `path not found: <p>` (exit 1). Exit status on every command: 0 found, 1 none / no match / path not found, 2 usage or error; MCP marks errors `isError` and a none answer with `structuredContent: {"none": true}`. `grep -x` is the whole-line flag unless a kind/glob list follows (then it excludes); `--line-regexp` is always whole-line; after `--` everything is the pattern. `howto <task>` answers common tasks with the exact command first. Unknown `--sort`, `--conf` or `--order` values are a one-line error (exit 2). `--json`, `--jsonl`, `--pretty` and `--no-refresh` are accepted after the pattern too (`aix grep foo --json`; after a `--` they are text). A bad grep regex or flag exits 2. Quote a flag value with spaces (`-x 'my dir/**'`). `aix card --json` prints `{"card","lines"}`. Footer suggestions use the real top directory and quote globs.

Defaults: `default_excludes = ["docs", "**/*.snap"]` in `.aix/config.toml` (repo-local is allowed: it only narrows answers and
never widens what is indexed or readable) and `AIX_EXCLUDE=docs,tests`. An answer a default changed ends with
`(default excludes: docs; --no-default-excludes to include)`. `count_first_over` (default 60) is the row count above which a
truncated answer prints the count breakdown and narrowing hints (`--all` / `--full` lift it).
Large answers end with a footer computed from their own composition ("62% of this answer is in docs and tests: add -x
docs,tests", "the bugs section is 40% of this brief: add --skip bugs"). The JSON envelope carries
`excluded: {criteria, counts}`. `--json` is compact (no null or empty fields; text is about half the size of any JSON),
`--json --pretty` indents, `--jsonl` prints one answer per line and a final `{"summary":{n,truncated,excluded}}` line.

## Claude Code integration

`aix-init` installs all of this for you; the files live in `integrations/claude-code/` if you prefer
to wire them by hand:

- `mcp.json`: project `.mcp.json` entry for the stdio MCP server (one tool, `aix`, with `command`,
  `args`, `limit`, `kind`, `answer`, `json`). CLI equivalent:
  `claude mcp add --transport stdio --scope project aix -- aix mcp`.
- `skills/aix/SKILL.md`: when to use each query (short; loaded when the skill is used), with details in `skills/aix/reference/` (filters, logs and pastes, search) that agents read only when needed.
- `hooks/aix-session-start.sh`: SessionStart hook; prints a ~10-line project card. The hook scripts are the shell
  form; `aix init` registers the exec form instead (`{"command": "<path>/aix", "args": ["hook", "session-start"]}`,
  `["hook", "pretool"]`, `["hook", "prompt"]`), which needs no shell and is what Windows uses.
- `hooks/aix-pretool-nudge.sh`: PreToolUse hook (matcher `Bash|PowerShell|Grep|Glob|Read`). Every segment of a
  shell command (`;`, `&&`, `|`, also inside `bash -c`, `powershell -Command`, `pwsh -c`, `cmd /c`) is translated
  with one table (grep/rg/git grep, find, ls, cat/head/tail/sed -n, wc, findstr, Select-String, Get-Content,
  Get-ChildItem ...) into ONE combined aix line (`aix 'grep X f ; code f:10-40'`), shown as context. Paths outside the
  repo, unindexed files, logs, `$vars` and unknown flags stay silent. A read the hook can reproduce exactly
  (`sed -n A,Bp`, `head`, `tail`, `cat` of indexed unchanged files with no secret on them) is answered:
  `permissionDecision: "deny"` with the output as the reason; the built-in Grep/Glob over a scope of indexed files
  too, labelled as aix's answer (`AIX_HOOK_DENY_GREP=0` makes those a nudge). Repeat the call or prefix `AIX_HOOK=off` to run the real tool;
  `AIX_HOOK_DENY=0` turns all answering off. Read/Edit/Write and anything
  with side effects are never denied. Large data files read twice and long build/test output piped into
  head/tail/grep get `aix put <name>` hints. The same file read a third time in a session with sed/cat/head/Read gets a note naming `aix outline F` / `aix code F:A-B` and the bytes those reads printed. A call that works in another git checkout (`cd DIR && ...`, a scratch clone under the project) is steered with that checkout's index; when it has none, the hook says once per session the exact one-time command (`aix --repo DIR stats`: a copy of the parent's index for a clone/worktree, else a first build with its file count, or the .gitignore decision it waits for), never a query that cannot answer yet. Each decision is a line in `.aix/hook-events.jsonl` (redacted):
  `aix stats --hooks [--since 7d]` sums them (and counts nudges followed by an aix call among the session's next 3 calls vs ignored), and `aix hook classify [transcript.jsonl] [--summary]` labels every
  tool call of a Claude Code transcript with the same rules (missed-opportunity rate = miss / (miss + aix)).
  `AIX_HOOK_SHELL_TOOLS=Name` adds another PowerShell-style tool name.
- `settings.hooks.json`: the hook registration snippet for `.claude/settings.json`.
- `hooks/install-post-commit.sh` (or `aix install-git-hook`): a post-commit hook that refreshes the
  index in the background; an existing hook is kept as `post-commit.pre-aix` and still runs first.
- `commands/brief.md`, `impact.md`, `bugs.md`: slash commands.

## Configuration

`aix` reads the first of `<db dir>/config.toml`, `<repo>/.aix/config.toml`,
`~/.config/aix/config.toml`, then fills missing endpoints from the local AI harness routing file
`~/.config/local-llm/backends.json` (role `embed` for embeddings, role `chat` for summaries and answers).

```toml
exclude = ["^vendor/", "^docs/archive/"]   # extra path regexes
query_embed_deadline_secs = 0.0             # embedding work before an `ask` (0 = none)
script_dirs = ["~/tools"]                   # opt-in: `aix script` also lists these folders' scripts (name + usage line); AIX_SCRIPT_DIRS=a:b adds more
embed_query_prefix = "Instruct: Given a question about a software project's features, pages, bugs, tests or code, retrieve the index entries that answer it\nQuery: "
embed_doc_prefix = ""

[embed]
url = "http://127.0.0.1:8092"
model = "local-embed"

[[chat]]
url = "http://127.0.0.1:8093"
model = "local-fast"
```

`script_dirs` (or `AIX_SCRIPT_DIRS`, colon separated) names folders outside the repo, one level deep. `aix script` then lists their
scripts (shebang or a script extension) as `~/tools/x.sh [outside repo]  <first usage line>`. Nothing from them is indexed
for `grep`, `code`, `text` or `find`; the usage line is redacted; dotfiles, credential-like names, history/keyring files, hidden
folders of `$HOME`, non-owned files and locations outside the allowed roots are skipped.

`AIX_EMBED_URL=` (empty) disables embeddings for one run.

Files that are never read: anything gitignored, `.env*`, `*.tok`, `*.pem`/`*.key`/keystores, SSH keys, data or
config files whose name contains `key`, `secret`, `credential` or `password`, and source files named like
`apiKey`/`private_key`. Indexed text is also redacted (JWTs, long opaque tokens, values on password-ish lines). The redactor is layered: provider detectors (AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, npm, PyPI, OpenAI/Anthropic keys, JWTs, private-key blocks, connection strings, auth headers and cookies, Kubernetes Secret data, vault blobs...), key/value detectors for every syntax, base64-wrapped secrets, a high-entropy detector and PII (emails, phone numbers, Luhn-valid card numbers; IPs with `[redact] ip = true`). Also: SQL accounts (`IDENTIFIED BY`, `WITH PASSWORD`, INSERT values in credential columns), name/value pairs (k8s `env`, HAR/cookie JSON, YAML flow), `::add-mask::`, argv lists (`["--api-key", "..."]`), `System.setProperty("...Password", ...)`, markdown tables, `psk`, letter-spaced key names and a bare 32-character token next to a credential word. References, types and pins stay readable (`${X}`, `password: str`, `id-token: write`, `uses: org/repo@<sha>`, `password_reset_token`, empty values, public certificates), and an empty value never masks the next line. Masks keep a type hint (`***aws-key***`) and never part of the value. It runs on ingest and on every output (text, JSON fields including file paths, MCP, hooks, card, errors, `aix sql` cells); the index keeps the raw path only to re-stat the file. `aix redact-test` (stdin to redacted stdout) checks your own text: stderr names every rule that changed a line (`line 7: kv`) and prints the `sha1:` allow-list entry for each changed token, to keep a false positive readable. `.aix/config.toml` `[redact]` can add `[[redact.rules]]` and hashed `allow` entries (`aix redact-test --hash STRING`); it cannot switch a built-in family off.

**Keep a value or pattern out of everything aix shows** (customer names, internal hostnames, ticket ids...): `aix mask add '<regex>' [--hint label] [--scope repo|global]`, or `aix mask add --literal 'exact text' [--icase]` (6+ characters; only a PBKDF2-HMAC-SHA256 hash with 600000 iterations is stored; it matches at every offset, inside words and next to itself, and with `--icase` in any case and percent-encoded). Public key shapes (`ghp_`, `AKIA`...) and text the redactor already masks are refused, as are names or hints equal to a built-in rule name or holding a secret. Masks live in `.aix/masks.toml` / `~/.config/aix/masks.toml` (0600, never tracked), apply to all output and stored text (already-stored text is re-masked when you add one, freed pages are zeroed and the index is compacted; file and entry paths keep their raw names in the index because it needs them to open files, and are masked when shown). Masks run after the built-in rules and can only add masks; `--icase` on text you already masked case-sensitively upgrades that mask. `aix mask list`, `aix mask test '<text>'`, `aix mask rm <name> [--purge]` (stored rows stay masked; `aix update --full`, or `--purge`, re-ingests from source).

## What is extracted

Generic (any repo): files (kind, lines, bytes); symbols via tree-sitter (TS/TSX exports, functions,
components, classes; Java types and public methods; Python defs/classes; Bash functions); UI strings from
TSX (JSX text and `{cond ? 'A' : 'B'}` children, title/placeholder/aria-label/label/... props, toast/confirm
arguments, user-facing literals); Markdown headings and sections; scripts (header comment, usage lines,
flags, `/api` paths they call); SQL tables touched; git history (fix/bug/revert flagged); checklists
(`- [ ]`/`- [x]` with DECISION / Found / BLOCKER tags).

Stack extractors: React Router `<Route>` tables with nested paths, role guards and feature flags; navigation
menus (`{ name, href, roles }`, groups, tabs); JAX-RS endpoints with class/method `@RolesAllowed`,
`@PermitAll`, `@Authenticated`; HTTP client objects (`export const xApi = { list: () => api.get(...) }`)
and their callers; e2e JSON specs (scenarios, steps, quoted texts, API checks); QA-findings docs and JSON ->
bugs; user-flow docs, feature flags, tips and page help -> features. Role constants are resolved across files
(`STAFF = [...ADMIN, 'clerk']`, `Roles.CLERK`).

## Supported languages and frameworks

Code graph = members with line ranges, imports, calls with receiver types, functions used as values, argument counts
(`callers`, `callees`, `impact`, `outline`). Symbols = members, imports and calls resolved by name and by `this` /
static / declared-type receivers. Every grammar is a pinned tree-sitter crate (see [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)).

| Language | Level | Versions covered | Routes |
|---|---|---|---|
| Java | code graph | 8-21: records, sealed types, switch and record patterns, text blocks | Spring MVC, JAX-RS |
| TypeScript / JavaScript | code graph | TS 5.x (decorators, `satisfies`, const type parameters, `using`), ES2023 | Express, Next.js |
| Vue, Svelte | code graph of `<script>` blocks, template strings | Vue 3 `<script setup>`, Svelte 4/5 scripts | n/a |
| Python | code graph | 3.8-3.13: `match`, PEP 695 generics and `type` | FastAPI, Flask, Django |
| Go | code graph | 1.18-1.23: generics, range-over-int and range-over-func | net/http, chi, gin, echo, fiber, gorilla |
| Rust | code graph | 2021 and 2024: async fn in traits, let-else, let chains | Actix web, Axum, Rocket |
| Kotlin | code graph | 1.9 and 2.x: data / sealed / value classes, objects, `fun interface` | Ktor, Spring |
| C# | code graph | 10-12: records, file-scoped namespaces, primary constructors | ASP.NET Core (controllers, minimal APIs) |
| PHP | code graph | 7.4-8.x: attributes, enums, readonly, promoted properties | Laravel |
| Ruby | code graph | 2.7-3.x: endless methods, pattern matching, `Data.define` | Rails |
| Swift, Scala (2.13 / 3), C, C++, Dart, Lua | symbols | current grammars | n/a |
| XQuery (`.xqy .xq .xqm .xql .xquery .xqe`), MarkLogic SJS (`.sjs`, as JavaScript) | code graph (hand-made scanner, no grammar) | XQuery 1.0 / 3.1, MarkLogic `1.0-ml`: `import module … at`, arity overloads, `%annotations`, `p:f#2`, direct XML constructors | MarkLogic REST extensions (`/v1/resources/NAME`), `rewriter.xml`, URL rewriter modules, `xdmp:invoke` / `xdmp:spawn` |
| Jinja / Django / Twig, Thymeleaf, ERB, Blade, Go templates | UI strings for `aix text` | n/a | n/a |

Not parsed: a file the grammar cannot handle keeps the declarations it could read (a parse error never aborts the
run, and a pathologically deep file is indexed by a flat line scan). Known grammar gaps are listed in
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). Accuracy per language is measured with `bench/lang/score.py`
(definition recall and callers precision / recall on cloned public repos) next to `bench/codegraph`; XQuery with
`bench/lang/xquery.py` (MarkLogic repos, against a regex oracle).

## Adding an extractor

1. Create `aix-extract/src/<name>.rs` with a unit struct implementing `Extractor`:

   ```rust
   pub struct Express;
   impl Extractor for Express {
       fn name(&self) -> &'static str { "express" }
       fn detect(&self, repo: &Path) -> bool { crate::package_json_mentions(repo, "\"express\"") }
       fn handles(&self, path: &str) -> bool { matches!(ext_of(path), "js" | "ts") }
       fn extract(&self, _repo: &Path, files: &[SourceFile]) -> Rows {
           let mut rows = Rows::default();
           // parse each file (tree-sitter helpers in ts_util.rs) and push rows.endpoints, rows.symbols, ...
           rows
       }
   }
   ```

   Every row carries its `file`, so the engine can drop and replace one file's facts. Reuse the existing
   row types (`Endpoint`, `Route`, `MenuItem`, `ApiCall`, `TestCase`, `Bug`, `Feature`, ...) so the canned
   queries pick the facts up with no further changes.
2. Register it in `all()` in `aix-extract/src/lib.rs`, and bump `REVISION` so existing indexes
   re-extract once.
3. Add a fixture under `tests/fixtures/` and a test in `aix-extract/tests/extractors.rs`.

## Development

```sh
cargo build -j 8 && cargo test -j 8 && cargo clippy --all-targets -- -D warnings
scripts/bench.sh /path/to/repo "" path/in/repo/to/edit.tsx        # timings as one JSON line
scripts/oracle-diff.py PROTO_DB AIX_DB                        # table-level diff vs the Python prototype
scripts/oracle-queries.py --repo R --aix BIN --proto P.py --queries Q.json --db DB   # same queries, cited facts compared
bench/expert/score.py --eval bench/expert/example-eval.json --sk BIN --db DB --repo R   # precision/recall of cited lines
bench/accuracy.sh BIN REPOS_DIR WORK_DIR [EVAL.json REPO [DB]]   # precision guard, fails below 1.0
scripts/check-private.sh                                       # maintainers: no private markers in tracked files
```

The bench and oracle tools take the eval file, repo and index as required arguments and carry no repo-specific
defaults. `scripts/check-private.sh` reads a deny list of regexes kept outside the repo
(`~/.config/aix/private-markers`, or `$AIX_PRIVATE_MARKERS`); `scripts/install-maintainer-hooks.sh` is an opt-in
pre-commit hook that runs it on the staged diff.

Layout: `aix-extract` (extractors, no DB), `aix-core` (schema, incremental engine, derived
cross-file layer, semantic layer, queries), `aix-cli` (CLI, MCP server, hooks).

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT licence](LICENSE-MIT) at your option.
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined
in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.
