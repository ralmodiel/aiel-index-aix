# aix-expert: a source-code expert for any repo

Owner's request (2026-10-23): make aix an expert on the source code of whatever project it is installed in, useful
to Claude Code or any AI tool, and always answer from the index for fast, correct lookups.

## Ground rules
- Local only: loopback embedder, optional local LLM tiers, tracked files only, secrets redacted, no listeners (MCP over stdio).
- Index-only answers: every answer is read from precomputed tables/views. A query never scans the repo, never calls an
  LLM, never falls back to grep. A missing fact is said plainly ("none (index has no X for this file)").
- LLM summaries are built offline at index time, labelled, optional, never needed for correctness.
- Incremental: per-file facts replaced on change (blake3); derived edges recomputed only for dirty keys.
- Bounded output, one line per hit with file:line[-end], `--limit` per section, `(+N more)`; every fact carries
  `conf` = exact | resolved | name | heuristic.
- Latency on a large repo: <50 ms p95 per query, <150 ms for closures (depth <= 4, frontier <= 500); one-file refresh <150 ms.

## Ranked items (all project-agnostic; stack auto-detected)
1. Full symbol table + call graph (L): `callers`, `callees`, `impact <symbol>` with confidence. Tables: symbols (all
   members, sig, visibility, annotations), refs(file,line,caller_id,callee_name,recv_type,kind,conf),
   call_edges view, sym_fanin. Extractors: Java/Kotlin (receiver types from injected/constructor fields, statics,
   Panache), TS/JS (import bindings, obj.member, JSX components, hooks), Python, Go, Rust, shell; name-only fallback.
2. `outline <file> [words]` (S after 1): members with line ranges and facts (endpoint+roles, tables, calls, UI strings);
   the PreToolUse hint names the matching members for single-file greps.
3. Cross-layer `trace` + `explain` (M): screen -> client fn -> endpoint -> handler -> service -> tables, both
   directions; layer_edges + materialized trace_paths; explain = feature resolution + trace + docs + findings.
4. Data model map (M): entity_columns, migrations, data_access(sym, table, r/w), fks; JPA/Panache, Spring Data,
   Prisma/TypeORM/Drizzle, SQLAlchemy/Django, sqlc; Flyway/Liquibase/Alembic/Rails/Prisma migrations.
5. Coverage map + `verify` (M): test_links, script_checks; JUnit/Jest/Vitest/pytest/go/Rust tests, Playwright, JSON specs.
6. Stable JSON v1 + typed MCP tools + AGENTS.md snippet (S) - folded into the first release.
7. `change <sha|diff>` + `risk` (S/M): commit_symbols, dirty_hunks, sym_risk.
8. Conventions as checkable rules (M): rules mined from docs and dominance stats; rule_violations per changed file.
9. `example "<pattern>"` similar-code retrieval (M): structural features + minhash, optional offline embeddings.
10. Stack detection, generic fallback and large-repo scaling (L, ongoing).

Build first: 1, 2, 3 (+ JSON v1 envelope).

## Evaluation
An eval file (`bench/expert/example-eval.json` shows the format) lists questions with ground-truth file:line. Score precision/recall of cited
locations (same file, +-3 lines or inside the symbol), `must` terms, answer bytes vs a grep+Read baseline, p95 latency.
Gate per item: recall >= 0.9, precision >= 0.8, >= 40% fewer tokens with correctness held.
