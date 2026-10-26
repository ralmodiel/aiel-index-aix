# aix on the codebase-memory-mcp benchmark corpus

`bench/corpus/bench.py` clones the repos of `corpus.tsv` at pinned commits (shallow, under `--dir`, never in this
repo) and measures one full build, one update after 50 edited source files, and the median of 5 runs of six
queries (`--no-refresh`, so the refresh check is not counted). The repos are the ones codebase-memory-mcp publishes
numbers for (Linux kernel, Django) plus 8 of its 31-repo evaluation set, one per language aix extracts
(Go, Python, TypeScript, Rust, Java, C++, C, PHP).

Machine: AMD Ryzen AI 9 HX 470 (12 cores / 24 threads), 59 GB RAM, NVMe SSD, Linux. The box was shared with other
jobs during the runs (load average 9-38), every build ran under `nice -n 10`: times are upper bounds.

## Results (aix after the fixes below)

| repo | files | nodes (members) | edges (call edges) | full build | peak RSS | index | update, 50 files | grep | symbol | callers | callees | trace | impact |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| linux v6.19 | 72,042 | 4,674,217 | 6,134,139 | 206 s | 3.17 GB | 5.8 GB | 7.1 s | 646 ms | 87 ms | 90 ms | 97 ms | 87 ms | 204 ms |
| linux v6.19, `--max-memory 2G` | | | identical | 361 s | 1.96 GB | 5.8 GB | | | | | | | |
| django 5.2.7 | 4,111 | 57,109 | 100,603 | 8.8 s | 468 MB | 119 MB | 1.9 s | 64 ms | 39 ms | 28 ms | 35 ms | 34 ms | 46 ms |
| laravel/framework | 3,333 | 44,270 | 137,829 | 10.7 s | 406 MB | 116 MB | 1.1 s | 285 ms | 73 ms | 84 ms | 63 ms | 58 ms | 52 ms |
| redis | 1,548 | 27,202 | 84,126 | 2.5 s | 296 MB | 65 MB | 0.5 s | 132 ms | 33 ms | 40 ms | 33 ms | 40 ms | 34 ms |
| trpc | 1,506 | 9,429 | 12,710 | 0.9 s | 220 MB | 27 MB | 0.3 s | 49 ms | 40 ms | 28 ms | 25 ms | 41 ms | 33 ms |
| nlohmann/json | 1,133 | 9,751 | 40,021 | 1.7 s | 234 MB | 30 MB | 1.0 s | 161 ms | 45 ms | 53 ms | 42 ms | 39 ms | 39 ms |
| meilisearch | 832 | 16,555 | 41,760 | 1.1 s | 232 MB | 44 MB | 0.7 s | 49 ms | 48 ms | 33 ms | 48 ms | 50 ms | 42 ms |
| httpie/cli | 235 | 1,783 | 1,760 | 0.3 s | 136 MB | 5 MB | 0.1 s | 37 ms | 41 ms | 27 ms | 43 ms | 40 ms | 33 ms |
| spring-petclinic | 103 | 323 | 374 | 0.2 s | 84 MB | 3 MB | 0.1 s | 45 ms | 46 ms | 45 ms | 31 ms | 51 ms | 41 ms |
| go-chi/chi | 99 | 515 | 2,117 | 0.2 s | 78 MB | 3 MB | 0.1 s | 49 ms | 34 ms | 25 ms | 42 ms | 38 ms | 33 ms |

Probe names (`corpus.tsv`): linux `vfs_read` / grep `kmem_cache_alloc`, django `get_object_or_404`, and so on. Query
times are whole-process wall times (start, open, answer, exit), not in-process query times.

For comparison, codebase-memory-mcp's README (Apple M3 Pro): Linux kernel full index 3 min, 28M LOC / 75K files ->
4.81M nodes, 7.72M edges; Django ~6 s, 49K nodes, 196K edges; name search < 10 ms; trace depth 5 < 10 ms. Its nodes
and edges are not the same units: aix counts code members (functions, methods, types, fields, constants) and
resolved call/reference edges only; it also indexes text, docs, git history and routes, which cbm counts elsewhere.

## Fixes made for this corpus (before -> after, same machine)

| what | before | after |
|---|---|---|
| Linux kernel full build, peak RSS | 5.47 GB | 3.17-3.26 GB; 1.96 GB with `--max-memory 2G` (edges identical) |
| kernel subset (17.5k files), peak RSS | 2.95 GB | 1.64 GB; 0.68 GB with `--max-memory 1G` (edges identical) |
| 40k-file synthetic repo, peak RSS | 1.04 GB | 0.66 GB |
| 39 MB / 1,236-file Rust repo, peak RSS | 557 MB | 255 MB with `--max-memory 256M` (22 s instead of 6 s: 2 workers) |
| kernel `callers kmalloc` (copies under tools/ made every call ambiguous) | 5 call sites | 2,304 |
| session card, 40k files | 0.35-0.43 s | 0.12 s |
| `grep process --page 13836` (last page, 276k matches) | 10.3 s | 0.9 s |
| first query on a never-indexed 1,236-file repo | blocks for the whole build | answers if the build ends within 5 s, else "INDEX NOT READY (543 of 1224 files)"; the build carries on in its own process |

How: the code graph shares repeated strings and keys (file, kind, container) instead of copying them per member,
freed heap goes back to the OS between stages, and a memory budget (`aix update --max-memory`, `AIX_MAX_MEMORY`,
default half the available memory) caps workers and SQLite's cache and resolves the graph in batches read from the
index when the whole graph would not fit. C/C++ calls to a name defined in several files bind to the definition the
caller's `#include`s bring in.

## Known gaps

- The kernel index is 3.4x the source (5.8 GB); most of it is full-text search and the rows of
  2.9M constants (`#define` and enum values).
- C include resolution looks two levels deep: `kmalloc` reaches 2,304 of about 5,000 call lines; deeper chains
  keep the old rule (no edge when more than 5 definitions).
- Extraction costs about 0.5 CPU-seconds per MB of source (linear in bytes, not in files); redacting every indexed
  string is about a third of it.
- Token use per answer (cbm's 10x claim) is not measured here: `bench/ab-bench.py` does that and costs model calls.
