# Filters, counts, paging and grouping

Every answer is paid for in tokens, so name what you do NOT need up front. One vocabulary on every command (CLI flags
and MCP arguments `exclude`, `only`, `hide`, `skip`, `fields`, `order`, `sort`, `conf`, `count`, `page`, `exists`, `group_by`, `having`):

- `-x <kinds|globs>` (`--exclude`): `-x tests,docs`, `-x 'docs/**,**/*.test.ts'`; kinds are docs, tests, scripts, generated,
  fixtures, migrations, vendor, data. Filtered in SQL before ranking and `--limit`, so the slots go to what you want.
  `--only <kinds|globs>` is the positive form. (`grep -x` stays "whole line"; with a pattern and a kind/glob list it means exclude.)
- `--conf exact,resolved` drops name-only call-graph rows (callers, callees, impact, trace).
- `--skip bugs,hints` (brief: menu,api,roles,e2e,scripts,bugs,fixes,decisions,hints; trace/explain: ui,endpoint,service,
  tables,state,docs,findings; table: columns,constraints,migrations,readers,writers,endpoints; callers: name-only,tests) or
  `--fields api` to choose the sections; `--order decisions,api` puts what you need first (the size cap is spent in that order).
- `--hide <kinds|globs|sections>` is the POST form: applied after ranking and limiting, and the answer keeps a one-line tally
  ("hid 12 lines: tests 8, docs 4"); `--plan`, `--exists` and `--group-by` apply it too. Use `-x` when you know you do not want it, `--hide` when you want the counts but not the rows. In `grep`, prefer `--exclude` (its `-x` means whole line).
- `--sort path|recency|conf|fanin|size` (comma list = tie-breaks); `--json` is compact (no empty fields), `--json --pretty` for humans.
- Broad question? Run `--count` (grep: `--plan`) first: total, per kind/dir/section/confidence, token estimates and 2-3 ready-to-run
  narrower commands; then page (`--page 2 --per-page 20`; pages tile the whole result, `--json`/`--jsonl` hits too) or exclude. Answers that are cut short print that breakdown
  themselves, and large ones end with the most effective exclusions computed from their own composition ("62% of this answer is
  in docs and tests: add -x docs,tests"); follow them. `--full` lifts it (grep: `--head N` or `--page N`).
- Just need to know if it exists or is used? `--exists` prints `yes (first: path:line)` or `no` (exit 0/1; 2 and the message on a bad regex or flag) with the same filters:
  before deleting a function, `aix callers X --exists --conf exact,resolved`.
- Want the shape, not the rows? `--group-by dir:2|file|kind|lang|caller-class|callee|conf|endpoint|method|role|table|op|month|match
  --having 'count>5 and share>0.1' --sort count`: `aix grep 'TODO' --group-by dir:2 --having 'count>5'` (`match` is the whole match, `match:N` a capture group).
- A repo can set `default_excludes = ["docs"]` in `.aix/config.toml` (or `AIX_EXCLUDE=docs,tests`); answers they changed say
  "(default excludes: ...; --no-default-excludes to include)". An exclusion can turn "some" into "none": a `none` line next to a
  note means rerun without it before concluding anything.
