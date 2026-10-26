#!/usr/bin/env bash
# SessionStart hook: prints the ~10-line aix project card (plain stdout goes into Claude's context).
# Only in repos where `aix-init` was run (marker .aix/initialized; a fresh worktree or clone without it gets
# a one-line pointer and nothing is built or started). There: refreshes the index first (incremental, usually
# < 100 ms), then starts `aix-refresh --embed 120` and the
# `aix-watch` auto-refresh watcher in the background. Silent and exit 0 when aix is missing.
# installed next to `aix` by scripts/install.sh: find it even when that dir is not on the hook's PATH
PATH="$(dirname "$(readlink -f "$0")"):$PATH"
command -v aix >/dev/null 2>&1 || exit 0
cd "${CLAUDE_PROJECT_DIR:-$PWD}" 2>/dev/null || exit 0
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
# an index kept outside the checkout (AIX_DB, as aix-refresh/aix-watch read it) counts as initialized: without this
# a session on such a checkout was told "use grep/Read" while every aix query worked
if [ ! -f "$root/.aix/initialized" ] && { [ -z "${AIX_DB:-}" ] || [ ! -f "$AIX_DB" ]; }; then
  echo "aix: no index for this checkout (run \`aix-init\` here to build one; until then use grep/Read)."
  exit 0
fi
timeout 15 aix card 2>/dev/null || true
# Fill embeddings in the background through the refresh script (locked, logged, low priority), and start the
# auto-refresh watcher (one per index; re-indexes ~3.5 s after edits stop (adaptive, at most 30.5 s), exits after 4 h without changes).
if command -v aix-refresh >/dev/null 2>&1; then
  (aix-refresh "$root" --embed 120 --wait 5 >/dev/null 2>&1 &)
fi
if command -v aix-watch >/dev/null 2>&1; then
  (setsid aix-watch "$root" </dev/null >/dev/null 2>&1 &)
fi
exit 0
