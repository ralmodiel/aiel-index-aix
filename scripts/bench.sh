#!/usr/bin/env bash
# Benchmark aix on a repo: full build, no-op refresh, refresh after a one-file edit, query latency.
# Never modifies REPO: the edit step runs on a scratch `git clone --shared` copy (set BENCH_EDIT=0 to skip it).
# Usage: scripts/bench.sh REPO [DB] [FILE_TO_EDIT]      (BIN: $AIX_BIN, default `aix`)
# Prints one JSON line. (Drafted by the local LLM harness via local_ask, then fixed and reviewed.)
set -euo pipefail
REPO="${1:?usage: $0 REPO [DB] [FILE_TO_EDIT]}"
DB="${2:-$(mktemp -d "${TMPDIR:-/tmp}/skbench.XXXX")/index.db}"
FILE="${3:-}"
BIN="${AIX_BIN:-aix}"
ms() { local s e; s=$(date +%s%N); "$@" >/dev/null 2>&1; e=$(date +%s%N); echo $(( (e - s) / 1000000 )); }

full_out=$("$BIN" --repo "$REPO" --db "$DB" update --full --embed-deadline 0)
full_ms=$(echo "$full_out" | sed -n 's/.* in \([0-9]*\) ms$/\1/p')
files=$(echo "$full_out" | sed -n 's/^full build: \([0-9]*\) files scanned.*/\1/p')
wall_full=$(ms "$BIN" --repo "$REPO" --db "$DB" update --full --embed-deadline 0)
noop_ms=$(ms "$BIN" --repo "$REPO" --db "$DB" update --embed-deadline 0)

edit_ms=null
if [[ -n "$FILE" && "${BENCH_EDIT:-1}" == "1" ]]; then
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/skbench-repo.XXXX")
  git clone -q --shared "$REPO" "$tmp/repo"
  "$BIN" --repo "$tmp/repo" --db "$tmp/index.db" update --full --embed-deadline 0 >/dev/null
  printf '\n// bench edit\n' >> "$tmp/repo/$FILE"
  edit_ms=$(ms "$BIN" --repo "$tmp/repo" --db "$tmp/index.db" update --embed-deadline 0)
  rm -rf "$tmp"
fi

q() { ms "$BIN" --repo "$REPO" --db "$DB" --no-refresh "$@"; }
printf '{"repo":"%s","files":%s,"full_ms":%s,"full_wall_ms":%s,"noop_ms":%s,"edit_ms":%s,"query_ms":{"stats":%s,"find":%s,"brief":%s,"text":%s,"endpoint":%s,"impact":%s}}\n' \
  "$REPO" "${files:-0}" "${full_ms:-0}" "$wall_full" "$noop_ms" "$edit_ms" \
  "$(q stats)" "$(q find cancel order)" "$(q brief /)" "$(q text Save)" "$(q endpoint /api)" "$(q impact)"
