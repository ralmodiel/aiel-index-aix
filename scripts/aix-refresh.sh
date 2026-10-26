#!/usr/bin/env bash
# usage: aix-refresh.sh [REPO] [--db PATH] [--full] [--embed SECS] [--summaries SECS] [--backfill] [--wait SECS] [--strict] [--accept-ignore]
# The one way to update an aix index (git hook, SessionStart hook, cron, agents): a locked, logged, low-priority
# run of `aix update`, optionally followed by deadline-bound embedding and local-LLM summaries.
#   (default)        incremental update only (no embedding): ~20-300 ms on a 1,200-file repo
#   --full           re-extract every file
#   --embed SECS     then embed pending entries for up to SECS seconds (resumable)
#   --summaries SECS then write one-line local-LLM summaries for up to SECS seconds (resumable)
#   --backfill       embed in 300 s chunks until nothing is pending (or a chunk makes no progress)
#   --wait SECS      wait this long for another refresh's UPDATE step to finish (default 120), then skip
#   --strict         exit non-zero on failure (default: always exit 0, so hooks never fail a commit or a session)
#   --accept-ignore  build even with .gitignore findings (`aix ignore-check`), recording the user's decision. Without it a
#                    first build or --full with unaccepted findings is refused: the STOP block goes to stderr, exit 3
#                    with --full/--strict (0 otherwise, so hooks stay quiet)
# Locks live in /tmp/aix-locks-UID/ keyed by the db path (so deleting .aix cannot split them) and are
# never inherited by the children: the update step runs under the "update" lock, which is released before the slow
# embed/summaries/backfill steps run under a separate "embed" lock (taken without waiting: if another embed is
# running, this run skips embedding, so a burst of post-commit refreshes does not queue behind one embed).
# Each run appends one line to <db dir>/refresh.log (kept to the last 500 lines, writes and trims under a log lock).
# Env: AIX_BIN (default `aix`), AIX_DB.
set -uo pipefail
umask 077   # every file these scripts create under .aix/ (sig, logs, markers) is private to the user
REPO=""; DB="${AIX_DB:-}"; FULL=0; EMBED=0; SUMM=0; BACKFILL=0; WAIT=120; STRICT=0; ACC=()
while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB="$2"; shift 2 ;;
    --full) FULL=1; shift ;;
    --embed) EMBED="$2"; shift 2 ;;
    --summaries) SUMM="$2"; shift 2 ;;
    --backfill) BACKFILL=1; shift ;;
    --wait) WAIT="$2"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --accept-ignore) ACC=(--accept-ignore); shift ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "aix-refresh: unknown option $1" >&2; exit 2 ;;
    *) REPO="$1"; shift ;;
  esac
done
BIN="${AIX_BIN:-aix}"
fail() { echo "aix-refresh: $*" >&2; [ "$STRICT" = 1 ] && exit 1; exit 0; }
command -v "$BIN" >/dev/null 2>&1 || fail "$BIN not on PATH"
ARG="$REPO"
REPO="$(git -C "${REPO:-$PWD}" rev-parse --show-toplevel 2>/dev/null || (cd "${REPO:-$PWD}" && pwd))" || fail "no repo"
# a subdirectory would refresh the enclosing repo's index without saying so: refuse and name it
if [ "$(cd "${ARG:-$PWD}" 2>/dev/null && pwd -P)" != "$(cd "$REPO" 2>/dev/null && pwd -P)" ]; then
  echo "aix-refresh: ${ARG:-the current directory} is inside the git repo $REPO, not its root: run aix-refresh $REPO" >&2
  exit 2
fi
[ -n "$DB" ] || DB="$REPO/.aix/index.db"
mkdir -p "$(dirname "$DB")" || fail "cannot create $(dirname "$DB")"
LOG="$(dirname "$DB")/refresh.log"
chmod 600 "$LOG" 2>/dev/null   # an older run may have made it group-readable
# Children never inherit the lock fds (9 update, 7 embed, 6 log): a killed refresh must not leave its embed holding a lock.
sk() { AIX_LOW=1 nice -n 10 "$BIN" --repo "$REPO" --db "$DB" "$@" 9>&- 7>&- 6>&-; }
# skq: run sk with output captured in a temp file instead of $(...)/pipes: those fork a subshell that would keep
# the lock fds open for as long as the child runs, even after this script was killed.
TMPO="$(mktemp)" && trap 'rm -f "$TMPO"' EXIT || fail "mktemp failed"
skq() { sk "$@" >"$TMPO" 2>&1; }
pending() { sk --no-refresh stats 2>/dev/null | sed -n 's/.*embeddings: \([0-9]*\) of .* pending.*/\1/p'; }
LOCKDIR="${AIX_LOCK_DIR:-/tmp/aix-locks-$(id -u)}"
mkdir -p -m 700 "$LOCKDIR" 2>/dev/null
{ [ -d "$LOCKDIR" ] && [ ! -L "$LOCKDIR" ] && [ -O "$LOCKDIR" ]; } || fail "unsafe lock dir $LOCKDIR"
KEY="$(printf '%s' "$(readlink -m "$DB")" | { sha1sum 2>/dev/null || cksum; } | cut -c1-16)"
# one log line, appended (and the log trimmed) under the log lock; the file is re-opened by path each time
log() {
  ( flock -w 10 6 || exit 0
    echo "$1" >> "$LOG"
    if [ "$(wc -l < "$LOG")" -gt 600 ]; then tail -500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; fi
  ) 6>"$LOCKDIR/$KEY.log.lock"
}

exec 9>"$LOCKDIR/$KEY.refresh.lock" || fail "cannot open lock"
flock -w "$WAIT" 9 || { log "$(date '+%F %T') skipped: another refresh held the lock for ${WAIT}s"; exit 0; }

t0=$(date +%s%N); rc=0; notes=()
args=("${ACC[@]}" update --quiet --embed-deadline 0); [ "$FULL" = 1 ] && args+=(--full)
skq "${args[@]}" || rc=$?; out=$(cat "$TMPO"); ums=$(( ($(date +%s%N) - t0) / 1000000 ))
if [ "$rc" = 2 ] && grep -q '^STOP: .gitignore is missing or incomplete' "$TMPO"; then
  # the .gitignore preflight refused a first build / --full: the user decides (aix ignore-check, --accept-ignore)
  cat "$TMPO" >&2
  log "$(date '+%F %T') refused: .gitignore findings not accepted (aix ignore-check)"
  if [ "$STRICT" = 1 ] || [ "$FULL" = 1 ]; then exit 3; fi
  exit 0
fi
notes+=("update rc=$rc ${ums}ms${out:+: ${out//$'\n'/ | }}")   # the update alone (aix-watch reads it)
flock -u 9; exec 9>&-   # update done: later refreshes may start while this one embeds
have_embed=0
if [ "$rc" = 0 ] && { [ "$EMBED" != 0 ] || [ "$BACKFILL" = 1 ] || [ "$SUMM" != 0 ]; }; then
  exec 7>"$LOCKDIR/$KEY.embed.lock" && flock -n 7 && have_embed=1
  [ "$have_embed" = 1 ] || notes+=("embed/summaries skipped: another run is embedding")
fi
if [ "$rc" = 0 ] && [ "$have_embed" = 1 ] && [ "$EMBED" != 0 ]; then
  skq --no-refresh embed --deadline "$EMBED" || true; notes+=("embed: $(tail -1 "$TMPO")")
fi
if [ "$rc" = 0 ] && [ "$have_embed" = 1 ] && [ "$BACKFILL" = 1 ]; then
  before=$(pending); before=${before:-0}
  while [ "${before:-0}" -gt 0 ]; do
    sk --no-refresh embed --deadline 300 >/dev/null 2>&1 || { rc=$?; break; }
    after=$(pending); after=${after:-0}
    [ "$after" -lt "$before" ] || { notes+=("backfill stalled at $after pending (embedder down?)"); break; }
    before=$after
  done
  notes+=("backfill: ${before:-0} pending")
fi
if [ "$rc" = 0 ] && [ "$have_embed" = 1 ] && [ "$SUMM" != 0 ]; then
  skq --no-refresh summarize --deadline "$SUMM" || true; notes+=("summaries: $(tail -1 "$TMPO")")
fi
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
line="$(date '+%F %T') rc=$rc ${ms}ms $(printf '%s; ' "${notes[@]}")"; line="${line%; }"
log "$line"
echo "$line"
[ "$rc" = 0 ] || fail "failed (rc=$rc), see $LOG"
exit 0
