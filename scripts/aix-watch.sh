#!/usr/bin/env bash
# usage: aix-watch.sh [REPO] [--db PATH] [--idle SECS] [--poll SECS] [--exit-after SECS] [--embed SECS] [--storage auto|fast|slow]
#                     [--once] [--stop] [--storage-check]
# Auto-refresh: watches the repo and, once files changed and then stayed untouched for a short quiet time, runs
# `aix-refresh --embed N` so the index (and its embeddings) catch up without anyone telling aix. Quiet time (ms):
# adaptive = the 25th percentile of the repo's recent gaps between edits + 500, kept within 2500..10500 (3500 until 5
# gaps are seen; measured on agent edit streams: p25 gap ~3 s, median ~10 s); 10500 when a change touches more than
# 200 files (checkout, rebase, formatter); and never more than 30500 ms after the first pending change, so a long
# stream of edits still refreshes. Queries refresh changed files themselves, so this only bounds how stale the
# background parts (hints, embeddings, derived stages) can get. --idle SECS fixes the quiet time (no adaptation).
# Polls `git status` + the mtimes of dirty files every 0.5 s while changes are pending and every --poll seconds
# (default 2) otherwise (~10-30 ms per poll on a 1,200-file repo), so it needs no inotify tools. A commit, checkout or rebase (HEAD
# moves) counts as a change too.
# One watcher per index (flock on /tmp/aix-locks-UID/<hash of the db path>.watch.lock, deliberately outside
# the deletable .aix dir; children never inherit the lock fd): starting a second one is a silent no-op, so
# hooks can start it freely. Exits after --exit-after seconds with no change (default 14400 = 4 h; 0 = never,
# e.g. under systemd), or when the repo directory is gone / stops being a git repo (5 failed checks in a row).
# Registered logs: see `aix logs watch` (started from here when .aix/logs.toml has logs).
# --once: refresh if anything changed since the last refresh, then exit (for cron).
# --stop: stop this repo's watcher (pidfile + /proc start-time and cmdline check; a watcher from an older version
#   without a pidfile is found by argv + `git rev-parse --show-toplevel`, so one started in a subdirectory counts; never a
#   pattern kill) and exit.
# Embedding backlog: while idle it checks every --backlog SECS (default 60) and, if entries are still waiting for
# embeddings, spends --embed seconds on them (small batches, circuit breaker in aix), until nothing is pending.
# Slow storage (--storage auto, the default): a repo on a spinning disk, a USB stick or SD card, or a network/shared
# filesystem (nfs, smb, sshfs, 9p, WSL drvfs, virtiofs, VM shared folders) gets about twice the quiet times (5-20.5 s,
# 7 s until 5 gaps are seen, 30.5 s for big changes, refresh at most 60.5 s after the first change) and slower polls
# (5 s idle, 1.5 s while changes are pending), so the watcher does not keep the disk busy while edits are still
# coming. What it measures wins over what the disk claims: once 5 refreshes ran, a median index update over 1500 ms or
# a median change poll over 200 ms switches to the slow timings, and both under half of that switches back. The class
# and its reason go to <db>.watch.storage (shown by `aix stats`). --storage fast|slow fixes the class; --poll still
# wins for the idle poll. --storage-check prints the detected class and reason and exits.
# Env: AIX_BIN (default `aix`), AIX_DB, AIX_SYSFS (default /sys, for tests).
set -uo pipefail
umask 077   # every file these scripts create under .aix/ (sig, logs, markers) is private to the user
REPO=""; DB="${AIX_DB:-}"; IDLE=""; POLL=""; STORAGE=auto; SCHECK=0; EXIT_AFTER=14400; EMBED=30; ONCE=0; BACKLOG=60; STOP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB="$2"; shift 2 ;;
    --idle) IDLE="$2"; shift 2 ;;
    --poll) POLL="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --storage-check) SCHECK=1; shift ;;
    --exit-after) EXIT_AFTER="$2"; shift 2 ;;
    --embed) EMBED="$2"; shift 2 ;;
    --backlog) BACKLOG="$2"; shift 2 ;;
    --once) ONCE=1; shift ;;
    --stop) STOP=1; shift ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "aix-watch: unknown option $1" >&2; exit 2 ;;
    *) REPO="$1"; shift ;;
  esac
done
case "$STORAGE" in auto|fast|slow) ;; *) echo "aix-watch: --storage takes auto, fast or slow" >&2; exit 2 ;; esac
for nv in "--idle:$IDLE" "--poll:$POLL" "--exit-after:$EXIT_AFTER" "--embed:$EMBED" "--backlog:$BACKLOG"; do
  v="${nv#*:}"; [ -z "$v" ] || [[ "$v" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "aix-watch: ${nv%%:*} takes a number of seconds, got '$v'" >&2; exit 2; }
done
ARG="$REPO"
REPO="$(git -C "${REPO:-$PWD}" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "aix-watch: not a git repo: ${ARG:-$PWD}" >&2
  [ -n "$ARG" ] && exit 2   # an explicit path that is no repo is a usage error; the cwd form stays quiet for hooks
  exit 0
}
# a subdirectory would watch the enclosing repo without saying so (the --stop form looks it up on purpose)
if [ "$STOP" = 0 ] && [ "$(cd "${ARG:-$PWD}" 2>/dev/null && pwd -P)" != "$(cd "$REPO" 2>/dev/null && pwd -P)" ]; then
  echo "aix-watch: ${ARG:-the current directory} is inside the git repo $REPO, not its root: run aix-watch $REPO" >&2
  exit 2
fi

# Storage class of the repo's filesystem: prints "slow <reason>" or "fast <reason>" (unknown counts as fast).
# Linux only (findmnt + sysfs, no root); a device-mapper/RAID/LVM volume is slow when any disk under it is.
SYSFS="${AIX_SYSFS:-/sys}"
disk_class() {   # $1 = kernel block name (sda1, nvme0n1p2, dm-0, mmcblk0p1); $2 = depth guard
  local n="$1" d="${2:-0}" b real s r
  [ "$d" -le 8 ] || { echo fast "device chain too deep"; return; }
  b="$SYSFS/class/block/$n"
  [ -e "$b" ] || { echo fast "no sysfs entry for $n"; return; }
  real="$(readlink -f "$b")"
  if [ -f "$b/partition" ]; then n="${real%/*}"; n="${n##*/}"; real="${real%/*}"; fi
  local first=""
  for s in "$SYSFS/block/$n/slaves/"*; do
    [ -e "$s" ] || continue
    r="$(disk_class "${s##*/}" $((d + 1)))"
    case "$r" in slow*) echo "$r"; return ;; esac
    first="${first:-$r}"
  done
  [ -n "$first" ] && { echo "$first"; return; }
  case "$real" in */usb*) echo slow "USB disk $n"; return ;; esac
  case "$n" in
    mmcblk*) echo slow "SD/eMMC card $n"; return ;;
    nvme*) echo fast "NVMe disk $n"; return ;;
  esac
  if [ "$(cat "$SYSFS/block/$n/queue/rotational" 2>/dev/null)" = 1 ]; then echo slow "rotational disk $n"; return; fi
  echo fast "solid-state disk $n"
}
storage_class() {
  command -v findmnt >/dev/null 2>&1 || { echo fast "no findmnt (not Linux?)"; return; }
  local src fs
  read -r src fs < <(findmnt -no SOURCE,FSTYPE -T "$REPO" 2>/dev/null)
  case "$fs" in
    nfs*|cifs|smb*|9p|drvfs|virtiofs|vboxsf|afs|ceph|glusterfs|davfs|fuse.sshfs|fuse.rclone|fuse.s3fs|fuse.gcsfuse|fuse.vmhgfs-fuse|fuse.drvfs)
      echo slow "network/shared filesystem ($fs)"; return ;;
    "") echo fast "filesystem unknown"; return ;;
  esac
  case "$src" in
    /dev/*) local real; real="$(readlink -f "$src" 2>/dev/null)"; real="${real:-$src}"
            local r; r="$(disk_class "${real##*/}")"; echo "${r} ($fs)" ;;
    *) echo fast "$fs on ${src:-?}" ;;
  esac
}
if [ "$SCHECK" = 1 ]; then storage_class; exit 0; fi
# Lock/pid files live outside the repo, keyed by the absolute db path, so `rm -rf .aix` cannot hand the
# same index to a second watcher. (Same helper in aix-refresh.sh.)
LOCKDIR="${AIX_LOCK_DIR:-/tmp/aix-locks-$(id -u)}"
mkdir -p -m 700 "$LOCKDIR" 2>/dev/null
{ [ -d "$LOCKDIR" ] && [ ! -L "$LOCKDIR" ] && [ -O "$LOCKDIR" ]; } || { echo "aix-watch: unsafe lock dir $LOCKDIR" >&2; exit 0; }
keyof() { printf '%s' "$(readlink -m "$1")" | { sha1sum 2>/dev/null || cksum; } | cut -c1-16; }

starttime() { sed -E 's/^[0-9]+ \(.*\) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f20; }   # field 22 of /proc/PID/stat
is_watcher() {   # pid $1 is a live aix-watch whose start time is $2 (guards against pid reuse)
  [ -r "/proc/$1/cmdline" ] && [ "$(starttime "$1")" = "$2" ] || return 1
  local t; while IFS= read -r -d '' t; do case "${t##*/}" in aix-watch|aix-watch.sh) return 0 ;; esac; done < "/proc/$1/cmdline"
  return 1
}
kill_wait() { kill "$1" 2>/dev/null; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$1" 2>/dev/null || break; sleep 0.2; done; }
# stop_watchers: stop this repo's watcher(s), never by pattern.
#   1. pidfile + /proc start-time + cmdline check, in this lock dir;
#   2. a watcher started by an older version has no (readable) pidfile: find it by argv. The script name must be the
#      command (after at most a shell/setsid/env prefix); its repo argument (or, without one, its cwd) must have THIS repo
#      as `git rev-parse --show-toplevel`, so a watcher started from a subdirectory is found too.
stop_watchers() {
  local db pf pid st d p top cwd i n idx a skip
  local -a av
  for db in "$DB" "$REPO/.aix/index.db"; do
    [ -n "$db" ] || continue
    pf="$LOCKDIR/$(keyof "$db").watch.pid"
    [ -r "$pf" ] || continue
    pid=""; st=""; read -r pid st < "$pf"
    if [ -n "$pid" ] && [ "$pid" != "$$" ] && is_watcher "$pid" "$st"; then
      kill_wait "$pid"; echo "aix-watch: stopped $pid"
    fi
    rm -f "$pf"
  done
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"; [ "$pid" != "$$" ] && [ -O "$d" ] || continue
    mapfile -d '' -t av < "$d/cmdline" 2>/dev/null || continue
    n=${#av[@]}; idx=-1
    for ((i = 0; i < n && i < 3; i++)); do
      if [[ "${av[i]##*/}" =~ ^(aix-watch|aix-watch\.sh)$ ]]; then
        if [ "$i" = 0 ]; then idx=0; else case "${av[i-1]##*/}" in bash|sh|dash|setsid|env|nice|timeout|nohup) idx=$i ;; esac; fi
        break
      fi
    done
    [ "$idx" -ge 0 ] || continue
    p=""; skip=0
    for ((i = idx + 1; i < n; i++)); do
      a="${av[i]}"
      case "$a" in
        --stop|--once|--storage-check|-h|--help) skip=1; break ;;
        --db|--idle|--poll|--exit-after|--embed|--backlog|--storage) i=$((i + 1)) ;;
        -*) ;;
        *) p="$a"; break ;;
      esac
    done
    [ "$skip" = 0 ] || continue
    cwd="$(readlink "$d/cwd" 2>/dev/null)" || continue
    top="$(cd "$cwd" 2>/dev/null && git -C "${p:-.}" rev-parse --show-toplevel 2>/dev/null)" || continue
    if [ "$top" = "$REPO" ]; then kill_wait "$pid"; echo "aix-watch: stopped $pid"; fi
  done
  return 0
}
[ -n "$DB" ] || DB="$REPO/.aix/index.db"
KEY="$(keyof "$DB")"
LOCK="$LOCKDIR/$KEY.watch.lock"; PIDFILE="$LOCKDIR/$KEY.watch.pid"
if [ "$STOP" = 1 ]; then
  stopped="$(stop_watchers)"
  if [ -n "$stopped" ]; then printf '%s\n' "$stopped"; exit 0; fi
  echo "aix-watch: no watcher running for $REPO" >&2
  exit 1
fi

mkdir -p "$(dirname "$DB")" || exit 0
here="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
REFRESH="$(command -v aix-refresh || echo "$here/aix-refresh.sh")"
STAMP="$DB.watch.sig"
chmod 600 "$STAMP" 2>/dev/null   # an older run may have made it group-readable

exec 8>"$LOCK" || exit 0
flock -n 8 || exit 0          # another watcher already covers this index
LW_PID=""
[ "$ONCE" = 1 ] || { printf '%s %s\n' "$$" "$(starttime $$)" > "$PIDFILE"; trap '[ -n "$LW_PID" ] && kill "$LW_PID" 2>/dev/null; rm -f "$PIDFILE"' EXIT; }
# Every child runs with fd 8 closed (8>&-): a long refresh/embed or a `sleep` must not keep the lock alive after
# the watcher dies, or a restart would be refused until the child ends.

# Change signature: HEAD + dirty/untracked paths (NUL-parsed from `git status -z`, so odd names and renames are
# exact) + their full-precision mtimes and sizes (catches repeated edits of a dirty file), the stat calls batched through xargs.
# Above BIG changed paths the stat pass is replaced by one hash of `git ls-files -m -o` (status line + names only).
BIG="${AIX_WATCH_BIG:-20000}"
sig() {
  cd "$REPO" 2>/dev/null || { echo gone; return 1; }
  local rec skip=0 xy p; local -a recs=() paths=()
  {
    git rev-parse HEAD 2>/dev/null
    while IFS= read -r -d '' rec; do
      if [ "$skip" = 1 ]; then skip=0; recs+=("old:$rec"); continue; fi   # the other half of a rename/copy
      xy=${rec:0:2}; p=${rec:3}
      case "$xy" in R?|C?|?R|?C) skip=1 ;; esac
      case "/$p" in */.aix/*) continue ;; esac
      recs+=("$rec"); paths+=("$p")
    done < <(git status --porcelain=v1 -z -uall --ignore-submodules 2>/dev/null)
    [ "${#recs[@]}" -gt 0 ] && printf '%s\0' "${recs[@]}"
    if [ "${#paths[@]}" -gt "$BIG" ]; then
      git ls-files -m -o --exclude-standard -z 2>/dev/null | cksum
    elif [ "${#paths[@]}" -gt 0 ]; then
      # %y = full-precision mtime: two same-size edits within one second still differ (%Y was whole seconds)
      printf '%s\0' "${paths[@]}" | xargs -0 stat -c '%n %y %s' -- 2>/dev/null
    fi
  } 8>&- 9>&- | cksum
}
# the refresh line says how long the index update itself took ("update rc=0 412ms"): the watcher's storage measure
refresh() {
  local line u; line="$("$REFRESH" "$REPO" --db "$DB" --embed "$EMBED" --wait 30 2>/dev/null 8>&-)"
  u="$(printf '%s\n' "$line" | sed -n 's/.*update rc=0 \([0-9]*\)ms.*/\1/p' | tail -1)"
  [ -n "$u" ] && { UPD+=("$u"); [ "${#UPD[@]}" -gt 10 ] && UPD=("${UPD[@]:1}"); }
  sig > "$STAMP"
}
SK="${AIX_BIN:-aix}"
pending() { "$SK" --repo "$REPO" --db "$DB" --no-refresh stats 2>/dev/null 8>&- | sed -n 's/.*embeddings: \([0-9]*\) of .* pending.*/\1/p'; }
backlog_at=0
# Registered logs (`aix logs add`, .aix/logs.toml): one `aix logs watch` child (stat polling of only those paths, own flock,
# exits when nothing is registered); started when registrations exist, restarted if it died.
LOGS_TOML="$(dirname "$DB")/logs.toml"
logs_watch() {
  # at least one registered log that is not paused (unwatched / auto-stopped)
  [ -r "$LOGS_TOML" ] || return 0
  local nlog npaused
  nlog="$(grep -c '^\[\[log\]\]' "$LOGS_TOML" 2>/dev/null)"; npaused="$(grep -c '^paused = true' "$LOGS_TOML" 2>/dev/null)"
  [ "${nlog:-0}" -gt "${npaused:-0}" ] || return 0
  { [ -n "$LW_PID" ] && kill -0 "$LW_PID" 2>/dev/null; } && return 0
  "$SK" --repo "$REPO" --db "$DB" --no-refresh logs watch --exit-after "$EXIT_AFTER" >/dev/null 2>&1 8>&- & LW_PID=$!
}

cur=$(sig)
if [ "$ONCE" = 1 ]; then
  [ "$cur" = "$(cat "$STAMP" 2>/dev/null)" ] || refresh
  exit 0
fi
[ "$cur" = "$(cat "$STAMP" 2>/dev/null)" ] || refresh   # catch up on edits made while no watcher ran
ms() { date +%s%3N; }
# Quiet time in ms: fixed by --idle, else adaptive from the last 20 gaps between detected changes.
GAPS=(); BIG_FILES=200
# timings per storage class (see the header); --poll fixes the idle poll for both
USER_POLL="$POLL"
set_class() {   # $1 fast|slow, $2 reason; records the class next to the index when it changes
  [ "$1" = "${CLASS:-}" ] && return
  CLASS="$1"
  if [ "$1" = slow ]; then MIN_Q=5000; MAX_Q=20500; BIG_Q=30500; CAP_MS=60500; START_Q=7000; POLL="${USER_POLL:-5}"; PEND_POLL=1.5
  else MIN_Q=2500; MAX_Q=10500; BIG_Q=10500; CAP_MS=30500; START_Q=3500; POLL="${USER_POLL:-2}"; PEND_POLL=0.5; fi
  printf '%s %s %s\n' "$(date '+%F %T')" "$1" "$2" > "$DB.watch.storage" 2>/dev/null
}
UPD=(); POLLS=()   # last 10 update times and last 20 change-poll times (ms)
median() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
measure() {   # auto mode: switch on what refreshes and polls actually cost
  [ "$STORAGE" = auto ] && [ "${#UPD[@]}" -ge 5 ] && [ "${#POLLS[@]}" -ge 5 ] || return 0
  local u p; u=$(median "${UPD[@]}"); p=$(median "${POLLS[@]}")
  if [ "$CLASS" = fast ] && { [ "$u" -gt 1500 ] || [ "$p" -gt 200 ]; }; then set_class slow "measured: median update ${u} ms, poll ${p} ms"
  elif [ "$CLASS" = slow ] && [ "$u" -lt 750 ] && [ "$p" -lt 100 ]; then set_class fast "measured: median update ${u} ms, poll ${p} ms"; fi
}
if [ "$STORAGE" = auto ]; then read -r c r < <(storage_class); set_class "$c" "$r"; else set_class "$STORAGE" "set by --storage"; fi
quiet_ms() {
  if [ -n "$IDLE" ]; then awk -v s="$IDLE" 'BEGIN{printf "%d", s*1000}'; return; fi
  [ "${pending_files:-0}" -gt "$BIG_FILES" ] && { echo "$BIG_Q"; return; }
  [ "${#GAPS[@]}" -lt 5 ] && { echo "$START_Q"; return; }
  local p25; p25=$(printf '%s\n' "${GAPS[@]}" | sort -n | awk '{a[NR]=$1} END{i=int((NR-1)*0.25)+1; print a[i]}')
  local q=$((p25 + 500)); [ "$q" -lt "$MIN_Q" ] && q=$MIN_Q; [ "$q" -gt "$MAX_Q" ] && q=$MAX_Q; echo "$q"
}
changed_count() { git -C "$REPO" status --porcelain -z --untracked-files=normal 2>/dev/null | tr -cd '\0' | wc -c; }
# start from the signature the last refresh recorded, not a fresh one: an edit made while the watcher was starting
# (after the catch-up refresh) must still count as a change
last=$(cat "$STAMP" 2>/dev/null); changed_at=0; first_change=0; last_change_ms=0; pending_files=0; quiet_since=$(date +%s); bad=0
while :; do
  if [ "$changed_at" != 0 ]; then sleep "$PEND_POLL" 8>&-; else sleep "$POLL" 8>&-; fi
  [ "$ONCE" = 1 ] || logs_watch
  # repo moved/deleted (or no longer a git repo): give up after 5 failed checks in a row
  if [ -d "$REPO" ] && git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then bad=0; else bad=$((bad+1)); [ "$bad" -ge 5 ] && exit 0; continue; fi
  now=$(date +%s); nms=$(ms); s=$(sig)
  POLLS+=($(( $(ms) - nms ))); [ "${#POLLS[@]}" -gt 20 ] && POLLS=("${POLLS[@]:1}")
  if [ "$s" != "$last" ]; then
    last=$s
    if [ "$last_change_ms" != 0 ]; then g=$((nms - last_change_ms)); [ "$g" -le 600000 ] && { GAPS+=("$g"); [ "${#GAPS[@]}" -gt 20 ] && GAPS=("${GAPS[@]:1}"); }; fi
    last_change_ms=$nms; changed_at=$nms; [ "$first_change" = 0 ] && first_change=$nms
    pending_files=$(changed_count); quiet_since=$now; continue
  fi
  if [ "$changed_at" != 0 ] && { [ $((nms - changed_at)) -ge "$(quiet_ms)" ] || [ $((nms - first_change)) -ge "$CAP_MS" ]; }; then
    refresh; measure; changed_at=0; first_change=0; quiet_since=$(date +%s)
  elif [ "$changed_at" = 0 ] && [ "$BACKLOG" != 0 ] && [ $((now - backlog_at)) -ge "$BACKLOG" ]; then
    backlog_at=$now
    p=$(pending); [ "${p:-0}" -gt 0 ] && "$REFRESH" "$REPO" --db "$DB" --embed "$EMBED" --wait 0 >/dev/null 2>&1 8>&-
  fi
  [ "$EXIT_AFTER" != 0 ] && [ "$changed_at" = 0 ] && [ $((now - quiet_since)) -ge "$EXIT_AFTER" ] && exit 0
done
