#!/usr/bin/env bash
# usage: aix-init [REPO] [--shared] [--mcp] [--no-git-hook] [--no-watch] [--allow-data | --no-allow-data] [--accept-ignore] [--uninstall]
# Step 2 of 2 (after scripts/install.sh): sets aix up for one repo in one command, idempotently:
#   1. builds the index (.aix/index.db, ignores itself) through aix-refresh, with 30 s of embedding
#   2. Claude Code: the aix skill and /brief /impact /bugs commands in .claude/, the SessionStart and
#      PreToolUse hooks, and allow rules for the read-only `aix <query>` commands (not install-git-hook), merged into .claude/settings.local.json
#      (yours only; --shared writes .claude/settings.json so the team gets it)
#   3. a post-commit git hook that refreshes the index in the background (--no-git-hook to skip)
#   4. starts the auto-refresh watcher (--no-watch to skip)
#   --mcp also registers the MCP server in .mcp.json (the CLI on Bash measured faster: no extra tool-loading turn)
#   --allow-data (opt-in, per repo) lets Claude store and delete data sets without asking: adds exactly Bash(aix put:*),
#   Bash(aix sets rm:*) to .claude/settings.local.json (sets prune still asks) and allow_data = true to .aix/config.toml
#   (which also enables put / sets rm through MCP); --no-allow-data takes both back. Without it Claude asks first.
#   --uninstall removes everything above that it added (the index directory too; settings/.mcp.json files only if
#   aix created them and they are now empty; only THIS repo's watcher is stopped)
# Also marks the repo (.aix/initialized): the SessionStart hook builds an index and starts a watcher only in
# marked repos (not in every worktree or clone Claude Code is opened in).
# Existing settings are merged, never overwritten: other hooks (also ones sharing a group with ours) and permissions are
# kept; --uninstall removes only the allow rules aix-init added (recorded in .aix/created-files), and the skill/commands
# only while they are unmodified (a modified copy is kept; an edited copy that an upgrade replaces is saved as .bak).
# .gitignore preflight first (`aix ignore-check --gate`, read-only): with findings the user has not accepted it prints
# them and a STOP line and exits 3 with nothing changed; --accept-ignore (or --yes) indexes as is and records the decision.
# Preflight: every file it will touch (settings, .mcp.json) must parse and be writable BEFORE anything is stopped or
# moved, so a failure leaves the repo exactly as it was.
set -euo pipefail
umask 077   # every file this script creates (.aix/initialized, created-files, ...) is private to the user
REPO_ARG=""; SHARED=0; MCP=0; GITHOOK=1; WATCH=1; UNINSTALL=0; DATA=""; ACCEPT=0
for a in "$@"; do
  case "$a" in
    --shared) SHARED=1 ;; --mcp) MCP=1 ;; --no-git-hook) GITHOOK=0 ;; --no-watch) WATCH=0 ;; --uninstall) UNINSTALL=1 ;; --accept-ignore|--yes) ACCEPT=1 ;;
    --allow-data) DATA=on ;; --no-allow-data) DATA=off ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "aix-init: unknown option $a" >&2; exit 2 ;;
    *) REPO_ARG="$a" ;;
  esac
done
die() { echo "aix-init: $*" >&2; exit 1; }
command -v aix >/dev/null 2>&1 || { echo "aix is not installed: run scripts/install.sh from the aiel-index clone" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "aix-init needs python3 to merge .claude/settings JSON" >&2; exit 1; }
REPO="$(git -C "${REPO_ARG:-$PWD}" rev-parse --show-toplevel 2>/dev/null)" || { echo "not a git repository: ${REPO_ARG:-$PWD}" >&2; exit 1; }
# a subdirectory (or a plain directory inside a repo) would silently act on the enclosing repo: name it and stop
here_dir="$(cd "${REPO_ARG:-$PWD}" 2>/dev/null && pwd -P)"
if [ "$here_dir" != "$(cd "$REPO" && pwd -P)" ]; then
  echo "aix-init: ${REPO_ARG:-the current directory} ($here_dir) is inside the git repo $REPO, not its root; nothing was changed." >&2
  echo "aix-init: to set up that repo run: aix-init $REPO   (a separate repo here needs its own git init first)" >&2
  exit 2
fi
echo "aix-init: repo $REPO"
bindir="$(dirname "$(command -v aix)")"
share="${XDG_DATA_HOME:-$HOME/.local/share}/aix/claude-code"
LSET="$REPO/.claude/settings.local.json"; SSET="$REPO/.claude/settings.json"
MCPJSON="$REPO/.mcp.json"

# ---- .gitignore preflight: read-only and before anything is touched (no settings, no .aix, no index)
if [ "$UNINSTALL" = 0 ]; then
  ic=0; icout="$(aix --repo "$REPO" ignore-check --gate 2>&1)" || ic=$?
  if [ "$ic" = 1 ] && [ "$ACCEPT" = 0 ]; then
    printf '%s\n' "$icout"
    echo "aix-init: stopped before changing anything. Fix .gitignore (aix ignore-check --suggest), or re-run with --accept-ignore to index as is."
    exit 3
  elif [ "$ic" != 0 ] && [ "$ic" != 1 ]; then
    die "aix ignore-check failed (rc=$ic): $icout"
  fi
fi

# ---- JSON helpers (python3). pyset: .claude/settings*.json; pymcp: .mcp.json.
pyset() { python3 - "$@" <<'PY'
import json, os, re, shlex, sys
mode, path = sys.argv[1], sys.argv[2]
def die(msg): sys.exit("aix-init: " + msg)
LEGACY_RULE = ["Bash(aix:*)"]   # the blanket rule older releases wrote
# Read-only query commands only: NOT a blanket `aix:*` (that would also pre-approve `install-git-hook`, which
# writes an executable hook, `--db`/`--repo` redirection, `mcp` and `update`). The old blanket rule is removed.
QUERIES = ["brief", "impact", "scope", "callers", "callees", "outline", "trace", "explain", "bugs", "qa", "feature", "text", "endpoint", "symbol", "script", "tasks", "history",
           "find", "ask", "hints", "grep", "howto", "code", "table", "route", "sql", "schema", "stats", "card", "mask list", "mask test", "redact-test",
           # logs/pastes: queries only. NOT `logs add|rm|prune|mark|watch|alert` (unwatch only stops following: allowed), `paste add|rm|prune`, `attach` (they change what is indexed: Claude asks you)
           "logs errors", "logs unwatch", "logs grep", "logs show", "logs tail", "logs list", "logs suggest", "logs since-mark", "logs await", "logs alerts",
           "paste list", "paste show", "paste grep", "paste errors", "paste frames", "paste suggest", "file list", "wait"]
# privacy-check: exact read-only forms only; `--fix` purges and vacuums, so Claude asks you first
PRIVACY = ["Bash(aix privacy-check)", "Bash(aix privacy-check --deep)", "Bash(aix privacy-check --json)", "Bash(aix privacy-check --deep --json)"]
# data sets: listing and showing only (exact forms: a `sets:*` prefix would also approve `sets rm`); querying a set goes
# through the query rules above (`aix grep X @gate`, `aix code @gate:1-60`)
SETS = ["Bash(aix sets)", "Bash(aix sets --global)", "Bash(aix sets list:*)", "Bash(aix sets show:*)"]
# ignore-check: the read-only forms only; `--accept` records the user's decision, so Claude asks you first
IGNORE = ["Bash(aix ignore-check)", "Bash(aix ignore-check --json)", "Bash(aix ignore-check --suggest)"]
ALLOW = [f"Bash(aix {q}:*)" for q in QUERIES] + PRIVACY + SETS + IGNORE + ["Bash(aix-refresh:*)"]
# opt-in (aix-init --allow-data): store and delete data sets without asking
DATA_RULES = ["Bash(aix put:*)", "Bash(aix sets rm:*)"]  # sets prune stays asked (the user approved put and rm only)

def load(required):
    """(existed, dict) ; (True, None) for an unparseable file that has nothing to do with us (and is not required)."""
    if not os.path.exists(path): return False, {}
    try: raw = open(path, encoding="utf-8").read()
    except OSError as e: die(f"cannot read {path} ({e.strerror}); nothing was changed.")
    try:
        s = json.loads(raw) if raw.strip() else {}
        if not isinstance(s, dict): raise ValueError("the top level is not a JSON object")
    except ValueError as e:
        if not required and not re.search(r"aix-hook", raw): return True, None
        die(f"{path} is not plain JSON ({e}).\n  Claude Code accepts comments/trailing commas there, but aix-init cannot merge into them safely.\n  Fix or remove the comments, or add the hooks by hand (see integrations/claude-code/settings.hooks.json); nothing was changed.")
    return True, s

def commands(s):
    out = []
    hooks = s.get("hooks")
    if isinstance(hooks, dict):
        for groups in hooks.values():
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks", []) if isinstance(g, dict) else []):
                    if isinstance(h, dict): out.append(str(h.get("command", "")))
    return out
def allow_rules(s):
    perms = s.get("permissions")
    al = perms.get("allow") if isinstance(perms, dict) else None
    return [x for x in al if isinstance(x, str)] if isinstance(al, list) else []
def is_legacy(s):
    return any(x in LEGACY_RULE for x in allow_rules(s))
def is_ours(s):
    return any("aix-hook-" in c for c in commands(s))

def writable():
    if os.path.exists(path): return os.access(path, os.W_OK) and not os.path.isdir(path)
    d = os.path.dirname(path)
    while d and not os.path.exists(d): d = os.path.dirname(d)
    return os.access(d or ".", os.W_OK | os.X_OK)

if mode == "probe":      # probe PATH REQUIRED -> missing | legacy | ours | plain   (dies on unparseable + related)
    existed, s = load(sys.argv[3] == "1")
    print("missing" if not existed else "plain" if s is None else "legacy" if is_legacy(s) else "ours" if is_ours(s) else "plain")
    sys.exit(0)
if mode == "data":       # data PATH on|off MARKER : add or remove exactly DATA_RULES in the allow list
    on, marker = sys.argv[3] == "on", sys.argv[4]
    existed, s = load(True)
    perms = s.get("permissions") if isinstance(s.get("permissions"), dict) else {}
    al = [x for x in (perms.get("allow") if isinstance(perms.get("allow"), list) else [])]
    new = al + [r for r in DATA_RULES if r not in al] if on else [x for x in al if x not in DATA_RULES]
    if new == al and existed: print("data-set rules already " + ("on" if on else "off") + " in " + path); sys.exit(0)
    if new: perms["allow"] = new
    else: perms.pop("allow", None)
    if perms: s["permissions"] = perms
    else: s.pop("permissions", None)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tgt = os.path.realpath(path); tmp = tgt + ".aix-tmp"
        with open(tmp, "w") as f: f.write(json.dumps(s, indent=2) + "\n")
        if existed:
            try: os.chmod(tmp, os.stat(tgt).st_mode & 0o7777)
            except OSError: pass
        os.replace(tmp, tgt)
        if on:
            with open(marker, "a") as f:
                if not existed: f.write(path + "\n")
                for r in DATA_RULES:
                    if r not in al: f.write("rule\t" + path + "\t" + r + "\n")
    except OSError as e:
        die(f"cannot write {path} ({e.strerror}); the file was left as it was.")
    print(("data sets: put / sets rm allowed without asking (sets prune still asks) -> " if on else "data sets: put / sets rm ask again -> ") + path)
    sys.exit(0)
if mode == "writable":   # writable PATH : die unless the file (or the directory it would be created in) is writable
    if not writable(): die(f"{path} is not writable (permissions?); nothing was changed.")
    sys.exit(0)

def orig_path(marker, p):    # the bytes a file had before aix first rewrote it (uninstall restores them when nothing else changed)
    import hashlib
    return os.path.join(os.path.dirname(marker), "orig-" + hashlib.sha1(os.path.realpath(p).encode()).hexdigest()[:16] + ".json")
def keep_orig(marker, p):
    o = orig_path(marker, p)
    if os.path.exists(p) and not os.path.exists(o):
        try:
            with open(p, "rb") as src, open(o, "wb") as dst: dst.write(src.read())
            os.chmod(o, 0o600)
        except OSError: pass
def restored(marker, p, obj):  # the original bytes when they parse to the same object, else None
    try:
        b = open(orig_path(marker, p), "rb").read()
        return b if json.loads(b.decode() or "{}") == obj else None
    except (OSError, ValueError): return None
# mode == "apply": apply PATH ACTION MARKER BINDIR   ACTION = install | clean (drop the old blanket rule only) | uninstall
action, marker, bindir = sys.argv[3], sys.argv[4], sys.argv[5]
existed, s = load(action == "install")
if not existed and action != "install": sys.exit(0)
if s is None: sys.exit(0)
before = json.dumps(s, sort_keys=True)
try: created = open(marker).read().split("\n")
except OSError: created = []
recorded = {l.split("\t", 2)[2] for l in created if l.startswith("rule\t" + path + "\t")}
tracked = ("tracked\t" + path) in created
ours = {"SessionStart": (None, shlex.quote(f"{bindir}/aix-hook-session-start"), 20),
        "PreToolUse": ("Bash|PowerShell|Grep|Glob|Read", shlex.quote(f"{bindir}/aix-hook-pretool"), 5),
        "UserPromptSubmit": (None, shlex.quote(f"{bindir}/aix-hook-prompt"), 5)}
names = () if action == "clean" else ("aix-hook-",)
hooks = s.get("hooks") if isinstance(s.get("hooks"), dict) else {}
for ev, (matcher, cmd, timeout) in ours.items():
    out = []
    for g in hooks.get(ev, []) if isinstance(hooks.get(ev, []), list) else []:
        hs = g.get("hooks") if isinstance(g, dict) else None
        if not isinstance(hs, list): out.append(g); continue
        keep = [h for h in hs if not (isinstance(h, dict) and any(n in str(h.get("command", "")) for n in names))]
        if len(keep) == len(hs): out.append(g)           # not ours: untouched
        elif keep: out.append({**g, "hooks": keep})      # a user's own hook shares the group: only our entries go
    if action == "install":
        g = {"hooks": [{"type": "command", "command": cmd, "timeout": timeout}]}
        if matcher: g["matcher"] = matcher
        out.append(g)
    if out: hooks[ev] = out
    else: hooks.pop(ev, None)
if hooks: s["hooks"] = hooks
else: s.pop("hooks", None)
perms = s.get("permissions") if isinstance(s.get("permissions"), dict) else {}
al = perms.get("allow") if isinstance(perms.get("allow"), list) else []
out = []
for x in al:
    if isinstance(x, str):
        if x in LEGACY_RULE: continue
        if action == "uninstall" and (x == "mcp__aix" or x.startswith("mcp__aix__")): continue
        # only the rules aix-init added are removed (an identical rule the user wrote stays); no record = an older aix-init
        if action == "uninstall" and (x in ALLOW or x in DATA_RULES) and (x in recorded or not tracked): continue
    out.append(x)
out = list(dict.fromkeys(out))
added = []
if action == "install":
    added = [r for r in ALLOW if r not in out]
    out += added
if out:
    perms["allow"] = out
else:
    perms.pop("allow", None)
if perms: s["permissions"] = perms
else: s.pop("permissions", None)
if action == "uninstall" and not s and path in created:
    try: os.remove(path)
    except OSError as e: die(f"cannot remove {path} ({e.strerror}).")
    print("removed " + path + " (aix created it and nothing else was in it)")
    sys.exit(0)
changed = json.dumps(s, sort_keys=True) != before
try:
    if changed or not existed:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tgt = os.path.realpath(path); tmp = tgt + ".aix-tmp"
        if action == "install" and existed: keep_orig(marker, path)
        orig = restored(marker, path, s) if action != "install" else None
        with open(tmp, "wb" if orig is not None else "w") as f: f.write(orig if orig is not None else json.dumps(s, indent=2) + "\n")
        if existed:
            try: os.chmod(tmp, os.stat(tgt).st_mode & 0o7777)
            except OSError: pass
        os.replace(tmp, tgt)
    if action == "install":
        with open(marker, "a") as f:
            if not existed and path not in created: f.write(path + "\n")
            if not tracked: f.write("tracked\t" + path + "\n")
            for r in added: f.write("rule\t" + path + "\t" + r + "\n")
except OSError as e:
    die(f"cannot write {path} ({e.strerror}); the file was left as it was.")
if action == "install": print("hooks + allow rules -> " + path)
elif changed: print(("removed aix hooks/permissions from " if action == "uninstall" else "removed the old blanket Bash(aix:*) rule from ") + path)
PY
}

pymcp() { python3 - "$@" <<'PY'
import json, os, sys
mode, p = sys.argv[1], sys.argv[2]
def die(msg): sys.exit("aix-init: " + msg)
def load():
    existed = os.path.exists(p)
    try:
        s = json.load(open(p)) if existed and os.path.getsize(p) else {}
        if not isinstance(s, dict): raise ValueError("the top level is not a JSON object")
    except (ValueError, OSError) as e:
        die(f"{p} is not plain JSON ({e}); fix it or add/remove the MCP server by hand. Nothing was changed.")
    return existed, s
if mode == "probe":    # probe PATH : dies unless parseable and writable
    existed, s = load()
    ok = os.access(p, os.W_OK) if existed else os.access(os.path.dirname(p) or ".", os.W_OK | os.X_OK)
    if not ok: die(f"{p} is not writable (permissions?); nothing was changed.")
    sys.exit(0)
def orig_path(marker, p):    # the bytes a file had before aix first rewrote it (uninstall restores them when nothing else changed)
    import hashlib
    return os.path.join(os.path.dirname(marker), "orig-" + hashlib.sha1(os.path.realpath(p).encode()).hexdigest()[:16] + ".json")
def keep_orig(marker, p):
    o = orig_path(marker, p)
    if os.path.exists(p) and not os.path.exists(o):
        try:
            with open(p, "rb") as src, open(o, "wb") as dst: dst.write(src.read())
            os.chmod(o, 0o600)
        except OSError: pass
def restored(marker, p, obj):  # the original bytes when they parse to the same object, else None
    try:
        b = open(orig_path(marker, p), "rb").read()
        return b if json.loads(b.decode() or "{}") == obj else None
    except (OSError, ValueError): return None
action, marker = sys.argv[3], sys.argv[4]     # apply PATH install|uninstall MARKER [EXE]
existed, s = load()
try: created = open(marker).read().split("\n")
except OSError: created = []
srv = s.get("mcpServers") if isinstance(s.get("mcpServers"), dict) else {}
try:
    if action == "uninstall":
        srv.pop("aix", None)
        if srv: s["mcpServers"] = srv
        else: s.pop("mcpServers", None)
        if not s and p in created: os.remove(p); print("removed " + p)
        else:
            orig = restored(marker, p, s)
            if orig is not None: open(p, "wb").write(orig)
            else: open(p, "w").write(json.dumps(s, indent=2) + "\n")
    else:
        exe = sys.argv[5]
        cur = srv.get("aix")
        # keep a customised entry (extra args, env, ...): only the executable of a stock entry is swapped
        e = dict(cur if isinstance(cur, dict) else {})
        e.setdefault("type", "stdio")
        if not e.get("command") or os.path.basename(str(e["command"])) == "aix": e["command"] = exe
        if not isinstance(e.get("args"), list): e["args"] = ["mcp"]
        srv["aix"] = e; s["mcpServers"] = srv
        if not existed: open(marker, "a").write(p + "\n")
        else: keep_orig(marker, p)
        open(p, "w").write(json.dumps(s, indent=2) + "\n")
        print("MCP server -> " + p)
except OSError as e:
    die(f"cannot write {p} ({e.strerror}).")
PY
}

stop_watch() {   # THIS repo's watcher(s) (pidfile + start time + argv checked inside aix-watch --stop; no pattern kill)
  local w="$bindir/aix-watch"; [ -x "$w" ] || w="$(command -v aix-watch || true)"
  [ -n "$w" ] && "$w" "$REPO" --stop 2>/dev/null || true
}

# ---- preflight: decide which files get touched; each must parse and be writable BEFORE anything is stopped or moved.
if [ "$UNINSTALL" = 1 ]; then
  T_L=uninstall; T_S=uninstall
else
  sL="$(pyset probe "$LSET" 0)" || exit 1; sS="$(pyset probe "$SSET" 0)" || exit 1
  primary="$LSET"; other="$SSET"; so="$sS"
  if [ "$SHARED" = 1 ] || { [ "$sS" = legacy ] && [ "$sL" != legacy ]; }; then
    primary="$SSET"; other="$LSET"; so="$sL"
    [ "$SHARED" = 1 ] || echo "note: an older aix-init wired .claude/settings.json (shared); updating it there"
  fi
  other_action=none; [ "$so" = legacy ] && other_action=clean
  if [ "$primary" = "$LSET" ]; then T_L=install; T_S=$other_action; else T_S=install; T_L=$other_action; fi
  pyset probe "$primary" 1 >/dev/null || exit 1
fi
[ "$T_L" = none ] || pyset writable "$LSET" || exit 1
if [ -n "$DATA" ] && [ "$UNINSTALL" = 0 ]; then pyset probe "$LSET" 1 >/dev/null || exit 1; pyset writable "$LSET" || exit 1; fi
[ "$T_S" = none ] || pyset writable "$SSET" || exit 1
if [ -f "$MCPJSON" ] && { [ "$MCP" = 1 ] || [ "$UNINSTALL" = 1 ]; }; then pymcp probe "$MCPJSON" || exit 1
elif [ ! -f "$MCPJSON" ] && [ "$MCP" = 1 ]; then pymcp probe "$MCPJSON" || exit 1; fi
if [ "$UNINSTALL" = 0 ]; then
  mkdir -p "$REPO/.claude" 2>/dev/null && [ -w "$REPO/.claude" ] || die "cannot create or write $REPO/.claude (permissions?); nothing was changed."
fi

# ---- stop the watcher first, unconditionally: a second one must never start next to it. A fresh one is started at the
#      end (unless --no-watch).
WATCH_STOPPED=""; WATCH_STARTED=0
if [ "$UNINSTALL" = 0 ]; then
  WATCH_STOPPED="$(stop_watch)"
  [ -n "$WATCH_STOPPED" ] && printf '%s\n' "$WATCH_STOPPED"
  # a run that ends early (an error, Ctrl-C, a closed stdout) leaves the repo with the watcher it had
  restart_watch() {
    if [ -n "$WATCH_STOPPED" ] && [ "$WATCH_STARTED" = 0 ] && command -v aix-watch >/dev/null 2>&1; then
      (setsid aix-watch "$REPO" </dev/null >/dev/null 2>&1 &) || true
    fi
  }
  trap restart_watch EXIT
  trap 'exit 141' PIPE; trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
fi
[ "$UNINSTALL" = 1 ] || mkdir -p "$REPO/.aix"
marker="$REPO/.aix/created-files"   # config files aix-init created itself (removed again by --uninstall if empty), rules it added, hashes of what it copied

rec_get() { awk -F'\t' -v k="$1" '$1=="hash" && $2==k {v=$3} END {print v}' "$marker" 2>/dev/null; }
rec_set() {   # rec_set REL SUM : remember the hash of what we copied (so an edited copy can be told from ours later)
  [ "$(rec_get "$1")" = "$2" ] && return 0
  { awk -F'\t' -v k="$1" '!($1=="hash" && $2==k)' "$marker" 2>/dev/null || true; printf 'hash\t%s\t%s\n' "$1" "$2"; } > "$marker.tmp" && mv "$marker.tmp" "$marker"
}
hash_of() {   # a file, or a directory tree
  if [ -d "$1" ]; then (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1)
  else sha256sum "$1" | cut -d' ' -f1; fi
}

# ---- hooks + allow rules in the settings file(s)
[ "$T_L" = none ] || pyset apply "$LSET" "$T_L" "$marker" "$bindir"
[ "$T_S" = none ] || pyset apply "$SSET" "$T_S" "$marker" "$bindir"

# ---- data sets opt-in: the allow rules (settings.local.json, yours only) and allow_data in .aix/config.toml (MCP reads it)
if [ -n "$DATA" ] && [ "$UNINSTALL" = 0 ]; then
  pyset data "$LSET" "$DATA" "$marker"
  python3 - "$REPO/.aix/config.toml" "$DATA" <<'PY'
import os, re, sys
p, on = sys.argv[1], sys.argv[2] == "on"
try: lines = open(p).read().split("\n")
except FileNotFoundError: lines = []
# allow_data is a top-level key: it goes before the first [table]
lines = [l for l in lines if not re.match(r"\s*allow_data\s*=", l)]
if on:
    k = next((i for i, l in enumerate(lines) if l.strip().startswith("[")), len(lines))
    lines.insert(k, "allow_data = true   # aix-init --allow-data: put / sets rm through MCP")
text = "\n".join(lines).strip("\n")
if text or os.path.exists(p):
    with open(p, "w") as f: f.write(text + ("\n" if text else ""))
    os.chmod(p, 0o600)
PY
fi

if [ "$UNINSTALL" = 1 ]; then
  # skill + commands: removed only while unmodified (hash of what we copied, or of what this release ships)
  skill="$REPO/.claude/skills/aix"
  if [ -d "$skill" ]; then
    ch="$(hash_of "$skill")"; rec="$(rec_get skills/aix)"; sh=""; [ -d "$share/skills/aix" ] && sh="$(hash_of "$share/skills/aix")"
    if [ "$ch" = "$sh" ] || { [ -n "$rec" ] && [ "$ch" = "$rec" ]; } || { [ -z "$rec" ] && grep -q '^name: aix' "$skill/SKILL.md" 2>/dev/null; }; then rm -rf "$skill"
    else echo "kept $skill (your modified copy)"; fi
  fi
  for c in brief impact bugs; do
    f="$REPO/.claude/commands/$c.md"; [ -f "$f" ] || continue
    ch="$(hash_of "$f")"; rec="$(rec_get "commands/$c.md")"; sh=""; [ -f "$share/commands/$c.md" ] && sh="$(hash_of "$share/commands/$c.md")"
    if [ "$ch" = "$sh" ] || { [ -n "$rec" ] && [ "$ch" = "$rec" ]; } || { [ -z "$rec" ] && grep -qi 'aix' "$f"; }; then rm -f "$f"
    else echo "kept $f (your own or modified copy)"; fi
  done
  # the rules block (.claude/rules/aix.md): removed only while unmodified
  f="$REPO/.claude/rules/aix.md"
  if [ -f "$f" ]; then
    ch="$(hash_of "$f")"; rec="$(rec_get rules/aix.md)"; sh=""; [ -f "$share/rules/aix.md" ] && sh="$(hash_of "$share/rules/aix.md")"
    if [ "$ch" = "$sh" ] || { [ -n "$rec" ] && [ "$ch" = "$rec" ]; }; then rm -f "$f"; else echo "kept $f (your modified copy)"; fi
  fi
  hook="$(git -C "$REPO" rev-parse --git-path hooks)/post-commit"; case "$hook" in /*) ;; *) hook="$REPO/$hook" ;; esac
  # the hook file is shared by all worktrees of a clone: leave it while another worktree still uses aix
  others=""
  while IFS= read -r wt; do
    [ -n "$wt" ] && [ "$(readlink -f "$wt")" != "$(readlink -f "$REPO")" ] || continue
    if [ -f "$wt/.aix/initialized" ]; then others="${others:+$others, }$wt"; fi
  done < <(git -C "$REPO" worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p')
  if grep -q ">>> aix post-commit >>>" "$hook" 2>/dev/null; then
    if [ -n "$others" ]; then echo "left the aix post-commit hook in place: it is shared and these worktrees still use aix: $others"
    else
      if [ -f "$hook.pre-aix" ]; then mv "$hook.pre-aix" "$hook"; else rm -f "$hook"; fi
      echo "removed the aix post-commit hook"
    fi
  fi
  [ -f "$MCPJSON" ] && pymcp apply "$MCPJSON" uninstall "$marker"
  # stop only THIS repo's watcher, and drop this index's lock and pid files
  stop_watch
  lockdir="${AIX_LOCK_DIR:-/tmp/aix-locks-$(id -u)}"
  if [ -d "$lockdir" ] && [ -O "$lockdir" ] && [ ! -L "$lockdir" ]; then
    key="$(printf '%s' "$(readlink -m "$REPO/.aix/index.db")" | { sha1sum 2>/dev/null || cksum; } | cut -c1-16)"
    rm -f "$lockdir/$key".{embed,log,refresh,watch}.lock "$lockdir/$key.watch.pid" 2>/dev/null || true
  fi
  rm -rf "$REPO/.aix"
  rmdir "$REPO/.claude/commands" "$REPO/.claude/skills" "$REPO/.claude/rules" "$REPO/.claude" 2>/dev/null || true
  echo "aix removed from $REPO"
  exit 0
fi

# Skill + slash commands (project scope, so they travel with --shared). A copy that differs from the installed one
# (the skill gains commands between releases) is replaced and what changed is printed; a copy YOU edited since we
# copied it (hash recorded in .aix/created-files) is saved as .bak first.
if [ -d "$share/skills/aix" ]; then
  mkdir -p "$REPO/.claude/skills" "$REPO/.claude/commands"
  changes=""
  shipped="$(hash_of "$share/skills/aix")"
  if [ -d "$REPO/.claude/skills/aix" ]; then
    ch="$(hash_of "$REPO/.claude/skills/aix")"; rec="$(rec_get skills/aix)"
    if [ "$ch" != "$shipped" ] && [ -n "$rec" ] && [ "$ch" != "$rec" ]; then
      # SKILL.md is renamed inside the copy so Claude Code does not load it as a second skill
      bak="$REPO/.claude/skills/aix.bak"; rm -rf "$bak"; cp -a "$REPO/.claude/skills/aix" "$bak"
      find "$bak" -name SKILL.md -exec sh -c 'mv "$1" "$1.bak"' _ {} \;
      echo "your edited skill was saved as $bak (SKILL.md.bak) before the update"
    fi
    changes="$(diff -rq "$share/skills/aix" "$REPO/.claude/skills/aix" 2>&1 | sed -e 's|^Files .*/\([^/]*\) and .* differ$|skill: updated \1|' -e 's|^Only in .*aix[^:]*: \(.*\)$|skill: \1 added or removed|' || true)"
  else
    changes="skill: installed"
  fi
  if [ "$(hash_of "$REPO/.claude/skills/aix" 2>/dev/null || true)" != "$shipped" ]; then
    rm -rf "$REPO/.claude/skills/aix"; cp -r "$share/skills/aix" "$REPO/.claude/skills/"
  fi
  rec_set skills/aix "$shipped"
  for f in "$share"/commands/*.md; do
    t="$REPO/.claude/commands/$(basename "$f")"; rel="commands/$(basename "$f")"
    if [ -e "$t" ] && ! grep -qi 'aix' "$t" && [ -z "$(rec_get "$rel")" ]; then echo "kept your own $t"
    else
      if [ ! -e "$t" ]; then changes="${changes:+$changes$'\n'}command: $(basename "$f") installed"
      elif ! cmp -s "$f" "$t"; then
        rec="$(rec_get "$rel")"
        if [ -n "$rec" ] && [ "$(hash_of "$t")" != "$rec" ]; then cp -p "$t" "$t.bak"; echo "your edited $t was saved as $t.bak before the update"; fi
        changes="${changes:+$changes$'\n'}command: $(basename "$f") updated"
      fi
      cmp -s "$f" "$t" || cp "$f" "$t"
      rec_set "$rel" "$(hash_of "$f")"
    fi
  done
  # the rules block: a short "who calls / what breaks / trace -> aix first" instruction Claude Code loads as project
  # memory from .claude/rules/ (bench/RESULTS-sonnet.md: it is what makes Sonnet reach for aix); a copy you edited stays
  if [ -f "$share/rules/aix.md" ]; then
    t="$REPO/.claude/rules/aix.md"; rec="$(rec_get rules/aix.md)"
    if [ -f "$t" ] && [ -n "$rec" ] && [ "$(hash_of "$t")" != "$rec" ]; then echo "kept your edited $t"
    elif ! cmp -s "$share/rules/aix.md" "$t" 2>/dev/null; then
      mkdir -p "$REPO/.claude/rules"; [ -f "$t" ] && changes="${changes:+$changes$'\n'}rules: aix.md updated" || changes="${changes:+$changes$'\n'}rules: aix.md installed"
      cp "$share/rules/aix.md" "$t"; rec_set rules/aix.md "$(hash_of "$t")"
    else rec_set rules/aix.md "$(hash_of "$t")"
    fi
  fi
  if [ -n "$changes" ]; then echo "$changes"; echo "skill + /brief /impact /bugs + rules refreshed -> $REPO/.claude/"; else echo "skill + /brief /impact /bugs + rules already current in $REPO/.claude/"; fi
else
  echo "note: skill files not found in $share (re-run scripts/install.sh)"
fi

[ "$MCP" = 1 ] && pymcp apply "$MCPJSON" install "$marker" "$bindir/aix"

[ "$GITHOOK" = 1 ] && aix --repo "$REPO" install-git-hook --force

: > "$REPO/.aix/initialized"   # marker: SessionStart may build/refresh the index and start a watcher here
chmod 600 "$REPO/.aix/initialized" "$REPO/.aix/created-files" 2>/dev/null   # older runs made them group-readable
[ "$ACCEPT" = 1 ] && aix --repo "$REPO" ignore-check --accept
echo "building the index..."
aix-refresh "$REPO" --embed 30 --strict
if [ "$WATCH" = 1 ] && command -v aix-watch >/dev/null 2>&1; then
  (setsid aix-watch "$REPO" </dev/null >/dev/null 2>&1 &) && WATCH_STARTED=1 && echo "auto-refresh watcher started"
else
  WATCH_STARTED=1   # --no-watch: the user asked for none
fi
chmod 700 "$REPO/.aix" 2>/dev/null || true
echo
aix --repo "$REPO" --no-refresh card 2>/dev/null | head -12 || true
echo "privacy check:"
aix --repo "$REPO" --no-refresh privacy-check 2>&1 | head -12 || true
echo
echo "done. Start Claude Code in $REPO; try: aix brief <a route or menu label>   (undo: aix-init --uninstall)"
