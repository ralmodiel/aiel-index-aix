#!/usr/bin/env bash
# PreToolUse hook (matcher Bash|PowerShell|Grep|Glob|Read): a code lookup on indexed files gets one combined hint
# (hookSpecificOutput.additionalContext) naming the aix line that answers it; an exact read it can reproduce byte for
# byte (sed -n/head/tail/cat; Grep/Glob too unless AIX_HOOK_DENY_GREP=0) is answered instead (permissionDecision "deny" with the
# answer as the reason; AIX_HOOK_DENY=0 turns that off). Read, Edit, Write and anything with side effects are never
# denied. Silent when aix is missing or for paths aix cannot answer; in a git checkout with no index yet it names the
# one-time index command once per session.
# installed next to `aix` by scripts/install.sh: find it even when that dir is not on the hook's PATH
PATH="$(dirname "$(readlink -f "$0")"):$PATH"
command -v aix >/dev/null 2>&1 || exit 0
cd "${CLAUDE_PROJECT_DIR:-$PWD}" 2>/dev/null || exit 0
timeout 3 aix hook pretool 2>/dev/null || true
exit 0
