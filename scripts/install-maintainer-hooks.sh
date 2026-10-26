#!/bin/bash
# Opt-in, for maintainers: install a pre-commit hook in THIS repo that runs scripts/check-private.sh --staged and
# blocks the commit when a staged line matches your private-marker deny list (see check-private.sh for the list).
#   scripts/install-maintainer-hooks.sh [--uninstall]
# It never runs on its own and touches only this repo's .git/hooks/pre-commit (an existing hook is kept and chained).
set -eu
ROOT=$(git rev-parse --show-toplevel); HOOKS=$(git rev-parse --git-path hooks); case $HOOKS in /*) ;; *) HOOKS=$ROOT/$HOOKS;; esac
H=$HOOKS/pre-commit; B="# >>> aix check-private >>>"; E="# <<< aix check-private <<<"
strip() { [ -f "$H" ] && awk -v b="$B" -v e="$E" '$0==b{s=1;next} $0==e{s=0;next} !s' "$H" > "$H.new" && mv "$H.new" "$H"; true; }
if [ "${1:-}" = "--uninstall" ]; then strip; echo "removed"; exit 0; fi
mkdir -p "$HOOKS"; [ -f "$H" ] || printf '#!/bin/sh\n' > "$H"
strip
printf '%s\n"%s/scripts/check-private.sh" --staged || exit 1\n%s\n' "$B" "$ROOT" "$E" >> "$H"
chmod +x "$H"; echo "installed pre-commit check in $H"
