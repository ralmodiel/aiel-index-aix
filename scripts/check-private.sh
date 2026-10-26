#!/bin/bash
# Fail if a tracked file (or the staged diff, with --staged) matches a private-marker deny list.
#   scripts/check-private.sh [--staged]
# The deny list is OUTSIDE the repo: one case-insensitive regex per line, '#' comments and blank lines ignored.
# Path: $AIX_PRIVATE_MARKERS, default ~/.config/aix/private-markers. If the file does not exist the check is skipped
# (exit 0 with a note), so contributors without a list are not blocked. Matching lines are printed as file:line only,
# never the matched text, so the output itself leaks nothing.
set -u
LIST=${AIX_PRIVATE_MARKERS:-$HOME/.config/aix/private-markers}
STAGED=0; [ "${1:-}" = "--staged" ] && STAGED=1
if [ ! -f "$LIST" ]; then echo "check-private: no deny list at $LIST, skipped"; exit 0; fi
PAT=$(mktemp); trap 'rm -f "$PAT"' EXIT
grep -vE '^[[:space:]]*(#|$)' "$LIST" > "$PAT"
[ -s "$PAT" ] || { echo "check-private: deny list is empty, skipped"; exit 0; }
cd "$(git rev-parse --show-toplevel)" || exit 2
if [ $STAGED = 1 ]; then
  # added lines only, per file, with new-file line numbers
  hits=$(git diff --cached --no-color -U0 --diff-filter=AMR | awk '
    /^\+\+\+ b\//{f=substr($0,7);next} /^@@/{split($3,a,",");n=substr(a[1],2)-1;next}
    /^\+/{n++; print f "\t" n "\t" substr($0,2)}' |
    while IFS=$'\t' read -r f n t; do printf '%s' "$t" | grep -qiE -f "$PAT" && echo "$f:$n"; done)
  hits=${hits:-}
  # file names too
  names=$(git diff --cached --name-only --diff-filter=AMR | grep -iE -f "$PAT" | sed 's/$/ (file name)/')
else
  hits=$(git grep -inIE -f "$PAT" -- . | cut -d: -f1,2)
  names=$(git ls-files | grep -iE -f "$PAT" | sed 's/$/ (file name)/')
fi
out=$(printf '%s\n%s\n' "$hits" "$names" | sed '/^$/d')
if [ -n "$out" ]; then
  echo "check-private: FAIL, private markers found (move the material out of the repo or genericise it):"
  printf '%s\n' "$out" | head -50
  exit 1
fi
echo "check-private: ok"
