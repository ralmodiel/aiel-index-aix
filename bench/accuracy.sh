#!/bin/bash
# Precision guard: builds the public repos (+ optionally one more repo's index copy) and FAILS (exit 1) unless every eval question has
# precision 1.0 and recall 1.0 and every must/mustnot term holds.
#   bench/accuracy.sh <aix binary> <repos dir (4 clones)> <work dir> [<expert eval.json> <repo> [index.db to copy]]
set -u
SK=$(realpath "$1"); REPOS=$(realpath "$2"); WORK=$(realpath -m "$3"); EVAL=${4:-}; SCH=${5:-}; SCHDB=${6:-}
HERE=$(cd "$(dirname "$0")" && pwd); mkdir -p "$WORK"; rc=0
python3 "$HERE/codegraph/score.py" --sk "$SK" --repos "$REPOS" --dbs "$WORK/dbs" --build --json "$WORK/cg.json" >"$WORK/cg.txt" 2>&1 || rc=1
python3 - "$WORK/cg.json" <<'P' || rc=1
import json,sys
j=json.load(open(sys.argv[1])); bad=[q for q in j["questions"] if q["p"]<1 or (q["r"] is not None and q["r"]<1) or not all(q["must"].values()) or not all(q["mustnot"].values())]
for q in bad: print("codegraph FAIL", q["id"], q["cmd"], "p", q["p"], "r", q["r"])
if j["ranges"]["go_wrong_end"]: print("go range errors", j["ranges"]); bad.append(1)
sys.exit(1 if bad else 0)
P
if [ -n "$EVAL" ]; then
  [ -n "$SCH" ] || { echo "usage: expert eval needs <repo> after <eval.json>" >&2; exit 2; }
  EVAL=$(realpath "$EVAL")
  DB="$WORK/expert.db"; cp "${SCHDB:-$SCH/.aix/index.db}" "$DB"
  AIX_EMBED_URL= "$SK" --repo "$SCH" --db "$DB" update --embed-deadline 0 >/dev/null 2>&1
  python3 "$HERE/expert/score.py" --eval "$EVAL" --sk "$SK" --db "$DB" --repo "$SCH" --json "$WORK/ex.json" >"$WORK/ex.txt" 2>&1 || rc=1
  python3 - "$WORK/ex.json" <<'P' || rc=1
import json,sys
j=json.load(open(sys.argv[1])); bad=[q for q in j["questions"] if q["precision"]<1 or q["recall"]<1 or q["must_missing"]]
for q in bad: print("expert FAIL", q["id"], "p", q["precision"], "r", q["recall"], q["must_missing"])
sys.exit(1 if bad else 0)
P
fi
[ $rc = 0 ] && echo "accuracy: PASS" || echo "accuracy: FAIL"; exit $rc
