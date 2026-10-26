#!/bin/bash
# usage: tests/regress/composition.sh [WORKDIR] — builds tiny generic git repos + data sets under WORKDIR (default: a mktemp dir) and checks aix's composition surface (pipes, sequences, paging, data sets, exit codes); prints OK/BUG per check and a SUMMARY, exit 1 on any BUG. Touches nothing outside WORKDIR (HOME and AIX_LOCK_DIR point into it; indexes via --db outside .aix).
set -u
W=${1:-$(mktemp -d)}
mkdir -p "$W/home" "$W/locks" "$W/db"
export HOME="$W/home" AIX_LOCK_DIR="$W/locks"
ok=0; bad=0
pass() { echo "OK   $1"; ok=$((ok+1)); }
fail() { echo "BUG  $1"; bad=$((bad+1)); }
expect() { # name expected actual
  if [ "$2" == "$3" ]; then pass "$1 (= $3)"; else fail "$1: expected '$2', got '$3'"; fi
}
mkrepo() { # dir file=content ...
  local d=$1; shift; rm -rf "$d"; mkdir -p "$d"
  for kv in "$@"; do local f=${kv%%=*}; mkdir -p "$d/$(dirname "$f")"; printf '%b' "${kv#*=}" > "$d/$f"; done
  git -C "$d" init -q . && git -C "$d" add -A && git -C "$d" -c user.email=t@example.com -c user.name=t commit -qm init
}
# repo A: languages outside the paging extension list + a hit whose text says "defined in"
mkrepo "$W/ra" 'a.rb=e = 1\n' 'b.cs=e = 1\n' 'c.py=e = 1\n' 'd.py=x = 1 # defined in cfg\n'
A() { aix --repo "$W/ra" --db "$W/db/ra.db" "$@" 2>/dev/null </dev/null; }
A update >/dev/null
expect "1 pipe wc -l keeps .rb/.cs rows and 'defined in' hits" 4 "$(A 'grep "= 1" | wc -l' | tail -1)"
expect "1 pipe 'grep -l | count' = files" 4 "$(A 'grep -l "= 1" | count' | tail -1)"
expect "1 --page total equals the grep header" "rows 1-4 of 4" "$(A grep '= 1' --page 1 --per-page 10 | grep -o 'rows [0-9]*-[0-9]* of [0-9]*')"

# repo B: a path with a space
mkrepo "$W/rb" 'docs/my notes.md=A TODO here\n' 'src/x.py=# TODO two\n' 'src/y.py=print(1)\n'
B() { aix --repo "$W/rb" --db "$W/db/rb.db" "$@" 2>/dev/null </dev/null; }
B update >/dev/null
P() { aix --repo "$W/rb" --db "$W/db/rb.db" put "$@" >/dev/null 2>&1; }  # reads stdin (B closes it)
expect "6 count by file sees a path with a space (in-call)" "2 in 2 groups" "$(B 'grep TODO | count by file' | head -1 | grep -o '[0-9]* in [0-9]* groups')"
expect "6 aix --bare rows round-trip through count by file -" "2 in 2 groups" "$(B grep TODO --bare | aix --repo "$W/rb" --db "$W/db/rb.db" count by file - 2>/dev/null | head -1 | grep -o '[0-9]* in [0-9]* groups')"

# exit status in the one-argument / pipe form (direct = 1)
B grep ZZ_NONE_1 >/dev/null; d=$?; B 'grep ZZ_NONE_1' >/dev/null; o=$?; B pipe 'symbol zz_none' >/dev/null; p=$?
expect "3 exit: direct grep none" 1 "$d"; expect "3 exit: aix 'grep none'" 1 "$o"; expect "3 exit: aix pipe 'symbol none'" 1 "$p"

# shell operators inside the quotes
B 'grep TODO || true' --bare >/dev/null; r=$?; n=$(B 'grep TODO || true' --bare | wc -l)
if [ $r -eq 2 ] || [ "$n" -le 2 ]; then pass "7 'grep X || true' refused or not widened (exit $r, $n rows)"; else fail "7 'grep TODO || true' matches every line ($n rows of 3, exit $r)"; fi
B 'grep TODO |count' >/dev/null; r=$?; [ $r -ne 0 ] && pass "7 '|count' without space is refused or piped (exit $r)" || { out=$(B 'grep TODO |count' | head -1); [[ "$out" =~ ^[0-9]+$ ]] && pass "7 '|count' piped" || fail "7 'grep TODO |count' silently greps the regex 'TODO |count' (exit 0)"; }

# continuation commands aix prints must run
foot=$(B 'grep TODO | head -n 2' --head 1 | grep -o 'next `[^`]*`' | sed 's/^next `//;s/`$//')
if [ -z "$foot" ]; then fail "4 no continuation footer for a cut pipe"; else
  eval "aix --repo '$W/rb' --db '$W/db/rb.db' ${foot#aix }" >/dev/null 2>&1 </dev/null; expect "4 pipe continuation '$foot' runs" 0 $?; fi
foot=$(A 'grep "= 1" | count by file' --head 1 | grep -o 'next `[^`]*`' | sed 's/^next `//;s/`$//')
r=$(eval "aix --repo '$W/ra' --db '$W/db/ra.db' ${foot#aix }" 2>/dev/null </dev/null | grep -o '[0-9]* in [0-9]* groups')
expect "4 count continuation '$foot' still counts the pipe" "4 in 4 groups" "$r"

# sql with global output options
B sql "select path from files" --bare >/dev/null; expect "5 sql --bare exit" 0 $?
B sql "select path from files" --head 1 >/dev/null; expect "5 sql --head 1 exit" 0 $?

# data sets
seq 1 20000 | sed 's/^/line /' | P big - >/dev/null
seq 2 2 20000 | sed 's/^/line /' | P half - >/dev/null
expect "2 'grep . @big | count' (64 KB set-grep cap must not undercount silently)" 20000 "$(B 'grep . @big | count' | tail -1)"
expect "2 set difference 'grep -v -x -F -f @half @big | count'" 10000 "$(B 'grep -v -x -F -f @half @big | count' | tail -1)"
printf 'id,name,role\n1,"multi\nline",student\n2,x,teacher\n' > "$W/m.csv"
B put mcsv "$W/m.csv" >/dev/null
expect "9 sql over a CSV with a quoted newline: one row per record" 2 "$(B sql 'SELECT count(*) FROM @mcsv' | sed -n 3p)"
printf 'a\nb\n' | P keepme - >/dev/null
B sets rm keepme --dry-run >/dev/null
expect "10 'sets rm X --dry-run' must not delete (unknown flag)" 1 "$(B sets | grep -c '^@keepme ')"
printf 'k=1\n' | P kvs - --kv >/dev/null
B filter --where 'nosuch=1' @kvs >/dev/null; r=$?
out=$(B filter --where 'nosuch=1' @kvs 2>&1); [[ "$out" =~ nosuch ]] && pass "11 unknown --where field is named" || fail "11 filter --where on an unknown field answers a silent '0 records' (exit $r)"

# BRE alternation in filter (grep translates it)
expect "12 filter --grep 'a\\|b' matches like aix grep" 2 "$(printf 'a\nb\nc\n' | aix --repo "$W/rb" --db "$W/db/rb.db" filter --grep 'a\|b' - 2>/dev/null | grep -c '^[ab]$')"

# exact duplicate range in a sequence
expect "13 identical range in a sequence shown once" 1 "$(B 'code src/x.py:1-1 ; code src/x.py:1-1' | grep -c '^1 # TODO two')"

# 8 MB stdin cut: the partial last row must not become a row
python3 - "$W/cut.txt" <<'EOF'
import sys
cap=8*1024*1024; row="src/x.py:13:compute\n"; fill="src/x.py:1:x\n"
pre=cap-len("src/x.py:1"); n=pre//len(fill); rem=pre-n*len(fill)
open(sys.argv[1],'w').write(fill*n+"#"*(rem-1)+"\n"+row+row)
EOF
expect "14 partial last row after the 8 MB cut is dropped" 0 "$(aix --repo "$W/rb" --db "$W/db/rb.db" count by line - < "$W/cut.txt" 2>/dev/null | grep -c '^ *[0-9]*  src/x.py:1$')"

echo "SUMMARY ok=$ok bug=$bad (workdir $W)"
[ $bad -eq 0 ]
