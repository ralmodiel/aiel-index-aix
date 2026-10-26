#!/usr/bin/env bash
# usage: bash tests/regress/correctness.sh [WORKDIR]  -- aix grep/read correctness vs GNU grep/git on a throwaway generic repo (prints OK/BUG lines, exit 1 on any BUG)
set -u
W=${1:-$(mktemp -d)}; R=$W/repo; DB=$W/repo.db
export HOME=$W/home AIX_LOCK_DIR=$W/lock; mkdir -p "$HOME" "$AIX_LOCK_DIR"
rm -rf "$R" "$DB"*; mkdir -p "$R/src" "$R/app/models" "$R/docs"; cd "$R" || exit 2
git init -q . && git config user.email t@example.com && git config user.name T
G=/usr/bin/grep
printf 'alpha one\nbeta two\nalpha three\n\tTabbed alpha\n' > src/plain.ts
printf 'export function other() {\n  return 2;\n}\n' > src/with.ts
printf 'export function spaced() {\n  return 1;\n}\n' > 'src/with space.ts'
printf 'export function parenFn() {\n  return 1;\n}\n' > 'src/p(1).ts'
printf 'class ApiKey\n  def owner\n  end\nend\n' > app/models/api_key.rb
printf '  {m: mGET, r: "/users/2/settings/password", h: hStub15, k: []string{"id"}},\n' > src/table.go
printf '  {m: mPOST, pw: pStub27, k: 1},\n' > src/creds.go
printf 'Measurement modes are identified by their configuration,\n' > docs/bench.md
printf '\xef\xbb\xbfusing System;\nusing System.Text;\n' > src/Bom.cs
python3 -c "open('src/many.ts','w').write(''.join('export const value_%05d = \"padding padding padding\";\n' % i for i in range(3000)))"
python3 -c "open('src/big.ts','w').write(''.join('export const big_%06d = 1; // filler filler filler\n' % i for i in range(40000)))"
printf 'class C {\n  a() {\n    return 1;\n  }\n}\n' > src/cls.ts
git add -A && git commit -qm init
A=(aix --repo "$R" --db "$DB")
"${A[@]}" update >/dev/null 2>&1; A+=(--no-refresh)
bad=0; ok(){ echo "OK   $1"; }; bug(){ echo "BUG  $1"; bad=$((bad+1)); }
chk(){ if [ "$2" = "$3" ]; then ok "$1"; else bug "$1 (expected $3, got $2)"; fi; }

# 1. grep must match the file text, not the redacted text (false negatives)
# (no oracle: a match that lies only inside a redacted span is not a hit, whatever the redactor masked)
chk "grep -c on a token the redactor masks is no hit (no oracle)" "$("${A[@]}" grep -c pStub27 --bare | cut -d: -f2)" ""
chk "a route path naming password does not mask the line's other tokens" "$("${A[@]}" grep -c hStub15 --bare | cut -d: -f2)" "$($G -c hStub15 src/table.go)"
chk "a line with a masked token and a visible match is found" "$("${A[@]}" grep -c 'mGET' --bare | cut -d: -f2)" "$($G -c mGET src/table.go)"
# 2. ... and must not match the redaction labels (false positives)
chk "grep password does not match a redaction label" "$("${A[@]}" grep -c password docs/bench.md --bare | cut -d: -f2)" "$($G -c password docs/bench.md)"
# 3. --bare --head N returns N rows (no silent 60 KB cap, footer must not repeat the same command)
n=$("${A[@]}" grep value_ src/many.ts --bare --head 3000 | $G -vc '^…'); chk "--bare --head 3000 returns 3000 rows" "$n" 3000
# 4. a flag before -- must not change the result
chk "grep -n -- alpha FILE" "$("${A[@]}" --bare grep -n -- alpha src/plain.ts 2>/dev/null | md5sum)" "$($G -Hn -- alpha src/plain.ts | md5sum)"
chk "grep -c -- alpha FILE" "$("${A[@]}" --bare grep -c -- alpha src/plain.ts 2>/dev/null)" "src/plain.ts:$($G -c -- alpha src/plain.ts)"
# 5. --bare / --head must not re-quote path arguments
for c in history outline; do
  "${A[@]}" --bare $c 'src/p(1).ts' >/dev/null 2>&1; chk "--bare $c 'src/p(1).ts' exits 0" $? 0
  "${A[@]}" $c 'src/p(1).ts' --head 5 >/dev/null 2>&1; chk "$c 'src/p(1).ts' --head 5 exits 0" $? 0
done
"${A[@]}" code 'src/with space.ts:1-3' --bare >/dev/null 2>&1; chk "code 'src/with space.ts:1-3' --bare exits 0" $? 0
# 6. outline of a path with a space must outline that file
chk "outline 'src/with space.ts' names that file" "$("${A[@]}" outline 'src/with space.ts' | head -1 | $G -c 'with space')" 1
# 7. source files named *api_key* are code, not secrets
chk "files lists app/models/api_key.rb" "$("${A[@]}" files app/models/api_key.rb --bare 2>/dev/null)" app/models/api_key.rb
# 8. a time-budget-cut grep must say so in --bare (stdout or stderr) and in --jsonl summary
o=$(AIX_GREP_BUDGET_MS=0 "${A[@]}" grep -c export --bare 2>&1); chk "partial --bare grep is marked" "$(echo "$o" | $G -ci 'partial')" 1
# 9. too-big files skipped by -l/-c must be named (stdout or stderr)
o=$("${A[@]}" grep -l 'export const' --bare 2>&1); chk "-l names the skipped too-big src/big.ts" "$(echo "$o" | $G -c 'big.ts')" 1
# 10. a missing path among several must not be glued into the regex
chk "grep alpha FILE nosuch.ts keeps FILE's hits" "$("${A[@]}" grep -c alpha src/plain.ts nosuch.ts --bare 2>/dev/null | cut -d: -f2)" 3
# 11. code FILE:A-A is one line
chk "code src/cls.ts:4-4 prints 1 line" "$("${A[@]}" code src/cls.ts:4-4 --bare | $G -c '^src/cls.ts:')" 1
# 12. pipe/--bare rows keep indentation like the CLI
chk "quoted grep keeps the leading tab" "$("${A[@]}" --bare 'grep -n Tabbed src/plain.ts' | $G -cP ':\tTabbed')" 1
# 13. -t for every indexed language
"${A[@]}" grep -c x -t go --bare >/dev/null 2>&1; [ $? -le 1 ] && ok "-t go accepted" || bug "-t go rejected"
# 14. a UTF-8 BOM does not hide line 1 from ^ anchors (rg strips it)
chk "grep -c '^using' on a BOM file" "$("${A[@]}" grep -c '^using' src/Bom.cs --bare | cut -d: -f2)" 2
echo "SUMMARY $bad BUG"; [ $bad -eq 0 ]
