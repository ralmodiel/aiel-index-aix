#!/usr/bin/env python3
"""Regenerate the "You were about to run" block of the aix skill from mined shell use.

usage: python3 scripts/skill-recipes.py <non-use.tsv> <repo> [SKILL.md]
  <non-use.tsv>: rows `round<TAB>agent<TAB>tool<TAB>command...` (shell reads an agent ran instead of aix), in call order
  <repo>: an indexed checkout; each top command shape is passed through `aix hook pretool` there, so the aix line in
  the table is the hook's own translation, not a hand-written one.
Prints the block; with SKILL.md, replaces the text between the `<!-- recipes -->` markers in place.
Verdict line: `recipes: N shapes, M chains, K without an aix line`."""
import csv, json, re, subprocess, sys, collections

tsv, repo = sys.argv[1], sys.argv[2]
rows = list(csv.reader(open(tsv), delimiter='\t'))[1:]

def shape(cmd):
    """`sed -n 10,40p a/B.java` -> `sed -n A,Bp F.java`: the habit, without the specifics."""
    w = cmd.split('|')[0].split()
    if not w or w[0] not in ('sed', 'grep', 'rg', 'cat', 'head', 'tail', 'wc'): return ''
    ext = next((m.group(0) for x in reversed(w) for m in [re.search(r'\.[a-z]{1,4}$', x.strip('\'"'))] if m), '')
    flags = [x for x in w[1:] if re.fullmatch(r'-[a-zA-Z]+', x) and x not in ('-n',)][:2]
    rng = ' A,Bp' if w[0] == 'sed' and re.search(r'\d+,\d+p', cmd) else ' RE' if w[0] in ('grep', 'rg') else ''
    if w[0] == 'sed' and not rng: return ''
    return ' '.join([w[0], *(['-n'] if '-n' in w else []), *flags]) + rng + ' F' + ext

def generic(sug):
    """the hook's line with the specifics replaced: `aix code F:A-B`, `aix grep -A 10 'RE' F`"""
    sug = re.sub(r"'[^']*'|\"[^\"]*\"", "'RE'", sug)
    sug = re.sub(r'\S+(\.\w+):[\d*-]+', r'F\1:A-B', sug)
    sug = re.sub(r'(aix (?:cat|head|tail|outline)(?: -n \d+)?) \S+(\.\w+)', r'\1 F\2', sug)
    sug = re.sub(r'(aix grep(?: -[A-Za-z]+(?: \d+)?)*) (?!\x27RE\x27)\S+ ', r"\1 'RE' ", sug)
    sug = re.sub(r' \S+(\.\w+)$', r' F\1', sug)
    sug = re.sub(r"('RE') [^\sF][^\s]*$", r"\1 DIR", sug)
    return re.sub(r' +', ' ', sug)

def suggest(cmd):
    ev = {"tool_name": "Bash", "tool_input": {"command": cmd}, "hook_event_name": "PreToolUse", "cwd": repo, "session_id": "recipes"}
    o = subprocess.run(['aix', 'hook', 'pretool'], input=json.dumps(ev), capture_output=True, text=True, cwd=repo).stdout
    m = re.search(r'Same answer next time: (aix [^\n"`]+)|run `(aix [^`\n]+)`', o.replace('\\n', '\n'))
    return (m.group(1) or m.group(2)) if m else ''

def derived(s):
    """the aix line for a shape whose examples are outside <repo> (other checkouts): the same translation the hook makes"""
    w = s.split(); f = w[-1]
    if w[0] == 'sed': return f'aix code {f}:A-B'
    if w[0] in ('grep', 'rg'): return 'aix grep ' + ' '.join(x for x in w[1:-2] if x not in ('-n', '-r', '-rn', '-nr')) + f" 'RE' {f}"
    if w[0] in ('cat', 'head', 'tail'): return f'aix {w[0]} {f}'
    if w[0] == 'wc': return f'aix files {f} --lines'
    return ''

shapes = collections.Counter(); example = {}
for r in rows:
    s = shape(r[3])
    if s:
        shapes[s] += 1; example.setdefault(s, []).append(r[3])
# chains: consecutive shell reads by the same agent in the same round (grep -> sed -n, cat -> grep, ...)
chains = collections.Counter()
for a, b in zip(rows, rows[1:]):
    if a[:2] == b[:2] and a[2] != b[2]:
        chains[f'{a[2]} -> {b[2]}'] += 1

lines = ['| You were about to run (seen) | Run instead (one bounded call) |', '|---|---|']
none = 0
for s, n in shapes.most_common(14):
    sug = next((x for x in (suggest(c) for c in example[s][:5]) if x), '') or derived(s)
    none += not sug
    sug = generic(sug)
    lines.append(f'| `{s}` ({n}) | `{sug}` |' if sug else f'| `{s}` ({n}) | (no exact aix line: see the table above) |')
RECIPE = {'grep -> sed': "`aix grep -n RE F -A 20` (match plus body in one call), or `aix 'grep -l RE | code - --around RE'`",
          'sed -> grep': "`aix 'code F:A-B ; grep RE F'` (one call, both answers)",
          'grep -> cat': "`aix grep -l RE | aix code - --function`",
          'cat -> grep': "`aix grep RE F -C 3` (no whole-file read)",
          'grep -> grep': "`aix grep RE1 --and RE2` or `aix 'grep RE1 ; grep RE2'`",
          'sed -> sed': "`aix code F:A-B F:C-D` (several ranges, one call)",
          'wc -> sed': "`aix outline F` (members with line ranges), then one `code F:A-B`",
          'Read -> grep': "`aix outline F words` then `code Class.method`"}
lines += ['', 'Frequent chains, done in one call:', '']
k = 0
for c, n in chains.most_common(12):
    key = re.sub(r'\b(rg)\b', 'grep', c)
    if key in RECIPE and k < 6:
        lines.append(f'- {key} ({n}x): {RECIPE[key]}'); k += 1
block = '\n'.join(lines)
if len(sys.argv) > 3:
    p = sys.argv[3]; t = open(p).read()
    t2 = re.sub(r'(<!-- recipes -->\n).*?(<!-- /recipes -->)', lambda m: m.group(1) + block + '\n' + m.group(2), t, flags=re.S)
    if t2 == t and '<!-- recipes -->' not in t: sys.exit('no <!-- recipes --> markers in ' + p)
    open(p, 'w').write(t2)
else:
    print(block)
print(f'recipes: {min(14, len(shapes))} shapes, {k} chains, {none} without an aix line', file=sys.stderr)
