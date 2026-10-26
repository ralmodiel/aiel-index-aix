#!/usr/bin/env python3
"""Mine the regexes a repo's scripts and Claude's searches use, normalise and rank them; draft the seed patterns.

Usage: scripts/mine-regex.py --repo REPO --transcripts DIR [--wrapper scripts/grep.sh]
                             [--top 40] [--tsv OUT.tsv] [--seeds aix-core/src/seed_patterns.tsv]

Sources (pattern text only; nothing else is kept):
  static    every regex in the repo's scripts: tracked *.sh/*.py/*.mjs/*.js outside app source (scripts/, scripts/regress/,
            e2e/, infrastructure/, docs/...), plus .claude/skills/** - grep/egrep/rg patterns (BRE converted to ERE,
            -F escaped), sed/awk /address/ patterns, Python re.compile/search/match/findall/finditer/sub/split, JS regex
            literals and new RegExp('...').
  runs      how often each of those scripts ran: script paths found in Bash tool calls of the transcripts (the command
            line is matched in memory and dropped; only per-path counts survive).
  observed  regexes Claude searched with directly: the Grep tool's pattern, grep -r / rg patterns in Bash calls, and the
            pattern argument of the repo's grep wrapper script, if --wrapper names one. These are what aix's PreToolUse hook counts.
Normalisation: flags/quotes stripped, BRE -> ERE, POSIX classes and [0-9] -> \\d, {1,} -> +, leading/trailing .* dropped,
JS \\/ -> /; equivalent spellings collapse to one key. Score = sum over scripts (occurrences x max(1, runs)) + observed.
Every printed regex is redacted (credential shapes, emails, long opaque strings).
Each top candidate is then checked against the repo's tracked text files:
"lines/files" = matching lines in tracked source, "rust" = no look-around/backrefs/possessive, so aix's linear-time engine runs it.
"""
import argparse, ast, collections, glob, json, os, re, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True, help="git repo whose scripts are mined")
ap.add_argument("--transcripts", required=True, help="directory of agent transcripts (*.jsonl)")
ap.add_argument("--wrapper", default="", help="repo-relative path of a grep wrapper script whose pattern argument counts as observed")
ap.add_argument("--top", type=int, default=40)
ap.add_argument("--check", type=int, default=150, help="how many top candidates to check against the repo with rg")
ap.add_argument("--tsv", default="", help="write the ranked list (rank, score, static, runs, observed, lines, files, regex)")
ap.add_argument("--seeds", default="", help="seed TSV to cross-check: which seeds come from which mined rank")
a = ap.parse_args()
REPO = os.path.abspath(a.repo)

# ---------- redaction (mirrors aix_extract::text::redact for the shapes that matter in a regex) ----------
KNOWN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{16,}|\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_\w{20,}"
                   r"|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[\w-]{35}|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]*"
                   r"|(?i:bearer\s+)[\w.~+/-]{16,}=*|://[^/\s:@]+:[^/\s@]+@")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
OPAQUE = re.compile(r"(?<![\w/.-])[A-Za-z0-9+/_-]{32,}={0,2}(?![\w/.-])")
KV = re.compile(r"(?i)((?:password|passwd|pw|secret|token|api[_-]?key)\s*[:=]\s*)[^\s)|'\"]+")
def redact(s):
    s = KNOWN.sub("[redacted]", s)
    s = EMAIL.sub("<email>", s)
    s = OPAQUE.sub(lambda m: m.group(0) if re.fullmatch(r"[a-z_/-]+", m.group(0)) else "[redacted]", s)
    return KV.sub(r"\1***", s)

# ---------- normalisation ----------
def bre_to_ere(p):
    """grep/sed basic regex -> extended: \\| \\( \\) \\{ \\} \\+ \\? become operators; bare ( ) { } | + ? are literals."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            n = p[i + 1]
            out.append(n if n in "|(){}+?" else "\\" + n)
            i += 2
            continue
        if c == "[":  # bracket expressions are the same in both
            j = i + 1
            if j < len(p) and p[j] == "^": j += 1
            if j < len(p) and p[j] == "]": j += 1
            while j < len(p) and p[j] != "]":
                if p.startswith("[:", j) and p.find(":]", j) > 0:
                    j = p.find(":]", j) + 2
                else:
                    j += 1
            out.append(p[i:j + 1]); i = j + 1
            continue
        out.append("\\" + c if c in "|(){}+?" else c)
        i += 1
    return "".join(out)

CANON = [(r"\[\[:digit:\]\]|\[0-9\]", r"\\d"), (r"\[\[:space:\]\]", r"\\s"), (r"\[\[:alnum:\]_\]|\[A-Za-z0-9_\]|\[a-zA-Z0-9_\]", r"\\w"),
         (r"\{1,\}", "+"), (r"\{0,1\}", "?"), (r"\{0,\}", "*"), (r"\\/", "/"), (r"\\'", "'"), (r'\\"', '"')]
def norm(p, dialect="ere"):
    p = p.strip()
    if dialect == "bre": p = bre_to_ere(p)
    elif dialect == "fixed": p = re.escape(p).replace("\\ ", " ")
    p = re.sub(r"^\(\?[imsx]+\)", "", p)
    for a_, b_ in CANON: p = re.sub(a_, b_, p)
    p = re.sub(r"^\.\*", "", p); p = re.sub(r"(?<!\\)\.\*$", "", p)
    return p

def usable(p):
    if len(p) < 3 or len(p) > 300 or "$" in p and re.search(r"\$\{?\w", p): return False  # shell variable = dynamic
    if re.fullmatch(r"[\s.^$*+?\\]*", p): return False
    try: re.compile(p)
    except re.error: return False
    return True

# ---------- static extraction ----------
# flags: only -A/-B/-C/-m/-g/-t/-f and --include/--exclude/--glob/--type/--max-count take a separate argument
SHELL_GREP = re.compile(r"(?:^|[\s;|&(`$])(e?grep|rg)((?:\s+(?:-[ABCmgtf]|--(?:include|exclude|glob|type|max-count))\s+(?:'[^']*'|\"[^\"]*\"|\S+)|\s+-[-\w=,.*/{}]+)*)\s+(?:-e\s+)?('([^']*)'|\"((?:[^\"\\]|\\.)*)\"|([^\s'\"|;&)<>]+))")
SED_ADDR = re.compile(r"\bsed\s+((?:-[nEri]+\s+)*)['\"]\s*\\?/((?:[^/\\]|\\.)+)/")
AWK_ADDR = re.compile(r"\bawk\s+(?:-F\S+\s+)?'\s*/((?:[^/\\]|\\.)+)/")
PY_RE = re.compile(r"\bre\.(compile|search|match|fullmatch|findall|finditer|sub|subn|split)\(\s*((?:[rRbB]{1,2})?(?:'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"))")
JS_NEWRE = re.compile(r"new RegExp\(\s*(['\"`])((?:(?!\1)[^\\]|\\.)*)\1")

def grep_dialect(prog, flags):
    f = flags.replace("--", " --")
    if prog == "rg": return "fixed" if re.search(r"(^|\s)-\w*F|--fixed-strings", f) else "ere"
    if prog == "egrep" or re.search(r"(^|\s)-\w*[EP]|--extended-regexp|--perl-regexp", f): return "ere"
    if re.search(r"(^|\s)-\w*F|--fixed-strings", f): return "fixed"
    return "bre"

def shell_regexes(text):
    for m in SHELL_GREP.finditer(text):
        prog, flags = m.group(1), m.group(2) or ""
        pat = m.group(4) if m.group(4) is not None else m.group(5) if m.group(5) is not None else m.group(6)
        if pat is None or pat.startswith("-") or (m.group(6) and re.fullmatch(r"[\w./-]+", pat) and "/" in pat):
            continue  # a path, not a pattern
        if m.group(5) is not None: pat = re.sub(r"\\([\"\\$`])", r"\1", pat)
        yield norm(pat, grep_dialect(prog, flags))
    for m in SED_ADDR.finditer(text):
        yield norm(m.group(2), "ere" if re.search(r"-\w*[Er]", m.group(1)) else "bre")
    for m in AWK_ADDR.finditer(text):
        yield norm(m.group(1))

def py_regexes(text):
    for m in PY_RE.finditer(text):
        try: v = ast.literal_eval(m.group(2))
        except Exception: continue
        if isinstance(v, bytes): v = v.decode("utf-8", "replace")
        v = re.sub(r"^\(\?[aiLmsux]+\)", "", v)
        yield norm(v)

def js_regex_literals(text):
    """Regex literals found by a small tokenizer: skips strings, template text and comments; a / after an operator,
    open bracket, comma or keyword starts a regex."""
    i, n, prev = 0, len(text), "("
    while i < n:
        c = text[i]
        if c in " \t\r\n": i += 1; continue
        if text.startswith("//", i): i = text.find("\n", i); i = n if i < 0 else i; continue
        if text.startswith("/*", i): i = text.find("*/", i + 2); i = n if i < 0 else i + 2; continue
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            i = j + 1; prev = "a"; continue
        if c == "/" and (prev in "(,=:[!&|?{};+-*%<>~^" or prev == "kw"):
            j, cls = i + 1, False
            while j < n and text[j] != "\n":
                if text[j] == "\\": j += 2; continue
                if text[j] == "[": cls = True
                elif text[j] == "]": cls = False
                elif text[j] == "/" and not cls: break
                j += 1
            if j < n and text[j] == "/":
                body = text[i + 1:j]
                k = j + 1
                while k < n and text[k].isalpha(): k += 1
                yield norm(body)
                i = k; prev = "a"; continue
        if c.isalnum() or c in "_$":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_$"): j += 1
            prev = "kw" if text[i:j] in ("return", "typeof", "case", "in", "of", "and", "or", "not") else "a"
            i = j; continue
        prev = c if c not in ")]" else "a"
        i += 1
    for m in JS_NEWRE.finditer(text):
        try: v = m.group(2).encode().decode("unicode_escape") if m.group(1) != "`" else m.group(2)
        except Exception: v = m.group(2)
        yield norm(v)

def tracked():
    out = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True).stdout.split("\n")
    keep = []
    for f in out:
        if not f or f.startswith(("frontend/src/", "frontend/dev-dist/", "frontend/public/", "backend/src/")) or "node_modules/" in f: continue
        if f.startswith(".claude/skills/") or f.endswith((".sh", ".py", ".mjs", ".js", ".bash")):
            keep.append(f)
    return keep

static = collections.defaultdict(collections.Counter)  # regex -> {script: occurrences}
for f in tracked():
    try: t = open(os.path.join(REPO, f), errors="replace").read()
    except OSError: continue
    found = []
    if f.endswith((".sh", ".bash", ".md")) or f.startswith(".claude/skills/"): found += shell_regexes(t)
    elif f.endswith(".py"): found += list(py_regexes(t)) + list(shell_regexes(t))
    elif f.endswith((".mjs", ".js")): found += list(js_regex_literals(t)) + list(shell_regexes(t))
    for p in found:
        if usable(p): static[p][f] += 1

# ---------- transcripts: script runs + observed searches ----------
SCRIPT = re.compile(r"(?:^|[\s;&|(`'\"])(?:\./|bash |python3? |node |sh )?(?:[\w./~-]*/)?((?:scripts|e2e|infrastructure/scripts|docs/audit)/[\w./-]+\.(?:sh|py|mjs|js))")
WRAPPER = (re.compile(r"(?:^|[\s;&|(])(?:bash\s+)?(?:\./)?" + re.escape(a.wrapper) + r"\s+(?:-\w+\s+)*('([^']*)'|\"([^\"]*)\"|(\S+))")
           if a.wrapper else None)
RECURSIVE = re.compile(r"\bgrep\b[^|;]*\s-\w*[rR]|\brg\b")
runs, observed, seen, ntools = collections.Counter(), collections.Counter(), set(), collections.Counter()
for path in glob.glob(os.path.join(a.transcripts, "**", "*.jsonl"), recursive=True):
    try: fh = open(path, errors="replace")
    except OSError: continue
    for line in fh:
        if '"tool_use"' not in line: continue
        try: ev = json.loads(line)
        except Exception: continue
        content = (ev.get("message") or {}).get("content")
        if not isinstance(content, list): continue
        for b in content:
            if not isinstance(b, dict) or b.get("type") != "tool_use" or b.get("id") in seen: continue
            seen.add(b.get("id"))
            nm, inp = b.get("name"), b.get("input") or {}
            if nm == "Grep":
                p = norm(inp.get("pattern", ""), "ere")
                if usable(p): observed[p] += 1; ntools["Grep tool"] += 1
            elif nm == "Bash":
                cmd = inp.get("command", "")
                for s in {m.group(1) for m in SCRIPT.finditer(cmd)}:
                    runs[s] += 1
                for m in (WRAPPER.finditer(cmd) if WRAPPER else ()):
                    p = norm(next(g for g in m.groups()[1:] if g is not None), "ere")
                    if usable(p): observed[p] += 1; ntools["grep wrapper"] += 1
                for seg in re.split(r"\|\||&&|;|\|", cmd):
                    if RECURSIVE.search(seg):
                        for p in shell_regexes(seg):
                            if usable(p): observed[p] += 1; ntools["grep -r/rg"] += 1
                del cmd

# ---------- rank ----------
rows = []
for p in set(static) | set(observed):
    st = static.get(p, {})
    s_score = sum(k * max(1, runs.get(f, 0)) for f, k in st.items())
    rows.append({"re": p, "score": s_score + observed.get(p, 0), "occ": sum(st.values()), "scripts": len(st),
                 "runs": sum(runs.get(f, 0) for f in st), "obs": observed.get(p, 0)})
rows.sort(key=lambda r: (-r["score"], r["re"]))

NOT_RUST = re.compile(r"\(\?<?[=!]|\\[1-9]|[*+?}]\+|\(\?>")  # look-around, backrefs, possessive, atomic groups
SRC = []  # (is app source, lines)
APP = re.compile(r"\.(java|kt|tsx?|jsx?|py|go|rs|sql|vue|svelte)$")
OTHER = re.compile(r"^(scripts|e2e|docs|bench|tests?|infrastructure|\.claude)/|(^|/)(test|tests|__tests__)/|\.(test|spec)\.")
for f in subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True).stdout.split("\n"):
    fp = os.path.join(REPO, f)
    if not f or "node_modules/" in f or not os.path.isfile(fp) or os.path.getsize(fp) > 1_000_000: continue
    try: SRC.append((bool(APP.search(f)) and not OTHER.search(f), open(fp, encoding="utf-8").read().split("\n")))
    except (OSError, UnicodeDecodeError): continue
def repo_check(p):
    """(matching lines, files, share of lines in app source, runs on a linear-time engine) over the repo's tracked
    text files, line by line like aix. Regexes aix cannot run (look-around, backrefs) are not checked."""
    if NOT_RUST.search(p): return None, None, None, False
    try: rx = re.compile(p)
    except re.error: return None, None, None, False
    lines = files = app = 0
    for is_app, ls in SRC:
        k = sum(1 for l in ls if rx.search(l))
        if k: lines += k; files += 1; app += k if is_app else 0
    return lines, files, (app / lines if lines else 0.0), True
def check_all(ps, budget=300):
    """Checks run in parallel workers under one deadline (Python's engine backtracks; a slow regex is reported as
    unchecked instead of being waited on)."""
    import multiprocessing as mp, time
    out, t0 = {}, time.time()
    pool = mp.get_context("fork").Pool(min(8, os.cpu_count() or 2))
    futs = {p: pool.apply_async(repo_check, (p,)) for p in ps}
    for p, fu in futs.items():
        try: out[p] = fu.get(timeout=max(0.1, budget - (time.time() - t0)))
        except mp.TimeoutError: out[p] = (None, None, None, not NOT_RUST.search(p))
    pool.terminate()
    return out
res = check_all([r["re"] for r in rows[:a.check]])
for r in rows[:a.check]:
    r["lines"], r["files"], r["app"], r["rust"] = res[r["re"]]

def fmt(i, r):
    ln = "-" if r.get("lines") is None else r["lines"]
    fl = "-" if r.get("files") is None else r["files"]
    ap_ = "-" if r.get("app") is None else f"{r['app']:.0%}"
    rust = "" if r.get("rust", True) else "  [not rust-regex]"
    return f"{i:4d} {r['score']:6d} {r['occ']:4d} {r['runs']:5d} {r['obs']:4d} {ln:>6} {fl:>5} {ap_:>4}  {redact(r['re'])[:100]}{rust}"
HEAD = f"{'rank':>4} {'score':>6} {'occ':>4} {'runs':>5} {'obs':>4} {'lines':>6} {'files':>5} {'app':>4}  regex (redacted)"
tot = sum(r["score"] for r in rows)
print(f"repo {REPO}: {sum(len(v) for v in static.values())} (regex, script) pairs from {len({f for v in static.values() for f in v})} scripts; "
      f"{len(seen)} tool calls read, {sum(runs.values())} script runs over {len(runs)} scripts; observed searches: "
      + ", ".join(f"{k} {v}" for k, v in ntools.most_common()))
print(f"{len(rows)} distinct normalised regexes, total score {tot}")
print(f"== top {a.top} by score (occ = occurrences in scripts, runs = runs of those scripts, obs = direct searches, "
      f"lines/files = matches in the repo, app = share of those lines in app source)")
print(HEAD)
rank = {r["re"]: i for i, r in enumerate(rows, 1)}
for i, r in enumerate(rows[:a.top], 1):
    print(fmt(i, r))
# seed candidates: regexes that search the code (most matching lines are app source), runnable by aix, selective
# (1..5000 matching lines), not trivially short; N is where the cumulative score flattens
cand = [r for r in rows[:a.check] if r.get("rust") and r.get("lines") and 1 <= r["lines"] <= 5000
        and len(r["re"]) >= 4 and (r.get("app") or 0) >= 0.5]
ctot = sum(r["score"] for r in cand) or 1
acc, cut = 0, {}
for i, r in enumerate(cand, 1):
    acc += r["score"]
    for q in (0.5, 0.7, 0.8, 0.9):
        if acc / ctot >= q and q not in cut: cut[q] = i
print(f"== code-search candidates (rust-compatible, 1..5000 lines, >=50% in app source; top {a.check} checked): {len(cand)}; "
      + ", ".join(f"{int(q*100)}% of their score in the top {k}" for q, k in sorted(cut.items())))
print(HEAD)
for r in cand[:a.top]:
    print(fmt(rank[r["re"]], r))
if a.tsv:
    with open(a.tsv, "w") as w:
        w.write("rank\tscore\tocc\truns\tobserved\tlines\tfiles\tapp_share\tregex\n")
        for i, r in enumerate(rows[:a.check], 1):
            app = "" if r.get("app") is None else f"{r['app']:.2f}"
            w.write(f"{i}\t{r['score']}\t{r['occ']}\t{r['runs']}\t{r['obs']}\t{r.get('lines','')}\t{r.get('files','')}\t{app}\t{redact(r['re'])}\n")
if a.seeds and os.path.exists(a.seeds):
    print("== seed cross-check (seed -> mined rank of the regex it was built from)")
    for ln in open(a.seeds):
        if ln.startswith("#") or not ln.strip(): continue
        parts = ln.rstrip("\n").split("\t")
        if len(parts) >= 3:
            src = parts[2]
            print(f"  {parts[0]:<22} rank {rank.get(src, '-'):>4}  score {next((r['score'] for r in rows if r['re'] == src), 0)}")
