#!/usr/bin/env python3
"""Measure the code graph per language on cloned repos (see bench/codegraph for the Java / TS / Python / Go set).

  score.py --sk <aix> --repos <dir> --dbs <dir> [--build] [--json out.json] [--repo name,...]

Per repo: full-build time, parse notes (extract-skipped: panic / too deep), members found against an independent
definition count (a regex over the source: a definition line is found when a function / method member of that name
covers it), and callers precision / recall on 5 functions defined exactly once (ground truth = grep of call sites,
comment lines dropped, +-2 lines). The 5 are picked by hash of the name, so the choice does not depend on the tool."""
import argparse, hashlib, json, os, re, sqlite3, subprocess, sys, time

REPOS = {
    # repo: (lang, extensions, definition regex (group 1 = name), call-site regex template, path filter)
    "ripgrep": ("rust", (".rs",), r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+(\w+)", None),
    "axum": ("rust", (".rs",), r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)", None),
    "wild-workouts-go-ddd-example": ("go", (".go",), r"^func\s+(?:\([^)]*\)\s*)?(\w+)", None),
    "ktor-samples": ("kotlin", (".kt",), r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?, ]+\.)?(\w+)\s*\(", r"/(build|node_modules)/"),
    "eShopOnWeb": ("csharp", (".cs",), r"^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\s+(?:static\s+|async\s+|virtual\s+|override\s+|abstract\s+|sealed\s+|new\s+|partial\s+|extern\s+)*[\w<>\[\],.?]+(?:<[^>]*>)?\s+(\w+)\s*(?:<[^>]*>)?\s*\(", None),
    "koel": ("php", (".php",), r"\bfunction\s+&?(\w+)\s*\(", r"/(vendor|node_modules)/"),
    "rubygems.org": ("ruby", (".rb",), r"^\s*def\s+(?:self\.)?(\w+[?!]?)", None),
    "vapor": ("swift", (".swift",), r"\bfunc\s+(\w+)", None),
    "play-samples": ("scala", (".scala",), r"\bdef\s+(\w+)", None),
    "jq": ("c", (".c",), None, None),
    "fmt": ("cpp", (".cc", ".cpp", ".h"), None, None),
    "samples": ("dart", (".dart",), r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:static\s+|external\s+|abstract\s+|factory\s+)*(?:[\w<>?,.\[\] ]+\s+)(?!if\b|for\b|while\b|switch\b|catch\b|return\b|else\b)(\w+)\s*(?:<[^>]*>)?\s*\([^;{=]*\)\s*(?:async\s*\*?\s*|sync\*\s*)?(?:\{|=>)", r"/(build|\.dart_tool)/|_generated\.dart$|\.g\.dart$"),
    "plenary.nvim": ("lua", (".lua",), r"\bfunction\s+(?:[\w.]+[.:])?(\w+)\s*\(", None),
}
COMMENT = ("//", "#", "*", "/*", "--", "///")
KW = {"if", "for", "while", "switch", "return", "else", "sizeof", "defined", "catch", "do", "case", "new", "delete", "throw", "using", "typedef"}
CLIKE = re.compile(r"^\s*(?:(?:static|inline|extern|virtual|constexpr|const|explicit|friend|template\s*<[^>]*>|unsigned|signed|struct|enum|union)\s+)*[A-Za-z_][\w:<>,*&\s]*?[\s*&]+~?(\w+)\s*\(")

def clike_defs(lines):
    """Function definitions of C / C++: a line with `type name(` whose parameter list is followed by `{` before any `;`."""
    out = []
    for i, l in enumerate(lines):
        if l.lstrip().startswith(COMMENT + ("typedef", "return", "else")) or ";" in l.split("(")[0]: continue
        m = CLIKE.match(l)
        if not m or m.group(1) in KW: continue
        txt = " ".join(lines[i:i + 8])
        depth, j = 0, txt.find("(")
        while j < len(txt):
            depth += (txt[j] == "(") - (txt[j] == ")")
            if depth == 0: break
            j += 1
        rest = txt[j + 1:].lstrip()
        rest = re.sub(r"^(?:const|noexcept|override|final|->\s*[\w:<>*&\s]+|\s)+", "", rest).lstrip()
        if rest.startswith("{") or rest.startswith(":"): out.append((m.group(1), i + 1))
    return out

ap = argparse.ArgumentParser()
ap.add_argument("--sk", required=True); ap.add_argument("--repos", required=True); ap.add_argument("--dbs", required=True)
ap.add_argument("--build", action="store_true"); ap.add_argument("--json", default=""); ap.add_argument("--repo", default="")
a = ap.parse_args()
env = dict(os.environ, AIX_EMBED_URL="", HOME="/nonexistent")
os.makedirs(a.dbs, exist_ok=True)
want = set(a.repo.split(",")) - {""}

def sources(repo, exts, skip):
    out = subprocess.run(["git", "-C", os.path.join(a.repos, repo), "ls-files"], capture_output=True, text=True).stdout.split("\n")
    return [f for f in out if f.endswith(exts) and not (skip and re.search(skip, "/" + f))]

results = {}
for repo, (lang, exts, defre, skip) in REPOS.items():
    if want and repo not in want: continue
    if not os.path.isdir(os.path.join(a.repos, repo)): continue
    db = os.path.join(a.dbs, repo + ".db")
    ms = None
    if a.build or not os.path.exists(db):
        if os.path.exists(db): os.remove(db)
        t = time.perf_counter()
        subprocess.run([a.sk, "--repo", os.path.join(a.repos, repo), "--db", db, "update", "--full", "--embed-deadline", "0"], capture_output=True, env=env)
        ms = round((time.perf_counter() - t) * 1000)
    con = sqlite3.connect(db)
    files = sources(repo, exts, skip)
    fs = set(files)
    mem = con.execute("SELECT file,line,end_line,name,kind FROM members").fetchall()
    mem = [m for m in mem if m[0] in fs]
    funcs = [m for m in mem if m[4] in ("function", "method", "ctor")]
    notes = dict(con.execute("SELECT text,count(*) FROM notes WHERE kind='extract-skipped' GROUP BY text").fetchall())
    row = dict(lang=lang, files=len(files), build_ms=ms, members=len(mem), funcs=len(funcs), skipped=notes)
    byfile = {}
    for m in funcs: byfile.setdefault(m[0], []).append(m)
    defs = {}  # name -> [(file,line)]
    if defre or lang in ("c", "cpp"):
        rx = re.compile(defre) if defre else None
        for f in files:
            try: lines = open(os.path.join(a.repos, repo, f), errors="replace").read().split("\n")
            except OSError: continue
            if rx is None:
                for n, i in clike_defs(lines): defs.setdefault(n, []).append((f, i))
                continue
            for i, l in enumerate(lines, 1):
                if l.lstrip().startswith(COMMENT): continue
                m = rx.search(l)
                if m: defs.setdefault(m.group(1), []).append((f, i))
        total = sum(len(v) for v in defs.values())
        hit = sum(1 for n, v in defs.items() for (f, i) in v if any(m[3] == n and m[1] - 3 <= i <= m[2] for m in byfile.get(f, [])))
        row.update(gt_defs=total, defs_found=hit, defs_recall=round(hit / total, 3) if total else None)
        # five callers questions
        cands = []
        for n, v in defs.items():
            if len(v) != 1 or len(n) < 6 or n in ("constructor", "initialize", "__init__", "toString"): continue
            rx_call = re.compile(r"(?<![\w$])" + re.escape(n) + r"\s*[(<]")
            sites = []
            for f in files:
                try: lines = open(os.path.join(a.repos, repo, f), errors="replace").read().split("\n")
                except OSError: continue
                for i, l in enumerate(lines, 1):
                    if rx_call.search(l) and not l.lstrip().startswith(COMMENT) and (f, i) != v[0]:
                        sites.append((f, i))
            if 3 <= len(sites) <= 30: cands.append((hashlib.sha1(n.encode()).hexdigest(), n, sites))
            if len(cands) >= 60: break
        cands.sort()
        qs = []
        for _, n, sites in cands[:5]:
            p = subprocess.run([a.sk, "--repo", os.path.join(a.repos, repo), "--db", db, "--no-refresh", "--limit", "300", "--json", "callers", n], capture_output=True, text=True, env=env)
            try: j = json.loads(p.stdout)
            except Exception: qs.append(dict(name=n, err=1)); continue
            cs = list(dict.fromkeys((c["file"], c["line"]) for x in j["answers"] if x["kind"] == "caller" for c in x.get("cites", [])))
            ok = lambda c, g: c[0] == g[0] and abs(c[1] - g[1]) <= 2
            pr = sum(1 for c in cs if any(ok(c, g) for g in sites)) / len(cs) if cs else (1.0 if not sites else 0.0)
            rc = sum(1 for g in sites if any(ok(c, g) for c in cs)) / len(sites)
            qs.append(dict(name=n, gt=len(sites), n=len(cs), p=round(pr, 2), r=round(rc, 2)))
        row["callers"] = qs
        if qs:
            row["callers_p"] = round(sum(q.get("p", 0) for q in qs) / len(qs), 3); row["callers_r"] = round(sum(q.get("r", 0) for q in qs) / len(qs), 3)
    results[repo] = row
    print(repo, json.dumps(row), flush=True)
if a.json: json.dump(results, open(a.json, "w"), indent=1)
