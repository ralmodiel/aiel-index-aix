#!/usr/bin/env python3
"""Index-scale benchmark on a pinned public corpus (the repos codebase-memory-mcp publishes numbers for).
Usage: bench/corpus/bench.py [--dir /data/aixbench] [--only linux,django] [--clone-only] [--no-incr] [--reps 5]
Clones each repo of corpus.tsv at its pinned commit (shallow, under --dir, never in this repo), then per repo:
full index (wall time, peak RSS via /usr/bin/time, index size), node/edge counts, an incremental refresh after
--edits edited files, and the median latency of grep / symbol / callers / callees / trace / impact.
Prints one TSV row per repo (and writes --dir/results.tsv). One heavy index at a time, under `nice -n 10`."""
import argparse, os, pathlib, statistics, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("--dir", default="/data/aixbench")
ap.add_argument("--bin", default=str(HERE.parent.parent / "target/release/aix"))
ap.add_argument("--only", default="")
ap.add_argument("--clone-only", action="store_true")
ap.add_argument("--no-incr", action="store_true")
ap.add_argument("--edits", type=int, default=50)
ap.add_argument("--reps", type=int, default=5)
a = ap.parse_args()
D = pathlib.Path(a.dir); (D / "dbs").mkdir(parents=True, exist_ok=True)
EXT = {"c": (".c", ".h"), "cpp": (".cpp", ".hpp", ".h"), "python": (".py",), "go": (".go",), "typescript": (".ts", ".tsx"),
       "rust": (".rs",), "java": (".java",), "php": (".php",)}

def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def clone(name, url, commit):
    r = D / name
    if (r / ".git").exists() and sh("git", "-C", str(r), "rev-parse", "HEAD").stdout.strip() == commit:
        return r
    r.mkdir(exist_ok=True)
    for c in (["init", "-q"], ["remote", "add", "origin", url], ["fetch", "-q", "--depth", "1", "origin", commit],
              ["checkout", "-q", "FETCH_HEAD"]):
        p = sh("nice", "-n", "10", "git", "-C", str(r), *c)
        if p.returncode and c[0] != "remote":
            sys.exit(f"clone {name}: git {' '.join(c)} failed: {p.stderr.strip()[:200]}")
    return r

def timed(cmd):
    """(wall s, peak RSS MB, rc) of one run, via /usr/bin/time."""
    p = sh("/usr/bin/time", "-f", "%e %M", "nice", "-n", "10", *cmd)
    wall, rss = p.stderr.strip().splitlines()[-1].split()[-2:]
    return float(wall), int(rss) / 1024, p.returncode

def median_ms(cmd):
    ts = []
    for _ in range(a.reps):
        t = time.perf_counter(); sh(*cmd); ts.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(ts))

def db_mb(db):
    return sum(f.stat().st_size for f in db.parent.glob(db.name + "*") if f.is_file()) / 1e6

rows = [l.rstrip("\n").split("\t") for l in open(HERE / "corpus.tsv") if l.strip() and not l.startswith("#")]
only = set(filter(None, a.only.split(",")))
out = []
hdr = "repo\tfiles\tnodes\tedges\tfull_s\tpeak_rss_mb\tindex_mb\tincr_s\tincr_rss_mb\tgrep_ms\tsymbol_ms\tcallers_ms\tcallees_ms\ttrace_ms\timpact_ms"
print(hdr, flush=True)
for name, url, _ref, commit, lang, sym, rx in rows:
    if only and name not in only:
        continue
    repo = clone(name, url, commit)
    if a.clone_only:
        print(f"{name}\tcloned {commit[:12]}", flush=True); continue
    db = D / "dbs" / f"{name}.db"
    for f in db.parent.glob(db.name + "*"):
        f.unlink()
    A = [a.bin, "--repo", str(repo), "--db", str(db)]
    full, rss, rc = timed(A + ["update", "--full", "--quiet"])
    if rc:
        print(f"{name}\tFULL INDEX FAILED rc={rc}", flush=True); continue
    q = lambda s: sh(*A, "--no-refresh", "sql", s, "--bare").stdout.strip().splitlines()[-1]
    files, nodes, edges = q("select count(*) from files"), q("select count(*) from members"), q("select count(*) from call_edges")
    incr = irss = ""
    if not a.no_incr:
        srcs = [l for l in sh("git", "-C", str(repo), "ls-files").stdout.splitlines() if l.endswith(EXT.get(lang, ()))]
        step = max(1, len(srcs) // a.edits)
        for f in srcs[::step][: a.edits]:
            with open(repo / f, "a") as fh:
                fh.write("\n")
        try:
            i, ir, _ = timed(A + ["update", "--quiet"]); incr, irss = f"{i:.1f}", f"{ir:.0f}"
        finally:
            sh("git", "-C", str(repo), "checkout", "-q", "--", ".")
            sh(*A, "update", "--quiet")
    lat = [median_ms(A + ["--no-refresh", *c]) for c in
           (["grep", rx], ["symbol", sym], ["callers", sym], ["callees", sym], ["trace", sym], ["impact"])]
    row = [name, files, nodes, edges, f"{full:.1f}", f"{rss:.0f}", f"{db_mb(db):.0f}", incr, irss, *map(str, lat)]
    out.append("\t".join(row)); print(out[-1], flush=True)
if out:
    (D / "results.tsv").write_text(hdr + "\n" + "\n".join(out) + "\n")
