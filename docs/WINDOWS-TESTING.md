# Windows support: test plan

aix is developed and tested on Linux. This plan checks whether it builds, indexes, answers and integrates with
Claude Code on Windows, and records what breaks. Work through the steps in order. Every step has a PASS condition.
Record each result in `docs/WINDOWS-RESULTS.md` (template at the end).

## 0. Setup

- Windows 11 (record the build: `winver`), PowerShell 7 (`pwsh`), Git for Windows (record whether `core.autocrlf` is
  on: `git config --get core.autocrlf`).
- Rust via rustup, MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`, Visual Studio Build Tools with
  the C++ workload). Record `rustc -V`.
- Claude Code for Windows, signed in.
- Clone: `git clone <aix remote URL> aix` (a path without spaces first; step 7 repeats
  with spaces and non-ASCII).
- Test repos: one small repo (~300 files, e.g. this repo itself) and one medium repo (~5k files, any public
  Java/TS/Python project). Clone them with Git for Windows defaults.

Keep output small: build and test quietly and save output to files, then read only the failures.

## 1. Build

```powershell
cargo build -q --release --locked *> build.log; $LASTEXITCODE
Select-String -Path build.log -Pattern '^error' -Context 0,6 | Select-Object -First 20
```

PASS: exit code 0. Expected trouble spots (Unix-only code, check each compiles on Windows or is cfg-gated):

| Area | File | Unix-only call |
|---|---|---|
| file locks | `aix-core/src/logs.rs` (~1490, ~1536) | `libc::flock` |
| priority | `aix-core/src/par.rs` (~39), `logs.rs` (~882, ~1540), `index.rs` (spawn_refresh) | `setpriority`, `ioprio_set`, `nice` |
| time | `aix-core/src/logs.rs` (~43-60) | `localtime_r` |
| process | `aix-core/src/logs.rs` (~2113, ~2187) | `kill(pid, 0)`, `setsid` |
| open flags | `aix-core/src/logs.rs` (~533), `sets.rs` (~1246) | `O_NONBLOCK`, `O_NOFOLLOW`, `O_CLOEXEC` |
| ownership | `aix-core/src/privacy.rs` (~616), `index.rs` (~326), `logs.rs` (~373) | `geteuid`, `uid()` |
| lock dir | `aix-core/src/logs.rs` (~1474) | default `/tmp/aix-locks-<uid>` |

`libc` is a Unix-only dependency in both `aix-core/Cargo.toml` and `aix-cli/Cargo.toml`, so any ungated `libc::`
use fails to compile. If the build fails, list every error location in the results file and stop here.
A fix belongs in a portable wrapper module (one place per concern: lock, priority, local time, process alive,
private file create), not scattered cfgs.

## 2. Test suite

```powershell
cargo test -q --release --locked --no-fail-fast *> test.log
Select-String -Path test.log -Pattern 'test result|FAILED|panicked' | Select-Object -First 40
```

PASS: every `test result: ok`. Record each failing test name. Tests marked `#[cfg(unix)]` are skipped by design.
Group failures by cause: paths (`\` vs `/`), line endings (CRLF), file locking, permissions, shell scripts.

## 3. Index and query (CLI)

In the small test repo:

```powershell
$aix = "<clone>\target\release\aix.exe"
& $aix --repo . stats
& $aix --repo . grep "fn main" --bare
& $aix --repo . outline <some source file>
& $aix --repo . code <some source file>:1-40
& $aix --repo . callers <a function name>
& $aix --repo . brief <a source file>
```

PASS for each:
- the first `stats` builds the index (or stops at the `.gitignore` check, which is expected; accept it with the
  printed command), and later calls answer in under 1 s;
- paths print with `/` and match `git ls-files`;
- `code` lines match the file byte for byte apart from line endings: no stray `\r` at line ends;
- `.aix\` gets created with the index; check who can read it (`icacls .aix`).

Then edit a file (add a function) and re-run `grep` for it without any manual refresh. PASS: the new function is
found on the next query.

Run the medium repo too and record the full index time and peak memory (Task Manager or
`Get-Process aix | Select PeakWorkingSet64` from a second shell while it runs).

## 4. Line endings

With `core.autocrlf=true`, check out the small repo, then:
- `grep` hits and `code F:A-B` line numbers match the editor's line numbers;
- no `\r` in `--bare` rows (`& $aix --repo . grep x --bare | Select-String "`r"` finds nothing);
- editing a file only in its line endings does not report every line as changed.

## 5. Concurrency and locks

- Two shells run `& $aix --repo . stats` at the same moment on a fresh index. PASS: one builds, the other waits or
  says the index is busy; neither corrupts it (a third `stats` afterwards is fine).
- Kill `aix.exe` during a full build (Task Manager). PASS: the next query recovers without a manual delete.
- Background refresh: change more than 300 files (e.g. `git checkout` an old commit), query once. PASS: the answer
  comes back quickly with a note, and an `aix update` process finishes on its own.

## 6. Claude Code integration

The shipped integration (`scripts/install.sh`, `scripts/aix-init.sh`, `aix-refresh.sh`, `aix-watch.sh`, the
PreToolUse hook script) is bash. Record for each whether it works under Git Bash, under PowerShell, or not at all:

- `aix-init` in the test repo: settings file written? Paths in it Windows-correct?
- The PreToolUse hook fires for `Read`, `Grep`, `Glob` and the `PowerShell` tool (the hook lexer has PowerShell and
  `cmd /c` dialects: check that `Get-Content file`, `Select-String`, `type file`, `findstr` are recognised and
  answered from the index). Ask Claude Code to "show lines 1-40 of <file>" and "find where <function> is called";
  PASS: the hook steers to `aix code` / `aix callers` and the session shows it, hook latency under 100 ms.
- `aix mcp`: register it (`claude mcp add aix -- <path>\aix.exe mcp --repo <repo>`), restart, `/mcp` lists it,
  a tool call answers. Record the time to connect.
- The skill (`SKILL.md`) is picked up and its commands run as written in PowerShell (quoting of `'a ; b'` batches
  and `@set` arguments: `@` is the splat operator in PowerShell, so check `aix grep x @t`).

## 7. Paths

Repeat step 3 briefly in a repo cloned to:
- a path with spaces (`C:\Users\<you>\My Projects\repo`);
- a path with non-ASCII characters (`C:\work\código`);
- a long path (> 260 characters; enable long paths in Git: `git config core.longpaths true`);
- a mapped or UNC network drive, if one is available.

And a repo containing file names that differ only in case, plus a symlinked folder (Git for Windows creates
symlinks only with developer mode on).

## 8. Results template (`docs/WINDOWS-RESULTS.md`)

```markdown
# Windows results — <date>, Windows <build>, rustc <version>, autocrlf <value>

| Step | Result | Notes (error, file:line, numbers) |
|---|---|---|
| 1 build | PASS/FAIL | |
| 2 tests | N passed, M failed | failing tests: |
| 3 index+query small | | index time, query times |
| 3 medium repo | | index time, peak memory |
| 4 line endings | | |
| 5 concurrency/locks | | |
| 6 hook / skill / mcp / scripts | | per item: works / Git Bash only / broken |
| 7 paths | | per case |

## Blockers (ranked: blocks use > wrong answers > slow > cosmetic)
1. ...

## Fixes made in this session (commit shas)
```

Commit fixes on a branch named `windows-<date>` with one commit per concern, plus the results file. Do not change
Linux behaviour; run the Linux suite before merging.
