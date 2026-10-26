# Windows results — 2026-10-25, Windows 11 Pro 26H2 (build 26300.9711), rustc 1.99.1 (x86_64-pc-windows-msvc), autocrlf true

Machine: Visual Studio 2022 Community 17.14 with the "Desktop development with C++" workload (MSVC 14.44.35207,
Windows SDK 10.0.26100), Git for Windows 2.45.1 (`core.autocrlf=true`, `core.longpaths` unset), Windows PowerShell
5.1.26100 (the shell Claude Code's PowerShell tool runs on this machine) and PowerShell 7.6.8, WSL2 Ubuntu 20.04.
Tested checkout: `F:\work\aiel-index` (no spaces; all 305 tracked files checked out CRLF, no
`.gitattributes`). Branch: `windows-2026-10-25`.

| Step | Result | Notes (error, file:line, numbers) |
|---|---|---|
| 1 build | PASS (after fixes) | First run FAIL: 72 s; every dependency builds with MSVC (tree-sitter grammars, bundled SQLite, ring), `aix-core` fails with 90 errors, all Unix-only std/libc outside `cfg(unix)` (list below). With `aix-core/src/sys.rs`: clean release build in 101 s, no warnings, `aix.exe` 53.4 MB, `--help` in 14 ms. Linux side checked from Windows with `cargo check --target x86_64-unknown-linux-gnu --all-targets` (C via `zig cc`): every one of the 7 fix commits type-checks on Linux on its own. |
| 2 tests | PASS: 571 passed, 0 failed, 1 ignored (after fixes, merged with master `c1ffa8f`). After QA round 1: 581 passed, 1 failed, 1 ignored in 727 s; the failure (`aixsh_k` data_sets_pipes_sql_and_strict_flags, a debug-build time budget) fails the same at HEAD `29a2d01` | First run: 488 passed, 64 failed (grouped by cause below; test targets first failed to compile: 11 files used `std::os::unix` for fixtures). Run with Git for Windows' `bin` and `usr\bin` first on PATH, as Claude Code's Bash tool has them (otherwise `bash` is WSL's and the GNU oracles are missing): 389 s. `masks_perf` (p95 budget 50 us) is load-sensitive: 25-40 us alone, 57-61 us beside the other test binaries. |
| 3 index+query small | PASS (QA round 1, after fixes) | This repo as a CRLF clone: 5.1 s fresh build, 3.3 s seeded clone, queries 45-190 ms; every printed path `/` and matching `git ls-files`; `code F:A-B` equals the file minus CRs over ~600 lines. Issues found and fixed: QA round 1 below |
| 3 medium repo | PASS (after fixes) | fastapi (3,233 tracked, 2,983 indexed, 7,932 commits): warm full build 4.8-5.5 s, builder peak 357 MB, 22 queries at 100-370 ms median. A fresh clone's first query blocked 18-36 s on Defender (fixed: cli-8) |
| 4 line endings | PASS (after fixes) | No `\r` in any output; CRLF-to-LF with autocrlf=true changes nothing. Fixed: `$` in CRLF files for grep `--bare/-l/-q/-o` (enc-1), `scope` after a line-ending-only edit with CRLF committed (cli-9), UTF-8 BOM on line 1 (cli-5) |
| 5 concurrency/locks | PASS (after fixes) | Concurrent first builds, kills at 12 points, locked index, 3000-line burst with 78 queries: no loss, no "database is locked". Fixed: a kill mid-checkpoint (conc-1), background jobs holding the caller's pipe (conc-2), `logs rm --all` under a watcher (conc-4) |
| 6 hook / skill / mcp / scripts | PASS (after fixes) | 22 Bash exact denies byte-identical to Git Bash; MCP initialize 26-43 ms; 17 Sonnet sessions all answered right. Fixed: the card's "not on PATH" (sonnet-1), Read nudge paths, PowerShell escalation quoting, PowerShell forms and other checkouts. The bash scripts (aix-init, aix-refresh, aix-watch) still need Git Bash (ledger 26) |
| 7 paths | PASS (after fixes) | Spaces, non-ASCII, 278-character file paths, shell metacharacters, reserved names, every `--repo` spelling. Fixed: subdirectories, case, subst/junction/8.3/UNC in the hook, 238+ character roots (where long paths are enabled) |

### Step 1 first run: error locations

By kind: 30 `libc` not found, 11 `Metadata::mtime`, 9 `ino`, 8 `dev`, 6 `OpenOptions::mode`, 6 `Permissions::from_mode`,
5 `std::os::unix`, 2 `mtime_nsec`, 2 `as_raw_fd`, 2 `std::os::fd`, 2 `uid`, 2 `custom_flags`, 2 `DirBuilder::mode`,
1 `pre_exec`, 1 `Metadata::mode`.

- `aix-core/src/logs.rs` (65): 11, 43-45, 58-60, 288, 373, 524, 533, 687, 710, 882, 1040, 1184, 1200, 1201, 1490-1493,
  1509, 1517, 1531-1540, 1563, 1786, 1826, 1947, 1968, 1975, 2113, 2170, 2179, 2186, 2187, 2299
- `aix-core/src/privacy.rs` (9): 13, 73, 502, 521, 574, 597, 616, 622
- `aix-core/src/sets.rs` (7): 10, 79, 81, 96, 1246
- `aix-core/src/logq.rs` (6): 879, 1199, 1945, 1955
- `aix-core/src/setq.rs` (2): 2836, 2837

Already portable (cfg-gated with a non-unix branch): `index.rs` (tighten, `.aix` create, spawn_refresh),
`par.rs` (be_nice), `hooks.rs`, `semantic.rs`, `ignorecheck.rs`, `aix-extract/src/masks.rs`. The plan's table missed
`logq.rs`, `setq.rs` and every `MetadataExt` use (mtime/dev/ino/uid/mode).

### Step 2: failing tests by cause (first run with the build fixed)

| Cause | Tests | What happens |
|---|---|---|
| paths: the repo root is `\\?\C:\...` | `aixsh_d` (10: builtin_tools_table, table_of_real_command_shapes "120 of 156 cases differ", event_log_and_stats, ...), `cli` (3 pretool), `clone_seed` (2), `excl` (1), `sk11` hook_suggests_callers, `aixsh_k3` hook_silent_after_cd_and_on_powershell_redirects, `incr` an_absolute_path_inside_the_repo, `fix4a` hook_ignores_agent_text | `find_repo` canonicalizes, so on Windows the root is a verbatim `\\?\C:\...` path. The hook's `strip_repo` compares its normalized `C:/x` / `/c/x` words and the event's `C:\...` cwd against that string: nothing matches, every repo file is `outside-repo` and the hook stays silent. `outline <abs path>` answers "path not found". |
| logs: allowed roots are Unix paths | `logs` (20 of 23), `fix4a` (8) | `aix logs add C:\Users\...\Temp\...\app.log` → "refused (outside the allowed roots: the repo, $HOME, /var/log, /tmp, ...)": the Windows temp dir (and `%USERPROFILE%` when `HOME` is unset) is never allowed. |
| GNU tools not on PATH | `aixsh_c` (5), `aixsh_i` (1), `logs` budgets_retention / live_files (2), `aix` bin hooks::tests::hook_script_quotes_every_value | "program not found": oracle tests compare aix with GNU `sort`/`uniq`/`cut`/`find`/`wc`/`ls`/`grep`/`gzip`/`sh`. Git for Windows ships them in `usr\bin`, not on PATH. |
| `bash` is the WSL launcher | `fix6a` exit_codes | `bash` on this PATH is `%LOCALAPPDATA%\Microsoft\WindowsApps\bash.exe` (WSL): `/bin/bash: F:workspaces-aielaiel-index-aixtargetreleaseaix.exe: command not found`. |
| CRLF checkout | `aix-extract` lang aspnet_routes, kotlin_and_rust_routes; `skill_frontmatter`; `sk13` extractor_nits | Route extraction returns no endpoints for the CRLF fixtures (C#, Kotlin, Rust); front matter not found in CRLF `SKILL.md`; a test helper fails on git's "LF will be replaced by CRLF" warning. |
| path lists split on `:` | `aixfeat` script_dirs_are_listed (verify) | `AIX_SCRIPT_DIRS=C:\...\tools` finds nothing; Windows path lists need `;` (`std::env::split_paths`). |
| Windows limits | `fix5p` cli_caps_long_query_arguments_in_a_blink | os error 206: the test's argument exceeds Windows' 32K command line. |
| test-only separator | `scale` hints_page_and_bare_footer | the test builds `frontend\src\App.tsx` and looks for `frontend/src/App.tsx`. |

Gated as Unix-only (skipped here by design): `watch_storage` (whole file), the aix-init/aix-refresh/lifecycle bash tests in
`aixsh_g`, `aixsh_k3`, `sk11`, `fix5p` scripts_create_private_files, the symlinked worktree in `clone_seed`, and inside
otherwise portable tests: permission-bit asserts, symlink/FIFO/`/dev`/`/etc` cases. Developer mode is off here, so
creating a symlink needs admin; those cases could run on Windows with developer mode on.

## Blockers (ranked: blocks use > wrong answers > slow > cosmetic)
1. ~~Hook: every repo path is "outside the repo" (`\\?\` root), so the PreToolUse hook never answers or steers.~~
   Fixed (`fc5d86a`): the 156-case command table passes on Windows.
2. ~~`aix logs add` / `attach` refuse every Windows log location except inside the repo.~~ Fixed (`9ffed2d`).
3. ~~Route extraction misses C#/Kotlin/Rust endpoints in CRLF files~~ (the same `Orders.cs`: 0 endpoints as CRLF,
   4 as LF; not Windows-only, .NET repos often commit CRLF). Fixed (`c046bfe`): extractors read LF text.
4. ~~`AIX_SCRIPT_DIRS` (and any `:`-split path list) breaks on drive letters.~~ Fixed (`9ffed2d`).
5. ~~Without `HOME` (PowerShell, cmd, MCP server) global masks, private markers and global config are not
   loaded.~~ Fixed (`f7b325c`).
6. ~~Text piped from Windows PowerShell starts with a BOM: the first row of `filter`/`count`/`put -` carries
   U+FEFF and a hook event piped from PowerShell fails to parse.~~ Fixed (`5fdd7fa`).

## Fixes made in this session (commit shas)

| Commit | Concern |
|---|---|
| `27f0d45` | `aix-core/src/sys.rs` (new): owner-only files and ownership; aix-cli drops its unused `libc` |
| `5125293` | local time (`localtime_r` / CRT `_localtime64_s` + `_mkgmtime64`) |
| `5f6a4b2` | priority (`nice`, `be_nice` moved from `par.rs`) |
| `3c273c1` | processes (`pid_alive`, `detach`, `detach_low`; `CREATE_NO_WINDOW` on Windows) |
| `05c2b81` | file lock: std `File::try_lock` instead of `libc::flock` |
| `0a69cbd` | file identity and mtime (`GetFileInformationByHandle` on Windows); aix-core builds on Windows |
| `ba92f4a` | tests: Unix-only fixtures `cfg(unix)`, so every test target builds on Windows |
| `fc5d86a` | paths: `sys::canonicalize` without `\\?\`, `sys::repo_rel_args`, the hook's one spelling (`/c/x`) for roots, cwds, `cd` and words, Grep/Glob answers with native separators |
| `c59aac9` | hook deny answers: a `sed` range of a CRLF file prints LF lines, like Git for Windows' sed |
| `f7b325c` | `home()`: `$HOME`, else `%USERPROFILE%`, for every lookup |
| `9ffed2d` | logs/attach/prompt attachments: `%TEMP%` allowed, `split_paths` for path lists, AppData credential stores and PowerShell history denied, `C:\x` paths in prompts |
| `5fdd7fa` | stdin: the UTF-8 BOM Windows PowerShell adds is dropped |
| `c046bfe` | extractors read a CRLF file as LF (REVISION 27) |
| `91351f8` | tests, the Windows environment side: GNU oracles through bash, '/' in bash command lines, a python that runs, CRLF oracle output, reserved names, the 32K command line |

## QA round 1 (2026-10-26): six agents on the frozen binary (git 3745dda-dirty, revision 28)

Six agents tested one area each against a copy of the binary, from PowerShell 5.1, pwsh 7.6 and Git Bash:
Sonnet sessions through Claude Code with exec-form hooks (17 headless sessions, $0.71), the CLI on small and medium
repos (this repo CRLF, fastapi with 3,233 files), path spellings, the hooks/MCP/skill, encoding and pipes, and
concurrency/logs. Each issue is listed once with the agents' IDs; repro scripts and logs are in the session's
scratchpad (`qa\<area>\`).

### Fixed

| Issue (class) | Seen as | Fix |
|---|---|---|
| The session card says aix is "not on PATH" and offers an absolute path that Claude Code's permissions reject (blocks use) | sonnet-1, hook-8, paths-8 | `hooks.rs` `aix_cmd`: looks for `aix.exe`; a path with a space is quoted, with the PowerShell `&` form beside it. Emulating the fix in 3 Sonnet sessions took permission rejections from 4 to 0 and turns from 11 to 8 |
| A first build killed during its first checkpoint (PowerShell's `Select-Object -First` kills the piped process) leaves an index every command refuses; following the hint deletes it (blocks use) | paths-9, conc-1 | `index.rs` `wal_holds_new_aix_db`: a main file that is not consistent alone (`quick_check`) is judged by a copy replayed with its `-wal`, as an empty one already was; the probe's corruption report is not taken as damage of the index. New test `a_first_build_killed_mid_checkpoint_reopens` (fails on the old check) |
| Background `aix update` and the paste worker keep the caller's stdout/stderr pipe open, so a pipe reader (`$(aix ...)`, the PowerShell tool, every hook) waits for the whole refresh: `aix card` 2.0 s instead of 0.9 s (slow, every hook) | conc-2 | `sys.rs` `background`/`detach`: the std handles stop being inheritable before the spawn (CreateProcess passes every inheritable handle; `Stdio::inherit` duplicates them for children that want them) |
| Hook silent when the project is opened through a subst drive, a junction or an 8.3 name, and in a UNC checkout (blocks use) | paths-2, paths-3 | `hooksh.rs` `Cx::new`: the cwd's own spelling of the root is one more root (checked to resolve to the repo); `lexical` keeps `//host/share`; `repo_rel` (Read paths) resolves such a path |
| A repo root of 238+ characters cannot be indexed: SQLite cannot create `index.db-journal` past 260 (blocks use) | paths-4, paths-11 | `aix-cli/windows.manifest` embedded by `build.rs` (MSVC): long-path aware, so it opens where Windows allows long paths (LongPathsEnabled=1); otherwise the error now names the cause and `--db` |
| `logs rm --all` with a watcher running zeroes `logs.db` but cannot delete it; every later `logs`/`stats` fails (blocks use) | conc-4 | `logq.rs` `cmd_rm`: when `sys::in_use` (another handle without delete sharing) the rows are purged instead, and the message says so |
| An absolute path inside the repo is refused by cat/head/tail/sed/diff/anchor, grep's path operand and files/ls (wrong answer) | cli-1 | `lib.rs`: argv words rewritten like the joined argument (not for the logs/paste/attach family and data sets, which name files on disk: the first try broke `attach` and the paste worker's `--input`); `readcmd.rs` strips any spelling of the root (`sys::strip_root`) |
| Through a subst drive, junction, 8.3 name or `\\?\`, an absolute file argument is "path not found" (wrong answer) | paths-6, cli minor | `sys::repo_rel_args`: one absolute word that does not match the root's text is canonicalized and stripped |
| From a subdirectory two or more levels deep, `.`, `ls` and `find` ignore the current directory (wrong answer) | cli-2, paths-1 | `main.rs`: the cwd below the root is stored with `/` |
| Git Bash rewrites a word starting with `/` (`aix brief /items/`, `sed -n '/re/p'`, `--in=/x`) into `C:/Program Files/Git/...` (wrong answer) | cli-4, hook-3 | `sys::args`: with MSYSTEM set, a word (or the value after `=`) that starts with MSYS's root is given back with its `/`; escalation runs with `MSYS_NO_PATHCONV=1`. A `F:/re/,/re/` word, which MSYS reads as a path list, is not undone: SKILL.md says to prefix `MSYS_NO_PATHCONV=1` |
| A UTF-8 BOM (Visual Studio, PowerShell 5.1) stays on line 1: `^namespace`/`^using` never matches it, `code`/`cat` print U+FEFF, the Grep-tool deny says "No matches" (wrong answer) | cli-5, hook-4, enc-2 | `query.rs` `decode_text` drops it (indexing, grep and reads all decode there; REVISION 29); `hookans.rs` Grep answers drop it as rg does |
| `$` never matches in a CRLF file in `grep --bare`, `-l`, `-q`, `-o`: the whole-file prefilter saw the raw `\r\n` (wrong answer) | enc-1 | `grepx.rs` `build`: CRLF mode, as the plain engine already had |
| A path typed in another case: `cat readme.md` printed a fixture's README.md, `code Aix-Core/src/Sys.rs` was refused; a file renamed on disk only in case was skipped by grep and refused by code (wrong answer) | cli-6, paths-5 | `opts.rs` `resolve_path`: on Windows a NOCASE match gives the indexed spelling (before the basename guess; misses remembered, as a stream's rows ask for the same word thousands of times); `sys::same_path` in the symlink guards of `read_indexed`, `read_for_grep` and `open_src`. A junction inside the repo is still refused by the symlink guard, as a symlink is on Unix |
| `scope` in a repo with CRLF committed (`autocrlf=false`, common in .NET) lists every member as changed after a line-ending-only edit (wrong answer) | cli-9 | `query.rs`: `git diff/show -U0 --ignore-cr-at-eol` |
| The Read nudge says "0 lines" and suggests `aix code aix-cli\src\hooks.rs:<line>`, which Bash cannot run (wrong answer) | sonnet-3, hook-1 | `hooks.rs`: the repo-relative path from `hooksh::repo_rel` |
| The prompt hook and `attach` treat tracked files as untracked (snapshot them as pastes, register "live" logs, point the model at `aix paste`) (wrong answer) | sonnet-2 | `logq.rs` `tracked`, `query.rs`, `sets.rs`: index paths with `/` (`sys::slash`); `hooks.rs` uses `sys::strip_root` |
| An escalated PowerShell call runs its PowerShell-quoted line through sh (`'repo''s'` reads `repos`: 0 rows instead of 2) and says "run it with Bash" (wrong answer) | hook-2 | `hooklog.rs`: escalation runs the line rendered with sh quoting; the deny says "run it directly" for PowerShell |
| PowerShell 5.1 drops `"` inside a native argument, so a suggested `aix grep '"pretool"'` matched 4 lines instead of 1 (wrong answer) | hook-6, enc-5, cli-10 | `hooksh.rs` `sls_to_grep`: a `"` in the pattern is written `\x22` (a `-SimpleMatch` pattern becomes an escaped regex); SKILL.md notes it |
| `@t` in PowerShell is a splat: the query silently runs on the whole repo (wrong answer) | hook-5, enc-3, cli-10 | SKILL.md and rules.md write `'@t'`; `aix put`'s "query it:" hint quotes it |
| `cmd 2>&1 \| aix put t -` in PowerShell 5.1 stores its error records (wrong answer) | hook-7, enc-4 | SKILL.md: `cmd /c "<command> 2>&1" \| aix put t -` (pwsh 7 is clean) |
| Rotated `.gz` logs are silently skipped without Git's `usr\bin` on PATH; `attach` of any `.gz` was refused as binary (its NUL check ran on the compressed bytes) (wrong answer) | conc-3 | `logs.rs` `gunzip`: flate2 in process (already in the build through ureq) |
| `attach` refuses UTF-16 (PowerShell's `Out-File`) as binary and keeps a UTF-8 BOM (wrong answer) | conc-5 | `read_attachment_with` decodes through `decode_text` and checks for NULs after that |
| The Unix log roots (`/tmp`, `/data`, `/opt`, `/workspaces` ...) are allowed on whatever drive the cwd is on (wrong answer, privacy) | conc-6 | `logs.rs` `allowed_roots`: Unix only |
| `.aix` and `index.db` inherit the drive's ACL (F:\ gives Authenticated Users modify), and privacy-check says nothing (privacy) | cli-7, conc-7 | `sys::owner_only_dir`: at creation `.aix` gets a full-control entry for the user, inherited by its files, then its inherited entries are dropped (`icacls`); privacy-check reports an `.aix` that still inherits (`(I)` in `icacls`) and `--fix` applies it |
| `--repo /c/x` typed in PowerShell is `\c\x` on the current drive (wrong answer) | cli minor | `main.rs`: `/x/...` with one letter is `X:/...` |
| The first query on a fresh clone blocks 18-36 s before the build goes to the background: `plan()` opened every file, and Defender scans each on its first open (slow) | cli-8 | `index.rs` `plan`: no open per file on Windows; the build's own read drops an unreadable file the same way |
| PowerShell lookups in another checkout (an indexed clone, an unindexed one) get no steer and no one-time index note (slow) | hook-10 | `hooks.rs` `target_repo` reads PowerShell commands (`cd`, `Set-Location`, absolute words) |
| `(Get-Content F)[0..39]`, `(Get-Content F).Count`, `Get-Content -LiteralPath F`, and `git grep`/`rg`/`grep`/`sed -n`/`head` typed in PowerShell get no steer (slow) | hook-11, sonnet-4 | `hooksh.rs` `ps()`: the indexed form is read as the `Select-Object -Skip/-First` / `Measure-Object` pipeline; `-LiteralPath` is `-Path`; POSIX tools go to the POSIX translator |
| `aix grep` printed 5 of 9 rows with no word about the rest (wrong answer) | sonnet-5 | `query.rs`: each file's cut rows are named ("N more (add --full for all n)") |
| `ls 'aix-core\src'` prints `aix-core\src/callmemo.rs` (cosmetic) | cli-3 | `files.rs`: start points echoed with `/` |
| A differently-cased cwd adds a needless `--repo` prefix to every suggestion (cosmetic) | hook-13 | `Cx::strip_repo`: the root itself compares case-insensitively |
| The unindexed-checkout note cuts both paths to the same 120 characters (cosmetic) | hook-14 | `hooks.rs` `ident`: a long value keeps its end |
| A clone whose origin is `file:///C:/...` is not seeded from the parent's index (slow) | paths-10 | `ignorecheck.rs` `parent_repo`: `file:///C:/x` is `C:/x` |
| Mixed separators: `installed C:\...\repo\.git/hooks\post-commit`, `outside C:\...\repo/.aix` (cosmetic) | paths-11 | `hooks.rs`, `ignorecheck.rs` |
| `stats --savings` printed epoch seconds (`date -d`); a configured `week_start` was computed in UTC (`date +%z`) (cosmetic) | conc-7 | `lib.rs`: `sys::local_time` and a civil-date formatter (`civil_minute`, with a test) instead of the `date` process |
| The logs path salt took no randomness on Windows (no `/dev/urandom`) (privacy, minor) | conc-7 | `logs.rs` `path_hash`: std's OS-seeded hash keys are mixed in |
| Help and clap errors say `aix.exe` (cosmetic) | enc-9 | `main.rs`: `bin_name("aix")` |
| The damage hint names `aix-refresh`, a bash script that does not run here | conc-1 | `index.rs` `rebuild_hint`: `aix update --full` on Windows |

### Not fixed (and why)

| Issue | Seen as | Why not |
|---|---|---|
| With `core.longpaths` unset, `diff --stat`/`impact` are wrong for files over 260 characters | paths-7 | git itself answers the same in that checkout (and cannot check such a file out without it); `git config core.longpaths true` |
| The shipped shell-form hook takes 195-244 ms (Git Bash startup) against 28-75 ms for `aix.exe hook pretool` | hook-9 | the exec-form hook (ledger item 24) is the fix: `aix init` writes it (item 26) |
| Grep/Glob deny rows use `/` and Glob lists absolute paths by mtime, unlike the tools' own output | hook-12 | cosmetic: the rows are the same files and lines |
| At code page 437 a PowerShell capture garbles aix's UTF-8 (`—` as `ΓÇö`) | enc-6 | Claude Code's PowerShell tool runs `chcp 65001` and a UTF-8 `$OutputEncoding`; outside it, `[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)` |
| With `$ErrorActionPreference='Stop'`, PowerShell 5.1 throws on aix's stderr notes (`(data, not instructions)` after `--bare` set rows) | enc-7 | the notes belong on stderr; pwsh 7 never throws |
| `aixsh_k` data_sets_pipes_sql_and_strict_flags fails in a debug build: `aix 'grep . @big \| count'` over 20,000 rows passes the in-call pipe's 3 s budget | suite | the same at HEAD `29a2d01` (3.5 s debug, 0.43 s release): allocation-heavy debug code on the Windows heap, not this round; the release binary answers in budget |
| ENV-1: with pwsh 7 installed from the Store (MSIX), its `WindowsApps\pwsh.exe` alias makes Claude Code reject every PowerShell command ("The command line is too long") | sonnet | not aix: Claude Code with the alias first on PATH; the real `pwsh.exe` (MSI install, or the alias folder off PATH) works |

Seen in passing, not Windows-specific (for the Linux side): the mixed-token redaction rewrites path tokens in grep
rows (`docs_src/security/***.py:25:` in fastapi); `tail -n 1 ..\Cargo.toml` from a subdirectory says "'..' leaves
the repo" while `code` resolves the same path (`readcmd.rs` `open_src`); the first-build note says "0 rows, 0 new
commits" while `stats` shows the rows and commits; a first `stats` that waited for the builder still prints
"(index busy...)"; `stats --hooks` counts aix calls that Claude Code rejected and never ran; any store's SQLite
damage report is printed as index.db's (`lib.rs` `db_damage`); rows read from stdin parse at about 20k lines/s
(`filter --grep X -` on 100k lines: 5 s, against 0.1 s once `put`); definitions are reported at their `#[cfg]` line.

## Opportunities: Windows + Claude Code integration

Seen while setting up and testing on this machine; "verify" marks what a later step still has to confirm.

1. **Claude Code's PowerShell tool is Windows PowerShell 5.1 here**, not pwsh 7: no `&&`/`||`, and `Get-Content`
   without `-Encoding UTF8` decodes UTF-8 as ANSI (seen: `—` read back as `â€”` from `logs.rs`). Code reads through
   PowerShell are lossy for non-ASCII; `aix code`/`aix cat` are not. The hook and SKILL.md should steer every
   PowerShell code read to aix.
2. **Native output through PowerShell 5.1 pipes is re-decoded with the console code page** (checked in QA round 1:
   Claude Code's PowerShell tool runs `chcp 65001` with a UTF-8 `$OutputEncoding`, so it is lossless there; a plain
   code-page-437 console garbles captures, enc-6): aix's
   non-ASCII output (em dashes in alerts and notes, box characters) may arrive garbled when Claude runs aix from the
   PowerShell tool. Options: ASCII-only output when stdout is not a UTF-8 console, or set the console output code
   page, or a documented `[Console]::OutputEncoding = [Text.Encoding]::UTF8` preamble in SKILL.md.
3. **`@set` arguments are PowerShell splats**: `aix grep x @t` passes nothing for `@t`, and the query silently runs on
   the whole repo (confirmed in QA round 1, PowerShell 5.1 and 7). Done: SKILL.md, rules.md and `aix put`'s hint write
   `'@t'`; an alternative sigil aix accepts would make the bare form safe too.
4. **PATH changes do not reach a running Claude Code session** (rustup's PATH edit was invisible to new tool shells
   until restart). Hook and MCP registrations on Windows should use the absolute path of `aix.exe`, and install docs
   should say to restart Claude Code after installing.
5. **The hook wrappers are bash** (`aix-pretool-nudge.sh` etc. spawn `dirname`, `readlink`, `command -v`, `timeout`
   before `aix`): under Git Bash each process start costs tens of ms, which threatens the 100 ms PreToolUse budget
   (measure in step 6). On Windows the hook command can be `aix.exe hook pretool` directly (aix already reads
   `CLAUDE_PROJECT_DIR`; the 3 s timeout can live in aix).
6. **`scripts/install.sh` copies `$stage/bin/aix`, but cargo installs `aix.exe`** on Windows (verify under Git Bash);
   `ln -s` in Git Bash copies unless developer mode and `MSYS=winsymlinks:nativestrict` are set. Under Git Bash
   `$here` is `/f/...`, which `src-path` stores and native `git -C` (aix's `stale_hint`) cannot open (exit 128).
   That note told a Windows user to "re-run .../scripts/install.sh" (bash), and did so after a docs-only commit.
   Fixed: on Windows it names `cargo install --locked --force --path <clone>/aix-cli` (without `--force` cargo
   refuses an `aix.exe` it did not install), and it stays quiet when nothing under
   the crates or `Cargo.*` changed since the build. Windows now has its own installer, `scripts/install.ps1` (item 26).
7. **`integrations/claude-code/mcp.json` runs `"command": "aix"`**, which depends on PATH as seen by Claude Code's
   process (item 4).
8. **Background children need `CREATE_NO_WINDOW`**: `spawn_refresh` and the paste worker start `aix.exe` from a
   hook; without the flag a console window can flash on every refresh (fixed in the build commit).
9. **`HOME` is unset under PowerShell and for an MCP server Claude Code launches directly, but set under Git Bash**:
   about 15 `HOME` lookups (global config, masks, private markers, `--global` sets, the hook lexer's `~`) then give
   different answers depending on which shell started aix. Global redaction masks
   (`~/.config/aix/masks.toml`) are not loaded at all in the PowerShell/MCP case. One `home()` with a `USERPROFILE`
   fallback fixes all of them.
10. **The watcher lock dir defaults to `/tmp/aix-locks-<uid>`**: on Windows that is `\tmp` on the current drive
    (`F:\tmp\...`), not a per-user directory.
11. **`std::fs::canonicalize` returns `\\?\C:\...` on Windows**: confirmed as blocker 1 (the hook sees every repo
    file as outside the repo). One normalisation point for the repo root and the paths compared against it.
12. **`bash` on PATH is the WSL launcher** (`%LOCALAPPDATA%\Microsoft\WindowsApps\bash.exe`, an app execution alias):
    anything that runs `bash` by name (hook wrappers, `aix-init`, tests) lands in WSL Ubuntu with Windows paths. On
    Windows, run Git Bash by absolute path (next to `git.exe`: `<git>\bin\bash.exe`) or drop the bash layer.
13. **Symlinks need admin or developer mode**: off on this machine, so `ln -s` in Git Bash copies and the symlink
    escape checks rarely matter; the tests that build symlinks are Unix-only.
14. **Windows PowerShell 5.1 turns redirected native stderr into errors**: `git push 2>&1` reported exit 255 on
    success. Claude running `aix … 2>&1` from the PowerShell tool will see a failure whenever aix prints a note on
    stderr; SKILL.md should say not to redirect aix's stderr in PowerShell.
15. **Path-list variables split on `:`** (`AIX_SCRIPT_DIRS`, likely `AIX_LOG_ROOTS`): a drive letter splits the path;
    `std::env::split_paths` uses `;` on Windows.
16. **Route extraction and CRLF**: C#/Kotlin/Rust endpoints vanish from CRLF files, and a Git for Windows checkout
    is CRLF by default.
17. **Windows PowerShell pipes add a UTF-8 BOM to a native program's stdin** (even with `$OutputEncoding` reporting
    no preamble): aix now drops it; the same BOM ended up at the start of `git commit -F -` messages made here.
18. **Git for Windows' text tools disagree on CRLF**: `sed`, `grep`, `awk`, `cut` strip the CR (text mode); `head`,
    `tail`, `cat` keep it. The hook's byte-identical deny answers now follow that per tool; Claude Code's Grep tool is
    ripgrep (native `\` paths, CR kept), which the Grep/Glob answers follow.
19. **Reserved device names** (`NUL`, `CON`, `AUX`, `PRN`, `COM1`..`LPT9`, also with an extension): a file named
    `nul.txt` cannot exist on Windows; one test fixture used it.
20. **`config.toml` with a Windows path**: `script_dirs = ["C:\Users\x"]` is a TOML escape error (`\U`); aix says so
    and ignores the file. Docs should say: single quotes (`'C:\Users\x'`) or forward slashes.
21. **Live-log writer detection reads `/proc`**: no Windows equivalent yet (the "writer exited" pause and "a writer
    holds it open, so it is live" never fire). The Restart Manager API (`RmGetList`) lists the processes holding a
    file without admin rights.
22. **`ident()` keeps only `[A-Za-z0-9_./:#@-]` of a path in hook notes**: spaces and non-ASCII are dropped on every
    platform (`My Projects` becomes `MyProjects`; on Windows the `\` were dropped too, fixed).
23. **`bash` the hook wrappers run is WSL's when Git Bash is not first on PATH** (item 12): with Git's `bin` and
    `usr\bin` first, the whole suite's shell and GNU-tool tests run as they would in Claude Code's Bash tool.
24. **How Claude Code runs hooks on Windows** (code.claude.com hooks reference): a hook `command` without `args`
    (shell form) runs in Git Bash, or PowerShell without Git Bash; a per-hook `"shell": "bash" | "powershell"`
    exists; with `args` (exec form) the program runs directly, no shell, and must be a real `.exe`. So the Windows
    registration is exec form: `{"command": "C:/Users/<you>/.cargo/bin/aix.exe", "args": ["hook", "pretool"]}`: no
    bash start-up per tool call, no wrapper script, no PATH lookup (and it works the same on Linux).
25. **The PowerShell tool is Claude Code's primary shell on Windows** (on by default for claude.ai and Console
    accounts when Git Bash is installed; Bash stays for POSIX scripts), and it uses pwsh 7 when installed, else
    Windows PowerShell 5.1. The hook's PowerShell dialect and SKILL.md's PowerShell quoting (`'@set'`, no
    `2>&1`) matter more on Windows than the Bash path.
26. **The shipped bash layer cannot run on Windows as is**: Git for Windows has no `setsid` (the session-start
    hook's watcher start fails silently) and no `flock` (`aix-refresh.sh` and `aix-watch.sh` lock with it); the
    watcher reads `/proc` and `findmnt`; `aix-init.sh` needs `python3`, which on this machine is the Microsoft Store
    stub (it prints "Python was not found" and exits 49). Moving init, refresh and watch into aix (it already has
    the index write lock and a Rust watch loop for logs) would make them work on Windows without Git Bash.
    Done (2026-10-26): `aix init`, `aix refresh`, `aix watch` and `aix hook session-start` are subcommands
    (`aix-cli/src/{init,refresh,watch}.rs`), with the scripts' options, lock files (`<key>.{refresh,embed,log,watch}.lock`,
    the same sha1 key, so a bash and a Rust run exclude each other), `refresh.log`, pidfile and `.aix/created-files`
    records; `scripts/install.ps1` builds and installs them with `aix-init`/`aix-refresh`/`aix-watch` shims (`.cmd` for
    PowerShell and cmd, sh for Git Bash). `aix init` writes exec-form hooks on every OS (`args: ["hook",
    "session-start" | "pretool" | "prompt"]`) and `PowerShell(...)` allow rules on Windows; a unit test keeps its
    allow list equal to aix-init.sh's. Differences from the scripts: the storage class is the drive type on Windows and
    the mount's filesystem type on Linux (no sysfs rotational/USB probe; the measured switch still applies); `--stop`
    finds watchers by pidfile only (aix-watch.sh also scans /proc argv for pre-pidfile watchers); with no embedder
    configured nothing counts as pending, so the idle watcher no longer runs a refresh every minute for nothing.
    Windows specifics: a detached watcher starts in %TEMP% (a process's working directory cannot be deleted or
    renamed, so one started in the repo pinned it for hours); its `aix logs watch` child is recorded in
    `<key>.watch.logs.pid` and ended by --stop (TerminateProcess runs no cleanup); --stop also recognises a watcher
    whose aix.exe install.ps1 renamed aside, and children of a watcher that outlived an upgrade run the new binary.
    For the Linux session: aix-watch.sh's `is_watcher` does not recognise a Rust watcher's argv (`aix ... watch`), so
    the bash `--stop` misses one (the Rust `--stop` recognises both); the scripts could become `exec aix init "$@"`
    wrappers once their tests pass against the subcommands.
27. **Free memory is read from `/proc/meminfo`** for the update's memory budget; Windows falls back to "4096 MB
    when unknown" (`GlobalMemoryStatusEx` gives the real value).
28. **A pasted cmd.exe line names the repo folder** (`F:\repo>aix init`): the prompt hook attached the folder, and
    its walk went into hidden folders, so aix's own `.aix\hook-events.jsonl` was indexed as a paste. Fixed: a
    folder's hidden folders are walked only with `--allow-dotfile` (test `a_named_folder_skips_its_hidden_folders`).
    Open: whether a `X:\path>` console prompt should name a folder at all.
29. **Windows gives the main thread a 1 MB stack** (Linux: 8 MB): with three more subcommands every debug-build
    `aix` overflowed it in clap's parse ("thread 'main' has overflowed its stack"). Fixed: `/STACK:8388608` at link
    time (aix-cli/build.rs, MSVC), Linux's size.
30. **Index freshness on Windows** (checked 2026-10-26, scratch repo, new build): a same-size edit, a rewrite by
    PowerShell `Set-Content` (ANSI) and `Out-File` (UTF-16), a delete, a new tracked file and a rename are all in the
    very next query's answer; right after an edit the PreToolUse hook does not answer from the index
    (`no-answer:stale`: the tool runs); a 1500-file change is refreshed in the background (the query says "other
    answers may lag", grep still reads the changed files) and was complete 2 s later; with no query at all, `aix watch`
    had a new function in the index 1.5 s after the edit, and the post-commit hook refreshes after every commit
    (`aix refresh` now). Files git does not track yet are not indexed by design (a fresh credentials file must not
    be), and are never answered from the index.

## Opportunities: scripts written in this session that aix could absorb

Every ad-hoc script used on this machine, with the aix command that already answers it or the feature it suggests.
Several exist only because PowerShell lacks `sed -n`/`cat -n`, which is exactly where aix can help on Windows.

| What the script did | Written as | aix today | Opportunity |
|---|---|---|---|
| Print line-numbered code regions from several files | PS `Get-Content` + `for` + `"{0,5}: {1}" -f` (broke twice: one-range arrays flatten, 5.1 mis-decodes UTF-8); then Git Bash `sed -n 'a,bp;c,dp' f \| cat -n` | `aix code f:A-B,C-D` (several files per call via `batch`), `aix sed -n` | Hook: recognise PowerShell range reads (`Get-Content f \| Select-Object -Skip N -First M`, `(Get-Content f)[a..b]`, `-TotalCount`, `-Tail`) and multi-range `sed -n 'a,bp;c,dp'`, answer with `aix code`. SKILL.md: on Windows, never `Get-Content` for code. |
| Find Unix-only APIs not cfg-gated (regex over `*/src/*.rs`, count per file, then lines) | Grep tool, twice | `aix grep -c`, `aix grep … \| count by file` | New: a portability audit (`aix portability --target windows`): platform-only APIs (`libc::`, `std::os::unix`, `/proc`, `/tmp`, `HOME`) whose enclosing item is not `cfg`-gated, grouped by concern with file:line. The code graph knows the enclosing item. |
| Summarise a failed build: errors by message, then the `--> file:line` after each `error[` grouped per file | PS `Select-String` + `Group-Object` + index loop | `aix filter` (bounded log view), `aix put build` + `aix count by template @build` | New: compiler-diagnostic parsing in `put`/`paste`/`filter` (rustc/cargo `error[E…]` + `-->`, MSVC `file(line): error C…`, tsc, javac): `count by field code`, `count by field file`, and a "locations per error" view. |
| Run the build with exit code, elapsed time and error count, output to a log | PS `Stopwatch` + `*> log` + `$LASTEXITCODE` | `cargo build 2>&1 \| aix put build -` | New: `aix run <name> -- <cmd…>`: aix spawns the command itself (no PowerShell pipe, so no code-page re-encoding and no `@` splat), stores the redacted output as `@name`, prints exit status, elapsed time, error/warning counts and the first diagnostics. Same behaviour in PS 5.1, pwsh, cmd and bash. |
| Environment probes: Windows build, PS version, autocrlf/longpaths, rustc, vswhere C++ tools, SDK, pwsh path, WSL, admin | PS, about 8 calls | none | New: `aix doctor` with a Windows section: shells (PS 5.1/7, Git Bash path), console code page, autocrlf and `.gitattributes`, `core.longpaths`, `HOME` vs `USERPROFILE`, whether `aix.exe` is on the PATH Claude Code's processes see, whether the registered hook command resolves. |
| Line-ending census (`git ls-files --eol`: 305 `w/crlf`, 0 `w/lf`) | PS | none | Add an EOL summary to `aix stats` (or `aix files --eol`); step 4 needs it. |
| Show definitions of several helpers by name | Git Bash `grep -n 'fn a\|fn b\|…'` then `sed -n` | `aix symbol`, `aix code <symbol>`, `aix outline` | Hook: recognise `grep -n 'fn X\|fn Y'` and answer with `aix code X Y`. |
| Who calls `pid_alive` / `euid`; every `HOME` lookup | Git Bash `grep -rn` | `aix callers pid_alive`, `aix grep '"HOME"'` | Nudge already covers `grep -rn` (verify under Git Bash in step 6). |
| Lines per source file | PS `Get-ChildItem \| Measure-Object -Line` | `aix files --lines --sort lines` | Hook: recognise `Measure-Object -Line`, `(Get-Content f).Count`, `wc -l`. |
| List the integration files and print each | Git Bash `find \| xargs ls -la; cat` | `aix ls`, `aix cat` | none |
| Highest `rust-version` among locked crates; who pulls in `windows-sys` and with which features | Git Bash awk over `Cargo.lock` + registry `Cargo.toml`; `cargo tree -i` | none (dependencies are not indexed) | Low priority: index lockfiles (`Cargo.lock`, `package-lock.json`) as facts: who depends on X, versions, MSRV. |
| Look up Win32 signatures in `windows-sys` sources | Git Bash grep in `~/.cargo/registry` | none | Low priority: `aix grep --dep <crate>` over a dependency's source. |
| Triage a test run: each failing test with its first panic line, and failing tests per binary | Git Bash awk over the `cargo test -q` log | `aix put tests` + `aix grep` | New: a test-output parser for `put`/`filter` (cargo test, pytest, jest, go test): fields test, binary, panic location, message; `count by field location @tests` groups failures by cause. |
| Find the test function enclosing each compile-error location | Git Bash awk scanning back for `fn` | `aix code <file:line> --function` (one location per call) | Let `code --function` read `file:line` rows from stdin (compiler output), so one call names the enclosing member of every error. |
| Who uses a helper inside one test file | Git Bash `grep -n 'init('` | `aix callers init` | none |
| Split the working-tree diff into one commit per concern | Python: difflib hunks + keyword rules + nearest-neighbour for structural hunks | `aix diff`, `aix outline` | New: `aix diff --hunks`: each hunk with its enclosing member and the symbols it touches, the input a per-concern split (or a review) needs. |
| Type-check every commit of a branch for Linux from Windows | PS loop over `git rev-list` + `zig cc` wrappers | none | Not aix; worth a `scripts/check-linux.ps1` in the repo so a Windows contributor can keep Linux green without WSL. |
| Reproduce one hook decision: build the event JSON, pipe it to `aix hook pretool`, read the decision and reason from `.aix/hook-events.jsonl` | Python `json.dumps` + Git Bash (PowerShell's pipe added a BOM and the hook stayed silent) | `aix stats --hooks` (aggregates) | New: `aix hook explain --tool Grep --input '<json>'` (or a file): runs the decision without logging it and prints decision, reason (`no-answer:outside-repo` here), suggestion and the answer it would deny with. |
| Compare one file's extracted facts as CRLF and as LF | two temp repos + `aix update` + `aix sql` over `endpoints` | `aix sql` | New: `aix extract <file> [--json]`: run the extractors on one file (no index) and print its rows, the quick check for extractor bugs like the CRLF routes. |
| Find which git step a test helper failed on (`git add -A` exit 128 on `nul.txt`) | reproduce the fixture in a temp repo | none | Not aix. |
| Set aix up for this repo without `aix-init` (it needs bash and python3): exec-form hooks plus aix-init's 61 read-only allow rules, each as `Bash(...)` and `PowerShell(...)`, into `.claude/settings.local.json`; skill, commands and rules copies; `.aix/initialized`; `aix install-git-hook` | Python (the rule lists read from `scripts/aix-init.sh`) + Git Bash `cp` | `aix init` (done, item 26) | Done: `aix init` in Rust, the same steps on every OS, exec form everywhere, `PowerShell(...)` rules next to `Bash(...)` on Windows; this repo was re-set up with it. Seen: Claude Code applied the new hooks to the running session (the next grep was answered by the hook); the post-commit hook works under Git for Windows (a 2000-file commit returned in 317 ms, the index caught up 2.5 s later). |
| Fire each registered hook the way exec form runs it (command + args, no shell, a sample event on stdin): exit, time, decision | Python `subprocess.run` over the settings file | `aix hook classify` (transcripts only) | Into `aix doctor` (the environment-probes row): run every registered aix hook once with a sample event. Here: card 200-240 ms (its profiled stages 9 ms), prompt 48 ms, pretool 25-160 ms. |
| Set the weekly allocation for `stats --savings` | `~/.config/aix/config.toml`: `weekly_tokens = 116_000_000` | `weekly_tokens` / `AIX_WEEKLY_TOKENS` | `stats --savings` prints the allocation as `116000K tokens/week`, but neither the env var nor the config takes `K`/`M` (the env value is then ignored without a word; `116000K` in TOML makes the whole file ignored): accept the suffix aix prints. |
