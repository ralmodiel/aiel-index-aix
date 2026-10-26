# Regex search, materialized patterns and test scope

Regex search: `aix grep '<regex>' [--in <path part>] [--scripts]` searches the indexed files with a
1.5 s budget and bounded output. When it answers "partial" or "too broad", do what it says: run the `rg`
command it prints, or use/write a script for that query instead of retrying.
Common regexes are already materialized: 30 seeded patterns mined from what the project's scripts and agents
search with (JSX tags, onClick handlers, confirm dialogs, `<Route path>`, `@Path`, `@RolesAllowed`, `@GET`..,
`Roles.X`, `api.get('/x')`), plus any regex you search 3 times. Capture groups are indexed columns, so field
questions are one SQL call: `aix sql "select path, count(*) from pat_jaxrs_path group by 1"`,
`aix sql "select file, line from pat_roles_allowed where roles like '%ADMIN%'"`,
`aix sql "select method, path from pat_api_call where path like '/orders%'"`.
`aix patterns list [words]` shows each pattern's fields, rows, uses and status; `patterns check '<regex>'`;
`grep pat:<name>`; `patterns pin|unpin|rm <name>`. Unused auto patterns go dormant after 14 days, seeded ones
after 60; over the row budget the least-used go first.

Before a UI audit or an e2e run: `aix scope [rev|A..B]` prints the affected routes x roles as
`UXC_ROUTES=... scripts/ux-check.sh run <role> phone,find` commands and the e2e scenarios to run (routes they visit,
changed UI text they quote, nav checks, plus a smoke set); a typical small commit touches only a few routes and scenarios. Run the full suites when it says a shell/global file changed.

Meaning search over code: `aix ask "<plain question>" --kind code` returns `[code] file:start-end Class.method  <signature>`
rows (one chunk per function/method, long ones in windows; two per file at most; tests rank below the code they test unless
the question says "test"). Ranking is bm25 fused with embedding similarity; without the embedder, or while chunks are not
embedded yet (`aix embed`, `aix-refresh --embed SECS`), the answer says it is keyword-only. Read the row with
`aix code file:start-end`. Plain `ask` and `find` never return code chunks.

UI text with live values: `aix text "Not listed: 4 learners still owe ₱2,177.01"` treats numbers, amounts, dates and times as
wildcards and finds the JSX line (`Not listed: {n} learners ... {amount}`) or template (`${...}`) that renders them; exact
matches still come first.

Scripts outside the repo: with `script_dirs = ["~/tools"]` in `.aix/config.toml` (or `AIX_SCRIPT_DIRS=a:b`), `aix script words`
also lists those folders' scripts as `path [outside repo]  usage`. Only name and the redacted first usage line are read; they
are never indexed for grep/code/text/find, and dotfiles, credential-like names and hidden folders of `$HOME` are skipped.
