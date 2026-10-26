# Code lookups: aix first

This repo has a code index, `aix` (CLI; also the MCP tool `aix`). For code questions run it before Grep/Read:
- who calls X: `aix callers Class.method`
- what a change breaks, which endpoints reach X: `aix impact Class.method`
- UI -> client -> endpoint -> handler -> table: `aix trace "METHOD /path"` · `aix trace table:T --up` · find one: `aix endpoint <words>`
- one function, not the whole file: `aix code Class.method`

Grep is for plain text; Read is for the lines you will edit.
