//! Stdio MCP server: one `aix` tool that runs any query command against the always-fresh index.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, RwLock};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};
use aix_core::{Index, Opts, COMMANDS};

#[derive(Clone)]
pub struct Server {
    pool: Arc<Pool>,
}

/// Index handles (one SQLite connection each, WAL: readers run side by side) and the gate that keeps a refresh apart
/// from the queries of this process: a query holds it shared, a refresh (several transactions: files, derived layer,
/// code graph, traces) holds it alone, so no query here ever reads a half-applied update.
struct Pool {
    idle: Mutex<(Vec<Index>, usize)>, // (handles not in use, handles opened)
    freed: Condvar,
    max: usize,
    repo: PathBuf,
    db: PathBuf,
    gate: RwLock<()>,
}

impl Pool {
    fn new(ix: Index) -> Pool {
        let max = std::env::var("AIX_MCP_READERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8))
            .max(1);
        let (repo, db) = (ix.repo.clone(), ix.db_path.clone());
        Pool { idle: Mutex::new((vec![ix], 1)), freed: Condvar::new(), max, repo, db, gate: RwLock::new(()) }
    }

    /// A free handle, a new one (up to `max`), or wait for one.
    fn take(&self) -> anyhow::Result<Index> {
        let mut g = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if let Some(ix) = g.0.pop() {
                return Ok(ix);
            }
            if g.1 < self.max {
                g.1 += 1;
                drop(g);
                return match Index::open(&self.repo, Some(&self.db)) {
                    Ok(ix) => Ok(ix),
                    Err(e) => {
                        let mut g = self.idle.lock().unwrap_or_else(|p| p.into_inner());
                        g.1 -= 1;
                        if g.1 == 0 {
                            return Err(e);
                        }
                        // the others still serve: wait for one of them
                        loop {
                            if let Some(ix) = g.0.pop() {
                                return Ok(ix);
                            }
                            g = self.freed.wait(g).unwrap_or_else(|p| p.into_inner());
                        }
                    }
                };
            }
            g = self.freed.wait(g).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn put(&self, ix: Index) {
        self.idle.lock().unwrap_or_else(|p| p.into_inner()).0.push(ix);
        self.freed.notify_one();
    }

    /// Run one command: a current index is queried under the shared gate (in parallel with other queries); one that
    /// needs a refresh is refreshed and queried under the exclusive gate (exactly as the single-handle server did).
    fn run(&self, cmd: &str, args: &str, opts: &Opts) -> anyhow::Result<aix_core::Out> {
        let mut ix = self.take()?;
        let res = (|| {
            let shared = self.gate.read().unwrap_or_else(|p| p.into_inner());
            // not current (files changed, or an update elsewhere is unfinished): refresh first, alone
            if ix.is_current() {
                test_pause();
                if cmd == "ask" && ix.cfg.query_embed_deadline_secs > 0.0 {
                    let _ = aix_core::semantic::embed_pending(&ix, std::time::Duration::from_secs_f64(ix.cfg.query_embed_deadline_secs));
                }
                let o = Opts { no_refresh: true, ..opts.clone() };
                return guarded(&mut ix, cmd, args, &o);
            }
            drop(shared);
            let _alone = self.gate.write().unwrap_or_else(|p| p.into_inner());
            guarded(&mut ix, cmd, args, opts)
        })();
        self.put(ix);
        res
    }
}

/// Test hook: `AIX_MCP_TEST_PAUSE_MS` widens the window between the freshness check and the query (so a test can
/// show that a refresh never runs inside it). Unset: nothing.
fn test_pause() {
    static MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let ms = *MS.get_or_init(|| std::env::var("AIX_MCP_TEST_PAUSE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(0));
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// `aix_core::run`, with a panic turned into an error: the server keeps serving and the caller gets an error result.
fn guarded(ix: &mut Index, cmd: &str, args: &str, opts: &Opts) -> anyhow::Result<aix_core::Out> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| aix_core::run(ix, cmd, args, opts))) {
        Ok(r) => r,
        Err(p) => {
            let m = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            Err(anyhow::anyhow!("internal error (panic) running '{cmd}': {m}"))
        }
    }
}

/// `read_only`: false when the repo opted in to data writes (`allow_data`: put, sets rm, sets prune over MCP).
fn tool(read_only: bool) -> Tool {
    let cmds: Vec<&str> = COMMANDS.iter().map(|c| c.0).collect();
    // tools/list is paid on every turn of every session: terse (size test in tests/sk13.rs); the long form of any
    // command is one call away (`howto <command>`), as is the CLI help
    let desc = "Project index for this repo: fresh, bounded answers citing file:line. Use BEFORE grep/Read. \
        Privacy: never attach/paste home dotfiles, history or credential files; run privacy-check after attach/paste/logs add. \
        Commands: before editing: brief route outline code symbol text endpoint table; who calls / what breaks: callers \
        callees impact trace scope; search: grep find ask files ls howto; history: bugs qa history tasks hints feature explain; \
        read: cat head tail sed diff anchor; data: put sets count filter dedup pipe batch logs paste; index: stats sql schema. \
        Usage of one: command=howto args=<command>. Save tokens: exclude/only, skip/fields, count first, exists, group_by, max_tokens.";
    let s = |d: &str| json!({"type": "string", "description": d});
    let i = |d: &str| json!({"type": "integer", "description": d});
    let b = |d: &str| json!({"type": "boolean", "description": d});
    let schema = json!({
        "type": "object",
        "properties": {
            "command": {"type": "string", "enum": cmds},
            "args": s("the command's arguments as on the CLI"),
            "limit": i("rows per section (20)"),
            "kind": s("find/ask: entry kinds"),
            "answer": b("ask: cited answer from the local LLM"),
            "json": b("structured hits as compact JSON"),
            "pretty": b("indented JSON"),
            "jsonl": b("JSON lines"),
            "exclude": s("pre-filter: kinds (docs,tests,...) or globs"),
            "only": s("only these kinds or globs"),
            "hide": s("post-filter, keeps a tally"),
            "skip": s("sections to leave out"),
            "fields": s("only these sections"),
            "order": s("section order"),
            "sort": s("relevance|path|recency|conf|fanin|size"),
            "conf": s("call-graph confidences, e.g. exact,resolved"),
            "no_default_excludes": b("ignore configured excludes"),
            "count": b("breakdown and narrower commands, no rows"),
            "page": i("page N"),
            "per_page": i("rows per page"),
            "offset": i("start at row K"),
            "group_by": s("one row per group: file, dir[:N], kind, ..."),
            "having": s("group filter, e.g. count>2"),
            "exists": b("one line: yes (first hit) or no"),
            "bare": b("machine rows only"),
            "locs": b("only path:line per hit (implies bare), when the location is all you need"),
            "head": i("at most N rows"),
            "width": i("clip text to N chars"),
            "max_tokens": i("token budget, whole rows"),
            "dedup": {"type": ["boolean", "string"], "description": "drop repeated rows (true or a key)"},
            "norm": b("with dedup: fold numbers/ids"),
            "commands": {"type": "array", "items": {"type": "string"}, "description": "batch/pipe: one command each"},
            "savings": b("stats: savings block"),
            "text": s("put: content to store")
        },
        "required": ["command"]
    });
    let obj = schema.as_object().cloned().unwrap_or_default();
    let mut t = Tool::new("aix", desc, Arc::new(obj));
    t.annotations = Some(ToolAnnotations::new().read_only(read_only));
    t
}

/// Intent-named tools next to the generic one (AIX_MCP_TOOLS=intent): (tool, command, argument, description). A model
/// that would not pick "aix" with a command enum may pick a tool named after the question it is answering.
const INTENT: &[(&str, &str, &str, &str)] = &[
    ("aix_callers", "callers", "symbol", "Who calls a function or method (Class.method or name): every call site with file:line, from the code graph. Use instead of grepping for the name."),
    ("aix_impact", "impact", "symbol", "What a change to a function reaches: the HTTP endpoints (METHOD /path, roles), UI routes and tests that call it through any chain, in one call."),
    ("aix_trace", "trace", "target", "Trace a route, \"METHOD /path\", table:NAME or Class.method across screen -> client fn -> endpoint -> handler -> service -> table, file:line per hop."),
    ("aix_endpoint", "endpoint", "query", "Find HTTP endpoints by path or words: METHOD path, handler file:line, roles, the client function and the screens that call it."),
    ("aix_find_text", "text", "text", "Where a UI string or message is defined and which tests quote it (file:line)."),
    ("aix_code", "code", "target", "Print one function or line range without reading the whole file: Class.method, file:line or file:A-B (60 lines max)."),
];

fn intent_mode() -> bool {
    std::env::var("AIX_MCP_TOOLS").is_ok_and(|v| v == "intent")
}

/// Intent mode: the six named tools and a slim generic `aix` (command + args) for everything else; all of it
/// within 4 KB of schema (tests/sk13.rs).
fn intent_tools(read_only: bool) -> Vec<Tool> {
    let schema = json!({"type": "object", "properties": {
        "command": {"type": "string", "description": "an aix command: brief outline symbol table grep find ask files ls bugs qa history tasks scope callees explain stats ... (howto <command>: its usage)"},
        "args": {"type": "string", "description": "its arguments as on the CLI"},
        "max_tokens": {"type": "integer", "description": "token budget"}}, "required": ["command"]});
    let mut generic = Tool::new("aix", "This repo's code index, any other query: fresh, bounded answers citing file:line. Use before grep/Read.", Arc::new(schema.as_object().cloned().unwrap_or_default()));
    generic.annotations = Some(ToolAnnotations::new().read_only(read_only));
    let mut v: Vec<Tool> = INTENT
        .iter()
        .map(|(name, _, arg, desc)| {
            let mut props = serde_json::Map::new();
            props.insert(arg.to_string(), json!({"type": "string"}));
            if *name == "aix_trace" {
                props.insert("up".into(), json!({"type": "boolean", "description": "from an endpoint or table up to the screens"}));
            }
            let schema = json!({"type": "object", "properties": props, "required": [arg]});
            let mut t = Tool::new(*name, *desc, Arc::new(schema.as_object().cloned().unwrap_or_default()));
            t.annotations = Some(ToolAnnotations::new().read_only(true));
            t
        })
        .collect();
    v.push(generic);
    v
}

/// An intent tool's call as the generic tool's arguments; None: not an intent tool.
fn intent_call(name: &str, a: &Value) -> Option<Result<Value, String>> {
    let (_, cmd, arg, _) = INTENT.iter().find(|t| t.0 == name)?;
    let Some(v) = a.get(*arg).and_then(Value::as_str).map(str::trim).filter(|v| !v.is_empty()) else {
        return Some(Err(format!("argument '{arg}' (a string) is required")));
    };
    let mut args = if v.contains(char::is_whitespace) && !v.starts_with('"') { format!("\"{}\"", v.replace('"', "")) } else { v.to_string() };
    if *cmd == "trace" && a.get("up").and_then(Value::as_bool) == Some(true) {
        args.push_str(" --up");
    }
    Some(Ok(json!({"command": cmd, "args": args})))
}

impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "aix answers project questions from a local index: brief <route|file> before editing, impact before committing, \
             bugs/qa/text/endpoint/symbol/script/feature for lookups, ask for meaning-based search.",
        );
        info.server_info = Implementation::new("aix", env!("CARGO_PKG_VERSION"));
        info
    }

    async fn list_tools(
        &self,
        _r: Option<PaginatedRequestParams>,
        _c: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let ro = !aix_core::setq::mcp_data_allowed(self.pool.db.parent().unwrap_or(&self.pool.repo));
        let tools = if intent_mode() { intent_tools(ro) } else { vec![tool(ro)] };
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        _c: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let a: Value = if req.name == "aix" {
            Value::Object(req.arguments.unwrap_or_default())
        } else {
            match intent_call(&req.name, &Value::Object(req.arguments.unwrap_or_default())) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return Err(ErrorData::invalid_params(e, None)),
                None => return Err(ErrorData::invalid_params(format!("unknown tool {}", req.name), None)),
            }
        };
        // argument types are checked, not coerced: a wrong type is a client bug (invalid params), not "empty"
        let bad = |k: &str, want: &str| ErrorData::invalid_params(format!("argument '{k}' must be {want}"), None);
        let cmd = match a.get("command") {
            Some(Value::String(c)) if !c.is_empty() => c.clone(),
            Some(Value::String(_)) | None => return Err(ErrorData::invalid_params("argument 'command' is required", None)),
            Some(_) => return Err(bad("command", "a string")),
        };
        // `command` is the command name only; "logs errors" in it is the commonest slip
        if let Some((first, rest)) = cmd.split_once(char::is_whitespace) {
            if COMMANDS.iter().any(|c| c.0 == first) {
                return Err(ErrorData::invalid_params(format!("unknown command '{cmd}': `command` is only the command name (\"{first}\"); put the rest ({}) in the separate `args` argument", rest.trim()), None));
            }
        }
        let mut args = match a.get("args") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err(bad("args", "a string")),
        };
        // batch / pipe: a commands array is one command per item
        let mut argv: Option<Vec<String>> = None;
        match a.get("commands") {
            None | Some(Value::Null) => {}
            Some(Value::Array(v)) if v.iter().all(|x| x.is_string()) => {
                let cs: Vec<String> = v.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
                if cmd == "batch" || cmd == "pipe" {
                    argv = Some(if cmd == "pipe" { vec![cs.join(" | ")] } else { cs });
                }
            }
            Some(_) => return Err(bad("commands", "an array of strings")),
        }
        // global output options travel with the arguments, as on the CLI
        let mut front: Vec<String> = vec![];
        if matches!(a.get("bare"), Some(Value::Bool(true))) {
            front.push("--bare".into());
        }
        if matches!(a.get("locs"), Some(Value::Bool(true))) {
            front.push("--locs".into());
        }
        match a.get("dedup") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => front.push("--dedup".into()),
            Some(Value::String(k)) => front.push(format!("--dedup={k}")),
            Some(_) => return Err(bad("dedup", "true or a key string")),
        }
        if matches!(a.get("norm"), Some(Value::Bool(true))) {
            front.push("--norm".into());
        }
        for k in ["head", "width", "max_tokens"] {
            match a.get(k) {
                None | Some(Value::Null) => {}
                Some(v) => match v.as_u64() {
                    Some(n) => front.extend([format!("--{}", k.replace('_', "-")), n.to_string()]),
                    None => return Err(bad(k, "a non-negative integer")),
                },
            }
        }
        if !front.is_empty() {
            match argv.as_mut() {
                Some(v) => {
                    front.extend(v.drain(..));
                    *v = front;
                }
                None if cmd == "pipe" || cmd == "batch" => {
                    let mut v = front;
                    v.push(args.clone());
                    argv = Some(v);
                }
                None => args = format!("{} {args}", front.join(" ")),
            }
        }
        if cmd == "patterns" {
            if let Some(e) = aix_core::logq::patterns_mcp_error(&args) {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!("aix: {e}"))]).into());
            }
        }
        // a pipe typed into `args` of a single command (`grep x -l | put s`): the stages would be read as words
        if !matches!(cmd.as_str(), "pipe" | "batch" | "sql" | "put") {
            let parts = aix_core::pipe::split_outside_quotes(&args, '|');
            if parts.len() > 1 && parts[1..].iter().all(|p| p.split_whitespace().next().is_some_and(|w| COMMANDS.iter().any(|c| c.0 == w) || matches!(w, "sort" | "uniq" | "head" | "tail" | "cut" | "wc" | "sed" | "put"))) {
                return Err(ErrorData::invalid_params(format!("`|` in args of `{cmd}`: a pipe is command \"pipe\" with args \"{cmd} {args}\""), None));
            }
        }
        if cmd == "put" {
            return Ok(mcp_put(&self.pool.repo, &self.pool.db, &args, a.get("text")).into());
        }
        if let Some(e) = aix_core::logq::query_arg_error(&cmd, &args) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(e)]).into());
        }
        let limit = match a.get("limit") {
            None | Some(Value::Null) => 20,
            Some(v) => match v.as_u64() {
                Some(n) => usize::try_from(n).unwrap_or(usize::MAX),
                None => return Err(bad("limit", "a non-negative integer")),
            },
        };
        let kind = match a.get("kind") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(bad("kind", "a string")),
        };
        let flag = |k: &str| -> Result<bool, ErrorData> {
            match a.get(k) {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(b)) => Ok(*b),
                Some(_) => Err(bad(k, "a boolean")),
            }
        };
        let list = |k: &str| -> Result<Vec<String>, ErrorData> {
            match a.get(k) {
                None | Some(Value::Null) => Ok(vec![]),
                Some(Value::String(s)) => Ok(s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()),
                Some(_) => Err(bad(k, "a string")),
            }
        };
        let num = |k: &str| -> Result<Option<usize>, ErrorData> {
            match a.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => v.as_u64().map(|n| Some(n as usize)).ok_or_else(|| bad(k, "a non-negative integer")),
            }
        };
        let x = aix_core::excl::ExclArgs {
            exclude: list("exclude")?,
            only: list("only")?,
            hide: list("hide")?,
            skip: list("skip")?,
            fields: list("fields")?,
            order: list("order")?,
            sort: list("sort")?,
            conf: list("conf")?,
            no_default: flag("no_default_excludes")?,
            plan: flag("count")?,
            exists: flag("exists")?,
            page: num("page")?.map(|n| n.max(1)),
            per_page: num("per_page")?.map(|n| n.max(1)),
            offset: num("offset")?,
            group_by: match a.get("group_by") { Some(Value::String(s)) if !s.is_empty() => Some(s.to_ascii_lowercase()), _ => None },
            having: match a.get("having") { Some(Value::String(s)) if !s.is_empty() => Some(s.clone()), _ => None },
        };
        let opts = Opts {
            limit,
            kind,
            answer: flag("answer")?,
            // as the CLI: the savings block only when asked (`stats --savings` there, `savings: true` here)
            savings: cmd == "stats" && (flag("savings")? || args.split_whitespace().any(|w| w == "--savings")),
            current_week_pct: {
                let w: Vec<&str> = args.split_whitespace().collect();
                w.iter().position(|x| *x == "--currentweek").and_then(|i| w.get(i + 1))
                    .and_then(|v| v.trim_end_matches('%').parse::<f64>().ok()).filter(|p| (0.0..=100.0).contains(p))
            },
            no_refresh: false,
            argv,
            x,
        };
        let (as_json, pretty, jsonl) = (flag("json")?, flag("pretty")?, flag("jsonl")?);
        let pool = self.pool.clone();
        let cmd_name = cmd.clone();
        // a poisoned lock (an earlier panic) is recovered, never fatal; a panic in a call is caught (see `guarded`)
        let res = tokio::task::spawn_blocking(move || pool.run(&cmd, &args, &opts))
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let r = match res {
            Ok(out) => {
                // the lines were redacted once in `run` (a second pass would turn a credential-looking file name's
                // `path:line` into `path:***`)
                let text = if as_json || jsonl { aix_core::render_json(&out, pretty, jsonl) } else { out.text() };
                let first = out.lines.first().map(String::as_str).unwrap_or("");
                // 0 found, 1 none (a structured marker, not an error), 2 usage / error (isError)
                let status = aix_core::opts::exit_status(&cmd_name, &out);
                if status == 2 || first.starts_with("usage: aix ") || first.starts_with("aix: ") {
                    CallToolResult::error(vec![ContentBlock::text(text)])
                } else {
                    let mut ok = CallToolResult::success(vec![ContentBlock::text(text)]);
                    if status == 1 {
                        ok.structured_content = Some(json!({"none": true, "exit": 1}));
                    }
                    ok
                }
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(aix_extract::redact::redact_line(&format!("aix error: {e}")))]),
        };
        Ok(r.into())
    }
}

/// `put` over MCP: content in `text`; allowed only where the repo opted in (`aix-init --allow-data`).
fn mcp_put(repo: &std::path::Path, db: &std::path::Path, args: &str, text: Option<&Value>) -> CallToolResult {
    let dir = db.parent().unwrap_or(repo).to_path_buf();
    if !aix_core::setq::mcp_data_allowed(&dir) {
        return CallToolResult::error(vec![ContentBlock::text("aix: put writes a data set: not enabled for MCP in this repo (opt in with aix-init --allow-data, or run `cmd | aix put <name> -` in a shell)")]);
    }
    let Some(Value::String(t)) = text else {
        return CallToolResult::error(vec![ContentBlock::text("aix: put needs the content in the `text` argument (a string)")]);
    };
    match aix_core::setq::mcp_put(repo, &dir, args, t) {
        Ok(po) if po.exit == 0 => CallToolResult::success(vec![ContentBlock::text(aix_extract::redact::redact_block(&po.lines.join("\n")))]),
        Ok(po) => CallToolResult::error(vec![ContentBlock::text(aix_extract::redact::redact_block(&po.lines.join("\n")))]),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(aix_extract::redact::redact_line(&format!("aix: {e:#}")))]),
    }
}

pub fn serve(ix: Index) -> anyhow::Result<()> {
    // one MCP process is one agent session: `code` may say "already printed" instead of repeating a range
    aix_core::query::CODE_SESSION.store(true, std::sync::atomic::Ordering::Relaxed);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        // the embedding generation lets the vector matrices stay in memory between `ask` calls
        aix_core::semantic::ensure_gen(&ix);
        let server = Server { pool: Arc::new(Pool::new(ix)) };
        let running = server.serve(filtered_stdio()).await?;
        running.waiting().await?;
        anyhow::Ok(())
    })
}

/// JSON-RPC errors the transport would not send: a line that is not JSON gets -32700 (the client would otherwise wait
/// for ever), a `tools/call` whose `arguments` is not an object gets -32602 (not "method not found").
fn protocol_error(line: &str) -> Option<String> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    let v: Value = match serde_json::from_str(t) {
        Ok(v) => v,
        Err(e) => return Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("Parse error: {e}")}}).to_string()),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    if !v.is_object() {
        return Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Invalid Request: not a JSON-RPC object"}}).to_string());
    }
    if v.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
        let p = v.get("params");
        let bad = match p {
            Some(Value::Object(o)) => o.get("arguments").is_some_and(|a| !a.is_object() && !a.is_null()) || !o.get("name").is_some_and(|n| n.is_string()),
            _ => true,
        };
        if bad {
            return Some(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "Invalid params: tools/call takes {\"name\": string, \"arguments\": object}"}}).to_string());
        }
    }
    None
}

/// stdin/stdout for the server with `protocol_error` answered here: lines go through a filter task into the server,
/// and the server's lines and the filter's error lines share one locked stdout (whole lines, never interleaved).
fn filtered_stdio() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (srv_in, mut feed) = tokio::io::duplex(1 << 20);
    let (srv_out, drain) = tokio::io::duplex(1 << 20);
    let out = Arc::new(std::sync::Mutex::new(std::io::stdout()));
    let say = |out: &Arc<std::sync::Mutex<std::io::Stdout>>, l: &str| {
        use std::io::Write;
        if let Ok(mut o) = out.lock() {
            let _ = o.write_all(format!("{l}\n").as_bytes());
            let _ = o.flush();
        }
    };
    let o1 = out.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            match protocol_error(&l) {
                Some(err) => say(&o1, &err),
                None => {
                    if feed.write_all(format!("{l}\n").as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = feed.shutdown().await; // end of input: the server stops as with the plain stdio transport
    });
    let o2 = out;
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(drain).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            say(&o2, &l);
        }
    });
    (srv_in, srv_out)
}
