//! CLI front of data sets (aix_core::sets / setq): `aix put` (stdin or files) and `aix sets`, before clap and without
//! opening the repo index. Every other command naming an `@set` (`aix grep X @gate`, `aix head @gate`) goes through the
//! usual dispatch (lib.rs answers it from the set store), and pipes / sequences through pipe.rs.

use std::io::IsTerminal;
use std::path::PathBuf;

use aix_core::setq;

struct Globals {
    repo: Option<PathBuf>,
    db: Option<PathBuf>,
    limit: Option<usize>,
    json: bool,
    jsonl: bool,
    pretty: bool,
}

/// Global flags anywhere before `--` are taken out; the rest is the command line.
fn split_globals(raw: Vec<String>) -> (Globals, Vec<String>) {
    let mut g = Globals { repo: None, db: None, limit: None, json: false, jsonl: false, pretty: false };
    let mut rest = vec![];
    let mut it = raw.into_iter().peekable();
    let mut dashdash = false;
    while let Some(a) = it.next() {
        if dashdash {
            rest.push(a);
            continue;
        }
        match a.as_str() {
            "--" => {
                dashdash = true;
                rest.push(a);
            }
            "--repo" => g.repo = it.next().map(PathBuf::from),
            "--db" => g.db = it.next().map(PathBuf::from),
            "--limit" => g.limit = it.next().and_then(|v| v.parse().ok()),
            "--json" => g.json = true,
            "--jsonl" => g.jsonl = true,
            "--pretty" => g.pretty = true,
            "--no-refresh" => {}
            s if s.starts_with("--repo=") => g.repo = Some(PathBuf::from(&s[7..])),
            s if s.starts_with("--db=") => g.db = Some(PathBuf::from(&s[5..])),
            s if s.starts_with("--limit=") => g.limit = s[8..].parse().ok(),
            _ => rest.push(a),
        }
    }
    (g, rest)
}

/// Handle the command line if it is about data sets; `Some(exit status)` when it was.
pub fn intercept() -> Option<i32> {
    let raw: Vec<String> = aix_core::sys::args().into_iter().skip(1).collect();
    let first = raw.iter().position(|a| !a.starts_with('-'))?;
    // a value of a global flag is not the command (`aix --repo x grep ...`)
    let (g, rest) = split_globals(raw);
    let cmd = rest.first()?.clone();
    let _ = first;
    // only `put` (reads stdin or files) and `sets`: every other command naming an @set, and every pipe, goes through
    // the usual dispatch (lib.rs answers @set commands from the store; pipe.rs runs each stage)
    let pipe_line = false;
    let verb = String::new();
    if !matches!(cmd.as_str(), "put" | "sets") {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let repo = g.repo.clone().unwrap_or_else(|| aix_core::find_repo(&cwd));
    let db = g.db.clone().or_else(|| std::env::var_os("AIX_DB").map(PathBuf::from));
    let dir = db.as_ref().and_then(|d| d.parent().map(|p| p.to_path_buf())).unwrap_or_else(|| repo.join(".aix"));
    if !matches!(cmd.as_str(), "put" | "sets") && !setq::any_store(&dir) {
        return None;
    }
    let mut ctx = setq::Ctx::open(&repo, &dir, db.as_deref(), true);
    ctx.limit = g.limit;
    let (cmd, args): (String, Vec<String>) = if pipe_line { ("pipe".into(), rest.clone()) } else { (cmd.clone(), rest[1..].to_vec()) };
    if !setq::wants(&ctx, &cmd, &args) {
        return None;
    }
    let _ = verb;
    if cmd == "put" {
        return Some(match setq::cli_put(&ctx, &args, std::io::stdin().is_terminal()) {
            Ok(po) => {
                for l in po.lines {
                    println!("{}", aix_extract::redact::redact_line(&l));
                }
                po.exit
            }
            Err(e) => {
                eprintln!("{}", aix_extract::redact::redact_line(&format!("aix: {e:#}")));
                2
            }
        });
    }
    let out = setq::run(&mut ctx, &cmd, &args, g.json || g.jsonl, true);
    let text = if g.json || g.jsonl { aix_core::render_json(&out, g.pretty, g.jsonl) } else { out.text() };
    {
        use std::io::Write;
        let mut o = std::io::stdout().lock();
        let _ = o.write_all(text.as_bytes());
        if !text.is_empty() {
            let _ = o.write_all(b"\n");
        }
        let _ = o.flush();
    }
    let bare = args.iter().any(|a| a == "--bare") || (cmd == "pipe" && args[0].contains("--bare"));
    if bare && out.label.is_none() && !out.error {
        eprintln!("{}", aix_core::sets::LABEL);
    }
    Some(setq::status(&out))
}
