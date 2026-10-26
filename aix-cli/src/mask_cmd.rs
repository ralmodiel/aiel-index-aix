//! `aix mask add|list|rm|test`: user-submitted masks (see aix_extract::masks).

use std::io::Read;
use std::path::Path;

use aix_extract::masks::{self, Scope};
use anyhow::{bail, Result};

fn usage() -> anyhow::Error {
    anyhow::anyhow!("usage: aix mask add '<regex>' [--name N] [--hint label] [--scope repo|global] | aix mask add --literal '<text>' [--icase] [...] | aix mask list | aix mask rm <name> [--purge] | aix mask test ['<text>']  (text from stdin when omitted)")
}

/// `rest` is the argv after `mask`. `reindex` runs the retroactive pass (needs the index).
pub fn run(repo: &Path, db: Option<&Path>, rest: &[String]) -> Result<()> {
    let sub = rest.first().map(String::as_str).unwrap_or("");
    let _ = aix_core::config::Config::load(repo, &repo.join(".aix")); // installs the current masks
    match sub {
        "list" => {
            let l = masks::list(repo);
            if l.is_empty() {
                println!("no masks (add one: aix mask add '<regex>' [--literal] [--hint label])");
            }
            for (sc, m) in l {
                let kind = if m.is_legacy() {
                    format!("literal, {} chars, legacy sha1 fingerprint (re-add it with `aix mask add --literal` for the slow hash)", m.len)
                } else if m.is_literal() {
                    format!("literal, {} chars, {} x{} iterations{} (only a slow salted hash is stored)", m.len, m.kdf, m.iters, if m.icase { ", case-insensitive" } else { "" })
                } else {
                    format!("regex {}", m.pattern)
                };
                println!("{} [{}] ***{}*** {kind}", m.name, if sc == Scope::Repo { "repo" } else { "global" }, m.label());
            }
            Ok(())
        }
        "test" => {
            let text = match rest.get(1) {
                Some(t) => t.clone(),
                None => {
                    let mut s = String::new();
                    std::io::stdin().take(8 << 20).read_to_string(&mut s)?;
                    aix_core::sys::strip_stdin_bom(&mut s);
                    s
                }
            };
            let (out, hits) = aix_extract::redact::redact_with_hits(&text);
            println!("{out}");
            eprintln!("aix mask test: {} installed mask(s); hits: {}", masks::count(), if hits.is_empty() { "none".into() } else { hits.iter().map(|(n, c)| format!("{n} x{c}")).collect::<Vec<_>>().join(", ") });
            Ok(())
        }
        "rm" => {
            let purge = rest.iter().any(|a| a == "--purge");
            let Some(name) = rest[1..].iter().find(|a| !a.starts_with("--")) else { return Err(usage()) };
            if !masks::remove(repo, name).map_err(anyhow::Error::msg)? {
                bail!("no mask named '{name}' (aix mask list)");
            }
            if purge {
                println!("removed mask '{name}'; re-ingesting everything from source (aix update --full) so the text is back ...");
                let mut ix = aix_core::index::Index::open(repo, db)?;
                let s = ix.update(true)?;
                println!("{}", s.line());
            } else {
                println!("removed mask '{name}'. Rows already stored stay masked: run `aix update --full` to re-ingest from source (or `aix mask rm {name} --purge` does that now).");
            }
            Ok(())
        }
        "add" => {
            let mut pat: Option<String> = None;
            let (mut name, mut hint, mut scope, mut literal, mut icase) = (None, None, Scope::Repo, false, false);
            let mut it = rest[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--name" => name = it.next().cloned(),
                    "--hint" => hint = it.next().cloned(),
                    "--scope" => {
                        scope = match it.next().map(String::as_str) {
                            Some("repo") => Scope::Repo,
                            Some("global") => Scope::Global,
                            _ => return Err(usage()),
                        }
                    }
                    "--literal" => literal = true,
                    "--icase" => icase = true,
                    x if pat.is_none() => pat = Some(x.to_string()),
                    _ => return Err(usage()),
                }
            }
            let Some(pat) = pat else { return Err(usage()) };
            if icase && !literal {
                bail!("--icase applies to --literal masks (write (?i) in a regex)");
            }
            let def = masks::add_ex(scope, repo, &pat, name.as_deref(), hint.as_deref(), literal, icase).map_err(|e| anyhow::anyhow!("mask refused: {e}"))?;
            masks::install(repo);
            println!("added mask '{}' ({}): masked as ***{}*** in every answer and in stored text; file and entry paths keep their raw names in the index (it needs them to find files) and are masked when shown", def.name, if def.is_literal() { if def.icase { "literal, slow hash only, any case or percent-encoded" } else { "literal, slow hash only" } } else { "regex" }, def.label());
            // retroactive: re-mask what is already stored
            match aix_core::index::Index::open(repo, db) {
                Ok(ix) => {
                    let (rows, tables) = aix_core::remask::remask(&ix, |l| eprintln!("aix: {l}"))?;
                    println!("re-masked {rows} stored value(s) in {tables} table(s); output-time masking covers the rest");
                }
                Err(e) => println!("no index to re-mask yet ({e}); it is masked as it is ingested"),
            }
            Ok(())
        }
        _ => Err(usage()),
    }
}
