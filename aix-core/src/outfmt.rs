//! Global output options, for every command (CLI and MCP), read wherever they stand before a `--`:
//!
//! - `--bare`: machine rows only, no headers, notes, labels or indent: hits `path:line:text`, files `path`, ranges
//!   `path:A-B[:text]`, per-file counts `path:N` (like grep -c), groups `N<TAB>key`, other lines as plain text. When the
//!   answer was cut, one last line starting with `…` says how much and the exact next command (never a silent cut).
//! - `--head N`: at most N rows. On a listing command it reads page 1 of N rows of the full answer, so the footer's
//!   `--page 2` is the exact continuation; on a sectioned answer (brief, trace, code, outline ...) the first N rows
//!   are kept and the footer names the rest (`aix code F:A-B` for code, else the command without --head).
//! - `--width N`: clip each text column to N characters with `…` (the `path:line:` prefix is never clipped);
//!   `--width 0` = no clip. With `--bare` the default is 200; without it the command's own clip applies.
//!
//! - `--max-tokens N`: the whole answer kept within N tokens (4 bytes a token), cut only between lines (never a partial
//!   row); the last line says how many rows were shown and names the exact commands for the rest and for all of it.
//!   A first row bigger than the budget is never shown in part: the footer says so. Default from `max_tokens` in
//!   config.toml or `AIX_MAX_TOKENS` (0 = off); `--max-tokens 0` turns it off for one call.
//!
//! - Group-by-file layout (decorated listings only, `--no-group` turns it off): consecutive `path:line...` rows of one
//!   file print the path once (`  path:` then `    line...` under it), only when that saves >= 15% and >= 64 bytes of
//!   the answer and its token shape too. `--bare` rows never change.
//!
//! Default output (none of these given) is byte-for-byte what it was, apart from that layout.

use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutFmt {
    pub bare: bool,
    pub head: Option<usize>,
    pub width: Option<usize>,
    /// --head on a sectioned answer: the command that shows the rest (set by `run`)
    pub next: Option<String>,
    /// `--dedup[=KEY]` (dedup.rs): repeated rows removed, first occurrence kept; `--norm` with it collapses shapes
    pub dedup: Option<String>,
    pub norm: bool,
    /// `--no-dedup`: a `;` sequence / batch keeps rows an earlier section already printed
    pub no_dedup: bool,
    /// `--max-tokens N` (Some(0) = off for this call)
    pub max_tokens: Option<usize>,
    /// the command and its line as typed again (set by `run` when a budget applies; the budget footer names them)
    pub cmd: Option<String>,
    pub cmdline: Option<String>,
    /// `--no-group`: keep `path:line` on every row (no group-by-file layout)
    pub no_group: bool,
    /// `--locs`: rows reduced to `path:line` (implies --bare); for a caller that only needs where, then reads the lines itself
    pub locs: bool,
    /// `--gen G`: the index generation a continuation footer was printed at (a later page warns when it changed)
    pub gen: Option<String>,
}

impl OutFmt {
    pub fn is_default(&self) -> bool {
        !self.bare && self.head.is_none() && self.width.is_none() && self.dedup.is_none() && !self.no_dedup && !self.no_group && !self.locs && self.budget().is_none()
    }
    /// The output budget in bytes, when one applies.
    pub fn budget(&self) -> Option<usize> {
        self.max_tokens.filter(|n| *n > 0).map(|n| n.saturating_mul(4))
    }
    /// The flags as they would be typed again (for continuation commands).
    pub fn flags(&self) -> String {
        let mut s = String::new();
        if self.bare {
            s.push_str(" --bare");
        }
        if let Some(w) = self.width {
            s.push_str(&format!(" --width {w}"));
        }
        match self.dedup.as_deref() {
            Some("line") => s.push_str(" --dedup"),
            Some(k) => s.push_str(&format!(" --dedup={}", crate::shell_quote(k))),
            None => {}
        }
        if self.norm {
            s.push_str(" --norm");
        }
        if self.locs {
            s.push_str(" --locs");
        }
        if self.no_group {
            s.push_str(" --no-group");
        }
        s
    }
}

/// The line clip of the file readers (sed, code, cat, head, tail): 240 characters, and the flag that shows the rest.
/// `--width N` replaces it (0 = no clip; N > 0 clips the text column with the global rule).
pub fn reader_clip(l: &str) -> String {
    let n = l.chars().count();
    if n <= 240 || current().width.is_some() {
        return l.to_string();
    }
    format!("{}... [{} more chars] (--width 0 shows them)", l.chars().take(240).collect::<String>(), n - 240)
}

thread_local! {
    static CURRENT: std::cell::RefCell<OutFmt> = std::cell::RefCell::new(OutFmt::default());
}

/// The output options of the command running on this thread (row commands render with them).
pub fn current() -> OutFmt {
    CURRENT.with(|c| c.borrow().clone())
}

/// Set them; returns the previous ones (restored after the command: pipes nest commands).
pub fn set_current(f: OutFmt) -> OutFmt {
    CURRENT.with(|c| std::mem::replace(&mut *c.borrow_mut(), f))
}

/// The bare text width when none was given.
pub const BARE_WIDTH: usize = 200;

/// Pull `--bare`, `--head N|--head=N`, `--width N|--width=N` out of a token list (only before a `--`).
pub fn take_tokens(toks: &[String]) -> Result<(Vec<String>, OutFmt), String> {
    let mut f = OutFmt::default();
    let mut keep = Vec::with_capacity(toks.len());
    let mut i = 0;
    let mut literal = false;
    while i < toks.len() {
        let t = toks[i].as_str();
        if literal {
            keep.push(toks[i].clone());
            i += 1;
            continue;
        }
        if t == "--" {
            literal = true;
            keep.push(toks[i].clone());
            i += 1;
            continue;
        }
        let (name, inline) = match t.split_once('=') {
            Some((n, v)) if n == "--head" || n == "--width" || n == "--dedup" || n == "--max-tokens" || n == "--gen" => (n, Some(v)),
            _ => (t, None),
        };
        match name {
            "--bare" => {
                f.bare = true;
                i += 1;
            }
            "--locs" => {
                f.bare = true;
                f.locs = true;
                i += 1;
            }
            "--dedup" => {
                let k = inline.unwrap_or("line");
                crate::dedup::Key::parse(k).map_err(|e| format!("--dedup: {e}"))?;
                f.dedup = Some(k.to_string());
                i += 1;
            }
            // with --dedup only (a command's own --norm stays its own)
            "--norm" if toks.iter().take_while(|x| *x != "--").any(|x| x == "--dedup" || x.starts_with("--dedup=")) => {
                f.norm = true;
                i += 1;
            }
            "--no-dedup" => {
                f.no_dedup = true;
                i += 1;
            }
            "--no-group" => {
                f.no_group = true;
                i += 1;
            }
            "--gen" => {
                let (v, used) = match inline {
                    Some(v) => (Some(v), 1),
                    None => (toks.get(i + 1).map(String::as_str), 2),
                };
                let v = v.filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_hexdigit())).ok_or("--gen needs the generation a footer printed")?;
                f.gen = Some(v.to_string());
                i += used;
            }
            "--head" | "--width" | "--max-tokens" => {
                let (v, used) = match inline {
                    Some(v) => (Some(v), 1),
                    None => (toks.get(i + 1).map(String::as_str), 2),
                };
                let n = v.and_then(|v| v.trim().parse::<usize>().ok()).ok_or_else(|| format!("{name} needs a non-negative number"))?;
                if name == "--head" {
                    f.head = Some(n.max(1));
                } else if name == "--max-tokens" {
                    f.max_tokens = Some(n);
                } else {
                    f.width = Some(n);
                }
                i += used;
            }
            _ => {
                keep.push(toks[i].clone());
                i += 1;
            }
        }
    }
    Ok((keep, f))
}

/// The same on an argument string; the string is returned untouched (spacing kept) when nothing was taken.
pub fn take_str(arg: &str) -> Result<(String, OutFmt), String> {
    if !arg.contains("--bare") && !arg.contains("--locs") && !arg.contains("--head") && !arg.contains("--width") && !arg.contains("-dedup") && !arg.contains("--max-tokens") && !arg.contains("--no-group") && !arg.contains("--gen") {
        return Ok((arg.to_string(), OutFmt::default()));
    }
    let toks: Vec<String> = crate::query::shell_split(arg);
    let (keep, f) = take_tokens(&toks)?;
    if keep.len() == toks.len() {
        return Ok((arg.to_string(), f));
    }
    // words that were not quoted stay as typed (`src/p(1).ts`, `src/with space.ts:1-3` as the CLI joins them);
    // a string that held quotes keeps its quoting
    if !arg.contains(['\'', '"', '\\']) {
        return Ok((keep.join(" "), f));
    }
    Ok((keep.iter().map(|t| crate::shell_quote(t)).collect::<Vec<_>>().join(" "), f))
}

/// Listing commands: `--head N` reads page 1 of N rows of the full answer (the pager's `--page 2` continues it).
pub fn pageable(cmd: &str) -> bool {
    matches!(cmd, "callers" | "callees" | "symbol" | "find" | "ask" | "grep" | "text" | "endpoint" | "script" | "tasks" | "bugs" | "feature" | "hints")
}

/// A row line of decorated output (not a header, note, label, footer or context line).
pub fn is_row_line(l: &str) -> bool {
    let t = l.trim_start();
    !(t.is_empty() || t.starts_with("==") || t.starts_with('(') || t.starts_with('\u{2026}') || t == "--" || crate::plan::is_ctx(l))
}

static NUM_ROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+)(?: |$)").unwrap());
static CODE_HEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^== .*?(\S+):(\d+)-(\d+)").unwrap());

/// `--head N` on a sectioned answer: keep the first N rows (headers before them stay) and say what was cut.
pub fn cut_rows(lines: &mut Vec<String>, n: usize, cmd: &str, cmdline: &str) {
    let mut rows = 0usize;
    let mut cut_at: Option<usize> = None;
    // sql: the first row is the column header, not a data row
    let mut header = cmd == "sql";
    for (i, l) in lines.iter().enumerate() {
        if is_row_line(l) {
            if std::mem::take(&mut header) {
                continue;
            }
            rows += 1;
            if rows == n + 1 && cut_at.is_none() {
                cut_at = Some(i);
            }
        }
    }
    let Some(at) = cut_at else { return };
    let more = rows - n;
    // code: the exact next range of the block that was cut
    let mut next = format!("aix {cmdline}");
    if cmd == "code" {
        let head = lines[..at].iter().rev().find_map(|l| CODE_HEAD.captures(l).map(|c| (c[1].to_string(), c[3].parse::<usize>().unwrap_or(0))));
        let last = lines[..at].iter().rev().find_map(|l| NUM_ROW.captures(l).and_then(|c| c[1].parse::<usize>().ok()));
        if let (Some((f, b)), Some(last)) = (head, last) {
            next = format!("aix code {f}:{}-{b}", last + 1);
        }
    }
    lines.truncate(at);
    lines.push(format!("\u{2026} --head {n}: {more} more row{} not shown; the rest: `{next}`", if more == 1 { "" } else { "s" }));
}

/// Clip the text column of one line to `w` characters (the `path:line:` / `N ` prefix is kept whole).
pub fn clip_line(l: &str, w: usize) -> String {
    static PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*(?:[A-Za-z]:[\\/])?[^\s:]+:\d+(?:-\d+)?(?::\d+)?[: ] ?|\d+ |L\d+-\d+ |\d+\t)").unwrap());
    if w == 0 || l.chars().count() <= w {
        return l.to_string();
    }
    let (p, rest) = match PREFIX.find(l) {
        Some(m) => l.split_at(m.end()),
        None => ("", l),
    };
    if rest.chars().count() <= w {
        return l.to_string();
    }
    let mut s: String = p.to_string();
    s.extend(rest.chars().take(w));
    s.push('\u{2026}');
    s
}

/// Is this line a continuation footer (it names how to see more)?
fn is_continuation(l: &str) -> bool {
    let t = l.trim_start();
    t.starts_with('\u{2026}') || (t.starts_with('(') && (t.contains("next `aix") || t.contains(" more") && t.contains("`aix") || t.contains("partial")))
}

/// Render an answer's text lines with the options (the label is the caller's: it is dropped in bare mode).
pub fn render(lines: &[String], f: &OutFmt) -> Vec<String> {
    let width = f.width.or(if f.bare { Some(BARE_WIDTH) } else { None }).unwrap_or(0);
    if !f.bare {
        if width == 0 {
            return lines.to_vec();
        }
        return lines.iter().map(|l| if is_row_line(l) { clip_line(l, width) } else { l.clone() }).collect();
    }
    // the count-first footer (`  next: aix ... --page 2  # rows ...` and its indented alternatives) is not a row
    let footer = |l: &str| {
        let t = l.trim_start();
        t.starts_with("next: aix ") || (l.starts_with("        aix ") && l.contains("  # "))
    };
    let body: Vec<&str> = lines.iter().map(String::as_str).filter(|l| !footer(l)).collect();
    let rows = crate::rows::parse_text(&body.join("\n"), None);
    let mut out: Vec<String> = rows.bare_lines().into_iter().map(|l| clip_line(&l, width)).collect();
    // text lines of a sectioned answer (brief) lose their indent
    for l in out.iter_mut() {
        if l.starts_with(' ') {
            *l = l.trim_start().to_string();
        }
    }
    // the one continuation line: the last footer that says how to see more
    if let Some(c) = lines.iter().rev().find(|l| is_continuation(l)).or_else(|| lines.iter().find(|l| l.trim_start().starts_with("next: aix "))) {
        let t = c.trim();
        let t = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')).unwrap_or(t);
        out.push(if t.starts_with('\u{2026}') { t.to_string() } else { format!("\u{2026} {t}") });
    }
    out
}

/// Continuation footers (`next `aix ... --page N``) carry the index generation they were printed at (`--gen G`), so
/// the next page can tell that the index changed in between (rows may have moved). Rows are never rewritten.
pub fn stamp_gen(lines: &mut [String], gen: &str) {
    static PAGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(next:? `?aix [^`)]*? --page \d+)(?: --gen [0-9a-f]+)?").unwrap());
    for l in lines.iter_mut() {
        if is_row_line(l) && !l.starts_with('\u{2026}') {
            continue;
        }
        if l.contains("next `aix ") || l.contains("next: aix ") {
            let new = PAGE.replace_all(l, |c: &regex::Captures| format!("{} --gen {gen}", &c[1])).to_string();
            *l = new;
        }
    }
}

/// The listing commands whose decorated rows are `path:line...` (the group-by-file layout may apply to them).
pub fn groupable(cmd: &str) -> bool {
    // (not `text`: its rows are quoted back as `path:line` to find where a UI string lives)
    matches!(cmd, "grep" | "callers" | "callees" | "find" | "symbol" | "impact" | "trace" | "endpoint" | "bugs" | "scope")
}

static PATH_ROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*)([^\s:()\[\]`'\x22]*[/.][^\s:()\[\]`'\x22]*):(\d+(?:-\d+)?)([: ].*)?$").unwrap());

/// A rough token count (word runs, digit runs, other characters): paths split into many tokens, so a layout that
/// saves bytes but not tokens is not worth it.
fn token_shape(lines: &[String]) -> usize {
    static TOK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z]+|\d+|[^\sA-Za-z\d]").unwrap());
    lines.iter().map(|l| TOK.find_iter(l).count() + 1).sum()
}

/// Is this line the path line of a file group (`  path:`)?
pub fn is_group_head(l: &str) -> bool {
    let t = l.trim_start();
    t.len() > 1 && t.ends_with(':') && !t.contains(' ') && PATH_ROW.is_match(&format!("{}1", t))
}

/// Group-by-file layout: runs of 2+ consecutive `path:line...` rows of one file become `path:` then `  line...`
/// under it. None when it saves less than 15% or 64 bytes of the answer, or no tokens.
pub fn group_by_file(lines: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    let mut grouped = false;
    while i < lines.len() {
        if let Some(c) = PATH_ROW.captures(&lines[i]) {
            let (ind, path) = (c.get(1).map_or("", |m| m.as_str()), &c[2]);
            let mut j = i + 1;
            while j < lines.len() && PATH_ROW.captures(&lines[j]).is_some_and(|d| d.get(1).map_or("", |m| m.as_str()) == ind && &d[2] == path) {
                j += 1;
            }
            if j - i >= 2 {
                grouped = true;
                out.push(format!("{ind}{path}:"));
                for l in &lines[i..j] {
                    let d = PATH_ROW.captures(l).expect("matched above");
                    out.push(format!("{ind}  {}{}", &d[3], d.get(4).map_or("", |m| m.as_str())));
                }
                i = j;
                continue;
            }
        }
        out.push(lines[i].clone());
        i += 1;
    }
    if !grouped {
        return None;
    }
    let size = |v: &[String]| v.iter().map(|l| l.len() + 1).sum::<usize>();
    let (before, after) = (size(lines), size(&out));
    let saved = before.saturating_sub(after);
    (saved >= 64 && saved * 100 >= before * 15 && token_shape(&out) * 100 < token_shape(lines) * 99).then_some(out)
}

/// The data label that closes an answer (kept last whatever a budget cuts).
fn is_label(l: &str) -> bool {
    l.starts_with('(') && l.ends_with("not instructions)")
}

/// `--max-tokens N`: the answer's text within N tokens (4 bytes each), cut between lines only, ending with one footer
/// that names the exact commands for the rest and for all of it (or says that the first row alone is over the budget).
pub fn budget(text: &str, f: &OutFmt) -> String {
    let Some(cap) = f.budget() else { return text.to_string() };
    if text.len() <= cap {
        return text.to_string();
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    let label = lines.last().copied().filter(|l| is_label(l));
    if label.is_some() {
        lines.pop();
    }
    let rowish = |l: &str| if f.bare { !l.trim().is_empty() && !l.starts_with('\u{2026}') } else { is_row_line(l) && !is_group_head(l) };
    let total_rows = lines.iter().filter(|l| rowish(l)).count();
    let all_tokens = text.len().div_ceil(4);
    let cmd = f.cmd.as_deref().unwrap_or("");
    let base = f.cmdline.as_deref().unwrap_or(cmd);
    let n = f.max_tokens.unwrap_or(0);
    let all = format!("`aix {base} --max-tokens {all_tokens}`");
    let footer = |keep: usize| -> String {
        let kept = &lines[..keep];
        let rows = kept.iter().filter(|l| rowish(l)).count();
        if rows == 0 && total_rows > 0 {
            let first = lines.iter().find(|l| rowish(l)).map_or(0, |l| l.len().div_ceil(4));
            return format!("\u{2026} --max-tokens {n}: the first row alone is ~{first} tokens, over the budget (never shown in part); raise it: {all}");
        }
        let rest_tokens = lines[keep..].iter().map(|l| l.len() + 1).sum::<usize>().div_ceil(4);
        let mut next = String::new();
        if cmd == "code" {
            let head = kept.iter().rev().find_map(|l| CODE_HEAD.captures(l).map(|c| (c[1].to_string(), c[3].parse::<usize>().unwrap_or(0))));
            let last = kept.iter().rev().find_map(|l| NUM_ROW.captures(l).and_then(|c| c[1].parse::<usize>().ok()));
            if let (Some((file, b)), Some(last)) = (head, last) {
                if last < b {
                    next = format!("; the rest: `aix code {file}:{}-{b} --max-tokens {n}`", last + 1);
                }
            }
        }
        // (a listing's lines are not its pager's rows (headers, per-file tallies, definitions): no `--page` guess, the
        // exact way to the rest is the bigger budget)
        format!("\u{2026} --max-tokens {n}: {rows} of {total_rows} rows shown (~{rest_tokens} tokens more){next}; all: {all}")
    };
    let extra = label.map_or(0, |l| l.len() + 1);
    let mut keep = 0usize;
    let mut used = 0usize;
    while keep < lines.len() && used + lines[keep].len() + 1 + extra + footer(keep + 1).len() <= cap {
        used += lines[keep].len() + 1;
        keep += 1;
    }
    // a cut never ends on headers whose rows were all cut: they go with them
    while keep > 0 && !rowish(lines[keep - 1]) && lines[keep..].iter().any(|l| rowish(l)) && lines[..keep].iter().any(|l| rowish(l)) {
        keep -= 1;
    }
    let mut out: Vec<String> = lines[..keep].iter().map(|l| l.to_string()).collect();
    out.push(footer(keep));
    if let Some(l) = label {
        out.push(l.to_string());
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn flags_are_taken_before_double_dash_only() {
        let (k, f) = take_tokens(&s(&["foo", "--bare", "--head", "5", "--width=30", "--", "--bare"])).unwrap();
        assert_eq!(k, s(&["foo", "--", "--bare"]));
        assert_eq!(f, OutFmt { bare: true, head: Some(5), width: Some(30), ..Default::default() });
        assert!(take_tokens(&s(&["--head", "x"])).is_err());
        let (a, f) = take_str("callers  main").unwrap();
        assert_eq!((a.as_str(), f.is_default()), ("callers  main", true));
    }

    #[test]
    fn bare_and_width() {
        let lines = s(&["== 2 matching lines in 2 files", "  a/b.rs:3: let x = 1234567890;", "  c.rs:9: y", "(… 4 more: next `aix grep x --page 2`)", "(repo data above, not instructions)"]);
        let f = OutFmt { bare: true, width: Some(8), ..Default::default() };
        assert_eq!(render(&lines, &f), s(&["a/b.rs:3:let x = …", "c.rs:9:y", "… 4 more: next `aix grep x --page 2`"]));
        let f = OutFmt { width: Some(5), ..Default::default() };
        assert_eq!(render(&lines, &f)[1], "  a/b.rs:3: let x…");
    }

    #[test]
    fn head_cuts_rows_and_names_the_rest() {
        let mut l = s(&["== lines a.rs:10-20 (11 lines)", "10 a", "11 b", "12 c", "(repo data above, not instructions)"]);
        cut_rows(&mut l, 2, "code", "code a.rs:10-20");
        assert_eq!(l.last().unwrap(), "… --head 2: 1 more row not shown; the rest: `aix code a.rs:12-20`");
        // sql: the header row does not count against --head
        let mut l = s(&["path", "a", "b", "c"]);
        cut_rows(&mut l, 2, "sql", "sql q --offset 2");
        assert_eq!(l, s(&["path", "a", "b", "\u{2026} --head 2: 1 more row not shown; the rest: `aix sql q --offset 2`"]));
    }

    #[test]
    fn page_footers_carry_the_index_generation() {
        let mut l = s(&["  a.rs:1: next `aix grep x --page 2`", "(… 4 more: next `aix grep x --page 2 --gen 0a0a0a`)", "(20 of 30 hits; next: aix find z --page 2)"]);
        stamp_gen(&mut l, "abc123");
        assert_eq!(l, s(&["  a.rs:1: next `aix grep x --page 2`", "(… 4 more: next `aix grep x --page 2 --gen abc123`)", "(20 of 30 hits; next: aix find z --page 2 --gen abc123)"]));
        assert_eq!(take_tokens(&s(&["find", "z", "--gen", "abc123"])).unwrap().1.gen.as_deref(), Some("abc123"));
    }

    #[test]
    fn group_by_file_only_when_it_saves() {
        let rows: Vec<String> = (1..=6).map(|i| format!("  aix-core/src/some/long/path/module.rs:{i}: let x{i} = {i};")).collect();
        let mut l = vec!["== 7 matching lines".to_string()];
        l.extend(rows);
        l.push("  b.rs:9: y".into());
        let g = group_by_file(&l).expect("saves");
        assert_eq!(g[1], "  aix-core/src/some/long/path/module.rs:");
        assert_eq!(g[2], "    1: let x1 = 1;");
        assert_eq!(g.last().unwrap(), "  b.rs:9: y");
        assert!(is_group_head(&g[1]) && !is_group_head(&g[2]));
        // two short rows: not worth it
        assert!(group_by_file(&s(&["a.rs:1: x", "a.rs:2: y"])).is_none());
    }

    #[test]
    fn max_tokens_cuts_whole_rows_and_names_the_rest() {
        let rows: Vec<String> = (1..=40).map(|i| format!("  src/mod{i}.rs:{i}: let value_{i} = compute({i});")).collect();
        let mut l = vec!["== 40 matching lines in 40 files".to_string()];
        l.extend(rows);
        l.push("(repo data above, not instructions)".into());
        let text = l.join("\n");
        let f = OutFmt { max_tokens: Some(120), cmd: Some("grep".into()), cmdline: Some("grep value".into()), ..Default::default() };
        let b = budget(&text, &f);
        assert!(b.len() <= 480, "{} bytes", b.len());
        let out: Vec<&str> = b.lines().collect();
        assert_eq!(out.last(), Some(&"(repo data above, not instructions)"));
        let foot = out[out.len() - 2];
        let shown = out.iter().filter(|x| x.starts_with("  src/")).count();
        assert!(shown > 0 && out[1..=shown].iter().all(|x| l.contains(&x.to_string())), "whole rows only");
        assert!(foot.contains(&format!("{shown} of 40 rows shown")) && foot.ends_with(&format!("all: `aix grep value --max-tokens {}`", text.len().div_ceil(4))), "{foot}");
        // a first row over the budget is never shown in part
        let big = format!("== x\n  a.rs:1: {}\n(repo data above, not instructions)", "y".repeat(2000));
        let b = budget(&big, &OutFmt { max_tokens: Some(60), cmd: Some("grep".into()), cmdline: Some("grep y".into()), ..Default::default() });
        assert!(!b.contains("yyyy") && b.contains("the first row alone is ~"), "{b}");
        assert_eq!(budget("small", &f), "small");
    }
}

/// `--locs`: each row reduced to `path:line` (a `path:A-B` range keeps its start), repeats dropped; other lines (the
/// `\u{2026}` continuation) stay.
pub fn locs_only(t: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = vec![];
    for l in t.lines() {
        let loc = l.split_once(':').and_then(|(p, rest)| {
            let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            // a path may hold spaces (`my dir/a b.txt:3:x`); the line number must end at `:`/`-` or the line end
            let after = rest[n.len()..].chars().next();
            let pathy = !p.starts_with([' ', '(', '\u{2026}', '=']) && !p.ends_with(' ');
            (pathy && !n.is_empty() && matches!(after, None | Some(':' | '-'))).then(|| format!("{p}:{n}"))
        });
        match loc {
            Some(x) => {
                if seen.insert(x.clone()) {
                    out.push(x);
                }
            }
            None => out.push(l.to_string()),
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod locs_tests {
    #[test]
    fn rows_reduce_to_path_line() {
        let t = "a/b.rs:12:fn x() {}\na/b.rs:12:again\na/c.ts:3-9:y\n\u{2026} next: aix grep z --page 2";
        assert_eq!(super::locs_only(t), "a/b.rs:12\na/c.ts:3\n\u{2026} next: aix grep z --page 2");
        assert_eq!(super::locs_only("my dir/sp ace.txt:1:in space foo"), "my dir/sp ace.txt:1");
    }
}
