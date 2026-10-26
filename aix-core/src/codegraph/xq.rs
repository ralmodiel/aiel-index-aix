//! XQuery / MarkLogic call resolution (rows from `aix_extract::lang::xquery`).
//!
//! A prefixed call carries the namespace URI its prefix is bound to; the functions of a module have that URI as
//! their container. Targets, in order: this file (the module's own functions, `local:`), the files named by the
//! `import module … at "…"` locations of that namespace (relative to the importing file, or absolute `/…` against
//! any modules root: the file whose path ends with it, nearest to the importer), else any module declaring the
//! namespace (nearest first). Overloads are picked by arity. `xqmod:<path>` (xdmp:invoke / xdmp:spawn) targets the
//! module member of that file. Only members named like the callee are read, so incremental updates re-resolve
//! exactly what a full build would.

use super::*;
use aix_extract::lang::xquery::{EXTS, LOCAL_NS, MOD_PREFIX};

pub(super) fn is_xq(file: &str) -> bool {
    file.rsplit_once('.').is_some_and(|(_, e)| EXTS.contains(&e))
}

/// Leading path segments two repo paths share.
fn common(a: &str, b: &str) -> usize {
    a.split('/').zip(b.split('/')).take_while(|(x, y)| x == y).count()
}

/// Is repo file `f` the module that location `at` (written in `from`) names?
fn at_matches(from: &str, at: &str, f: &str) -> bool {
    if at.is_empty() || at.contains("://") {
        return false;
    }
    if let Some(abs) = at.strip_prefix('/') {
        return f == abs || (f.len() > abs.len() && f.ends_with(abs) && f.as_bytes()[f.len() - abs.len() - 1] == b'/');
    }
    let dir = from.rsplit_once('/').map(|x| x.0).unwrap_or("");
    f == norm_path(&format!("{dir}/{at}"))
}

/// Absolute module path (`/lib/x.sjs`) to a repo file: the indexed file ending with it, nearest to `from`.
pub(super) fn abs_file(files: &HashSet<String>, from: &str, source: &str) -> Option<String> {
    source.strip_prefix('/')?;
    files.iter().filter(|f| at_matches(from, source, f)).max_by_key(|f| (common(from, f), std::cmp::Reverse(f.len()), std::cmp::Reverse((*f).clone()))).cloned()
}

impl Graph {
    /// Of `cands`, the members in the file(s) location `at` names (the nearest one when several files end with it).
    fn xq_at(&self, from: &str, at: &str, cands: &[usize]) -> Vec<usize> {
        let hit: Vec<usize> = cands.iter().copied().filter(|&i| at_matches(from, at, &self.ms[i].file)).collect();
        let best = hit.iter().map(|&i| common(from, &self.ms[i].file)).max().unwrap_or(0);
        hit.into_iter().filter(|&i| common(from, &self.ms[i].file) == best).collect()
    }

    pub(super) fn xq_targets(&self, file: &str, callee: &str, rt: &str, kind: &str, argc: i32) -> Vec<(usize, &'static str)> {
        if let Some(path) = rt.strip_prefix(MOD_PREFIX) {
            let c: Vec<usize> = self.by_name(callee).into_iter().flatten().copied().filter(|&i| self.ms[i].kind == "module").collect();
            return self.xq_at(file, path, &c).into_iter().take(3).map(|i| (i, "exact")).collect();
        }
        if rt.is_empty() {
            return vec![]; // built-in prefix (fn, xs, xdmp, cts, map, …) or an unbound one: a library name
        }
        let want = |i: usize| if kind == "field" { self.ms[i].kind == "field" } else { callable(&self.ms[i].kind) };
        let all: Vec<usize> = self.by_cn(&(rt.to_string(), callee.to_string())).into_iter().flatten().copied().filter(|&i| want(i)).collect();
        if all.is_empty() {
            return vec![];
        }
        // XQuery overloads by arity: keep the declarations taking this many arguments (none fits: a name-only match)
        let fits = |i: usize| argc < 0 || kind == "field" || self.ms[i].arity.is_none_or(|(lo, hi)| argc >= lo && (hi < 0 || argc <= hi));
        let fit: Vec<usize> = all.iter().copied().filter(|&i| fits(i)).collect();
        let (c, weak) = if fit.is_empty() { (all, true) } else { (fit, false) };
        let tag = |v: Vec<usize>, conf: &'static str| -> Vec<(usize, &'static str)> { v.into_iter().map(|i| (i, if weak { "name" } else { conf })).collect() };
        let same: Vec<usize> = c.iter().copied().filter(|&i| self.ms[i].file == file).collect();
        if !same.is_empty() || rt == LOCAL_NS {
            return tag(same, "exact");
        }
        let mut v: Vec<usize> = vec![];
        for im in self.imps(file).into_iter().flatten().filter(|im| im.callee == rt && !im.source.is_empty()) {
            for i in self.xq_at(file, &im.source, &c) {
                if !v.contains(&i) {
                    v.push(i);
                }
            }
        }
        if !v.is_empty() {
            return tag(v, "exact");
        }
        // no location given (or none indexed): the modules declaring the namespace, nearest first
        let best = c.iter().map(|&i| common(file, &self.ms[i].file)).max().unwrap_or(0);
        let near: Vec<usize> = c.into_iter().filter(|&i| common(file, &self.ms[i].file) == best).collect();
        let conf = if near.len() == 1 { "resolved" } else { "name" };
        tag(near.into_iter().take(4).collect(), conf)
    }
}
