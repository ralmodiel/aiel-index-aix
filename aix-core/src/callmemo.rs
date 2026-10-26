//! Work remembered for the length of one `run` call. An answer is often computed more than once in a call: the
//! exclusion tally re-runs the query without its criteria, and the count-first footer re-runs it uncapped. For grep
//! each run read and redacted every file again; here a file's result is kept by (search signature, path), so a re-run
//! only does the files the first run did not (the excluded ones). The memo is dropped when the call ends, so file
//! edits between calls are always seen.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// One file's grep result: whether the file was read, and (file, shown lines (line no, text, is a match), matching
/// lines in the file, matched texts) when it matched.
pub(crate) type GrepFile = (bool, Option<(String, Vec<(usize, String, bool)>, usize, Vec<String>, usize)>);

#[derive(Default)]
pub(crate) struct Memo {
    grep: Mutex<HashMap<(Arc<str>, String), GrepFile>>,
    any: Mutex<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>,
}

/// `f()`, or the value it gave earlier in this call for the same `key` (the key must name everything the value
/// depends on besides the index contents, e.g. the active exclusions). Outside a call: just `f()`.
pub(crate) fn cached<T: Clone + Send + Sync + 'static>(key: &str, f: impl FnOnce() -> T) -> T {
    let Some(m) = current() else { return f() };
    if let Some(v) = m.any.lock().ok().and_then(|g| g.get(key).cloned()) {
        if let Some(v) = v.downcast_ref::<T>() {
            return v.clone();
        }
    }
    let v = f();
    if let Ok(mut g) = m.any.lock() {
        g.insert(key.to_string(), Arc::new(v.clone()));
    }
    v
}

impl Memo {
    pub(crate) fn grep_get(&self, sig: &Arc<str>, path: &str) -> Option<GrepFile> {
        self.grep.lock().ok()?.get(&(sig.clone(), path.to_string())).cloned()
    }
    pub(crate) fn grep_put(&self, sig: &Arc<str>, path: &str, v: &GrepFile) {
        if let Ok(mut m) = self.grep.lock() {
            m.insert((sig.clone(), path.to_string()), v.clone());
        }
    }
}

thread_local! {
    static CUR: std::cell::RefCell<Option<Arc<Memo>>> = const { std::cell::RefCell::new(None) };
}

/// The memo of the call running on this thread (None outside `run`).
pub(crate) fn current() -> Option<Arc<Memo>> {
    CUR.with(|c| c.borrow().clone())
}

/// A fresh memo for the call that holds the guard (the previous one, of an enclosing call, comes back on drop).
pub(crate) struct Scope(Option<Arc<Memo>>);

pub(crate) fn scope() -> Scope {
    Scope(CUR.with(|c| c.replace(Some(Arc::new(Memo::default())))))
}

impl Drop for Scope {
    fn drop(&mut self) {
        let prev = self.0.take();
        CUR.with(|c| *c.borrow_mut() = prev);
    }
}
