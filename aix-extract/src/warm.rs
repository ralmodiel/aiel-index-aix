//! Process-start warm-up: the redaction rules are compiled on background threads while the main thread opens the
//! index and runs the query, so the first printed line does not pay for the compile. Every regex here is a pure
//! function of its pattern (no settings are read at compile time), so compiling it on another thread gives the
//! very same matcher the main thread would have built; a main-thread use that arrives first simply waits for it.

/// Start compiling the redaction rules in the background (idempotent; never blocks the caller).
pub fn prewarm() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = std::thread::Builder::new().name("aix-warm-set".into()).spawn(crate::redact::warm_set);
        let _ = std::thread::Builder::new().name("aix-warm-text".into()).spawn(|| {
            crate::text::warm();
            crate::redact::warm_rest();
        });
    });
}

/// Parts the rule set is compiled in (one thread each): compile time falls about linearly with the part size, and
/// matching a line against a few parts costs about what one big set costs.
const PARTS: usize = 4;

/// Compile `pats` as `PARTS` contiguous slices of about equal pattern length, on scoped threads. Returns (index of
/// the slice's first pattern, compiled slice) in order. A panic in `build` propagates as it would unsplit.
pub(crate) fn split_compile<T: Send>(pats: &[&str], build: impl Fn(&[&str]) -> T + Sync) -> Vec<(usize, T)> {
    let total: usize = pats.iter().map(|p| p.len()).sum();
    let mut cuts = vec![0usize];
    let mut acc = 0usize;
    for (i, p) in pats.iter().enumerate() {
        acc += p.len();
        if cuts.len() < PARTS && acc * PARTS >= total * cuts.len() && i + 1 < pats.len() {
            cuts.push(i + 1);
        }
    }
    cuts.push(pats.len());
    cuts.dedup();
    let build = &build;
    std::thread::scope(|sc| {
        let hs: Vec<_> = cuts.windows(2).map(|w| (w[0], sc.spawn(move || build(&pats[w[0]..w[1]])))).collect();
        hs.into_iter().map(|(at, h)| (at, h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))).collect()
    })
}
