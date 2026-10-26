//! Meaning-based code search (`ask --kind code`), `text` with live values, and opt-in script folders.
//! Generic fixtures in a temp git repo; no embedder (keyword fallback is what is asserted).

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
}

fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("shop");
    for (p, t) in files {
        let f = r.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-q", "-m", "Initial shop"]);
    (d, r)
}

fn sk_env(repo: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aix"));
    c.arg("--repo").arg(repo).args(args).env("AIX_EMBED_URL", "").env("HOME", repo);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    assert!(out.status.code().is_some_and(|c| c <= 1), "aix {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn sk(repo: &Path, args: &[&str]) -> String {
    sk_env(repo, args, &[])
}

const PRICING: &str = r#"package shop;
public class PricingService {
    /** Round a price to whole cents using banker's rounding. */
    public long roundPrice(double raw) {
        long cents = Math.round(raw * 100);
        if (cents < 0) {
            cents = 0;
        }
        return cents;
    }
    /** Apply a percentage discount to an order total, never below zero. */
    public double applyDiscount(double total, double percent) {
        double off = total * percent / 100.0;
        if (off > total) {
            off = total;
        }
        return total - off;
    }
}
"#;
const SHIPPING: &str = r#"package shop;
public class ShippingService {
    /** Decide whether two parcels would be loaded on the same truck slot at the same time. */
    public boolean slotsClash(int startA, int endA, int startB, int endB) {
        boolean overlap = startA < endB && startB < endA;
        if (overlap) {
            return true;
        }
        return false;
    }
}
"#;
const UTIL_TS: &str = r#"export function formatInvoiceNumber(prefix: string, seq: number): string {
  const padded = String(seq).padStart(6, '0');
  const out = prefix + '-' + padded;
  return out.toUpperCase();
}
"#;

#[test]
fn ask_kind_code_returns_chunks_and_follows_edits() {
    let (_d, r) = repo(&[
        ("src/main/java/shop/PricingService.java", PRICING),
        ("src/main/java/shop/ShippingService.java", SHIPPING),
        ("web/util.ts", UTIL_TS),
    ]);
    sk(&r, &["update", "--full"]);
    // the flag may come after the question
    let o = sk(&r, &["ask", "where is the discount applied to an order total", "--kind", "code"]);
    let first = o.lines().find(|l| l.starts_with("[code]")).unwrap_or_else(|| panic!("no code row: {o}"));
    assert!(first.contains("PricingService.java:") && first.contains("PricingService.applyDiscount"), "{o}");
    assert!(o.contains("FTS-only") || o.contains("semantic layer unavailable"), "must say it fell back: {o}");
    let o = sk(&r, &["ask", "--kind", "code", "which parcels clash on the same truck slot"]);
    assert!(o.lines().find(|l| l.starts_with("[code]")).unwrap().contains("ShippingService.slotsClash"), "{o}");
    // row format: file:start-end Class.method
    let re = regex_lite(&o);
    assert!(re, "{o}");
    // plain `ask` (no kind) never returns code rows
    let o = sk(&r, &["ask", "discount order total"]);
    assert!(!o.contains("[code]"), "{o}");
    // an edit is picked up incrementally: the new method is found, the removed one is gone
    let edited = PRICING.replace("applyDiscount", "applyVoucher").replace("Apply a percentage discount", "Apply a voucher");
    std::fs::write(r.join("src/main/java/shop/PricingService.java"), edited).unwrap();
    let o = sk(&r, &["ask", "--kind", "code", "voucher applied to an order total"]);
    assert!(o.contains("PricingService.applyVoucher") && !o.contains("PricingService.applyDiscount"), "{o}");
}

fn regex_lite(o: &str) -> bool {
    o.lines().filter(|l| l.starts_with("[code] ")).all(|l| {
        let rest = &l["[code] ".len()..];
        let loc = rest.split(' ').next().unwrap_or("");
        let (_, range) = loc.rsplit_once(':').unwrap_or(("", ""));
        let (a, b) = range.split_once('-').unwrap_or(("", ""));
        a.parse::<u32>().is_ok() && b.parse::<u32>().is_ok()
    })
}

const RECEIVABLES: &str = r#"import React from 'react';
export function Receivables({ leavers }: { leavers: { count: number; total: number } }) {
  return (
    <div>
      <p>Nobody owes fees for this year.</p>
      <p className="note">Not listed: {leavers.count} learner{leavers.count === 1 ? '' : 's'} who left this year still {leavers.count === 1 ? 'has' : 'have'} {peso(leavers.total)} unpaid.</p>
      <p>Last payment on {fmtDate(leavers.last)} at {fmtTime(leavers.last)}</p>
      <p>Unpaid balances appear here.</p>
    </div>
  );
}
"#;

#[test]
fn text_treats_live_values_as_wildcards() {
    let (_d, r) = repo(&[("web/Receivables.tsx", RECEIVABLES)]);
    sk(&r, &["update", "--full"]);
    for q in [
        "Not listed: 4 learners who left this year still have ₱2,177.01 unpaid",
        "Not listed: 1 learner who left this year still has ₱310.00 unpaid.",
        "Not listed: 12 learners who left this year still have PHP 1,000 unpaid",
    ] {
        let o = sk(&r, &["text", q]);
        let first = o.lines().find(|l| l.contains("Receivables.tsx:")).unwrap_or_else(|| panic!("{q}: {o}"));
        assert!(first.contains("Receivables.tsx:6 "), "{q}: {o}");
    }
    // dates and times
    let o = sk(&r, &["text", "Last payment on 2026-03-14 at 9:30 AM"]);
    assert!(o.lines().find(|l| l.contains("Receivables.tsx:")).unwrap().contains("Receivables.tsx:7 "), "{o}");
    let o = sk(&r, &["text", "Last payment on Mar 14, 2026 at 14:05"]);
    assert!(o.contains("Receivables.tsx:7 "), "{o}");
    // an exact (value-free) string still ranks first and the line with values is not invented for other text
    let o = sk(&r, &["text", "Nobody owes fees for this year."]);
    assert!(o.lines().find(|l| l.contains("Receivables.tsx:")).unwrap().contains("Receivables.tsx:5 "), "{o}");
    let o = sk(&r, &["text", "Refund of 15 items was declined"]);
    assert!(!o.contains("Receivables.tsx:6"), "{o}");
}

#[test]
fn script_dirs_are_listed_not_indexed_and_filtered() {
    let (_d, r) = repo(&[("src/a.ts", "export const a = 1;\n"), ("scripts/in-repo.sh", "#!/bin/sh\n# In-repo helper.\necho hi\n")]);
    let ext = tempfile::tempdir().unwrap();
    let t = ext.path().join("tools");
    std::fs::create_dir_all(t.join(".hidden-dir")).unwrap();
    std::fs::write(t.join("rotate-keys.sh"), "#!/bin/sh\n# Usage: rotate-keys.sh <env>  rotate the signing keys\ntoken=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD\necho x\n").unwrap();
    std::fs::write(t.join("tidy.py"), "#!/usr/bin/env python3\n\"\"\"Tidy the downloads folder.\"\"\"\nprint(1)\n").unwrap();
    std::fs::write(t.join(".dotscript.sh"), "#!/bin/sh\n# Usage: dot\n").unwrap();
    std::fs::write(t.join("credentials.sh"), "#!/bin/sh\n# Usage: credentials loader\n").unwrap();
    std::fs::write(t.join("notes.txt"), "just notes about tidy\n").unwrap();
    std::fs::write(t.join("blob.bin"), b"\x00\x01\x02tidy").unwrap();
    let td = t.to_string_lossy().to_string();
    // not configured: nothing outside the repo
    let o = sk_env(&r, &["script", "rotate"], &[]);
    assert!(!o.contains("rotate-keys"), "{o}");
    // via the environment
    let o = sk_env(&r, &["script", "rotate"], &[("AIX_SCRIPT_DIRS", &td)]);
    assert!(o.contains("rotate-keys.sh") && o.contains("[outside repo]") && o.contains("rotate the signing keys"), "{o}");
    assert!(!o.contains("ghp_"), "usage lines are redacted: {o}");
    let o = sk_env(&r, &["script", "tidy"], &[("AIX_SCRIPT_DIRS", &td)]);
    assert!(o.contains("tidy.py") && o.contains("Tidy the downloads folder"), "{o}");
    assert!(!o.contains("notes.txt") && !o.contains("blob.bin"), "{o}");
    let o = sk_env(&r, &["script", "loader"], &[("AIX_SCRIPT_DIRS", &td)]);
    assert!(!o.contains("credentials") && !o.contains(".dotscript"), "{o}");
    // via .aix/config.toml; the in-repo script is still found
    std::fs::create_dir_all(r.join(".aix")).unwrap();
    // a TOML basic string: a Windows path's backslashes are escaped
    std::fs::write(r.join(".aix/config.toml"), format!("script_dirs = [\"{}\"]\n", td.replace('\\', "\\\\"))).unwrap();
    let o = sk(&r, &["script", "helper"]);
    assert!(o.contains("scripts/in-repo.sh"), "{o}");
    let o = sk(&r, &["script", "rotate"]);
    assert!(o.contains("rotate-keys.sh"), "{o}");
    // never indexed for grep/text/find
    let o = sk(&r, &["grep", "rotate-keys|signing keys"]);
    assert!(!o.contains("rotate-keys"), "{o}");
    let o = sk(&r, &["find", "signing keys"]);
    assert!(!o.contains("rotate-keys"), "{o}");
    // a folder under a hidden folder of HOME is refused, a visible one under it is listed
    let home = ext.path().join("home");
    let hid = home.join(".secret-tools");
    std::fs::create_dir_all(&hid).unwrap();
    std::fs::write(hid.join("x.sh"), "#!/bin/sh\n# Usage: hidden thing\n").unwrap();
    let vis = home.join("bin2");
    std::fs::create_dir_all(&vis).unwrap();
    std::fs::write(vis.join("y.sh"), "#!/bin/sh\n# Usage: visible thing\n").unwrap();
    let h = home.to_string_lossy().to_string();
    let dirs = std::env::join_paths([&hid, &vis]).unwrap().to_string_lossy().to_string();
    let o = sk_env(&r, &["script", "thing"], &[("AIX_SCRIPT_DIRS", &dirs), ("HOME", &h)]);
    assert!(o.contains("y.sh") && !o.contains("x.sh"), "{o}");
}
