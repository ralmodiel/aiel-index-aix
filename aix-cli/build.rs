//! Stamps the git sha (short, `-dirty` when the tree has changes) into `aix --version`.
use std::process::Command;

fn main() {
    // Windows (MSVC): embed windows.manifest (long-path aware), so SQLite can open an index path over 260 characters
    let target = |k: &str| std::env::var(k).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") == "windows" && target("CARGO_CFG_TARGET_ENV") == "msvc" {
        let m = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", m.display());
        println!("cargo:rerun-if-changed=windows.manifest");
        // an 8 MB main-thread stack, as Linux gives (Windows reserves 1 MB): a debug build's clap parse of aix's
        // subcommands overflowed 1 MB
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    }
    // Only trust git when this crate's workspace IS the repo root: building from an exported copy that sits inside
    // another repo (e.g. a scratch dir) would otherwise stamp THAT repo's sha. AIX_GIT_SHA overrides.
    if let Ok(v) = std::env::var("AIX_GIT_SHA") {
        println!("cargo:rustc-env=AIX_GIT_SHA={v}");
        println!("cargo:rerun-if-env-changed=AIX_GIT_SHA");
        return;
    }
    let ws = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let top = Command::new("git").arg("-C").arg(&ws).args(["rev-parse", "--show-toplevel"]).output().ok()
        .filter(|o| o.status.success()).map(|o| std::path::PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
    let own = top.as_ref().and_then(|t| t.canonicalize().ok()) == ws.canonicalize().ok();
    let git = |args: &[&str]| if !own { None } else { Command::new("git").arg("-C").arg(&ws).args(args).output().ok().filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()) };
    let sha = git(&["rev-parse", "--short", "HEAD"]).filter(|s| !s.is_empty());
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    let v = match sha {
        Some(s) if dirty => format!("{s}-dirty"),
        Some(s) => s,
        None => "unknown".into(),
    };
    println!("cargo:rustc-env=AIX_GIT_SHA={v}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AIX_GIT_SHA");
}
