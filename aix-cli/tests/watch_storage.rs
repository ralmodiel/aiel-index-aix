// aix-watch picks its timings from the repo's storage: detected from findmnt + sysfs (faked here), then corrected by
// what refreshes actually cost; `aix stats` shows the class it picked. Unix only: findmnt, sysfs and a bash script.
#![cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/aix-watch.sh")
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git").arg("-C").arg(repo).args(args).env("GIT_AUTHOR_NAME", "t").env("GIT_AUTHOR_EMAIL", "t@example.com").env("GIT_COMMITTER_NAME", "t").env("GIT_COMMITTER_EMAIL", "t@example.com").status().unwrap().success();
    assert!(ok, "git {args:?}");
}

fn write_exe(p: &Path, body: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Env {
    d: tempfile::TempDir,
    repo: PathBuf,
    sys: PathBuf,
    bin: PathBuf,
}

fn env() -> Env {
    let d = tempfile::tempdir().unwrap();
    let (repo, sys, bin) = (d.path().join("proj"), d.path().join("sys"), d.path().join("bin"));
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("main.py"), "def load(x):\n    return x\n").unwrap();
    std::fs::write(repo.join(".gitignore"), ".aix/\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    // findmnt answers from FAKE_MNT ("SOURCE FSTYPE")
    write_exe(&bin.join("findmnt"), "#!/bin/sh\necho \"$FAKE_MNT\"\n");
    Env { d, repo, sys, bin }
}

impl Env {
    /// A block device in the fake sysfs: `/sys/class/block/<name>` links to its device directory; a partition lives
    /// inside its disk's directory and has a `partition` file.
    fn disk(&self, name: &str, devpath: &str, rotational: bool) {
        let dev = self.sys.join("devices").join(devpath).join(name);
        std::fs::create_dir_all(dev.join("queue")).unwrap();
        std::fs::write(dev.join("queue/rotational"), if rotational { "1\n" } else { "0\n" }).unwrap();
        std::fs::create_dir_all(self.sys.join("class/block")).unwrap();
        std::fs::create_dir_all(self.sys.join("block")).unwrap();
        std::os::unix::fs::symlink(&dev, self.sys.join("class/block").join(name)).unwrap();
        std::os::unix::fs::symlink(&dev, self.sys.join("block").join(name)).unwrap();
    }
    fn part(&self, disk: &str, part: &str) {
        let dev = std::fs::read_link(self.sys.join("class/block").join(disk)).unwrap().join(part);
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("partition"), "1\n").unwrap();
        std::os::unix::fs::symlink(&dev, self.sys.join("class/block").join(part)).unwrap();
    }
    fn slave(&self, top: &str, under: &str) {
        let s = self.sys.join("block").join(top).join("slaves");
        std::fs::create_dir_all(&s).unwrap();
        std::os::unix::fs::symlink(self.sys.join("class/block").join(under), s.join(under)).unwrap();
    }
    fn path(&self) -> String {
        format!("{}:{}:{}", self.bin.display(), Path::new(env!("CARGO_BIN_EXE_aix")).parent().unwrap().display(), std::env::var("PATH").unwrap())
    }
    fn check(&self, mnt: &str) -> String {
        let o = Command::new("bash").arg(script()).arg(&self.repo).arg("--storage-check").env("FAKE_MNT", mnt).env("AIX_SYSFS", &self.sys).env("PATH", self.path()).env("AIX_LOCK_DIR", self.d.path().join("locks")).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }
}

#[test]
fn storage_class_is_detected_from_the_mount_and_the_disk_under_it() {
    let e = env();
    e.disk("nvme0n1", "pci/nvme/nvme0", false);
    e.part("nvme0n1", "nvme0n1p2");
    e.disk("sda", "pci/ata1/host0/target0/0:0:0:0/block", true);
    e.part("sda", "sda1");
    e.disk("sdb", "pci/usb2/2-1/host1/target1/1:0:0:0/block", false);
    e.part("sdb", "sdb1");
    e.disk("sdc", "pci/ata2/host2/target2/2:0:0:0/block", false);
    e.disk("mmcblk0", "platform/mmc0/mmc0:0001/block", false);
    e.part("mmcblk0", "mmcblk0p1");
    e.disk("dm-0", "virtual/block", false);
    e.slave("dm-0", "sda1");
    e.disk("dm-1", "virtual/block", false);
    e.slave("dm-1", "nvme0n1p2");
    let cases = [
        ("/dev/nvme0n1p2 ext4", "fast NVMe disk nvme0n1 (ext4)"),
        ("/dev/sda1 ext4", "slow rotational disk sda (ext4)"),
        ("/dev/sdb1 exfat", "slow USB disk sdb (exfat)"),
        ("/dev/sdc xfs", "fast solid-state disk sdc (xfs)"),
        ("/dev/mmcblk0p1 ext4", "slow SD/eMMC card mmcblk0 (ext4)"),
        ("/dev/dm-0 ext4", "slow rotational disk sda (ext4)"),
        ("/dev/dm-1 btrfs", "fast NVMe disk nvme0n1 (btrfs)"),
        ("server:/export nfs4", "slow network/shared filesystem (nfs4)"),
        ("C:\\ 9p", "slow network/shared filesystem (9p)"),
        ("user@host:/src fuse.sshfs", "slow network/shared filesystem (fuse.sshfs)"),
        ("overlay overlay", "fast overlay on overlay"),
        ("/dev/vdz ext4", "fast no sysfs entry for vdz (ext4)"),
        ("", "fast filesystem unknown"),
    ];
    for (mnt, want) in cases {
        assert_eq!(e.check(mnt), want, "mount {mnt:?}");
    }
}

#[test]
fn bad_storage_value_is_a_usage_error() {
    let e = env();
    let o = Command::new("bash").arg(script()).arg(&e.repo).args(["--storage", "ssd"]).env("PATH", e.path()).env("AIX_LOCK_DIR", e.d.path().join("locks")).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--storage takes auto, fast or slow"));
}

/// Runs a watcher whose aix-refresh is a fake that reports the update time read from `upd_ms` and counts its runs.
struct Watcher {
    child: std::process::Child,
    count: PathBuf,
    upd: PathBuf,
    storage: PathBuf,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn watcher(e: &Env, mnt: &str, extra: &[&str], upd_ms: u32) -> Watcher {
    let (count, upd) = (e.d.path().join("refreshes"), e.d.path().join("upd_ms"));
    std::fs::write(&upd, upd_ms.to_string()).unwrap();
    write_exe(
        &e.bin.join("aix-refresh"),
        &format!("#!/bin/sh\necho x >> '{}'\nms=$(cat '{}')\necho \"2026-01-01 00:00:00 rc=0 ${{ms}}ms update rc=0 ${{ms}}ms: done\"\n", count.display(), upd.display()),
    );
    let db = e.repo.join(".aix/index.db");
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let child = Command::new("bash")
        .arg(script())
        .arg(&e.repo)
        .args(["--idle", "0.2", "--poll", "0.2", "--backlog", "0"])
        .args(extra)
        .env("FAKE_MNT", mnt)
        .env("AIX_SYSFS", &e.sys)
        .env("PATH", e.path())
        .env("AIX_LOCK_DIR", e.d.path().join("locks"))
        .env("AIX_EMBED_URL", "")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Watcher { child, count, upd, storage: e.repo.join(".aix/index.db.watch.storage") }
}

impl Watcher {
    fn runs(&self) -> usize {
        std::fs::read_to_string(&self.count).map(|t| t.lines().count()).unwrap_or(0)
    }
    fn storage(&self) -> String {
        std::fs::read_to_string(&self.storage).unwrap_or_default()
    }
    fn wait_for(&self, what: &str, f: impl Fn(&Watcher) -> bool) {
        let t0 = Instant::now();
        while !f(self) {
            assert!(t0.elapsed() < Duration::from_secs(60), "timed out waiting for {what}; storage file: {:?}", self.storage());
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    /// One edit, then wait until the watcher refreshed for it. Every edit has the same size and they come faster
    /// than one per second, so only the full-precision mtime in the change signature tells them apart.
    fn edit_and_refresh(&self, e: &Env, n: usize) {
        let before = self.runs();
        std::fs::write(e.repo.join("main.py"), format!("def load(x):\n    return x + {}\n", n % 10)).unwrap();
        self.wait_for("a refresh after an edit", |w| w.runs() > before);
    }
}

#[test]
fn measured_refresh_cost_switches_the_class_both_ways() {
    let e = env();
    e.disk("nvme0n1", "pci/nvme/nvme0", false);
    let w = watcher(&e, "/dev/nvme0n1 ext4", &[], 2000);
    w.wait_for("the class file", |w| !w.storage().is_empty());
    assert!(w.storage().contains(" fast NVMe disk nvme0n1 (ext4)"), "{}", w.storage());
    for n in 0..6 {
        w.edit_and_refresh(&e, n);
    }
    w.wait_for("the switch to slow", |w| w.storage().contains(" slow measured: median update 2000 ms"));
    std::fs::write(&w.upd, "100").unwrap();
    for n in 10..18 {
        w.edit_and_refresh(&e, n);
    }
    w.wait_for("the switch back to fast", |w| w.storage().contains(" fast measured: median update 100 ms"));
}

#[test]
fn a_fixed_class_is_never_switched_by_measurement() {
    let e = env();
    e.disk("sda", "pci/ata1/block", true);
    let w = watcher(&e, "/dev/sda ext4", &["--storage", "fast"], 3000);
    w.wait_for("the class file", |w| !w.storage().is_empty());
    for n in 0..6 {
        w.edit_and_refresh(&e, n);
    }
    let s = w.storage();
    assert!(s.contains(" fast set by --storage"), "{s}");
}

#[test]
fn stats_shows_the_watcher_class() {
    let e = env();
    let db = e.repo.join(".aix/index.db");
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let aix = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_aix")).arg("--repo").arg(&e.repo).arg("--db").arg(&db).args(args).env("AIX_EMBED_URL", "").env("HOME", e.d.path()).env("AIX_LOCK_DIR", e.d.path().join("locks")).output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    assert!(!aix(&["stats"]).contains("watcher timing"), "no line without a watcher");
    std::fs::write(e.repo.join(".aix/index.db.watch.storage"), "2026-01-02 03:04:05 slow rotational disk sda (ext4)\n").unwrap();
    let s = aix(&["stats"]);
    assert!(s.contains("  watcher timing: slow storage (rotational disk sda (ext4)), since 2026-01-02 03:04:05"), "{s}");
}

#[test]
fn same_size_edits_within_one_second_are_both_seen() {
    let e = env();
    e.disk("nvme0n1", "pci/nvme/nvme0", false);
    let w = watcher(&e, "/dev/nvme0n1 ext4", &[], 50);
    w.wait_for("the class file", |w| !w.storage().is_empty());
    let f = e.repo.join("main.py");
    let base = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let edit = |text: &str, ms: u64| {
        std::fs::write(&f, text).unwrap();
        std::fs::File::options().write(true).open(&f).unwrap().set_modified(base + Duration::from_millis(ms)).unwrap();
    };
    let before = w.runs();
    edit("def load(x):\n    return x + 1\n", 100);
    w.wait_for("a refresh after the first edit", |w| w.runs() > before);
    // same size, same whole second: only the sub-second part of the mtime differs
    let before = w.runs();
    edit("def load(x):\n    return x + 2\n", 900);
    w.wait_for("a refresh after the second edit", |w| w.runs() > before);
}
