//! Platform calls, one portable function per concern: local time, priority, process liveness and detached children,
//! owner-only files, file identity and modification time, the lock directory. Unix keeps its exact calls; Windows gets
//! the nearest native equivalent, or a no-op where the concept does not exist (POSIX modes, uid ownership). File locks
//! need nothing here: `std::fs::File::try_lock` is flock(2) on Linux and LockFileEx on Windows.

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;

// ---- local time ---------------------------------------------------------------------------------------------------

/// `epoch` in the local time zone: (offset east of UTC in seconds, [month 1-12, day, hour, minute, second]).
#[cfg(unix)]
pub fn local_time(epoch: i64) -> Option<(i64, [i32; 5])> {
    // SAFETY: localtime_r only writes the zeroed `tm` it is given
    unsafe {
        let t: libc::time_t = epoch as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        Some((tm.tm_gmtoff as i64, [tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec]))
    }
}

#[cfg(windows)]
pub fn local_time(epoch: i64) -> Option<(i64, [i32; 5])> {
    // the C runtime's struct tm: sec, min, hour, mday, mon, year, wday, yday, isdst (no tm_gmtoff)
    #[repr(C)]
    struct Tm([i32; 9]);
    extern "C" {
        fn _localtime64_s(tm: *mut Tm, t: *const i64) -> i32;
        fn _mkgmtime64(tm: *mut Tm) -> i64;
    }
    let mut tm = Tm([0; 9]);
    // SAFETY: both read `epoch` and the `tm` they are given and write only that `tm`
    if unsafe { _localtime64_s(&mut tm, &epoch) } != 0 {
        return None;
    }
    let [sec, min, hour, mday, mon, ..] = tm.0;
    // the local wall clock read as UTC, minus the instant, is the offset
    let utc = unsafe { _mkgmtime64(&mut tm) };
    Some((if utc == -1 { 0 } else { utc - epoch }, [mon + 1, mday, hour, min, sec]))
}

// ---- priority -----------------------------------------------------------------------------------------------------

/// Lower the calling thread's CPU priority by `n` nice steps (Linux applies nice(2) per thread). Windows: below normal.
pub fn nice(n: i32) {
    #[cfg(unix)]
    // SAFETY: nice(2) has no memory effects
    unsafe {
        libc::nice(n);
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL};
        let _ = n;
        // SAFETY: the current-thread pseudo handle needs no closing
        unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL) };
    }
}

/// Lower CPU and IO priority of this process (best effort). Windows: the below-normal priority class.
pub fn be_nice() {
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
        // ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13) = best effort: class BE, level 7
        #[cfg(target_os = "linux")]
        libc::syscall(libc::SYS_ioprio_set, 1, 0, (2 << 13) | 7);
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS};
        // SAFETY: the current-process pseudo handle needs no closing
        unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
    }
}

/// Memory the system can hand out without swapping, in MB: MemAvailable of /proc/meminfo; Windows: the available
/// physical memory (GlobalMemoryStatusEx). None when unknown.
pub fn mem_available_mb() -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        // SAFETY: an all-zero MEMORYSTATUSEX with dwLength set is what the call expects; it only writes `m`
        let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (unsafe { GlobalMemoryStatusEx(&mut m) } != 0).then_some(m.ullAvailPhys / (1024 * 1024))
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("MemAvailable:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()))
            .map(|kb| kb / 1024)
    }
}

// ---- processes ----------------------------------------------------------------------------------------------------

/// Is process `pid` running? (Unix: kill(pid, 0), EPERM counts as alive. Windows: it has no exit code yet; access
/// denied counts as alive.)
#[cfg(unix)]
pub fn pid_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 || *libc::__errno_location() == libc::EPERM }
}

#[cfg(windows)]
pub fn pid_alive(pid: i64) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let Ok(pid) = u32::try_from(pid) else { return false };
    if pid == 0 {
        return false;
    }
    // SAFETY: the handle is checked before use and closed once
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let mut code = 0u32;
        let alive = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(h);
        alive
    }
}

/// When process `pid` started, to tell it from a later process that reused the pid: Linux field 22 of
/// /proc/PID/stat (clock ticks since boot, what aix-watch.sh records in its pidfile); Windows the creation time
/// (FILETIME). None when unknown (other Unixes, or the process is gone).
pub fn proc_start(pid: i64) -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        let pid = u32::try_from(pid).ok().filter(|p| *p != 0)?;
        // SAFETY: the handle is checked before use and closed once; GetProcessTimes only writes the four FILETIMEs
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut c, mut e, mut k, mut u) = (z, z, z, z);
            let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0;
            CloseHandle(h);
            ok.then(|| (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
        }
    }
    #[cfg(not(windows))]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(") ")?.1.split_whitespace().nth(19)?.parse().ok()
    }
}

/// File name of process `pid`'s executable (`aix`, `aix.exe`): Linux /proc/PID/exe; Windows the process image.
pub fn proc_exe_name(pid: i64) -> Option<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
        let pid = u32::try_from(pid).ok().filter(|p| *p != 0)?;
        let mut buf = vec![0u16; 1024];
        let mut n = buf.len() as u32;
        // SAFETY: the handle is checked before use and closed once; the call writes at most `n` UTF-16 units into `buf`
        let ok = unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) != 0;
            CloseHandle(h);
            ok
        };
        let full = String::from_utf16_lossy(&buf[..n as usize]);
        ok.then(|| full.rsplit(['\\', '/']).next().unwrap_or_default().to_string())
    }
    #[cfg(not(windows))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()?.file_name().map(|n| n.to_string_lossy().into_owned())
    }
}

/// Ask process `pid` to stop: SIGTERM; Windows: TerminateProcess (no handler runs there). False when it could not.
pub fn terminate(pid: i64) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        let Some(pid) = u32::try_from(pid).ok().filter(|p| *p != 0) else { return false };
        // SAFETY: the handle is checked before use and closed once
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if h.is_null() {
                return false;
            }
            let ok = TerminateProcess(h, 1) != 0;
            CloseHandle(h);
            ok
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: kill(2) has no memory effects
        pid > 0 && unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) == 0 }
    }
}

/// Is the filesystem holding `p` slow (network/shared, removable)? `(slow, reason)`; unknown counts as fast.
/// Windows: the drive type. Linux: the type of the longest mount point above `p` (/proc/self/mounts).
// ponytail: no rotational/USB/SD detection (aix-watch.sh reads sysfs for that); the watcher's measured switch covers it
pub fn storage_class(p: &Path) -> (bool, String) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        let root: Vec<u16> = match p.components().next() {
            Some(std::path::Component::Prefix(px)) => px.as_os_str().encode_wide().chain("\\".encode_utf16()).chain([0]).collect(),
            _ => return (false, "drive unknown".into()),
        };
        // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call
        match unsafe { GetDriveTypeW(root.as_ptr()) } {
            // DRIVE_REMOTE, DRIVE_REMOVABLE (Win32::System::WindowsProgramming)
            4 => (true, "network drive".into()),
            2 => (true, "removable drive".into()),
            _ => (false, "local drive".into()),
        }
    }
    #[cfg(not(windows))]
    {
        let Ok(m) = std::fs::read_to_string("/proc/self/mounts") else { return (false, "filesystem unknown".into()) };
        let c = canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let best = m.lines().filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, at, fs) = (f.next()?, f.next()?, f.next()?);
            let at = at.replace("\\040", " ");
            c.starts_with(&at).then(|| (at.len(), fs.to_string()))
        });
        match best.max_by_key(|b| b.0) {
            // aix-watch.sh's list
            Some((_, fs)) if fs.starts_with("nfs") || fs.starts_with("smb")
                || ["cifs", "9p", "drvfs", "virtiofs", "vboxsf", "afs", "ceph", "glusterfs", "davfs", "fuse.sshfs", "fuse.rclone", "fuse.s3fs", "fuse.gcsfuse", "fuse.vmhgfs-fuse", "fuse.drvfs"]
                    .contains(&fs.as_str()) =>
            {
                (true, format!("network/shared filesystem ({fs})"))
            }
            Some((_, fs)) => (false, fs),
            None => (false, "filesystem unknown".into()),
        }
    }
}

/// Start `c` detached in its own session (setsid), so it outlives the hook or shell that started it. Windows: no
/// console window and its own process group (a child is not killed when its parent exits).
pub fn detach(c: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid(2) only changes this child's session between fork and exec
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        no_window(c, 0);
        std_no_inherit();
    }
}

/// Windows: a background child must not hold the caller's pipes open (a hook's stdout, or `$(aix ...)`'s, would not
/// end before it exits). CreateProcess hands the child every inheritable handle, so this process's std handles stop
/// being inheritable; `Stdio::inherit` duplicates them for a child that wants them.
#[cfg(windows)]
fn std_no_inherit() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    for h in [std::io::stdin().as_raw_handle(), std::io::stdout().as_raw_handle(), std::io::stderr().as_raw_handle()] {
        // SAFETY: changes only the inherit flag of this process's own std handles; a null or invalid one just fails
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0) };
    }
}

/// Start `c` in the background; `low`: its own process group, niced by 10 (otherwise unchanged: a first build someone
/// waits for). Windows: always no console window and its own process group, below-normal priority when `low`.
pub fn background(c: &mut Command, low: bool) {
    #[cfg(unix)]
    if low {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
        // SAFETY: nice(2) only lowers this child's own priority between fork and exec
        unsafe {
            c.pre_exec(|| {
                libc::nice(10);
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        no_window(c, if low { windows_sys::Win32::System::Threading::BELOW_NORMAL_PRIORITY_CLASS } else { 0 });
        std_no_inherit();
    }
}

/// Start `c` in its own process group, so `kill_tree` can stop it with everything it started. Windows: no console
/// window either.
pub fn own_group(c: &mut Command) {
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(c, 0);
    #[cfg(windows)]
    no_window(c, 0);
}

/// Stop `ch` and the processes it started (it was started with `own_group`): SIGTERM to its group, then the child
/// itself. Windows: `taskkill /T /F` (the tree).
pub fn kill_tree(ch: &mut std::process::Child) {
    use std::process::Stdio;
    #[cfg(unix)]
    let _ = Command::new("kill").arg("-TERM").arg(format!("-{}", ch.id())).stdout(Stdio::null()).stderr(Stdio::null()).status();
    #[cfg(windows)]
    let _ = Command::new("taskkill").args(["/T", "/F", "/PID"]).arg(ch.id().to_string()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    let _ = ch.kill();
}

/// A POSIX `sh` for a pipeline of read-only commands, and a folder holding its text tools (grep, head, sort) to put
/// on PATH. Unix: `sh`. Windows: Git for Windows' `bin\sh.exe` (the folder of CLAUDE_CODE_GIT_BASH_PATH, else next to
/// `git.exe` on PATH, else the default install), with its `usr\bin`; None without Git for Windows.
pub fn posix_sh() -> Option<(PathBuf, Option<PathBuf>)> {
    #[cfg(not(windows))]
    {
        Some((PathBuf::from("sh"), None))
    }
    #[cfg(windows)]
    {
        let mut roots: Vec<PathBuf> = vec![];
        if let Some(b) = std::env::var_os("CLAUDE_CODE_GIT_BASH_PATH").map(PathBuf::from) {
            roots.extend(b.ancestors().skip(1).take(3).map(Path::to_path_buf));
        }
        if let Some(p) = std::env::var_os("PATH") {
            for d in std::env::split_paths(&p).filter(|d| d.join("git.exe").is_file()) {
                roots.extend(d.ancestors().skip(1).take(2).map(Path::to_path_buf));
            }
        }
        roots.extend([r"C:\Program Files\Git", r"C:\Program Files (x86)\Git"].map(PathBuf::from));
        roots.into_iter().find(|r| r.join(r"bin\sh.exe").is_file()).map(|r| (r.join(r"bin\sh.exe"), Some(r.join(r"usr\bin"))))
    }
}

/// The program's arguments as typed. Windows, run from Git Bash (MSYSTEM set): a word that started with `/` (a route,
/// a sed `/re/p`, `--in=/x`) arrives as `C:/Program Files/Git/...`, MSYS's root; it is given back with its `/`.
// ponytail: a `F:/re/` word that MSYS read as a path list (`a\F;C:\Program Files\Git\re\`) stays as it came
pub fn args() -> Vec<String> {
    #[allow(unused_mut)]
    let mut a: Vec<String> = std::env::args().collect();
    #[cfg(windows)]
    if std::env::var_os("MSYSTEM").is_some() && a.iter().skip(1).any(|w| w.contains(":/")) {
        let exe = std::env::var_os("EXEPATH").map(PathBuf::from).filter(|e| e.ends_with("bin"));
        let root = exe.and_then(|e| e.parent().map(Path::to_path_buf)).or_else(|| posix_sh().and_then(|(sh, _)| Some(sh.parent()?.parent()?.to_path_buf())));
        if let Some(r) = root {
            let r = format!("{}/", slash(&r).trim_end_matches('/'));
            let at = |w: &str, i: usize| w.get(i..i + r.len()).is_some_and(|x| x.eq_ignore_ascii_case(&r));
            for w in a.iter_mut().skip(1) {
                let i = if at(w, 0) { Some(0) } else { w.find('=').map(|i| i + 1).filter(|&i| at(w, i)) };
                if let Some(i) = i {
                    *w = format!("{}/{}", &w[..i], &w[i + r.len()..]);
                }
            }
        }
    }
    a
}

/// A console child started from a hook would flash a window of its own without CREATE_NO_WINDOW.
#[cfg(windows)]
fn no_window(c: &mut Command, flags: u32) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
    c.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | flags);
}

// ---- owner-only files ---------------------------------------------------------------------------------------------

/// Create files owner-only (mode 0600). Windows has no POSIX modes: the file inherits its directory's ACL (owner-only
/// for .aix, see `owner_only_dir`).
pub fn private_file(o: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(o, 0o600);
    o
}

/// Create directories owner-only (mode 0700); Windows: the inherited ACL, as for `private_file`.
pub fn private_dir(b: &mut DirBuilder) -> &mut DirBuilder {
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(b, 0o700);
    b
}

/// Make directory `p` this user's alone, as mode 0700 does. Windows: an entry giving the user full control, inherited
/// by everything created in it, then the entries it inherits from its folder dropped (`icacls`; a drive like F:\
/// lets Authenticated Users read and change what is under it). Nothing changes when the user cannot be named.
pub fn owner_only_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        chmod(p, 0o700)
    }
    #[cfg(windows)]
    {
        let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
            (Ok(d), Ok(u)) if !d.is_empty() => format!(r"{d}\{u}"),
            (_, Ok(u)) => u,
            _ => return Err(std::io::Error::other("USERNAME is not set")),
        };
        let icacls = |args: &[&str]| {
            let mut c = Command::new("icacls");
            no_window(&mut c, 0);
            c.arg(p).args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
        };
        // the grant first: dropping the inherited entries of a directory nobody is granted would lock everyone out
        if icacls(&["/grant:r", &format!("{user}:(OI)(CI)F"), "/q"]) && icacls(&["/inheritance:r", "/q"]) {
            Ok(())
        } else {
            Err(std::io::Error::other("icacls failed"))
        }
    }
}

/// Windows: does directory `p` still take access entries from its folder (other users of the machine may read it)?
/// Read from `icacls`, whose `(I)` marks an inherited entry in every language. Unix: false (modes are checked).
pub fn inherits_acl(p: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut c = Command::new("icacls");
        no_window(&mut c, 0);
        c.arg(p).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output().is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("(I)"))
    }
    #[cfg(not(windows))]
    {
        let _ = p;
        false
    }
}

/// chmod. Windows: a no-op that succeeds.
pub fn chmod(p: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (p, mode);
        Ok(())
    }
}

/// The permission bits; None on Windows (no modes to check).
pub fn mode(md: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(std::os::unix::fs::MetadataExt::mode(md))
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// Is the file owned by the current user? Windows: always true.
// ponytail: no owner check on Windows; compare the owner SID (GetSecurityInfo) if a shared-machine threat model needs it
pub fn owned_by_me(md: &Metadata) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::uid(md) == unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        true
    }
}

/// The current user's id for per-user names (temp dirs); 0 on Windows, whose temp dir is already per user.
pub fn uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Default directory for the shared lock files: /tmp/aix-locks-<uid>; Windows: aix-locks in the user's temp dir.
pub fn lock_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(format!("/tmp/aix-locks-{}", uid()))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("aix-locks")
    }
}

/// Open for reading without following a symlink in the last component (O_NOFOLLOW; `nonblock` adds O_NONBLOCK so a
/// FIFO swapped in cannot block the open). Windows: the reparse point itself is opened, so a link swapped in reads as a
/// link and the caller's is_file check refuses it.
pub fn open_nofollow(p: &Path, nonblock: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | if nonblock { libc::O_NONBLOCK } else { 0 });
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let _ = nonblock;
        o.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    o.open(p)
}

// ---- paths --------------------------------------------------------------------------------------------------------

/// The user's home: `$HOME`, else `%USERPROFILE%` on Windows (shared with aix-extract's global masks); and the
/// UTF-8 byte-order mark Windows PowerShell puts in front of text it pipes in, dropped from stdin.
pub use aix_extract::{home, skip_stdin_bom, strip_stdin_bom, strip_stdin_bom_bytes};

/// `std::fs::canonicalize`. Windows: without the `\\?\` verbatim prefix it adds (`\\?\C:\x` is `C:\x`, `\\?\UNC\h\s`
/// is `\\h\s`), so a canonical path compares and prints like the paths git, Claude Code and users spell.
// ponytail: no reserved-name (CON, NUL) check before dropping the prefix; std re-adds \\?\ itself for long paths
pub fn canonicalize(p: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let c = std::fs::canonicalize(p)?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let base = match c.components().next() {
            Some(Component::Prefix(x)) => match x.kind() {
                Prefix::VerbatimDisk(d) => Some(format!("{}:", d as char)),
                Prefix::VerbatimUNC(host, share) => Some(format!(r"\\{}\{}", host.to_string_lossy(), share.to_string_lossy())),
                _ => None,
            },
            _ => None,
        };
        if let Some(b) = base {
            let mut parts = c.components();
            parts.next();
            return Ok(PathBuf::from(b).join(parts.as_path()));
        }
    }
    Ok(c)
}

/// A repo-relative path as the index spells it: `/` separators (Windows `strip_prefix` leaves `\`).
pub fn slash(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) { s.replace('\\', "/") } else { s.into_owned() }
}

/// Is the file at `p` open in another process? Windows cannot delete such a file (and zeroing it would corrupt it
/// under that process); Unix unlinks it anyway, so there this is always false.
pub fn in_use(p: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // 32 = ERROR_SHARING_VIOLATION: another handle does not share the file
        matches!(OpenOptions::new().read(true).share_mode(0).open(p), Err(e) if e.raw_os_error() == Some(32))
    }
    #[cfg(not(windows))]
    {
        let _ = p;
        false
    }
}

/// Do `a` and `b` name one path as the file system compares names? Windows ignores case (git may track `app.py`
/// that sits on disk as `App.py`, and `readme.md` opens `README.md`); Unix does not.
pub fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) { slash(a).to_lowercase() == slash(b).to_lowercase() } else { a == b }
}

/// `s` ('/'-separated) without the repo root it starts with, or None. Unix: `<repo>/` exactly. Windows: any spelling
/// of the root (`C:/r`, `c:/r`, Git Bash `/c/r`, `//?/C:/r`), case-insensitive.
pub fn strip_root<'a>(s: &'a str, repo: &Path) -> Option<&'a str> {
    let root = repo.display().to_string();
    if !cfg!(windows) {
        return s.strip_prefix(&format!("{root}/"));
    }
    // one spelling, `C:/x`: `\` -> `/`, no `//?/`, Git Bash `/c/x` -> `c:/x` (same length, so the part after the root
    // is the same bytes in `s`)
    let key = |p: &str| -> String {
        let p = p.replace('\\', "/");
        let p = p.strip_prefix("//?/").map(str::to_string).unwrap_or(p);
        match p.as_bytes() {
            [b'/', d, b'/', ..] if d.is_ascii_alphabetic() => format!("{}:{}", *d as char, &p[2..]),
            _ => p,
        }
    };
    let (k, r) = (key(s), key(&root));
    let r = r.trim_end_matches('/');
    let n = r.len();
    let under = k.len() > n && k.is_char_boundary(n) && k[..n].eq_ignore_ascii_case(r) && k.as_bytes()[n] == b'/';
    under.then(|| &s[s.len() - (k.len() - n - 1)..])
}

/// Windows: the absolute paths inside `repo` in a command argument (`C:\r\src\a.rs`, `C:/r/src`, Git Bash `/c/r/src`,
/// `\\?\C:\r\src`; any case, either separator) as repo-relative `/` paths (`src/a.rs`). None when there are none, and
/// always elsewhere: there the caller's `<repo>/` replacement covers it.
pub fn repo_rel_args(arg: &str, repo: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        // built once per repo: every argv word of every command (and of each in-call pipe stage) comes through here
        static RE: std::sync::Mutex<Option<(PathBuf, regex::Regex)>> = std::sync::Mutex::new(None);
        let re = {
            let mut g = RE.lock().ok()?;
            if g.as_ref().is_none_or(|(r, _)| r != repo) {
                let s = repo.display().to_string().replace('\\', "/");
                let parts: Vec<&str> = s.split('/').filter(|x| !x.is_empty()).collect();
                let (head, rest) = parts.split_first()?;
                let head = match head.strip_suffix(':') {
                    Some(d) => format!("(?:{0}:|/{0})", regex::escape(d)),
                    None => format!(r"[\\/]{{2}}{}", regex::escape(head)), // a UNC host
                };
                let tail: String = rest.iter().map(|p| format!(r"[\\/]{}", regex::escape(p))).collect();
                *g = Some((repo.to_path_buf(), regex::Regex::new(&format!(r#"(?i)(?:\\\\\?\\|//\?/)?{head}{tail}[\\/]([^\s"']*)"#)).ok()?));
            }
            g.as_ref()?.1.clone()
        };
        if re.is_match(arg) {
            return Some(re.replace_all(arg, |c: &regex::Captures| c[1].replace('\\', "/")).into_owned());
        }
        // one word naming the same folder another way (a subst drive, a junction, an 8.3 name): what it resolves to
        let (p, suf) = match arg.rsplit_once(':') {
            Some((p, s)) if p.len() > 2 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-') => (p, &arg[p.len()..]),
            _ => (arg, ""),
        };
        if !p.contains(char::is_whitespace) && Path::new(p).is_absolute() {
            if let Some(r) = canonicalize(p).ok().and_then(|c| strip_root(&slash(&c), repo).map(str::to_string)) {
                return Some(format!("{r}{suf}"));
            }
        }
    }
    let _ = (arg, repo);
    None
}

// ---- file identity and times --------------------------------------------------------------------------------------

/// (device, inode) of the file at `p` that `md` was read from: what tells a rotated log (a new file at the same path)
/// from the same file grown. Windows: (volume serial, file index), from `p` opened for attributes only; (0, 0) when it
/// cannot be opened.
pub fn file_id(p: &Path, md: &Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        let _ = p;
        (std::os::unix::fs::MetadataExt::dev(md), std::os::unix::fs::MetadataExt::ino(md))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        let _ = md;
        match OpenOptions::new().access_mode(0).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(p) {
            Ok(f) => handle_id(&f),
            Err(_) => (0, 0),
        }
    }
}

/// `file_id` of an open file (`md` = its metadata): the file being read, even if the path now names another.
pub fn open_file_id(f: &File, md: &Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        let _ = f;
        (std::os::unix::fs::MetadataExt::dev(md), std::os::unix::fs::MetadataExt::ino(md))
    }
    #[cfg(windows)]
    {
        let _ = md;
        handle_id(f)
    }
}

/// std's `MetadataExt::file_index` is still unstable (windows_by_handle), so ask the handle directly.
#[cfg(windows)]
fn handle_id(f: &File) -> (u64, u64) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is valid; the call only writes it
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
        return (0, 0);
    }
    (i.dwVolumeSerialNumber as u64, (i.nFileIndexHigh as u64) << 32 | i.nFileIndexLow as u64)
}

/// Modification time, whole seconds since the epoch.
pub fn mtime(md: &Metadata) -> i64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::mtime(md)
    }
    #[cfg(not(unix))]
    {
        since_epoch(md).0
    }
}

/// The nanoseconds within the second of the modification time.
pub fn mtime_nsec(md: &Metadata) -> i64 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::mtime_nsec(md)
    }
    #[cfg(not(unix))]
    {
        since_epoch(md).1
    }
}

#[cfg(not(unix))]
fn since_epoch(md: &Metadata) -> (i64, i64) {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or((0, 0), |d| (d.as_secs() as i64, d.subsec_nanos() as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_time_is_sane() {
        let (off, [mo, d, h, mi, s]) = local_time(1_700_000_000).expect("local time");
        assert!(off.abs() <= 14 * 3600 && off % 900 == 0, "offset {off}");
        assert!((1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 61);
        // 2023-11-14 22:13:20 UTC: the local wall clock minus the offset is that time of day
        assert_eq!((((h * 60 + mi) * 60 + s) as i64 - off).rem_euclid(86_400), (22 * 60 + 13) * 60 + 20);
    }

    #[test]
    fn pid_alive_sees_itself_not_a_dead_child() {
        assert!(pid_alive(std::process::id() as i64));
        assert!(!pid_alive(0) && !pid_alive(-1));
        let mut c = if cfg!(windows) { Command::new("cmd") } else { Command::new("true") };
        if cfg!(windows) {
            c.args(["/c", "exit"]);
        }
        let mut ch = c.spawn().expect("spawn");
        let pid = ch.id() as i64;
        ch.wait().expect("wait");
        assert!(!pid_alive(pid), "reaped child {pid} still alive");
    }

    #[test]
    fn file_id_survives_rename_and_differs_between_files() {
        let d = tempfile::tempdir().unwrap();
        let (a, b, c) = (d.path().join("a.log"), d.path().join("b.log"), d.path().join("a.log.1"));
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "x").unwrap();
        let id = |p: &Path| file_id(p, &std::fs::metadata(p).unwrap());
        let ida = id(&a);
        assert_ne!(ida, (0, 0));
        assert_ne!(ida, id(&b));
        let f = File::open(&a).unwrap();
        assert_eq!(open_file_id(&f, &f.metadata().unwrap()), ida);
        drop(f);
        std::fs::rename(&a, &c).unwrap();
        assert_eq!(id(&c), ida, "a rename keeps the identity (a rotated log is recognised)");
        std::fs::write(&a, "new").unwrap();
        assert_ne!(id(&a), ida, "a new file at the old path is a new identity");
    }

    #[test]
    fn canonicalize_prints_like_the_paths_users_spell() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let c = canonicalize(d.path().join("sub").join("..").join("sub")).unwrap();
        assert!(c.is_absolute() && c.ends_with("sub") && !c.to_string_lossy().starts_with(r"\\?\"), "{c:?}");
        assert_eq!(canonicalize(&c).unwrap(), c, "idempotent");
        let a = format!("outline {} x", c.join("a.rs").display());
        if cfg!(windows) {
            let s = c.display().to_string();
            for spelled in [s.clone(), s.replace('\\', "/"), format!("/{}{}", s[..1].to_lowercase(), s[2..].replace('\\', "/")), format!(r"\\?\{}", s.to_uppercase())] {
                assert_eq!(repo_rel_args(&format!("outline {spelled}\\src\\a.rs x"), &c).as_deref(), Some("outline src/a.rs x"), "{spelled}");
            }
            assert_eq!(repo_rel_args("grep x src", &c), None);
        } else {
            assert_eq!(repo_rel_args(&a, &c), None);
        }
    }

    #[test]
    fn strip_root_takes_every_spelling_of_the_root() {
        let d = tempfile::tempdir().unwrap();
        let repo = canonicalize(d.path()).unwrap();
        let s = repo.display().to_string().replace('\\', "/");
        assert_eq!(strip_root(&format!("{s}/src/a.rs"), &repo), Some("src/a.rs"));
        assert_eq!(strip_root("src/a.rs", &repo), None);
        assert_eq!(strip_root(&format!("{s}x/src/a.rs"), &repo), None, "a sibling with the root as its prefix");
        if cfg!(windows) {
            let bash = format!("/{}{}", s[..1].to_lowercase(), &s[2..]);
            for sp in [s.to_lowercase(), bash, format!("//?/{s}"), s.replace('/', "\\")] {
                assert_eq!(strip_root(&format!("{sp}/src/a.rs"), &repo), Some("src/a.rs"), "{sp}");
            }
            assert_eq!(slash(Path::new(r"src\a.rs")), "src/a.rs");
        }
    }

    #[test]
    fn mem_available_is_known_on_linux_and_windows() {
        if cfg!(any(target_os = "linux", windows)) {
            assert!(mem_available_mb().is_some_and(|m| m > 0));
        }
    }

    #[test]
    fn try_lock_excludes_a_second_handle() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.lock");
        let a = private_file(OpenOptions::new().create(true).truncate(false).write(true)).open(&p).unwrap();
        a.try_lock().unwrap();
        let b = OpenOptions::new().read(true).open(&p).unwrap();
        assert!(b.try_lock().is_err());
        drop(a);
        b.try_lock().unwrap();
    }
}
