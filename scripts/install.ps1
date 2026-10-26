# usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1      (from a clone of aiel-index; needs Rust: https://rustup.rs)
# Windows counterpart of scripts/install.sh (Windows PowerShell 5.1 or pwsh 7). Step 1 of 2. Installs into
# %CARGO_HOME%\bin, by default %USERPROFILE%\.cargo\bin (AIX_BINDIR overrides):
#   aix.exe                            the binary (CLI + MCP server); `aix init`, `aix refresh`, `aix watch` and the
#                                      Claude Code hooks (`aix hook ...`) are subcommands, so nothing needs bash
#   aix-init, aix-refresh, aix-watch   the per-repo commands under their Linux names: .cmd shims for PowerShell and
#                                      cmd, extensionless sh shims for Git Bash; each runs `aix.exe <command>`
# and the Claude Code skill + slash commands + rules into %USERPROFILE%\.local\share\aix\claude-code (aix init copies
# them into a repo). Claude Code runs aix.exe directly from its hooks (exec form), so no hook scripts are installed.
# Re-run to upgrade: a running aix.exe (a watcher, an MCP server) is renamed aside, never overwritten in place.
# Next: cd your\repo; aix init
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

$cargo = (Get-Command cargo -ErrorAction SilentlyContinue).Source
if (-not $cargo) {
    # a rustup installed after this terminal opened is not on its PATH yet
    $c = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path $c) { $cargo = $c }
}
if (-not $cargo) {
    Write-Host 'Rust is needed to build aix: winget install Rustlang.Rustup (or https://rustup.rs), then open a new terminal and re-run this script.'
    exit 1
}

$bindir = $env:AIX_BINDIR
if (-not $bindir) {
    if ($env:CARGO_HOME) { $bindir = Join-Path $env:CARGO_HOME 'bin' } else { $bindir = Join-Path $env:USERPROFILE '.cargo\bin' }
}
New-Item -ItemType Directory -Force $bindir | Out-Null

Write-Host 'building aix (the first build takes a few minutes)...'
$stage = Join-Path ([IO.Path]::GetTempPath()) ("aix-install-" + [guid]::NewGuid().ToString('N'))
try {
    # the clone's own target dir: an earlier release build is reused
    & $cargo install --quiet --locked --path (Join-Path $here 'aix-cli') --root $stage --target-dir (Join-Path $here 'target')
    if ($LASTEXITCODE -ne 0) { Write-Host "cargo install failed (exit $LASTEXITCODE)"; exit 1 }

    # a running aix.exe cannot be overwritten, but it can be renamed: move it aside, put the new one in its place
    $exe = Join-Path $bindir 'aix.exe'
    $new = Join-Path $bindir '.aix.exe.new'
    Copy-Item -Force (Join-Path $stage 'bin\aix.exe') $new
    if (Test-Path $exe) { Move-Item -Force $exe (Join-Path $bindir (".aix.exe.old-" + [DateTime]::Now.Ticks)) }
    Move-Item -Force $new $exe
    Get-ChildItem -Force $bindir -Filter '.aix.exe.old-*' | ForEach-Object { try { Remove-Item -Force $_.FullName } catch { } }   # still running: next time
} finally {
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
}

# the per-repo commands under their Linux names; a file of that name that is not one of these shims is left alone
$utf8 = New-Object Text.UTF8Encoding $false
foreach ($n in 'init', 'refresh', 'watch') {
    $shims = @(
        @{ Path = (Join-Path $bindir "aix-$n.cmd"); Text = "@`"%~dp0aix.exe`" $n %*`r`n" },
        @{ Path = (Join-Path $bindir "aix-$n"); Text = "#!/bin/sh`nexec `"`$(dirname `"`$0`")/aix.exe`" $n `"`$@`"`n" }
    )
    foreach ($s in $shims) {
        if ((Test-Path $s.Path) -and -not ((Get-Content -Raw $s.Path) -like '*aix.exe*')) {
            Write-Host "note: $($s.Path) exists and is not an aix shim; left alone"
            continue
        }
        [IO.File]::WriteAllText($s.Path, $s.Text, $utf8)
    }
}

# the skill, commands and rules aix init copies; replaced as a whole (built beside the old one, then swapped)
$home_ = $env:HOME
if (-not $home_) { $home_ = $env:USERPROFILE }   # where aix looks: $HOME, else %USERPROFILE%
$data = $env:XDG_DATA_HOME
if (-not $data) { $data = Join-Path $home_ '.local\share' }
$aixdata = Join-Path $data 'aix'
$share = Join-Path $aixdata 'claude-code'
$newshare = Join-Path $aixdata ".claude-code.new.$PID"
$oldshare = Join-Path $aixdata ".claude-code.old.$PID"
New-Item -ItemType Directory -Force $newshare | Out-Null
foreach ($d in 'skills', 'commands', 'rules') { Copy-Item -Recurse (Join-Path $here "integrations\claude-code\$d") $newshare }
if (Test-Path $share) { Move-Item $share $oldshare }
Move-Item $newshare $share
if (Test-Path $oldshare) { Remove-Item -Recurse -Force $oldshare }
# where this was built from: an unknown-flag error in an older binary can say the clone has moved on
[IO.File]::WriteAllText((Join-Path $aixdata 'src-path'), "$here`n", $utf8)

Write-Host "installed $(& $exe --version) into $bindir"
Write-Host "  + aix-init, aix-refresh, aix-watch (shims for aix init / refresh / watch); skill files in $share"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ }
$onUser = $userPath | Where-Object { $_.TrimEnd('\') -ieq $bindir.TrimEnd('\') }
$onNow = ($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $bindir.TrimEnd('\') }
if (-not $onUser -and -not $onNow) {
    Write-Host "note: add $bindir to your PATH (Settings > System > About > Advanced system settings > Environment Variables), then open a new terminal"
} elseif (-not $onNow) {
    Write-Host "note: open a new terminal (and restart Claude Code) so $bindir is on their PATH"
}
Write-Host 'next: cd your\repo; aix init'
