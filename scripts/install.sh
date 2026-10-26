#!/usr/bin/env bash
# usage: scripts/install.sh            (from a clone of aiel-index; needs Rust: https://rustup.rs)
# Step 1 of 2. Installs into ~/.cargo/bin (or $CARGO_HOME/bin):
#   aix                          the binary (CLI + MCP server)
#   aix-init                     step 2, run once per repo: `cd your/repo && aix-init`
#   aix-refresh, aix-watch  the index updaters (locked/logged refresh; auto-refresh after edits go idle)
#   aix-hook-session-start, aix-hook-pretool, aix-hook-prompt   the Claude Code hooks aix-init registers
# and the Claude Code skill + slash commands into ~/.local/share/aix/claude-code (aix-init copies them).
# Files are copied, not linked, so the clone can be deleted afterwards. Re-run to upgrade.
# Each file is written to a temp name and renamed into place (a running aix or hook never sees a half-written
# binary). Every installed command is also symlinked into ~/.local/bin when that directory exists or is on PATH
# (Claude's Bash tool rarely has ~/.cargo/bin on PATH); a non-aix file already there is never overwritten.
# AIX_BINDIR overrides the install directory (default ${CARGO_HOME:-~/.cargo}/bin); AIX_NO_LINK=1 skips the ~/.local/bin links.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
command -v cargo >/dev/null 2>&1 || {
  echo "Rust is needed to build aix. Install it with:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
  exit 1
}
echo "building aix (the first build takes a few minutes)..."
bindir="${AIX_BINDIR:-${CARGO_HOME:-$HOME/.cargo}/bin}"
mkdir -p "$bindir"
stage="$(mktemp -d)"; trap 'rm -rf "$stage"' EXIT
cargo install --quiet --locked --path "$here/aix-cli" --root "$stage"
# atomic: copy to a temp name in the destination directory, then rename over the old file
inst() { local tmp="$bindir/.$2.new.$$"; install -m 755 "$1" "$tmp" && mv -f "$tmp" "$bindir/$2"; }
inst "$stage/bin/aix" aix
inst "$here/scripts/aix-refresh.sh" aix-refresh
inst "$here/scripts/aix-watch.sh" aix-watch
inst "$here/scripts/aix-init.sh" aix-init
inst "$here/integrations/claude-code/hooks/aix-session-start.sh" aix-hook-session-start
inst "$here/integrations/claude-code/hooks/aix-pretool-nudge.sh" aix-hook-pretool
inst "$here/integrations/claude-code/hooks/aix-prompt-submit.sh" aix-hook-prompt
data="${XDG_DATA_HOME:-$HOME/.local/share}"
share="$data/aix/claude-code"
# replace the share dir atomically: build the new tree beside it, swap with two renames (never a half-copied tree)
mkdir -p "$data/aix"
newshare="$data/aix/.claude-code.new.$$"; oldshare="$data/aix/.claude-code.old.$$"
rm -rf "$newshare" "$oldshare"; mkdir -p "$newshare"
cp -r "$here/integrations/claude-code/skills" "$here/integrations/claude-code/commands" "$here/integrations/claude-code/rules" "$newshare/"
[ -e "$share" ] && mv -T "$share" "$oldshare"
mv -T "$newshare" "$share"; rm -rf "$oldshare"
# where this was built from: an unknown-flag error in an older binary can say the clone has moved on
printf '%s\n' "$here" > "$(dirname "$share")/src-path"
echo "installed $("$bindir/aix" --version 2>/dev/null) into $bindir"
# PATH: link every installed command into ~/.local/bin (only where it exists or is already on PATH)
lb="$HOME/.local/bin"
if [ "${AIX_NO_LINK:-0}" != 1 ] && [ "$lb" != "$bindir" ] && { [ -d "$lb" ] || case ":$PATH:" in *":$lb:"*) true ;; *) false ;; esac; }; then
  mkdir -p "$lb"; linked=0
  for n in aix aix-init aix-refresh aix-watch aix-hook-session-start aix-hook-pretool aix-hook-prompt; do
    dest="$lb/$n"
    if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$bindir/$n" ]; then continue
    elif [ -L "$dest" ] && case "$(readlink "$dest")" in */.cargo/bin/"$n") true ;; *) false ;; esac; then ln -sfn "$bindir/$n" "$dest"; linked=1
    elif [ -e "$dest" ] || [ -L "$dest" ]; then echo "note: $dest exists and is not an aix link; left alone"
    else ln -s "$bindir/$n" "$dest"; linked=1
    fi
  done
  [ "$linked" = 1 ] && echo "linked the commands into $lb"
fi
case ":$PATH:" in *":$bindir:"*) ;; *) case ":$PATH:" in *":$lb:"*) ;; *) echo "note: add $bindir (or $lb) to your PATH" ;; esac ;; esac
echo "next: cd your/repo && aix-init"
