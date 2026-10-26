#!/usr/bin/env bash
# Installs a post-commit git hook in the given repo (default: current) that refreshes the aix index in
# the background after each commit. An existing post-commit hook is kept as post-commit.pre-aix and
# still runs first; re-running is a no-op. Respects core.hooksPath.
# Usage: integrations/claude-code/hooks/install-post-commit.sh [repo] [--db PATH]
set -euo pipefail
repo="${1:-$PWD}"; shift || true
command -v aix >/dev/null 2>&1 || { echo "aix not on PATH (cargo install --path aix-cli)" >&2; exit 1; }
cd "$repo" && exec aix --repo "$repo" "$@" install-git-hook
