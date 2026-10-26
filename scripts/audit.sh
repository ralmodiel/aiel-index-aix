#!/usr/bin/env bash
# usage: scripts/audit.sh     Supply-chain checks on the locked dependency tree: cargo-deny (licenses, bans,
# sources, advisories per deny.toml) and cargo-audit (RustSec advisories), whichever is installed. Nothing is
# installed or downloaded by this script; install them yourself (`cargo install --locked cargo-deny cargo-audit`).
# The advisory databases are fetched by those tools; with no network use `--offline` on cargo-deny
# (`scripts/audit.sh --offline` passes it on) against an existing database.
# Exit: 0 clean, 1 findings, 2 neither tool installed.
set -uo pipefail
cd "$(dirname "$0")/.."
rc=0; ran=0
if cargo deny --version >/dev/null 2>&1; then
  ran=1
  echo "== cargo deny check"
  if [ "${1:-}" = "--offline" ]; then cargo deny --offline check || rc=1; else cargo deny check || rc=1; fi
else
  echo "cargo-deny is not installed (cargo install --locked cargo-deny): skipped"
fi
if cargo audit --version >/dev/null 2>&1; then
  ran=1
  echo "== cargo audit"
  cargo audit --deny warnings || rc=1
else
  echo "cargo-audit is not installed (cargo install --locked cargo-audit): skipped"
fi
echo "== dependency count (normal, default features / without mcp): $(cargo tree --locked --offline -p aix-cli -e normal --prefix none 2>/dev/null | sort -u | wc -l) / $(cargo tree --locked --offline -p aix-cli --no-default-features -e normal --prefix none 2>/dev/null | sort -u | wc -l)"
[ "$ran" = 1 ] || exit 2
exit $rc
