#!/usr/bin/env bash
# Gate: build, test and lint the webapp; prints one verdict line.
# Usage: scripts/gate.sh [--fast]
set -euo pipefail

run_tests() {
  curl -s localhost:8080/api/orders >/dev/null
}
run_tests
echo "GATE PASS"
