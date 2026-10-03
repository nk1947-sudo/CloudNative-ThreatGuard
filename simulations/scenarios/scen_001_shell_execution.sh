#!/usr/bin/env bash
# SCEN-001: Interactive Shell Execution
# Expected Detection: RUNTIME-001 (T1059.004, Unix Shell)
# Expected Enforcement: the shell-execution TracingPolicy kills the process (exit 137).
# This is the only scenario that invokes a shell, because it tests the shell block.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-001] Executing a shell inside ${TARGET_POD} (policy is expected to kill it)..."
require_target
step /bin/sh -c "true"
finish
