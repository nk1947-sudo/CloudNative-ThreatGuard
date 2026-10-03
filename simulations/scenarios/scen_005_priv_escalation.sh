#!/usr/bin/env bash
# SCEN-005: Privilege Escalation Tooling
# Expected Detection: RUNTIME-005 (T1068)
# Runs nsenter's help output only; no namespace is entered.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-005] Executing nsenter --help inside ${TARGET_POD}..."
require_target
step /usr/bin/nsenter --help
finish
