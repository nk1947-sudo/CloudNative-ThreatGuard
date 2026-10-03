#!/usr/bin/env bash
# SCEN-002: Network Utility Execution
# Expected Detection: RUNTIME-002 (T1105, Ingress Tool Transfer)
# Runs wget against the pod's own loopback address; nothing leaves the pod.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-002] Executing wget against loopback inside ${TARGET_POD}..."
require_target
step /usr/bin/wget -q -T 1 -O /dev/null http://127.0.0.1:8080/healthz
finish
