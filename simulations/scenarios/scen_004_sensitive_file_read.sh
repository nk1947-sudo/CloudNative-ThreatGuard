#!/usr/bin/env bash
# SCEN-004: Sensitive File Access
# Expected Detection: RUNTIME-004 (T1552.007, Container API credential access)
# Opens /etc/shadow, which a non-root user cannot read. The open attempt is what
# the sensor observes; no credential content is read or printed, and the target
# pod does not need a mounted ServiceAccount token for this test.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-004] Attempting to open /etc/shadow inside ${TARGET_POD}..."
require_target
step /bin/cat /etc/shadow
finish
