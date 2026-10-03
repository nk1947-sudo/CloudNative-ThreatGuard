#!/usr/bin/env bash
# SCEN-006: Outbound Network Connection
# Expected Detection: RUNTIME-006 (connect syscall)
# A single TCP probe with a 1 second timeout. Whether the connection succeeds
# or is refused by the NetworkPolicy is a separate question (see
# scripts/test-network-policy.sh); this scenario tests the sensor only.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-006] Probing 1.1.1.1:443 from ${TARGET_POD}..."
require_target
step /usr/bin/nc -z -w 1 1.1.1.1 443
finish
