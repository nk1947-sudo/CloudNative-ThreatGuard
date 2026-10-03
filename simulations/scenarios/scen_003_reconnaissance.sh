#!/usr/bin/env bash
# SCEN-003: Reconnaissance Binaries
# Expected Detection: RUNTIME-003 (T1082, System Information Discovery)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-003] Executing id, whoami and uname inside ${TARGET_POD}..."
require_target
step /usr/bin/id
step /usr/bin/whoami
step /bin/uname -a
finish
