#!/usr/bin/env bash
# SCEN-B01: Benign Control
# Expected Detection: none. Measures false alerts: an ordinary command that no
# rule should flag. It only counts as a pass if the sensor saw the command and
# the detector stayed silent.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-B01] Executing a benign echo inside ${TARGET_POD}..."
require_target
step /bin/echo benign-control
finish
