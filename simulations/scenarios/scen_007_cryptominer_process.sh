#!/usr/bin/env bash
# SCEN-007: Cryptominer Process Name
# Expected Detection: RUNTIME-007 (T1496, Resource Hijacking)
#
# This tests the detector's process-name rule only. No mining software is
# involved: the "miner" is an inert copy of busybox named xmrig in the pod's
# writable /tmp volume. Busybox does not know that applet name, prints an
# error and exits, so nothing is mined and no pool is contacted. The copy is
# removed afterwards.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-007] Executing an inert test executable named xmrig inside ${TARGET_POD}..."
require_target
step /bin/cp /bin/busybox /tmp/xmrig
# Non-zero exit is expected here (unknown applet); only the exec event matters.
kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /tmp/xmrig --version >/dev/null 2>&1
echo "    exit=$?  /tmp/xmrig --version (non-zero expected)"
step /bin/rm -f /tmp/xmrig
finish
