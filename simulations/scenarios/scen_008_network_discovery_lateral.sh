#!/usr/bin/env bash
# SCEN-008: Internal Service Discovery Connection
# Expected Detection: RUNTIME-006 (connect syscall to an in-cluster service)
# One TCP probe of the Kubernetes API service name. Connectivity is recorded
# separately from sensor observation.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/_common.sh"

echo "[SCEN-008] Probing kubernetes.default.svc.cluster.local:443 from ${TARGET_POD}..."
require_target
step /usr/bin/nc -z -w 1 kubernetes.default.svc.cluster.local 443
finish
