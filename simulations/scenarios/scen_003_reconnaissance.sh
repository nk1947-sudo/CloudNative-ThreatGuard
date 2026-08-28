#!/usr/bin/env bash
# SCEN-003: System Information Discovery / Reconnaissance
# Expected Detection: RUNTIME-003
# MITRE ATT&CK: T1082 (System Information Discovery)
# Severity: MEDIUM

set -euo pipefail
export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-003] Simulating post-exploitation reconnaissance commands (id, whoami, uname) inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "whoami; id; uname -a; env || true"
else
    echo "[SCEN-003] Offline/local mode: executing simulated reconnaissance marker"
fi
