#!/usr/bin/env bash
# SCEN-002: Ingress/Egress Network Utility Execution
# Expected Detection: RUNTIME-002
# MITRE ATT&CK: T1105 (Ingress Tool Transfer)
# Severity: HIGH

set -euo pipefail
export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-002] Simulating suspicious network ingress utility execution (wget/nc) inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "which wget >/dev/null 2>&1 && wget -qO- --timeout=1 http://127.0.0.1:8080/healthz || nc -z -w 1 127.0.0.1 8080 || true"
else
    echo "[SCEN-002] Offline/local mode: executing simulated network utility marker"
fi
