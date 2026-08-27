#!/usr/bin/env bash
# SCEN-005: Container Privilege Escalation Indicator
# Expected Detection: RUNTIME-005
# MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
# Severity: CRITICAL

set -euo pipefail

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-005] Simulating privilege escalation indicator (capsh / nsenter / unshare) inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "which capsh >/dev/null 2>&1 && capsh --print || nsenter --help 2>/dev/null || true"
else
    echo "[SCEN-005] Offline/local mode: executing simulated privilege escalation marker"
fi
