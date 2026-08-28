#!/usr/bin/env bash
# SCEN-004: Sensitive Credential & ServiceAccount Token Access
# Expected Detection: RUNTIME-004
# MITRE ATT&CK: T1552.007 (Unsecured Credentials: Container and Resource Discovery)
# Severity: CRITICAL

set -euo pipefail
export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-004] Simulating unauthorized sensitive file access (/var/run/secrets/.../token and /etc/shadow) inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || cat /etc/shadow 2>/dev/null || true"
else
    echo "[SCEN-004] Offline/local mode: executing simulated sensitive file read marker"
fi
