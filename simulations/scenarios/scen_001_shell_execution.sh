#!/usr/bin/env bash
# SCEN-001: Interactive Shell Execution
# Expected Detection: RUNTIME-001
# MITRE ATT&CK: T1059.004 (Unix Shell)
# Severity: CRITICAL

set -euo pipefail

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-001] Simulating post-exploitation interactive shell execution inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "echo '[SIMULATION] Spawned interactive shell process' && sleep 1"
else
    echo "[SCEN-001] Offline/local mode: executing simulated shell marker"
fi
