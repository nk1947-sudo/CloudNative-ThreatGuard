#!/usr/bin/env bash
# SCEN-006: Outbound Network Connection Simulation
# Expected Detection: RUNTIME-006
# MITRE ATT&CK: T1071 (Application Layer Protocol)
# Severity: HIGH

set -euo pipefail
export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "[SCEN-006] Simulating outbound network connection attempt inside ${TARGET_POD}..."
if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    # Attempt connection to documentation site / external IP (will be captured by eBPF connect kprobe and restricted by NetworkPolicy)
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "nc -z -w 1 1.1.1.1 443 2>/dev/null || true"
else
    echo "[SCEN-006] Offline/local mode: executing simulated outbound network connection marker"
fi
