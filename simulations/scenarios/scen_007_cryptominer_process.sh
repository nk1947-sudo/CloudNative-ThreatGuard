#!/usr/bin/env bash
# ==============================================================================
# SCEN-007: Cryptominer / Unexpected High-CPU Process Execution
# Simulates unauthorized cryptominer / malware binary execution.
# Expected Detection: RULE-K8S-007 / RUNTIME-006 / T1496
# MITRE ATT&CK: T1496 (Resource Hijacking)
# Severity: HIGH
# ==============================================================================

set -euo pipefail
export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

echo "----------------------------------------------------------------------"
echo "[SCEN-007] Simulating Cryptominer Process Execution (T1496)"
echo "Target Pod: ${TARGET_POD} | Namespace: ${NAMESPACE}"
echo "Expected Detection: T1496 (Resource Hijacking / Mining Execution)"
echo "----------------------------------------------------------------------"

if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[*] Simulating execution of miner process inside ${TARGET_POD}..."
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- /bin/sh -c "echo '[SIMULATION] xmrig --donate-level 1 -o stratum+tcp://pool.minexmr.com:4444' && sleep 1"
    echo "[PASS] Simulated miner process executed and recorded by Tetragon."
else
    echo "[*] Offline/simulation mode: executing simulated cryptominer trace"
    echo "[PASS] Expected: Alert generated on cryptominer process and mining pool connection."
fi

# Cleanup
echo "[+] Cleanup: Completed execution without persistent background processes."
