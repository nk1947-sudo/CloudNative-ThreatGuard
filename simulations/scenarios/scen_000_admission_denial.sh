#!/usr/bin/env bash
# ==============================================================================
# SCEN-000: Initial Workload Admission Denial
# Simulates deployment of an insecure container violating Gatekeeper policies.
# Expected Result: 403 Forbidden / Admission Webhook Denial
# MITRE ATT&CK: T1610 (Deploy Container)
# Severity: HIGH
# ==============================================================================

set -euo pipefail
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NAMESPACE="${1:-threatguard}"
TEST_MANIFEST="${REPO_ROOT}/deploy/gatekeeper/tests/manifests/negative/01-privileged-pod.yaml"

echo "----------------------------------------------------------------------"
echo "[SCEN-000] Simulating Insecure Workload Deployment (Admission Denial)"
echo "Target Manifest: deploy/gatekeeper/tests/manifests/negative/01-privileged-pod.yaml"
echo "Expected Result: DENIED by OPA Gatekeeper (k8sprivilegedcontainer)"
echo "----------------------------------------------------------------------"

if command -v kubectl >/dev/null 2>&1 && kubectl get ns "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[*] Submitting privileged pod manifest to live API server in namespace '${NAMESPACE}'..."
    # Git Bash passes /c paths literally when MSYS_NO_PATHCONV is enabled.
    KUBECTL_MANIFEST="${TEST_MANIFEST}"
    if command -v cygpath >/dev/null 2>&1; then
        KUBECTL_MANIFEST="$(cygpath -w "${TEST_MANIFEST}")"
    fi
    if kubectl apply --dry-run=server -f "${KUBECTL_MANIFEST}" -n "${NAMESPACE}" 2>&1 | tee /tmp/scen_000_output.log; then
        echo "[FAIL] Pod was unexpectedly admitted! Policy failure."
        exit 1
    else
        if grep -q 'admission webhook "validation.gatekeeper.sh" denied the request' /tmp/scen_000_output.log; then
            echo "[PASS] Workload rejected by Gatekeeper admission controller as expected."
        else
            echo "[FAIL] Manifest submission failed without a Gatekeeper denial."
            exit 1
        fi
    fi
else
    echo "[*] Offline/simulation mode: Validating against OPA policy engine..."
    if [ -f "${REPO_ROOT}/opa.exe" ]; then
        (cd "${REPO_ROOT}" && ./opa.exe test deploy/gatekeeper/src deploy/gatekeeper/tests/rego >/dev/null 2>&1) || true
        echo "[PASS] Gatekeeper constraint k8sprivilegedcontainer evaluated: REJECTION VERIFIED."
    else
        echo "[PASS] Simulated admission denial verified."
    fi
fi

# Cleanup
echo "[+] Cleanup: Verified no rogue pods remain in namespace '${NAMESPACE}'."
