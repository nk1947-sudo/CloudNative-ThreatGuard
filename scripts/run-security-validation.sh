#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Automated Security Test Harness
# Executes the 11-step verification of pre-deployment admission and
# post-deployment runtime eBPF detection.
#
# Usage: run-security-validation.sh [--mode live|demo]
#
#   live (default)  Requires a reachable cluster with Gatekeeper and Tetragon.
#                   Any missing prerequisite is reported BLOCKED, never as a
#                   pass.
#   demo            Explicitly simulated: OPA-only admission evaluation and the
#                   fixture trace. A demo run can pass its own checks but is
#                   always labelled SIMULATED and is never live acceptance.
#
# Every step records PASS, FAIL, BLOCKED or SKIPPED. The harness keeps going
# after a failing step where later steps are independent, prints the full
# table, and exits 0 only if no step failed or was blocked.
#   exit 0 all steps passed | 1 at least one step failed | 2 blocked
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# common.sh enables errexit; this script handles each exit code itself.
set +e

MODE="${THREATGUARD_MODE:-live}"
if [ "${1:-}" = "--mode" ]; then
    MODE="${2:-live}"
fi
case "${MODE}" in
    live | demo) ;;
    *)
        echo "Unknown mode '${MODE}' (use live or demo)" >&2
        exit 2
        ;;
esac

cd "${REPO_ROOT}"
export THREATGUARD_MODE="${MODE}"
export THREATGUARD_RUN_ID="${THREATGUARD_RUN_ID:-$(python -c 'import uuid; print(uuid.uuid4().hex[:12])')}"

STEP_NAMES=()
STEP_STATUS=()
STEP_DETAIL=()
HAS_FAIL=0
HAS_BLOCKED=0

# record <name> <PASS|FAIL|BLOCKED|SKIPPED> <detail>
record() {
    STEP_NAMES+=("$1")
    STEP_STATUS+=("$2")
    STEP_DETAIL+=("$3")
    case "$2" in
        PASS) log_success "$1: $3" ;;
        SKIPPED) log_info "$1: SKIPPED - $3" ;;
        BLOCKED) HAS_BLOCKED=1; log_error "$1: BLOCKED - $3" ;;
        *) HAS_FAIL=1; log_error "$1: FAIL - $3" ;;
    esac
}

# record_rc <name> <rc> <pass detail> <fail detail>: maps exit codes 0/2/other.
record_rc() {
    case "$2" in
        0) record "$1" PASS "$3" ;;
        2) record "$1" BLOCKED "$4" ;;
        *) record "$1" FAIL "$4" ;;
    esac
}

finish() {
    echo ""
    echo "======================================================================"
    echo " VALIDATION SUMMARY  (mode: ${MODE}, run: ${THREATGUARD_RUN_ID})"
    echo "======================================================================"
    local i
    for i in "${!STEP_NAMES[@]}"; do
        printf ' %-8s %-44s %s\n' "${STEP_STATUS[$i]}" "${STEP_NAMES[$i]}" "${STEP_DETAIL[$i]}"
    done
    echo "----------------------------------------------------------------------"
    if [ "${HAS_FAIL}" -eq 1 ]; then
        log_error "RESULT: FAILED - at least one required step failed."
        exit 1
    elif [ "${HAS_BLOCKED}" -eq 1 ]; then
        log_error "RESULT: BLOCKED - prerequisites were missing; the validation is incomplete."
        exit 2
    elif [ "${MODE}" = "demo" ]; then
        log_warn "RESULT: DEMO PASSED - simulated evidence only. This is NOT live acceptance."
        exit 0
    else
        log_success "RESULT: LIVE VALIDATION PASSED - every step passed against real evidence."
        exit 0
    fi
}

echo "======================================================================"
echo "    CloudNative ThreatGuard — End-to-End Security Validation Pipeline"
echo "    mode: ${MODE}"
echo "======================================================================"

have_cluster() { command -v kubectl >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1; }

# Step 1: Cluster health
log_step "Step 1/11: Cluster Health Check"
if [ "${MODE}" = "demo" ]; then
    record "1 cluster health" SKIPPED "demo mode does not use a cluster"
elif have_cluster; then
    record "1 cluster health" PASS "cluster reachable"
else
    record "1 cluster health" BLOCKED "no reachable Kubernetes cluster (kubectl missing or API unreachable)"
    finish
fi

# Step 2: Gatekeeper health
log_step "Step 2/11: Gatekeeper Health Check"
if [ "${MODE}" = "demo" ]; then
    record "2 gatekeeper health" SKIPPED "demo mode evaluates policies through OPA only"
elif kubectl get crd constrainttemplates.templates.gatekeeper.sh >/dev/null 2>&1 \
    && kubectl rollout status deployment/gatekeeper-controller-manager -n gatekeeper-system --timeout=30s >/dev/null 2>&1; then
    record "2 gatekeeper health" PASS "CRDs present and controller rolled out"
else
    record "2 gatekeeper health" BLOCKED "Gatekeeper CRDs or controller not ready"
    finish
fi

# Step 3: Rego unit tests. OPA is required; its absence is never a pass.
log_step "Step 3/11: Static Policy Validation (Rego Unit Tests)"
OPA_BIN=""
if command -v opa >/dev/null 2>&1; then
    OPA_BIN="opa"
elif [ -f "${REPO_ROOT}/opa.exe" ]; then
    OPA_BIN="${REPO_ROOT}/opa.exe"
fi
if [ -z "${OPA_BIN}" ]; then
    record "3 rego unit tests" BLOCKED "OPA binary not found (install opa or place opa.exe at the repo root)"
else
    opa_out="$("${OPA_BIN}" test "${REPO_ROOT}/deploy/gatekeeper/src" "${REPO_ROOT}/deploy/gatekeeper/tests/rego" 2>&1)"
    opa_rc=$?
    echo "${opa_out}"
    summary="$(echo "${opa_out}" | grep -E '^(PASS|FAIL|ERROR)' | tail -1)"
    if [ "${opa_rc}" -eq 0 ]; then
        record "3 rego unit tests" PASS "${summary:-opa test passed}"
    else
        record "3 rego unit tests" FAIL "${summary:-opa test failed (exit ${opa_rc})}"
    fi
fi

# Step 4: Admission tests
log_step "Step 4/11: Admission Enforcement Tests (Negative and Positive Workloads)"
if [ "${MODE}" = "demo" ]; then
    bash "${SCRIPT_DIR}/test-admission-policies.sh" --mode offline
    rc=$?
    record_rc "4 admission tests (offline OPA)" "${rc}" "OPA evaluation matched expectations" "admission evaluation did not match (exit ${rc})"
else
    bash "${SCRIPT_DIR}/test-admission-policies.sh" --mode live
    rc=$?
    record_rc "4 admission tests (live webhook)" "${rc}" "all denials came from the Gatekeeper webhook; compliant manifest admitted" "see admission results (exit ${rc})"
fi

# Step 5: Secure workload deployment
log_step "Step 5/11: Secure Workload Deployment"
if [ "${MODE}" = "demo" ]; then
    record "5 secure workload deployment" SKIPPED "demo mode does not deploy"
else
    bash "${SCRIPT_DIR}/deploy-app.sh"
    rc=$?
    record_rc "5 secure workload deployment" "${rc}" "compliant workload admitted and rolled out" "deployment or rollout failed (exit ${rc})"
fi

# Step 6: Runtime security health check
log_step "Step 6/11: Runtime Security Health Check (Tetragon eBPF Engine)"
if [ "${MODE}" = "demo" ]; then
    record "6 tetragon health" SKIPPED "demo mode replays fixtures"
elif kubectl rollout status ds/tetragon -n tetragon --timeout=30s >/dev/null 2>&1; then
    record "6 tetragon health" PASS "DaemonSet rolled out"
else
    record "6 tetragon health" BLOCKED "Tetragon DaemonSet not ready"
fi

# Step 7: Attack simulations (kept going after failure so evidence is still collected)
log_step "Step 7/11: Attack Simulations Execution"
if [ "${HAS_BLOCKED}" -eq 1 ] && [ "${MODE}" = "live" ]; then
    record "7 attack simulations" BLOCKED "not run: an earlier prerequisite was blocked"
else
    bash "${REPO_ROOT}/simulations/run_simulations.sh" --mode "${MODE}"
    rc=$?
    record_rc "7 attack simulations" "${rc}" "every required scenario passed" "required scenario(s) failed or were not run (exit ${rc})"
fi

# Step 8: Telemetry collection
log_step "Step 8/11: Telemetry Collection"
python - <<'PYEOF'
import json, sys
from pathlib import Path
manifest_path = Path("artifacts/runtime/run-manifest.json")
if not manifest_path.exists():
    print("NO_MANIFEST")
    sys.exit(3)
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
collector = manifest.get("collector", {})
if manifest.get("evidence_mode") == "live":
    ok = collector.get("status") == "ok" and collector.get("events_captured", 0) > 0
    print(f"collector={collector.get('status')} events_captured={collector.get('events_captured', 0)}")
    sys.exit(0 if ok else 1)
print("demo fixture trace (no live collector)")
sys.exit(0)
PYEOF
rc=$?
if [ "${rc}" -eq 0 ]; then
    record "8 telemetry collection" PASS "collector status ok with captured sensor events (or labelled demo trace)"
elif [ "${rc}" -eq 3 ]; then
    record "8 telemetry collection" BLOCKED "no run manifest was produced by the simulation step"
else
    record "8 telemetry collection" FAIL "collector degraded, unavailable or captured no events"
fi

# Step 9: Detection validation, derived from the scenario catalog results
log_step "Step 9/11: Detection Validation"
python - <<'PYEOF'
import json, sys
from pathlib import Path
path = Path("artifacts/runtime/run-manifest.json")
if not path.exists():
    sys.exit(3)
manifest = json.loads(path.read_text(encoding="utf-8"))
bad = [s for s in manifest["scenarios"] if s.get("required", True) and s["status"] != "passed"]
passed = sum(s["status"] == "passed" for s in manifest["scenarios"])
print(f"{passed}/{len(manifest['scenarios'])} planned scenarios passed")
for s in bad:
    print(f"  {s['scenario_id']}: {s['status']} - {'; '.join(s['reasons'])}")
sys.exit(1 if bad else 0)
PYEOF
rc=$?
if [ "${rc}" -eq 0 ]; then
    record "9 detection validation" PASS "all required scenarios passed"
elif [ "${rc}" -eq 3 ]; then
    record "9 detection validation" BLOCKED "no run manifest to validate"
else
    record "9 detection validation" FAIL "required scenario(s) did not pass"
fi

# Step 10: Metrics generation (the exporter's own renderer, not a parallel format)
log_step "Step 10/11: Metrics Generation"
mkdir -p artifacts/metrics
if python -c "
from cloudnative_threatguard.observability.metrics_exporter import render_metrics
open('artifacts/metrics/security-metrics.prom', 'w', encoding='utf-8').write(render_metrics())
"; then
    record "10 metrics generation" PASS "artifacts/metrics/security-metrics.prom"
else
    record "10 metrics generation" FAIL "exporter could not render metrics"
fi

# Step 11: Evidence and scorecard
log_step "Step 11/11: Evidence & Scorecard Generation"
bash "${SCRIPT_DIR}/collect-evidence.sh"
rc=$?
if [ "${rc}" -eq 0 ]; then
    record "11 evidence and scorecard" PASS "scorecard overall status PASS"
else
    record "11 evidence and scorecard" FAIL "scorecard did not report PASS (see artifacts/security-report.json)"
fi

finish
