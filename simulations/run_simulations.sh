#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Attack Simulation Orchestrator
#
# Usage: run_simulations.sh [--mode live|demo] [TARGET_POD] [NAMESPACE]
#
#   live (default)  Runs each scenario in the target pod, then reads the real
#                   Tetragon event stream for each scenario's time window.
#                   Requires a reachable cluster; it never falls back to
#                   fixtures. Missing prerequisites exit 2 (BLOCKED).
#   demo            Replays the deterministic fixture trace without running
#                   anything. Evidence is labelled demo/SIMULATED.
#
# The orchestrator does not stop at the first failing scenario: an enforced
# kill (exit 137) is an expected, recorded outcome. After every scenario has
# been attempted, outcomes are decided from sensor evidence (see
# src/cloudnative_threatguard/runtime/pipeline.py) and the exit code is
#   0  all required scenarios passed
#   1  at least one required scenario failed or was not run
#   2  blocked (no cluster, no target pod or no sensor event stream)
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCENARIOS_DIR="${SCRIPT_DIR}/scenarios"
ARTIFACTS_RUNTIME="artifacts/runtime"  # repo-relative: Windows Python cannot read Git Bash /c/... paths
RESULTS_FILE="${ARTIFACTS_RUNTIME}/scenario-results.tsv"

MODE="${THREATGUARD_MODE:-live}"
if [ "${1:-}" = "--mode" ]; then
    MODE="${2:-live}"
    shift 2
fi
TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"
PAUSE_SECONDS="${SCENARIO_PAUSE_SECONDS:-4}"

case "${MODE}" in
    live | demo) ;;
    *)
        echo "Unknown mode '${MODE}' (use live or demo)" >&2
        exit 2
        ;;
esac

cd "${REPO_ROOT}"
mkdir -p "${ARTIFACTS_RUNTIME}"
export THREATGUARD_MODE="${MODE}"
export THREATGUARD_RUN_ID="${THREATGUARD_RUN_ID:-$(python -c 'import uuid; print(uuid.uuid4().hex[:12])')}"

now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }

echo "======================================================================"
echo " CloudNative ThreatGuard — Behavioral Attack Simulation Suite"
echo " Mode: ${MODE} | Run: ${THREATGUARD_RUN_ID} | Target: ${NAMESPACE}/${TARGET_POD}"
echo "======================================================================"

if [ "${MODE}" = "demo" ]; then
    echo "[demo] Replaying the deterministic fixture trace. No scenario is executed."
    python -m cloudnative_threatguard.runtime.pipeline --mode demo \
        --run-id "${THREATGUARD_RUN_ID}" --namespace "${NAMESPACE}" --pod "${TARGET_POD}"
    exit $?
fi

if ! command -v kubectl >/dev/null 2>&1 || ! kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[BLOCKED] kubectl or the target pod ${NAMESPACE}/${TARGET_POD} is unavailable." >&2
    echo "          Start the cluster, or run with --mode demo for the labelled simulation." >&2
    exit 2
fi
echo "[+] Live target pod detected: ${TARGET_POD}"

SINCE="$(now)"
: > "${RESULTS_FILE}"

# Scenario list comes from the catalog, the single source of truth.
while IFS=$'\t' read -r scenario_id script; do
    echo ""
    echo "[${scenario_id}] ${script}"
    started="$(now)"
    bash "${SCENARIOS_DIR}/${script}" "${TARGET_POD}" "${NAMESPACE}"
    rc=$?
    ended="$(now)"
    status="executed"
    # 125 is the scenario helper's "prerequisite missing" code; 127 means the
    # scenario script itself could not be run.
    if [ "${rc}" -eq 125 ] || [ "${rc}" -eq 127 ]; then
        status="blocked"
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "${scenario_id}" "${status}" "${rc}" "${started}" "${ended}" >> "${RESULTS_FILE}"
    echo "    -> recorded: status=${status} exit=${rc}"
    sleep "${PAUSE_SECONDS}"
done < <(python -c "
import json
for s in json.load(open('simulations/scenario_catalog.json'))['scenarios']:
    print(s['id'] + '\t' + s['script'])
" | tr -d '\r')

echo ""
echo "======================================================================"
echo "[+] Collecting sensor events and evaluating each scenario..."
echo "======================================================================"
python -m cloudnative_threatguard.runtime.pipeline --mode live \
    --run-id "${THREATGUARD_RUN_ID}" --namespace "${NAMESPACE}" --pod "${TARGET_POD}" \
    --results "${RESULTS_FILE}" --since "${SINCE}" \
    --wait "${SENSOR_WAIT_SECONDS:-45}"
exit $?
