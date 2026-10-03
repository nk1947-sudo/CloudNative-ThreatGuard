#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Admission Policy Test Runner
# Validates admission enforcement against positive and negative manifests.
#
# Usage: test-admission-policies.sh [--mode live|offline]
#   live    (default) submits each manifest to the live Gatekeeper webhook.
#   offline evaluates the Rego policies through OPA only (no cluster involved).
#
# Exit codes: 0 all checks matched, 1 policy mismatch or error, 2 BLOCKED.
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# common.sh enables errexit; this script handles each exit code itself.
set +e

MODE="live"
if [ "${1:-}" = "--mode" ]; then
    MODE="${2:-live}"
fi

cd "${REPO_ROOT}"
log_step "Executing Admission Policy Verification Suite (${MODE})..."

python -m cloudnative_threatguard.admission.live_check --mode "${MODE}"
status=$?

case "${status}" in
    0) log_success "Admission checks matched expectations: artifacts/admission/admission-results.json" ;;
    2) log_error "Admission checks BLOCKED: prerequisites unavailable." ;;
    *) log_error "Admission checks FAILED: see results above." ;;
esac
exit "${status}"
