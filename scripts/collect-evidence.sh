#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Evidence Collection Script
# Consolidates admission logs, runtime telemetry, metrics, and security reports.
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# common.sh enables errexit; this script handles each exit code itself.
set +e

ARTIFACTS_DIR="${REPO_ROOT}/artifacts"

log_step "Consolidating security evidence and audit trails..."

mkdir -p "${ARTIFACTS_DIR}/admission"
mkdir -p "${ARTIFACTS_DIR}/runtime"
mkdir -p "${ARTIFACTS_DIR}/metrics"
mkdir -p "${ARTIFACTS_DIR}/reports"

# 1. Diagnostic logs (live mode only). These are supporting diagnostics, not
# scenario telemetry: events are collected by the runtime pipeline. A failed
# capture is reported, not hidden, and does not by itself fail the run.
if [ "${THREATGUARD_MODE:-live}" = "live" ] && command -v kubectl >/dev/null 2>&1; then
    if kubectl get pods -n gatekeeper-system >/dev/null 2>&1; then
        log_info "Collecting Gatekeeper controller logs..."
        if ! kubectl logs -n gatekeeper-system deployment/gatekeeper-controller-manager --tail=100 \
            > "${ARTIFACTS_DIR}/admission/gatekeeper-controller.log"; then
            log_warn "Could not collect Gatekeeper controller logs."
        fi
    fi
    if kubectl get pods -n tetragon >/dev/null 2>&1; then
        log_info "Collecting Tetragon agent logs (daemon container only)..."
        if ! kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon -c tetragon --tail=150 \
            > "${ARTIFACTS_DIR}/runtime/tetragon-daemon.log"; then
            log_warn "Could not collect Tetragon agent logs."
        fi
    fi
fi

# 2. Generate consolidated forensic evidence and incident reports
log_info "Generating normalized forensic evidence package..."
if ! python -m cloudnative_threatguard.cli.main report evidence; then
    log_error "Evidence package generation failed."
    exit 1
fi

# 3. Re-compute the security scorecard. Its exit code is this script's result:
# non-zero unless the scorecard's overall status is PASS.
log_info "Refreshing security scorecard and report metrics..."
python -m cloudnative_threatguard.cli.main report scorecard
rc=$?
if [ "${rc}" -ne 0 ]; then
    log_error "Scorecard did not report PASS. Review '${ARTIFACTS_DIR}/security-report.json'."
    exit "${rc}"
fi

log_success "Evidence collection complete. Review artifacts in '${ARTIFACTS_DIR}/'."
