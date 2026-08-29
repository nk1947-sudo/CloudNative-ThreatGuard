#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Evidence Collection Script
# Consolidates admission logs, runtime telemetry, metrics, and security reports.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

ARTIFACTS_DIR="${REPO_ROOT}/artifacts"

log_step "Consolidating security evidence and audit trails..."

mkdir -p "${ARTIFACTS_DIR}/admission"
mkdir -p "${ARTIFACTS_DIR}/runtime"
mkdir -p "${ARTIFACTS_DIR}/metrics"
mkdir -p "${ARTIFACTS_DIR}/reports"

# 1. If cluster is active, capture live Gatekeeper violations and Tetragon logs
if command -v kubectl >/dev/null 2>&1 && kubectl get pods -n gatekeeper-system >/dev/null 2>&1; then
    log_info "Collecting live Gatekeeper audit and controller logs..."
    kubectl logs -n gatekeeper-system deployment/gatekeeper-controller-manager --tail=100 > "${ARTIFACTS_DIR}/admission/gatekeeper-controller.log" 2>/dev/null || true
fi

if command -v kubectl >/dev/null 2>&1 && kubectl get pods -n tetragon >/dev/null 2>&1; then
    log_info "Collecting live Tetragon daemon logs..."
    kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon --tail=150 > "${ARTIFACTS_DIR}/runtime/tetragon-daemon.log" 2>/dev/null || true
fi

# 2. Generate consolidated forensic evidence and incident reports
log_info "Generating normalized forensic evidence package..."
python "${REPO_ROOT}/runtime/evidence_collector.py"

# 3. Re-compute dynamic security scorecard
log_info "Refreshing security scorecard and report metrics..."
python "${REPO_ROOT}/scripts/generate-report.py"

log_success "Evidence collection complete. Review artifacts in '${ARTIFACTS_DIR}/'."
