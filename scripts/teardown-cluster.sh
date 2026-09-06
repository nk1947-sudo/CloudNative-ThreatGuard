#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Cluster Teardown Script
# Deletes the local KIND cluster created by setup-cluster.sh.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

CLUSTER_NAME="threatguard-cluster"

if ! command -v kind >/dev/null 2>&1; then
    log_error "KIND is not installed or not in PATH; nothing to tear down."
    exit 1
fi

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_step "Deleting KIND cluster '${CLUSTER_NAME}'..."
    kind delete cluster --name "${CLUSTER_NAME}"
    log_success "Cluster '${CLUSTER_NAME}' deleted."
else
    log_info "KIND cluster '${CLUSTER_NAME}' does not exist; nothing to do."
fi
