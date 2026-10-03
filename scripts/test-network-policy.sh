#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — NetworkPolicy Verification
# Proves (or refuses to claim) network isolation:
#   1. Canary: does the cluster's CNI enforce NetworkPolicy at all?
#   2. Matrix: each allowance and denial the project's policy declares.
#
# Exit codes: 0 every case matched | 1 a case did not match | 2 BLOCKED
# (cluster unreachable, or the CNI does not enforce NetworkPolicy). A blocked
# result means isolation is UNVERIFIED, not that it works.
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# common.sh enables errexit; this script handles each exit code itself.
set +e

cd "${REPO_ROOT}"
export MSYS_NO_PATHCONV=1

log_step "Verifying NetworkPolicy behaviour..."
python -m cloudnative_threatguard.runtime.network_check
status=$?

case "${status}" in
    0) log_success "Network isolation verified: every allowance and denial behaved as declared." ;;
    2) log_error "Network isolation UNVERIFIED: see the CNI enforcement result above." ;;
    *) log_error "Network isolation check FAILED: a connection did not behave as declared." ;;
esac
exit "${status}"
