#!/usr/bin/env bash
# SCEN-000: Admission Denial (pre-deployment block)
# Expected Result: every insecure test manifest is denied by the Gatekeeper
# webhook and the compliant manifest is admitted.
#
# Thin wrapper around the admission verifier, which classifies each result
# (policy_denied / unexpectedly_allowed / execution_error) and exits 0 only
# when every check matched, 1 on a mismatch or error and 2 when blocked.
#
# Usage: scen_000_admission_denial.sh [live|offline]

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"
echo "[SCEN-000] Verifying admission enforcement (${1:-live})..."
python -m cloudnative_threatguard.admission.live_check --mode "${1:-live}"
exit $?
