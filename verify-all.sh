#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Complete Platform Verification (verify-all.sh)
# Runnable locally and inside CI/CD environments.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "========================================================================"
echo " CloudNative ThreatGuard: Invoking Verification Engine"
echo "========================================================================"

if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "ERROR: Python runtime not found in PATH."
    exit 1
fi

"${PYTHON_CMD}" "${SCRIPT_DIR}/verify-all.py"
