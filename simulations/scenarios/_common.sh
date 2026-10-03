#!/usr/bin/env bash
# Shared helpers for attack simulation scenarios (sourced, not executed).
#
# Scenarios execute test binaries directly with `kubectl exec -- <binary>`,
# not through `/bin/sh -c`. The shell-blocking Tetragon policy kills any
# shell, so wrapping every scenario in a shell would stop each one at its
# first command and exercise nothing. Only the shell scenario invokes a shell.
#
# Each scenario exits with the exit code of its first failing step, so the
# orchestrator can tell a normal run (0), an ordinary command failure and a
# sensor kill (137) apart. It never prints PASS: a scenario's outcome is
# decided later from the sensor's events, not from a marker string.

export MSYS_NO_PATHCONV=1

TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"
SCENARIO_STATUS=0

# Fails closed: the live scenarios require a reachable cluster and target pod.
require_target() {
    if ! command -v kubectl >/dev/null 2>&1; then
        echo "[BLOCKED] kubectl is not available" >&2
        exit 125
    fi
    if ! kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
        echo "[BLOCKED] target pod ${NAMESPACE}/${TARGET_POD} not found" >&2
        exit 125
    fi
}

# Runs one binary in the target pod. Output is discarded so credentials or
# environment contents never reach logs. Records the first non-zero exit code.
step() {
    kubectl exec -n "${NAMESPACE}" "${TARGET_POD}" -- "$@" >/dev/null 2>&1
    local rc=$?
    echo "    exit=${rc}  $*"
    if [ "${SCENARIO_STATUS}" -eq 0 ] && [ "${rc}" -ne 0 ]; then
        SCENARIO_STATUS="${rc}"
    fi
    return 0
}

finish() {
    exit "${SCENARIO_STATUS}"
}
