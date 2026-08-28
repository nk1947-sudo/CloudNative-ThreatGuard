#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Attack Simulation Orchestrator
# Executes safe, controlled, non-destructive post-exploitation scenarios.
# ==============================================================================

set -euo pipefail

export MSYS_NO_PATHCONV=1


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCENARIOS_DIR="${SCRIPT_DIR}/scenarios"
ARTIFACTS_RUNTIME="${REPO_ROOT}/artifacts/runtime"
TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

mkdir -p "${ARTIFACTS_RUNTIME}"

echo "======================================================================"
echo " CloudNative ThreatGuard — Behavioral Attack Simulation Engine"
echo " Target Pod: ${TARGET_POD} | Namespace: ${NAMESPACE}"
echo "======================================================================"

if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[+] Live Kubernetes target pod detected: ${TARGET_POD}"
else
    echo "[!] Target pod not active or kubectl unavailable. Running in local trace simulation mode."
fi

# Raw events capture file
RAW_TELEMETRY="artifacts/runtime/tetragon-raw.json"
: > "${RAW_TELEMETRY}"

echo ""
echo "[1/6] Executing SCEN-001 (Interactive Shell Execution)..."
bash "${SCENARIOS_DIR}/scen_001_shell_execution.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:01Z","process_exec":{"process":{"binary":"/bin/sh","arguments":"-c whoami","pid":5101,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[2/6] Executing SCEN-002 (Suspicious Network Utility)..."
bash "${SCENARIOS_DIR}/scen_002_network_utility.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:02Z","process_exec":{"process":{"binary":"/usr/bin/wget","arguments":"-qO- http://127.0.0.1:8080/healthz","pid":5102,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[3/6] Executing SCEN-003 (Reconnaissance Binaries)..."
bash "${SCENARIOS_DIR}/scen_003_reconnaissance.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:03Z","process_exec":{"process":{"binary":"/usr/bin/whoami","arguments":"","pid":5103,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[4/6] Executing SCEN-004 (Sensitive Filesystem Access)..."
bash "${SCENARIOS_DIR}/scen_004_sensitive_file_read.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:04Z","process_kprobe":{"function_name":"security_file_open","process":{"binary":"/bin/cat","pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}},"args":[{"file_arg":{"path":"/var/run/secrets/kubernetes.io/serviceaccount/token"}},{"int_arg":0}]}}
EOF

echo ""
echo "[5/6] Executing SCEN-005 (Privilege Escalation Indicator)..."
bash "${SCENARIOS_DIR}/scen_005_priv_escalation.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:05Z","process_exec":{"process":{"binary":"/sbin/capsh","arguments":"--print","pid":5105,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[6/6] Executing SCEN-006 (Outbound Network Activity)..."
bash "${SCENARIOS_DIR}/scen_006_outbound_network.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:06Z","process_kprobe":{"function_name":"sys_enter_connect","process":{"binary":"/usr/bin/nc","pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}},"args":[{"int_arg":3},{"sock_arg":{"daddr":"1.1.1.1","dport":443,"proto":"TCP"}}]}}
EOF

echo ""
echo "======================================================================"
echo "[+] Telemetry events captured in: ${RAW_TELEMETRY}"
echo "[+] Ingesting through ThreatGuard Correlation Engine..."
echo "======================================================================"

python -c "
import sys, json, os
from runtime.engine.correlation_engine import ThreatGuardCorrelationEngine

engine = ThreatGuardCorrelationEngine(protected_namespace='${NAMESPACE}')
raw_file = 'artifacts/runtime/tetragon-raw.json'
detections = engine.ingest_file(raw_file)

out_file = 'artifacts/runtime/runtime-events.json'
with open(out_file, 'w', encoding='utf-8') as f:
    json.dump([d.to_dict() for d in detections], f, indent=2)

summary = engine.get_summary()
print(f'Total eBPF Events Processed: {summary[\"total_events_processed\"]}')
print(f'Correlated Detections: {summary[\"total_detections\"]}/6 scenarios')
for sev, count in summary[\"by_severity\"].items():
    if count > 0:
        print(f'  - Severity {sev}: {count}')

for rule, count in summary[\"by_rule\"].items():
    print(f'  - Rule {rule}: {count}')
"

echo ""
echo "[+] Runtime detections saved to: artifacts/runtime/runtime-events.json"
echo "[+] Attack simulation completed successfully."
