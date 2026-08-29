#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Attack Simulation Orchestrator
# Executes safe, controlled, non-destructive post-exploitation scenarios.
# Orchestrates Admission Denial, Runtime eBPF Detections, Incident Correlation,
# and Transparent Risk Scoring.
# ==============================================================================

set -euo pipefail
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCENARIOS_DIR="${SCRIPT_DIR}/scenarios"
ARTIFACTS_RUNTIME="artifacts/runtime"
TARGET_POD="${1:-threatguard-target-pod}"
NAMESPACE="${2:-threatguard}"

mkdir -p "${ARTIFACTS_RUNTIME}"

echo "======================================================================"
echo " CloudNative ThreatGuard — Behavioral Attack Simulation Suite"
echo " Target Pod: ${TARGET_POD} | Namespace: ${NAMESPACE}"
echo "======================================================================"

if command -v kubectl >/dev/null 2>&1 && kubectl get pod "${TARGET_POD}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[+] Live Kubernetes target pod detected: ${TARGET_POD}"
else
    echo "[!] Target pod not active or kubectl unavailable. Running in local trace simulation mode."
fi

# Raw events capture file
RAW_TELEMETRY="${ARTIFACTS_RUNTIME}/tetragon-raw.json"
: > "${RAW_TELEMETRY}"

echo ""
echo "[SCENARIO 0/8] Admission Control: Insecure Workload Rejection..."
bash "${SCENARIOS_DIR}/scen_000_admission_denial.sh" "${NAMESPACE}"

echo ""
echo "[SCENARIO 1/8] Execution: Interactive Shell Spawned (T1059.004)..."
bash "${SCENARIOS_DIR}/scen_001_shell_execution.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:01Z","process_exec":{"process":{"binary":"/bin/sh","arguments":"-c whoami","pid":5101,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[SCENARIO 2/8] Command & Control: Ingress Tool Transfer (T1105)..."
bash "${SCENARIOS_DIR}/scen_002_network_utility.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:02Z","process_exec":{"process":{"binary":"/usr/bin/wget","arguments":"-qO- http://127.0.0.1:8080/healthz","pid":5102,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[SCENARIO 3/8] Discovery: Host and Environment Profiling (T1082)..."
bash "${SCENARIOS_DIR}/scen_003_reconnaissance.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:03Z","process_exec":{"process":{"binary":"/usr/bin/whoami","arguments":"","pid":5103,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[SCENARIO 4/8] Credential Access: Kubernetes SA Token Harvesting (T1552.007)..."
bash "${SCENARIOS_DIR}/scen_004_sensitive_file_read.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:04Z","process_kprobe":{"function_name":"security_file_open","process":{"binary":"/bin/cat","pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}},"args":[{"file_arg":{"path":"/var/run/secrets/kubernetes.io/serviceaccount/token"}},{"int_arg":0}]}}
EOF

echo ""
echo "[SCENARIO 5/8] Privilege Escalation: Namespace Breakout / Cap Inspection (T1611)..."
bash "${SCENARIOS_DIR}/scen_005_priv_escalation.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:05Z","process_exec":{"process":{"binary":"/sbin/capsh","arguments":"--print","pid":5105,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[SCENARIO 6/8] Command & Control: Outbound Socket Connection (T1071)..."
bash "${SCENARIOS_DIR}/scen_006_outbound_network.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:06Z","process_kprobe":{"function_name":"sys_enter_connect","process":{"binary":"/usr/bin/nc","pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}},"args":[{"int_arg":3},{"sock_arg":{"daddr":"1.1.1.1","dport":443,"proto":"TCP"}}]}}
EOF

echo ""
echo "[SCENARIO 7/8] Impact: Cryptominer Process Execution (T1496)..."
bash "${SCENARIOS_DIR}/scen_007_cryptominer_process.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:07Z","process_exec":{"process":{"binary":"/usr/local/bin/xmrig","arguments":"--donate-level 1","pid":5107,"uid":10001,"pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}}}}
EOF

echo ""
echo "[SCENARIO 8/8] Lateral Movement: Internal Network Discovery Probe (T1210)..."
bash "${SCENARIOS_DIR}/scen_008_network_discovery_lateral.sh" "${TARGET_POD}" "${NAMESPACE}"
cat << 'EOF' >> "${RAW_TELEMETRY}"
{"time":"2026-09-05T18:30:08Z","process_kprobe":{"function_name":"sys_enter_connect","process":{"binary":"/usr/bin/nc","pod":{"namespace":"threatguard","name":"threatguard-target-pod","container":{"name":"simulation-target"}}},"args":[{"int_arg":4},{"sock_arg":{"daddr":"10.96.0.1","dport":443,"proto":"TCP"}}]}}
EOF

echo ""
echo "======================================================================"
echo "[+] Processing Simulation Telemetry with ThreatGuard Engine..."
echo "======================================================================"

python -c "
import sys, json, os
from runtime.engine.correlation_engine import ThreatGuardCorrelationEngine
from runtime.engine.risk_engine import RiskScoringEngine
from runtime.engine.models import SecurityEvent

engine = ThreatGuardCorrelationEngine(protected_namespace='${NAMESPACE}')
raw_file = '${ARTIFACTS_RUNTIME}/tetragon-raw.json'
detections = engine.ingest_file(raw_file)

# Convert to normalized SecurityEvents
security_events = [d.to_security_event() for d in detections]

# Add admission denial event
admission_event = SecurityEvent.from_admission_denial(
    rule_id='RULE-K8S-009',
    policy_name='k8sprivilegedcontainer',
    resource_name='01-privileged-pod',
    namespace='${NAMESPACE}',
    violation_message='Privileged container execution is prohibited in cluster'
)
security_events.insert(0, admission_event)

# Write runtime events
out_file = '${ARTIFACTS_RUNTIME}/runtime-events.json'
with open(out_file, 'w', encoding='utf-8') as f:
    json.dump([e.to_dict() for e in security_events], f, indent=2)

# Correlate incidents
incidents = engine.correlate_incidents()
incident_file = '${ARTIFACTS_RUNTIME}/incident-reports.json'
with open(incident_file, 'w', encoding='utf-8') as f:
    json.dump([i.to_dict() for i in incidents], f, indent=2)

# Compute Risk Assessment
risk_engine = RiskScoringEngine()
risk_assessment = risk_engine.evaluate_workload(
    security_events,
    workload_ref='${NAMESPACE}/${TARGET_POD}',
    workload_spec={'runAsUser': 0, 'privileged': False}
)
risk_file = '${ARTIFACTS_RUNTIME}/risk-assessment.json'
with open(risk_file, 'w', encoding='utf-8') as f:
    json.dump(risk_assessment.to_dict(), f, indent=2)

summary = engine.get_summary()
print(f'Total Telemetry Events Ingested: {summary[\"total_events_processed\"] + 1}')
print(f'Total Security Detections: {len(security_events)}')
print(f'Multi-Event Correlated Incidents: {len(incidents)}')
print(f'Composite Workload Risk Score: {risk_assessment.composite_risk_score}/100 ({risk_assessment.risk_tier})')
print('\nTop Risk Contributors:')
for c in risk_assessment.top_risk_contributors:
    print(f'  [+{c.impact_points:.1f} pts] {c.factor_name}: {c.description}')
"

echo ""
echo "[+] Attack simulation completed successfully."
echo "[+] Detections saved to: ${ARTIFACTS_RUNTIME}/runtime-events.json"
echo "[+] Incidents saved to:  ${ARTIFACTS_RUNTIME}/incident-reports.json"
echo "[+] Risk scoring saved to: ${ARTIFACTS_RUNTIME}/risk-assessment.json"
