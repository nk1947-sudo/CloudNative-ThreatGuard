# CloudNative ThreatGuard — Simulation & Detection Runbook

This runbook outlines operational procedures for executing adversary attack scenarios, observing kernel-level telemetry, verifying detection rule firing, inspecting correlated incidents, and evaluating remediation recommendations.

---

## 1. Simulation Philosophy

CloudNative ThreatGuard uses deterministic, controlled emulation of techniques documented in the MITRE ATT&CK for Containers matrix. Scenarios are executed using standard `kubectl exec` or manifest application, requiring zero synthetic mock libraries during live cluster runs.

---

## 2. One-Command Simulation Execution

To execute the entire 8-scenario attack chain in sequential order:
```bash
./simulations/run_simulations.sh
```

To run offline or test without an active KIND cluster:
```bash
python -m unittest simulations/test_simulations.py -v
```

---

## 3. Individual Scenario Execution & Observation Guide

### SCEN-000: Admission Policy Enforcement (Pre-Deployment Block)
* **Description**: Verifies that OPA Gatekeeper blocks pods violating Kubernetes hardening standards.
* **Execution**:
  ```bash
  kubectl apply -f policies/gatekeeper/tests/01-privileged-pod.yaml
  ```
* **Expected Result**: Immediate admission denial from the API server:
  ```text
  Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [privilege-escalation] Privileged container is not allowed: privileged-test-pod
  ```

---

### SCEN-001: Interactive Shell Spawn in Production Pod
* **Description**: Simulates remote code execution (RCE) resulting in a spawned `/bin/sh` process.
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_001_shell_exec.sh
  ```
* **Observation**:
  - Tetragon traces `sys_enter_execve` for `/bin/sh`.
  - Rule Triggered: `RULE-K8S-001` (Interactive Shell Spawned).
  - MITRE Technique: `T1059.004` (Command and Scripting Interpreter: Unix Shell).
  - Incident Association: Grouped into active workload incident `#TG-xxx`.

---

### SCEN-002: Ingress Tool Transfer (Network Utility Execution)
* **Description**: Emulates adversary downloading exploitation tooling via `curl` or `wget`.
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_002_network_utility.sh
  ```
* **Observation**:
  - Process execution captured for `curl` / `wget`.
  - Rule Triggered: `RULE-K8S-002` (Suspicious Network Tool Execution).
  - MITRE Technique: `T1105` (Ingress Tool Transfer).

---

### SCEN-003: System Discovery & Environment Reconnaissance
* **Description**: Emulates container fingerprinting (`whoami`, `id`, `uname`, `env`).
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_003_reconnaissance.sh
  ```
* **Observation**:
  - Telemetry logs execution of system discovery binaries.
  - Rule Triggered: `RULE-K8S-003` (Container Reconnaissance and Discovery).
  - MITRE Technique: `T1082` (System Information Discovery).

---

### SCEN-004: Sensitive Credential Harvesting
* **Description**: Attempts reading `/var/run/secrets/kubernetes.io/serviceaccount/token`.
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_004_sensitive_file_read.sh
  ```
* **Observation**:
  - In-kernel tracepoint `security_file_open` fires on ServiceAccount token path.
  - Rule Triggered: `RULE-K8S-004` (Kubernetes Service Account Token Access).
  - MITRE Technique: `T1552.007` (Container and Resource Discovery: Container API).
  - Severity: **CRITICAL**.

---

### SCEN-005: Privilege Escalation Attempt
* **Description**: Spawns capability manipulation binaries (`capsh`, `nsenter`).
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_005_priv_escalation.sh
  ```
* **Observation**:
  - Rule Triggered: `RULE-K8S-005` (Privilege Escalation / Capability Manipulation).
  - MITRE Technique: `T1548` (Abuse Elevation Control Mechanism).

---

### SCEN-006: Unauthorized Outbound Network Egress
* **Description**: Attempts TCP connection to external IP (`1.1.1.1:443`).
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_006_outbound_network.sh
  ```
* **Observation**:
  - Kernel tracepoint `sys_enter_connect` logs destination socket.
  - Rule Triggered: `RULE-K8S-006` (Unauthorized Outbound Network Connection).
  - MITRE Technique: `T1071.001` (Application Layer Protocol: Web Protocols).

---

### SCEN-007: Cryptominer Process Execution
* **Description**: Simulates cryptomining malware (`xmrig` process emulation).
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_007_cryptominer.sh
  ```
* **Observation**:
  - Rule Triggered: `RULE-K8S-007` (Cryptocurrency Mining Activity).
  - MITRE Technique: `T1496` (Resource Hijacking).

---

### SCEN-008: Internal Cluster & Lateral Discovery
* **Description**: Scans internal Kubernetes services (CoreDNS / Kubernetes API).
* **Execution**:
  ```bash
  ./simulations/scenarios/scen_008_lateral_recon.sh
  ```
* **Observation**:
  - Rule Triggered: `RULE-K8S-008` (Internal Network Port Scanning & Lateral Discovery).
  - MITRE Technique: `T1046` (Network Service Discovery).

---

## 4. Post-Simulation Operational Review

Following scenario execution, perform the following verification steps:

1. **List Active Correlated Incidents**:
   ```bash
   python runtime/cli.py incidents list
   ```
2. **Inspect Highest Risk Incident**:
   ```bash
   python runtime/cli.py incidents show <incident_id>
   ```
3. **Review Dry-Run Remediation Guidance**:
   ```bash
   python runtime/cli.py remediate <incident_id> --dry-run
   ```
4. **Collect Forensic Evidence Package**:
   ```bash
   python runtime/evidence_collector.py
   ```
