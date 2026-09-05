# ThreatGuard Attack Simulation Framework & Scenarios

## 1. Overview
The ThreatGuard Attack Simulation Suite provides a deterministic, reproducible framework for emulating real-world container breach techniques across the entire MITRE ATT&CK for Containers lifecycle.

Each scenario includes:
1. **Pre-check**: Validates workload readiness and environment prerequisites.
2. **Simulation Execution**: Dispatches atomic, controlled adversary commands inside target pods.
3. **Expected Telemetry**: Identifies the kernel tracepoints and eBPF events captured by Tetragon or Gatekeeper.
4. **Expected Detection**: Maps directly to ThreatGuard rules (`RULE-K8S-001` through `RULE-K8S-010`).
5. **Expected Correlation**: Correlates sequential actions into a unified incident (`#TG-xxxxxx`).
6. **Cleanup**: Resets state to prevent residual noise.

---

## 2. Scenario Matrix

| Scenario ID | Name | MITRE Tactic | Technique | Detection Rule | Target Pod |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SCEN-000** | Admission Rejection | Defense Evasion | `T1610` | `RULE-K8S-009` | `01-privileged-pod` |
| **SCEN-001** | Shell Execution | Execution | `T1059.004` | `RULE-K8S-001` | `threatguard-target-pod` |
| **SCEN-002** | Network Utility | Ingress Tool Transfer | `T1105` | `RULE-K8S-002` | `threatguard-target-pod` |
| **SCEN-003** | Reconnaissance | Discovery | `T1082` | `RULE-K8S-003` | `threatguard-target-pod` |
| **SCEN-004** | Credential Harvesting | Credential Access | `T1552.007` | `RULE-K8S-004` | `threatguard-target-pod` |
| **SCEN-005** | Privilege Escalation | Privilege Escalation | `T1548` | `RULE-K8S-005` | `threatguard-target-pod` |
| **SCEN-006** | Outbound C2 Traffic | Command and Control | `T1071.001` | `RULE-K8S-006` | `threatguard-target-pod` |
| **SCEN-007** | Cryptomining Malware | Impact | `T1496` | `RULE-K8S-007` | `threatguard-target-pod` |
| **SCEN-008** | Lateral Discovery | Discovery / Lateral | `T1046` | `RULE-K8S-008` | `threatguard-target-pod` |

---

## 3. Detailed Scenario Walkthroughs

### SCEN-000: Admission Rejection (OPA Gatekeeper)
* **Goal**: Validate that misconfigured pods requesting `privileged: true` or `hostPath: /` mounts are rejected at admission time before reaching the node kubelet.
* **Pre-check**: Verify Gatekeeper admission controller webhook is operational.
* **Command**:
  ```bash
  kubectl apply -f deploy/gatekeeper/tests/manifests/negative/01-privileged-pod.yaml
  ```
* **Expected Result**: API server rejection:
  `Error from server (Forbidden): admission webhook "validation.gatekeeper.sh" denied the request: [privilege-escalation] Privileged container is not allowed`

---

### SCEN-001: Interactive Shell Spawn in Production Pod
* **Goal**: Detect unexpected interactive shell processes (`/bin/sh`, `/bin/bash`, `/bin/zsh`) in production containers.
* **Command**:
  ```bash
  kubectl exec -n threatguard threatguard-target-pod -c simulation-target -- /bin/sh -c "echo 'Compromise test'"
  ```
* **Expected Telemetry**: Tetragon `process_exec` tracing `/bin/sh`.
* **Detection Rule**: `RULE-K8S-001` (Severity: HIGH).

---

### SCEN-004: Sensitive Credential Access
* **Goal**: Detect unauthorized access to the container's mounted Kubernetes ServiceAccount token or `/etc/shadow`.
* **Command**:
  ```bash
  kubectl exec -n threatguard threatguard-target-pod -c simulation-target -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
  ```
* **Expected Telemetry**: Tetragon kprobe hook on `security_file_open` with target path `/var/run/secrets/kubernetes.io/serviceaccount/token`.
* **Detection Rule**: `RULE-K8S-004` (Severity: CRITICAL, MITRE `T1552.007`).

---

### SCEN-006: Outbound Connection to External Host
* **Goal**: Detect unauthorized egress to external IP addresses from an isolated pod.
* **Command**:
  ```bash
  kubectl exec -n threatguard threatguard-target-pod -c simulation-target -- nc -zvw1 1.1.1.1 443
  ```
* **Expected Telemetry**: Tetragon kprobe hook on `sys_enter_connect` capturing destination IP `1.1.1.1` and port `443`.
* **Detection Rule**: `RULE-K8S-006` (Severity: HIGH, MITRE `T1071.001`).

---

### SCEN-007: Cryptominer Process Emulation
* **Goal**: Detect cryptocurrency miner binaries or worker process masquerading.
* **Command**:
  ```bash
  kubectl exec -n threatguard threatguard-target-pod -c simulation-target -- /bin/sh -c "cp /bin/sleep /tmp/xmrig && /tmp/xmrig 1"
  ```
* **Expected Telemetry**: Tetragon `process_exec` capturing binary containing `xmrig` or `cryptonight`.
* **Detection Rule**: `RULE-K8S-007` (Severity: HIGH, MITRE `T1496`).

---

## 4. One-Command Simulation Runner

To execute the end-to-end simulation suite against a running cluster or offline validation pipeline:
```bash
./simulations/run_simulations.sh
```
Or execute the automated regression test:
```bash
python -m unittest simulations/test_simulations.py -v
```
