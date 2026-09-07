# CloudNative ThreatGuard

> A Kubernetes defense-in-depth security engineering platform combining **OPA Gatekeeper** for deterministic pre-deployment admission control with **Cilium Tetragon eBPF** for behavioral runtime threat detection, automated attack simulations, and verified security telemetry.

[![CI](https://github.com/cloudnative-threatguard/cloudnative-threatguard/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudnative-threatguard/cloudnative-threatguard/actions/workflows/ci.yml)
[![Security Scan](https://github.com/cloudnative-threatguard/cloudnative-threatguard/actions/workflows/security.yml/badge.svg)](https://github.com/cloudnative-threatguard/cloudnative-threatguard/actions/workflows/security.yml)
[![Kubernetes Version](https://img.shields.io/badge/kubernetes-v1.30+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![OPA Gatekeeper](https://img.shields.io/badge/OPA%20Gatekeeper-v3.17-orange)](https://open-policy-agent.github.io/gatekeeper/)
[![Cilium Tetragon](https://img.shields.io/badge/eBPF-Tetragon%20v1.1-blue)](https://tetragon.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Containers-red)](https://attack.mitre.org/matrices/enterprise/containers/)

---

## Overview

Kubernetes cluster security is frequently treated as a single checkpoint—either focusing solely on static manifest scanning or relying entirely on post-compromise monitoring. 

**CloudNative ThreatGuard** demonstrates that robust cloud-native protection requires a **defense-in-depth** model spanning the entire workload lifecycle:

1. **Pre-Deployment (Preventive Control)**: OPA Gatekeeper admission webhooks inspect and reject non-compliant Kubernetes manifests before pods are scheduled to nodes.
2. **Post-Deployment (Detective Control)**: In-kernel eBPF probes via Cilium Tetragon trace system calls (`sys_enter_execve`, `security_file_open`, `sys_enter_connect`) to detect, correlate, and terminate unauthorized behaviors within running workloads.
3. **Automated Security Validation**: A single-command verification harness executes real admission tests, simulates controlled post-exploitation attacks, verifies detection correlation, and produces machine-readable scorecards.

---

## Problem

Modern container security faces two failure modes:

- **Relying solely on Admission Control**: Once a legitimate, compliant workload is admitted (e.g., non-root, read-only rootfs), admission webhooks are blind to runtime exploitation. If the application contains an application-level vulnerability (e.g., RCE, deserialization flaw, command injection), an attacker can execute commands, steal credentials, and perform reconnaissance while remaining entirely invisible to the admission controller.
- **Relying solely on Runtime Alerts**: Without admission guardrails, workloads may run as root with `privileged: true`, `hostPID: true`, or host socket mounts (`/var/run/docker.sock`), allowing an attacker to achieve instant node compromise and container escape before runtime detection can effectively respond.

---

## Security Architecture

```
Developer / CI / GitOps
          |
          v
+-----------------------+
| Kubernetes API Server |
+-----------------------+
          |
          v
+-----------------------+
|     OPA Gatekeeper    |  <--- Pre-Deployment Admission Control (Validating Webhook)
+-----------------------+
     |             |
     | Deny        | Allow
     v             v
[REJECTED]   +-----------------------+
(Insecure    |  Kubelet / Container  |
 Workload)   |        Runtime        |
             +-----------------------+
                         |
                         v
             +-----------------------+
             |      Linux Kernel     |
             +-----------------------+
                         |
                         v
             +-----------------------+
             | Tetragon eBPF Engine  |  <--- Post-Deployment Behavioral Detection
             +-----------------------+
               |         |         |
      Execve / |  File / | Net /   | Privilege Escalation
      Process  |  Open   | Connect | Probes
               +---------+---------+
                         |
                         v
             +-----------------------+
             | Correlation Engine &  |
             |   Telemetry Exporter  |
             +-----------------------+
               |         |         |
               v         v         v
         [JSON Logs] [Metrics] [Dashboard]
         (Artifacts) (Prometheus) (Grafana)
```

### Prevention vs. Detection in Practice

```
ATTACK BEFORE DEPLOYMENT

Malicious YAML (privileged: true, hostPID: true, hostPath: /var/run/docker.sock)
     |
     v
Gatekeeper Validating Webhook
     |
     X ---> BLOCKED (403 Forbidden with exact container & rule justification)

--------------------------------------------------------------------------------

ATTACK AFTER DEPLOYMENT

Approved Compliant Workload (runAsNonRoot, dropped capabilities, RuntimeDefault seccomp)
     |
     v
Compromised Application Behavior (RCE exploitation spawning /bin/sh or reading tokens)
     |
     v
eBPF Kernel Probes (sys_enter_execve, security_file_open)
     |
     v
DETECTION & RESPONSE (High-fidelity telemetry alert + SIGKILL)
```

---

## Threat Model

CloudNative ThreatGuard aligns against the **STRIDE** framework and container threat paths:

| Threat | Attack Path | Preventive Control (Gatekeeper) | Detective Control (eBPF Runtime) | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Insecure Workload Spec** | Requesting `privileged: true` or `hostPID: true` | `k8sprivilegedcontainer`, `k8shostnamespaces` | Audit logging | Misconfigurations in exempt system namespaces |
| **Host Socket Takeover** | Mounting `/var/run/docker.sock` to escape container | `k8shostfilesystem` | eBPF monitoring of host file open calls | Container runtime 0-days |
| **Privilege Escalation** | Invoking `capsh` or setuid binaries | `k8sprivilegeescalation`, `k8sdropcapabilities` | `RUNTIME-005` (`T1068`) | Kernel privilege escalation exploits |
| **Interactive Shell Access** | Attacker obtains RCE and executes `/bin/sh` | N/A (valid container spec) | `RUNTIME-001` (`T1059.004`) | In-memory code execution without binary spawn |
| **Ingress Tool Staging** | Running `curl` or `wget` to fetch secondary payloads | `k8sreadonlyrootfs`, NetworkPolicy | `RUNTIME-002` (`T1105`) | Binaries implemented natively via Python sockets |
| **ServiceAccount Theft** | Accessing `/var/run/secrets/.../token` | `automountServiceAccountToken: false` | `RUNTIME-004` (`T1552.007`) | Memory scraping of tokens already in process |
| **Lateral Movement / C2** | Outbound TCP socket to command-and-control server | Kubernetes NetworkPolicy (DNS-only egress) | `RUNTIME-006` (`T1071`) | DNS tunneling |

*Full threat analysis documented in [docs/threat-model.md](docs/threat-model.md).*

---

## Preventive Security — OPA Gatekeeper

Admission policies are structured into modular `ConstraintTemplate` specifications with clean Rego logic and parameterized constraints:

1. **`k8sprivilegedcontainer`**: Prohibits running privileged containers.
2. **`k8shostnamespaces`**: Prohibits `hostPID: true`, `hostIPC: true`, and `hostNetwork: true`.
3. **`k8shostfilesystem`**: Prohibits mounting host root (`/`), container runtime sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`), and sensitive node paths.
4. **`k8snonrootuser`**: Enforces `runAsNonRoot: true` or `runAsUser > 0`.
5. **`k8sprivilegeescalation`**: Enforces `allowPrivilegeEscalation: false`.
6. **`k8sdropcapabilities`**: Requires dropping `ALL` Linux capabilities and prohibits adding dangerous capabilities (`SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`).
7. **`k8sseccompprofile`**: Requires `seccompProfile.type: RuntimeDefault` or `Localhost`.
8. **`k8sreadonlyrootfs`**: Enforces `readOnlyRootFilesystem: true` on application workloads.

### Structured Violation Messages

Instead of returning vague rejection notices, policies produce clear, actionable feedback:

```
Container 'web' in pod 'insecure-pod' violates policy [SEC-ADM-001]:
privileged mode must be false to prevent full container breakout.
```

---

## Runtime Security — eBPF (Tetragon)

Behavioral detection is handled by in-kernel eBPF probes managed by **Cilium Tetragon** and scoped to the protected `threatguard` namespace:

- **`RUNTIME-001`**: Interactive Shell Execution (`/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/zsh`) in application containers.
- **`RUNTIME-002`**: Suspicious Network Utilities (`curl`, `wget`, `nc`, `netcat`, `socat`, `nmap`).
- **`RUNTIME-003`**: Host & Environment Reconnaissance Binaries (`id`, `whoami`, `uname`, `ps`, `env`).
- **`RUNTIME-004`**: Sensitive Filesystem Access (`/var/run/secrets/.../token`, `/etc/shadow`, `/root/.ssh`).
- **`RUNTIME-005`**: Container Privilege Escalation Indicators (`capsh`, `nsenter`, `unshare`, `chroot`).
- **`RUNTIME-006`**: Unexpected Outbound Network Connections (`sys_enter_connect` syscalls).

---

## Detection Engineering & Data Model

Raw Tetragon events are parsed and enriched by the ThreatGuard Correlation Engine into a standardized security event schema:

```json
{
  "event_id": "30c28419-5e56-4f40-9ef9-89e224b849b9",
  "timestamp": "2026-09-05T18:30:01Z",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "simulation-target",
  "process": "/bin/sh",
  "command": "/bin/sh -c whoami",
  "event_type": "process_exec",
  "severity": "CRITICAL",
  "detection_name": "Interactive Shell Execution in Workload Container",
  "rule_id": "RUNTIME-001",
  "technique": "T1059.004",
  "technique_name": "Command and Scripting Interpreter: Unix Shell",
  "source": "eBPF / Tetragon",
  "evidence": {
    "binary": "/bin/sh",
    "arguments": "-c whoami",
    "pid": 5101,
    "uid": 10001
  }
}
```

*Comprehensive technique mappings available in [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md).*

---

## Attack Simulation

Controlled, local, non-destructive post-exploitation scenarios simulate attacker actions within a test container:

- **`SCEN-001`**: Spawns an interactive shell process inside the target workload.
- **`SCEN-002`**: Runs networking utilities (`wget` / `nc`) simulating payload retrieval.
- **`SCEN-003`**: Executes discovery commands (`whoami`, `id`, `uname -a`).
- **`SCEN-004`**: Attempts unauthorized reads of the Kubernetes ServiceAccount token and `/etc/shadow`.
- **`SCEN-005`**: Tests capability and namespace inspection (`capsh --print` / `nsenter`).
- **`SCEN-006`**: Initiates outbound socket connections to simulate external command-and-control beacons.

---

## Security Validation & Real Test Results

The platform includes an automated 11-step verification harness (`scripts/run-security-validation.sh` or `make security-test`).

### Verified Test Results (Executed in Environment)

```
===========================================================================
                    SECURITY SCORECARD SUMMARY
===========================================================================
Project:              CloudNative ThreatGuard
Status:               PASS
---------------------------------------------------------------------------
Rego Unit Tests:      27/27 passed (100.0%)
Admission Control:    8/8 malicious workloads blocked (100.0%)
Compliant Workload:   Admitted & Running (100.0%)
Runtime Detections:   6/6 simulated attack scenarios detected (100.0%)
Severity Breakdown:   CRITICAL: 3 | HIGH: 2 | MEDIUM: 1
===========================================================================
```

*Results are dynamically generated from actual test runs and saved to `artifacts/security-report.json`.*

---

## Observability — Prometheus & Grafana

- **Prometheus Exporter**: Exposes real-time metrics on port `9100`:
  - `threatguard_admission_enforcement_rate`
  - `threatguard_admission_blocked_total`
  - `threatguard_runtime_detections_total{rule_id, severity, technique}`
  - `threatguard_detection_rate`
- **Grafana Dashboard**: Production-ready dashboard titled **"CloudNative ThreatGuard — Security Operations Dashboard"** (`observability/grafana/dashboards/threatguard-security-operations.json`):
  - Admission Enforcement Gauge
  - eBPF Runtime Detection Rate Gauge
  - Active Critical Alerts Stat Panel
  - Severity Breakdown Donut Chart
  - MITRE ATT&CK Matrix Bar Gauge

---

## Repository Structure

```
cloudnative-threatguard/
├── .github/workflows/
│   ├── ci.yml                       # Package install, ruff, pytest, OPA test & Kubeconform
│   ├── security.yml                 # Hadolint, ShellCheck, and Trivy scan
│   ├── e2e.yml                      # KIND cluster deployment & E2E verification
│   └── release.yml                  # Build & verify the sdist/wheel on version tags
├── src/cloudnative_threatguard/     # The installable Python package
│   ├── cli/                         # threatguard operator CLI (main.py, verify.py)
│   ├── admission/                   # OPA subprocess client & Gatekeeper manifest validator
│   ├── runtime/                     # Shared SecurityEvent/Severity/SecurityIncident model
│   ├── detection/                   # Detection rule registry & raw-telemetry matching engine
│   ├── correlation/
│   │   ├── kubernetes.py            # Single-cluster incident grouping
│   │   └── cross_domain/            # CloudGraphGuard <-> ThreatGuard cross-domain engine
│   ├── reporting/                   # Risk scoring, incidents, investigation, attack chains,
│   │                                 # remediation recommendations, evidence/scorecard export
│   ├── cloudgraphguard/             # AWS IAM attack-path & privilege-escalation analysis
│   ├── observability/               # Prometheus metrics exporter
│   ├── config/                      # Centralized settings (paths, defaults)
│   └── utils/                       # Small generic helpers
├── tests/
│   ├── unit/<domain>/                # Fast, isolated tests mirroring src/cloudnative_threatguard/
│   ├── integration/<domain>/         # Cross-module / filesystem / external-tool tests
│   └── fixtures/                     # Shared sample data (e.g. raw Tetragon events)
├── app/secure-web-app/
│   ├── Dockerfile                   # Multi-stage hardened non-root container
│   ├── src/app.py                   # Hardened Python/Flask microservice (own requirements.txt)
│   └── k8s/                         # Hardened Deployment, Service & NetworkPolicy
├── deploy/
│   ├── kubernetes/namespace.yaml    # The `threatguard` namespace
│   ├── gatekeeper/                  # 8 ConstraintTemplates, 8 Constraints, Rego src & tests
│   └── tetragon/                    # Helm values + 7 TracingPolicies (RUNTIME-001 to 007)
├── simulations/
│   ├── manifests/test-pod.yaml      # Simulation execution target pod
│   ├── lab/                         # Isolated lab manifests (benign, target, misconfigured)
│   ├── scenarios/                   # SCEN-000 through SCEN-008 attack scripts
│   └── run_simulations.sh           # Master simulation orchestrator
├── observability/
│   ├── grafana/dashboards/          # Grafana Security Operations dashboard
│   └── prometheus/alerts.yaml       # Alertmanager rule definitions
├── scripts/
│   ├── setup-cluster.sh / teardown-cluster.sh   # KIND cluster lifecycle (eBPF mounts)
│   ├── install-security-stack.sh    # Gatekeeper & Tetragon installation
│   ├── test-admission-policies.sh   # Admission enforcement tester
│   ├── run-security-validation.sh   # 11-step master test harness
│   └── collect-evidence.sh, generate-sbom.sh, scan-images.sh
├── docs/
│   ├── architecture/                # System architecture & the prior audit findings
│   ├── security/                    # STRIDE threat model, ATT&CK mapping, network security
│   ├── operations/                  # Deployment, incident response, troubleshooting runbooks
│   ├── development/                 # Cross-platform guide, CloudGraphGuard integration design
│   └── assets/screenshots/          # Verification screenshots, by category
├── artifacts/                       # Structured JSON evidence & scorecards (generated, gitignored)
├── pyproject.toml                   # Package metadata, dependencies, [project.scripts]
├── Makefile                         # Primary developer interface
└── README.md
```

---

## Installation

```bash
git clone https://github.com/cloudnative-threatguard/cloudnative-threatguard.git
cd cloudnative-threatguard
pip install -e ".[dev]"
```

This installs the `cloudnative_threatguard` package and exposes the **`threatguard`** command on your
PATH. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup.

---

## Prerequisites

- **Docker**: Docker Desktop (Windows/macOS) or Docker Engine (Linux).
- **kubectl**: Kubernetes CLI v1.28+.
- **KIND**: Kubernetes in Docker (`go install sigs.k8s.io/kind@latest`).
- **Python**: Python 3.10+ (for the `cloudnative_threatguard` package and test suite).
- **Open Policy Agent (OPA)**: For local Rego testing (`opa test`).
- **Linux Kernel**: Linux 5.4+ (5.15+ recommended) for live eBPF tracing. In Windows, WSL2 provides the Linux 6.x kernel.

---

## Running the Security Lab

### 1. Run Unit & Manifest Tests (Works on all platforms)
```bash
make test              # full pytest suite
make test-admission    # 27 Rego policy unit tests + 8 negative admission manifests
```

### 2. Execute Attack Simulations & Generate Telemetry
```bash
make simulate
```
Executes the attack scenarios and outputs correlated detections to `artifacts/runtime/runtime-events.json`.

### 3. Run the Complete 11-Step Security Test Harness
```bash
make security-test
```
Executes cluster health check, Gatekeeper validation, malicious admission denial, workload deployment, attack simulations, telemetry correlation, metrics generation, and scorecard production.

### 4. Start Prometheus Metrics Exporter
```bash
make dashboard
```
Serves metrics on `http://localhost:9100/metrics`.

### 5. Run Unified Cloud Identity + Kubernetes Security Demo (Offline, No AWS Credentials)
```bash
make demo-cloud
# Or directly:
threatguard demo cross-domain
```
Executes the full cross-domain kill chain: IAM PassRole privilege escalation &rarr; EKS Access Entry &rarr; ServiceAccount mapping &rarr; eBPF runtime shell execution &rarr; credential token read &rarr; dual-track dry-run remediation.

### 6. Operate via the CLI directly
```bash
threatguard status
threatguard incidents list
threatguard incidents show <incident_id>
threatguard workloads
threatguard remediate <incident_id> --dry-run
threatguard remediate <incident_id> --dry-run --live-k8s  # optional: resolve Pod ownership via a live, read-only kubectl lookup (see docs/security/kubernetes-ownership-rbac.md); falls back safely if unavailable
threatguard report evidence
threatguard verify
```

---

## CloudGraphGuard Integration: Unified Cloud Identity & Kubernetes Security

ThreatGuard unites with **CloudGraphGuard** (AWS IAM attack-path and least-privilege engine) to provide defense-in-depth across both cloud identities and Kubernetes runtime environments.

### The Unified Kill Chain

```
IDENTITY (AWS IAM User: developer)
   ↓ [sts:AssumeRole / iam:PassRole]
CLOUD ROLE (eks-deployer-role)
   ↓ [Amazon EKS Access Entry API]
KUBERNETES IDENTITY (threatguard-workload-sa)
   ↓ [Deployment Pod Binding]
WORKLOAD (threatguard-target-pod)
   ↓ [Cilium Tetragon eBPF Kernel Probe]
RUNTIME ACTIVITY (/bin/bash, openat token)
   ↓ [Network Socket Connect: 198.51.100.24:4444]
SENSITIVE RESOURCE EXPOSURE
```

### Integration Capabilities

| Layer | Component | Functionality |
| :--- | :--- | :--- |
| **Shared Event Contract** | `src/cloudnative_threatguard/correlation/cross_domain/models/event.py` | Normalized `UnifiedSecurityEvent` (v1.0) for both IAM findings and eBPF events |
| **Identity-K8s Mapper** | `src/cloudnative_threatguard/correlation/cross_domain/models/mapping.py` | Resolves IAM Roles &rarr; EKS Access Entries &rarr; ServiceAccounts &rarr; Pods |
| **Correlation Engine** | `src/cloudnative_threatguard/correlation/cross_domain/engine/correlation_engine.py` | Detects cross-domain kill chains and generates causal attack sequences |
| **Unified Attack Graph** | `src/cloudnative_threatguard/correlation/cross_domain/graph/unified_graph.py` | Heterogeneous directed graph with Mermaid visualizer and edge provenance |
| **Dual-Track Remediation**| `src/cloudnative_threatguard/correlation/cross_domain/models/incident.py` | Advisory dry-run remediation commands for both AWS IAM and Kubernetes |
| **Composite Risk Scoring**| `src/cloudnative_threatguard/correlation/cross_domain/engine/risk_evaluator.py` | Multi-factor risk formula attributing score contributions across domains |
| **SOC Web Console** | `observability/dashboard/unified_dashboard.html` | Unified dashboard with Cloud Security overview, findings, and attack paths |
| **Offline Demo** | `threatguard demo cross-domain` | Deterministic demonstration requiring **zero AWS credentials** |

---

## Limitations

- **Kernel Dependency**: Live eBPF tracing requires a Linux kernel with BTF and BPF capabilities enabled. On Windows and macOS, live tracing requires a Linux virtual machine (WSL2 or Docker Desktop Linux VM).
- **In-Memory Payloads**: eBPF syscall tracing monitors process invocation and file operations. Exploit payloads executed entirely in-memory within an existing Python or Node.js interpreter process without spawning child binaries require application-level instrumentation (APM/RASP).
- **Prototype Scope**: This repository provides a defense-in-depth security demonstration platform and reference architecture; production enterprise deployments should pair this with managed SIEM/SOAR pipelines.

---

## Skills Demonstrated

- **Cloud Security Engineering**: Kubernetes defense-in-depth architecture, threat modeling (STRIDE), and zero-trust workload hardening.
- **Policy-as-Code (PaC)**: OPA Gatekeeper `ConstraintTemplates`, parameterized constraints, and custom Rego unit testing.
- **Linux Kernel & eBPF Security**: Cilium Tetragon `TracingPolicy` definitions targeting kprobes, tracepoints, and LSM hooks (`execve`, `file_open`, `connect`).
- **Detection Engineering**: Structured event schemas, correlation logic, and MITRE ATT&CK container matrix mappings.
- **DevSecOps & Supply Chain**: Multi-stage non-root Docker builds, SBOM generation, Trivy vulnerability scanning, and GitHub Actions CI pipelines.
- **Cloud-Native Observability**: Prometheus metrics export, alerting rules, and Grafana SecOps dashboard engineering.
