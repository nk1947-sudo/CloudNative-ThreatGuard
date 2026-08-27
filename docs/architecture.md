# CloudNative ThreatGuard — System Architecture & Security Model

CloudNative ThreatGuard implements a layered, **defense-in-depth** Kubernetes security architecture that tightly couples **preventive admission control** before workload deployment with **continuous behavioral detection** via the Linux kernel at runtime.

---

## 1. High-Level Architecture Flow

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

---

## 2. The Core Philosophy: Prevention vs. Detection

A common misconception in Kubernetes security is assuming either admission control or runtime security is sufficient on its own. CloudNative ThreatGuard demonstrates that both layers are essential and mutually supportive.

| Dimension | Pre-Deployment: OPA Gatekeeper | Post-Deployment: eBPF (Tetragon) |
| :--- | :--- | :--- |
| **Execution Point** | Kubernetes API Admission Webhook (`k8s.io/api/admission`) | Linux Kernel Syscalls & Tracepoints |
| **Target** | YAML Configuration, Pod Specs, Capabilities | Real process execution, sockets, file descriptors |
| **Enforcement Model** | **Deterministic Prevention** (Zero-trust block) | **Behavioral Detection** (Real-time alerting & kill) |
| **Blind Spot** | Cannot see what the application does *after* it starts | Cannot stop misconfigurations from being scheduled |
| **Primary Threats Addressed** | Privileged containers, root users, hostPath mounts, missing seccomp | Remote Code Execution (RCE), reverse shells, token theft, lateral movement |

### Attack Scenario Comparison

#### A. Attack Before Deployment (Misconfiguration / Supply Chain Injection)
```
Insecure YAML (privileged: true, hostPID: true, docker.sock mount)
      |
      v
Kubernetes API Server
      |
      v
OPA Gatekeeper Admission Webhook
      |
      X ---> BLOCKED: 403 Forbidden with contextual explanation:
             "Container 'web' in pod 'insecure-pod' violates policy [SEC-ADM-001]:
              privileged mode must be false to prevent full container breakout."
```

#### B. Attack After Deployment (Workload Compromise / RCE)
```
Approved Hardened Workload (runAsNonRoot, dropped capabilities, RuntimeDefault seccomp)
      |
      v
Application vulnerability exploited (e.g., Command Injection / Log4j style RCE)
      |
      v
Attacker spawns /bin/sh and curls a secondary payload
      |
      v
eBPF Kernel Probes (sys_enter_execve via Tetragon)
      |
      +---> DETECTED: RUNTIME-001 (MITRE T1059.004) & RUNTIME-002 (MITRE T1105)
      +---> SIGKILL issued immediately to malicious child process
      +---> Structured telemetry emitted to Prometheus & Grafana
```

---

## 3. Subsystem Breakdown

### 3.1 Admission Control Subsystem (OPA Gatekeeper)
- **ConstraintTemplates**: Standardized CRDs declaring the validation logic in Rego.
- **Constraints**: Declarative enforcement rules bound to target namespaces (`threatguard`) while exempting core control-plane components.
- **Dry-Run & Auditing**: Supports continuous cluster audits alongside synchronous blocking.

### 3.2 Runtime Security Subsystem (Cilium Tetragon)
- **Kernel-Level Observability**: Tetragon uses eBPF kprobes, tracepoints, and LSM hooks (`security_file_open`, `sys_enter_execve`, `sys_enter_connect`).
- **Contextual Awareness**: Automatically correlates Linux PIDs with Kubernetes namespaces, pod names, and container IDs.
- **In-Kernel Filtering**: Drops irrelevant kernel events inside eBPF maps to maintain low CPU overhead (<1-2% in production).

### 3.3 Security Telemetry & Evidence Pipeline
- **Raw Event Stream**: Line-delimited JSON events streamed from `/var/run/cilium/tetragon/tetragon.log`.
- **Correlation Engine**: Enriches telemetry with MITRE ATT&CK tactics, techniques, rule IDs, and severity classifications.
- **Metrics Exporter**: Exposes standard Prometheus metrics (`threatguard_admission_enforcement_rate`, `threatguard_runtime_detections_total`).
- **Scorecard Generator**: Produces machine-readable `artifacts/security-report.json` with verified pass/fail statistics.
