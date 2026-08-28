# CloudNative ThreatGuard — System Architecture & Security Model

CloudNative ThreatGuard implements a layered, **defense-in-depth** Kubernetes security platform combining **preventive admission control** before workload deployment with **continuous behavioral detection** via the Linux kernel at runtime, stateful incident correlation, risk scoring, and a dedicated SOC console.

---

## 1. High-Level Target Architecture

```
                      CloudNative ThreatGuard
                                │
                      ┌─────────▼─────────┐
                      │ Security Control  │
                      │      Plane        │
                      └─────────┬─────────┘
                                │
           ┌────────────────────┼────────────────────┐
           │                    │                    │
           ▼                    ▼                    ▼
    Admission Layer       Runtime Layer       Detection Layer
    OPA Gatekeeper        Tetragon/eBPF        Rule Engine
           │                    │                    │
           └────────────────────┼────────────────────┘
                                │
                                ▼
                         Event Normalizer
                                │
                                ▼
                         Correlation Engine
                                │
                  ┌─────────────┼──────────────┐
                  │             │              │
                  ▼             ▼              ▼
               Risk         Incident        Response
              Engine         Engine          Engine
                  │             │              │
                  └─────────────┼──────────────┘
                                │
                                ▼
                          Security API
                                │
                                ▼
                        SOC Web Dashboard
```

---

## 2. Core Architecture Tenets

### 2.1 Prevention vs. Detection in Practice

A fundamental tenet in Kubernetes security is recognizing that admission control and runtime detection address complementary stages of the threat lifecycle:

| Dimension | Pre-Deployment: OPA Gatekeeper | Post-Deployment: eBPF (Tetragon) |
| :--- | :--- | :--- |
| **Execution Point** | Kubernetes API Admission Webhook (`k8s.io/api/admission`) | Linux Kernel Syscalls & Tracepoints |
| **Target** | YAML Configuration, Pod Specs, Capabilities, Seccomp | Real process execution, sockets, file descriptors |
| **Enforcement Model** | **Deterministic Prevention** (Zero-trust block) | **Behavioral Detection** (Real-time alerting & telemetry) |
| **Blind Spot** | Cannot observe in-memory or post-start execution | Cannot prevent misconfigurations from being admitted |
| **Primary Threats Addressed** | Privileged containers, root execution, hostPath mounts, missing seccomp | RCE exploitation, reverse shells, credential theft, egress beacons |

---

## 3. Subsystem Breakdown

### 3.1 Admission Control Subsystem (OPA Gatekeeper)
* **ConstraintTemplates**: Parameterized Rego policies defining admission constraints.
* **Constraints**: Applied against workload namespaces (`threatguard`, `threatguard-lab`) to enforce Pod Security Standards.
* **Validation Harness**: Validates positive manifests (safe workloads) and negative manifests (host namespaces, privilege escalation, writable root filesystems) with 100% deterministic blocking.
* **Policy Simulation ("What-If")**: Offline evaluation of proposed policy changes against representative cluster manifests without live cluster mutation.

### 3.2 Runtime Observability Subsystem (Cilium Tetragon / eBPF)
* **Kernel Tracing**: Employs in-kernel eBPF kprobes and tracepoints (`sys_enter_execve`, `security_file_open`, `sys_enter_connect`).
* **Contextual Tagging**: Enriches kernel events with container runtime metadata: Pod name, namespace, container ID, and image.
* **In-Kernel Overhead Minimization**: Uses eBPF maps for namespace and binary filtering directly inside the kernel (<1-2% CPU overhead).

### 3.3 Event Normalization Layer
* Normalizes all security signals into a unified, extensible security event model (`SecurityEvent` envelope).
* Maps disparate inputs (Gatekeeper webhook rejections, Tetragon execve/kprobe events, simulation triggers, and configuration risks) into standard JSON schemas.

### 3.4 Detection Rule Engine
* Decouples detection logic into an extensible rule registry.
* Each rule defines unique ID (`RULE-K8S-xxx`), severity, confidence score, MITRE ATT&CK technique/tactic mapping, predicate conditions, false-positive context, and default recommended response.

### 3.5 Stateful Correlation & Incident Engine
* Tracks sliding temporal windows across workloads and namespaces.
* Correlates sequential multi-stage behaviors (e.g. Admission Denial → Shell Execution → Credential Read → Outbound Network Connection) into a single high-fidelity Incident entity (`#TG-xxx`).
* Manages incident lifecycle states: `NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`.

### 3.6 Explainable Risk Scoring Engine
* Calculates transparent, composite risk scores (0–100) based on weighted factors:
  - Behavior Severity (Critical/High/Medium/Low)
  - Workload Privilege Level (Privileged, HostPID, HostPath)
  - Asset Sensitivity (Protected vs. Lab namespace)
  - Detection Confidence & Recurrence Rate
* Every score outputs an explainable breakdown of contributing factors.

### 3.7 Safe Incident Response Engine
* Generates actionable, non-destructive remediation plans:
  - Workload Isolation (generate dry-run `NetworkPolicy`)
  - Pod Eviction / Reschedule (`kubectl delete pod ... --dry-run=server`)
  - Admission Guardrail Reinforcement
  - Service Account Token Rotation
* **Guardrail**: Operates in **Recommend-Only** mode by default, requiring explicit operator review before any action.

### 3.8 Security API & SOC Operations Console
* **Security API**: Serves RESTful endpoints for findings, incidents, audit logs, cluster posture score, and policy simulation.
* **SOC Console**: Modern dark-mode web console providing security overview, incident investigation drilldowns, interactive attack chain graphs, container process trees, and live telemetry feeds.

---

## 4. Architectural Baseline & Review Status

For complete findings from our multi-agent security audit across 9 engineering disciplines and the prioritized feature improvement matrix, refer to [architecture-audit.md](file:///c:/Users/nkaus/Desktop/Project/Projects/CloudNative%20ThreatGuard/docs/architecture-audit.md).
