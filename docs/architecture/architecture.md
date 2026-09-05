# CloudNative ThreatGuard — System Architecture & Security Model

CloudNative ThreatGuard implements a layered, **defense-in-depth** Kubernetes security platform combining **preventive admission control** before workload deployment with **continuous behavioral detection** via the Linux kernel at runtime, stateful incident correlation, risk scoring, and a dedicated SOC console.

---

## 1. High-Level Target Architecture

```mermaid
flowchart TD
    subgraph K8s["Kubernetes Cluster & Control Plane"]
        API["kube-apiserver"]
        GK["OPA Gatekeeper Webhook"]
        Workload["Workload Pods (threatguard namespace)"]
        Kernel["Linux Kernel (5.15+ eBPF Tracing)"]
        Tet["Tetragon DaemonSet"]
        
        API -->|Admission Review (mTLS:8443)| GK
        GK -->|Block Misconfigurations| API
        API -->|Admitted Pod Spec| Workload
        Workload -->|Syscalls (execve, openat, connect)| Kernel
        Kernel -->|eBPF kprobes & tracepoints| Tet
    end

    subgraph Normalization["Ingestion & Normalization Layer"]
        StreamIn["Raw Telemetry Stream (JSONL / gRPC)"]
        SimIn["Simulation Scenarios / Lab Triggers"]
        Norm["SecurityEvent Normalizer v2"]
        
        Tet -->|Export Stream| StreamIn
        GK -->|Violation Audit Logs| StreamIn
        SimIn --> Norm
        StreamIn --> Norm
    end

    subgraph CorrelationEngine["ThreatGuard Core Processing Engine"]
        RuleReg["Detection Rule Registry (RULE-K8S-001..010)"]
        SlidingWindow["Sliding Temporal Window Correlator"]
        IncidentMgr["Incident Lifecycle Manager"]
        RiskScore["Explainable Risk Scoring Engine"]
        AttackChain["Attack Chain Visualizer (Mermaid & ASCII)"]
        RemEngine["Safe Response Recommender (Dry-Run Safe)"]

        Norm --> RuleReg
        RuleReg --> SlidingWindow
        SlidingWindow --> IncidentMgr
        IncidentMgr --> RiskScore
        IncidentMgr --> AttackChain
        IncidentMgr --> RemEngine
    end

    subgraph Operations["Operator & SOC Delivery Layer"]
        CLI["ThreatGuard CLI (threatguard)"]
        ForensicCol["Forensic Evidence Collector"]
        SOC["Security Dashboard (FastAPI / HTML5)"]
        AuditReports["Audit Reports (JSON, MD, HTML)"]

        IncidentMgr --> CLI
        IncidentMgr --> SOC
        ForensicCol --> AuditReports
        RemEngine --> CLI
    end
```

---

## 2. Component Boundaries & Communication Protocols

| Source Component | Destination Component | Protocol / Interface | Data Format | Authentication / Encryption |
| :--- | :--- | :--- | :--- | :--- |
| `kube-apiserver` | OPA Gatekeeper | HTTPS (port 8443) | `AdmissionReview` v1 JSON | Mutual TLS (mTLS) with API server CA |
| Linux Kernel eBPF | Tetragon Agent | In-kernel BPF Ring Buffer / Perf Event Array | Binary eBPF telemetry struct | Kernel internal memory |
| Tetragon DaemonSet | ThreatGuard Normalizer | POSIX stdout stream / gRPC (`/var/run/tetragon/tetragon.sock`) | Raw Tetragon JSON (`process_exec`, `process_kprobe`) | Local UNIX domain socket or container filesystem |
| ThreatGuard Ingestion | Detection Engine | Internal Python Call / Async queue | `SecurityEvent` envelope v2 | In-process memory |
| Incident Manager | ThreatGuard Operator CLI | CLI commands / Subprocess execution | Formatted text, Mermaid, JSON | Local terminal environment |
| Remediation Engine | Kubernetes Cluster | `kubectl` CLI via API Server | Declarative YAML (`NetworkPolicy`, dry-run) | Kubernetes ServiceAccount / kubeconfig |
| SOC Dashboard | ThreatGuard API | HTTP/1.1 (port 8080) | RESTful JSON | Cookie / Bearer token (configurable) |

---

## 3. Telemetry Normalization Schema (`SecurityEvent` v2)

Every security signal originating from Gatekeeper, Tetragon, network flows, or simulation frameworks is normalized into the following standardized envelope:

```json
{
  "event_id": "ev-7c42df98ab12",
  "timestamp": "2026-09-05T18:42:15.123456Z",
  "event_type": "runtime_detection",
  "source": "tetragon",
  "cluster": "threatguard-local",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "target-container",
  "node": "threatguard-local-control-plane",
  "process": "/bin/sh",
  "parent_process": "containerd-shim",
  "executable": "/bin/sh",
  "action": "detected",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "detection_rule": "RULE-K8S-001",
  "mitre_technique": "T1059.004",
  "mitre_tactic": "Execution",
  "description": "Interactive Shell Execution in Workload Container",
  "metadata": {
    "binary": "/bin/sh",
    "arguments": "-c whoami",
    "pid": 12432,
    "uid": 0,
    "technique_name": "Command and Scripting Interpreter: Unix Shell"
  }
}
```

### Event Type Enumerations
- `admission_violation`: Pod manifest rejected by OPA Gatekeeper constraint at webhook admission.
- `runtime_detection`: Behavioral anomaly detected by in-kernel eBPF probes.
- `network_anomaly`: Unauthorized egress or unexpected inter-pod network connection.
- `policy_violation`: Non-compliant resource or configuration state.
- `configuration_risk`: Insecure posture detected during static workload inspection.
- `attack_simulation`: Deterministic scenario injected for security verification.
- `incident`: Correlated multi-stage security incident entity.
- `response_action`: Containment or remediation action recommended/executed.

---

## 4. Core Architecture Tenets

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
