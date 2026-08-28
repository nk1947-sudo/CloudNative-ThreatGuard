# CloudNative ThreatGuard — Comprehensive Security Architecture Audit

**Author:** Security Architecture & Detection Engineering Team  
**Evaluation Date:** 2026-09-05  
**Baseline Version:** v1.1.0  
**Target Evolution:** v2.0.0 Production-Oriented Kubernetes Security Platform  

---

## 1. Executive Summary

CloudNative ThreatGuard currently represents a functional Kubernetes defense-in-depth portfolio system featuring:
- **Pre-Deployment Admission Control**: 8 OPA Gatekeeper ConstraintTemplates and Constraints with 27 passing Rego unit tests and 8 negative test manifests.
- **Runtime Observability**: 6 custom Cilium Tetragon eBPF TracingPolicy CRDs monitoring process execution, network connections, and sensitive file operations.
- **Heuristic Correlation**: A Python-based correlation engine that ingests raw Tetragon JSON and flags detections against 6 predefined rules.
- **Basic Observability & Reporting**: A Prometheus metric exporter serving on port 9100, a provisioned Grafana dashboard, and an automated scorecard generator.

However, moving from a portfolio prototype to a **realistic, production-oriented Kubernetes security platform** reveals critical architectural gaps:
1. **No Unified Event Schema**: Admission denials, runtime eBPF telemetry, and policy findings do not share a normalized security event envelope.
2. **Missing Multi-Event Incident Correlation**: Detections exist as isolated alerts rather than correlated, stateful attack chains with causal timelines.
3. **Absence of Dedicated SOC / Investigation UI**: Telemetry is viewed only via raw JSON artifacts, Prometheus endpoints, or basic Grafana panels; there is no interactive SOC incident console, attack graph, process tree, or workload risk view.
4. **Static Hardcoded Simulation Scripts**: Attack scenarios are separate bash scripts that append static raw events rather than a unified, structured simulation framework with verifiable telemetry feedback loops.
5. **Lack of Safe Remediation Recommendations**: The platform flags detections but does not generate actionable, non-destructive response recommendations (dry-run kubectl commands, network isolation policies, or service account tokens rotation).

---

## 2. Multi-Agent Engineering Review

### Agent 1: Kubernetes Security Architect
* **Admission Security**: Strong baseline. OPA Gatekeeper blocks privileged pods, host namespaces (`hostPID`, `hostIPC`, `hostNetwork`), dangerous capabilities, writable root filesystems, root user execution, and missing seccomp profiles.
* **Workload Isolation & RBAC**: The protected sample app in `app/` is well-hardened, running as UID 10001 with dropped capabilities and `readOnlyRootFilesystem: true`. However, the repository lacks explicit cluster-wide RBAC audits, service account token automount restrictions on default service accounts, and Pod Security Standards (PSS) baseline/restricted namespace label validation.
* **Network Segmentation**: A default ingress-only NetworkPolicy exists for the sample app, but egress controls are unmonitored and unconstrained, allowing arbitrary external communication if a container is compromised.
* **Gaps Identified**:
  - Missing admission policy simulation / "what-if" impact evaluation engine.
  - Default namespace service account tokens are mounted by default without explicit validation.
  - Lack of documented RBAC least-privilege matrix (`docs/rbac.md`).

### Agent 2: Runtime Security Engineer
* **Tetragon eBPF Integration**: 6 TracingPolicies cover `sys_enter_execve`, `sys_enter_connect`, and `security_file_open`.
* **Telemetry Quality**: Telemetry is captured via line-delimited JSON. However, kernel kprobes on `security_file_open` and `sys_enter_connect` depend heavily on kernel header matching and structure offsets. In KIND on Windows/WSL2, tracepoint availability can vary.
* **Normalization**: The raw Tetragon output contains deeply nested structures (`process_exec.process`, `process_kprobe.args`) which are mapped ad-hoc in `correlation_engine.py` rather than through an extensible adapter pattern.
* **Gaps Identified**:
  - Kernel events are not enriched with runtime process hierarchy (PPID lineage, tree reconstruction).
  - Network connection tracing is limited to destination IP/port without DNS resolution or cluster service name mapping.

### Agent 3: Detection Engineer
* **Rule Engine Structure**: Rules are statically defined in a Python dictionary (`DETECTION_RULES`) with 6 rules (`RUNTIME-001` through `RUNTIME-006`).
* **Rule Metadata**: Includes rule ID, name, severity, technique, and description.
* **Detection Sophistication**: Rules rely on direct substring matching of binary basenames (e.g., `sh`, `curl`, `whoami`) or exact file path matches (`/var/run/secrets/.../token`).
* **Gaps Identified**:
  - No support for rule enablement/disablement flags or dynamic configuration.
  - Lack of confidence scores, false-positive suppression rules, and deduplication windows.
  - No distinction between admission rule violations and runtime behavioral rules in a unified registry.

### Agent 4: SOC / Incident Response Engineer
* **Alert Management**: Alerts exist only as a list of detection objects in `runtime-events.json`.
* **Incident Lifecycle**: Completely missing. There are no incident IDs, statuses (`NEW`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`), or triage ownership.
* **Correlation**: An attacker executing a shell, reading service account tokens, and initiating an egress connection generates 3 separate detection items rather than a single aggregated, high-severity Incident.
* **Gaps Identified**:
  - No incident aggregation engine correlating multi-step kill chains.
  - No investigation timeline or causal timeline generation.
  - No safe, dry-run response recommendations (e.g., isolate pod via network policy, revoke token).

### Agent 5: Kubernetes Platform Engineer
* **Cluster Lifecycle**: `scripts/setup-cluster.sh` provisions a KIND cluster with explicit `/sys/kernel/debug` and `/sys/fs/bpf` host mounts.
* **Platform Portability**: Tested on KIND across Linux and Windows/WSL2.
* **Deployment Orchestration**: Scripts are split (`setup-cluster.sh`, `install-security-stack.sh`, `deploy-app.sh`, `run-security-validation.sh`).
* **Gaps Identified**:
  - No single `make demo` or `scripts/demo.sh` that stands up a complete, self-contained walkthrough from scratch to dashboard.
  - No dedicated, isolated security lab namespace (`threatguard-lab`) hosting vulnerable workloads separate from the platform control plane.

### Agent 6: Observability Engineer
* **Prometheus & Grafana**: Prometheus scrapes custom metrics on port 9100 from `metrics_exporter.py`. Grafana dashboard is pre-provisioned.
* **Metric Granularity**: Metrics are limited to coarse counters (`threatguard_runtime_detections_total`, `threatguard_admission_blocked_total`).
* **Health Checks**: Microservice exposes `/healthz` and `/readyz`, but the security platform itself lacks internal health monitoring, processing latency metrics, or pipeline queue depth counters.
* **Gaps Identified**:
  - Metrics exporter is a synchronous Python script reading static JSON files from disk on every scrape.
  - Dashboards do not visualize incident lifecycle states, MITRE tactic heatmaps, or cluster risk scores.

### Agent 7: Frontend Product Engineer
* **Current UI**: Grafana dashboard only. There is no dedicated ThreatGuard web application or interactive SOC console.
* **Information Architecture**: Users cannot search findings, drill down into incident timelines, inspect container process trees, or run policy simulations from a web interface.
* **Gaps Identified**:
  - Missing a modern, responsive SOC console providing: Overview, Findings Table, Incident Investigation, Workload Risk, Policy Management, Attack Simulations, and Audit Log.
  - Missing REST API backend serving structured security endpoints.

### Agent 8: Adversary Simulation Engineer
* **Current Simulations**: 6 bash scripts in `simulations/scenarios/` that execute commands inside `threatguard-target-pod`.
* **Determinism**: Scripts rely on `kubectl exec`. If the target pod is not deployed, `run_simulations.sh` falls back to writing synthetic telemetry lines to disk.
* **Gaps Identified**:
  - Lack of a structured Python simulation CLI (`python -m threatguard.simulate <scenario>`).
  - No multi-stage chained attack scenarios demonstrating an end-to-end compromise lifecycle.

### Agent 9: DevSecOps Engineer
* **CI/CD Pipeline**: GitHub Actions workflows validate Rego unit tests, run Trivy vulnerability scanning, and execute KIND cluster E2E.
* **SBOM & Provenance**: `scripts/generate-sbom.sh` exists for Syft/Trivy, but SBOM generation is not integrated into the runtime risk calculation.
* **Secrets & Supply Chain**: No committed secrets; `.gitignore` and `.dockerignore` properly configured.
* **Gaps Identified**:
  - Lack of automated security regression test suites validating false-positive rates and edge-case handling.
  - No automated cluster security posture score calculation based on live observable configurations.

---

## 3. Comprehensive Feature Inventory

| Subsystem / Feature | Status | Notes |
| :--- | :--- | :--- |
| **OPA Gatekeeper Templates & Constraints** | `IMPLEMENTED` | 8 robust constraints covering Pod Security Standards. |
| **Rego Unit Tests (27 tests)** | `IMPLEMENTED` | Comprehensive coverage of pass/deny logic via `opa test`. |
| **Admission Negative Manifest Tests** | `IMPLEMENTED` | 8/8 negative manifests blocked deterministically. |
| **Tetragon TracingPolicy CRDs** | `IMPLEMENTED` | 6 policies for process, kprobe, and file opens. |
| **Basic Runtime Correlation Engine** | `PARTIALLY IMPLEMENTED` | Matches 6 rules against raw Tetragon events; lacks incident grouping. |
| **Normalized Security Event Envelope** | `MISSING` | Admission, runtime, and simulation events use disparate structures. |
| **Extensible Detection Rule Registry** | `PARTIALLY IMPLEMENTED` | Hardcoded dictionary; lacks confidence scoring and suppression. |
| **Stateful Event Correlation Engine** | `MISSING` | No multi-event correlation or incident timeline builder. |
| **Incident Lifecycle Management Engine** | `MISSING` | No statuses (`NEW`, `TRIAGED`, `CONTAINED`), severities, or asset linking. |
| **Transparent Risk Scoring Engine** | `MISSING` | No weighted factor model combining asset criticality and behavior. |
| **Attack-Chain & Process Tree Visualization** | `MISSING` | No graphical representation of attack steps or PID hierarchy. |
| **Dedicated SOC Web Dashboard & Security API** | `MISSING` | Platform relies purely on Grafana; no custom SOC UI exists. |
| **Safe Incident Response Recommendations** | `MISSING` | No automated dry-run remediation suggestions or kubectl generation. |
| **Policy "What-If" Simulation Mode** | `MISSING` | No capability to simulate policy changes against historical manifests. |
| **Deterministic Security Lab (`threatguard-lab`)**| `PARTIALLY IMPLEMENTED` | Only a single test pod in `threatguard` namespace; no dedicated lab. |
| **Python Attack Simulation CLI** | `MISSING` | Only loose bash scripts in `simulations/scenarios/`. |
| **Cluster Security Posture Score** | `MISSING` | Scorecard reports binary pass/fail; no derived 0-100 security score. |
| **Security Audit Trail Log** | `MISSING` | No audit log tracking policy edits, triage notes, or simulation runs. |
| **Structured Evidence Export (JSON/CSV/MD)** | `PARTIALLY IMPLEMENTED` | Exports static JSON scorecard; lacks incident-specific evidence export. |
| **Reproducible Local 1-Command Demo** | `PARTIALLY IMPLEMENTED` | Validation script exists, but lacks end-to-end `make demo` orchestration. |

---

## 4. Prioritized Improvement Matrix (P0 to P3)

| Priority | Feature / Upgrade | Current State | Target Architecture & Engineering Gap | Security Value | Demo Value | Complexity |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: |
| **P0** | **Normalized Security Event Model** | Ad-hoc dicts in models.py | Implement unified event envelope (`event_id`, `timestamp`, `event_type`, `source`, `workload`, `risk`, `mitre`, `evidence`). | CRITICAL | HIGH | MEDIUM |
| **P0** | **Extensible Detection Rule Registry** | Static dict in rules.py | Pluggable rule classes with confidence, condition predicates, false-positive rationale, and MITRE mapping. | HIGH | HIGH | MEDIUM |
| **P0** | **Stateful Correlation & Incident Engine** | Stateless single-event detector | Windowed correlator linking admission violations, shells, and file reads into cohesive Incidents (`#TG-xxx`). | CRITICAL | CRITICAL | HIGH |
| **P0** | **Transparent Risk Scoring Engine** | Hardcoded report stats | Multi-factor risk calculator (asset criticality, namespace privilege, behavior severity) with explainable factors. | HIGH | HIGH | MEDIUM |
| **P0** | **Dedicated SOC Web Console & Security API** | Grafana dashboard only | FastAPI/Flask REST API + modern, polished SOC Dashboard (Overview, Incidents, Findings, Policies, Simulations). | HIGH | CRITICAL | HIGH |
| **P1** | **Attack Chain & Process Tree Engine** | None | Directed acyclic graph generator for kill chain progression and process parentage reconstruction. | HIGH | CRITICAL | MEDIUM |
| **P1** | **Deterministic Security Lab & Simulation CLI** | 6 bash scripts | `threatguard-lab` namespace with vulnerable workloads + structured CLI (`python -m threatguard.simulate`). | HIGH | HIGH | MEDIUM |
| **P1** | **Safe Response Recommendation Engine** | None | Generates non-destructive, user-reviewed response actions (pod isolation NetworkPolicy, dry-run kubectl commands). | HIGH | HIGH | MEDIUM |
| **P1** | **Policy Simulation ("What-If") Engine** | None | Evaluates policy rule changes against workload samples without mutating the live cluster. | HIGH | HIGH | MEDIUM |
| **P1** | **Cluster Security Posture & Trend Engine** | Pass/fail boolean | Derived 0-100 cluster posture score broken into admission, runtime, identity, and network dimensions over time. | MEDIUM | HIGH | MEDIUM |
| **P2** | **Full Audit Trail Logging** | None | Tamper-evident local audit log recording policy toggles, triage status transitions, and simulation executions. | HIGH | MEDIUM | LOW |
| **P2** | **Multi-Format Evidence Export** | JSON scorecard only | Export incidents and findings to JSON, CSV, and formatted Markdown investigation reports. | MEDIUM | HIGH | LOW |
| **P2** | **Enhanced Observability Metrics** | Basic counters | Prometheus metrics for incident count, correlation latency, rule evaluation time, and cluster security score. | MEDIUM | MEDIUM | LOW |
| **P2** | **Hardened Container Configuration** | App container hardened | Formalize RBAC matrix (`docs/rbac.md`), container security contexts, and non-root service definitions. | HIGH | MEDIUM | LOW |
| **P3** | **Expanded Security Regression Suite** | 7 engine unit tests | Comprehensive test suite covering positive, negative, edge cases, malformed payloads, and high event volume. | HIGH | MEDIUM | MEDIUM |
| **P3** | **One-Command Demo Orchestrator** | Separate scripts | `make demo` / `./scripts/demo.sh` orchestrating cluster, policies, lab, simulations, API, and UI in under 2 minutes. | MEDIUM | CRITICAL | MEDIUM |

---

## 5. Architectural Baseline Conclusion

The baseline audit confirms that CloudNative ThreatGuard has solid foundational pillars in admission control (Gatekeeper) and runtime kernel tracing (Tetragon). By systematically executing the phased evolution plan across Stages 2 through 22, the platform will gain stateful correlation, incident management, a dedicated SOC console, an attack chain graph, safe remediation recommendations, and a frictionless local demo experience.
