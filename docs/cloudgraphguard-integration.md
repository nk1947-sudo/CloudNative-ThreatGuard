# CloudNative ThreatGuard + CloudGraphGuard Integration Architecture

## 1. Executive Overview

This document defines the integration architecture unifying **CloudNative ThreatGuard** (Kubernetes admission control & eBPF runtime security) and **CloudGraphGuard** (Cloud IAM attack-path, permission analysis, and least-privilege engine).

The integrated platform delivers end-to-end cloud-native defense-in-depth across the full kill chain:
$$\text{Cloud Identity} \longrightarrow \text{EKS / Cloud Access} \longrightarrow \text{K8s ServiceAccount} \longrightarrow \text{Workload / Pod} \longrightarrow \text{Runtime Activity} \longrightarrow \text{Sensitive Resource}$$

---

## 2. Component Architectures

### 2.1 Existing CloudNative ThreatGuard Architecture
* **Admission Control**: OPA Gatekeeper enforcing 8 constraint templates (`K8sDisallowPrivileged`, `K8sDisallowRootUser`, `K8sRequiredCapabilitiesDrop`, `K8sDisallowHostPath`, `K8sRequiredReadOnlyRootFilesystem`, `K8sAllowedHostPorts`, `K8sRequiredResourceLimits`, `K8sDisallowPrivilegeEscalation`).
* **Kernel Runtime Detection**: Cilium Tetragon eBPF tracing policies intercepting raw syscalls (`sys_enter_execve`, `sys_enter_openat`, `sys_enter_connect`, `sys_enter_setuid`).
* **Workload Security**: Hardened microservice baseline (`app/src/app.py`), lab environment (`simulations/lab/`), and automated simulation framework (`simulations/scenarios/`).
* **Detection & Analysis**: Rule registry (`runtime/engine/rules.py`), correlation engine (`correlation_engine.py`), risk scoring (`risk_engine.py`), MITRE ATT&CK mapping (`mitre_mapping.py`), incident lifecycle manager (`incident_engine.py`), and forensic collector (`evidence_collector.py`).
* **Observability & Operations**: Prometheus metrics exporter (`metrics_exporter.py`), Grafana dashboard, operator CLI (`runtime/cli.py`), and verification harness (`verify-all.py`).

### 2.2 CloudGraphGuard Architecture
* **Cloud IAM Ingestion**: AWS IAM collector ingesting users, roles, groups, instance profiles, managed policies, inline policies, and trust policies.
* **Normalization Engine**: Provider-neutral representation of identities, permissions, actions, and resource boundaries.
* **Effective Permission Evaluator**: Computes resolved permissions accounting for permission boundaries, SCPs, identity-based policies, and resource-based policies.
* **Trust & Privilege Escalation Analysis**: Analyzes `sts:AssumeRole`, cross-account trust boundaries, and 14+ well-known AWS IAM privilege escalation vectors (e.g., `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`).
* **Attack Path & Blast Radius Graph**: Directed graph analyzing multi-hop traversal paths from initial principal identities to high-value assets (S3 buckets, databases, KMS keys).
* **Remediation Engine**: Deterministic policy diffing, least-privilege policy generation, and dry-run remediation validation.

---

## 3. Integration Boundaries & Guiding Principles

1. **Decoupled Engines**: CloudGraphGuard and ThreatGuard remain independent engines. Neither imports the other's internal implementation details.
2. **Shared Contract / Event Model**: Inter-system communication occurs via a versioned, provider-neutral security event schema (`schema_version: "1.0"`).
3. **No Unnecessary Merging**: Engines are not combined into a monolithic codebase; they are coordinated via a dedicated integration layer (`correlation/`).
4. **Deterministic & Offline First**: Zero cloud dependencies or AWS credentials required for integration verification and demonstration.
5. **Read-Only / Non-Mutating**: Remediation proposals remain recommendations/dry-run only; no automatic mutation of cloud or Kubernetes resources.

```mermaid
graph TD
    subgraph Identity Domain [CloudGraphGuard - Identity Engine]
        IAM_C[IAM Ingestion / Scanner] --> IAM_NORM[IAM Normalizer]
        IAM_NORM --> IAM_EVAL[Effective Permission Evaluator]
        IAM_EVAL --> IAM_GRAPH[IAM Attack Path Graph]
        IAM_GRAPH --> CGG_ADAPT[CloudGraphGuard Event Adapter]
    end

    subgraph Runtime Domain [ThreatGuard - Runtime Engine]
        ADM[OPA Gatekeeper Admission] --> TG_ADAPT[ThreatGuard Event Adapter]
        EBPF[Tetragon eBPF Kernel Traces] --> RULE_REG[Rule Registry]
        RULE_REG --> TG_ADAPT
    end

    subgraph Integration Layer [Cross-Domain Correlation & Risk Engine]
        CGG_ADAPT --> SEC_EVENT[Unified Security Event Stream (v1.0)]
        TG_ADAPT --> SEC_EVENT
        
        ID_MAP[Identity-to-Kubernetes Mapper] --> CORR[Cross-Domain Correlation Engine]
        SEC_EVENT --> CORR
        
        CORR --> UNIFIED_GRAPH[Unified Security Graph]
        CORR --> UNIFIED_INC[Unified Incident Engine]
        CORR --> UNIFIED_RISK[Unified Risk Scoring Engine]
    end

    subgraph Operations & Interface [Operator & SOC Interface]
        UNIFIED_GRAPH --> DASH[Unified SOC Dashboard]
        UNIFIED_INC --> DASH
        UNIFIED_RISK --> DASH
        UNIFIED_INC --> CLI[ThreatGuard Unified CLI]
    end
```

---

## 4. Shared Models & Schemas

| Model | Purpose | Location |
| :--- | :--- | :--- |
| **Unified Security Event** (`UnifiedSecurityEvent`) | Standardized event contract for IAM risks, runtime detections, admission violations, and network anomalies | `correlation/models/event.py` |
| **Identity-K8s Mapping** (`CloudToK8sMapping`) | Explicit bindings between Cloud IAM roles, EKS access entries, K8s ServiceAccounts, and Workloads | `correlation/models/mapping.py` |
| **Unified Security Graph** (`UnifiedSecurityGraph`) | Heterogeneous directed graph modeling IAM principals, cloud resources, Kubernetes workloads, and security events | `correlation/graph/unified_graph.py` |
| **Unified Incident** (`CrossDomainIncident`) | Multi-stage incident model linking initial cloud identity compromise to runtime workload exploitation | `correlation/models/incident.py` |
| **Unified Risk Score** (`UnifiedRiskAssessment`) | Multi-factor risk model combining IAM attack paths, workload criticality, runtime detection severity, and blast radius | `correlation/engine/risk_evaluator.py` |

---

## 5. Duplicated Functionality Analysis & Resolution

| Capability | ThreatGuard Implementation | CloudGraphGuard Implementation | Integration Strategy |
| :--- | :--- | :--- | :--- |
| **Risk Scoring** | Workload-centric composite risk (`RiskScoringEngine`) | Principal/path-centric blast radius score | **Keep both separate**; integration layer aggregates into a composite multi-factor score without overriding domain scorers. |
| **Graph Modeling** | Linear causal attack chain (`AttackChainVisualizer`) | Complex directed IAM permission graph | **Keep both separate**; integration layer introduces `UnifiedSecurityGraph` representing cross-domain transitions. |
| **Remediation** | K8s NetworkPolicy / pod cordon dry-runs | AWS IAM least-privilege policy diffs | **Keep both separate**; unified incidents display dual-track remediation proposals clearly categorized by domain. |

---

## 6. Required Adapters & Integration Components

1. **`cloudgraphguard/`**: Complete self-contained CloudGraphGuard identity engine with IAM models, evaluator, privilege escalation detection, attack path traversal, and demo collectors.
2. **`correlation/adapters/cgg_adapter.py`**: Converts CloudGraphGuard findings (privilege escalation, excessive permissions, cross-account trust, attack paths) into normalized `UnifiedSecurityEvent` objects.
3. **`correlation/adapters/tg_adapter.py`**: Converts ThreatGuard admission violations and runtime eBPF detections into normalized `UnifiedSecurityEvent` objects.
4. **`correlation/models/mapping.py`**: Generic schema mapping cloud provider identities (`AWS IAM Role`, `GCP Service Account`, `Azure Managed Identity`) to Kubernetes identities (`Cluster`, `Namespace`, `ServiceAccount`, `Workload`).
5. **`correlation/engine/correlation_engine.py`**: Correlates events across domains based on identity mapping, workload name, container ID, and temporal proximity.
6. **`correlation/graph/unified_graph.py`**: Cross-domain graph capturing transitions from IAM Principal $\to$ Cloud Role $\to$ EKS Access $\to$ ServiceAccount $\to$ Pod $\to$ Process $\to$ Sensitive Resource.
7. **`correlation/engine/risk_evaluator.py`**: Calculates unified cross-domain risk scores with factor attribution.
8. **`correlation/demo/deterministic_demo.py`**: Deterministic offline scenario providing complete cloud-to-runtime attack chain data without requiring AWS credentials or cloud infrastructure.
