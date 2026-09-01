# CloudNative ThreatGuard + CloudGraphGuard Integration Architecture

## 1. Executive Overview

This document specifies the integration architecture uniting **CloudNative ThreatGuard** (Kubernetes admission control & eBPF runtime security) and **CloudGraphGuard** (Cloud IAM attack-path, permission analysis, and least-privilege engine).

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
* **Cloud IAM Ingestion**: AWS IAM collector ingesting users, roles, groups, instance profiles, managed policies, inline policies, and trust policies (`cloudgraphguard/models/iam.py`).
* **Normalization Engine**: Provider-neutral representation of identities, permissions, actions, and resource boundaries.
* **Effective Permission Evaluator**: Computes resolved permissions accounting for permission boundaries, SCPs, identity-based policies, and resource-based policies.
* **Trust & Privilege Escalation Analysis**: Analyzes `sts:AssumeRole`, cross-account trust boundaries, and well-known AWS IAM privilege escalation vectors (e.g., `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`) via `cloudgraphguard/analysis/escalation.py`.
* **Attack Path & Blast Radius Graph**: Directed graph analyzing multi-hop traversal paths from initial principal identities to high-value assets (S3 buckets, databases, KMS keys) via `cloudgraphguard/graph/iam_graph.py`.
* **Remediation Engine**: Deterministic policy diffing, least-privilege policy generation, and dry-run remediation validation.

---

## 3. Integration Boundaries & Guiding Principles

1. **Decoupled Engines**: CloudGraphGuard and ThreatGuard remain independent engines. Neither imports the other's internal implementation details.
2. **Shared Contract / Event Model**: Inter-system communication occurs via a versioned, provider-neutral security event schema (`UnifiedSecurityEvent` v1.0).
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
| **Identity-K8s Mapping** (`IdentityBinding`, `IdentityMappingRegistry`) | Explicit bindings between Cloud IAM roles, EKS access entries, K8s ServiceAccounts, and Workloads | `correlation/models/mapping.py` |
| **Unified Security Graph** (`UnifiedSecurityGraph`) | Heterogeneous directed graph modeling IAM principals, cloud resources, Kubernetes workloads, and security events | `correlation/graph/unified_graph.py` |
| **Unified Incident** (`CrossDomainIncident`) | Multi-stage incident model linking initial cloud identity compromise to runtime workload exploitation | `correlation/models/incident.py` |
| **Unified Risk Score** (`UnifiedRiskAssessment`) | Multi-factor risk model combining IAM attack paths, workload criticality, runtime detection severity, and blast radius | `correlation/engine/risk_evaluator.py` |

---

## 5. Completed Implementation Stages

The integration has been executed across 12 distinct, fully tested, and committed stages:

* **STAGE 1**: Integration architecture definition and boundaries (`docs/cloudgraphguard-integration.md`).
* **STAGE 2**: Shared Pydantic v2 event schema (`correlation/models/event.py`).
* **STAGE 3**: CloudGraphGuard identity engine and event adapter (`cloudgraphguard/`, `correlation/adapters/cgg_adapter.py`).
* **STAGE 4**: ThreatGuard event adapter (`correlation/adapters/tg_adapter.py`).
* **STAGE 5**: Cloud Identity to Kubernetes relationship model (`correlation/models/mapping.py`).
* **STAGE 6**: Cross-domain correlation engine (`correlation/engine/correlation_engine.py`).
* **STAGE 7**: Unified attack graph abstraction and Mermaid visualizer (`correlation/graph/unified_graph.py`).
* **STAGE 8**: Cross-domain incident model and dual-track remediation manager (`correlation/models/incident.py`).
* **STAGE 9**: Multi-factor cross-domain risk scoring engine (`correlation/engine/risk_evaluator.py`).
* **STAGE 10**: Unified SOC dashboard (`observability/dashboard/unified_dashboard.html`) and Prometheus metrics.
* **STAGE 11**: Fully deterministic offline demonstration (`demo-cloud-security.py`).
* **STAGE 12**: Platform integration documentation and runbook updates.

---

## 6. Multi-Factor Risk Calculation Model

The unified risk score aggregates individual domain assessments into a transparent, documented formula:
$$\text{Score} = \min\left(100.0, \sum \text{IAM Factors} + \sum \text{Runtime Factors} + \text{Kill Chain Amplifier}\right)$$

### Factor Breakdown:
1. **IAM Factors (CloudGraphGuard)**:
   * Privilege Escalation vector (`iam:PassRole`, `iam:AttachRolePolicy`): up to **+35.0 pts**
   * Administrative wildcard access (`*`): up to **+30.0 pts**
   * Elevated cloud access: up to **+25.0 pts**
2. **Kubernetes Runtime Factors (ThreatGuard)**:
   * Credential access / token exfiltration: **+40.0 pts**
   * Interactive shell execution (`/bin/bash`): **+25.0 pts**
   * External network socket egress: **+15.0 pts**
   * OPA Gatekeeper admission violation: **+10.0 pts**
3. **Cross-Domain Kill Chain Context**:
   * Active progression from initial cloud identity compromise to runtime container exploitation adds a **+10.0 pt** correlation amplifier.

---

## 7. Dual-Track Remediation (Dry-Run Only)

Remediation proposals are strictly advisory and dry-run to ensure safety:

* **Cloud IAM Track**:
  ```bash
  aws iam get-user-policy --user-name developer --policy-name PassRoleEscalationPolicy
  ```
  *Action*: Remove wildcard `iam:PassRole` and scope to explicit non-privileged compute ARNs.
* **Kubernetes Runtime Track**:
  ```bash
  kubectl label pod threatguard-target-pod -n threatguard security.threatguard.io/quarantine=true --dry-run=client
  ```
  *Action*: Isolate compromised pod via zero-trust default-deny NetworkPolicy.

---

## 8. Demonstration & Testing Guide

```bash
# Execute deterministic cross-domain cloud security demo (0 credentials required)
python demo-cloud-security.py

# Or via Makefile
make demo-cloud

# Run correlation unit tests
python -m unittest discover correlation/tests/

# Verify entire ThreatGuard platform
python verify-all.py
```

---

## 9. Known Integration Limitations & Next Steps

### Known Limitations:
1. **Live AWS Collector**: Current ingestion uses deterministic mock collection (`cloudgraphguard/collector/mock_collector.py`). Live Boto3 AWS API scraping is deferred to production deployment environments.
2. **Dynamic Dashboard API**: Unified dashboard is served as a self-contained responsive SPA; live WebSocket streaming is slated for the subsequent full-stack phase.

### Recommended Next Phase:
* **Phase 2**: Comprehensive E2E Testing, Attack Simulation Validation, Chaos/Failure Injection Testing, Live eBPF Sensor Profiling, and Security Audit Certification.
