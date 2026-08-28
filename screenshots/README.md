# CloudNative ThreatGuard — Security Verification Screenshots

This directory contains visual verification artifacts demonstrating the end-to-end operation of CloudNative ThreatGuard across admission control, runtime eBPF detection, microservice hardening, and Prometheus/Grafana observability.

---

### Screenshot Catalog

| File | Description | Security Domain |
| :--- | :--- | :--- |
| [`01-opa-rego-unit-tests-pass.png`](./01-opa-rego-unit-tests-pass.png) | 27/27 static policy unit tests passing via `opa test` across all 8 Gatekeeper modules. | Pre-Deployment Admission |
| [`02-gatekeeper-admission-negative-tests.png`](./02-gatekeeper-admission-negative-tests.png) | Automated admission verification suite blocking 8/8 negative workloads and admitting compliant workloads. | Pre-Deployment Admission |
| [`03-correlation-engine-unit-tests.png`](./03-correlation-engine-unit-tests.png) | Unit test suite passing 7/7 tests for the ThreatGuard eBPF correlation and MITRE mapping engine. | Runtime Engine |
| [`04-attack-simulations-execution.png`](./04-attack-simulations-execution.png) | Execution of all 6 post-exploitation attack scenarios with real-time correlation and detection. | Behavioral Attack Simulation |
| [`05-security-scorecard-summary.png`](./05-security-scorecard-summary.png) | Automated security scorecard output showing 100% admission enforcement and 100% runtime detection rate. | Automated Scorecard |
| [`06-grafana-security-operations-dashboard.png`](./06-grafana-security-operations-dashboard.png) | Live Grafana SecOps dashboard with 100% gauges, severity breakdown donut chart, and MITRE ATT&CK technique bars. | Security Observability |
| [`07-prometheus-grafana-alert-rules-firing.png`](./07-prometheus-grafana-alert-rules-firing.png) | Prometheus alerting rules evaluated in Grafana Alerting UI with critical runtime alert in `Firing` state. | Alerting & Incident Response |
| [`08-hardened-app-telemetry-nonroot.png`](./08-hardened-app-telemetry-nonroot.png) | `/api/v1/telemetry` response proving non-root unprivileged container execution (`uid: 10001`, `gid: 10001`). | Workload Hardening |
| [`09-hardened-app-healthz-probe.png`](./09-hardened-app-healthz-probe.png) | `/healthz` liveness probe endpoint returning active status and container uptime. | Workload Health |
| [`10-hardened-app-security-profile.png`](./10-hardened-app-security-profile.png) | Root endpoint `/` displaying enforced zero-trust controls (non-root, read-only rootfs, dropped capabilities). | Workload Hardening |
