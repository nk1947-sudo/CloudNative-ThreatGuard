# CloudNative ThreatGuard — Security Verification Screenshots

This directory contains visual verification artifacts demonstrating the end-to-end operation of CloudNative ThreatGuard across admission control, runtime eBPF detection, microservice hardening, and Prometheus/Grafana observability. They are organized by security domain: `gatekeeper/`, `runtime/`, `testing/`, `grafana/`, and `architecture/`.

---

### Screenshot Catalog

| File | Description | Security Domain |
| :--- | :--- | :--- |
| [`gatekeeper/01-opa-rego-unit-tests-pass.png`](./gatekeeper/01-opa-rego-unit-tests-pass.png) | 27/27 static policy unit tests passing via `opa test` across all 8 Gatekeeper modules. | Pre-Deployment Admission |
| [`gatekeeper/02-gatekeeper-admission-negative-tests.png`](./gatekeeper/02-gatekeeper-admission-negative-tests.png) | Automated admission verification suite blocking 8/8 negative workloads and admitting compliant workloads. | Pre-Deployment Admission |
| [`runtime/03-correlation-engine-unit-tests.png`](./runtime/03-correlation-engine-unit-tests.png) | Unit test suite passing for the ThreatGuard eBPF detection/correlation and MITRE mapping engine. | Runtime Engine |
| [`runtime/04-attack-simulations-execution.png`](./runtime/04-attack-simulations-execution.png) | Execution of the post-exploitation attack scenarios with real-time correlation and detection. | Behavioral Attack Simulation |
| [`testing/05-security-scorecard-summary.png`](./testing/05-security-scorecard-summary.png) | Automated security scorecard output showing 100% admission enforcement and 100% runtime detection rate. | Automated Scorecard |
| [`grafana/06-grafana-security-operations-dashboard.png`](./grafana/06-grafana-security-operations-dashboard.png) | Live Grafana SecOps dashboard with 100% gauges, severity breakdown donut chart, and MITRE ATT&CK technique bars. | Security Observability |
| [`grafana/07-prometheus-grafana-alert-rules-firing.png`](./grafana/07-prometheus-grafana-alert-rules-firing.png) | Prometheus alerting rules evaluated in Grafana Alerting UI with critical runtime alert in `Firing` state. | Alerting & Incident Response |
| [`architecture/08-hardened-app-telemetry-nonroot.png`](./architecture/08-hardened-app-telemetry-nonroot.png) | `/api/v1/telemetry` response proving non-root unprivileged container execution (`uid: 10001`, `gid: 10001`). | Workload Hardening |
| [`architecture/09-hardened-app-healthz-probe.png`](./architecture/09-hardened-app-healthz-probe.png) | `/healthz` liveness probe endpoint returning active status and container uptime. | Workload Health |
| [`architecture/10-hardened-app-security-profile.png`](./architecture/10-hardened-app-security-profile.png) | Root endpoint `/` displaying enforced zero-trust controls (non-root, read-only rootfs, dropped capabilities). | Workload Hardening |
