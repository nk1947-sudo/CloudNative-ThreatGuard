# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] -- Truthful validation and evidence pipeline (2026-10-03)

### Fixed
- Admission runner counted any failed `kubectl apply` as a Gatekeeper block. Results are now classified `policy_denied`, `unexpectedly_allowed` or `execution_error`; only a response carrying the Gatekeeper webhook identity counts as a denial. A rejected compliant manifest, a missing manifest, an unreachable API or missing OPA can no longer produce a pass.
- The validation harness printed "27 Rego tests passed" and "6/6 detected" unconditionally. Every step now records PASS, FAIL, BLOCKED or SKIPPED, totals are derived from real inputs, and the exit code is 0 / 1 / 2.
- The orchestrator appended fixed events dated 2026-09-05 after every scenario, even against a live pod. Live mode reads the real Tetragon stream and never falls back to fixtures.
- A policy-enforced kill (exit 137) no longer ends the whole run; outcomes are decided per scenario from sensor evidence.
- Scenarios exec binaries directly instead of through `/bin/sh -c`, which the shell policy kills.
- `deploy-app.sh` no longer reports success when the rollout does not become ready; `install-security-stack.sh` fails on a Tetragon or target-pod rollout failure.
- The simulated risk input assumed `runAsUser: 0` for a UID 10001 target. Live runs read the effective pod security context; unknown settings are not scored; demo runs use a coherent simulated spec.
- Target pod now sets `runAsGroup: 10001`, disables ServiceAccount token mounting and starts `/bin/sleep` directly instead of a shell wrapper.
- Cluster and node defaults match the real KIND cluster (`threatguard-cluster`).
- The deployment runbook referenced paths that do not exist; rewritten against the real scripts.

### Added
- `runtime/collector.py`: bounded live Tetragon capture with source-identity deduplication, secret redaction, pod filtering and explicit degraded/unavailable states.
- `runtime/pipeline.py` and `simulations/scenario_catalog.json`: explicit `live` and `demo` modes, per-scenario outcomes (including a benign control), and a run manifest.
- Evidence provenance on every event (`evidence_mode`, `run_id`, `scenario_id`, `captured_at`, `observed_at`, `collector_version`). Demo events can never be reported as live.
- Scorecard reports origin, run id and capture time; separates scenario outcomes from rule coverage; rejects mixed-run evidence and flags stale evidence. Only a passing LIVE run has `live_acceptance: true`.
- Exporter: `origin` label, gauge semantics for snapshot counts, `threatguard_artifact_valid`, evidence age, collector health, and `/healthz`. Missing or corrupt evidence is visible instead of a zero.
- `threatguard verify` has `local` and `--live` scopes with PASS/FAIL/SKIP/BLOCKED states.
- `make network-test`: NetworkPolicy enforcement canary and connectivity matrix.
- Execve kprobe events are evaluated by the shell rule (RUNTIME-001).

### Network isolation and sensor diagnostics (follow-up)
- `deploy/kubernetes/kindnet-netpol.yaml` and a newer kindnet image make KIND enforce NetworkPolicy in place. On the tested cluster this passes 5 of 6 network-test cases; pod-to-node-address traffic (API server, kubelet) is still reachable.
- `CNI=calico bash scripts/setup-cluster.sh` creates a KIND cluster with Calico (`scripts/kind-config-calico.yaml`). Validated on a throwaway cluster: all 6 network-test cases pass, including blocking pod-to-API-server traffic.
- `make sensor-diagnose` compares the Tetragon sensor's policy counters with the export stream so a posted-but-not-exported gap is reported as such.
- Fixed the network check selecting its own probe pod as the application destination; `THREATGUARD_KUBE_CONTEXT` targets a specific cluster without changing the current context.

### Known limitations
- On KIND with Docker Desktop, Tetragon posts kprobe events but they are not exported (see `make sensor-diagnose` and `docs/operations/deployment-runbook.md`); SCEN-001, 004, 006 and 008 are reported failed with a diagnosis, not detected. Needs a Linux host or VM.
- KIND's default CNI does not enforce NetworkPolicy; the upgraded kindnet leaves node-destined traffic reachable. Use Calico for full enforcement.

## [Unreleased] -- Repository restructure (2026-09-05/07)

A full repository restructure into an installable Python package with a single canonical CLI,
consolidated deployment manifests, unified tests, and standard OSS repository files. Package version
bumped to `2.0.0` to reflect the scale of the structural and import-path changes.

### Added
- `pyproject.toml`: the project is now `pip install -e .`-able as `cloudnative-threatguard`, exposing a
  `threatguard` console script. `pydantic` and `PyYAML` are declared as explicit dependencies -- both
  were used throughout the codebase without ever being listed anywhere.
- `src/` layout: `src/cloudnative_threatguard/` with domain packages `admission/`, `runtime/`,
  `detection/`, `correlation/` (`kubernetes.py` for single-cluster grouping, `cross_domain/` for the
  CloudGraphGuard integration), `reporting/`, `cloudgraphguard/`, `observability/`, `config/`, `utils/`.
- `src/cloudnative_threatguard/admission/`: OPA subprocess client and manifest validator, extracted from
  the old standalone `validate_admission_manifests.py` script and exposed as `threatguard admission validate`.
- `src/cloudnative_threatguard/config/settings.py`: single source for the project root, artifacts
  directory, and default namespace/cluster/node names, replacing ~5 independently-recomputed copies.
- New `threatguard` CLI subcommands: `verify` (replaces `verify-all.py`/`.sh`), `demo cross-domain`
  (replaces `demo-cloud-security.py`), `admission validate`, `report scorecard` (replaces
  `scripts/generate-report.py`), `report evidence`.
- `deploy/kubernetes/namespace.yaml`: the `threatguard` namespace was previously only ever created
  imperatively (`kubectl create namespace ...`) inside two different shell scripts, never declared as
  an actual manifest.
- `RUNTIME-007` detection rule for known cryptocurrency-mining binaries (`xmrig`, `minerd`, `ccminer`,
  `cpuminer`, `cgminer`, `ethminer`), mapped to MITRE T1496.
- `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `SECURITY.md`, this `CHANGELOG.md`.
- `tests/integration/admission/test_manifest_validation.py`: the admission-manifest validation logic is
  now testable programmatically, not just runnable as a script.
- `tests/fixtures/tetragon_events.py`: shared sample raw Tetragon event builders.
- `app/secure-web-app/.dockerignore`, scoped to the sample app's own build context.
- `CrossDomainIncident.contributing_findings`: preserves each source event's own
  `source`/`event_type`/`severity`/`detection_rule`/`technique`/`evidence` through correlation,
  additive to the existing `evidence_summary` counts.
- Optional live Kubernetes ownership resolution for `threatguard remediate`: a new `--live-k8s` flag
  resolves a Pod's owning Deployment/StatefulSet/DaemonSet authoritatively via a read-only `kubectl get`
  lookup (`reporting/workload_resolver.py`'s `KubernetesOwnershipClient` protocol and
  `KubectlOwnershipClient`), including a real Pod -> ReplicaSet -> Deployment lookup instead of
  string-parsing the ReplicaSet name. Fully opt-in and dependency-injected -- every other command, and
  `remediate` without the flag, remain kubeconfig-free. `docs/security/kubernetes-ownership-rbac.md`
  documents the minimum required (read-only, namespace-scoped) RBAC.

### Changed
- Repository layout: `runtime/`, `correlation/`, `cloudgraphguard/` (three loose top-level Python
  packages) consolidated into `src/cloudnative_threatguard/`. `app/` -> `app/secure-web-app/`.
  `policies/gatekeeper/` -> `deploy/gatekeeper/`. `runtime/tetragon/` -> `deploy/tetragon/`.
  `screenshots/` -> `docs/assets/screenshots/{gatekeeper,runtime,testing,grafana,architecture}/`.
  `docs/*.md` split into `docs/{architecture,security,operations,development}/`.
- Tests unified under `tests/{unit,integration}/<domain>/`, replacing three inconsistent locations
  (`runtime/test_*.py`, `runtime/engine/test_*.py`, `correlation/tests/`).
- `docker-compose.yaml`: the exporter service now installs the package and runs via
  `python -m cloudnative_threatguard.observability.metrics_exporter`; all three services bind to
  `127.0.0.1` instead of every interface; the Grafana admin password is environment-overridable
  (`GRAFANA_ADMIN_PASSWORD`) instead of a bare hardcoded `admin`/`admin`.
- All shell scripts under `scripts/` and `simulations/run_simulations.sh` updated for the new paths and
  the new `threatguard` CLI.

### Fixed
- **Incident record schema mismatch**: `IncidentManager` produces incident dicts keyed by
  `affected_pod`/`affected_namespace`/`tactics`/`techniques`; the CLI and the executive-report renderer
  read a different, never-matching set of keys (`pod_name`/`namespace`/`mitre_tactics`/`mitre_techniques`).
  Every incident field rendered as `None`/blank in `threatguard incidents show`, `threatguard workloads`,
  `threatguard remediate`, and the generated executive audit report, regardless of the underlying data.
- **Missing `mitre_tactic`/`action` on detections**: the detection engine never forwarded a rule's
  `mitre_tactic` or a concrete `action` (`process_exec`/`file_read`/`net_connect`/`priv_escalation`) onto
  the `ThreatGuardDetection` objects it created from real telemetry, so `mitre_tactic` was always `''`
  and `action` always stayed at its `'detected'` default. This silently disabled multi-stage incident
  classification (every incident degraded to a single-event "Security Violation Burst", never "Multi-Stage
  Attack Chain", regardless of how many distinct tactics were actually involved) and broke the workload
  investigation dossier's event categorization (socket connections and file accesses undercounted to zero).
- **Undetected cryptominer scenario**: the attack-simulation suite runs a cryptominer scenario (SCEN-007)
  that no detection rule matched, producing zero detections end to end. Added `RUNTIME-007`.
- Investigation dossier metadata key mismatch: socket-connection extraction looked for `daddr`/`dport`/
  `proto` in event metadata; the detection engine actually writes `destination_ip`/`destination_port`/
  `protocol`. Destination IPs rendered as `"unknown"` even when the underlying detection had the data.
- `.gitignore`: `artifacts/threatguard-state.json` sits directly in `artifacts/` and wasn't covered by
  any existing rule (only subdirectories were ignored); added.
- **Hardcoded cross-domain Prometheus metrics**: `threatguard_cloud_iam_risks_total`,
  `threatguard_open_incidents_total`, and the rest of the "Cross-Domain Cloud Security Overview" block
  were static placeholder values. They're now derived from persisted `CrossDomainIncident` records via
  `reporting/cross_domain_metrics.py`, using correct Prometheus types (counter for
  `threatguard_cross_domain_correlations_total`, gauges for the rest) and bounded-cardinality
  (`severity`-only) labels.
- **Pod-name-vs-Deployment-name in remediation commands**: `reporting/recommendations.py` generated
  `kubectl patch/scale deployment <pod_name>` against a resource that doesn't exist, because a
  Deployment-managed Pod's name (`<deployment>-<hash>-<suffix>`) was used as if it were the Deployment's
  own name. `reporting/workload_resolver.py` now resolves the real owning controller (preferring
  `ownerReferences`, then an optional live lookup, then a documented naming-pattern fallback) and refuses
  to guess -- emitting a manual-remediation recommendation instead -- for Jobs/CronJobs, ambiguous owner
  data, or unrecognized standalone Pods.
- **NetworkPolicy quarantine selecting by Pod name**: the same engine's network-isolation recommendation
  built a `podSelector` from the unique Pod instance name, which no pod is ever labeled with, so it
  silently matched and quarantined nothing. It now selects by the resolved workload name.
- **Cross-domain metrics bucketed by incident severity, not each finding's own severity**:
  `iam_risks_by_severity`/`runtime_threats_by_severity` counted every contributing IAM/runtime finding
  under the incident's single aggregated severity, so a HIGH-severity incident with LOW/MEDIUM/HIGH source
  findings reported all of them as HIGH. `contributing_findings` (see Added) now preserves each finding's
  own severity through correlation, and both metrics bucket by it.
- `tests/unit/correlation/cross_domain/test_deterministic_demo.py` wrote a real cross-domain incident
  into the repo's actual `artifacts/forensics/` directory on every test run, silently accumulating state
  across CI runs; isolated behind a temporary directory.

### Removed
- `threatguard` (bash launcher), `threatguard.py` (shim) -- replaced by the installed `threatguard`
  console script.
- `verify-all.py`, `verify-all.sh` -- replaced by `threatguard verify`.
- `run_tests.py` -- replaced by `pytest` (wrapped by `make test`).
- `demo-cloud-security.py` -- replaced by `threatguard demo cross-domain`.
- `policies/gatekeeper/tests/validate_admission_manifests.py` -- logic moved into
  `src/cloudnative_threatguard/admission/validator.py`.
- `scripts/generate-report.py` -- logic moved into `src/cloudnative_threatguard/reporting/scorecard.py`,
  exposed as `threatguard report scorecard`.

### Known limitations carried forward
- `correlation/kubernetes.py` and `correlation/cross_domain/` remain two separate implementations with
  different event/severity models; unifying them is a larger semantic change than this pass covers.
- Live Kubernetes ownership resolution (`--live-k8s`) is opt-in and off by default; the incident schema
  `cmd_remediate` reads today has no `owner_references` field (raw Tetragon telemetry never carries owner
  metadata), so in practice the CLI's default path still resolves ownership via the naming-pattern
  fallback. It has been tested only against a mocked `KubernetesOwnershipClient`, never a real cluster.
