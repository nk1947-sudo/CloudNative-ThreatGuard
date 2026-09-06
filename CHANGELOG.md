# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased] -- Repository restructure (2026-09-05/06)

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

### Known limitations carried forward (not fixed in this pass)
- `observability/metrics_exporter.py`'s "Cross-Domain Cloud Security Overview" Prometheus metrics
  (`threatguard_cloud_iam_risks_total`, `threatguard_open_incidents_total`, etc.) are still static
  placeholder values, not derived from any evidence file -- flagged inline with a comment.
- `reporting/recommendations.py`'s generated `kubectl patch/scale deployment <pod_name>` commands still
  use the raw pod name rather than resolving the owning Deployment name.
- `correlation/kubernetes.py` and `correlation/cross_domain/` remain two separate implementations with
  different event/severity models; unifying them is a larger semantic change than this pass covers.
