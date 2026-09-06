# Contributing to CloudNative ThreatGuard

Thanks for your interest in improving CloudNative ThreatGuard. This is a Kubernetes defense-in-depth
security lab combining OPA Gatekeeper admission control, Cilium Tetragon eBPF runtime detection, and
a cross-domain (AWS IAM + Kubernetes) correlation engine. This guide covers everything you need to get
a development environment running and submit a change.

## Development setup

**Requirements:** Python 3.10+, Docker (for the KIND cluster and container builds), `kubectl`, and
optionally `kind`, `helm`, and `opa` for the full cluster lab (see [docs/development/cross-platform-guide.md](docs/development/cross-platform-guide.md)
for Windows/WSL2/macOS specifics).

```bash
git clone https://github.com/cloudnative-threatguard/cloudnative-threatguard.git
cd cloudnative-threatguard
python -m venv .venv
source .venv/bin/activate      # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

This installs the `cloudnative_threatguard` package in editable mode plus `pytest` and `ruff`, and
exposes the `threatguard` command on your PATH.

The sample hardened microservice under `app/secure-web-app/` has its own, separate dependency surface
(`app/secure-web-app/src/requirements.txt`) since it's built and deployed as its own container image,
not part of the main package:

```bash
pip install -r app/secure-web-app/src/requirements.txt
```

## Running the test suite

```bash
pytest                  # or: make test
pytest tests/unit       # fast, no external tools required
pytest tests/integration -k admission   # requires an opa binary on PATH or ./opa.exe
```

Tests are organized as `tests/unit/<domain>/` and `tests/integration/<domain>/`, mirroring
`src/cloudnative_threatguard/<domain>/`. Put a test in `unit/` if it exercises one module in isolation;
put it in `integration/` if it chains multiple modules together, touches the filesystem, or shells out
to an external tool (OPA, kubectl). Shared sample payloads (e.g. raw Tetragon events) belong in
`tests/fixtures/` rather than being redefined in every test file.

## Linting and formatting

```bash
ruff check src tests    # or: make lint
ruff format src tests   # or: make format
```

## Kubernetes test environment

The full security lab (KIND cluster, Gatekeeper, Tetragon, the sample app) is orchestrated through the
Makefile and the scripts under `scripts/`:

```bash
make cluster            # provision a local KIND cluster with eBPF mounts
make install-security   # install Gatekeeper + Tetragon + policies
make deploy             # build and deploy the hardened sample app
make security-test      # run the full 11-step validation pipeline
make cluster-down       # tear the cluster down
```

See [docs/operations/deployment-runbook.md](docs/operations/deployment-runbook.md) and
[docs/operations/troubleshooting.md](docs/operations/troubleshooting.md) if something doesn't come up cleanly.

## Developing admission policies (OPA Gatekeeper)

Rego source lives in `deploy/gatekeeper/src/`, `ConstraintTemplate`/`Constraint` manifests in
`deploy/gatekeeper/{templates,constraints}/`, and tests in `deploy/gatekeeper/tests/`
(`rego/` for `opa test` unit tests, `manifests/{positive,negative}/` for end-to-end manifest fixtures).

```bash
opa test deploy/gatekeeper/src deploy/gatekeeper/tests/rego -v   # or: make test-admission
threatguard admission validate                                   # exercises the actual manifests via OPA eval
```

Every new constraint should ship with: a Rego unit test in `deploy/gatekeeper/tests/rego/`, a negative
manifest under `deploy/gatekeeper/tests/manifests/negative/` that the constraint is expected to block,
and an entry in `POLICIES` in `src/cloudnative_threatguard/admission/validator.py` mapping the manifest
to its constraint package and expected violation message.

## Developing runtime detection rules

Detection rules live in `src/cloudnative_threatguard/detection/rules.py` (the `RuleRegistry`); the raw
Tetragon-event-to-detection matching logic is in `src/cloudnative_threatguard/detection/engine.py`.
When adding a rule:

1. Add a `DetectionRule` to `RuleRegistry._initialize_default_rules()` with a unique `rule_id`, a real
   `mitre_technique`/`mitre_tactic` pair, and `target_binaries` or `target_paths`.
2. Wire the matching branch into `DetectionEngine._handle_process_exec` or `_handle_kprobe`, making sure
   to pass `tactic=` and a concrete `action=` (not just `technique=`/`rule_id=`) -- a prior version of
   this engine silently dropped `mitre_tactic` on every detection because these weren't forwarded, which
   broke multi-stage incident classification. See `tests/unit/detection/test_engine.py` for the pattern
   each rule's test should follow, including asserting on `.tactic` and `.action`.
3. If the corresponding TracingPolicy doesn't exist yet, add it under `deploy/tetragon/policies/`.

## Pull request expectations

- Keep PRs focused on one change; large refactors should be discussed first via an issue.
- Add or update tests for any behavior change -- a bug fix without a regression test is easy to
  reintroduce.
- Run `pytest` and `ruff check` locally before opening a PR; CI runs the same checks.
- Update the relevant doc under `docs/` if you change a command, a file layout, or a public interface.
- Add an entry to `CHANGELOG.md` under `[Unreleased]`.
