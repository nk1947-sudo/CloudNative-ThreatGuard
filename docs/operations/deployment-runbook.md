# CloudNative ThreatGuard — Operational Deployment Runbook

Step-by-step procedures for provisioning, validating and operating CloudNative ThreatGuard on a local KIND cluster. Every path and command below exists in this repository; the scripts in `scripts/` are the source of truth.

Names used throughout: cluster `threatguard-cluster`, namespace `threatguard`, target pod `threatguard-target-pod`.

---

## 1. Prerequisites

| Tool | Minimum Version | Verification Command | Purpose |
| :--- | :--- | :--- | :--- |
| Docker Desktop / Engine | 24.0+ | `docker info` | Container runtime (the daemon must be running) |
| KIND | 0.20.0+ | `kind --version` | Local Kubernetes cluster |
| kubectl | 1.28.0+ | `kubectl version --client` | Kubernetes API client |
| Helm | 3.x | `helm version` | Installs Tetragon |
| Python | 3.10+ | `python --version` | ThreatGuard engine and CLI |
| OPA | 0.60+ | `opa version` (or `opa.exe` at the repo root) | Rego unit tests |

eBPF enforcement needs a Linux kernel with BTF. On Docker Desktop the sensor runs inside the Docker VM kernel; see the limitations in section 7.

Install the package once:

```bash
pip install -e ".[dev]"
```

---

## 2. Provision the cluster

```bash
make cluster-up        # runs scripts/setup-cluster.sh with scripts/kind-config.yaml
kubectl get nodes -o wide
```

The node must be `Ready`.

## 3. Install Gatekeeper, Tetragon and the policies

```bash
make install-security  # runs scripts/install-security-stack.sh
```

This installs Gatekeeper, applies the ConstraintTemplates and Constraints from `deploy/gatekeeper/`, installs Tetragon with `deploy/tetragon/values.yaml`, applies the TracingPolicies from `deploy/tetragon/policies/`, and finally creates the simulation target pod from `simulations/manifests/test-pod.yaml`. The script exits non-zero if a rollout fails.

Verify what is actually active in the cluster:

```bash
kubectl get constrainttemplates
kubectl get tracingpolicy
kubectl get pod -n threatguard threatguard-target-pod
```

## 4. Deploy the protected sample application

```bash
make deploy            # runs scripts/deploy-app.sh
```

The script builds the image, loads it into KIND, applies the NetworkPolicy, Service and Deployment, and fails if the rollout does not become ready.

## 5. Validate

There are three distinct levels. Each reports what it did and did not test.

```bash
make verify            # local: static files, test suite, in-process checks (no cluster claim)
make verify-live       # live: cluster, Gatekeeper, Tetragon, deployed service, Prometheus
make security-test     # live 11-step validation; exits 2 (BLOCKED) if prerequisites are missing
make security-test-demo  # simulated: fixtures only, labelled SIMULATED, never live acceptance
```

Exit codes for the validation scripts: `0` everything passed, `1` something failed, `2` blocked by a missing prerequisite. A skipped or blocked check is never reported as a pass.

Individual stages:

```bash
make test-admission    # Rego unit tests and offline manifest evaluation
make simulate          # live attack scenarios, evaluated from real sensor events
make network-test      # NetworkPolicy enforcement canary and connectivity matrix
```

### Reading the result

`artifacts/security-report.json` contains `overall_status` (`PASS`, `FAIL`, `INCOMPLETE`, `STALE`), `origin` (`LIVE` or `SIMULATED`), the `run_id` and capture time, and per-scenario outcomes. Only a passing `LIVE` report has `live_acceptance: true`. Evidence from a different run, or older than 24 hours (`THREATGUARD_MAX_EVIDENCE_AGE_HOURS`), is reported as `INCOMPLETE` or `STALE`.

## 6. Observability

```bash
docker compose up -d   # exporter on 127.0.0.1:9100, Prometheus, Grafana
```

- Exporter: `http://127.0.0.1:9100/metrics` (health: `/healthz`)
- Prometheus: `http://127.0.0.1:9090/targets`
- Grafana: `http://127.0.0.1:3000` (dashboard `threatguard-secops`)

The exporter labels admission and runtime series with `origin` (`live`, `demo`, `unknown`) and exposes `threatguard_artifact_valid`, `threatguard_evidence_age_seconds` and `threatguard_collector_up`. Missing or corrupt evidence appears as `artifact_valid 0`, not as a zero count.

Supported operational interfaces: Grafana and the `threatguard` CLI. `observability/dashboard/unified_dashboard.html` is an illustrative static page with fixed sample data and says so in its banner.

## 7. Known limitations

- **Kprobe events on Docker Desktop.** In the KIND-on-Docker-Desktop setup tested, Tetragon exported `process_exec` events only. Shell-block, file-open and connect events never reached the export stream, so SCEN-001, 004, 006 and 008 fail with an explicit diagnosis instead of being counted as detected. `make sensor-diagnose` compares the sensor's own counters with the export stream and reproduces the gap: after a probe, `tetra tracingpolicy list` shows events posted and the shell policy enforcing (`NPOST`/`NENFORCE` moved) while no kprobe event is exported. Removing the empty-namespace entry from the export denylist did not change this (tested, then reverted), and an event captured straight from the agent's gRPC stream had no process or pod attached. The agent also logs `procfs does not appear to be host procfs`. The working explanation is that the agent cannot resolve host PIDs from the KIND node's nested PID namespace, so unattributable kprobe events are dropped; that is an inference, not a confirmed root cause. It could not be fixed on this machine. Run `make security-test` on a Linux host or VM where the agent sees the host procfs to exercise those scenarios.
- **NetworkPolicy enforcement depends on the CNI.** KIND's default kindnet (`v20240202`) does not enforce policies. Upgrading it in place (`deploy/kubernetes/kindnet-netpol.yaml`) enforces pod and internet egress and ingress, but a pod can still reach the node's own address (API server, kubelet). Calico (`CNI=calico bash scripts/setup-cluster.sh`, which creates a new cluster) passed all six `make network-test` cases. See `docs/security/network-security.md`.
- **Simulated inputs.** The cloud IAM correlation uses fixed local inputs; no cloud account is queried.
