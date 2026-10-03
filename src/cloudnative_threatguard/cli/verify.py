"""
Platform verification for CloudNative ThreatGuard (``threatguard verify``).

Two explicit scopes, so the summary never implies more than was tested:

* ``local`` (default)  Static and in-process checks: tool availability,
  policy definitions on disk, the test suite, the CLI, the exporter and the
  sample app through Flask's test client. Nothing here proves a deployed
  cluster works, and every result is labelled ``local``.
* ``live`` (``--live``) Queries the running cluster: readiness, Gatekeeper
  and Tetragon state, the deployed sample service over HTTP (through the API
  server's service proxy) and Prometheus's scrape target state.

Each check ends in PASS, FAIL, SKIP or BLOCKED. Only PASS counts as success:
a skipped check stays visible, and a check whose prerequisite is missing is
BLOCKED rather than passed. Exit code: 0 no failures or blocks, 1 a failure,
2 blocked.

This replaces the standalone verify-all.py / verify-all.sh scripts.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from cloudnative_threatguard.config import settings

PROMETHEUS_URL = os.environ.get("THREATGUARD_PROMETHEUS_URL", "http://127.0.0.1:9090")
SAMPLE_SERVICE = "threatguard-app-service"
SAMPLE_PORT = 8080
SAMPLE_ENDPOINTS = ("/healthz", "/readyz", "/api/v1/telemetry")


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    BLOCKED = "BLOCKED"


@dataclass
class VerificationResult:
    name: str
    category: str
    status: Status
    details: str = ""
    duration_ms: float = 0.0
    scope: str = "local"

    @property
    def passed(self) -> bool:
        return self.status is Status.PASS


Runner = Callable[[list[str]], tuple[int, str]]


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]} timed out"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _timed(fn: Callable[[], VerificationResult]) -> VerificationResult:
    start = time.time()
    result = fn()
    result.duration_ms = (time.time() - start) * 1000
    return result


# --------------------------------------------------------------------------
# Local checks
# --------------------------------------------------------------------------

def _check_prerequisites(run: Runner = _run) -> list[VerificationResult]:
    results = []

    ok = sys.version_info >= (3, 10)
    results.append(VerificationResult(
        "Python 3.10+ Runtime", "Prerequisites", Status.PASS if ok else Status.FAIL,
        f"Python {sys.version.split()[0]}"))

    if not shutil.which("docker"):
        results.append(VerificationResult("Docker Engine", "Prerequisites", Status.BLOCKED, "docker CLI not found in PATH"))
    else:
        # The CLI being present does not mean the daemon is reachable.
        code, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
        results.append(VerificationResult(
            "Docker Engine", "Prerequisites", Status.PASS if code == 0 else Status.BLOCKED,
            f"daemon reachable (server {out})" if code == 0 else f"CLI present but daemon unreachable: {out[:120]}"))

    if not shutil.which("kubectl"):
        results.append(VerificationResult("Kubectl CLI", "Prerequisites", Status.SKIP,
                                          "kubectl not installed; live checks are unavailable"))
    else:
        results.append(VerificationResult("Kubectl CLI", "Prerequisites", Status.PASS, "kubectl available"))
    return results


def _count_files(directory) -> int:
    return len(list(directory.iterdir())) if directory.is_dir() else 0


def _check_policies() -> list[VerificationResult]:
    root = settings.PROJECT_ROOT / "deploy"
    specs = [
        ("OPA Gatekeeper ConstraintTemplates (files)", root / "gatekeeper" / "templates", 4),
        ("OPA Gatekeeper Constraints (files)", root / "gatekeeper" / "constraints", 4),
        ("Tetragon TracingPolicies (files)", root / "tetragon" / "policies", 6),
    ]
    results = []
    for name, directory, minimum in specs:
        count = _count_files(directory)
        results.append(VerificationResult(
            name, "Policies", Status.PASS if count >= minimum else Status.FAIL,
            f"{count} definition file(s) on disk (not proof they are active in a cluster)"))
    return results


def _check_tests() -> list[VerificationResult]:
    def run_tests() -> VerificationResult:
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(settings.PROJECT_ROOT / "tests"), "-q"],
                cwd=str(settings.PROJECT_ROOT), capture_output=True, text=True, timeout=300,
            )
        except Exception as exc:
            return VerificationResult("Full pytest suite (tests/)", "Testing", Status.FAIL, f"Test execution error: {exc}")
        summary = next((ln for ln in reversed(proc.stdout.splitlines()) if ln.strip()), proc.stdout[-200:])
        status = Status.PASS if proc.returncode == 0 else Status.FAIL
        return VerificationResult("Full pytest suite (tests/)", "Testing", status, summary)

    return [_timed(run_tests)]


def _check_cli() -> list[VerificationResult]:
    def check() -> VerificationResult:
        try:
            # Deferred import: cli.main imports this module for the 'verify' subcommand.
            from cloudnative_threatguard.cli.main import main as cli_main
        except Exception as exc:
            return VerificationResult("ThreatGuard Operator CLI", "Operator Tools", Status.FAIL, f"CLI import failure: {exc}")
        orig_argv = sys.argv
        sys.argv = ["threatguard", "--help"]
        try:
            cli_main()
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        finally:
            sys.argv = orig_argv
        return VerificationResult(
            "ThreatGuard Operator CLI", "Operator Tools", Status.PASS if code == 0 else Status.FAIL,
            "--help exited 0" if code == 0 else f"--help exited {code}")

    return [_timed(check)]


def _check_exporter_and_dashboard() -> list[VerificationResult]:
    results = []

    def exporter() -> VerificationResult:
        try:
            from cloudnative_threatguard.observability.metrics_exporter import render_metrics
            text = render_metrics()
        except Exception as exc:
            return VerificationResult("Metrics Exporter (renderer)", "Observability", Status.FAIL, f"Exporter error: {exc}")
        needed = ("threatguard_artifact_valid", "threatguard_evidence_info", "threatguard_collector_up")
        missing = [m for m in needed if m not in text]
        return VerificationResult(
            "Metrics Exporter (renderer)", "Observability", Status.PASS if not missing else Status.FAIL,
            "renders evidence-health series (in-process; not the running exporter)" if not missing else f"missing series: {missing}")

    results.append(_timed(exporter))

    def dashboard() -> VerificationResult:
        path = settings.PROJECT_ROOT / "observability" / "grafana" / "dashboards" / "threatguard-security-operations.json"
        if not path.is_file():
            return VerificationResult("Grafana Dashboard (definition)", "Observability", Status.FAIL, "dashboard JSON not found")
        try:
            panels = json.loads(path.read_text(encoding="utf-8")).get("panels", [])
        except json.JSONDecodeError as exc:
            return VerificationResult("Grafana Dashboard (definition)", "Observability", Status.FAIL, f"JSON parse error: {exc}")
        return VerificationResult("Grafana Dashboard (definition)", "Observability",
                                  Status.PASS if panels else Status.FAIL, f"{len(panels)} panel(s) defined in JSON")

    results.append(_timed(dashboard))
    return results


def _check_sample_app_locally() -> list[VerificationResult]:
    """Exercises every advertised endpoint through Flask's test client (not a deployed service)."""

    def check() -> VerificationResult:
        name = "Sample Microservice (Flask test client)"
        app_file = settings.PROJECT_ROOT / "app" / "secure-web-app" / "src" / "app.py"
        if not app_file.exists():
            return VerificationResult(name, "Workloads", Status.FAIL, f"source not found at {app_file}")
        try:
            spec = importlib.util.spec_from_file_location("threatguard_sample_app", app_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except ModuleNotFoundError as exc:
            return VerificationResult(name, "Workloads", Status.SKIP,
                                      f"{exc}; install app/secure-web-app/src/requirements.txt to test the app")
        except Exception as exc:
            return VerificationResult(name, "Workloads", Status.FAIL, f"app import error: {exc}")
        client = module.app.test_client()
        failures = [f"{p} -> {client.get(p).status_code}" for p in SAMPLE_ENDPOINTS if client.get(p).status_code != 200]
        return VerificationResult(
            name, "Workloads", Status.PASS if not failures else Status.FAIL,
            f"{', '.join(SAMPLE_ENDPOINTS)} returned 200" if not failures else "; ".join(failures))

    return [_timed(check)]


def _check_evidence_collection() -> list[VerificationResult]:
    def check() -> VerificationResult:
        name = "Forensic Evidence Collector"
        try:
            from cloudnative_threatguard.reporting.evidence import ForensicEvidenceCollector
            files = ForensicEvidenceCollector().generate_evidence_package()
        except Exception as exc:
            return VerificationResult(name, "Forensics & Audit", Status.FAIL, f"Evidence collection error: {exc}")
        ok = bool(files) and all(os.path.exists(p) for p in files.values())
        return VerificationResult(name, "Forensics & Audit", Status.PASS if ok else Status.FAIL,
                                  f"generated {len(files)} file(s)" if ok else "an evidence artifact was not generated")

    return [_timed(check)]


def run_local_checks() -> list[VerificationResult]:
    results: list[VerificationResult] = []
    results += _check_prerequisites()
    results += _check_policies()
    results += _check_tests()
    results += _check_cli()
    results += _check_exporter_and_dashboard()
    results += _check_sample_app_locally()
    results += _check_evidence_collection()
    return results


# --------------------------------------------------------------------------
# Live checks
# --------------------------------------------------------------------------

def _live(name: str, category: str, status: Status, details: str) -> VerificationResult:
    return VerificationResult(name, category, status, details, scope="live")


def run_live_checks(run: Runner = _run, http_get: Callable[[str], tuple[int, str]] | None = None) -> list[VerificationResult]:
    http_get = http_get or _http_get
    results: list[VerificationResult] = []

    code, out = run(["kubectl", "cluster-info"])
    if code != 0:
        return [_live("Kubernetes API", "Cluster", Status.BLOCKED, f"cluster unreachable: {out[:120]}")]
    results.append(_live("Kubernetes API", "Cluster", Status.PASS, "cluster-info succeeded"))

    code, out = run(["kubectl", "get", "nodes", "-o", "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{' '}{end}"])
    ready = out.split()
    ok = code == 0 and bool(ready) and all(s == "True" for s in ready)
    results.append(_live("Cluster nodes Ready", "Cluster", Status.PASS if ok else Status.FAIL,
                         f"{ready.count('True')}/{len(ready)} node(s) Ready" if code == 0 else out[:120]))

    code, out = run(["kubectl", "get", "crd", "constrainttemplates.templates.gatekeeper.sh"])
    if code != 0:
        results.append(_live("Gatekeeper admission", "Admission", Status.BLOCKED, "Gatekeeper CRDs not installed"))
    else:
        code, out = run(["kubectl", "rollout", "status", "deployment/gatekeeper-controller-manager",
                         "-n", "gatekeeper-system", "--timeout=30s"])
        results.append(_live("Gatekeeper controller", "Admission", Status.PASS if code == 0 else Status.FAIL,
                             "controller rolled out" if code == 0 else out[:120]))
        code, out = run(["kubectl", "get", "constrainttemplates", "-o", "name"])
        count = len(out.splitlines()) if code == 0 and out else 0
        results.append(_live("Gatekeeper ConstraintTemplates (active)", "Admission",
                             Status.PASS if count >= 4 else Status.FAIL, f"{count} template(s) active in the cluster"))

    code, out = run(["kubectl", "rollout", "status", "ds/tetragon", "-n", "tetragon", "--timeout=30s"])
    results.append(_live("Tetragon DaemonSet", "Runtime", Status.PASS if code == 0 else Status.BLOCKED,
                         "DaemonSet rolled out" if code == 0 else out[:120]))
    code, out = run(["kubectl", "get", "tracingpolicy", "-o", "name"])
    count = len(out.splitlines()) if code == 0 and out else 0
    results.append(_live("Tetragon TracingPolicies (active)", "Runtime", Status.PASS if count >= 6 else Status.FAIL,
                         f"{count} policy(ies) active in the cluster"))

    for endpoint in SAMPLE_ENDPOINTS:
        path = f"/api/v1/namespaces/threatguard/services/{SAMPLE_SERVICE}:{SAMPLE_PORT}/proxy{endpoint}"
        code, out = run(["kubectl", "get", "--raw", path])
        results.append(_live(f"Deployed service {endpoint}", "Workloads", Status.PASS if code == 0 else Status.FAIL,
                             "HTTP 200 via the API server service proxy" if code == 0 else out[:120]))

    try:
        status, body = http_get(f"{PROMETHEUS_URL}/api/v1/targets")
    except (urllib.error.URLError, OSError) as exc:
        results.append(_live("Prometheus scrape target", "Observability", Status.BLOCKED,
                             f"Prometheus unreachable at {PROMETHEUS_URL}: {exc}"))
    else:
        try:
            targets = json.loads(body)["data"]["activeTargets"]
        except (json.JSONDecodeError, KeyError):
            targets = []
        threatguard = [t for t in targets if "threatguard" in json.dumps(t.get("labels", {}))]
        up = [t for t in threatguard if t.get("health") == "up"]
        ok = status == 200 and bool(threatguard) and len(up) == len(threatguard)
        results.append(_live("Prometheus scrape target", "Observability", Status.PASS if ok else Status.FAIL,
                             f"{len(up)}/{len(threatguard)} threatguard target(s) up"))
    return results


def _http_get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - fixed local URL
        return resp.status, resp.read().decode("utf-8")


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def exit_code_for(results: list[VerificationResult]) -> int:
    if any(r.status is Status.FAIL for r in results):
        return 1
    if any(r.status is Status.BLOCKED for r in results):
        return 2
    return 0


def print_results(results: list[VerificationResult], scope: str) -> None:
    print("\n" + "=" * 90)
    print(f"{'Scope':<6} | {'Category':<16} | {'Check':<40} | {'Status':<8} | {'Latency':<8}")
    print("-" * 90)
    for res in results:
        print(f"{res.scope:<6} | {res.category:<16} | {res.name:<40} | {res.status.value:<8} | {res.duration_ms:.0f}ms")
        if res.details:
            print(f"   |- {res.details}")
    counts = {s: sum(r.status is s for r in results) for s in Status}
    print("=" * 90)
    print(f"VERIFICATION SUMMARY ({scope}): {counts[Status.PASS]} passed, {counts[Status.FAIL]} failed, {counts[Status.SKIP]} skipped, {counts[Status.BLOCKED]} blocked (total {len(results)})")
    code = exit_code_for(results)
    if code == 0 and counts[Status.SKIP] == 0:
        verdict = "all checks passed"
    elif code == 0:
        verdict = "no failures, but some checks were skipped (see above)"
    elif code == 1:
        verdict = "FAILED"
    else:
        verdict = "BLOCKED: prerequisites missing, verification incomplete"
    print(f"RESULT: {verdict}")
    if scope == "local":
        print("NOTE: local checks do not prove a running cluster works; use 'threatguard verify --live'.")
    print("=" * 90)


def run_verification(live: bool = False) -> int:
    scope = "live" if live else "local"
    print("=" * 90)
    print(f" CLOUDNATIVE THREATGUARD -- PLATFORM VERIFICATION ({scope.upper()})")
    print("=" * 90)
    results = run_live_checks() if live else run_local_checks()
    print_results(results, scope)
    return exit_code_for(results)
