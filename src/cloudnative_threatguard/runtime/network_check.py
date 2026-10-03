"""
NetworkPolicy behaviour verification.

A NetworkPolicy object existing is not proof that traffic is filtered: the
cluster's CNI plugin must enforce it. This check therefore runs in two
stages and records connection outcomes independently of what Tetragon
observed:

1. Canary: in a throwaway namespace, prove the CNI enforces policies at all.
   Traffic must flow before a deny-all policy exists and be refused after.
   If the baseline fails, or traffic still flows after the policy, the matrix
   is not run and the result is BLOCKED rather than a false pass or fail.
2. Matrix: probe pods exercise each allowance and denial the project's
   NetworkPolicy claims. Every case records source, destination and a
   bounded timeout.

Exit codes: 0 every case matched, 1 a case did not match, 2 blocked.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_BLOCKED = 2

APP_NAMESPACE = "threatguard"
CANARY_NAMESPACE = "tg-netpol-canary"
PROBE_NAMESPACE = "tg-netpol-probe"
APP_LABEL = "threatguard-app"
APP_PORT = 8080
CONNECT_TIMEOUT = 3
IMAGE = "alpine:3.20"
POD_READY_TIMEOUT = "90s"

Runner = Callable[[list[str], str | None], tuple[int, str]]


def kubectl(args: list[str], stdin: str | None = None) -> tuple[int, str]:
    # THREATGUARD_KUBE_CONTEXT targets a specific cluster without changing the
    # user's current kubectl context.
    context = os.environ.get("THREATGUARD_KUBE_CONTEXT")
    base = ["kubectl", *(["--context", context] if context else [])]
    try:
        proc = subprocess.run(
            [*base, *args], input=stdin, capture_output=True, text=True, timeout=120, check=False
        )
    except FileNotFoundError:
        return 127, "kubectl not found"
    except subprocess.TimeoutExpired:
        return 124, "kubectl timed out"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def hardened_pod(name: str, namespace: str, labels: dict[str, str], command: list[str]) -> dict[str, Any]:
    """A pod that satisfies the cluster's admission policies (non-root, read-only rootfs, no caps)."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": {"security.threatguard.io/purpose": "netpol-test", **labels}},
        "spec": {
            "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "probe", "image": IMAGE, "imagePullPolicy": "IfNotPresent", "command": command,
                "securityContext": {"allowPrivilegeEscalation": False, "privileged": False,
                                    "readOnlyRootFilesystem": True, "runAsNonRoot": True, "runAsUser": 10001,
                                    "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
                "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}, "requests": {"cpu": "20m", "memory": "32Mi"}},
            }],
        },
    }


def listener_command() -> list[str]:
    # busybox nc: -ll keeps listening after each connection; -e runs /bin/true per connection.
    return ["/bin/busybox", "nc", "-ll", "-p", str(APP_PORT), "-e", "/bin/true"]


def sleeper_command() -> list[str]:
    return ["/bin/sleep", "3600"]


@dataclass
class CaseResult:
    case: str
    source: str
    destination: str
    expected: str  # allow | deny
    observed: str  # connected | failed
    matched: bool
    timeout_seconds: int = CONNECT_TIMEOUT
    detail: str = ""


class NetworkChecker:
    def __init__(self, run: Runner = kubectl, sleep: Callable[[float], None] = time.sleep):
        self.run = run
        self.sleep = sleep
        self.created: list[tuple[str, str, str]] = []  # (kind, name, namespace)

    # -- plumbing ---------------------------------------------------------

    def apply(self, manifest: dict[str, Any]) -> tuple[int, str]:
        code, out = self.run(["apply", "-f", "-"], json.dumps(manifest))
        if code == 0:
            meta = manifest["metadata"]
            self.created.append((manifest["kind"].lower(), meta["name"], meta.get("namespace", "")))
        return code, out

    def wait_ready(self, name: str, namespace: str) -> bool:
        code, _ = self.run(["wait", "--for=condition=Ready", f"pod/{name}", "-n", namespace,
                            f"--timeout={POD_READY_TIMEOUT}"], None)
        return code == 0

    def pod_ip(self, name: str, namespace: str) -> str:
        code, out = self.run(["get", "pod", name, "-n", namespace, "-o", "jsonpath={.status.podIP}"], None)
        return out.strip() if code == 0 else ""

    def connect(self, source: str, namespace: str, host: str, port: int) -> tuple[bool, str]:
        """True if a TCP connection from the source pod was established within the timeout."""
        code, out = self.run(["exec", "-n", namespace, source, "--", "/usr/bin/nc", "-z", "-w",
                              str(CONNECT_TIMEOUT), host, str(port)], None)
        return code == 0, out[:120]

    def resolves(self, source: str, namespace: str, name: str) -> tuple[bool, str]:
        code, out = self.run(["exec", "-n", namespace, source, "--", "/usr/bin/nslookup", "-timeout=3", name], None)
        return code == 0, out[:120]

    def cleanup(self) -> None:
        for kind, name, namespace in reversed(self.created):
            args = ["delete", kind, name, "--ignore-not-found", "--wait=false"]
            if namespace:
                args += ["-n", namespace]
            self.run(args, None)
        self.created.clear()

    # -- stage 1: does the CNI enforce policies? ---------------------------

    def canary(self) -> tuple[bool, str]:
        """Returns (enforced, explanation). Not enforced or untestable means the matrix must not run."""
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": CANARY_NAMESPACE}}
        code, out = self.apply(ns)
        if code != 0:
            return False, f"could not create canary namespace: {out[:100]}"
        labels = {"app": "canary-server"}
        for pod in (
            hardened_pod("canary-server", CANARY_NAMESPACE, labels, listener_command()),
            hardened_pod("canary-client", CANARY_NAMESPACE, {"app": "canary-client"}, sleeper_command()),
        ):
            code, out = self.apply(pod)
            if code != 0:
                return False, f"could not create {pod['metadata']['name']}: {out[:100]}"
        if not (self.wait_ready("canary-server", CANARY_NAMESPACE) and self.wait_ready("canary-client", CANARY_NAMESPACE)):
            return False, "canary pods did not become Ready"
        ip = self.pod_ip("canary-server", CANARY_NAMESPACE)
        if not ip:
            return False, "canary server has no pod IP"

        before, detail = self.connect("canary-client", CANARY_NAMESPACE, ip, APP_PORT)
        if not before:
            return False, f"baseline connection failed before any policy existed ({detail}); cannot test enforcement"

        deny_all = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "canary-deny-ingress", "namespace": CANARY_NAMESPACE},
            "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress"]},
        }
        code, out = self.apply(deny_all)
        if code != 0:
            return False, f"could not apply canary policy: {out[:100]}"
        # Policy programming is asynchronous in most CNIs; allow a bounded settle time.
        for _ in range(5):
            self.sleep(2)
            after, _ = self.connect("canary-client", CANARY_NAMESPACE, ip, APP_PORT)
            if not after:
                return True, "CNI enforces NetworkPolicy: traffic flowed before and was refused after a deny-all policy"
        return False, "traffic still flowed after a deny-all NetworkPolicy: the CNI does not enforce NetworkPolicy"

    # -- stage 2: the project's own policy claims --------------------------

    def matrix(self) -> list[CaseResult]:
        results: list[CaseResult] = []

        code, out = self.apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": PROBE_NAMESPACE}})
        pods = [
            # Selected by the project's NetworkPolicy (app=threatguard-app): used to test egress.
            hardened_pod("netpol-egress-probe", APP_NAMESPACE, {"app": APP_LABEL}, sleeper_command()),
            # Not selected by it: a same-namespace client for the ingress allowance.
            hardened_pod("netpol-client", APP_NAMESPACE, {"app": "netpol-client"}, sleeper_command()),
            # A client in another namespace for the ingress denial.
            hardened_pod("netpol-xns-client", PROBE_NAMESPACE, {"app": "netpol-client"}, sleeper_command()),
        ]
        for pod in pods:
            self.apply(pod)
        for pod in pods:
            meta = pod["metadata"]
            if not self.wait_ready(meta["name"], meta["namespace"]):
                results.append(CaseResult("setup", "-", meta["name"], "allow", "failed", False,
                                          detail="probe pod did not become Ready"))
        if results:
            return results

        # The probe pods also carry app=threatguard-app (so the policy selects them);
        # exclude them so the destination is a real application pod with a listener.
        code, out = self.run(["get", "pods", "-n", APP_NAMESPACE, "-l",
                              f"app={APP_LABEL},security.threatguard.io/purpose!=netpol-test",
                              "-o", "jsonpath={.items[*].status.podIP}"], None)
        app_ips = [ip for ip in out.split() if ip] if code == 0 else []
        if not app_ips:
            return [CaseResult("setup", "-", f"app={APP_LABEL}", "allow", "failed", False, detail="no running app pod found")]
        app_ip = app_ips[0]
        code, api_ip = self.run(["get", "svc", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}"], None)
        api_ip = api_ip.strip() if code == 0 else ""

        def add(case, source, destination, expected, ok, detail=""):
            observed = "connected" if ok else "failed"
            matched = ok if expected == "allow" else not ok
            results.append(CaseResult(case, source, destination, expected, observed, matched, detail=detail))

        ok, detail = self.connect("netpol-client", APP_NAMESPACE, app_ip, APP_PORT)
        add("ingress same-namespace to app:8080", f"{APP_NAMESPACE}/netpol-client", f"{app_ip}:{APP_PORT}", "allow", ok, detail)
        ok, detail = self.connect("netpol-xns-client", PROBE_NAMESPACE, app_ip, APP_PORT)
        add("ingress cross-namespace to app:8080", f"{PROBE_NAMESPACE}/netpol-xns-client", f"{app_ip}:{APP_PORT}", "deny", ok, detail)
        ok, detail = self.resolves("netpol-egress-probe", APP_NAMESPACE, "kubernetes.default.svc.cluster.local")
        add("egress DNS to CoreDNS", f"{APP_NAMESPACE}/netpol-egress-probe", "kube-dns:53", "allow", ok, detail)
        ok, detail = self.connect("netpol-egress-probe", APP_NAMESPACE, "1.1.1.1", 443)
        add("egress to the internet", f"{APP_NAMESPACE}/netpol-egress-probe", "1.1.1.1:443", "deny", ok, detail)
        if api_ip:
            ok, detail = self.connect("netpol-egress-probe", APP_NAMESPACE, api_ip, 443)
            add("egress to the Kubernetes API service", f"{APP_NAMESPACE}/netpol-egress-probe", f"{api_ip}:443", "deny", ok, detail)
        ok, detail = self.connect("netpol-egress-probe", APP_NAMESPACE, app_ip, APP_PORT)
        add("egress to another pod in the namespace", f"{APP_NAMESPACE}/netpol-egress-probe", f"{app_ip}:{APP_PORT}", "deny", ok, detail)
        return results


def run_check(run: Runner = kubectl, sleep: Callable[[float], None] = time.sleep) -> tuple[dict[str, Any], int]:
    checker = NetworkChecker(run, sleep)
    report: dict[str, Any] = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "run_id": settings.RUN_ID,
        "evidence_mode": "live",
        "connect_timeout_seconds": CONNECT_TIMEOUT,
        "cni_enforcement": {"checked": False, "enforced": False, "detail": ""},
        "cases": [],
    }
    try:
        code, out = run(["cluster-info"], None)
        if code != 0:
            report["status"] = "BLOCKED"
            report["cni_enforcement"]["detail"] = f"cluster unreachable: {out[:100]}"
            return report, EXIT_BLOCKED

        enforced, detail = checker.canary()
        report["cni_enforcement"] = {"checked": True, "enforced": enforced, "detail": detail}
        if not enforced:
            report["status"] = "BLOCKED"
            return report, EXIT_BLOCKED

        cases = checker.matrix()
        report["cases"] = [asdict(c) for c in cases]
        passed = bool(cases) and all(c.matched for c in cases)
        report["status"] = "PASS" if passed else "FAIL"
        return report, EXIT_OK if passed else EXIT_FAILED
    finally:
        checker.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify NetworkPolicy allow/deny behaviour")
    parser.add_argument("--output", type=Path, default=settings.ARTIFACTS_DIR / "network" / "network-policy-results.json")
    args = parser.parse_args(argv)

    report, code = run_check()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"CNI enforcement: {report['cni_enforcement']['detail']}")
    for case in report["cases"]:
        mark = "ok " if case["matched"] else "BAD"
        print(f"  [{mark}] {case['case']:<46} expected={case['expected']:<5} observed={case['observed']}")
    print(f"[{report['status']}] network policy verification (results: {args.output})")
    return code


if __name__ == "__main__":
    sys.exit(main())
