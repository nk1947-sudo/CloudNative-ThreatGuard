"""
Tetragon sensor diagnostic: are the events the sensor posts reaching the export stream?

Compares two things for the same short probe:

* what the sensor says it did: the per-policy counters from
  ``tetra tracingpolicy list`` (NPOST = events posted, NENFORCE = actions
  enforced), read before and after running harmless commands in the target pod;
* what actually arrived in the exported event stream (the stream the collector
  reads) for that pod.

If a policy posted or enforced something but no matching kprobe event was
exported, the gap is between the sensor and the export, not in detection. The
diagnostic reports that gap explicitly instead of letting it look like a
detection miss.

Exit codes: 0 the stream carries kprobe events, 1 events were posted but not
exported, 2 blocked (cluster or agent unreachable), 3 inconclusive (the probe
did not trigger any policy).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.runtime import collector

EXIT_OK = 0
EXIT_GAP = 1
EXIT_BLOCKED = 2
EXIT_INCONCLUSIVE = 3

PROBE_COMMANDS = (
    ["/bin/cat", "/etc/shadow"],
    ["/usr/bin/nc", "-z", "-w", "1", "1.1.1.1", "443"],
    ["/bin/sh", "-c", "true"],
)

Runner = Callable[[list[str]], tuple[int, str]]


def kubectl_run(args: list[str]) -> tuple[int, str]:
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    ctx = os.environ.get("THREATGUARD_KUBE_CONTEXT")
    cmd = ["kubectl", *(["--context", ctx] if ctx else []), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False, env=env)
    except FileNotFoundError:
        return 127, "kubectl not found"
    except subprocess.TimeoutExpired:
        return 124, "kubectl timed out"
    return proc.returncode, proc.stdout + (proc.stderr if proc.returncode else "")


@dataclass
class PolicyCounters:
    posted: int = 0
    enforced: int = 0


def parse_policy_table(text: str) -> dict[str, PolicyCounters]:
    """Parses `tetra tracingpolicy list`; the last three columns are NPOST, NENFORCE, NMONITOR."""
    counters: dict[str, PolicyCounters] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            posted, enforced = int(parts[-3]), int(parts[-2])
        except ValueError:
            continue
        counters[parts[1]] = PolicyCounters(posted, enforced)
    return counters


@dataclass
class Diagnosis:
    posted_delta: dict[str, int] = field(default_factory=dict)
    enforced_delta: dict[str, int] = field(default_factory=dict)
    exported_kprobe_events: int = 0
    exported_exec_events: int = 0

    @property
    def sensor_activity(self) -> int:
        return sum(self.posted_delta.values()) + sum(self.enforced_delta.values())

    @property
    def verdict(self) -> str:
        if self.sensor_activity == 0:
            return "INCONCLUSIVE"
        return "EXPORTED" if self.exported_kprobe_events else "POSTED_NOT_EXPORTED"

    def explain(self) -> str:
        if self.verdict == "EXPORTED":
            return "kprobe events posted by the sensor are present in the export stream."
        if self.verdict == "POSTED_NOT_EXPORTED":
            return (
                "the sensor posted or enforced actions (see counters) but no kprobe event reached the export stream. "
                "Detections that depend on kprobe events (shell block, file open, connect) cannot be confirmed here. "
                "Observed on KIND with Docker Desktop, where the agent logs that its procfs is not the host procfs; "
                "kprobe events that cannot be resolved to a process and pod are not exported. "
                "Run on a Linux host or VM where the agent sees the host procfs."
            )
        return "no policy counter moved: check that the TracingPolicies are loaded and the probe commands ran."


def diagnose(namespace: str, pod: str, run: Runner = kubectl_run, sleep: Callable[[float], None] = time.sleep) -> tuple[Diagnosis | None, str]:
    code, agent = run(["get", "pod", "-n", "tetragon", "-l", "app.kubernetes.io/name=tetragon",
                       "-o", "jsonpath={.items[0].metadata.name}"])
    agent = agent.strip()
    if code != 0 or not agent:
        return None, "no reachable Tetragon agent pod"

    def counters() -> dict[str, PolicyCounters] | None:
        rc, out = run(["exec", "-n", "tetragon", agent, "-c", "tetragon", "--", "tetra", "tracingpolicy", "list"])
        return parse_policy_table(out) if rc == 0 else None

    before = counters()
    if before is None:
        return None, "could not read policy counters from the agent"

    since = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for command in PROBE_COMMANDS:
        run(["exec", "-n", namespace, pod, "--", *command])
        sleep(2)
    sleep(10)  # allow for export delay

    after = counters()
    if after is None:
        return None, "could not read policy counters after the probe"

    result = Diagnosis()
    for name, now in after.items():
        was = before.get(name, PolicyCounters())
        if now.posted > was.posted:
            result.posted_delta[name] = now.posted - was.posted
        if now.enforced > was.enforced:
            result.enforced_delta[name] = now.enforced - was.enforced

    captured = collector.collect_live_events(since, namespace, pod, runner=lambda a: run(a))
    if captured.status == "unavailable":
        return None, "could not read the export stream: " + "; ".join(captured.errors)
    result.exported_kprobe_events = captured.event_kinds.get("process_kprobe", 0)
    result.exported_exec_events = captured.event_kinds.get("process_exec", 0)
    return result, ""


def main(argv: list[str] | None = None, run: Runner = kubectl_run, sleep: Callable[[float], None] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description="Diagnose whether sensor events reach the export stream")
    parser.add_argument("--namespace", default=settings.DEFAULT_PROTECTED_NAMESPACE)
    parser.add_argument("--pod", default="threatguard-target-pod")
    args = parser.parse_args(argv)

    result, error = diagnose(args.namespace, args.pod, run, sleep)
    if result is None:
        print(f"[BLOCKED] {error}", file=sys.stderr)
        return EXIT_BLOCKED
    print(f"sensor counters moved: posted={result.posted_delta or 'none'} enforced={result.enforced_delta or 'none'}")
    print(f"exported for {args.pod}: process_exec={result.exported_exec_events} process_kprobe={result.exported_kprobe_events}")
    print(f"[{result.verdict}] {result.explain()}")
    return {"EXPORTED": EXIT_OK, "POSTED_NOT_EXPORTED": EXIT_GAP}.get(result.verdict, EXIT_INCONCLUSIVE)


if __name__ == "__main__":
    sys.exit(main())
