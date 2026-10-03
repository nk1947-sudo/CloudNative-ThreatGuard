"""
Runtime evidence pipeline: sensor events -> detection -> correlation -> artifacts.

Two explicit modes share one code path:

* ``live``  reads the real Tetragon event stream for the scenario windows
            recorded by the orchestrator. It never falls back to fixtures.
* ``demo``  replays the deterministic fixture trace. Every produced event is
            labelled ``evidence_mode="demo"`` and the run manifest is marked
            SIMULATED, so it can never satisfy live acceptance.

Artifacts are written to an immutable per-run directory and then published
atomically to ``artifacts/runtime`` for the metrics exporter.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.correlation.kubernetes import correlate_incidents
from cloudnative_threatguard.detection.engine import DetectionEngine
from cloudnative_threatguard.reporting.risk import RiskScoringEngine
from cloudnative_threatguard.runtime import collector as tg_collector
from cloudnative_threatguard.runtime.events import SecurityEvent
from cloudnative_threatguard.runtime.scenarios import (
    Scenario,
    ScenarioOutcome,
    ScenarioRun,
    evaluate_scenario,
    load_catalog,
    parse_results_file,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_BLOCKED = 2

FIXTURE_PATH = settings.PROJECT_ROOT / "simulations" / "fixtures" / "demo_trace.jsonl"
# Tolerance for clock skew between the host and the cluster node. It must stay
# smaller than half the orchestrator's pause between scenarios, or neighbouring
# scenarios would claim each other's events.
WINDOW_GRACE = timedelta(seconds=1.5)

# Effective security context for demo runs. It describes the simulated target
# coherently (non-root, hardened) instead of assuming root privileges.
DEMO_WORKLOAD_SPEC: dict[str, Any] = {
    "runAsUser": 10001,
    "runAsNonRoot": True,
    "privileged": False,
    "readOnlyRootFilesystem": True,
}


def workload_spec_from_pod(pod: dict[str, Any], container_name: str | None = None) -> dict[str, Any]:
    """
    Builds the risk-scoring input from a pod's *effective* security context.
    Container settings override pod-level ones, and anything unset stays
    absent, so unknown configuration is never scored as root or privileged.
    """
    spec = pod.get("spec", {}) or {}
    pod_ctx = spec.get("securityContext", {}) or {}
    containers = spec.get("containers", []) or []
    container = next((c for c in containers if c.get("name") == container_name), containers[0] if containers else {})
    ctr_ctx = container.get("securityContext", {}) or {}

    result: dict[str, Any] = {}
    for key in ("runAsUser", "runAsNonRoot"):
        value = ctr_ctx.get(key, pod_ctx.get(key))
        if value is not None:
            result[key] = value
    for key in ("privileged", "readOnlyRootFilesystem", "allowPrivilegeEscalation"):
        if key in ctr_ctx:
            result[key] = ctr_ctx[key]
    for key in ("hostPID", "hostNetwork", "hostIPC"):
        if key in spec:
            result[key] = spec[key]
    return result


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _read_fixture(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def _stamp(event: SecurityEvent, mode: str, run_id: str, scenario_id: str, observed_at: str, captured_at: str) -> SecurityEvent:
    event.evidence_mode = mode
    event.run_id = run_id
    event.scenario_id = scenario_id
    event.observed_at = observed_at
    event.captured_at = captured_at
    event.collector_version = settings.COLLECTOR_VERSION if mode == "live" else "demo-fixture"
    if mode == "demo":
        event.source = "threatguard_simulator"
    return event


def _scenario_events(
    mode: str, scenario: Scenario, run: ScenarioRun | None, events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if mode == "demo":
        return [e for e in events if e.get("_scenario") == scenario.id]
    if run is None or run.status != "executed":
        return []
    start = tg_collector.parse_time(run.started_at)
    end = tg_collector.parse_time(run.ended_at)
    if start is None or end is None:
        return []
    return tg_collector.events_in_window(events, start - WINDOW_GRACE, end + WINDOW_GRACE)


def _evaluate_all(
    mode: str,
    catalog: list[Scenario],
    runs: dict[str, ScenarioRun],
    events: list[dict[str, Any]],
    namespace: str,
) -> tuple[list[ScenarioOutcome], list[tuple[str, Any, dict[str, Any]]]]:
    outcomes: list[ScenarioOutcome] = []
    detections: list[tuple[str, Any, dict[str, Any]]] = []
    for scenario in catalog:
        run = runs.get(scenario.id)
        scenario_events = _scenario_events(mode, scenario, run, events)
        engine = DetectionEngine(protected_namespace=namespace)
        found = []
        for raw in scenario_events:
            det = engine.process_raw_tetragon_event(raw, record=False)
            if det:
                found.append((scenario.id, det, raw))
        detections.extend(found)
        outcomes.append(
            evaluate_scenario(
                scenario,
                run,
                {det.rule_id for _, det, _ in found},
                tg_collector.enforcement_observed(scenario_events),
                check_exit_code=(mode == "live"),
                events_seen=len(scenario_events),
            )
        )
    return outcomes, detections


def _admission_events(mode: str, run_id: str, namespace: str, captured_at: str) -> list[SecurityEvent]:
    """Admission events come from recorded results in live mode; the demo synthesizes one, labelled demo."""
    if mode == "demo":
        event = SecurityEvent.from_admission_denial(
            rule_id="RULE-K8S-009",
            policy_name="k8sprivilegedcontainer",
            resource_name="01-privileged-pod",
            namespace=namespace,
            violation_message="Privileged container execution is prohibited in cluster",
        )
        return [_stamp(event, "demo", run_id, "SCEN-000", event.timestamp, captured_at)]

    results_file = settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json"
    if not results_file.exists():
        return []
    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if data.get("run_id") != run_id or data.get("evidence_mode") != "live":
        return []
    events = []
    for item in data.get("negative_results", []):
        if item.get("outcome") != "policy_denied":
            continue
        event = SecurityEvent.from_admission_denial(
            rule_id="RULE-K8S-009",
            policy_name=item.get("constraint") or "gatekeeper",
            resource_name=str(item.get("manifest", "")).removesuffix(".yaml"),
            namespace=namespace,
            violation_message=str(item.get("detail", ""))[:200],
        )
        events.append(_stamp(event, "live", run_id, "SCEN-000", event.timestamp, captured_at))
    return events


def run_pipeline(
    mode: str,
    run_id: str,
    namespace: str,
    pod: str,
    results_path: Path | None = None,
    catalog: list[Scenario] | None = None,
    fixture_path: Path = FIXTURE_PATH,
    out_dir: Path | None = None,
    since: str = "",
    wait_seconds: int = 45,
    runner: tg_collector.Runner = tg_collector.kubectl_runner,
    sleep: Callable[[float], None] = time.sleep,
    workload_spec: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], int]:
    """Runs the pipeline and returns (manifest, exit code)."""
    if mode not in ("live", "demo"):
        raise ValueError(f"unknown mode: {mode}")
    catalog = catalog if catalog is not None else load_catalog()
    out_dir = out_dir or settings.ARTIFACTS_RUNTIME_DIR
    started_at = datetime.now(timezone.utc).isoformat()

    if mode == "demo":
        runs = {s.id: ScenarioRun(s.id, "executed", None, "", "") for s in catalog}
        events = _read_fixture(fixture_path)
        collection = None
    else:
        runs = parse_results_file(results_path) if results_path else {}
        collection = tg_collector.collect_live_events(since, namespace, pod, runner)
        events = collection.events

    outcomes, detections = _evaluate_all(mode, catalog, runs, events, namespace)

    # Live evidence can arrive after the command exits; re-collect within a bound.
    if mode == "live" and collection is not None and collection.status != "unavailable":
        waited = 0
        while waited < wait_seconds and any(o.status == "failed" for o in outcomes):
            sleep(2)
            waited += 2
            collection = tg_collector.collect_live_events(since, namespace, pod, runner)
            if collection.status == "unavailable":
                break
            events = collection.events
            outcomes, detections = _evaluate_all(mode, catalog, runs, events, namespace)

    if mode == "live" and collection is not None and collection.status != "unavailable" and collection.events:
        # A missing event class is a sensor deployment problem, not a detection miss.
        if not collection.event_kinds.get("process_kprobe"):
            hint = (
                "the sensor stream contains no process_kprobe events: kprobe-based policies "
                "(shell block, file open, connect) are not exporting events in this deployment; "
                "check the Tetragon export allow/deny lists and host procfs access"
            )
            for outcome in outcomes:
                if outcome.status == "failed" and any(
                    "not observed" in r or "kill evidence" in r for r in outcome.reasons
                ):
                    outcome.reasons.append(hint)

    if mode == "live" and collection is not None and collection.status == "unavailable":
        # Without a working event stream nothing can be confirmed either way.
        for outcome in outcomes:
            if outcome.status in ("passed", "failed"):
                outcome.status = "blocked"
                outcome.reasons.append("sensor event stream unavailable")

    captured_at = datetime.now(timezone.utc).isoformat()
    security_events: list[SecurityEvent] = []
    for scenario_id, det, _ in detections:
        event = det.to_security_event()
        security_events.append(_stamp(event, mode, run_id, scenario_id, det.timestamp, captured_at))
    admission_events = _admission_events(mode, run_id, namespace, captured_at)
    all_events = admission_events + security_events

    incidents = correlate_incidents(security_events)
    if workload_spec is None:
        workload_spec = DEMO_WORKLOAD_SPEC if mode == "demo" else {}
    risk = RiskScoringEngine().evaluate_workload(
        all_events, workload_ref=f"{namespace}/{pod}", workload_spec=workload_spec or None
    )

    collector_info = collection.to_dict() if collection else {"status": "not_applicable", "collector_version": "demo-fixture"}
    manifest = {
        "run_id": run_id,
        "evidence_mode": mode,
        "origin": "LIVE" if mode == "live" else "SIMULATED",
        "started_at": started_at,
        "captured_at": captured_at,
        "namespace": namespace,
        "target_pod": pod,
        "collector": collector_info,
        "scenarios": [o.to_dict() for o in outcomes],
    }

    raw_for_artifact = [{k: v for k, v in e.items() if k != "_scenario"} for e in events]
    run_dir = settings.ARTIFACTS_DIR / "runs" / f"{mode}-{run_id}"
    artifacts = {
        "tetragon-raw.json": "\n".join(json.dumps(e) for e in raw_for_artifact) + ("\n" if raw_for_artifact else ""),
        "runtime-events.json": [e.to_dict() for e in all_events],
        "incident-reports.json": [i.to_dict() for i in incidents],
        "risk-assessment.json": risk.to_dict(),
        "run-manifest.json": manifest,
    }
    for name, payload in artifacts.items():
        for directory in (run_dir, out_dir):
            if isinstance(payload, str):
                directory.mkdir(parents=True, exist_ok=True)
                tmp = (directory / name).with_suffix(".tmp")
                tmp.write_text(payload, encoding="utf-8")
                os.replace(tmp, directory / name)
            else:
                _atomic_write(directory / name, payload)

    if mode == "live" and collection is not None and collection.status == "unavailable":
        return manifest, EXIT_BLOCKED
    required_failed = any(o.required and o.status != "passed" for o in outcomes)
    return manifest, EXIT_FAILED if required_failed else EXIT_OK


def _fetch_workload_spec(namespace: str, pod: str, runner: tg_collector.Runner) -> dict[str, Any]:
    code, out = runner(["get", "pod", pod, "-n", namespace, "-o", "json"])
    if code != 0:
        return {}
    try:
        return workload_spec_from_pod(json.loads(out))
    except json.JSONDecodeError:
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Process a validation run into evidence artifacts")
    parser.add_argument("--mode", choices=["live", "demo"], default=settings.EVIDENCE_MODE)
    parser.add_argument("--run-id", default=settings.RUN_ID or uuid.uuid4().hex[:12])
    parser.add_argument("--namespace", default=settings.DEFAULT_PROTECTED_NAMESPACE)
    parser.add_argument("--pod", default="threatguard-target-pod")
    parser.add_argument("--results", type=Path, default=None, help="Orchestrator scenario results (live mode)")
    parser.add_argument("--since", default="", help="RFC 3339 start of the capture window (live mode)")
    parser.add_argument("--wait", type=int, default=45, help="Seconds to wait for late sensor events")
    args = parser.parse_args(argv)

    spec = _fetch_workload_spec(args.namespace, args.pod, tg_collector.kubectl_runner) if args.mode == "live" else None
    manifest, code = run_pipeline(
        mode=args.mode, run_id=args.run_id, namespace=args.namespace, pod=args.pod,
        results_path=args.results, since=args.since, wait_seconds=args.wait, workload_spec=spec,
    )
    print(f"Run {manifest['run_id']} ({manifest['origin']}), collector: {manifest['collector']['status']}")
    for item in manifest["scenarios"]:
        reason = f"  <- {'; '.join(item['reasons'])}" if item["reasons"] else ""
        print(f"  {item['scenario_id']:<9} {item['status']:<8} detected={item['detected_rules']}{reason}")
    if code == EXIT_BLOCKED:
        print("[BLOCKED] Sensor event stream unavailable; no live evidence was collected.", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
