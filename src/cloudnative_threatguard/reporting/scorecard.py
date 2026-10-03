"""
Security Scorecard Generator for CloudNative ThreatGuard.

Builds the scorecard from the evidence of one validation run: the admission
results and the runtime run manifest. Outcome and origin are separate
concepts: a demo run can PASS its own checks while its origin stays
SIMULATED, and ``live_acceptance`` is only true for a passing LIVE run.

Overall status values:
  PASS        every required check passed for the evidence's origin
  FAIL        a required check ran and failed
  INCOMPLETE  evidence is missing, from different runs, or has planned
              scenarios that were never executed
  STALE       evidence is older than the allowed age
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings

SCENARIO_STATUSES = ("passed", "failed", "blocked", "skipped", "not_run")
RUNTIME_RULE_PREFIX = "RUNTIME-"
MAX_EVIDENCE_AGE = timedelta(hours=float(os.environ.get("THREATGUARD_MAX_EVIDENCE_AGE_HOURS", "24")))


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _admission_ok(admission: dict[str, Any]) -> bool:
    if "status" in admission:
        return admission["status"] == "PASS"
    # Legacy results without an explicit status.
    total = admission.get("total", 0)
    return total > 0 and admission.get("blocked", 0) == total and admission.get("allowed", 0) == 0


def generate_scorecard(now: datetime | None = None) -> dict[str, Any]:
    """Computes the scorecard dict from the run's evidence files, without writing it."""
    now = now or datetime.now(timezone.utc)
    admission = _load_json(settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json")
    manifest = _load_json(settings.ARTIFACTS_RUNTIME_DIR / "run-manifest.json")
    events = _load_json(settings.ARTIFACTS_RUNTIME_DIR / "runtime-events.json") or []

    issues: list[str] = []
    if not isinstance(admission, dict):
        issues.append("admission results are missing or unreadable")
        admission = {}
    if not isinstance(manifest, dict):
        issues.append("runtime run manifest is missing or unreadable")
        manifest = {}

    scenarios = manifest.get("scenarios", [])
    counts = {status: sum(s.get("status") == status for s in scenarios) for status in SCENARIO_STATUSES}
    planned = len(scenarios)
    required = [s for s in scenarios if s.get("required", True)]

    expected_rules = sorted({r for s in scenarios for r in s.get("expected_rules", [])})
    covered_rules = sorted({r for s in scenarios for r in s.get("detected_rules", []) if r in expected_rules})

    origin = manifest.get("origin", "UNKNOWN")
    run_id = manifest.get("run_id", "")

    if admission and manifest:
        if admission.get("run_id") != run_id:
            issues.append("admission and runtime evidence come from different runs")
        if manifest.get("evidence_mode") == "live" and admission.get("evidence_mode") != "live":
            issues.append("live runtime evidence paired with non-live admission evidence")

    captured = _parse_ts(manifest.get("captured_at"))
    stale = captured is not None and now - captured > MAX_EVIDENCE_AGE
    if manifest and captured is None:
        issues.append("run manifest has no capture time")

    collector_status = (manifest.get("collector") or {}).get("status", "unknown")
    collector_ok = collector_status in ("ok", "not_applicable")
    admission_ok = bool(admission) and _admission_ok(admission)
    required_passed = bool(required) and all(s.get("status") == "passed" for s in required)
    never_ran = counts["not_run"] + counts["blocked"] + counts["skipped"]

    if issues or planned == 0:
        overall = "INCOMPLETE"
    elif stale:
        overall = "STALE"
    elif never_ran and any(s.get("required", True) and s.get("status") in ("not_run", "blocked", "skipped") for s in scenarios):
        overall = "INCOMPLETE"
    elif admission_ok and required_passed and collector_ok:
        overall = "PASS"
    else:
        overall = "FAIL"

    by_severity: dict[str, int] = {}
    runtime_event_count = 0
    for ev in events:
        if str(ev.get("rule_id", "")).startswith(RUNTIME_RULE_PREFIX):
            runtime_event_count += 1
            sev = ev.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1

    adm_total = admission.get("total", 0)
    return {
        "project": "CloudNative ThreatGuard",
        "timestamp": now.isoformat(),
        "overall_status": overall,
        "origin": origin,
        "live_acceptance": overall == "PASS" and origin == "LIVE",
        "run_id": run_id,
        "evidence_captured_at": manifest.get("captured_at", ""),
        "issues": issues + (["evidence is older than the allowed age"] if stale else []),
        "admission": {
            "total": adm_total,
            "blocked": admission.get("blocked", 0),
            "allowed": admission.get("allowed", 0),
            "errors": admission.get("errors", 0),
            "enforcement_rate": round(admission.get("blocked", 0) / adm_total * 100.0, 1) if adm_total else 0.0,
            "positive_allowed": admission.get("positive_allowed", 0),
            "positive_total": admission.get("positive_total", 0),
            "mode": admission.get("mode", "unknown"),
            "status": "PASS" if admission_ok else ("FAIL" if admission else "MISSING"),
        },
        "runtime": {
            "total_scenarios": planned,
            "detected": counts["passed"],
            "missed": planned - counts["passed"],
            "detection_rate": round(counts["passed"] / planned * 100.0, 1) if planned else 0.0,
            "scenario_counts": {"planned": planned, **counts},
            "rule_coverage": {
                "expected_rules": expected_rules,
                "covered_rules": covered_rules,
                "coverage_rate": round(len(covered_rules) / len(expected_rules) * 100.0, 1) if expected_rules else 0.0,
            },
            "detected_rules": covered_rules,
            "detections_by_severity": by_severity,
            "scenarios": scenarios,
        },
        "telemetry": {
            "total_runtime_events": runtime_event_count,
            "collector": manifest.get("collector", {}),
            "evidence_location": "artifacts/",
        },
    }


def write_scorecard(report: dict[str, Any]) -> list:
    """Writes the scorecard to both legacy destination paths, returning the list of paths written."""
    destinations = [
        settings.ARTIFACTS_DIR / "security-report.json",
        settings.ARTIFACTS_REPORTS_DIR / "security-report.json",
    ]
    written = []
    for dest in destinations:
        os.makedirs(dest.parent, exist_ok=True)
        tmp = dest.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
        os.replace(tmp, dest)
        written.append(str(dest))
    return written


def print_summary(report: dict[str, Any]) -> None:
    adm = report["admission"]
    run = report["runtime"]
    counts = run["scenario_counts"]
    coverage = run["rule_coverage"]
    print("=" * 75)
    print("                    SECURITY SCORECARD SUMMARY")
    print("=" * 75)
    print(f"Project:              {report['project']}")
    print(f"Report generated:     {report['timestamp']}")
    print(f"Evidence origin:      {report['origin']}  (run {report['run_id'] or 'n/a'})")
    print(f"Evidence captured:    {report['evidence_captured_at'] or 'n/a'}")
    print(f"Overall Status:       {report['overall_status']}  (live acceptance: {report['live_acceptance']})")
    for issue in report["issues"]:
        print(f"  ! {issue}")
    print("-" * 75)
    print(f"Admission Control:    {adm['blocked']}/{adm['total']} denied by policy, "
          f"{adm['allowed']} unexpectedly allowed, {adm['errors']} errors [{adm['status']}]")
    print(f"Scenarios:            {counts['passed']} passed / {counts['planned']} planned "
          f"(failed {counts['failed']}, blocked {counts['blocked']}, skipped {counts['skipped']}, "
          f"not run {counts['not_run']})")
    print(f"Rule Coverage:        {len(coverage['covered_rules'])}/{len(coverage['expected_rules'])} rules observed")
    print(f"Severity Breakdown:   {run['detections_by_severity']}")
    print("=" * 75)
