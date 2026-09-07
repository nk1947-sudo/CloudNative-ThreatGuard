"""
Security Scorecard Generator for CloudNative ThreatGuard.
Calculates admission-control and runtime-detection statistics dynamically
from actual evidence files. Never uses hardcoded percentages.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any

from cloudnative_threatguard.config import settings

TOTAL_SCENARIOS = 7  # RUNTIME-001..007 (cryptomining added as RUNTIME-007)


def generate_scorecard() -> dict[str, Any]:
    """Computes the scorecard dict from admission/runtime evidence files, without writing it."""
    admission_file = settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json"
    runtime_file = settings.ARTIFACTS_RUNTIME_DIR / "runtime-events.json"

    adm_total = adm_blocked = adm_allowed = 0
    adm_rate = 0.0
    if admission_file.exists():
        with open(admission_file, encoding="utf-8") as f:
            adm_data = json.load(f)
            adm_total = adm_data.get("total", 0)
            adm_blocked = adm_data.get("blocked", 0)
            adm_allowed = adm_data.get("allowed", 0)
            if adm_total > 0:
                adm_rate = round((adm_blocked / adm_total) * 100.0, 1)

    runtime_detected_rules = set()
    runtime_events = []
    by_severity: dict[str, int] = {}
    if runtime_file.exists():
        with open(runtime_file, encoding="utf-8") as f:
            runtime_events = json.load(f)
            for ev in runtime_events:
                rule = ev.get("rule_id")
                if rule:
                    runtime_detected_rules.add(rule)
                sev = ev.get("severity", "UNKNOWN")
                by_severity[sev] = by_severity.get(sev, 0) + 1

    run_detected = len(runtime_detected_rules)
    run_missed = max(0, TOTAL_SCENARIOS - run_detected)
    run_rate = round((run_detected / TOTAL_SCENARIOS) * 100.0, 1)

    overall_status = "PASS" if (adm_rate == 100.0 and run_rate == 100.0) else "FAIL"

    return {
        "project": "CloudNative ThreatGuard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "admission": {
            "total": adm_total,
            "blocked": adm_blocked,
            "allowed": adm_allowed,
            "enforcement_rate": adm_rate,
        },
        "runtime": {
            "total_scenarios": TOTAL_SCENARIOS,
            "detected": run_detected,
            "missed": run_missed,
            "detection_rate": run_rate,
            "detected_rules": sorted(runtime_detected_rules),
            "detections_by_severity": by_severity,
        },
        "telemetry": {
            "total_runtime_events": len(runtime_events),
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
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        written.append(str(dest))
    return written


def print_summary(report: dict[str, Any]) -> None:
    adm = report["admission"]
    run = report["runtime"]
    print("=" * 75)
    print("                    SECURITY SCORECARD SUMMARY")
    print("=" * 75)
    print(f"Project:              {report['project']}")
    print(f"Timestamp:            {report['timestamp']}")
    print(f"Overall Status:       {report['overall_status']}")
    print("-" * 75)
    print(f"Admission Control:    {adm['blocked']}/{adm['total']} blocked ({adm['enforcement_rate']}%)")
    print(f"Runtime Detections:   {run['detected']}/{run['total_scenarios']} detected ({run['detection_rate']}%)")
    print(f"Severity Breakdown:   {run['detections_by_severity']}")
    print("=" * 75)
