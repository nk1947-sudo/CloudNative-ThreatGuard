#!/usr/bin/env python3
"""
Generates the comprehensive Security Scorecard for CloudNative ThreatGuard.
Calculates all statistics dynamically from actual admission and runtime evidence.
Never uses hardcoded percentages.
"""

import os
import sys
import json
from datetime import datetime, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ADMISSION_FILE = os.path.join(REPO_ROOT, "artifacts", "admission", "admission-results.json")
RUNTIME_FILE = os.path.join(REPO_ROOT, "artifacts", "runtime", "runtime-events.json")
REPORT_DESTINATIONS = [
    os.path.join(REPO_ROOT, "artifacts", "security-report.json"),
    os.path.join(REPO_ROOT, "artifacts", "reports", "security-report.json")
]

TOTAL_SCENARIOS = 6

def main():
    print("=" * 75)
    print("CloudNative ThreatGuard — Security Scorecard Generator")
    print("=" * 75)

    # 1. Parse Admission Evidence
    adm_total = 0
    adm_blocked = 0
    adm_allowed = 0
    adm_rate = 0.0

    if os.path.exists(ADMISSION_FILE):
        with open(ADMISSION_FILE, "r", encoding="utf-8") as f:
            adm_data = json.load(f)
            adm_total = adm_data.get("total", 0)
            adm_blocked = adm_data.get("blocked", 0)
            adm_allowed = adm_data.get("allowed", 0)
            if adm_total > 0:
                adm_rate = round((adm_blocked / adm_total) * 100.0, 1)
    else:
        print(f"[WARN] Admission evidence file not found at {ADMISSION_FILE}")

    # 2. Parse Runtime Evidence
    runtime_detected_rules = set()
    runtime_events = []
    by_severity = {}

    if os.path.exists(RUNTIME_FILE):
        with open(RUNTIME_FILE, "r", encoding="utf-8") as f:
            runtime_events = json.load(f)
            for ev in runtime_events:
                rule = ev.get("rule_id")
                if rule:
                    runtime_detected_rules.add(rule)
                sev = ev.get("severity", "UNKNOWN")
                by_severity[sev] = by_severity.get(sev, 0) + 1
    else:
        print(f"[WARN] Runtime evidence file not found at {RUNTIME_FILE}")

    run_detected = len(runtime_detected_rules)
    run_missed = max(0, TOTAL_SCENARIOS - run_detected)
    run_rate = round((run_detected / TOTAL_SCENARIOS) * 100.0, 1)

    # 3. Determine Overall Status
    overall_status = "PASS" if (adm_rate == 100.0 and run_rate == 100.0) else "FAIL"

    report = {
        "project": "CloudNative ThreatGuard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "admission": {
            "total": adm_total,
            "blocked": adm_blocked,
            "allowed": adm_allowed,
            "enforcement_rate": adm_rate
        },
        "runtime": {
            "total_scenarios": TOTAL_SCENARIOS,
            "detected": run_detected,
            "missed": run_missed,
            "detection_rate": run_rate,
            "detected_rules": sorted(list(runtime_detected_rules)),
            "detections_by_severity": by_severity
        },
        "telemetry": {
            "total_runtime_events": len(runtime_events),
            "evidence_location": "artifacts/"
        }
    }

    # Save to destination paths
    for dest in REPORT_DESTINATIONS:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Security report generated: {os.path.relpath(dest, REPO_ROOT)}")

    print("\n" + "=" * 75)
    print("                    SECURITY SCORECARD SUMMARY")
    print("=" * 75)
    print(f"Project:              {report['project']}")
    print(f"Timestamp:            {report['timestamp']}")
    print(f"Overall Status:       {report['overall_status']}")
    print("-" * 75)
    print(f"Admission Control:    {adm_blocked}/{adm_total} blocked ({adm_rate}%)")
    print(f"Runtime Detections:   {run_detected}/{TOTAL_SCENARIOS} detected ({run_rate}%)")
    print(f"Severity Breakdown:   {by_severity}")
    print("=" * 75)

    if overall_status != "PASS":
        sys.exit(1)

if __name__ == "__main__":
    main()
