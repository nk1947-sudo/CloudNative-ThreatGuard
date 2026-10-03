"""
CloudNative ThreatGuard -- Prometheus Security Metrics Exporter.
Serves metrics derived from the current evidence snapshot on /metrics.

Metric semantics:
  * Counts describe the *current evidence snapshot*, not a cumulative
    history, so they are exposed as gauges.
  * Admission and runtime series carry a bounded ``origin`` label (live,
    demo or unknown) taken from the evidence itself.
  * Missing or corrupt evidence omits the affected series and sets
    ``threatguard_artifact_valid`` to 0, so unavailable data is never
    displayed as a healthy zero.
"""

import json
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.reporting.cross_domain_metrics import compute_snapshot, load_incidents

PORT = settings.EXPORTER_PORT
RUNTIME_RULE_PREFIX = "RUNTIME-"
VALID_ORIGINS = ("live", "demo")


def _read_artifact(path: Path) -> tuple[Any | None, bool]:
    """Returns (data, valid). A missing, unreadable or malformed file is invalid, never empty."""
    try:
        return json.loads(path.read_text(encoding="utf-8")), True
    except (OSError, json.JSONDecodeError):
        return None, False


def _origin(value: Any) -> str:
    return value if value in VALID_ORIGINS else "unknown"


def _parse_epoch(value: str) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _evidence_section(lines: list[str], manifest: dict[str, Any], artifact_status: dict[str, bool], now: float) -> None:
    lines.append("# HELP threatguard_artifact_valid 1 if the evidence artifact was read and parsed, 0 if missing or corrupt")
    lines.append("# TYPE threatguard_artifact_valid gauge")
    for name, ok in artifact_status.items():
        lines.append(f'threatguard_artifact_valid{{artifact="{name}"}} {1 if ok else 0}')

    lines.append("# HELP threatguard_evidence_info Origin of the current evidence snapshot (live, demo or unknown)")
    lines.append("# TYPE threatguard_evidence_info gauge")
    lines.append(f'threatguard_evidence_info{{origin="{_origin(manifest.get("evidence_mode"))}"}} 1')

    captured = _parse_epoch(manifest.get("captured_at", ""))
    if captured is not None:
        lines.append("# HELP threatguard_evidence_captured_timestamp_seconds Unix time the current evidence snapshot was captured")
        lines.append("# TYPE threatguard_evidence_captured_timestamp_seconds gauge")
        lines.append(f"threatguard_evidence_captured_timestamp_seconds {captured:.0f}")
        lines.append("# HELP threatguard_evidence_age_seconds Age of the current evidence snapshot")
        lines.append("# TYPE threatguard_evidence_age_seconds gauge")
        lines.append(f"threatguard_evidence_age_seconds {max(0, now - captured):.0f}")

    collector = manifest.get("collector") or {}
    lines.append("# HELP threatguard_collector_up 1 if the sensor event collector captured cleanly, 0 if degraded, unavailable or not run live")
    lines.append("# TYPE threatguard_collector_up gauge")
    lines.append(f"threatguard_collector_up {1 if collector.get('status') == 'ok' else 0}")
    if "parse_errors" in collector:
        lines.append("# HELP threatguard_collector_parse_errors Malformed sensor event lines skipped in the last capture")
        lines.append("# TYPE threatguard_collector_parse_errors gauge")
        lines.append(f"threatguard_collector_parse_errors {collector.get('parse_errors', 0)}")
        lines.append("# HELP threatguard_collector_duplicates_dropped Duplicate sensor export records dropped in the last capture")
        lines.append("# TYPE threatguard_collector_duplicates_dropped gauge")
        lines.append(f"threatguard_collector_duplicates_dropped {collector.get('duplicates_dropped', 0)}")


def _admission_section(lines: list[str], adm: dict[str, Any]) -> None:
    if adm.get("evidence_mode") == "live":
        origin = "live"
    elif adm.get("mode") == "opa_offline_evaluation":
        origin = "demo"
    else:
        origin = "unknown"
    label = f'{{origin="{origin}"}}'
    lines.append("# HELP threatguard_admission_blocked_total Insecure test manifests denied by policy in the current snapshot")
    lines.append("# TYPE threatguard_admission_blocked_total gauge")
    lines.append(f"threatguard_admission_blocked_total{label} {adm.get('blocked', 0)}")
    lines.append("# HELP threatguard_admission_enforcement_rate Percentage of insecure test manifests denied by policy")
    lines.append("# TYPE threatguard_admission_enforcement_rate gauge")
    lines.append(f"threatguard_admission_enforcement_rate{label} {adm.get('enforcement_rate', 0.0)}")
    lines.append("# HELP threatguard_admission_errors Admission checks that errored rather than being denied or allowed")
    lines.append("# TYPE threatguard_admission_errors gauge")
    lines.append(f"threatguard_admission_errors{label} {adm.get('errors', 0)}")


def _runtime_section(lines: list[str], events: list[dict[str, Any]]) -> None:
    lines.append("# HELP threatguard_runtime_detections_total Runtime detections in the current evidence snapshot, by origin (live sensor events or demo fixtures)")
    lines.append("# TYPE threatguard_runtime_detections_total gauge")
    by_rule: dict[tuple[str, str, str, str], int] = {}
    for ev in events:
        rule = ev.get("rule_id", "UNKNOWN")
        if not str(rule).startswith(RUNTIME_RULE_PREFIX):
            continue
        key = (rule, ev.get("severity", "UNKNOWN"), ev.get("technique", "UNKNOWN"), _origin(ev.get("evidence_mode")))
        by_rule[key] = by_rule.get(key, 0) + 1
    for (rule, sev, tech, origin), count in by_rule.items():
        lines.append(
            f'threatguard_runtime_detections_total{{rule_id="{rule}",severity="{sev}",technique="{tech}",origin="{origin}"}} {count}'
        )


def _scorecard_section(lines: list[str], report: dict[str, Any]) -> None:
    stats = report["runtime"]
    label = f'{{origin="{_origin(str(report.get("origin", "")).lower())}"}}'
    lines.append("# HELP threatguard_detection_rate Percentage of planned scenarios that passed in the current run")
    lines.append("# TYPE threatguard_detection_rate gauge")
    lines.append(f"threatguard_detection_rate{label} {stats.get('detection_rate', 0.0)}")
    lines.append("# HELP threatguard_scenarios_total Scenarios planned in the current run")
    lines.append("# TYPE threatguard_scenarios_total gauge")
    lines.append(f"threatguard_scenarios_total{label} {stats.get('total_scenarios', 0)}")
    lines.append("# HELP threatguard_scenarios_detected Scenarios that passed in the current run")
    lines.append("# TYPE threatguard_scenarios_detected gauge")
    lines.append(f"threatguard_scenarios_detected{label} {stats.get('detected', 0)}")


def _cross_domain_section(lines: list[str]) -> None:
    # Derived from persisted CrossDomainIncident objects (written by the
    # cross-domain demo / a future live pipeline) via
    # reporting.cross_domain_metrics -- never hardcoded. With no persisted
    # incidents yet, every value below is honestly 0. The cloud inputs are
    # currently simulated; no cloud account is queried.
    incidents_file = settings.ARTIFACTS_FORENSICS_DIR / "cross-domain-incidents.json"
    snapshot = compute_snapshot(load_incidents(incidents_file))

    lines.append("# HELP threatguard_cross_domain_correlations_total Total cross-domain incidents ever correlated (cumulative, simulated cloud inputs)")
    lines.append("# TYPE threatguard_cross_domain_correlations_total counter")
    lines.append(f"threatguard_cross_domain_correlations_total {snapshot.total_correlations}")

    lines.append("# HELP threatguard_cloud_iam_risks_total Cloud IAM security findings contributing to incidents, by each finding's own severity")
    lines.append("# TYPE threatguard_cloud_iam_risks_total gauge")
    for sev, count in snapshot.iam_risks_by_severity.items():
        lines.append(f'threatguard_cloud_iam_risks_total{{severity="{sev}"}} {count}')

    lines.append("# HELP threatguard_cloud_runtime_threats_total Kubernetes runtime threats contributing to incidents, by each finding's own severity")
    lines.append("# TYPE threatguard_cloud_runtime_threats_total gauge")
    for sev, count in snapshot.runtime_threats_by_severity.items():
        lines.append(f'threatguard_cloud_runtime_threats_total{{severity="{sev}"}} {count}')

    lines.append("# HELP threatguard_open_incidents_total Current open cross-domain security incidents")
    lines.append("# TYPE threatguard_open_incidents_total gauge")
    lines.append(f"threatguard_open_incidents_total {snapshot.open_incidents}")

    lines.append("# HELP threatguard_exploitable_attack_paths_total Currently open incidents with a realized cloud-identity-to-Kubernetes path")
    lines.append("# TYPE threatguard_exploitable_attack_paths_total gauge")
    lines.append(f"threatguard_exploitable_attack_paths_total {snapshot.exploitable_attack_paths}")

    lines.append("# HELP threatguard_high_risk_principals_total Distinct high/critical-severity IAM principals with an open incident")
    lines.append("# TYPE threatguard_high_risk_principals_total gauge")
    lines.append(f"threatguard_high_risk_principals_total {snapshot.high_risk_principals}")

    lines.append("# HELP threatguard_high_risk_workloads_total Distinct high/critical-severity Kubernetes workloads with an open incident")
    lines.append("# TYPE threatguard_high_risk_workloads_total gauge")
    lines.append(f"threatguard_high_risk_workloads_total {snapshot.high_risk_workloads}")

    lines.append("# HELP threatguard_sensitive_resources_exposed_total Distinct resources named in open incidents' remediation proposals")
    lines.append("# TYPE threatguard_sensitive_resources_exposed_total gauge")
    lines.append(f"threatguard_sensitive_resources_exposed_total {snapshot.sensitive_resources_exposed}")


def render_metrics(now: float | None = None) -> str:
    now = time.time() if now is None else now
    lines: list[str] = []

    adm, adm_ok = _read_artifact(settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json")
    events, events_ok = _read_artifact(settings.ARTIFACTS_RUNTIME_DIR / "runtime-events.json")
    manifest, manifest_ok = _read_artifact(settings.ARTIFACTS_RUNTIME_DIR / "run-manifest.json")
    report, report_ok = _read_artifact(settings.ARTIFACTS_DIR / "security-report.json")

    adm_ok = adm_ok and isinstance(adm, dict)
    events_ok = events_ok and isinstance(events, list)
    manifest_ok = manifest_ok and isinstance(manifest, dict)
    report_ok = report_ok and isinstance(report, dict)

    _evidence_section(
        lines,
        manifest if manifest_ok else {},
        {
            "admission_results": adm_ok,
            "runtime_events": events_ok,
            "run_manifest": manifest_ok,
            "security_report": report_ok,
        },
        now,
    )
    if adm_ok:
        _admission_section(lines, adm)
    if events_ok:
        _runtime_section(lines, events)
    if report_ok and isinstance(report.get("runtime"), dict):
        _scorecard_section(lines, report)
    _cross_domain_section(lines)

    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/metrics", "/"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(self.generate_metrics().encode("utf-8"))
        elif self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
        else:
            self.send_response(404)
            self.end_headers()

    def generate_metrics(self) -> str:
        return render_metrics()

    def log_message(self, format, *args):
        # Quiet logger
        pass


def run():
    server = HTTPServer(("0.0.0.0", PORT), MetricsHandler)
    print(f"[+] ThreatGuard Prometheus Metrics Exporter running on port {PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
