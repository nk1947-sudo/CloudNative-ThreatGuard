"""Exporter semantics: missing telemetry is visible, origins are separate, types match meaning."""

import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.observability.metrics_exporter import render_metrics


@contextmanager
def artifacts():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "admission").mkdir()
        (root / "runtime").mkdir()
        (root / "forensics").mkdir()
        patches = [
            patch.object(settings, "ARTIFACTS_DIR", root),
            patch.object(settings, "ARTIFACTS_ADMISSION_DIR", root / "admission"),
            patch.object(settings, "ARTIFACTS_RUNTIME_DIR", root / "runtime"),
            patch.object(settings, "ARTIFACTS_FORENSICS_DIR", root / "forensics"),
        ]
        for p in patches:
            p.start()
        try:
            yield root
        finally:
            for p in patches:
                p.stop()


def write(root, rel, data):
    (root / rel).write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


class TestMissingAndCorruptEvidence(unittest.TestCase):
    def test_missing_artifacts_are_flagged_not_reported_as_zero(self):
        with artifacts():
            text = render_metrics()
        self.assertIn('threatguard_artifact_valid{artifact="admission_results"} 0', text)
        self.assertIn('threatguard_artifact_valid{artifact="runtime_events"} 0', text)
        self.assertNotIn("threatguard_admission_blocked_total", text)
        self.assertNotIn("threatguard_runtime_detections_total{", text)
        self.assertNotIn("threatguard_detection_rate", text)
        self.assertIn("threatguard_collector_up 0", text)

    def test_corrupt_artifact_is_invalid_not_empty(self):
        with artifacts() as root:
            write(root, "admission/admission-results.json", "{not json")
            text = render_metrics()
        self.assertIn('threatguard_artifact_valid{artifact="admission_results"} 0', text)
        self.assertNotIn("threatguard_admission_blocked_total", text)


class TestOriginAndSemantics(unittest.TestCase):
    def runtime_event(self, mode):
        return {"rule_id": "RUNTIME-003", "severity": "MEDIUM", "technique": "T1082", "evidence_mode": mode}

    def test_demo_and_live_detections_are_labelled_separately(self):
        with artifacts() as root:
            write(root, "runtime/runtime-events.json", [self.runtime_event("demo"), self.runtime_event("live")])
            text = render_metrics()
        self.assertIn('origin="demo"} 1', text)
        self.assertIn('origin="live"} 1', text)

    def test_unlabelled_events_are_unknown_origin(self):
        with artifacts() as root:
            write(root, "runtime/runtime-events.json", [{"rule_id": "RUNTIME-003", "severity": "LOW", "technique": "T1"}])
            text = render_metrics()
        self.assertIn('origin="unknown"} 1', text)

    def test_admission_rule_events_are_not_counted_as_runtime(self):
        with artifacts() as root:
            write(root, "runtime/runtime-events.json", [{"rule_id": "RULE-K8S-009", "severity": "HIGH", "technique": "T1610"}])
            text = render_metrics()
        self.assertNotIn('rule_id="RULE-K8S-009"', text)

    def test_snapshot_counts_are_gauges_not_counters(self):
        with artifacts() as root:
            write(root, "runtime/runtime-events.json", [self.runtime_event("live")])
            write(root, "admission/admission-results.json", {"blocked": 8, "enforcement_rate": 100.0, "evidence_mode": "live"})
            text = render_metrics()
        self.assertIn("# TYPE threatguard_runtime_detections_total gauge", text)
        self.assertIn("# TYPE threatguard_admission_blocked_total gauge", text)
        self.assertNotIn("captured by Tetragon", text)

    def test_evidence_identity_and_age_are_exposed(self):
        with artifacts() as root:
            write(root, "runtime/run-manifest.json", {
                "evidence_mode": "demo", "captured_at": "2026-10-03T10:00:00+00:00",
                "collector": {"status": "not_applicable"},
            })
            text = render_metrics(now=1_791_021_600.0)
        self.assertIn('threatguard_evidence_info{origin="demo"} 1', text)
        self.assertIn("threatguard_evidence_age_seconds", text)
        self.assertIn("threatguard_collector_up 0", text)

    def test_healthy_live_collector_reports_up(self):
        with artifacts() as root:
            write(root, "runtime/run-manifest.json", {
                "evidence_mode": "live", "captured_at": "2026-10-03T10:00:00+00:00",
                "collector": {"status": "ok", "parse_errors": 2, "duplicates_dropped": 1},
            })
            text = render_metrics()
        self.assertIn("threatguard_collector_up 1", text)
        self.assertIn("threatguard_collector_parse_errors 2", text)


if __name__ == "__main__":
    unittest.main()
