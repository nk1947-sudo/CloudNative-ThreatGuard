"""
Integration test: runs the actual cross-domain demo pipeline (not an
isolated helper) and confirms the Prometheus metrics exporter's real text
output changes as incident state accumulates -- the exact behavior the
previous hardcoded implementation could never exhibit.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloudnative_threatguard.config import settings
from cloudnative_threatguard.correlation.cross_domain.demo.deterministic_demo import build_demo_scenario
from cloudnative_threatguard.observability.metrics_exporter import MetricsHandler


def _metrics_text() -> str:
    handler = MetricsHandler.__new__(MetricsHandler)
    return handler.generate_metrics()


class TestCrossDomainMetricsPipeline(unittest.TestCase):
    def test_metrics_reflect_zero_before_any_incident_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(settings, "ARTIFACTS_FORENSICS_DIR", Path(tmp)):
                text = _metrics_text()

        self.assertIn("threatguard_cross_domain_correlations_total 0", text)
        self.assertIn("threatguard_open_incidents_total 0", text)
        self.assertIn("threatguard_high_risk_principals_total 0", text)
        self.assertIn("threatguard_sensitive_resources_exposed_total 0", text)

    def test_metrics_change_after_running_the_real_demo_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(settings, "ARTIFACTS_FORENSICS_DIR", Path(tmp)):
                before_text = _metrics_text()
                self.assertIn("threatguard_cross_domain_correlations_total 0", before_text)
                self.assertIn("threatguard_open_incidents_total 0", before_text)

                result = build_demo_scenario()
                self.assertEqual(result["status"], "SUCCESS")

                after_text = _metrics_text()

        self.assertIn("threatguard_cross_domain_correlations_total 1", after_text)
        self.assertIn("threatguard_open_incidents_total 1", after_text)
        self.assertIn("threatguard_exploitable_attack_paths_total 1", after_text)
        # The demo's incident is CRITICAL severity with both IAM and runtime
        # evidence -- it must show up under "critical", not a hardcoded number
        # under some other label.
        self.assertIn('threatguard_cloud_iam_risks_total{severity="critical"} 1', after_text)
        self.assertIn('threatguard_cloud_runtime_threats_total{severity="critical"} 3', after_text)

    def test_metrics_accumulate_across_repeated_demo_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(settings, "ARTIFACTS_FORENSICS_DIR", Path(tmp)):
                build_demo_scenario()
                one_run_text = _metrics_text()
                self.assertIn("threatguard_cross_domain_correlations_total 1", one_run_text)

                build_demo_scenario()
                two_run_text = _metrics_text()

        self.assertIn("threatguard_cross_domain_correlations_total 2", two_run_text)
        self.assertIn("threatguard_open_incidents_total 2", two_run_text)
        # Proves this isn't just a static default that happens to equal the
        # single-run value -- it genuinely moved from 1 to 2.
        self.assertNotIn("threatguard_cross_domain_correlations_total 1\n", two_run_text)


if __name__ == "__main__":
    unittest.main()
