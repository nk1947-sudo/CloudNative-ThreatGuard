"""
Unit tests for ThreatGuard Forensic Evidence Collector.
Validates generation of all audit files (JSONL, JSON, MMD, HTML, MD).
"""

import unittest
import os
import tempfile
import json
from cloudnative_threatguard.reporting.evidence import ForensicEvidenceCollector


class TestEvidenceCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.collector = ForensicEvidenceCollector(artifacts_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_evidence_package_generation(self):
        files = self.collector.generate_evidence_package()

        self.assertIn("normalized_events", files)
        self.assertIn("incidents", files)
        self.assertIn("risk_assessments", files)
        self.assertIn("attack_chain_mermaid", files)
        self.assertIn("attack_chain_html", files)
        self.assertIn("executive_md", files)
        self.assertIn("executive_html", files)

        for path in files.values():
            self.assertTrue(os.path.exists(path))
            self.assertGreater(os.path.getsize(path), 0)

        # Check correlated incidents content
        with open(files["incidents"], "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertIn("incidents", data)
            self.assertGreater(len(data["incidents"]), 0)


if __name__ == "__main__":
    unittest.main()
