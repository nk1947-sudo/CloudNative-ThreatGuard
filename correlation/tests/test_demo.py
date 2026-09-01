"""
Unit tests for deterministic cross-domain cloud security demo.
"""

import unittest
import os
from correlation.demo.deterministic_demo import build_demo_scenario


class TestDeterministicDemo(unittest.TestCase):
    def test_demo_execution_and_evidence_generation(self):
        res = build_demo_scenario()

        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["demo_mode"], "DETERMINISTIC_OFFLINE")
        self.assertIn("SIMULATED_DEMO_DATA", res["label"])

        # Incident checks
        inc = res["incident"]
        self.assertTrue(inc["incident_id"].startswith("CDI-"))
        self.assertGreaterEqual(inc["risk_score"], 90.0)
        self.assertEqual(len(inc["remediation_proposals"]), 2)

        # Attack chain checks
        chain = res["attack_chain"]
        self.assertTrue(chain["is_cross_domain"])
        self.assertGreaterEqual(len(chain["stages"]), 4)

        # Graph checks
        graph = res["graph"]
        self.assertGreaterEqual(graph["node_count"], 6)
        self.assertGreaterEqual(graph["edge_count"], 5)

        # Mermaid output
        self.assertIn("flowchart TD", res["mermaid_diagram"])

        # File output check
        from correlation.demo.deterministic_demo import PROJECT_ROOT
        evidence_file = os.path.join(PROJECT_ROOT, "artifacts", "forensics", "cloud_security_demo_evidence.json")
        self.assertTrue(os.path.exists(evidence_file))
        self.assertGreater(os.path.getsize(evidence_file), 100)


if __name__ == "__main__":
    unittest.main()
