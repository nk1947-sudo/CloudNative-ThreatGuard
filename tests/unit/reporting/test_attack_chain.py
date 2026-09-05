"""
Unit tests for Attack Chain Visualization Engine.
Validates JSON graph construction, Mermaid flowchart output, ASCII diagrams, and HTML components.
"""

import unittest
from cloudnative_threatguard.reporting.attack_chain import AttackChainVisualizer


class TestAttackChainVisualizer(unittest.TestCase):
    def setUp(self):
        self.mock_incident = {
            "incident_id": "#TG-CHAIN01",
            "title": "Interactive Shell to Outbound C2 Progression",
            "severity": "CRITICAL",
            "affected_namespace": "threatguard",
            "affected_pod": "threatguard-target-pod",
            "attack_chain": [
                {
                    "node_id": "step-1",
                    "step": 1,
                    "tactic": "Execution",
                    "technique": "T1059.004",
                    "label": "Interactive Shell Spawned",
                    "process": "/bin/sh",
                    "severity": "HIGH",
                    "timestamp": "2026-09-05T12:00:00Z"
                },
                {
                    "node_id": "step-2",
                    "step": 2,
                    "tactic": "Credential Access",
                    "technique": "T1552.007",
                    "label": "Service Account Token Read",
                    "process": "/bin/cat",
                    "severity": "CRITICAL",
                    "timestamp": "2026-09-05T12:01:00Z"
                },
                {
                    "node_id": "step-3",
                    "step": 3,
                    "tactic": "Command and Control",
                    "technique": "T1071.001",
                    "label": "Outbound Connection to External IP",
                    "process": "/usr/bin/curl",
                    "severity": "HIGH",
                    "timestamp": "2026-09-05T12:02:00Z"
                }
            ]
        }
        self.visualizer = AttackChainVisualizer(self.mock_incident)

    def test_to_json(self):
        graph = self.visualizer.to_json()
        self.assertEqual(graph["incident_id"], "#TG-CHAIN01")
        self.assertEqual(graph["node_count"], 3)
        self.assertEqual(len(graph["nodes"]), 3)
        self.assertEqual(len(graph["edges"]), 2)
        self.assertEqual(graph["edges"][0]["source"], "step-1")
        self.assertEqual(graph["edges"][0]["target"], "step-2")
        self.assertEqual(graph["edges"][1]["source"], "step-2")
        self.assertEqual(graph["edges"][1]["target"], "step-3")

    def test_to_mermaid(self):
        mmd = self.visualizer.to_mermaid()
        self.assertIn("flowchart TD", mmd)
        self.assertIn("step_1", mmd)
        self.assertIn("step_2", mmd)
        self.assertIn("step_3", mmd)
        self.assertIn("step_1 -->|leads to| step_2", mmd)
        self.assertIn("step_2 -->|leads to| step_3", mmd)
        self.assertIn("class step_2 crit", mmd)

    def test_to_ascii(self):
        ascii_view = self.visualizer.to_ascii()
        self.assertIn("ThreatGuard Attack Chain: #TG-CHAIN01", ascii_view)
        self.assertIn("Step 1: Execution (T1059.004) [HIGH]", ascii_view)
        self.assertIn("Step 2: Credential Access (T1552.007) [CRITICAL]", ascii_view)
        self.assertIn("Step 3: Command and Control (T1071.001) [HIGH]", ascii_view)
        self.assertIn("▼  (escalates to)", ascii_view)

    def test_to_html_snippet(self):
        html_out = self.visualizer.to_html_snippet()
        self.assertIn("#TG-CHAIN01", html_out)
        self.assertIn("threatguard/threatguard-target-pod", html_out)
        self.assertIn("T1059.004", html_out)
        self.assertIn("T1552.007", html_out)
        self.assertIn("T1071.001", html_out)
        self.assertIn("CRITICAL", html_out)


if __name__ == "__main__":
    unittest.main()
