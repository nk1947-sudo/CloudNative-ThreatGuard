"""
Unit tests for ThreatGuard Operator CLI.
Tests command dispatching, state loading, and command execution across all subcommands.
"""

import unittest
import os
import tempfile
import json
from io import StringIO
from unittest.mock import patch
from runtime.cli import ThreatGuardCLI, main


class TestThreatGuardCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, "threatguard-state.json")
        sample_state = {
            "incidents": {
                "#TG-TEST01": {
                    "incident_id": "#TG-TEST01",
                    "title": "Unauthorized Interactive Shell Execution",
                    "severity": "HIGH",
                    "status": "NEW",
                    "pod_name": "target-pod",
                    "namespace": "threatguard",
                    "mitre_tactics": ["Execution"],
                    "mitre_techniques": ["T1059.004"],
                    "description": "Shell process executed",
                    "attack_chain": [
                        {
                            "step": 1,
                            "tactic": "Execution",
                            "technique": "T1059.004",
                            "label": "Spawn /bin/sh",
                            "process": "/bin/sh",
                            "severity": "HIGH",
                            "evidence": {}
                        }
                    ],
                    "recommended_actions": [
                        {
                            "title": "Quarantine Pod",
                            "priority": "HIGH",
                            "rationale": "Block traffic",
                            "execution_command": "kubectl apply -f quarantine.yaml"
                        }
                    ],
                    "events": []
                }
            },
            "audit_log": []
        }
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(sample_state, f)
        self.cli = ThreatGuardCLI(state_file=self.state_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("sys.stdout", new_callable=StringIO)
    def test_status_command(self, mock_stdout):
        class Args:
            pass
        ret = self.cli.cmd_status(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertIn("SYSTEM STATUS", output)
        self.assertIn("Detection Engine Rules", output)

    @patch("sys.stdout", new_callable=StringIO)
    def test_incidents_list(self, mock_stdout):
        class Args:
            status = None
            severity = None
        ret = self.cli.cmd_incidents_list(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertIn("#TG-TEST01", output)
        self.assertIn("target-pod", output)

    @patch("sys.stdout", new_callable=StringIO)
    def test_incidents_show(self, mock_stdout):
        class Args:
            incident_id = "#TG-TEST01"
            format = "ascii"
        ret = self.cli.cmd_incidents_show(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertIn("#TG-TEST01", output)
        self.assertIn("ATTACK CHAIN TIMELINE", output)

    @patch("sys.stdout", new_callable=StringIO)
    def test_remediate_command(self, mock_stdout):
        class Args:
            incident_id = "#TG-TEST01"
            dry_run = True
            apply = False
        ret = self.cli.cmd_remediate(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertIn("REMEDIATION PLAYBOOK", output)
        self.assertIn("DRY-RUN MODE", output)

    def test_report_export(self):
        output_file = os.path.join(self.temp_dir.name, "report.json")
        class Args:
            output = output_file
        ret = self.cli.cmd_report_export(Args())
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(output_file))
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["incidents_total"], 1)


if __name__ == "__main__":
    unittest.main()
