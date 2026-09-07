"""
Unit tests for ThreatGuard Operator CLI.
Tests command dispatching, state loading, and command execution across all subcommands.
"""

import json
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from cloudnative_threatguard.cli.main import ThreatGuardCLI, build_parser
from cloudnative_threatguard.reporting.workload_resolver import KubectlOwnershipClient


class TestThreatGuardCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, "threatguard-state.json")
        # This fixture uses the same field names IncidentManager.create_incident_from_correlation()
        # actually produces (affected_pod/affected_namespace/tactics/techniques/recommendations).
        # An earlier version of this fixture used a different set of names
        # (pod_name/namespace/mitre_tactics/mitre_techniques/recommended_actions) that the CLI
        # happened to read at the time -- but that never matched what IncidentManager wrote, so
        # every incident field rendered blank against real data. Keep this aligned with
        # reporting/incidents.py's IncidentManager docstring, which documents the canonical schema.
        sample_state = {
            "incidents": {
                "#TG-TEST01": {
                    "incident_id": "#TG-TEST01",
                    "title": "Unauthorized Interactive Shell Execution",
                    "severity": "HIGH",
                    "status": "NEW",
                    "affected_pod": "target-pod",
                    "affected_namespace": "threatguard",
                    "tactics": ["Execution"],
                    "techniques": ["T1059.004"],
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
                    "recommendations": [
                        {
                            "title": "Quarantine Pod",
                            "priority": "HIGH",
                            "rationale": "Block traffic",
                            "dry_run_command": "kubectl apply --dry-run=client -f quarantine.yaml"
                        }
                    ],
                    "events": [],
                    "metadata": {},
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
        self.assertIn("target-pod", output)
        self.assertIn("Execution", output)
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

    @patch("sys.stdout", new_callable=StringIO)
    def test_remediate_command_without_live_k8s_flag_never_touches_kubectl(self, mock_stdout):
        """
        The `live_k8s` attribute is entirely absent from this Args (mirrors
        every caller of cmd_remediate before --live-k8s existed) -- the
        default (offline) behavior must be unaffected and no live lookup
        attempted.
        """
        class Args:
            incident_id = "#TG-TEST01"
            dry_run = True
            apply = False
        with patch.object(KubectlOwnershipClient, "get_owner_references") as mock_lookup:
            ret = self.cli.cmd_remediate(Args())
        self.assertEqual(ret, 0)
        mock_lookup.assert_not_called()
        self.assertNotIn("Live Kubernetes ownership lookup unavailable", mock_stdout.getvalue())

    @patch("sys.stdout", new_callable=StringIO)
    def test_remediate_command_with_live_k8s_reports_unavailable_fallback(self, mock_stdout):
        class Args:
            incident_id = "#TG-TEST01"
            dry_run = True
            apply = False
            live_k8s = True
        with patch.object(KubectlOwnershipClient, "get_owner_references", return_value=None):
            ret = self.cli.cmd_remediate(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertIn("Live Kubernetes ownership lookup unavailable; using safe fallback resolution.", output)
        self.assertIn("REMEDIATION PLAYBOOK", output)

    @patch("sys.stdout", new_callable=StringIO)
    def test_remediate_command_with_live_k8s_resolves_owner_when_available(self, mock_stdout):
        class Args:
            incident_id = "#TG-TEST01"
            dry_run = True
            apply = False
            live_k8s = True
        with patch.object(
            KubectlOwnershipClient, "get_owner_references",
            return_value=[{"kind": "Deployment", "name": "target"}],
        ):
            ret = self.cli.cmd_remediate(Args())
        self.assertEqual(ret, 0)
        output = mock_stdout.getvalue()
        self.assertNotIn("Live Kubernetes ownership lookup unavailable", output)
        self.assertIn("deployment/target", output)

    def test_remediate_subparser_live_k8s_flag_is_opt_in(self):
        parser = build_parser()
        default_args = parser.parse_args(["remediate", "#TG-TEST01"])
        self.assertFalse(default_args.live_k8s)
        flagged_args = parser.parse_args(["remediate", "#TG-TEST01", "--live-k8s"])
        self.assertTrue(flagged_args.live_k8s)

    def test_report_incidents_export(self):
        output_file = os.path.join(self.temp_dir.name, "report.json")
        class Args:
            output = output_file
        ret = self.cli.cmd_report_incidents(Args())
        self.assertEqual(ret, 0)
        self.assertTrue(os.path.exists(output_file))
        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["incidents_total"], 1)


if __name__ == "__main__":
    unittest.main()
