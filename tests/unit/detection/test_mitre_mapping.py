"""
Unit tests for MITRE ATT&CK for Containers taxonomy in CloudNative ThreatGuard.
"""

import unittest

from cloudnative_threatguard.detection.mitre_mapping import get_mitre_mapping, list_tactics


class TestMitreMapping(unittest.TestCase):
    def test_required_tactics_covered(self):
        tactics = list_tactics()
        required_tactics = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Command and Control",
            "Impact"
        ]
        for req in required_tactics:
            self.assertIn(req, tactics, f"Missing required MITRE tactic: {req}")

    def test_technique_retrieval(self):
        mapping = get_mitre_mapping("T1059.004")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.tactic, "Execution")
        self.assertEqual(mapping.technique_id, "T1059")
        self.assertEqual(mapping.subtechnique_id, "T1059.004")
        self.assertIn("Tetragon", mapping.detection_control)

    def test_credential_access_technique(self):
        mapping = get_mitre_mapping("T1552.007")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.tactic, "Credential Access")
        self.assertIn("automountServiceAccountToken", mapping.prevention_control)

    def test_escape_to_host_technique(self):
        mapping = get_mitre_mapping("T1611")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.tactic, "Privilege Escalation")
        self.assertIn("privileged", mapping.prevention_control.lower())


if __name__ == "__main__":
    unittest.main()
