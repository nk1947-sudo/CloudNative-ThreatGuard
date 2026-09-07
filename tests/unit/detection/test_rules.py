"""
Unit tests for the Detection Rule Engine and Rule Registry in CloudNative ThreatGuard.
"""

import unittest

from cloudnative_threatguard.detection.rules import DETECTION_RULES, DetectionRule, RuleRegistry


class TestRuleRegistry(unittest.TestCase):
    def setUp(self):
        self.reg = RuleRegistry()

    def test_default_rules_registered(self):
        rules = self.reg.list_rules()
        self.assertGreaterEqual(len(rules), 6)
        rule_ids = [r.rule_id for r in rules]
        self.assertIn("RUNTIME-001", rule_ids)
        self.assertIn("RUNTIME-004", rule_ids)
        self.assertIn("RULE-K8S-007", rule_ids)

    def test_rule_evaluation_binary(self):
        rule = self.reg.get("RUNTIME-001")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.evaluate({"binary": "/bin/bash"}))
        self.assertTrue(rule.evaluate({"binary": "sh"}))
        self.assertFalse(rule.evaluate({"binary": "/usr/bin/nginx"}))

    def test_rule_evaluation_path(self):
        rule = self.reg.get("RUNTIME-004")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.evaluate({"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}))
        self.assertTrue(rule.evaluate({"path": "/etc/shadow"}))
        self.assertFalse(rule.evaluate({"path": "/app/index.html"}))

    def test_rule_enable_disable(self):
        rule_id = "RUNTIME-002"
        self.assertTrue(self.reg.get(rule_id).enabled)
        self.reg.disable_rule(rule_id)
        self.assertFalse(self.reg.get(rule_id).enabled)
        # Should evaluate to False when disabled even if match
        self.assertFalse(self.reg.get(rule_id).evaluate({"binary": "curl"}))
        self.reg.enable_rule(rule_id)
        self.assertTrue(self.reg.get(rule_id).evaluate({"binary": "curl"}))

    def test_custom_predicate_rule(self):
        custom = DetectionRule(
            rule_id="CUSTOM-001",
            name="Suspicious Low UID",
            description="Process running with UID 0",
            severity="CRITICAL",
            confidence=0.99,
            mitre_technique="T1068",
            mitre_tactic="Privilege Escalation",
            technique_name="Exploitation for Privilege Escalation",
            predicate=lambda ctx: ctx.get("uid") == 0 and ctx.get("namespace") == "threatguard"
        )
        self.reg.register(custom)
        self.assertTrue(self.reg.get("CUSTOM-001").evaluate({"uid": 0, "namespace": "threatguard"}))
        self.assertFalse(self.reg.get("CUSTOM-001").evaluate({"uid": 10001, "namespace": "threatguard"}))

    def test_legacy_dict_compatibility(self):
        self.assertIn("RUNTIME-001", DETECTION_RULES)
        self.assertEqual(DETECTION_RULES["RUNTIME-001"]["severity"], "CRITICAL")
        self.assertEqual(DETECTION_RULES["RUNTIME-001"]["technique"], "T1059.004")


if __name__ == "__main__":
    unittest.main()
