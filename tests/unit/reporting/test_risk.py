"""
Unit tests for the Transparent Risk Scoring Engine in CloudNative ThreatGuard.
"""

import unittest
from cloudnative_threatguard.runtime.events import SecurityEvent, Severity
from cloudnative_threatguard.reporting.risk import RiskScoringEngine, RiskTier, RiskAssessment


class TestRiskScoringEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskScoringEngine()

    def test_empty_workload_evaluation(self):
        assessment = self.engine.evaluate_workload([], workload_ref="threatguard/empty-pod")
        self.assertEqual(assessment.composite_risk_score, 0.0)
        self.assertEqual(assessment.risk_tier, RiskTier.LOW.value)
        self.assertEqual(len(assessment.top_risk_contributors), 0)

    def test_single_low_severity_event(self):
        event = SecurityEvent(
            severity="LOW",
            mitre_technique="T1082",
            process="/usr/bin/whoami",
            timestamp="2026-09-05T12:00:00Z"
        )
        assessment = self.engine.evaluate_workload([event], workload_ref="threatguard-lab/recon-pod")
        self.assertGreater(assessment.composite_risk_score, 0.0)
        self.assertLess(assessment.composite_risk_score, 50.0)
        self.assertIn(assessment.risk_tier, [RiskTier.LOW.value, RiskTier.MEDIUM.value])

    def test_multi_stage_critical_attack_burst(self):
        events = [
            SecurityEvent(
                severity="CRITICAL",
                mitre_technique="T1059.004",
                process="/bin/sh",
                action="process_exec",
                timestamp="2026-09-05T12:00:00Z"
            ),
            SecurityEvent(
                severity="CRITICAL",
                mitre_technique="T1552.007",
                process="/bin/cat",
                action="file_read",
                timestamp="2026-09-05T12:00:15Z"
            ),
            SecurityEvent(
                severity="HIGH",
                mitre_technique="T1071",
                process="/usr/bin/curl",
                action="net_connect",
                timestamp="2026-09-05T12:00:30Z"
            )
        ]
        workload_spec = {
            "privileged": True,
            "runAsUser": 0,
            "hostPID": True
        }
        assessment = self.engine.evaluate_workload(
            events,
            workload_ref="threatguard/compromised-pod",
            workload_spec=workload_spec
        )
        # Highly privileged container with shell + token read + outbound connection in 30s
        self.assertGreaterEqual(assessment.composite_risk_score, 85.0)
        self.assertEqual(assessment.risk_tier, RiskTier.CRITICAL.value)
        self.assertLessEqual(assessment.composite_risk_score, 100.0)

        # Check top risk contributors
        factor_names = [c.factor_name for c in assessment.top_risk_contributors]
        self.assertIn("Privileged Container", factor_names)
        self.assertIn("Behavioral Severity", factor_names)

        # Check serialization
        d = assessment.to_dict()
        self.assertEqual(d["risk_tier"], "CRITICAL")
        self.assertIn("factor_breakdown", d)
        self.assertIn("top_risk_contributors", d)


if __name__ == "__main__":
    unittest.main()
