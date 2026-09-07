"""
Unit tests for CrossDomainRiskEvaluator.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import CorrelatedCluster
from cloudnative_threatguard.correlation.cross_domain.engine.risk_evaluator import CrossDomainRiskEvaluator
from cloudnative_threatguard.correlation.cross_domain.models.event import (
    CloudProvider,
    EventSource,
    EventType,
    Severity,
    UnifiedSecurityEvent,
)


class TestUnifiedRiskEvaluator(unittest.TestCase):
    def test_combined_cross_domain_risk_calculation(self):
        iam_ev = UnifiedSecurityEvent(
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            provider=CloudProvider.AWS,
            account_id="123456789012",
            principal_arn="arn:aws:iam::123456789012:user/developer",
            role_arn="arn:aws:iam::123456789012:role/eks-deployer-role",
            action="iam:PassRole",
            severity=Severity.HIGH,
            risk_score=85.0,
            description="IAM Privilege Escalation via PassRole",
        )

        runtime_ev1 = UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=EventType.RUNTIME_DETECTION,
            provider=CloudProvider.KUBERNETES,
            namespace="threatguard",
            workload="target-deployment",
            pod="target-pod",
            action="execve:/bin/bash",
            detection_rule="TG-RULE-001",
            severity=Severity.HIGH,
            risk_score=75.0,
            description="Interactive shell execution inside container",
        )

        runtime_ev2 = UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=EventType.RUNTIME_DETECTION,
            provider=CloudProvider.KUBERNETES,
            namespace="threatguard",
            workload="target-deployment",
            pod="target-pod",
            action="openat:/var/run/secrets/kubernetes.io/serviceaccount/token",
            detection_rule="TG-RULE-004",
            severity=Severity.CRITICAL,
            risk_score=90.0,
            description="Service account credential token access",
        )

        cluster = CorrelatedCluster(
            iam_events=[iam_ev],
            runtime_events=[runtime_ev1, runtime_ev2],
        )

        assessment = CrossDomainRiskEvaluator.evaluate_cluster(cluster)

        # 34.0 (IAM PassRole: 85 * 0.4 = 34.0) + 40.0 (credential) + 25.0 (shell) + 10.0 (kill chain amplifier) -> clamped to 100.0
        self.assertGreaterEqual(assessment.overall_score, 90.0)
        self.assertEqual(assessment.severity, Severity.CRITICAL)
        self.assertEqual(assessment.remediation_urgency, "P1-Immediate")

        # Verify factors
        factor_names = [f.factor for f in assessment.factors]
        self.assertIn("iam_privilege_escalation", factor_names)
        self.assertIn("credential_access", factor_names)
        self.assertIn("runtime_shell_execution", factor_names)
        self.assertIn("cross_domain_kill_chain_correlation", factor_names)

        # Verify formula documentation
        self.assertIn("sum(IAM_Factors)", assessment.calculation_formula)


if __name__ == "__main__":
    unittest.main()
