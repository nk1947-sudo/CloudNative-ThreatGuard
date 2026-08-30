"""
Unit tests for UnifiedSecurityEvent (v1.0) model.
"""

import unittest
from correlation.models.event import (
    UnifiedSecurityEvent,
    EventSource,
    EventType,
    CloudProvider,
    Severity,
)


class TestUnifiedSecurityEventModel(unittest.TestCase):
    def test_iam_event_instantiation(self):
        event = UnifiedSecurityEvent(
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            provider=CloudProvider.AWS,
            account_id="123456789012",
            principal_id="AIDAIEXAMPLEUSER",
            principal_arn="arn:aws:iam::123456789012:user/developer",
            role_arn="arn:aws:iam::123456789012:role/eks-deployer",
            severity=Severity.HIGH,
            risk_score=75.0,
            confidence=0.95,
            detection_rule="IAM_PRIVILEGE_ESCALATION_PASSROLE",
            description="Principal can pass role to EC2/Lambda to escalate privileges",
            evidence={"vector": "iam:PassRole", "target_role": "admin-role"},
        )

        self.assertEqual(event.schema_version, "1.0")
        self.assertTrue(event.event_id.startswith("USE-"))
        self.assertEqual(event.source, "cloudgraphguard")
        self.assertEqual(event.event_type, "iam_risk")
        self.assertEqual(event.provider, "aws")
        self.assertEqual(event.risk_score, 75.0)

        # Test dictionary serialization
        data = event.to_dict()
        self.assertEqual(data["principal_arn"], "arn:aws:iam::123456789012:user/developer")
        self.assertEqual(data["severity"], "high")

        # Test round-trip reconstruction
        reconstructed = UnifiedSecurityEvent.from_dict(data)
        self.assertEqual(reconstructed.event_id, event.event_id)
        self.assertEqual(reconstructed.risk_score, event.risk_score)

    def test_runtime_event_instantiation(self):
        event = UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=EventType.RUNTIME_DETECTION,
            provider=CloudProvider.KUBERNETES,
            cluster_id="kind-threatguard-cluster",
            namespace="threatguard",
            workload="threatguard-target-deployment",
            pod="threatguard-target-pod",
            service_account="threatguard-workload-sa",
            action="execve",
            severity=Severity.CRITICAL,
            risk_score=90.0,
            detection_rule="TG-RULE-001",
            description="Unauthorized interactive shell spawned inside container",
            evidence={"binary": "/bin/bash", "parent": "nginx"},
        )

        self.assertEqual(event.source, "threatguard")
        self.assertEqual(event.event_type, "runtime_detection")
        self.assertEqual(event.namespace, "threatguard")
        self.assertEqual(event.service_account, "threatguard-workload-sa")
        self.assertEqual(event.severity, "critical")

    def test_score_bounds_validation(self):
        with self.assertRaises(Exception):
            UnifiedSecurityEvent(
                source=EventSource.THREATGUARD,
                event_type=EventType.ADMISSION_VIOLATION,
                provider=CloudProvider.KUBERNETES,
                severity=Severity.LOW,
                risk_score=150.0,  # exceeds 100.0
                description="Invalid high score",
            )


if __name__ == "__main__":
    unittest.main()
