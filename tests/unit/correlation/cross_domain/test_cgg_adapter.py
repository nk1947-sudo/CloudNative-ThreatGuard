"""
Unit tests for CloudGraphGuardAdapter.
"""

import unittest
from cloudnative_threatguard.cloudgraphguard.models.findings import IAMFinding, FindingType, PrivilegeEscalationVector
from cloudnative_threatguard.correlation.cross_domain.adapters.cgg_adapter import CloudGraphGuardAdapter
from cloudnative_threatguard.correlation.cross_domain.models.event import EventSource, EventType, CloudProvider, Severity


class TestCloudGraphGuardAdapter(unittest.TestCase):
    def test_adapter_privilege_escalation_finding(self):
        finding = IAMFinding(
            finding_type=FindingType.IAM_PRIVILEGE_ESCALATION,
            title="IAM Privilege Escalation via iam:PassRole",
            description="developer can pass role to compute service",
            severity="critical",
            risk_score=88.5,
            principal_arn="arn:aws:iam::123456789012:user/developer",
            principal_name="developer",
            account_id="123456789012",
            target_role_arn="arn:aws:iam::123456789012:role/eks-deployer-role",
            escalation_vector=PrivilegeEscalationVector.PASS_ROLE,
            effective_actions=["iam:PassRole", "ec2:RunInstances"],
            remediation_suggestion="Scope PassRole resource ARN",
            evidence={"vector": "iam:PassRole"},
        )

        event = CloudGraphGuardAdapter.to_unified_event(finding)

        self.assertEqual(event.source, EventSource.CLOUDGRAPHGUARD)
        self.assertEqual(event.event_type, EventType.IAM_RISK)
        self.assertEqual(event.provider, CloudProvider.AWS)
        self.assertEqual(event.principal_id, "developer")
        self.assertEqual(event.principal_arn, "arn:aws:iam::123456789012:user/developer")
        self.assertEqual(event.role_arn, "arn:aws:iam::123456789012:role/eks-deployer-role")
        self.assertEqual(event.severity, Severity.CRITICAL)
        self.assertEqual(event.risk_score, 88.5)
        self.assertEqual(event.action, "iam:PassRole")
        self.assertIn("remediation_suggestion", event.evidence)
        self.assertEqual(event.metadata["engine"], "cloudgraphguard")

    def test_adapter_dict_conversion(self):
        finding_dict = {
            "finding_type": "IAM_EXCESSIVE_PERMISSION",
            "title": "Excessive S3 Access",
            "description": "User has s3:* access to all buckets",
            "severity": "high",
            "risk_score": 70.0,
            "principal_arn": "arn:aws:iam::123456789012:user/analyst",
            "principal_name": "analyst",
            "account_id": "123456789012",
            "target_resource_arn": "arn:aws:s3:::prod-customer-data",
            "effective_actions": ["s3:GetObject", "s3:PutObject"],
        }

        event = CloudGraphGuardAdapter.to_unified_event(finding_dict)
        self.assertEqual(event.source, EventSource.CLOUDGRAPHGUARD)
        self.assertEqual(event.resource_arn, "arn:aws:s3:::prod-customer-data")
        self.assertEqual(event.severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
