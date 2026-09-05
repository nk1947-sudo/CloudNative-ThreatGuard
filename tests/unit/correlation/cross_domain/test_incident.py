"""
Unit tests for CrossDomainIncident and UnifiedIncidentManager.
"""

import unittest
from cloudnative_threatguard.correlation.cross_domain.models.event import (
    UnifiedSecurityEvent,
    EventSource,
    EventType,
    CloudProvider,
    Severity,
)
from cloudnative_threatguard.correlation.cross_domain.models.mapping import IdentityBinding, MappingMechanism
from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import CorrelatedCluster, CorrelatedAttackChain
from cloudnative_threatguard.correlation.cross_domain.models.incident import (
    UnifiedIncidentManager,
    IncidentStatus,
)


class TestUnifiedIncident(unittest.TestCase):
    def test_incident_creation_and_remediation_proposals(self):
        binding = IdentityBinding(
            cloud_provider="aws",
            cloud_identity="arn:aws:iam::123456789012:role/eks-deployer-role",
            cluster="threatguard-cluster",
            kubernetes_identity="threatguard-deployer",
            namespace="threatguard",
            service_account="threatguard-workload-sa",
            workload="threatguard-target-pod",
            mapping_mechanism=MappingMechanism.EKS_ACCESS_ENTRY,
        )

        iam_event = UnifiedSecurityEvent(
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            provider=CloudProvider.AWS,
            account_id="123456789012",
            principal_arn="arn:aws:iam::123456789012:user/developer",
            role_arn="arn:aws:iam::123456789012:role/eks-deployer-role",
            action="iam:PassRole",
            severity=Severity.HIGH,
            risk_score=85.0,
            description="Privilege escalation via PassRole",
        )

        runtime_event = UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=EventType.RUNTIME_DETECTION,
            provider=CloudProvider.KUBERNETES,
            cluster_id="threatguard-cluster",
            namespace="threatguard",
            workload="threatguard-target-pod",
            pod="threatguard-target-pod-12345",
            service_account="threatguard-workload-sa",
            action="openat:/var/run/secrets/kubernetes.io/serviceaccount/token",
            severity=Severity.CRITICAL,
            risk_score=94.0,
            description="Service account token accessed",
        )

        cluster = CorrelatedCluster(
            binding=binding,
            iam_events=[iam_event],
            runtime_events=[runtime_event],
            attack_chain=CorrelatedAttackChain(
                title="Cross-Domain Attack Chain",
                cloud_principal="arn:aws:iam::123456789012:user/developer",
                cloud_role="arn:aws:iam::123456789012:role/eks-deployer-role",
                kubernetes_cluster="threatguard-cluster",
                kubernetes_workload="threatguard-target-pod",
                service_account="threatguard-workload-sa",
                composite_risk=94.0,
                is_cross_domain=True,
            ),
        )

        manager = UnifiedIncidentManager()
        incident = manager.create_from_cluster(cluster)

        self.assertTrue(incident.incident_id.startswith("CDI-"))
        self.assertEqual(incident.severity, Severity.CRITICAL)
        self.assertEqual(incident.risk_score, 94.0)
        self.assertEqual(incident.status, IncidentStatus.NEW)
        self.assertIn("developer", incident.attack_chain)
        self.assertIn("eks-deployer-role", incident.attack_chain)
        self.assertIn("threatguard-target-pod", incident.attack_chain)

        # Verify dual-track remediation proposals
        domains = [r.domain for r in incident.remediation_proposals]
        self.assertIn("CLOUD_IAM", domains)
        self.assertIn("KUBERNETES_RUNTIME", domains)

        # All remediations must be dry-run
        for r in incident.remediation_proposals:
            self.assertTrue(r.is_dry_run_only)
            self.assertGreater(len(r.dry_run_command), 0)

        # Verify status transitions
        self.assertTrue(manager.update_status(incident.incident_id, IncidentStatus.INVESTIGATING))
        updated = manager.get_incident(incident.incident_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, IncidentStatus.INVESTIGATING)


if __name__ == "__main__":
    unittest.main()
