"""
Unit tests for CrossDomainIncident and UnifiedIncidentManager.
"""

import tempfile
import unittest
from pathlib import Path

from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import (
    CorrelatedAttackChain,
    CorrelatedCluster,
)
from cloudnative_threatguard.correlation.cross_domain.models.event import (
    CloudProvider,
    EventSource,
    EventType,
    Severity,
    UnifiedSecurityEvent,
)
from cloudnative_threatguard.correlation.cross_domain.models.incident import (
    IncidentStatus,
    UnifiedIncidentManager,
)
from cloudnative_threatguard.correlation.cross_domain.models.mapping import IdentityBinding, MappingMechanism


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

        # Regression guard: each source finding's own severity must survive
        # correlation even though it differs from the incident's overall
        # (aggregated) severity -- the IAM event here is HIGH, the runtime
        # event is CRITICAL, and the incident as a whole is CRITICAL.
        self.assertEqual(len(incident.contributing_findings), 2)
        iam_finding = next(f for f in incident.contributing_findings if f.source == EventSource.CLOUDGRAPHGUARD)
        runtime_finding = next(f for f in incident.contributing_findings if f.source == EventSource.THREATGUARD)
        self.assertEqual(iam_finding.severity, Severity.HIGH)
        self.assertEqual(iam_finding.event_type, EventType.IAM_RISK)
        self.assertEqual(runtime_finding.severity, Severity.CRITICAL)
        self.assertEqual(runtime_finding.event_type, EventType.RUNTIME_DETECTION)
        self.assertEqual(incident.severity, Severity.CRITICAL)

        # All remediations must be dry-run
        for r in incident.remediation_proposals:
            self.assertTrue(r.is_dry_run_only)
            self.assertGreater(len(r.dry_run_command), 0)

        # Verify status transitions
        self.assertTrue(manager.update_status(incident.incident_id, IncidentStatus.INVESTIGATING))
        updated = manager.get_incident(incident.incident_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, IncidentStatus.INVESTIGATING)


class TestUnifiedIncidentManagerPersistence(unittest.TestCase):
    """
    Persistence is what lets a separate process (the metrics exporter) see
    incidents created by another process (the demo / a future live pipeline)
    -- without it, cross-domain metrics have no real state to reflect.
    """

    def _make_manager_with_one_incident(self) -> UnifiedIncidentManager:
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
        cluster = CorrelatedCluster(
            binding=binding,
            iam_events=[
                UnifiedSecurityEvent(
                    source=EventSource.CLOUDGRAPHGUARD,
                    event_type=EventType.IAM_RISK,
                    provider=CloudProvider.AWS,
                    principal_arn="arn:aws:iam::123456789012:user/developer",
                    severity=Severity.CRITICAL,
                    risk_score=90.0,
                    description="Privilege escalation via PassRole",
                )
            ],
            runtime_events=[
                UnifiedSecurityEvent(
                    source=EventSource.THREATGUARD,
                    event_type=EventType.RUNTIME_DETECTION,
                    provider=CloudProvider.KUBERNETES,
                    pod="threatguard-target-pod-12345",
                    severity=Severity.CRITICAL,
                    risk_score=94.0,
                    description="Service account token accessed",
                )
            ],
            attack_chain=CorrelatedAttackChain(title="Cross-Domain Attack Chain", composite_risk=94.0, is_cross_domain=True),
        )
        manager = UnifiedIncidentManager()
        manager.create_from_cluster(cluster)
        return manager

    def test_save_then_load_round_trips_incident_data(self):
        manager = self._make_manager_with_one_incident()
        original = manager.list_incidents()[0]

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cross-domain-incidents.json"
            manager.save(path)
            self.assertTrue(path.exists())

            reloaded = UnifiedIncidentManager.load(path)

        reloaded_incidents = reloaded.list_incidents()
        self.assertEqual(len(reloaded_incidents), 1)
        self.assertEqual(reloaded_incidents[0].incident_id, original.incident_id)
        self.assertEqual(reloaded_incidents[0].severity, original.severity)
        self.assertEqual(reloaded_incidents[0].evidence_summary, original.evidence_summary)
        self.assertEqual(len(reloaded_incidents[0].contributing_findings), len(original.contributing_findings))
        self.assertEqual(
            [f.severity for f in reloaded_incidents[0].contributing_findings],
            [f.severity for f in original.contributing_findings],
        )

    def test_load_missing_file_returns_empty_manager_not_an_error(self):
        manager = UnifiedIncidentManager.load("/nonexistent/path/incidents.json")
        self.assertEqual(manager.list_incidents(), [])

    def test_save_append_load_grows_the_persisted_collection(self):
        """Mirrors how the offline demo accumulates incidents across runs."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cross-domain-incidents.json"

            first_manager = self._make_manager_with_one_incident()
            first_manager.save(path)
            self.assertEqual(len(UnifiedIncidentManager.load(path).list_incidents()), 1)

            combined = UnifiedIncidentManager.load(path)
            second_manager = self._make_manager_with_one_incident()
            for incident in second_manager.list_incidents():
                combined.register(incident)
            combined.save(path)

            self.assertEqual(len(UnifiedIncidentManager.load(path).list_incidents()), 2)


if __name__ == "__main__":
    unittest.main()
