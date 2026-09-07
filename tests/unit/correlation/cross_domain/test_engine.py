"""
Unit tests for CrossDomainCorrelationEngine.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import CrossDomainCorrelationEngine
from cloudnative_threatguard.correlation.cross_domain.models.event import (
    CloudProvider,
    EventSource,
    EventType,
    Severity,
    UnifiedSecurityEvent,
)
from cloudnative_threatguard.correlation.cross_domain.models.mapping import (
    IdentityBinding,
    IdentityMappingRegistry,
    MappingMechanism,
)


class TestCrossDomainCorrelation(unittest.TestCase):
    def setUp(self):
        self.registry = IdentityMappingRegistry()
        self.binding = IdentityBinding(
            cloud_provider="aws",
            cloud_identity="arn:aws:iam::123456789012:role/eks-deployer-role",
            cluster="threatguard-cluster",
            kubernetes_identity="threatguard-deployer",
            namespace="threatguard",
            service_account="threatguard-workload-sa",
            workload="threatguard-target-pod",
            mapping_mechanism=MappingMechanism.EKS_ACCESS_ENTRY,
        )
        self.registry.register(self.binding)
        self.engine = CrossDomainCorrelationEngine(mapping_registry=self.registry)

    def test_cross_domain_attack_chain_correlation(self):
        # 1. IAM Finding Event (CloudGraphGuard)
        iam_event = UnifiedSecurityEvent(
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            provider=CloudProvider.AWS,
            account_id="123456789012",
            principal_arn="arn:aws:iam::123456789012:user/developer",
            role_arn="arn:aws:iam::123456789012:role/eks-deployer-role",
            action="iam:PassRole",
            severity=Severity.HIGH,
            risk_score=80.0,
            description="Developer can pass role to compute",
        )

        # 2. Runtime Shell Execution Event (ThreatGuard)
        runtime_event = UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=EventType.RUNTIME_DETECTION,
            provider=CloudProvider.KUBERNETES,
            cluster_id="threatguard-cluster",
            namespace="threatguard",
            workload="threatguard-target-pod",
            pod="threatguard-target-pod-xyz",
            service_account="threatguard-workload-sa",
            action="execve:/bin/bash",
            severity=Severity.CRITICAL,
            risk_score=90.0,
            description="Unauthorized shell spawned inside pod",
        )

        # Ingest events
        self.assertTrue(self.engine.ingest_event(iam_event))
        self.assertTrue(self.engine.ingest_event(runtime_event))

        # Re-ingesting duplicate should return False
        self.assertFalse(self.engine.ingest_event(iam_event))

        # Correlate
        clusters = self.engine.correlate()
        self.assertEqual(len(clusters), 1)

        cluster = clusters[0]
        self.assertIsNotNone(cluster.attack_chain)
        chain = cluster.attack_chain

        self.assertTrue(chain.is_cross_domain)
        self.assertEqual(chain.cloud_principal, "arn:aws:iam::123456789012:user/developer")
        self.assertEqual(chain.cloud_role, "arn:aws:iam::123456789012:role/eks-deployer-role")
        self.assertEqual(chain.kubernetes_workload, "threatguard-target-pod")
        self.assertGreaterEqual(chain.composite_risk, 90.0)

        # Verify stages: Stage 1 (IAM) -> Stage 2 (EKS Transition) -> Stage 3 (Runtime)
        self.assertEqual(len(chain.stages), 3)
        self.assertEqual(chain.stages[0]["domain"], "CLOUD_IAM")
        self.assertEqual(chain.stages[1]["domain"], "EKS_ACCESS_TRANSITION")
        self.assertEqual(chain.stages[2]["domain"], "K8S_RUNTIME")


if __name__ == "__main__":
    unittest.main()
