"""
Unit tests for Identity-to-Kubernetes Mapping Model and Registry.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.models.mapping import (
    IdentityBinding,
    IdentityMappingRegistry,
    MappingMechanism,
)


class TestIdentityMapping(unittest.TestCase):
    def setUp(self):
        self.registry = IdentityMappingRegistry()
        self.binding1 = IdentityBinding(
            cloud_provider="aws",
            cloud_identity="arn:aws:iam::123456789012:role/eks-deployer-role",
            cloud_identity_type="IAM_ROLE",
            cluster="arn:aws:eks:us-east-1:123456789012:cluster/threatguard-cluster",
            kubernetes_identity="threatguard-deployer",
            namespace="threatguard",
            service_account="threatguard-workload-sa",
            workload="threatguard-target-pod",
            mapping_mechanism=MappingMechanism.EKS_ACCESS_ENTRY,
        )
        self.binding2 = IdentityBinding(
            cloud_provider="aws",
            cloud_identity="arn:aws:iam::123456789012:role/analytics-worker-role",
            cloud_identity_type="IAM_ROLE",
            cluster="arn:aws:eks:us-east-1:123456789012:cluster/threatguard-cluster",
            kubernetes_identity="analytics-worker",
            namespace="threatguard",
            service_account="analytics-sa",
            workload="analytics-worker",
            mapping_mechanism=MappingMechanism.IRSA,
        )
        self.registry.register(self.binding1)
        self.registry.register(self.binding2)

    def test_find_by_cloud_identity(self):
        results = self.registry.find_by_cloud_identity("arn:aws:iam::123456789012:role/eks-deployer-role")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].workload, "threatguard-target-pod")
        self.assertEqual(results[0].service_account, "threatguard-workload-sa")

    def test_find_by_k8s_workload(self):
        results = self.registry.find_by_k8s_workload("threatguard", "threatguard-target-pod")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cloud_identity, "arn:aws:iam::123456789012:role/eks-deployer-role")

    def test_find_by_service_account(self):
        results = self.registry.find_by_service_account("threatguard", "analytics-sa")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].workload, "analytics-worker")

    def test_serialization_roundtrip(self):
        data = self.registry.to_dict()
        self.assertIn("bindings", data)
        self.assertEqual(len(data["bindings"]), 2)

        reloaded = IdentityMappingRegistry.from_dict(data)
        self.assertEqual(len(reloaded.get_all()), 2)


if __name__ == "__main__":
    unittest.main()
