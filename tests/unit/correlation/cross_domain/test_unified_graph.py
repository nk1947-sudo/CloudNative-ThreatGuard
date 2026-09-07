"""
Unit tests for UnifiedSecurityGraph.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.graph.unified_graph import (
    UnifiedEdge,
    UnifiedNode,
    UnifiedNodeType,
    UnifiedRelationship,
    UnifiedSecurityGraph,
)


class TestUnifiedSecurityGraph(unittest.TestCase):
    def test_cross_domain_path_traversal(self):
        graph = UnifiedSecurityGraph()

        # Nodes
        user = UnifiedNode(
            id="iam:user:developer",
            label="developer",
            node_type=UnifiedNodeType.IAM_USER,
            source_system="CloudGraphGuard",
        )
        role = UnifiedNode(
            id="iam:role:eks-deployer",
            label="eks-deployer-role",
            node_type=UnifiedNodeType.IAM_ROLE,
            source_system="CloudGraphGuard",
        )
        cluster = UnifiedNode(
            id="k8s:cluster:threatguard",
            label="threatguard-cluster",
            node_type=UnifiedNodeType.EKS_CLUSTER,
            source_system="CloudGraphGuard",
        )
        sa = UnifiedNode(
            id="k8s:sa:threatguard-sa",
            label="threatguard-workload-sa",
            node_type=UnifiedNodeType.K8S_SERVICE_ACCOUNT,
            source_system="CloudNative ThreatGuard",
        )
        pod = UnifiedNode(
            id="k8s:pod:threatguard-target-pod",
            label="threatguard-target-pod",
            node_type=UnifiedNodeType.K8S_POD,
            source_system="CloudNative ThreatGuard",
        )
        secret = UnifiedNode(
            id="k8s:secret:serviceaccount-token",
            label="k8s-serviceaccount-token",
            node_type=UnifiedNodeType.SECRET,
            source_system="CloudNative ThreatGuard",
        )

        for n in [user, role, cluster, sa, pod, secret]:
            graph.add_node(n)

        # Edges with provenance
        graph.add_edge(
            UnifiedEdge(
                source=user.id,
                target=role.id,
                relationship=UnifiedRelationship.ASSUME_ROLE,
                provenance="IAM Trust Policy allows sts:AssumeRole from developer",
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=role.id,
                target=cluster.id,
                relationship=UnifiedRelationship.EKS_ACCESS,
                provenance="EKS Access Entry grants cluster administration",
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=cluster.id,
                target=sa.id,
                relationship=UnifiedRelationship.MAPPED_TO,
                provenance="EKS access mapped to namespace ServiceAccount",
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=sa.id,
                target=pod.id,
                relationship=UnifiedRelationship.RUNS,
                provenance="Deployment spec specifies serviceAccountName",
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=pod.id,
                target=secret.id,
                relationship=UnifiedRelationship.ACCESSED,
                provenance="Tetragon eBPF trace sys_enter_openat /var/run/secrets/.../token",
            )
        )

        # Pathfinding test
        paths = graph.find_attack_paths("iam:user:developer", "k8s:secret:serviceaccount-token")
        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(len(path), 5)
        self.assertEqual(path[0].relationship, UnifiedRelationship.ASSUME_ROLE)
        self.assertEqual(path[1].relationship, UnifiedRelationship.EKS_ACCESS)
        self.assertEqual(path[4].relationship, UnifiedRelationship.ACCESSED)

        # Mermaid output test
        mmd = graph.to_mermaid()
        self.assertIn("flowchart TD", mmd)
        self.assertIn("cggStyle", mmd)
        self.assertIn("tgStyle", mmd)


if __name__ == "__main__":
    unittest.main()
