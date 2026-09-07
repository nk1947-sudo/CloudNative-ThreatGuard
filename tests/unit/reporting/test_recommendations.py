"""
Unit tests for ThreatGuard Response Recommendation Engine.
Validates generation of safe, high-confidence playbooks and dry-run commands.
"""

import unittest

from cloudnative_threatguard.reporting.recommendations import (
    ActionCategory,
    RecommendationPriority,
    ResponseRecommendationEngine,
)


class TestResponseRecommendations(unittest.TestCase):
    def setUp(self):
        self.engine = ResponseRecommendationEngine()

    def test_credential_theft_recommendations(self):
        # "payment-service-7c9d8f6d7b-x2abc" matches the standard Deployment
        # Pod naming shape (<deployment>-<hash>-<suffix>), so the engine can
        # confidently resolve the owning Deployment as "payment-service".
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="payment-service-7c9d8f6d7b-x2abc",
            techniques=["T1552.007", "T1059.004"],
            severity="CRITICAL"
        )

        categories = [r.category for r in recs]
        self.assertIn(ActionCategory.FORENSICS.value, categories)
        self.assertIn(ActionCategory.QUARANTINE.value, categories)
        self.assertIn(ActionCategory.CREDENTIALS.value, categories)

        # Check token revoke recommendation
        token_rec = next(r for r in recs if r.category == ActionCategory.CREDENTIALS.value)
        self.assertEqual(token_rec.priority, RecommendationPriority.CRITICAL.value)
        self.assertIn("--dry-run=client", token_rec.dry_run_command)
        self.assertIn("automountServiceAccountToken", token_rec.execution_command)
        self.assertTrue(len(token_rec.blast_radius) > 0)
        self.assertTrue(len(token_rec.reversibility) > 0)
        self.assertFalse(token_rec.requires_manual_review)

        # Regression guard: the command must target the Deployment
        # ("payment-service"), never the raw Pod name.
        self.assertIn("deployment/payment-service", token_rec.dry_run_command)
        self.assertIn("deployment/payment-service ", token_rec.execution_command)
        self.assertNotIn("payment-service-7c9d8f6d7b-x2abc", token_rec.execution_command)

    def test_credential_theft_with_unresolvable_pod_name_requires_manual_review(self):
        """
        Regression guard for the pod-name-vs-deployment-name bug: when the pod
        name doesn't match any recognized controller naming pattern and no
        ownerReferences were supplied, the engine must not guess -- it must
        flag the credential-rotation and drain recommendations as requiring
        manual review instead of fabricating a 'kubectl patch deployment
        <pod-name>' command against a resource that doesn't exist.
        """
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="payment-service-pod",  # does not match any owner naming pattern
            techniques=["T1552.007"],
            severity="CRITICAL",
        )

        token_rec = next(r for r in recs if "REVOKE-TOKEN" in r.recommendation_id)
        self.assertTrue(token_rec.requires_manual_review)
        self.assertEqual(token_rec.category, ActionCategory.MANUAL_REVIEW.value)
        self.assertNotIn("kubectl patch deployment payment-service-pod", token_rec.execution_command)

        drain_rec = next(r for r in recs if "CONTROLLED-DRAIN" in r.recommendation_id)
        self.assertTrue(drain_rec.requires_manual_review)
        self.assertNotIn("kubectl scale deployment payment-service-pod", drain_rec.execution_command)

    def test_credential_theft_with_explicit_owner_references(self):
        """A Pod whose real ownerReferences are supplied should resolve via
        that authoritative data, independent of its name's shape."""
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="checkout-abcde",
            techniques=["T1552.007"],
            severity="CRITICAL",
            owner_references=[{"kind": "ReplicaSet", "name": "checkout-7c9d8f6d7b"}],
        )
        token_rec = next(r for r in recs if "REVOKE-TOKEN" in r.recommendation_id)
        self.assertFalse(token_rec.requires_manual_review)
        self.assertIn("deployment/checkout ", token_rec.execution_command)

    def test_statefulset_pod_drain_targets_statefulset_not_pod(self):
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="cache-2",
            techniques=["T1059.004"],
        )
        drain_rec = next(r for r in recs if "CONTROLLED-DRAIN" in r.recommendation_id)
        self.assertFalse(drain_rec.requires_manual_review)
        self.assertIn("statefulset/cache", drain_rec.execution_command)
        self.assertNotIn("cache-2", drain_rec.execution_command)

    def test_container_escape_node_cordon(self):
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="privileged-pod-7c9d8f6d7b-abcde",
            techniques=["T1611"],
            node_name="worker-node-01"
        )

        node_rec = next((r for r in recs if r.category == ActionCategory.NODE_SECURITY.value), None)
        self.assertIsNotNone(node_rec)
        self.assertIn("worker-node-01", node_rec.execution_command)
        self.assertIn("uncordon", node_rec.reversibility)

    def test_all_recommendations_have_dry_runs(self):
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="test-app-7c9d8f6d7b-x2abc",
            techniques=["T1059.004", "T1071", "T1496", "T1552.007", "T1611"]
        )

        for r in recs:
            self.assertTrue(r.recommendation_id.startswith("REC-"))
            self.assertTrue(len(r.dry_run_command) > 0)
            self.assertTrue(len(r.execution_command) > 0)
            self.assertTrue(len(r.blast_radius) > 0)


if __name__ == "__main__":
    unittest.main()
