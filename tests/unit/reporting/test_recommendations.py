"""
Unit tests for ThreatGuard Response Recommendation Engine.
Validates generation of safe, high-confidence playbooks and dry-run commands.
"""

import unittest
from cloudnative_threatguard.reporting.recommendations import ResponseRecommendationEngine, ActionCategory, RecommendationPriority


class TestResponseRecommendations(unittest.TestCase):
    def setUp(self):
        self.engine = ResponseRecommendationEngine()

    def test_credential_theft_recommendations(self):
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="payment-service-pod",
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

    def test_container_escape_node_cordon(self):
        recs = self.engine.generate_recommendations(
            namespace="threatguard",
            pod_name="privileged-pod",
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
            pod_name="test-pod",
            techniques=["T1059.004", "T1071", "T1496", "T1552.007", "T1611"]
        )

        for r in recs:
            self.assertTrue(r.recommendation_id.startswith("REC-"))
            self.assertTrue(len(r.dry_run_command) > 0)
            self.assertTrue(len(r.execution_command) > 0)
            self.assertTrue(len(r.blast_radius) > 0)


if __name__ == "__main__":
    unittest.main()
