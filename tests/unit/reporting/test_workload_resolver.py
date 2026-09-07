"""
Unit tests for Kubernetes workload-ownership resolution.

Covers: Pod owned by Deployment, StatefulSet, DaemonSet; standalone Pod;
missing owner reference; and ambiguous/unsupported owner metadata.
"""

import unittest

from cloudnative_threatguard.reporting.workload_resolver import resolve_workload_owner


class TestResolveWorkloadOwnerViaNamingPattern(unittest.TestCase):
    """No ownerReferences available -- the common case for this project's
    eBPF-telemetry-derived incidents, which never carry owner metadata."""

    def test_deployment_pod_naming_pattern(self):
        ref = resolve_workload_owner("threatguard", "web-app-7c9d8f6d7b-x2abc")
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "Deployment")
        self.assertEqual(ref.owner_name, "web-app")
        self.assertEqual(ref.inferred_from, "pod_name_pattern")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_statefulset_pod_naming_pattern(self):
        ref = resolve_workload_owner("threatguard", "web-0")
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "StatefulSet")
        self.assertEqual(ref.owner_name, "web")
        self.assertEqual(ref.inferred_from, "pod_name_pattern")
        self.assertEqual(ref.remediation_target, "statefulset/web")

    def test_standalone_pod_no_pattern_match(self):
        ref = resolve_workload_owner("threatguard", "debug-shell")
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertIn("standalone Pod", ref.manual_reason)

    def test_missing_pod_name_and_no_owner_references(self):
        ref = resolve_workload_owner("threatguard", None)
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)


class TestResolveWorkloadOwnerViaOwnerReferences(unittest.TestCase):
    """Authoritative ownerReferences metadata, when available."""

    def test_pod_owned_by_replicaset_resolves_to_deployment(self):
        ref = resolve_workload_owner(
            "threatguard",
            "web-app-7c9d8f6d7b-x2abc",
            owner_references=[{"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"}],
        )
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "Deployment")
        self.assertEqual(ref.owner_name, "web-app")
        self.assertEqual(ref.inferred_from, "owner_references")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_pod_owned_by_statefulset_directly(self):
        ref = resolve_workload_owner(
            "threatguard", "web-0", owner_references=[{"kind": "StatefulSet", "name": "web"}]
        )
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "StatefulSet")
        self.assertEqual(ref.owner_name, "web")
        self.assertEqual(ref.remediation_target, "statefulset/web")

    def test_pod_owned_by_daemonset(self):
        ref = resolve_workload_owner(
            "threatguard",
            "log-collector-abcde",
            owner_references=[{"kind": "DaemonSet", "name": "log-collector"}],
        )
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "DaemonSet")
        self.assertEqual(ref.owner_name, "log-collector")
        self.assertEqual(ref.remediation_target, "daemonset/log-collector")

    def test_pod_owned_by_job_is_not_auto_remediable(self):
        ref = resolve_workload_owner(
            "threatguard", "batch-job-x9z2p", owner_references=[{"kind": "Job", "name": "batch-job"}]
        )
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertIn("run-to-completion", ref.manual_reason)

    def test_replicaset_owner_with_unexpected_name_shape_is_manual(self):
        ref = resolve_workload_owner(
            "threatguard",
            "custom-pod-xyz",
            owner_references=[{"kind": "ReplicaSet", "name": "not-a-normal-replicaset-name"}],
        )
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)

    def test_ambiguous_multiple_owner_references(self):
        ref = resolve_workload_owner(
            "threatguard",
            "weird-pod",
            owner_references=[
                {"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"},
                {"kind": "DaemonSet", "name": "log-collector"},
            ],
        )
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertIn("ambiguous", ref.manual_reason)

    def test_owner_reference_missing_fields(self):
        ref = resolve_workload_owner("threatguard", "some-pod", owner_references=[{"kind": "ReplicaSet"}])
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)

    def test_unrecognized_owner_kind(self):
        ref = resolve_workload_owner(
            "threatguard", "custom-resource-pod", owner_references=[{"kind": "CustomController", "name": "x"}]
        )
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)


if __name__ == "__main__":
    unittest.main()
