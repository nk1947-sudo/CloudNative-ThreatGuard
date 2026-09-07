"""
Unit tests for Kubernetes workload-ownership resolution.

Covers: Pod owned by Deployment, StatefulSet, DaemonSet; standalone Pod;
missing owner reference; ambiguous/unsupported owner metadata; and the
optional live Kubernetes API lookup path (mocked -- no real cluster).
"""

import json
import subprocess
import unittest
from unittest.mock import patch

from cloudnative_threatguard.reporting.workload_resolver import (
    KubectlOwnershipClient,
    resolve_workload_owner,
)


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


class _FakeKubernetesClient:
    """
    Test double for KubernetesOwnershipClient. `responses` maps
    (namespace, kind, name) -> a list[dict] (success, possibly empty for "no
    owner") or None (lookup failed/unavailable, regardless of underlying
    cause -- the resolver treats every failure mode identically by design).
    A lookup for a key not in the map raises, so tests fail loudly if they
    exercise a call path they didn't expect (e.g. a live call that should
    have been skipped because explicit ownerReferences already won).
    """

    def __init__(self, responses: dict):
        self._responses = responses
        self.calls: list[tuple[str, str, str]] = []

    def get_owner_references(self, namespace, kind, name):
        self.calls.append((namespace, kind, name))
        key = (namespace, kind, name)
        if key not in self._responses:
            raise AssertionError(f"Unexpected live lookup: {key}")
        return self._responses[key]


class TestResolveWorkloadOwnerViaLiveKubernetesAPI(unittest.TestCase):
    """
    Live lookups are exercised entirely through the injected
    KubernetesOwnershipClient Protocol -- no real cluster involved.
    """

    def test_live_api_resolves_deployment_owned_pod(self):
        client = _FakeKubernetesClient({
            ("threatguard", "Pod", "web-app-custom-1"): [{"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"}],
            ("threatguard", "ReplicaSet", "web-app-7c9d8f6d7b"): [{"kind": "Deployment", "name": "web-app"}],
        })
        ref = resolve_workload_owner("threatguard", "web-app-custom-1", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "Deployment")
        self.assertEqual(ref.owner_name, "web-app")
        self.assertEqual(ref.inferred_from, "live_api")
        self.assertEqual(ref.live_lookup_status, "success")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_live_api_resolves_statefulset_owned_pod(self):
        client = _FakeKubernetesClient({
            ("threatguard", "Pod", "cache-custom-1"): [{"kind": "StatefulSet", "name": "cache"}],
        })
        ref = resolve_workload_owner("threatguard", "cache-custom-1", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "StatefulSet")
        self.assertEqual(ref.owner_name, "cache")
        self.assertEqual(ref.inferred_from, "live_api")
        self.assertEqual(ref.remediation_target, "statefulset/cache")

    def test_live_api_resolves_daemonset_owned_pod(self):
        client = _FakeKubernetesClient({
            ("threatguard", "Pod", "log-collector-custom-1"): [{"kind": "DaemonSet", "name": "log-collector"}],
        })
        ref = resolve_workload_owner("threatguard", "log-collector-custom-1", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "DaemonSet")
        self.assertEqual(ref.owner_name, "log-collector")
        self.assertEqual(ref.inferred_from, "live_api")
        self.assertEqual(ref.remediation_target, "daemonset/log-collector")

    def test_live_api_job_owned_pod_requires_manual_remediation(self):
        client = _FakeKubernetesClient({
            ("threatguard", "Pod", "batch-custom-1"): [{"kind": "Job", "name": "batch-job"}],
        })
        ref = resolve_workload_owner("threatguard", "batch-custom-1", kubernetes_client=client)
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertIn("run-to-completion", ref.manual_reason)
        self.assertEqual(ref.live_lookup_status, "success")

    def test_live_api_cronjob_owned_pod_requires_manual_remediation(self):
        client = _FakeKubernetesClient({
            ("threatguard", "Pod", "scheduled-custom-1"): [{"kind": "CronJob", "name": "nightly-job"}],
        })
        ref = resolve_workload_owner("threatguard", "scheduled-custom-1", kubernetes_client=client)
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertIn("run-to-completion", ref.manual_reason)

    def test_live_api_confirms_standalone_pod_with_no_owner(self):
        """
        The live API returning an empty ownerReferences list is authoritative
        ground truth -- unlike the naming-pattern path, this must NOT be
        second-guessed by trying to match the pod name against a controller
        naming shape.
        """
        client = _FakeKubernetesClient({("threatguard", "Pod", "debug-shell"): []})
        ref = resolve_workload_owner("threatguard", "debug-shell", kubernetes_client=client)
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertEqual(ref.inferred_from, "live_api")
        self.assertEqual(ref.live_lookup_status, "success")
        self.assertIn("no owner", ref.manual_reason.lower())

    def test_live_api_unavailable_falls_back_to_naming_pattern(self):
        client = _FakeKubernetesClient({("threatguard", "Pod", "web-app-7c9d8f6d7b-x2abc"): None})
        ref = resolve_workload_owner("threatguard", "web-app-7c9d8f6d7b-x2abc", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "Deployment")
        self.assertEqual(ref.owner_name, "web-app")
        self.assertEqual(ref.inferred_from, "pod_name_pattern")
        self.assertEqual(ref.live_lookup_status, "failed")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_live_api_permission_denied_falls_back_to_naming_pattern(self):
        """RBAC denial is reported the same way as any other lookup failure
        (as `None`) -- the resolver must still fall back safely, never crash
        or treat a permission error as 'no owner'."""
        client = _FakeKubernetesClient({("threatguard", "Pod", "web-app-7c9d8f6d7b-x2abc"): None})
        ref = resolve_workload_owner("threatguard", "web-app-7c9d8f6d7b-x2abc", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.live_lookup_status, "failed")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_live_api_resource_not_found_falls_back_to_naming_pattern(self):
        client = _FakeKubernetesClient({("threatguard", "Pod", "web-0"): None})
        ref = resolve_workload_owner("threatguard", "web-0", kubernetes_client=client)
        self.assertFalse(ref.requires_manual_remediation)
        self.assertEqual(ref.owner_kind, "StatefulSet")
        self.assertEqual(ref.live_lookup_status, "failed")
        self.assertEqual(ref.remediation_target, "statefulset/web")

    def test_live_api_timeout_falls_back_to_naming_pattern(self):
        client = _FakeKubernetesClient({("threatguard", "Pod", "web-app-7c9d8f6d7b-x2abc"): None})
        ref = resolve_workload_owner("threatguard", "web-app-7c9d8f6d7b-x2abc", kubernetes_client=client)
        self.assertEqual(ref.live_lookup_status, "failed")
        self.assertEqual(ref.remediation_target, "deployment/web-app")

    def test_final_manual_remediation_when_live_lookup_and_naming_pattern_both_fail(self):
        client = _FakeKubernetesClient({("threatguard", "Pod", "debug-shell"): None})
        ref = resolve_workload_owner("threatguard", "debug-shell", kubernetes_client=client)
        self.assertTrue(ref.requires_manual_remediation)
        self.assertIsNone(ref.remediation_target)
        self.assertEqual(ref.live_lookup_status, "failed")

    def test_explicit_owner_references_take_priority_and_skip_live_lookup(self):
        """
        Priority 1 (explicit ownerReferences) must win outright over priority
        2 (live API) for the Pod's immediate owner -- the client must not
        even be called for it. (The ReplicaSet -> Deployment hop is a
        separate concern, covered below.)
        """
        client = _FakeKubernetesClient({})
        ref = resolve_workload_owner(
            "threatguard", "cache-2", owner_references=[{"kind": "StatefulSet", "name": "cache"}],
            kubernetes_client=client,
        )
        self.assertEqual(ref.inferred_from, "owner_references")
        self.assertIsNone(ref.live_lookup_status)
        self.assertEqual(client.calls, [])

    def test_explicit_pod_owner_reference_still_uses_live_lookup_for_replicaset_hop(self):
        """
        Even when the Pod's immediate owner came from explicit event data
        (a ReplicaSet), resolving the owning Deployment authoritatively still
        uses a live lookup of the ReplicaSet's own ownerReferences when a
        client is available, instead of string-parsing the ReplicaSet name.
        """
        client = _FakeKubernetesClient({
            ("threatguard", "ReplicaSet", "web-app-7c9d8f6d7b"): [{"kind": "Deployment", "name": "web-app"}],
        })
        ref = resolve_workload_owner(
            "threatguard", "web-app-xyz",
            owner_references=[{"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"}],
            kubernetes_client=client,
        )
        self.assertEqual(ref.owner_kind, "Deployment")
        self.assertEqual(ref.owner_name, "web-app")
        # The Deployment hop was resolved live, so the result as a whole is
        # tagged live_api even though the Pod -> ReplicaSet step came from
        # explicit data.
        self.assertEqual(ref.inferred_from, "live_api")
        self.assertEqual(client.calls, [("threatguard", "ReplicaSet", "web-app-7c9d8f6d7b")])


class TestKubectlOwnershipClient(unittest.TestCase):
    """
    Unit tests for the concrete kubectl-subprocess-backed implementation,
    with `subprocess.run` mocked -- no real cluster or kubectl binary
    required. Every failure mode must resolve to `None`, never raise.
    """

    def test_successful_lookup_parses_owner_references_from_kubectl_json(self):
        pod_json = json.dumps({
            "metadata": {"ownerReferences": [{"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"}]}
        })
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = pod_json
            client = KubectlOwnershipClient()
            result = client.get_owner_references("threatguard", "Pod", "web-app-7c9d8f6d7b-x2abc")
        self.assertEqual(result, [{"kind": "ReplicaSet", "name": "web-app-7c9d8f6d7b"}])
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["kubectl", "get", "pod", "web-app-7c9d8f6d7b-x2abc", "-n", "threatguard", "-o", "json"])

    def test_successful_lookup_with_no_owner_references_returns_empty_list(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps({"metadata": {}})
            client = KubectlOwnershipClient()
            result = client.get_owner_references("threatguard", "Pod", "debug-shell")
        self.assertEqual(result, [])

    def test_resource_not_found_returns_none(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = 'Error from server (NotFound): pods "ghost-pod" not found'
            client = KubectlOwnershipClient()
            self.assertIsNone(client.get_owner_references("threatguard", "Pod", "ghost-pod"))

    def test_permission_denied_returns_none(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = 'Error from server (Forbidden): pods "web-app" is forbidden'
            client = KubectlOwnershipClient()
            self.assertIsNone(client.get_owner_references("threatguard", "Pod", "web-app"))

    def test_timeout_returns_none(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="kubectl", timeout=5)):
            client = KubectlOwnershipClient()
            self.assertIsNone(client.get_owner_references("threatguard", "Pod", "web-app"))

    def test_kubectl_not_installed_returns_none(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("kubectl not found")):
            client = KubectlOwnershipClient()
            self.assertIsNone(client.get_owner_references("threatguard", "Pod", "web-app"))

    def test_malformed_json_output_returns_none(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "not valid json{{"
            client = KubectlOwnershipClient()
            self.assertIsNone(client.get_owner_references("threatguard", "Pod", "web-app"))


if __name__ == "__main__":
    unittest.main()
