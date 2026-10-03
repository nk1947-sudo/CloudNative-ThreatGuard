"""NetworkPolicy verification: an unenforced CNI blocks the run; denials are observed, not assumed."""

import json
import unittest

from cloudnative_threatguard.runtime import network_check
from cloudnative_threatguard.runtime.network_check import EXIT_BLOCKED, EXIT_FAILED, EXIT_OK


class FakeCluster:
    """Scripted kubectl. `connect_results` maps a destination fragment to whether it connects."""

    def __init__(self, enforces=True, baseline_ok=True, connect_results=None, dns_ok=True, ready=True):
        self.enforces = enforces
        self.baseline_ok = baseline_ok
        self.connect_results = connect_results or {}
        self.dns_ok = dns_ok
        self.ready = ready
        self.canary_policy_applied = False
        self.calls = []

    def __call__(self, args, stdin=None):
        self.calls.append(args)
        if args[0] == "cluster-info":
            return 0, "ok"
        if args[0] == "apply":
            manifest = json.loads(stdin)
            if manifest["kind"] == "NetworkPolicy":
                self.canary_policy_applied = True
            return 0, "applied"
        if args[0] == "wait":
            return (0, "") if self.ready else (1, "timed out")
        if args[0] == "delete":
            return 0, ""
        if args[0] == "get":
            if "svc" in args:
                return 0, "10.96.0.1"
            if "-l" in args:
                return 0, "10.244.0.5 10.244.0.6"
            return 0, "10.244.0.9"
        if args[0] == "exec":
            if "/usr/bin/nslookup" in args:
                return (0, "") if self.dns_ok else (1, "timeout")
            host = args[args.index("/usr/bin/nc") + 4]
            if "canary" in " ".join(args):
                if self.canary_policy_applied:
                    return (1, "") if self.enforces else (0, "")
                return (0, "") if self.baseline_ok else (1, "")
            return (0, "") if self.connect_results.get(host, False) else (1, "")
        return 0, ""


def matrix_results(**overrides):
    base = {"10.244.0.5": False, "1.1.1.1": False, "10.96.0.1": False}
    base.update(overrides)
    return base


class TestCanary(unittest.TestCase):
    def check(self, cluster):
        return network_check.run_check(run=cluster, sleep=lambda s: None)

    def test_unenforced_cni_is_blocked_and_the_matrix_never_runs(self):
        cluster = FakeCluster(enforces=False)
        report, code = self.check(cluster)
        self.assertEqual(code, EXIT_BLOCKED)
        self.assertEqual(report["status"], "BLOCKED")
        self.assertFalse(report["cni_enforcement"]["enforced"])
        self.assertEqual(report["cases"], [])

    def test_failed_baseline_blocks(self):
        report, code = self.check(FakeCluster(baseline_ok=False))
        self.assertEqual(code, EXIT_BLOCKED)
        self.assertIn("baseline", report["cni_enforcement"]["detail"])

    def test_unreachable_cluster_blocks(self):
        report, code = network_check.run_check(run=lambda a, s=None: (1, "refused"), sleep=lambda s: None)
        self.assertEqual(code, EXIT_BLOCKED)

    def test_resources_are_cleaned_up_even_when_blocked(self):
        cluster = FakeCluster(enforces=False)
        self.check(cluster)
        self.assertTrue(any(c[0] == "delete" for c in cluster.calls))


class TestMatrix(unittest.TestCase):
    def test_expected_behaviour_passes_with_every_case_recorded(self):
        cluster = FakeCluster(connect_results=matrix_results(**{"10.244.0.5": True}))
        # same-namespace ingress is allowed; the egress probe reaching the same IP must be denied,
        # so make the ingress client connect while the egress probe does not.
        calls = {}

        def run(args, stdin=None):
            if args[0] == "exec" and "/usr/bin/nc" in args and "canary" not in " ".join(args):
                source = args[args.index("-n") + 2]
                host = args[args.index("/usr/bin/nc") + 4]
                allowed = source == "netpol-client" and host == "10.244.0.5"
                calls[(source, host)] = allowed
                return (0, "") if allowed else (1, "")
            return cluster(args, stdin)

        report, code = network_check.run_check(run=run, sleep=lambda s: None)
        self.assertEqual(code, EXIT_OK, report)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["cases"]), 6)
        self.assertTrue(all(c["matched"] for c in report["cases"]))
        self.assertTrue(all(c["timeout_seconds"] == 3 for c in report["cases"]))

    def test_a_denial_that_actually_connects_fails(self):
        cluster = FakeCluster(connect_results=matrix_results(**{"1.1.1.1": True}))
        report, code = network_check.run_check(run=cluster, sleep=lambda s: None)
        self.assertEqual(code, EXIT_FAILED)
        failing = [c for c in report["cases"] if not c["matched"]]
        self.assertTrue(any(c["case"] == "egress to the internet" for c in failing))

    def test_blocked_dns_fails_the_allow_case(self):
        report, code = network_check.run_check(run=FakeCluster(dns_ok=False), sleep=lambda s: None)
        self.assertEqual(code, EXIT_FAILED)
        dns = next(c for c in report["cases"] if c["case"] == "egress DNS to CoreDNS")
        self.assertFalse(dns["matched"])

    def test_probe_pods_that_never_become_ready_do_not_pass(self):
        class NotReady(FakeCluster):
            def __call__(self, args, stdin=None):
                if args[0] == "wait" and "canary" not in " ".join(args):
                    return 1, "timed out"
                return super().__call__(args, stdin)

        report, code = network_check.run_check(run=NotReady(), sleep=lambda s: None)
        self.assertEqual(code, EXIT_FAILED)
        self.assertEqual(report["cases"][0]["case"], "setup")


class TestManifests(unittest.TestCase):
    def test_probe_pods_satisfy_the_admission_policies(self):
        pod = network_check.hardened_pod("p", "ns", {"app": "x"}, ["/bin/sleep", "1"])
        ctr = pod["spec"]["containers"][0]["securityContext"]
        self.assertTrue(ctr["readOnlyRootFilesystem"])
        self.assertFalse(ctr["allowPrivilegeEscalation"])
        self.assertFalse(ctr["privileged"])
        self.assertEqual(ctr["capabilities"]["drop"], ["ALL"])
        self.assertEqual(ctr["seccompProfile"]["type"], "RuntimeDefault")
        self.assertEqual(ctr["runAsUser"], 10001)

    def test_probe_commands_do_not_use_a_shell(self):
        self.assertNotIn("/bin/sh", network_check.listener_command() + network_check.sleeper_command())


if __name__ == "__main__":
    unittest.main()
