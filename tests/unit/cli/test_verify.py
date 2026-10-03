"""Verifier states: skips stay visible, missing prerequisites block, local checks never imply live."""

import json
import unittest
from unittest.mock import patch

from cloudnative_threatguard.cli import verify
from cloudnative_threatguard.cli.verify import Status, VerificationResult


def result(status):
    return VerificationResult("x", "c", status)


class TestExitCodes(unittest.TestCase):
    def test_only_passes_exit_zero(self):
        self.assertEqual(verify.exit_code_for([result(Status.PASS), result(Status.PASS)]), 0)

    def test_skips_do_not_fail_but_are_not_passes(self):
        results = [result(Status.PASS), result(Status.SKIP)]
        self.assertEqual(verify.exit_code_for(results), 0)
        self.assertFalse(results[1].passed)

    def test_blocked_exits_two(self):
        self.assertEqual(verify.exit_code_for([result(Status.PASS), result(Status.BLOCKED)]), 2)

    def test_failure_outranks_blocked(self):
        self.assertEqual(verify.exit_code_for([result(Status.BLOCKED), result(Status.FAIL)]), 1)


class TestPrerequisites(unittest.TestCase):
    def test_docker_cli_without_daemon_is_blocked_not_passed(self):
        def run(cmd):
            return 1, "Cannot connect to the Docker daemon"

        with patch.object(verify.shutil, "which", side_effect=lambda n: "/bin/" + n):
            by_name = {r.name: r for r in verify._check_prerequisites(run)}
        self.assertEqual(by_name["Docker Engine"].status, Status.BLOCKED)

    def test_missing_docker_cli_is_blocked(self):
        with patch.object(verify.shutil, "which", return_value=None):
            by_name = {r.name: r for r in verify._check_prerequisites(lambda c: (0, ""))}
        self.assertEqual(by_name["Docker Engine"].status, Status.BLOCKED)
        self.assertEqual(by_name["Kubectl CLI"].status, Status.SKIP)


class TestLiveChecks(unittest.TestCase):
    def test_unreachable_cluster_blocks_instead_of_passing(self):
        results = verify.run_live_checks(run=lambda cmd: (1, "connection refused"))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, Status.BLOCKED)
        self.assertEqual(results[0].scope, "live")

    def healthy_runner(self, overrides=None):
        overrides = overrides or {}

        def run(cmd):
            key = " ".join(cmd)
            for needle, value in overrides.items():
                if needle in key:
                    return value
            if "get nodes" in key:
                return 0, "True "
            if "constrainttemplates -o name" in key:
                return 0, "\n".join(f"ct/{i}" for i in range(8))
            if "tracingpolicy" in key:
                return 0, "\n".join(f"tp/{i}" for i in range(6))
            return 0, "ok"

        return run

    def prometheus(self, health="up"):
        body = json.dumps({"data": {"activeTargets": [{"labels": {"job": "threatguard"}, "health": health}]}})
        return lambda url: (200, body)

    def test_healthy_cluster_passes_every_live_check(self):
        results = verify.run_live_checks(run=self.healthy_runner(), http_get=self.prometheus())
        self.assertTrue(all(r.status is Status.PASS for r in results), [(r.name, r.status) for r in results])
        self.assertTrue(all(r.scope == "live" for r in results))

    def test_service_endpoint_failure_is_reported_per_endpoint(self):
        runner = self.healthy_runner({"proxy/readyz": (1, "503")})
        results = verify.run_live_checks(run=runner, http_get=self.prometheus())
        failed = [r.name for r in results if r.status is Status.FAIL]
        self.assertEqual(failed, ["Deployed service /readyz"])

    def test_prometheus_target_down_fails(self):
        results = verify.run_live_checks(run=self.healthy_runner(), http_get=self.prometheus("down"))
        self.assertEqual(results[-1].status, Status.FAIL)

    def test_prometheus_unreachable_is_blocked(self):
        def refuse(url):
            raise OSError("connection refused")

        results = verify.run_live_checks(run=self.healthy_runner(), http_get=refuse)
        self.assertEqual(results[-1].status, Status.BLOCKED)

    def test_missing_gatekeeper_crds_block(self):
        runner = self.healthy_runner({"get crd": (1, "not found")})
        results = verify.run_live_checks(run=runner, http_get=self.prometheus())
        self.assertIn(Status.BLOCKED, [r.status for r in results])


class TestSampleAppLocal(unittest.TestCase):
    def test_missing_flask_is_a_visible_skip(self):
        with patch.object(verify.importlib.util, "spec_from_file_location", side_effect=ModuleNotFoundError("No module named 'flask'")):
            (res,) = verify._check_sample_app_locally()
        self.assertEqual(res.status, Status.SKIP)
        self.assertIn("flask", res.details)


if __name__ == "__main__":
    unittest.main()
