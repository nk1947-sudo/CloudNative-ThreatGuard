"""Failure-injection tests: no error path may be reported as successful enforcement."""

import json
import tempfile
import unittest
from pathlib import Path

from cloudnative_threatguard.admission import live_check
from cloudnative_threatguard.admission.live_check import (
    EXIT_BLOCKED,
    EXIT_FAILED,
    EXIT_OK,
    Outcome,
    classify_negative,
    classify_positive,
    run_live,
)

DENIAL = (
    'Error from server (Forbidden): error when creating "x.yaml": admission webhook '
    '"validation.gatekeeper.sh" denied the request: [k8sprivilegedcontainer] privileged mode must be false'
)


class TestClassification(unittest.TestCase):
    def test_webhook_denial_counts_as_policy_denied(self):
        self.assertEqual(classify_negative(1, DENIAL), Outcome.POLICY_DENIED)

    def test_missing_file_is_execution_error(self):
        out = "error: the path \"x.yaml\" does not exist"
        self.assertEqual(classify_negative(1, out), Outcome.EXECUTION_ERROR)

    def test_rbac_denial_is_execution_error(self):
        out = 'Error from server (Forbidden): pods is forbidden: User "x" cannot create resource "pods"'
        self.assertEqual(classify_negative(1, out), Outcome.EXECUTION_ERROR)

    def test_unreachable_api_is_execution_error(self):
        out = "The connection to the server localhost:8080 was refused"
        self.assertEqual(classify_negative(1, out), Outcome.EXECUTION_ERROR)

    def test_allowed_negative_is_unexpected(self):
        self.assertEqual(classify_negative(0, "pod/x created (server dry run)"), Outcome.UNEXPECTEDLY_ALLOWED)

    def test_positive_allowed_and_rejected(self):
        self.assertEqual(classify_positive(0, ""), Outcome.ALLOWED)
        self.assertEqual(classify_positive(1, DENIAL), Outcome.POSITIVE_REJECTED)
        self.assertEqual(classify_positive(1, "connection refused"), Outcome.EXECUTION_ERROR)


class TestRunLive(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.neg = root / "negative"
        self.pos = root / "positive"
        self.neg.mkdir()
        self.pos.mkdir()
        for name in ("a.yaml", "b.yaml", "c.yaml"):
            (self.neg / name).write_text("kind: Pod\n")
        (self.pos / "ok.yaml").write_text("kind: Pod\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _runner(self, negative_result, positive_result):
        def run(args):
            return positive_result if "positive" in args[-1] else negative_result
        return run

    def test_real_denials_pass_and_totals_come_from_inventory(self):
        results = run_live(self.neg, self.pos, self._runner((1, DENIAL), (0, "")))
        self.assertEqual(results["status"], "PASS")
        self.assertEqual((results["total"], results["blocked"]), (3, 3))
        self.assertEqual(live_check.exit_code_for(results), EXIT_OK)

    def test_errors_never_count_as_blocked(self):
        results = run_live(self.neg, self.pos, self._runner((1, "connection refused"), (0, "")))
        self.assertEqual(results["blocked"], 0)
        self.assertEqual(results["errors"], 3)
        self.assertEqual(live_check.exit_code_for(results), EXIT_FAILED)

    def test_allowed_negative_fails(self):
        results = run_live(self.neg, self.pos, self._runner((0, "created"), (0, "")))
        self.assertEqual(results["allowed"], 3)
        self.assertEqual(results["status"], "FAIL")

    def test_rejected_positive_fails_even_if_all_negatives_denied(self):
        results = run_live(self.neg, self.pos, self._runner((1, DENIAL), (1, DENIAL)))
        self.assertEqual(results["blocked"], 3)
        self.assertEqual(results["positive_rejected"], 1)
        self.assertEqual(results["status"], "FAIL")

    def test_empty_inventory_cannot_pass(self):
        empty = Path(self._tmp.name) / "empty"
        empty.mkdir()
        results = run_live(empty, self.pos, self._runner((1, DENIAL), (0, "")))
        self.assertEqual(results["status"], "FAIL")


class TestMainBlocked(unittest.TestCase):
    def test_missing_kubectl_is_blocked_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            code = live_check.main(["--mode", "live", "--output", str(out)], runner=lambda a: (127, "kubectl not found"))
            self.assertEqual(code, EXIT_BLOCKED)
            self.assertFalse(out.exists())

    def test_live_run_writes_result_file(self):
        def runner(args):
            if args[0] == "get":
                return 0, ""
            return (0, "") if "positive" in args[-1] else (1, DENIAL)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            code = live_check.main(["--mode", "live", "--output", str(out)], runner=runner)
            data = json.loads(out.read_text())
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(data["evidence_mode"], "live")
            self.assertEqual(data["total"], 8)


if __name__ == "__main__":
    unittest.main()
