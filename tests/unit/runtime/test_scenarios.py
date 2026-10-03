"""Scenario outcomes are decided per scenario from that scenario's own evidence."""

import unittest

from cloudnative_threatguard.runtime.scenarios import (
    Scenario,
    ScenarioRun,
    evaluate_scenario,
    load_catalog,
)


def scenario(sid="SCEN-X", rules=("RUNTIME-003",), enforcement="detect"):
    return Scenario(sid, "test", "x.sh", True, tuple(rules), enforcement)


def ran(code=0, sid="SCEN-X"):
    return ScenarioRun(sid, "executed", code, "s", "e")


class TestEvaluate(unittest.TestCase):
    def test_detection_passes(self):
        out = evaluate_scenario(scenario(), ran(0), {"RUNTIME-003"}, False)
        self.assertEqual(out.status, "passed")

    def test_missing_detection_fails(self):
        out = evaluate_scenario(scenario(), ran(0), set(), False)
        self.assertEqual(out.status, "failed")
        self.assertIn("RUNTIME-003", out.reasons[0])

    def test_never_executed_is_not_run(self):
        self.assertEqual(evaluate_scenario(scenario(), None, set(), False).status, "not_run")

    def test_blocked_and_skipped_are_preserved(self):
        blocked = ScenarioRun("SCEN-X", "blocked", None, "", "")
        self.assertEqual(evaluate_scenario(scenario(), blocked, set(), False).status, "blocked")

    def test_expected_block_needs_exit_137_and_kill_evidence(self):
        s = scenario("SCEN-001", ("RUNTIME-001",), "block")
        self.assertEqual(evaluate_scenario(s, ran(137), {"RUNTIME-001"}, True).status, "passed")

    def test_exit_137_without_kill_evidence_is_not_a_successful_block(self):
        s = scenario("SCEN-001", ("RUNTIME-001",), "block")
        out = evaluate_scenario(s, ran(137), {"RUNTIME-001"}, False)
        self.assertEqual(out.status, "failed")
        self.assertTrue(any("kill evidence" in r for r in out.reasons))

    def test_block_expected_but_process_survived_fails(self):
        s = scenario("SCEN-001", ("RUNTIME-001",), "block")
        self.assertEqual(evaluate_scenario(s, ran(0), {"RUNTIME-001"}, False).status, "failed")

    def test_unrelated_exit_137_does_not_pass_a_detect_scenario(self):
        out = evaluate_scenario(scenario(), ran(137), {"RUNTIME-003"}, False)
        self.assertEqual(out.status, "failed")

    def test_benign_control_fails_on_any_detection(self):
        out = evaluate_scenario(scenario("SCEN-B01", (), "none"), ran(0), {"RUNTIME-003"}, False)
        self.assertEqual(out.status, "failed")
        self.assertIn("false alert", out.reasons[0])

    def test_benign_control_passes_when_silent(self):
        self.assertEqual(evaluate_scenario(scenario("SCEN-B01", (), "none"), ran(0), set(), False).status, "passed")

    def test_benign_silence_without_any_sensor_events_is_not_confirmed(self):
        out = evaluate_scenario(scenario("SCEN-B01", (), "none"), ran(0), set(), False, events_seen=0)
        self.assertEqual(out.status, "failed")

    def test_demo_traces_skip_exit_code_checks(self):
        s = scenario("SCEN-001", ("RUNTIME-001",), "block")
        run = ScenarioRun("SCEN-001", "executed", None, "", "")
        self.assertEqual(evaluate_scenario(s, run, {"RUNTIME-001"}, True, check_exit_code=False).status, "passed")


class TestCatalog(unittest.TestCase):
    def test_two_scenarios_can_share_one_rule_and_stay_separate_checks(self):
        catalog = load_catalog()
        by_rule = {}
        for item in catalog:
            for rule in item.expected_rules:
                by_rule.setdefault(rule, []).append(item.id)
        self.assertEqual(by_rule["RUNTIME-006"], ["SCEN-006", "SCEN-008"])
        self.assertGreater(len(catalog), len(by_rule))

    def test_catalog_has_a_benign_control(self):
        self.assertTrue(any(not item.expected_rules for item in load_catalog()))


if __name__ == "__main__":
    unittest.main()
