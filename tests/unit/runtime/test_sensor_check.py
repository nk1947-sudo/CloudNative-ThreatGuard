"""Sensor diagnostic: a gap between posted and exported events is reported, not hidden."""

import json
import unittest

from cloudnative_threatguard.runtime import sensor_check
from cloudnative_threatguard.runtime.sensor_check import EXIT_BLOCKED, EXIT_GAP, EXIT_INCONCLUSIVE, EXIT_OK

POD = "threatguard-target-pod"
HEADER = "ID   NAME   STATE   FILTERID   NAMESPACE   SENSORS   KERNELMEMORY   MODE   NPOST   NENFORCE   NMONITOR"


def table(posted, enforced=0):
    rows = [HEADER]
    rows.append(f"6    tp-006-outbound-network   enabled   6   (global)   generic_kprobe   11.23 MB   monitor_only   {posted}   0   0")
    rows.append(f"7    tp-001-shell-execution   enabled   7   (global)   generic_kprobe   11.23 MB   enforce   {posted}   {enforced}   0")
    return "\n".join(rows)


def exec_line():
    return json.dumps({"time": "2026-10-03T10:00:01Z", "process_exec": {"process": {
        "exec_id": "a", "pid": 1, "binary": "/bin/cat", "pod": {"namespace": "threatguard", "name": POD}}}})


def kprobe_line():
    return json.dumps({"time": "2026-10-03T10:00:02Z", "process_kprobe": {
        "function_name": "sys_connect", "process": {"exec_id": "b", "pid": 2, "binary": "/usr/bin/nc",
                                                     "pod": {"namespace": "threatguard", "name": POD}}}})


class FakeAgent:
    def __init__(self, before, after, stream, agent_ok=True):
        self.tables = [before, after]
        self.stream = stream
        self.agent_ok = agent_ok

    def __call__(self, args):
        if args[0] == "get":
            return (0, "tetragon-abc") if self.agent_ok else (1, "")
        if "tracingpolicy" in args:
            return 0, self.tables.pop(0)
        if args[0] == "logs":
            return 0, self.stream
        return 0, ""


class TestParse(unittest.TestCase):
    def test_policy_counters_are_parsed_from_the_last_columns(self):
        counters = sensor_check.parse_policy_table(table(posted=3, enforced=2))
        self.assertEqual(counters["tp-001-shell-execution"].enforced, 2)
        self.assertEqual(counters["tp-006-outbound-network"].posted, 3)


class TestDiagnose(unittest.TestCase):
    def run_diag(self, before, after, stream, agent_ok=True):
        agent = FakeAgent(before, after, stream, agent_ok)
        return sensor_check.diagnose("threatguard", POD, run=agent, sleep=lambda s: None)

    def test_posted_but_only_exec_exported_is_a_gap(self):
        result, _ = self.run_diag(table(0), table(2, 2), exec_line())
        self.assertEqual(result.verdict, "POSTED_NOT_EXPORTED")
        self.assertEqual(result.enforced_delta, {"tp-001-shell-execution": 2})
        self.assertIn("Linux host", result.explain())

    def test_exported_kprobe_events_are_ok(self):
        result, _ = self.run_diag(table(0), table(2, 2), exec_line() + "\n" + kprobe_line())
        self.assertEqual(result.verdict, "EXPORTED")

    def test_unmoved_counters_are_inconclusive_not_a_gap(self):
        result, _ = self.run_diag(table(5, 5), table(5, 5), exec_line())
        self.assertEqual(result.verdict, "INCONCLUSIVE")

    def test_unreachable_agent_is_blocked(self):
        result, error = self.run_diag(table(0), table(0), "", agent_ok=False)
        self.assertIsNone(result)
        self.assertIn("agent", error)

    def test_main_exit_codes(self):
        self.assertEqual(sensor_check.main([], run=FakeAgent(table(0), table(2, 2), exec_line()), sleep=lambda s: None), EXIT_GAP)
        self.assertEqual(sensor_check.main([], run=FakeAgent(table(0), table(2), kprobe_line()), sleep=lambda s: None), EXIT_OK)
        self.assertEqual(sensor_check.main([], run=FakeAgent(table(1), table(1), ""), sleep=lambda s: None), EXIT_INCONCLUSIVE)
        self.assertEqual(sensor_check.main([], run=FakeAgent("", "", "", agent_ok=False), sleep=lambda s: None), EXIT_BLOCKED)


if __name__ == "__main__":
    unittest.main()
