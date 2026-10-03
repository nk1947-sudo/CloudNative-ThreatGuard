"""Collector behavior: window selection, dedup, redaction and explicit degraded states."""

import json
import unittest
from datetime import datetime, timezone

from cloudnative_threatguard.runtime import collector

POD = {"namespace": "threatguard", "name": "threatguard-target-pod"}


def exec_event(binary, time="2026-10-03T10:00:01.123456789Z", pod=None, args="", exec_id="e1", pid=10):
    return {
        "time": time,
        "node_name": "n",
        "process_exec": {"process": {
            "exec_id": exec_id, "pid": pid, "uid": 10001, "binary": binary, "arguments": args,
            "pod": pod or POD, "cwd": "/", "flags": "x",
        }},
    }


def lines(*events):
    return "\n".join(json.dumps(e) for e in events)


class TestParsing(unittest.TestCase):
    def test_nanosecond_timestamps_are_parsed(self):
        parsed = collector.parse_time("2026-10-03T10:00:01.123456789Z")
        self.assertEqual(parsed, datetime(2026, 10, 3, 10, 0, 1, 123456, tzinfo=timezone.utc))

    def test_invalid_timestamp_is_none(self):
        self.assertIsNone(collector.parse_time("not-a-time"))
        self.assertIsNone(collector.parse_time(""))

    def test_malformed_lines_are_counted_not_hidden(self):
        events, errors = collector.parse_event_lines(["{bad json", json.dumps(exec_event("/usr/bin/id")), ""])
        self.assertEqual(len(events), 1)
        self.assertEqual(errors, 1)


class TestCollection(unittest.TestCase):
    def collect(self, stdout, code=0):
        return collector.collect_live_events(
            "2026-10-03T10:00:00Z", "threatguard", "threatguard-target-pod", runner=lambda a: (code, stdout)
        )

    def test_keeps_only_target_pod_events(self):
        other = {"namespace": "kube-system", "name": "coredns"}
        result = self.collect(lines(exec_event("/usr/bin/id"), exec_event("/usr/bin/id", pod=other, exec_id="e2")))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.dropped_other_pods, 1)
        self.assertEqual(result.status, "ok")

    def test_duplicate_export_records_are_dropped_by_source_identity(self):
        event = exec_event("/usr/bin/id")
        result = self.collect(lines(event, event))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.duplicates_dropped, 1)

    def test_distinct_events_with_different_ids_are_both_kept(self):
        result = self.collect(lines(exec_event("/usr/bin/id", exec_id="a"), exec_event("/usr/bin/id", exec_id="b", pid=11)))
        self.assertEqual(len(result.events), 2)

    def test_command_failure_reports_unavailable_never_empty_success(self):
        result = self.collect("error: no pods", code=1)
        self.assertEqual(result.status, "unavailable")
        self.assertTrue(result.errors)

    def test_malformed_lines_mark_capture_degraded(self):
        result = self.collect("{oops\n" + json.dumps(exec_event("/usr/bin/id")))
        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.parse_errors, 1)

    def test_events_without_pod_metadata_are_not_attributed(self):
        event = exec_event("/usr/bin/id")
        del event["process_exec"]["process"]["pod"]
        result = self.collect(lines(event))
        self.assertEqual(result.events, [])

    def test_secret_arguments_are_redacted_and_extra_fields_dropped(self):
        result = self.collect(lines(exec_event("/usr/bin/curl", args="-H token=abc123 --password=hunter2")))
        process = result.events[0]["process_exec"]["process"]
        self.assertNotIn("abc123", process["arguments"])
        self.assertNotIn("hunter2", process["arguments"])
        self.assertNotIn("cwd", process)

    def test_original_event_time_is_retained(self):
        result = self.collect(lines(exec_event("/usr/bin/id")))
        self.assertEqual(result.events[0]["time"], "2026-10-03T10:00:01.123456789Z")


class TestWindowAndEnforcement(unittest.TestCase):
    def test_window_selects_by_event_time(self):
        early = exec_event("/usr/bin/id", time="2026-10-03T09:59:00Z", exec_id="x")
        inside = exec_event("/usr/bin/id", time="2026-10-03T10:00:30Z", exec_id="y")
        start = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 10, 3, 10, 1, 0, tzinfo=timezone.utc)
        self.assertEqual(collector.events_in_window([early, inside], start, end), [inside])

    def test_enforcement_requires_a_kill_signal(self):
        exit_event = {"time": "t", "process_exit": {"process": {"binary": "/bin/sh", "pod": POD}, "signal": "SIGKILL"}}
        self.assertTrue(collector.enforcement_observed([exit_event]))
        normal_exit = {"time": "t", "process_exit": {"process": {"binary": "/bin/sh", "pod": POD}, "signal": ""}}
        self.assertFalse(collector.enforcement_observed([normal_exit, exec_event("/bin/sh")]))

    def test_kprobe_sigkill_action_counts(self):
        kprobe = {"time": "t", "process_kprobe": {"process": {"pod": POD}, "function_name": "sys_execve",
                                                   "action": "KPROBE_ACTION_SIGKILL"}}
        self.assertTrue(collector.enforcement_observed([kprobe]))


if __name__ == "__main__":
    unittest.main()
