"""Policies that hook the execve syscall report the target binary as an argument."""

import unittest

from cloudnative_threatguard.detection.engine import DetectionEngine

POD = {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "c"}}


def execve_kprobe(arg):
    return {
        "time": "2026-10-03T10:00:01Z",
        "process_kprobe": {
            "function_name": "__x64_sys_execve",
            "process": {"binary": "/usr/bin/runc", "pod": POD},
            "args": [arg],
            "action": "KPROBE_ACTION_SIGKILL",
        },
    }


class TestExecveKprobe(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(protected_namespace="threatguard")

    def test_shell_in_file_arg_is_runtime_001(self):
        det = self.engine.process_event(execve_kprobe({"file_arg": {"path": "/bin/sh"}}))
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-001")

    def test_shell_in_string_arg_is_runtime_001(self):
        det = self.engine.process_event(execve_kprobe({"string_arg": "/bin/bash"}))
        self.assertEqual(det.rule_id, "RUNTIME-001")

    def test_benign_binary_is_not_detected(self):
        self.assertIsNone(self.engine.process_event(execve_kprobe({"file_arg": {"path": "/bin/echo"}})))

    def test_missing_path_argument_is_ignored(self):
        self.assertIsNone(self.engine.process_event(execve_kprobe({"int_arg": 3})))

    def test_other_namespaces_are_ignored(self):
        event = execve_kprobe({"file_arg": {"path": "/bin/sh"}})
        event["process_kprobe"]["process"]["pod"] = {"namespace": "kube-system", "name": "x"}
        self.assertIsNone(self.engine.process_event(event))


if __name__ == "__main__":
    unittest.main()
