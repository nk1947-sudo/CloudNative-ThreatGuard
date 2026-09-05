"""
Comprehensive Failure Mode and Resilience Test Suite for CloudNative ThreatGuard.
Tests system robustness against:
- Malformed / corrupted JSON payloads
- Missing critical Tetragon fields
- Out-of-order event streams
- Duplicate event deduplication / handling
- Missing or malformed namespace values
- Edge cases in process and network structures
"""

import unittest
from cloudnative_threatguard.detection.engine import DetectionEngine
from cloudnative_threatguard.correlation.kubernetes import correlate_incidents
from cloudnative_threatguard.reporting.incidents import IncidentManager
from cloudnative_threatguard.runtime.events import SecurityEvent, SecurityEventType, Severity
from cloudnative_threatguard.reporting.risk import RiskScoringEngine


class TestResilienceAndFailureModes(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(protected_namespace="threatguard")
        self.incident_manager = IncidentManager()
        self.risk_engine = RiskScoringEngine()

    def test_malformed_empty_and_corrupt_events(self):
        """Engine should gracefully ignore or reject empty/corrupted dicts without unhandled exceptions."""
        malformed_inputs = [
            {},
            {"time": "invalid-timestamp"},
            {"process_exec": None},
            {"process_exec": {}},
            {"process_exec": {"process": None}},
            {"process_exec": {"process": {"binary": None}}},
            {"process_kprobe": None},
            {"process_kprobe": {"args": None}},
            {"process_kprobe": {"function_name": None}},
            {"unknown_wrapper": {"some": "data"}}
        ]
        for item in malformed_inputs:
            det = self.engine.process_event(item)
            self.assertIsNone(det, f"Expected None for input: {item}")

    def test_missing_namespace_and_wrong_namespace(self):
        """Events missing pod.namespace or matching an unprotected namespace must be safely ignored."""
        no_ns_event = {
            "time": "2026-09-05T18:00:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/sh",
                    "arguments": "-c whoami",
                    "pod": {
                        "name": "orphan-pod"
                        # namespace omitted intentionally
                    }
                }
            }
        }
        self.assertIsNone(self.engine.process_event(no_ns_event))

        wrong_ns_event = {
            "time": "2026-09-05T18:00:00Z",
            "process_exec": {
                "process": {
                    "binary": "/bin/sh",
                    "pod": {
                        "name": "kube-pod",
                        "namespace": "kube-system"
                    }
                }
            }
        }
        self.assertIsNone(self.engine.process_event(wrong_ns_event))

    def test_out_of_order_events_chronological_sorting(self):
        """Engine and IncidentManager must correctly assemble attack chain in chronological order regardless of arrival order."""
        t1 = "2026-09-05T18:00:01Z"
        t2 = "2026-09-05T18:00:05Z"
        t3 = "2026-09-05T18:00:10Z"

        # Arriving in reverse order: t3, then t1, then t2
        ev3 = SecurityEvent(
            event_id="EV-003",
            timestamp=t3,
            event_type=SecurityEventType.NETWORK_ANOMALY.value,
            source="tetragon",
            namespace="threatguard",
            pod="test-pod",
            process="/usr/bin/nc",
            action="c2_beacon",
            severity="HIGH",
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control",
            description="Step 3: C2 egress"
        )
        ev1 = SecurityEvent(
            event_id="EV-001",
            timestamp=t1,
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            source="tetragon",
            namespace="threatguard",
            pod="test-pod",
            process="/bin/sh",
            action="shell_spawn",
            severity="HIGH",
            mitre_technique="T1059.004",
            mitre_tactic="Execution",
            description="Step 1: Shell spawned"
        )
        ev2 = SecurityEvent(
            event_id="EV-002",
            timestamp=t2,
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            source="tetragon",
            namespace="threatguard",
            pod="test-pod",
            process="/bin/cat",
            action="token_theft",
            severity="CRITICAL",
            mitre_technique="T1552.007",
            mitre_tactic="Credential Access",
            description="Step 2: Token theft"
        )

        out_of_order = [ev3, ev1, ev2]
        incidents = correlate_incidents(out_of_order)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        # Register in IncidentManager
        registered_inc = self.incident_manager.create_incident_from_correlation(inc)

        # Timeline must be sorted t1, t2, t3
        timeline = registered_inc["timeline"]
        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0]["timestamp"], t1)
        self.assertEqual(timeline[0]["event_id"], "EV-001")
        self.assertEqual(timeline[1]["timestamp"], t2)
        self.assertEqual(timeline[1]["event_id"], "EV-002")
        self.assertEqual(timeline[2]["timestamp"], t3)
        self.assertEqual(timeline[2]["event_id"], "EV-003")

    def test_duplicate_event_handling(self):
        """Duplicate events sent to correlation engine should not cause crashes or invalid state transitions."""
        ev = SecurityEvent(
            event_id="EV-DUP-01",
            timestamp="2026-09-05T18:00:00Z",
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            source="tetragon",
            namespace="threatguard",
            pod="test-pod",
            process="/bin/sh",
            action="shell_spawn",
            severity="HIGH",
            mitre_technique="T1059.004",
            mitre_tactic="Execution"
        )

        # Correlating duplicates
        incidents = correlate_incidents([ev, ev, ev])
        self.assertEqual(len(incidents), 1)
        # Should record events gracefully
        self.assertEqual(len(incidents[0].events), 3)

    def test_security_event_deserialization_defaults(self):
        """SecurityEvent.from_dict with partial/empty fields should safely fallback to sensible defaults."""
        partial_data = {
            "source": "unknown"
        }
        event = SecurityEvent.from_dict(partial_data)
        self.assertEqual(event.severity, Severity.HIGH.value)
        self.assertEqual(event.event_type, SecurityEventType.RUNTIME_DETECTION.value)
        self.assertEqual(event.namespace, "threatguard")
        self.assertIsNotNone(event.event_id)
        self.assertIsNotNone(event.timestamp)

    def test_risk_evaluation_with_extreme_values(self):
        """Risk engine should clamp composite scores strictly between 0.0 and 100.0 under extreme conditions."""
        # 50 critical events with 10 tactics
        burst_events = []
        for i in range(50):
            burst_events.append(SecurityEvent(
                event_id=f"EV-BURST-{i}",
                timestamp="2026-09-05T18:00:00Z",
                event_type=SecurityEventType.RUNTIME_DETECTION.value,
                source="tetragon",
                namespace="threatguard",
                pod="target-pod",
                process="/sbin/capsh",
                action="escalation",
                severity="CRITICAL",
                mitre_technique=f"T100{i%10}",
                mitre_tactic=f"Tactic-{i%10}"
            ))

        assessment = self.risk_engine.evaluate_workload(
            burst_events,
            workload_ref="threatguard/target-pod",
            workload_spec={"privileged": True, "hostPID": True, "runAsUser": 0}
        )
        self.assertLessEqual(assessment.composite_risk_score, 100.0)
        self.assertGreaterEqual(assessment.composite_risk_score, 0.0)
        self.assertEqual(assessment.risk_tier, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
