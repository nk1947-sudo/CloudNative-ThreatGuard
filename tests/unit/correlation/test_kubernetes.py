"""
Unit tests for ThreatGuard Security Event Correlation.
Validates grouping of sequential, multi-stage events into coherent security incidents (#TG-xxx).
"""

import unittest

from cloudnative_threatguard.correlation.kubernetes import correlate_incidents
from cloudnative_threatguard.runtime.events import SecurityEvent, SecurityEventType, Severity


class TestEventCorrelation(unittest.TestCase):
    def test_single_workload_multi_event_correlation(self):
        events = [
            SecurityEvent(
                event_id="ev-1",
                timestamp="2026-09-05T12:00:00Z",
                event_type=SecurityEventType.RUNTIME_DETECTION.value,
                namespace="threatguard",
                pod="payment-service-7f",
                container="app",
                process="/bin/sh",
                severity=Severity.HIGH.value,
                mitre_tactic="Execution",
                mitre_technique="T1059.004",
                description="Interactive Shell Spawned"
            ),
            SecurityEvent(
                event_id="ev-2",
                timestamp="2026-09-05T12:01:00Z",
                event_type=SecurityEventType.RUNTIME_DETECTION.value,
                namespace="threatguard",
                pod="payment-service-7f",
                container="app",
                process="/bin/cat",
                severity=Severity.CRITICAL.value,
                mitre_tactic="Credential Access",
                mitre_technique="T1552.007",
                description="Service Account Token Access"
            ),
            SecurityEvent(
                event_id="ev-3",
                timestamp="2026-09-05T12:02:00Z",
                event_type=SecurityEventType.RUNTIME_DETECTION.value,
                namespace="threatguard",
                pod="payment-service-7f",
                container="app",
                process="/usr/bin/curl",
                severity=Severity.HIGH.value,
                mitre_tactic="Command and Control",
                mitre_technique="T1071",
                description="Outbound Connection to External Host"
            )
        ]

        incidents = correlate_incidents(events)
        self.assertEqual(len(incidents), 1)

        inc = incidents[0]
        self.assertTrue(inc.incident_id.startswith("#TG-"))
        self.assertEqual(inc.namespace, "threatguard")
        self.assertEqual(inc.pod, "payment-service-7f")
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertEqual(len(inc.events), 3)
        self.assertIn("Execution", inc.tactics)
        self.assertIn("Credential Access", inc.tactics)
        self.assertIn("Command and Control", inc.tactics)
        self.assertIn("T1059.004", inc.techniques)
        self.assertIn("T1552.007", inc.techniques)
        self.assertIn("T1071", inc.techniques)
        self.assertIn("Multi-Stage Attack Chain", inc.title)

    def test_multi_workload_isolation(self):
        events = [
            SecurityEvent(
                event_id="ev-a",
                namespace="threatguard",
                pod="web-frontend-1",
                severity=Severity.LOW.value,
                mitre_tactic="Discovery",
                mitre_technique="T1082"
            ),
            SecurityEvent(
                event_id="ev-b",
                namespace="threatguard",
                pod="database-backend-2",
                severity=Severity.CRITICAL.value,
                mitre_tactic="Credential Access",
                mitre_technique="T1552.007"
            )
        ]

        incidents = correlate_incidents(events)
        self.assertEqual(len(incidents), 2)
        pod_map = {inc.pod: inc for inc in incidents}
        self.assertIn("web-frontend-1", pod_map)
        self.assertIn("database-backend-2", pod_map)
        self.assertEqual(pod_map["web-frontend-1"].severity, "LOW")
        self.assertEqual(pod_map["database-backend-2"].severity, "CRITICAL")

    def test_empty_events_correlation(self):
        incidents = correlate_incidents([])
        self.assertEqual(len(incidents), 0)


if __name__ == "__main__":
    unittest.main()
