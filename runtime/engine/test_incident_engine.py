"""
Unit tests for ThreatGuard Incident Management Engine.
Validates incident lifecycle transitions, attack chain generation, and recommendation logic.
"""

import unittest
from runtime.engine.incident_engine import IncidentManager, IncidentStatus
from runtime.engine.models import SecurityEvent, SecurityIncident, Severity, SecurityEventType


class TestIncidentManager(unittest.TestCase):
    def setUp(self):
        self.mgr = IncidentManager()

    def test_incident_creation_and_lifecycle(self):
        event1 = SecurityEvent(
            event_id="ev-001",
            timestamp="2026-09-05T12:00:00Z",
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            namespace="threatguard",
            pod="target-app",
            container="app",
            process="/bin/sh",
            severity=Severity.HIGH.value,
            mitre_tactic="Execution",
            mitre_technique="T1059.004",
            description="Interactive Shell Spawned"
        )
        event2 = SecurityEvent(
            event_id="ev-002",
            timestamp="2026-09-05T12:01:00Z",
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            namespace="threatguard",
            pod="target-app",
            container="app",
            process="/bin/cat",
            severity=Severity.CRITICAL.value,
            mitre_tactic="Credential Access",
            mitre_technique="T1552.007",
            description="Service Account Token Theft"
        )

        corr = SecurityIncident(
            incident_id="#TG-TEST01",
            cluster="threatguard-local",
            namespace="threatguard",
            pod="target-app",
            container="app",
            severity=Severity.CRITICAL.value,
            title="Multi-Stage Workload Breach",
            tactics=["Execution", "Credential Access"],
            techniques=["T1059.004", "T1552.007"],
            events=[event1, event2]
        )

        record = self.mgr.create_incident_from_correlation(corr)
        self.assertEqual(record["incident_id"], "#TG-TEST01")
        self.assertEqual(record["status"], IncidentStatus.NEW.value)
        self.assertEqual(record["severity"], "CRITICAL")
        self.assertEqual(len(record["attack_chain"]), 2)
        self.assertEqual(len(record["timeline"]), 2)
        self.assertGreater(len(record["recommendations"]), 0)

        # Test Status Transition to TRIAGED
        updated = self.mgr.update_status("#TG-TEST01", "TRIAGED", "Acknowledged by SecOps")
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "TRIAGED")
        self.assertEqual(len(updated["history"]), 2)

        # Test Status Transition to CONTAINED
        updated = self.mgr.update_status("#TG-TEST01", "CONTAINED", "Quarantine NetworkPolicy applied")
        self.assertEqual(updated["status"], "CONTAINED")

        # Test Status Transition to RESOLVED
        updated = self.mgr.update_status("#TG-TEST01", "RESOLVED", "Compromised pod replaced")
        self.assertEqual(updated["status"], "RESOLVED")

    def test_invalid_status_transition(self):
        corr = SecurityIncident(incident_id="#TG-INVALID", pod="dummy-pod")
        self.mgr.create_incident_from_correlation(corr)
        with self.assertRaises(ValueError):
            self.mgr.update_status("#TG-INVALID", "NOT_A_VALID_STATUS")

    def test_incident_filtering(self):
        corr1 = SecurityIncident(incident_id="#TG-01", namespace="threatguard", severity=Severity.HIGH.value)
        corr2 = SecurityIncident(incident_id="#TG-02", namespace="kube-system", severity=Severity.LOW.value)
        self.mgr.create_incident_from_correlation(corr1)
        self.mgr.create_incident_from_correlation(corr2)

        high_incidents = self.mgr.list_incidents(severity="HIGH")
        self.assertEqual(len(high_incidents), 1)
        self.assertEqual(high_incidents[0]["incident_id"], "#TG-01")

        kube_incidents = self.mgr.list_incidents(namespace="kube-system")
        self.assertEqual(len(kube_incidents), 1)
        self.assertEqual(kube_incidents[0]["incident_id"], "#TG-02")


if __name__ == "__main__":
    unittest.main()
