"""
Unit tests for the Normalized Security Event Model in CloudNative ThreatGuard.
"""

import unittest
from runtime.engine.models import (
    SecurityEvent,
    SecurityEventType,
    Severity,
    ThreatGuardDetection
)


class TestSecurityEventModel(unittest.TestCase):
    def test_default_initialization(self):
        event = SecurityEvent(
            namespace="threatguard",
            pod="sample-app-pod",
            process="/bin/bash",
            action="process_exec",
            severity=Severity.HIGH.value,
            detection_rule="RULE-K8S-001"
        )
        self.assertTrue(event.event_id.startswith("ev-"))
        self.assertIsNotNone(event.timestamp)
        self.assertEqual(event.event_type, SecurityEventType.RUNTIME_DETECTION.value)
        self.assertEqual(event.source, "tetragon")
        self.assertEqual(event.cluster, "threatguard-local")
        self.assertEqual(event.namespace, "threatguard")
        self.assertEqual(event.pod, "sample-app-pod")
        self.assertEqual(event.process, "/bin/bash")
        self.assertEqual(event.severity, "HIGH")

    def test_all_event_types_supported(self):
        expected_types = [
            SecurityEventType.ADMISSION_VIOLATION,
            SecurityEventType.RUNTIME_DETECTION,
            SecurityEventType.NETWORK_ANOMALY,
            SecurityEventType.POLICY_VIOLATION,
            SecurityEventType.CONFIGURATION_RISK,
            SecurityEventType.ATTACK_SIMULATION,
            SecurityEventType.INCIDENT,
            SecurityEventType.RESPONSE_ACTION,
        ]
        for et in expected_types:
            event = SecurityEvent(event_type=et.value)
            self.assertEqual(event.event_type, et.value)

    def test_serialization_and_deserialization(self):
        original = SecurityEvent(
            event_type=SecurityEventType.NETWORK_ANOMALY.value,
            source="tetragon_kprobe",
            namespace="threatguard",
            pod="threatguard-app-77bfd44b9-xldh2",
            container="app",
            process="/usr/bin/curl",
            action="outbound_egress_attempt",
            severity=Severity.HIGH.value,
            confidence=0.95,
            detection_rule="RULE-K8S-006",
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control",
            description="Unauthorized outbound connection to external IP",
            metadata={"destination_ip": "198.51.100.24", "destination_port": 443}
        )
        data = original.to_dict()
        self.assertIn("event_id", data)
        self.assertIn("timestamp", data)
        self.assertEqual(data["event_type"], "network_anomaly")
        self.assertEqual(data["rule_id"], "RULE-K8S-006")
        self.assertEqual(data["evidence"]["destination_ip"], "198.51.100.24")

        reconstructed = SecurityEvent.from_dict(data)
        self.assertEqual(reconstructed.event_id, original.event_id)
        self.assertEqual(reconstructed.event_type, original.event_type)
        self.assertEqual(reconstructed.namespace, original.namespace)
        self.assertEqual(reconstructed.detection_rule, original.detection_rule)
        self.assertEqual(reconstructed.metadata["destination_ip"], "198.51.100.24")

    def test_from_admission_denial_factory(self):
        event = SecurityEvent.from_admission_denial(
            rule_id="ADM-001",
            policy_name="k8sprivilegedcontainer",
            resource_name="malicious-pod",
            namespace="threatguard",
            violation_message="Privileged container is forbidden"
        )
        self.assertEqual(event.event_type, SecurityEventType.ADMISSION_VIOLATION.value)
        self.assertEqual(event.source, "opa_gatekeeper")
        self.assertEqual(event.severity, "CRITICAL")
        self.assertEqual(event.action, "blocked_admission")
        self.assertEqual(event.detection_rule, "ADM-001")
        self.assertIn("Privileged container is forbidden", event.description)

    def test_from_simulation_factory(self):
        event = SecurityEvent.from_simulation(
            scenario_id="SCEN-001",
            name="Interactive Shell Execution",
            pod="target-pod",
            namespace="threatguard",
            command="/bin/sh -i",
            technique="T1059.004",
            tactic="Execution"
        )
        self.assertEqual(event.event_type, SecurityEventType.ATTACK_SIMULATION.value)
        self.assertEqual(event.source, "threatguard_simulator")
        self.assertEqual(event.detection_rule, "SCEN-001")
        self.assertEqual(event.process, "/bin/sh")
        self.assertTrue(event.metadata["simulation"])

    def test_backwards_compatibility_threatguard_detection(self):
        det = ThreatGuardDetection(
            timestamp="2026-09-05T15:00:00Z",
            rule_id="RUNTIME-001",
            detection_name="Interactive Shell Spawned",
            severity="CRITICAL",
            technique="T1059.004",
            technique_name="Unix Shell",
            pod="sample-pod",
            container="app",
            process="/bin/sh",
            command="/bin/sh -i",
            evidence={"pid": 1234}
        )
        self.assertEqual(det.rule_id, "RUNTIME-001")
        self.assertEqual(det.detection_name, "Interactive Shell Spawned")
        self.assertEqual(det.technique, "T1059.004")
        self.assertEqual(det.technique_name, "Unix Shell")
        self.assertEqual(det.command, "/bin/sh -i")
        self.assertEqual(det.evidence["pid"], 1234)

        d_dict = det.to_dict()
        self.assertEqual(d_dict["rule_id"], "RUNTIME-001")
        self.assertEqual(d_dict["technique"], "T1059.004")


if __name__ == "__main__":
    unittest.main()
