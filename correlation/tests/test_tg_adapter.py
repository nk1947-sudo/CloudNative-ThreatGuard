"""
Unit tests for ThreatGuardAdapter.
"""

import unittest
from runtime.engine.models import SecurityEvent, SecurityEventType, Severity as TGSeverity
from correlation.adapters.tg_adapter import ThreatGuardAdapter
from correlation.models.event import EventSource, EventType, CloudProvider, Severity


class TestThreatGuardAdapter(unittest.TestCase):
    def test_runtime_event_conversion(self):
        tg_event = SecurityEvent(
            event_type=SecurityEventType.RUNTIME_DETECTION.value,
            source="tetragon",
            cluster="threatguard-prod",
            namespace="threatguard",
            pod="threatguard-target-pod-79f8b4cd6-abcde",
            process="bash",
            parent_process="nginx",
            executable="/bin/bash",
            action="process_exec",
            severity=TGSeverity.CRITICAL.value,
            confidence=0.98,
            detection_rule="TG-RULE-001",
            mitre_technique="T1059.004",
            mitre_tactic="Execution",
            description="Interactive shell execution in container",
            metadata={"container": "target-app", "risk_score": 92.0},
        )

        unified = ThreatGuardAdapter.to_unified_event(tg_event)

        self.assertEqual(unified.source, EventSource.THREATGUARD)
        self.assertEqual(unified.event_type, EventType.RUNTIME_DETECTION)
        self.assertEqual(unified.provider, CloudProvider.KUBERNETES)
        self.assertEqual(unified.cluster_id, "threatguard-prod")
        self.assertEqual(unified.namespace, "threatguard")
        self.assertEqual(unified.workload, "threatguard-target-pod")
        self.assertEqual(unified.pod, "threatguard-target-pod-79f8b4cd6-abcde")
        self.assertEqual(unified.severity, Severity.CRITICAL)
        self.assertEqual(unified.risk_score, 92.0)
        self.assertEqual(unified.detection_rule, "TG-RULE-001")
        self.assertIn("mitre_technique", unified.evidence)
        self.assertEqual(unified.evidence["mitre_technique"], "T1059.004")
        self.assertEqual(unified.metadata["engine"], "threatguard")

    def test_admission_denial_dict_conversion(self):
        admission_dict = {
            "event_type": "admission_violation",
            "source": "opa_gatekeeper",
            "cluster": "k8s-cluster",
            "namespace": "threatguard",
            "pod": "privileged-pod",
            "action": "blocked_admission",
            "severity": "HIGH",
            "confidence": 1.0,
            "detection_rule": "K8sDisallowPrivileged",
            "description": "Privileged container creation blocked",
            "metadata": {"workload": "privileged-workload"},
        }

        unified = ThreatGuardAdapter.to_unified_event(admission_dict)
        self.assertEqual(unified.source, EventSource.THREATGUARD)
        self.assertEqual(unified.event_type, EventType.ADMISSION_VIOLATION)
        self.assertEqual(unified.workload, "privileged-workload")
        self.assertEqual(unified.severity, Severity.HIGH)
        self.assertEqual(unified.risk_score, 75.0)


if __name__ == "__main__":
    unittest.main()
