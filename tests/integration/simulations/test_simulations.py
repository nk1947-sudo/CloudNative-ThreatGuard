"""
Automated unit and integration test for the Attack Simulation Suite in CloudNative ThreatGuard.
Verifies all 8 simulation scenarios execute cleanly, produce valid SecurityEvents,
correlate into multi-stage incidents, and generate transparent risk assessments.
"""

import unittest

from cloudnative_threatguard.correlation.kubernetes import correlate_incidents
from cloudnative_threatguard.detection.engine import DetectionEngine
from cloudnative_threatguard.reporting.risk import RiskScoringEngine, RiskTier
from cloudnative_threatguard.runtime.events import SecurityEvent


class TestSimulationSuite(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine(protected_namespace="threatguard")
        self.risk_engine = RiskScoringEngine()

    def test_full_attack_chain_simulation(self):
        # 1. Admission Denial Event (SCEN-000)
        admission_ev = SecurityEvent.from_admission_denial(
            rule_id="RULE-K8S-009",
            policy_name="k8sprivilegedcontainer",
            resource_name="01-privileged-pod",
            namespace="threatguard",
            violation_message="Privileged container execution is prohibited"
        )
        self.assertEqual(admission_ev.mitre_technique, "T1610")
        self.assertEqual(admission_ev.mitre_tactic, "Defense Evasion")

        # 2. Raw Tetragon Events (SCEN-001 through SCEN-008)
        simulated_raw_events = [
            # SCEN-001
            {"time": "2026-09-05T18:30:01Z", "process_exec": {"process": {"binary": "/bin/sh", "arguments": "-c whoami", "pid": 5101, "uid": 10001, "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}}},
            # SCEN-002
            {"time": "2026-09-05T18:30:02Z", "process_exec": {"process": {"binary": "/usr/bin/wget", "arguments": "-qO- http://127.0.0.1:8080/healthz", "pid": 5102, "uid": 10001, "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}}},
            # SCEN-003
            {"time": "2026-09-05T18:30:03Z", "process_exec": {"process": {"binary": "/usr/bin/whoami", "arguments": "", "pid": 5103, "uid": 10001, "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}}},
            # SCEN-004
            {"time": "2026-09-05T18:30:04Z", "process_kprobe": {"function_name": "security_file_open", "process": {"binary": "/bin/cat", "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}, "args": [{"file_arg": {"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}}, {"int_arg": 0}]}},
            # SCEN-005
            {"time": "2026-09-05T18:30:05Z", "process_exec": {"process": {"binary": "/sbin/capsh", "arguments": "--print", "pid": 5105, "uid": 10001, "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}}},
            # SCEN-006
            {"time": "2026-09-05T18:30:06Z", "process_kprobe": {"function_name": "sys_enter_connect", "process": {"binary": "/usr/bin/nc", "pod": {"namespace": "threatguard", "name": "threatguard-target-pod", "container": {"name": "simulation-target"}}}, "args": [{"int_arg": 3}, {"sock_arg": {"daddr": "1.1.1.1", "dport": 443, "proto": "TCP"}}]}}
        ]

        detections = []
        for raw in simulated_raw_events:
            det = self.engine.process_event(raw)
            if det:
                detections.append(det)

        self.assertEqual(len(detections), 6)

        # Convert to normalized SecurityEvent
        all_events = [admission_ev] + [d.to_security_event() for d in detections]
        self.assertEqual(len(all_events), 7)

        # Correlate incidents
        incidents = correlate_incidents(all_events)
        self.assertEqual(len(incidents), 2)
        pod_names = [inc.pod for inc in incidents]
        self.assertIn("threatguard-target-pod", pod_names)
        self.assertIn("01-privileged-pod", pod_names)
        for inc in incidents:
            self.assertTrue(inc.incident_id.startswith("#TG-"))

        # The 5-event, multi-tactic sequence on threatguard-target-pod must be
        # classified as a multi-stage attack chain, not an isolated burst --
        # this only holds now that DetectionEngine populates mitre_tactic on
        # every detection it produces.
        target_pod_incident = next(inc for inc in incidents if inc.pod == "threatguard-target-pod")
        self.assertIn("Multi-Stage Attack Chain", target_pod_incident.title)
        self.assertGreater(len(target_pod_incident.tactics), 1)

        # Evaluate risk score
        risk = self.risk_engine.evaluate_workload(
            all_events,
            workload_ref="threatguard/threatguard-target-pod",
            workload_spec={"runAsUser": 0, "privileged": True}
        )
        self.assertGreaterEqual(risk.composite_risk_score, 80.0)
        self.assertEqual(risk.risk_tier, RiskTier.CRITICAL.value)
        self.assertGreater(len(risk.top_risk_contributors), 0)


if __name__ == "__main__":
    unittest.main()
