"""
Unit tests for Workload and Process Investigation Engine.
Validates security posture extraction, process tree reconstruction, and telemetry dossiers.
"""

import unittest
from runtime.engine.investigation_engine import WorkloadInvestigator, WorkloadSecurityPosture
from runtime.engine.models import SecurityEvent, Severity, SecurityEventType


class TestWorkloadInvestigator(unittest.TestCase):
    def setUp(self):
        self.investigator = WorkloadInvestigator()

    def test_security_posture_extraction(self):
        pod_spec = {
            "spec": {
                "hostPID": True,
                "hostNetwork": True,
                "securityContext": {
                    "runAsUser": 0
                },
                "containers": [
                    {
                        "name": "target",
                        "securityContext": {
                            "privileged": True,
                            "allowPrivilegeEscalation": True,
                            "capabilities": {
                                "add": ["SYS_ADMIN", "NET_ADMIN"]
                            }
                        }
                    }
                ]
            }
        }

        posture = WorkloadSecurityPosture.from_pod_spec(pod_spec)
        self.assertTrue(posture.privileged)
        self.assertTrue(posture.host_pid)
        self.assertTrue(posture.host_network)
        self.assertIn("SYS_ADMIN", posture.capabilities_add)
        self.assertEqual(posture.run_as_user, 0)

    def test_full_investigation_dossier(self):
        events = [
            SecurityEvent(
                event_id="ev-1",
                timestamp="2026-09-05T12:00:00Z",
                action="process_exec",
                namespace="threatguard",
                pod="payment-service-pod",
                process="/bin/bash",
                severity=Severity.HIGH.value,
                mitre_tactic="Execution",
                mitre_technique="T1059.004",
                metadata={"pid": 105, "ppid": 1, "arguments": "-i"}
            ),
            SecurityEvent(
                event_id="ev-2",
                timestamp="2026-09-05T12:01:00Z",
                action="file_read",
                namespace="threatguard",
                pod="payment-service-pod",
                process="/bin/cat",
                file_path="/var/run/secrets/kubernetes.io/serviceaccount/token",
                severity=Severity.CRITICAL.value,
                mitre_tactic="Credential Access",
                mitre_technique="T1552.007",
                metadata={"pid": 110, "ppid": 105, "flags": "O_RDONLY"}
            ),
            SecurityEvent(
                event_id="ev-3",
                timestamp="2026-09-05T12:02:00Z",
                action="sys_enter_connect",
                namespace="threatguard",
                pod="payment-service-pod",
                process="/usr/bin/curl",
                destination_ip="198.51.100.23",
                destination_port=443,
                severity=Severity.HIGH.value,
                mitre_tactic="Command and Control",
                mitre_technique="T1071.001",
                metadata={"pid": 115, "ppid": 105, "proto": "TCP"}
            )
        ]

        dossier = self.investigator.investigate(
            namespace="threatguard",
            pod_name="payment-service-pod",
            events=events,
            container_image="payment-app:v1.2"
        )

        self.assertEqual(dossier["workload_ref"], "threatguard/payment-service-pod")
        self.assertEqual(dossier["container_image"], "payment-app:v1.2")
        self.assertEqual(dossier["telemetry_summary"]["total_events"], 3)
        self.assertEqual(dossier["telemetry_summary"]["process_executions"], 1)
        self.assertEqual(dossier["telemetry_summary"]["file_accesses"], 1)
        self.assertEqual(dossier["telemetry_summary"]["socket_connections"], 1)
        self.assertGreater(len(dossier["active_alerts"]), 0)

        # Verify process tree reconstruction
        tree = dossier["process_tree"]
        self.assertEqual(len(tree), 1)
        self.assertEqual(tree[0]["pid"], 1)
        # pid 105 (/bin/bash) should be a child of pid 1
        child_pids = [c["pid"] for c in tree[0]["children"]]
        self.assertIn(105, child_pids)


if __name__ == "__main__":
    unittest.main()
