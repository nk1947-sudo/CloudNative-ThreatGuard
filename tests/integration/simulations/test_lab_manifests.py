"""
Deterministic unit tests for ThreatGuard Security Lab Workload Manifests.
Validates YAML correctness, security profile designations, and misconfiguration criteria.
"""

import os
import unittest

import yaml

from cloudnative_threatguard.config import settings

# The manifests under test live with the simulation lab itself
# (simulations/lab/manifests/), not next to this test file -- tests must not
# assume they run from a fixed relative position on disk.
LAB_MANIFEST_DIR = settings.PROJECT_ROOT / "simulations" / "lab" / "manifests"


class TestLabManifests(unittest.TestCase):
    def test_benign_web_frontend(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "01-benign-web-frontend.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc["kind"], "Deployment")
        self.assertEqual(doc["metadata"]["name"], "web-frontend")
        self.assertEqual(doc["metadata"]["labels"]["security.threatguard.io/profile"], "benign")

        pod_sc = doc["spec"]["template"]["spec"]["securityContext"]
        self.assertTrue(pod_sc.get("runAsNonRoot"))
        self.assertEqual(pod_sc.get("runAsUser"), 10001)

        container_sc = doc["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        self.assertTrue(container_sc.get("readOnlyRootFilesystem"))
        self.assertFalse(container_sc.get("privileged"))
        self.assertIn("ALL", container_sc.get("capabilities", {}).get("drop", []))

    def test_target_payment_service(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "02-target-payment-service.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        deployment = docs[0]
        self.assertEqual(deployment["metadata"]["name"], "payment-service")
        self.assertEqual(deployment["metadata"]["labels"]["security.threatguard.io/profile"], "target")
        self.assertTrue(deployment["spec"]["template"]["spec"].get("automountServiceAccountToken"))

    def test_target_analytics_worker(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "03-target-analytics-worker.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc["metadata"]["name"], "analytics-worker")
        self.assertEqual(doc["metadata"]["labels"]["security.threatguard.io/profile"], "target")

    def test_misconfigured_privileged_pod(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "04-misconfigured-privileged-pod.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc["metadata"]["name"], "privileged-debug-pod")
        container_sc = doc["spec"]["containers"][0]["securityContext"]
        self.assertTrue(container_sc.get("privileged"))
        self.assertIn("SYS_ADMIN", container_sc.get("capabilities", {}).get("add", []))

    def test_misconfigured_hostpath_pod(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "05-misconfigured-hostpath-pod.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc["metadata"]["name"], "hostpath-mount-pod")
        volumes = doc["spec"]["volumes"]
        self.assertTrue(any("hostPath" in v for v in volumes))

    def test_unauthorized_cryptominer(self):
        filepath = os.path.join(LAB_MANIFEST_DIR, "06-unauthorized-cryptominer.yaml")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        self.assertEqual(doc["metadata"]["name"], "unauthorized-cryptominer")
        self.assertEqual(doc["metadata"]["labels"]["security.threatguard.io/profile"], "malicious")


if __name__ == "__main__":
    unittest.main()
