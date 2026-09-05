"""
Integration test for Gatekeeper admission manifest validation.

Exercises the real OPA CLI (via admission.opa_client) against the actual
Rego constraint source and test manifests under deploy/gatekeeper/ -- the
same path threatguard admission validate uses. Requires an 'opa' binary on
PATH or opa.exe at the project root; skipped otherwise.

This replaces the old policies/gatekeeper/tests/validate_admission_manifests.py
script, which only printed results and called sys.exit() -- there was no
way to assert on it programmatically or run it as part of the test suite.
"""

import shutil
import unittest

from cloudnative_threatguard.admission.opa_client import resolve_opa_binary
from cloudnative_threatguard.admission.validator import ALL_PACKAGES, validate_all
from cloudnative_threatguard.config import settings


def _opa_available() -> bool:
    if shutil.which("opa"):
        return True
    return (settings.PROJECT_ROOT / "opa.exe").exists()


@unittest.skipUnless(_opa_available(), "OPA binary not available on PATH or as ./opa.exe")
class TestManifestValidation(unittest.TestCase):
    def test_positive_manifest_passes_every_policy(self):
        report = validate_all()
        self.assertTrue(
            report.positive_passed,
            f"Compliant manifest unexpectedly triggered: {report.positive_failures}",
        )

    def test_all_negative_manifests_are_blocked(self):
        report = validate_all()
        self.assertEqual(report.total_negative, 8)
        self.assertEqual(report.blocked_negative, report.total_negative)
        for result in report.negative_results:
            self.assertTrue(result.blocked, f"{result.manifest} was not blocked by {result.policy_package}")

    def test_each_negative_manifest_matches_its_expected_violation_message(self):
        report = validate_all()
        mismatched = [r.manifest for r in report.negative_results if r.blocked and not r.message_matched_expected]
        self.assertEqual(mismatched, [], f"Blocked for the wrong reason: {mismatched}")

    def test_resolve_opa_binary_returns_something_runnable(self):
        self.assertTrue(resolve_opa_binary())

    def test_all_eight_policy_packages_covered(self):
        self.assertEqual(len(ALL_PACKAGES), 8)


if __name__ == "__main__":
    unittest.main()
