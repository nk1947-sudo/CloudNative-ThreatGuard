"""
Gatekeeper admission manifest validator.

Evaluates the positive (compliant) and negative (intentionally insecure)
test manifests under deploy/gatekeeper/tests/manifests/ against the Rego
constraint source, without requiring a live cluster or admission webhook.

This replaces the standalone policies/gatekeeper/tests/validate_admission_manifests.py
script; the same logic is now reusable from the CLI (``threatguard admission
validate``) and from tests/integration/admission/test_manifest_validation.py.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from cloudnative_threatguard.config import settings
from .opa_client import eval_policy

POLICIES: Dict[str, Tuple[str, str]] = {
    "01-privileged-pod.yaml": ("k8sprivilegedcontainer", "privileged mode must be false"),
    "02-hostpid-pod.yaml": ("k8shostnamespaces", "hostPID must be false"),
    "03-docker-socket-mount.yaml": ("k8shostfilesystem", "mounting hostPath '/var/run/docker.sock' is strictly prohibited"),
    "04-root-user-pod.yaml": ("k8snonrootuser", "runAsNonRoot must be true"),
    "05-allow-priv-escalation.yaml": ("k8sprivilegeescalation", "allowPrivilegeEscalation must be false"),
    "06-missing-drop-caps.yaml": ("k8sdropcapabilities", "capabilities.drop must explicitly include 'ALL'"),
    "07-missing-seccomp.yaml": ("k8sseccompprofile", "seccompProfile.type must be configured to 'RuntimeDefault'"),
    "08-writable-rootfs.yaml": ("k8sreadonlyrootfs", "readOnlyRootFilesystem must be true"),
}

ALL_PACKAGES: List[str] = [
    "k8sprivilegedcontainer", "k8shostnamespaces", "k8shostfilesystem",
    "k8snonrootuser", "k8sprivilegeescalation", "k8sdropcapabilities",
    "k8sseccompprofile", "k8sreadonlyrootfs",
]


@dataclass
class PolicyCheckResult:
    manifest: str
    policy_package: str
    blocked: bool
    message_matched_expected: bool
    violation_messages: List[str] = field(default_factory=list)


@dataclass
class ManifestValidationReport:
    positive_manifest: str
    positive_passed: bool
    positive_failures: List[str]
    negative_results: List[PolicyCheckResult]

    @property
    def total_negative(self) -> int:
        return len(self.negative_results)

    @property
    def blocked_negative(self) -> int:
        return sum(1 for r in self.negative_results if r.blocked)

    @property
    def all_passed(self) -> bool:
        return self.positive_passed and self.blocked_negative == self.total_negative


def _load_yaml(filepath: Path) -> Any:
    with open(filepath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_all(gatekeeper_dir: Optional[Path] = None) -> ManifestValidationReport:
    """
    Validates the positive manifest (must pass every policy) and all negative
    manifests (each must trigger its mapped policy) using the OPA CLI.
    """
    gatekeeper_dir = gatekeeper_dir or (settings.PROJECT_ROOT / "deploy" / "gatekeeper")
    src_dir = gatekeeper_dir / "src"

    # 1. Positive manifest
    pos_path = gatekeeper_dir / "tests" / "manifests" / "positive" / "secure-workload.yaml"
    pos_pod = _load_yaml(pos_path)
    positive_failures: List[str] = []
    for pkg in ALL_PACKAGES:
        violations = eval_policy(pkg, pos_pod, src_dir=src_dir)
        if violations:
            positive_failures.append(f"{pkg}: {violations}")

    # 2. Negative manifests
    neg_dir = gatekeeper_dir / "tests" / "manifests" / "negative"
    neg_files = sorted(glob.glob(str(neg_dir / "*.yaml")))

    negative_results: List[PolicyCheckResult] = []
    for fpath in neg_files:
        fname = os.path.basename(fpath)
        if fname not in POLICIES:
            continue
        pkg, expected_msg = POLICIES[fname]
        pod = _load_yaml(Path(fpath))
        violations = eval_policy(pkg, pod, src_dir=src_dir)
        violation_msgs = [v.get("msg", "") for v in violations]
        blocked = len(violations) > 0
        matched = any(expected_msg in m for m in violation_msgs)
        negative_results.append(PolicyCheckResult(
            manifest=fname,
            policy_package=pkg,
            blocked=blocked,
            message_matched_expected=matched,
            violation_messages=violation_msgs,
        ))

    return ManifestValidationReport(
        positive_manifest=os.path.basename(pos_path),
        positive_passed=not positive_failures,
        positive_failures=positive_failures,
        negative_results=negative_results,
    )


def print_report(report: ManifestValidationReport) -> None:
    print("=" * 70)
    print("CloudNative ThreatGuard - Admission Policy Manifest Verification")
    print("=" * 70)

    print(f"\n[+] Testing Positive Workload: {report.positive_manifest}")
    if report.positive_passed:
        for pkg in ALL_PACKAGES:
            print(f"  [PASS] {pkg}: ALLOWED (0 violations)")
    else:
        for failure in report.positive_failures:
            print(f"  [FAIL] Positive pod unexpectedly triggered policy {failure}")

    print("\n[+] Testing Negative (Insecure) Workloads:")
    for r in report.negative_results:
        if r.blocked and r.message_matched_expected:
            print(f"  [BLOCKED as expected] {r.manifest} -> Policy: {r.policy_package} [PASS]")
        elif r.blocked:
            print(f"  [WARN] {r.manifest} blocked, but message did not match expectation: {r.violation_messages}")
        else:
            print(f"  [FAIL] {r.manifest} was NOT blocked by {r.policy_package}!")

    print("\n" + "=" * 70)
    rate = (report.blocked_negative / report.total_negative * 100.0) if report.total_negative else 0.0
    print(f"Summary: Negative Workloads Blocked: {report.blocked_negative}/{report.total_negative} ({rate:.1f}%)")
    print("=" * 70)

    if report.all_passed:
        print("\nAll admission policy manifest verifications succeeded.\n")
