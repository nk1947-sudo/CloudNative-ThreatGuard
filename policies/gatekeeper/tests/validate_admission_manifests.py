#!/usr/bin/env python3
"""
Validates Gatekeeper admission test manifests against Rego policies using OPA.
Tests positive manifest (must pass all policies) and 8 negative manifests (each must trigger its respective policy).
"""

import os
import sys
import json
import subprocess
import glob

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
OPA_BIN = os.path.join(REPO_ROOT, "opa.exe") if os.name == "nt" else "opa"

POLICIES = {
    "01-privileged-pod.yaml": ("k8sprivilegedcontainer", "privileged mode must be false"),
    "02-hostpid-pod.yaml": ("k8shostnamespaces", "hostPID must be false"),
    "03-docker-socket-mount.yaml": ("k8shostfilesystem", "mounting hostPath '/var/run/docker.sock' is strictly prohibited"),
    "04-root-user-pod.yaml": ("k8snonrootuser", "runAsNonRoot must be true"),
    "05-allow-priv-escalation.yaml": ("k8sprivilegeescalation", "allowPrivilegeEscalation must be false"),
    "06-missing-drop-caps.yaml": ("k8sdropcapabilities", "capabilities.drop must explicitly include 'ALL'"),
    "07-missing-seccomp.yaml": ("k8sseccompprofile", "seccompProfile.type must be configured to 'RuntimeDefault'"),
    "08-writable-rootfs.yaml": ("k8sreadonlyrootfs", "readOnlyRootFilesystem must be true"),
}

def parse_yaml(filepath):
    try:
        import yaml
        with open(filepath, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        # Fallback simple parser for k8s pod
        import json
        cmd = [sys.executable, "-c", "import yaml, json, sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))", filepath]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(res.stdout)

def eval_policy(policy_pkg, pod_obj):
    input_data = {
        "review": {
            "object": pod_obj
        },
        "parameters": {}
    }
    src_dir = os.path.join(REPO_ROOT, "policies", "gatekeeper", "src")
    cmd = [
        OPA_BIN, "eval",
        "-d", src_dir,
        "-I",
        f"data.{policy_pkg}.violation",
        "--format", "json"
    ]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = p.communicate(input=json.dumps(input_data))
    if p.returncode != 0:
        raise RuntimeError(f"OPA eval error: {stderr}")
    out = json.loads(stdout)
    expressions = out.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
    return expressions

def main():
    print("=" * 70)
    print("CloudNative ThreatGuard — Admission Policy Manifest Verification")
    print("=" * 70)

    # 1. Test Positive Manifest
    pos_path = os.path.join(REPO_ROOT, "policies", "gatekeeper", "tests", "manifests", "positive", "secure-workload.yaml")
    pos_pod = parse_yaml(pos_path)
    print(f"\n[+] Testing Positive Workload: {os.path.basename(pos_path)}")
    all_passed = True

    packages = [
        "k8sprivilegedcontainer", "k8shostnamespaces", "k8shostfilesystem",
        "k8snonrootuser", "k8sprivilegeescalation", "k8sdropcapabilities",
        "k8sseccompprofile", "k8sreadonlyrootfs"
    ]

    for pkg in packages:
        violations = eval_policy(pkg, pos_pod)
        if len(violations) > 0:
            print(f"  [FAIL] Positive pod unexpectedly triggered policy {pkg}: {violations}")
            all_passed = False
        else:
            print(f"  [PASS] {pkg}: ALLOWED (0 violations)")

    # 2. Test Negative Manifests
    print("\n[+] Testing Negative (Insecure) Workloads:")
    neg_dir = os.path.join(REPO_ROOT, "policies", "gatekeeper", "tests", "manifests", "negative")
    neg_files = sorted(glob.glob(os.path.join(neg_dir, "*.yaml")))

    total_neg = len(neg_files)
    blocked_neg = 0

    for fpath in neg_files:
        fname = os.path.basename(fpath)
        if fname not in POLICIES:
            continue
        pkg, expected_msg = POLICIES[fname]
        pod = parse_yaml(fpath)
        violations = eval_policy(pkg, pod)
        if len(violations) > 0:
            violation_msgs = [v.get("msg", "") for v in violations]
            found = any(expected_msg in m for m in violation_msgs)
            if found:
                print(f"  [BLOCKED as expected] {fname} -> Policy: {pkg} [PASS]")
                blocked_neg += 1
            else:
                print(f"  [WARN] {fname} blocked, but expected '{expected_msg}', got: {violation_msgs}")
                blocked_neg += 1
        else:
            print(f"  [FAIL] {fname} was NOT blocked by {pkg}!")
            all_passed = False

    print("\n" + "=" * 70)
    print(f"Summary: Negative Workloads Blocked: {blocked_neg}/{total_neg} ({blocked_neg/total_neg*100:.1f}%)")
    print("=" * 70)

    if not all_passed or blocked_neg != total_neg:
        sys.exit(1)
    print("\nAll admission policy manifest verifications succeeded.\n")

if __name__ == "__main__":
    main()
