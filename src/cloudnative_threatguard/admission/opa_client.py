"""
Thin subprocess wrapper around the Open Policy Agent (OPA) CLI.
Used to evaluate Gatekeeper Rego constraint templates against a Kubernetes
object without needing a live admission webhook or cluster.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from cloudnative_threatguard.config import settings


def resolve_opa_binary() -> str:
    """
    Finds an OPA binary to invoke: a system-installed 'opa' on PATH, or a
    local opa.exe convenience binary at the project root (Windows dev use).
    """
    on_path = shutil.which("opa")
    if on_path:
        return on_path
    local_exe = settings.PROJECT_ROOT / "opa.exe"
    if os.name == "nt" and local_exe.exists():
        return str(local_exe)
    return "opa"


def eval_policy(policy_pkg: str, review_object: Dict[str, Any], src_dir: Path = None) -> List[Dict[str, Any]]:
    """
    Evaluates a single Gatekeeper Rego package's `violation` rule against a
    Kubernetes object, returning the list of violation dicts (each with a
    ``msg`` key), or an empty list if the object is compliant.
    """
    src_dir = src_dir or settings.GATEKEEPER_SRC_DIR
    input_data = {"review": {"object": review_object}, "parameters": {}}

    cmd = [
        resolve_opa_binary(), "eval",
        "-d", str(src_dir),
        "-I",
        f"data.{policy_pkg}.violation",
        "--format", "json",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate(input=json.dumps(input_data))
    if proc.returncode != 0:
        raise RuntimeError(f"OPA eval error for package '{policy_pkg}': {stderr}")

    out = json.loads(stdout)
    return out.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
