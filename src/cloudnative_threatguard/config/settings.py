"""
Centralized configuration for CloudNative ThreatGuard.

Consolidates values that were previously recomputed independently in
``runtime/cli.py``, ``runtime/evidence_collector.py``,
``observability/exporter/metrics_exporter.py``, and
``scripts/generate-report.py``: the repository root, the artifacts
directory, and the default protected namespace/cluster/node names used
throughout the detection and reporting engines.

Every value can be overridden with an environment variable so the package
also works when installed outside of a git checkout.
"""

from __future__ import annotations

import os
from pathlib import Path


def _project_root() -> Path:
    override = os.environ.get("THREATGUARD_PROJECT_ROOT")
    if override:
        return Path(override).resolve()
    # src/cloudnative_threatguard/config/settings.py -> repo root is 3 levels up
    return Path(__file__).resolve().parents[3]


PROJECT_ROOT: Path = _project_root()
ARTIFACTS_DIR: Path = Path(os.environ.get("THREATGUARD_ARTIFACTS_DIR", str(PROJECT_ROOT / "artifacts")))

DEFAULT_PROTECTED_NAMESPACE = os.environ.get("THREATGUARD_NAMESPACE", "threatguard")
DEFAULT_CLUSTER_NAME = os.environ.get("THREATGUARD_CLUSTER", "threatguard-local")
DEFAULT_NODE_NAME = os.environ.get("THREATGUARD_NODE", "threatguard-local-control-plane")

EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "9100"))

# Conventional artifact subdirectories used by the reporting engine.
ARTIFACTS_ADMISSION_DIR = ARTIFACTS_DIR / "admission"
ARTIFACTS_RUNTIME_DIR = ARTIFACTS_DIR / "runtime"
ARTIFACTS_INCIDENTS_DIR = ARTIFACTS_DIR / "incidents"
ARTIFACTS_REPORTS_DIR = ARTIFACTS_DIR / "reports"
ARTIFACTS_FORENSICS_DIR = ARTIFACTS_DIR / "forensics"
ARTIFACTS_METRICS_DIR = ARTIFACTS_DIR / "metrics"

CLI_STATE_FILE = ARTIFACTS_DIR / "threatguard-state.json"

# Gatekeeper / OPA layout, relative to PROJECT_ROOT, after the deploy/ restructure.
GATEKEEPER_SRC_DIR = PROJECT_ROOT / "deploy" / "gatekeeper" / "src"
GATEKEEPER_TESTS_DIR = PROJECT_ROOT / "deploy" / "gatekeeper" / "tests"
