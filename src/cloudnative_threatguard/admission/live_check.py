"""
Live and offline admission enforcement checks.

Each negative manifest is classified from the actual ``kubectl apply
--dry-run=server`` result instead of treating any non-zero exit as a
successful block. Only a response that carries the Gatekeeper webhook
identity counts as a policy denial; a missing file, unreachable API server
or RBAC failure is an execution error and never counts as enforcement.

Exit codes: 0 all checks matched expectations, 1 policy mismatch or
execution error, 2 prerequisites missing (BLOCKED).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings

WEBHOOK_MARKER = 'admission webhook "validation.gatekeeper.sh" denied the request'
_CONSTRAINT_RE = re.compile(re.escape(WEBHOOK_MARKER) + r":\s*\[([^\]]+)\]")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_BLOCKED = 2


class Outcome(str, Enum):
    POLICY_DENIED = "policy_denied"
    UNEXPECTEDLY_ALLOWED = "unexpectedly_allowed"
    EXECUTION_ERROR = "execution_error"
    ALLOWED = "allowed"
    POSITIVE_REJECTED = "positive_rejected"


Runner = Callable[[list[str]], tuple[int, str]]


def kubectl_runner(args: list[str]) -> tuple[int, str]:
    """Runs kubectl and returns (exit code, combined output); never raises."""
    try:
        proc = subprocess.run(
            ["kubectl", *args], capture_output=True, text=True, timeout=60, check=False
        )
    except FileNotFoundError:
        return 127, "kubectl not found"
    except subprocess.TimeoutExpired:
        return 124, "kubectl timed out"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def extract_constraint(output: str) -> str:
    match = _CONSTRAINT_RE.search(output)
    return match.group(1) if match else ""


def classify_negative(returncode: int, output: str) -> Outcome:
    """A negative manifest must be denied by the Gatekeeper webhook specifically."""
    if returncode == 0:
        return Outcome.UNEXPECTEDLY_ALLOWED
    if WEBHOOK_MARKER in output:
        return Outcome.POLICY_DENIED
    return Outcome.EXECUTION_ERROR


def classify_positive(returncode: int, output: str) -> Outcome:
    """A compliant manifest must be admitted; a webhook denial is a policy failure."""
    if returncode == 0:
        return Outcome.ALLOWED
    if WEBHOOK_MARKER in output:
        return Outcome.POSITIVE_REJECTED
    return Outcome.EXECUTION_ERROR


def summarize(negative: list[dict[str, Any]], positive: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    """Derives totals from the evaluated inventory, never from constants."""
    total = len(negative)
    blocked = sum(r["outcome"] == Outcome.POLICY_DENIED.value for r in negative)
    allowed = sum(r["outcome"] == Outcome.UNEXPECTEDLY_ALLOWED.value for r in negative)
    errors = sum(r["outcome"] == Outcome.EXECUTION_ERROR.value for r in negative + positive)
    positive_ok = sum(r["outcome"] == Outcome.ALLOWED.value for r in positive)
    positive_rejected = sum(r["outcome"] == Outcome.POSITIVE_REJECTED.value for r in positive)
    complete = total > 0 and bool(positive)
    passed = complete and blocked == total and positive_ok == len(positive) and errors == 0
    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "errors": errors,
        "enforcement_rate": round(blocked / total * 100.0, 1) if total else 0.0,
        "positive_total": len(positive),
        "positive_allowed": positive_ok,
        "positive_rejected": positive_rejected,
        "mode": mode,
        "evidence_mode": "live" if mode == "live_cluster_webhook" else "offline",
        "status": "PASS" if passed else "FAIL",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "run_id": uuid.uuid4().hex[:12],
        "negative_results": negative,
        "positive_results": positive,
    }


def run_live(negative_dir: Path, positive_dir: Path, runner: Runner = kubectl_runner) -> dict[str, Any]:
    negative = []
    for manifest in sorted(negative_dir.glob("*.yaml")):
        code, out = runner(["apply", "--dry-run=server", "-f", str(manifest)])
        outcome = classify_negative(code, out)
        negative.append({
            "manifest": manifest.name,
            "outcome": outcome.value,
            "exit_code": code,
            "constraint": extract_constraint(out) if outcome is Outcome.POLICY_DENIED else "",
            "detail": out[:500],
        })
    positive = []
    for manifest in sorted(positive_dir.glob("*.yaml")):
        code, out = runner(["apply", "--dry-run=server", "-f", str(manifest)])
        outcome = classify_positive(code, out)
        positive.append({
            "manifest": manifest.name,
            "outcome": outcome.value,
            "exit_code": code,
            "detail": "" if outcome is Outcome.ALLOWED else out[:500],
        })
    return summarize(negative, positive, "live_cluster_webhook")


def run_offline() -> dict[str, Any]:
    """Evaluates the Rego policies locally through OPA; no cluster webhook is involved."""
    from cloudnative_threatguard.admission.validator import validate_all

    report = validate_all()
    negative = [
        {
            "manifest": r.manifest,
            "outcome": (
                Outcome.POLICY_DENIED if r.blocked and r.message_matched_expected else Outcome.UNEXPECTEDLY_ALLOWED
            ).value,
            "constraint": r.policy_package,
            "detail": "; ".join(r.violation_messages)[:500],
        }
        for r in report.negative_results
    ]
    positive = [{
        "manifest": report.positive_manifest,
        "outcome": (Outcome.ALLOWED if report.positive_passed else Outcome.POSITIVE_REJECTED).value,
        "detail": "; ".join(report.positive_failures)[:500],
    }]
    return summarize(negative, positive, "opa_offline_evaluation")


def gatekeeper_is_live(runner: Runner = kubectl_runner) -> bool:
    code, _ = runner(["get", "crd", "constrainttemplates.templates.gatekeeper.sh"])
    return code == 0


def write_results(results: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")


def exit_code_for(results: dict[str, Any]) -> int:
    return EXIT_OK if results["status"] == "PASS" else EXIT_FAILED


def main(argv: list[str] | None = None, runner: Runner = kubectl_runner) -> int:
    parser = argparse.ArgumentParser(description="Admission enforcement verification")
    parser.add_argument("--mode", choices=["live", "offline"], default="live")
    parser.add_argument("--output", type=Path, default=settings.ARTIFACTS_ADMISSION_DIR / "admission-results.json")
    args = parser.parse_args(argv)

    if args.mode == "live":
        if not gatekeeper_is_live(runner):
            print(
                "[BLOCKED] Live Gatekeeper not reachable (kubectl or the Gatekeeper CRD is "
                "unavailable). Re-run with --mode offline to evaluate policies through OPA only.",
                file=sys.stderr,
            )
            return EXIT_BLOCKED
        manifests = settings.GATEKEEPER_TESTS_DIR / "manifests"
        results = run_live(manifests / "negative", manifests / "positive", runner)
    else:
        try:
            results = run_offline()
        except (FileNotFoundError, OSError) as exc:
            print(f"[BLOCKED] OPA is not available for offline evaluation: {exc}", file=sys.stderr)
            return EXIT_BLOCKED
        except RuntimeError as exc:
            print(f"[FAIL] OPA evaluation error: {exc}", file=sys.stderr)
            return EXIT_FAILED

    write_results(results, args.output)
    for item in results["negative_results"] + results["positive_results"]:
        print(f"  {item['manifest']:<36} {item['outcome']}")
    print(
        f"[{results['status']}] mode={results['mode']} denied={results['blocked']}/{results['total']} "
        f"unexpectedly_allowed={results['allowed']} errors={results['errors']} "
        f"positive_allowed={results['positive_allowed']}/{results['positive_total']}"
    )
    return exit_code_for(results)


if __name__ == "__main__":
    sys.exit(main())
