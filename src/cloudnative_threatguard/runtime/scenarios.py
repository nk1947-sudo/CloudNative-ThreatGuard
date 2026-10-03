"""
Scenario catalog and per-scenario outcome evaluation.

The catalog (``simulations/scenario_catalog.json``) is the single source of
truth for what a validation run plans to do: which scenarios exist, whether
they are required, the rule(s) each should trigger, and whether the sensor
policy is expected to block the process. Outcomes are evaluated per scenario
from that scenario's own evidence, so two scenarios sharing one rule remain
two checks and a skipped scenario never shrinks the planned denominator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudnative_threatguard.config import settings

CATALOG_PATH = settings.PROJECT_ROOT / "simulations" / "scenario_catalog.json"

STATUSES = ("passed", "failed", "blocked", "skipped", "not_run")
EXIT_KILLED = 137


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    script: str
    required: bool
    expected_rules: tuple[str, ...]
    expected_enforcement: str  # block | detect | none
    timeout_seconds: int = 30


@dataclass
class ScenarioRun:
    """What the orchestrator recorded about one scenario execution."""

    scenario_id: str
    status: str = "executed"  # executed | blocked | skipped
    exit_code: int | None = None
    started_at: str = ""
    ended_at: str = ""


@dataclass
class ScenarioOutcome:
    scenario_id: str
    name: str
    required: bool
    status: str
    expected_rules: list[str]
    detected_rules: list[str]
    expected_enforcement: str
    enforcement_observed: bool
    exit_code: int | None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "required": self.required,
            "status": self.status,
            "expected_rules": self.expected_rules,
            "detected_rules": self.detected_rules,
            "expected_enforcement": self.expected_enforcement,
            "enforcement_observed": self.enforcement_observed,
            "exit_code": self.exit_code,
            "reasons": self.reasons,
        }


def load_catalog(path: Path | None = None) -> list[Scenario]:
    data = json.loads((path or CATALOG_PATH).read_text(encoding="utf-8"))
    return [
        Scenario(
            id=item["id"],
            name=item["name"],
            script=item["script"],
            required=bool(item.get("required", True)),
            expected_rules=tuple(item.get("expected_rules", [])),
            expected_enforcement=item.get("expected_enforcement", "detect"),
            timeout_seconds=int(item.get("timeout_seconds", 30)),
        )
        for item in data["scenarios"]
    ]


def parse_results_file(path: Path) -> dict[str, ScenarioRun]:
    """Reads the orchestrator's tab-separated results: id, status, exit code, start, end."""
    runs: dict[str, ScenarioRun] = {}
    if not path.exists():
        return runs
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or not parts[0]:
            continue
        try:
            code = int(parts[2]) if parts[2] not in ("", "-") else None
        except ValueError:
            code = None
        runs[parts[0]] = ScenarioRun(parts[0], parts[1], code, parts[3], parts[4])
    return runs


def evaluate_scenario(
    scenario: Scenario,
    run: ScenarioRun | None,
    detected_rules: set[str],
    enforcement_seen: bool,
    check_exit_code: bool = True,
    events_seen: int | None = None,
) -> ScenarioOutcome:
    """
    Decides one scenario's outcome. ``check_exit_code`` is False for demo
    traces, where no process was executed and therefore no exit code exists.
    """
    outcome = ScenarioOutcome(
        scenario_id=scenario.id,
        name=scenario.name,
        required=scenario.required,
        status="not_run",
        expected_rules=list(scenario.expected_rules),
        detected_rules=sorted(detected_rules),
        expected_enforcement=scenario.expected_enforcement,
        enforcement_observed=enforcement_seen,
        exit_code=run.exit_code if run else None,
    )
    if run is None:
        outcome.reasons.append("scenario was planned but never executed")
        return outcome
    if run.status in ("blocked", "skipped"):
        outcome.status = run.status
        outcome.reasons.append(f"scenario {run.status} by the orchestrator")
        return outcome

    reasons = outcome.reasons
    if scenario.expected_enforcement == "block":
        if check_exit_code and run.exit_code != EXIT_KILLED:
            reasons.append(f"expected the process to be killed (exit 137), got {run.exit_code}")
        if not enforcement_seen:
            reasons.append("no kill evidence (SIGKILL) in the sensor events for this scenario")
    elif check_exit_code and run.exit_code == EXIT_KILLED:
        reasons.append("process was killed (exit 137) but this scenario does not expect enforcement")

    missing = sorted(set(scenario.expected_rules) - detected_rules)
    if missing:
        reasons.append(f"expected detection(s) not observed: {', '.join(missing)}")
    if not scenario.expected_rules:
        if detected_rules:
            reasons.append(f"false alert on benign control: {', '.join(sorted(detected_rules))}")
        elif events_seen == 0:
            # Silence only proves the detector is quiet if the sensor saw the command at all.
            reasons.append("no sensor events observed for the benign command; silence cannot be confirmed")

    outcome.status = "failed" if reasons else "passed"
    return outcome
