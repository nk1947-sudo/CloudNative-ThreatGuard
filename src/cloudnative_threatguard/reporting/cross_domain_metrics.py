"""
Cross-domain (CloudGraphGuard <-> ThreatGuard) metrics computation.

Turns a collection of persisted ``CrossDomainIncident`` objects into a
snapshot of real, derived counts. This exists specifically so the
Prometheus exporter never has to fabricate a number: if there are no
persisted cross-domain incidents yet, every value here is honestly zero.

Severities and statuses are small, fixed enums, so grouping by them keeps
label cardinality bounded (see observability/metrics_exporter.py) -- this
module never groups or labels by anything unbounded like an incident ID,
a principal ARN, or a workload name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cloudnative_threatguard.correlation.cross_domain.models.event import Severity
from cloudnative_threatguard.correlation.cross_domain.models.incident import (
    CrossDomainIncident,
    IncidentStatus,
    UnifiedIncidentManager,
)

_ALL_SEVERITIES = [s.value for s in Severity]
_HIGH_RISK_SEVERITIES = {Severity.HIGH.value, Severity.CRITICAL.value}


@dataclass
class CrossDomainMetricsSnapshot:
    # Counter semantics: every cross-domain incident ever recorded. Can only
    # grow (or reset to 0 if the persisted store itself is cleared) -- it
    # never decreases just because an incident's status changes.
    total_correlations: int = 0

    # Gauge semantics below: all reflect *current* state and can legitimately
    # go up or down as incidents are opened, resolved, or reclassified.
    open_incidents: int = 0
    exploitable_attack_paths: int = 0
    high_risk_principals: int = 0
    high_risk_workloads: int = 0
    sensitive_resources_exposed: int = 0
    iam_risks_by_severity: dict[str, int] = field(default_factory=lambda: dict.fromkeys(_ALL_SEVERITIES, 0))
    runtime_threats_by_severity: dict[str, int] = field(default_factory=lambda: dict.fromkeys(_ALL_SEVERITIES, 0))


def load_incidents(path: str | Path) -> list[CrossDomainIncident]:
    """Loads persisted cross-domain incidents, or an empty list if none exist yet."""
    return UnifiedIncidentManager.load(path).list_incidents()


def _is_cross_domain(incident: CrossDomainIncident) -> bool:
    iam_count = incident.evidence_summary.get("iam_events_count", 0)
    runtime_count = incident.evidence_summary.get("runtime_events_count", 0)
    admission_count = incident.evidence_summary.get("admission_events_count", 0)
    return iam_count > 0 and (runtime_count > 0 or admission_count > 0)


def compute_snapshot(incidents: list[CrossDomainIncident]) -> CrossDomainMetricsSnapshot:
    """
    Derives real metric values from actual incident objects. Every field is
    computed from the incidents passed in -- nothing here is a constant.
    """
    snapshot = CrossDomainMetricsSnapshot(total_correlations=len(incidents))

    open_incidents = [i for i in incidents if i.status != IncidentStatus.RESOLVED]
    snapshot.open_incidents = len(open_incidents)
    snapshot.exploitable_attack_paths = sum(1 for i in open_incidents if _is_cross_domain(i))

    high_risk_open = [i for i in open_incidents if i.severity.value in _HIGH_RISK_SEVERITIES]
    principals = {
        i.cloud_context.get("principal") or i.cloud_context.get("role")
        for i in high_risk_open
        if i.cloud_context.get("principal") or i.cloud_context.get("role")
    }
    workloads = {i.k8s_context.get("workload") for i in high_risk_open if i.k8s_context.get("workload")}
    snapshot.high_risk_principals = len(principals)
    snapshot.high_risk_workloads = len(workloads)

    resources = {
        proposal.target
        for i in open_incidents
        for proposal in i.remediation_proposals
        if proposal.target
    }
    snapshot.sensitive_resources_exposed = len(resources)

    for i in incidents:
        sev = i.severity.value
        iam_count = i.evidence_summary.get("iam_events_count", 0)
        runtime_count = i.evidence_summary.get("runtime_events_count", 0)
        if iam_count > 0:
            snapshot.iam_risks_by_severity[sev] = snapshot.iam_risks_by_severity.get(sev, 0) + iam_count
        if runtime_count > 0:
            snapshot.runtime_threats_by_severity[sev] = snapshot.runtime_threats_by_severity.get(sev, 0) + runtime_count

    return snapshot
