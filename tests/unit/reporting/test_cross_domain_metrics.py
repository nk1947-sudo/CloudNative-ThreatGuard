"""
Unit tests proving cross-domain metrics are derived from actual incident
state, not hardcoded -- the exact bug this module fixes.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.models.event import EventSource, EventType, Severity
from cloudnative_threatguard.correlation.cross_domain.models.incident import (
    ContributingFinding,
    CrossDomainIncident,
    IncidentStatus,
    RemediationProposal,
)
from cloudnative_threatguard.reporting.cross_domain_metrics import compute_snapshot


def _make_finding(source, event_type, severity, event_id="USE-TEST") -> ContributingFinding:
    return ContributingFinding(event_id=event_id, source=source, event_type=event_type, severity=severity)


def _make_incident(
    severity=Severity.HIGH,
    status=IncidentStatus.NEW,
    iam_events=1,
    runtime_events=1,
    admission_events=0,
    principal=None,
    workload=None,
    remediation_targets=None,
    contributing_findings=None,
) -> CrossDomainIncident:
    cloud_context = {"principal": principal} if principal else {}
    k8s_context = {"workload": workload} if workload else {}
    remediation_proposals = [
        RemediationProposal(
            domain="KUBERNETES_RUNTIME",
            title="t",
            target=target,
            action="a",
            dry_run_command="echo noop",
            rationale="r",
        )
        for target in (remediation_targets or [])
    ]
    if contributing_findings is None:
        # Default: every source finding mirrors the incident's own severity,
        # matching the pre-fix behavior that callers not exercising per-event
        # severity explicitly still expect.
        contributing_findings = (
            [_make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, severity, f"USE-IAM-{i}") for i in range(iam_events)]
            + [_make_finding(EventSource.THREATGUARD, EventType.RUNTIME_DETECTION, severity, f"USE-RT-{i}") for i in range(runtime_events)]
            + [_make_finding(EventSource.THREATGUARD, EventType.ADMISSION_VIOLATION, severity, f"USE-ADM-{i}") for i in range(admission_events)]
        )
    return CrossDomainIncident(
        title="Test Incident",
        severity=severity,
        status=status,
        risk_score=80.0,
        evidence_summary={
            "iam_events_count": iam_events,
            "runtime_events_count": runtime_events,
            "admission_events_count": admission_events,
        },
        contributing_findings=contributing_findings,
        cloud_context=cloud_context,
        k8s_context=k8s_context,
        remediation_proposals=remediation_proposals,
    )


class TestCrossDomainMetricsSnapshot(unittest.TestCase):
    def test_zero_incidents_yields_all_zero_metrics(self):
        snapshot = compute_snapshot([])
        self.assertEqual(snapshot.total_correlations, 0)
        self.assertEqual(snapshot.open_incidents, 0)
        self.assertEqual(snapshot.exploitable_attack_paths, 0)
        self.assertEqual(snapshot.high_risk_principals, 0)
        self.assertEqual(snapshot.high_risk_workloads, 0)
        self.assertEqual(snapshot.sensitive_resources_exposed, 0)
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 0)
        self.assertEqual(snapshot.runtime_threats_by_severity["critical"], 0)

    def test_adding_one_incident_increments_metrics(self):
        incident = _make_incident(
            severity=Severity.CRITICAL,
            principal="arn:aws:iam::123456789012:user/developer",
            workload="threatguard-target-pod",
            remediation_targets=["threatguard/threatguard-target-pod"],
        )
        snapshot = compute_snapshot([incident])

        self.assertEqual(snapshot.total_correlations, 1)
        self.assertEqual(snapshot.open_incidents, 1)
        self.assertEqual(snapshot.exploitable_attack_paths, 1)
        self.assertEqual(snapshot.high_risk_principals, 1)
        self.assertEqual(snapshot.high_risk_workloads, 1)
        self.assertEqual(snapshot.sensitive_resources_exposed, 1)
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 1)
        self.assertEqual(snapshot.runtime_threats_by_severity["critical"], 1)

    def test_adding_a_second_incident_increases_counts_further(self):
        first = _make_incident(severity=Severity.CRITICAL, principal="arn:.../developer", workload="pod-a")
        second = _make_incident(severity=Severity.HIGH, principal="arn:.../other-user", workload="pod-b")

        snapshot = compute_snapshot([first, second])
        self.assertEqual(snapshot.total_correlations, 2)
        self.assertEqual(snapshot.open_incidents, 2)
        self.assertEqual(snapshot.high_risk_principals, 2)
        self.assertEqual(snapshot.high_risk_workloads, 2)
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 1)
        self.assertEqual(snapshot.iam_risks_by_severity["high"], 1)

    def test_resolving_an_incident_drops_it_from_gauges_but_not_the_counter(self):
        open_incident = _make_incident(severity=Severity.CRITICAL, status=IncidentStatus.NEW, workload="pod-a")
        resolved_incident = _make_incident(severity=Severity.CRITICAL, status=IncidentStatus.RESOLVED, workload="pod-b")

        snapshot = compute_snapshot([open_incident, resolved_incident])

        # Counter: reflects everything ever recorded, resolved or not.
        self.assertEqual(snapshot.total_correlations, 2)
        # Gauges: only the still-open incident counts.
        self.assertEqual(snapshot.open_incidents, 1)
        self.assertEqual(snapshot.exploitable_attack_paths, 1)
        self.assertEqual(snapshot.high_risk_workloads, 1)

    def test_duplicate_principal_across_incidents_is_not_double_counted(self):
        first = _make_incident(severity=Severity.CRITICAL, principal="arn:.../developer", workload="pod-a")
        second = _make_incident(severity=Severity.HIGH, principal="arn:.../developer", workload="pod-b")
        snapshot = compute_snapshot([first, second])
        self.assertEqual(snapshot.high_risk_principals, 1)  # same principal, counted once
        self.assertEqual(snapshot.high_risk_workloads, 2)  # different workloads

    def test_low_severity_incident_does_not_count_as_high_risk(self):
        incident = _make_incident(severity=Severity.LOW, principal="arn:.../dev", workload="pod-a")
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.high_risk_principals, 0)
        self.assertEqual(snapshot.high_risk_workloads, 0)
        # But it still counts toward the plain incident/severity ledgers.
        self.assertEqual(snapshot.total_correlations, 1)
        self.assertEqual(snapshot.iam_risks_by_severity["low"], 1)

    def test_iam_only_incident_is_not_an_exploitable_attack_path(self):
        """An incident with only IAM events (no runtime/admission evidence)
        never crossed into Kubernetes, so it isn't a realized cross-domain path."""
        incident = _make_incident(iam_events=1, runtime_events=0, admission_events=0)
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.exploitable_attack_paths, 0)

    def test_admission_plus_iam_counts_as_exploitable_attack_path(self):
        incident = _make_incident(iam_events=1, runtime_events=0, admission_events=1)
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.exploitable_attack_paths, 1)


class TestPerFindingSeverityGranularity(unittest.TestCase):
    """
    Regression guards for the fix that buckets `iam_risks_by_severity` /
    `runtime_threats_by_severity` by each *source finding's own* severity,
    not the incident's overall (correlated) severity.
    """

    def test_source_finding_severity_is_preserved_independently_of_incident_severity(self):
        """
        Incident severity is HIGH, but its three IAM findings are
        LOW/MEDIUM/HIGH individually. Before this fix, all three would have
        been counted under "high" because bucketing used the incident's
        aggregated severity instead of each finding's own.
        """
        incident = _make_incident(
            severity=Severity.HIGH,
            iam_events=0,
            runtime_events=0,
            contributing_findings=[
                _make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, Severity.LOW, "USE-1"),
                _make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, Severity.MEDIUM, "USE-2"),
                _make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, Severity.HIGH, "USE-3"),
            ],
        )
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.iam_risks_by_severity["low"], 1)
        self.assertEqual(snapshot.iam_risks_by_severity["medium"], 1)
        self.assertEqual(snapshot.iam_risks_by_severity["high"], 1)
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 0)

    def test_multiple_source_events_across_both_domains_bucket_independently(self):
        incident = _make_incident(
            severity=Severity.CRITICAL,
            iam_events=0,
            runtime_events=0,
            contributing_findings=[
                _make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, Severity.HIGH, "USE-1"),
                _make_finding(EventSource.CLOUDGRAPHGUARD, EventType.IAM_RISK, Severity.HIGH, "USE-2"),
                _make_finding(EventSource.THREATGUARD, EventType.RUNTIME_DETECTION, Severity.CRITICAL, "USE-3"),
                _make_finding(EventSource.THREATGUARD, EventType.RUNTIME_DETECTION, Severity.LOW, "USE-4"),
            ],
        )
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.iam_risks_by_severity["high"], 2)
        self.assertEqual(snapshot.runtime_threats_by_severity["critical"], 1)
        self.assertEqual(snapshot.runtime_threats_by_severity["low"], 1)

    def test_admission_domain_findings_are_excluded_from_iam_and_runtime_buckets(self):
        """
        Admission-violation findings (Gatekeeper policy denials) are a third
        domain, tracked separately via evidence_summary's admission count --
        they must not silently inflate either the IAM or the Kubernetes
        runtime severity metric.
        """
        incident = _make_incident(
            severity=Severity.HIGH,
            iam_events=0,
            runtime_events=0,
            admission_events=0,
            contributing_findings=[
                _make_finding(EventSource.THREATGUARD, EventType.ADMISSION_VIOLATION, Severity.CRITICAL, "USE-1"),
            ],
        )
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 0)
        self.assertEqual(snapshot.runtime_threats_by_severity["critical"], 0)

    def test_incident_with_no_contributing_findings_contributes_zero_to_severity_metrics(self):
        """
        Backward compatibility: an incident persisted before this field
        existed (or one with a legitimately empty findings list) must not
        crash the exporter and must not fall back to bucketing by
        incident-level severity -- that would silently reintroduce the bug.
        """
        incident = _make_incident(severity=Severity.CRITICAL, iam_events=2, runtime_events=1, contributing_findings=[])
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.iam_risks_by_severity["critical"], 0)
        self.assertEqual(snapshot.runtime_threats_by_severity["critical"], 0)
        # The rest of the snapshot is still derived normally from evidence_summary.
        self.assertEqual(snapshot.total_correlations, 1)

    def test_unknown_finding_severity_is_counted_defensively_not_dropped_or_crashed(self):
        """
        Severity is normally a validated enum, so this can only arise from a
        finding built outside normal validation (e.g. a future looser
        producer). The snapshot must not crash, per the same defensive
        dict.get(..., 0) semantics already used for every other bucket here.
        """
        odd_finding = ContributingFinding.model_construct(
            event_id="USE-ODD",
            source=EventSource.CLOUDGRAPHGUARD,
            event_type=EventType.IAM_RISK,
            severity="unknown",
        )
        incident = _make_incident(
            severity=Severity.HIGH, iam_events=0, runtime_events=0, contributing_findings=[odd_finding]
        )
        snapshot = compute_snapshot([incident])
        self.assertEqual(snapshot.iam_risks_by_severity.get("unknown"), 1)
        self.assertEqual(snapshot.iam_risks_by_severity["high"], 0)


if __name__ == "__main__":
    unittest.main()
