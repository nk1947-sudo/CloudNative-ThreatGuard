"""
Unit tests proving cross-domain metrics are derived from actual incident
state, not hardcoded -- the exact bug this module fixes.
"""

import unittest

from cloudnative_threatguard.correlation.cross_domain.models.event import Severity
from cloudnative_threatguard.correlation.cross_domain.models.incident import (
    CrossDomainIncident,
    IncidentStatus,
    RemediationProposal,
)
from cloudnative_threatguard.reporting.cross_domain_metrics import compute_snapshot


def _make_incident(
    severity=Severity.HIGH,
    status=IncidentStatus.NEW,
    iam_events=1,
    runtime_events=1,
    admission_events=0,
    principal=None,
    workload=None,
    remediation_targets=None,
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


if __name__ == "__main__":
    unittest.main()
