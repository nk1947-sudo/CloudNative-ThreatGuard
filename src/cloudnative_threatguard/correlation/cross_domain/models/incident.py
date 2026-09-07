"""
Cross-Domain Unified Security Incident Model and Lifecycle Manager.
Unifies CloudGraphGuard IAM compromise evidence with ThreatGuard runtime detection evidence.
Maintains separate remediation proposals for Cloud IAM and Kubernetes domains (dry-run only).
"""

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import CorrelatedCluster

from .event import Severity


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class RemediationProposal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    domain: str  # "CLOUD_IAM", "KUBERNETES_RBAC", "KUBERNETES_RUNTIME", "KUBERNETES_NETWORK"
    title: str
    target: str
    action: str
    dry_run_command: str
    rationale: str
    is_dry_run_only: bool = True


class CrossDomainIncident(BaseModel):
    """
    Unified incident correlating cloud identity risks with Kubernetes workload exploit telemetry.
    """
    model_config = ConfigDict(populate_by_name=True)

    incident_id: str = Field(default_factory=lambda: f"CDI-{uuid.uuid4().hex[:6].upper()}")
    title: str
    severity: Severity
    status: IncidentStatus = IncidentStatus.NEW
    risk_score: float = Field(ge=0.0, le=100.0)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    attack_chain: list[str] = Field(
        default_factory=list,
        description="Linear high-level attack progression (e.g. developer -> role -> EKS -> pod -> secret)"
    )
    source_event_ids: list[str] = Field(
        default_factory=list,
        description="IDs of all supporting UnifiedSecurityEvents"
    )
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    cloud_context: dict[str, Any] = Field(default_factory=dict)
    k8s_context: dict[str, Any] = Field(default_factory=dict)
    remediation_proposals: list[RemediationProposal] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class UnifiedIncidentManager:
    """
    State manager for cross-domain security incidents.
    """

    def __init__(self):
        self._incidents: dict[str, CrossDomainIncident] = {}

    def create_from_cluster(self, cluster: CorrelatedCluster) -> CrossDomainIncident:
        chain = cluster.attack_chain
        risk = chain.composite_risk if chain else 75.0

        sev = Severity.HIGH
        if risk >= 85.0:
            sev = Severity.CRITICAL
        elif risk < 50.0:
            sev = Severity.MEDIUM

        # Build linear chain representation
        chain_steps: list[str] = []
        if chain and chain.cloud_principal:
            chain_steps.append(chain.cloud_principal.split("/")[-1])
        if chain and chain.cloud_role:
            chain_steps.append(chain.cloud_role.split("/")[-1])
        if chain and chain.kubernetes_cluster:
            chain_steps.append("EKS")
        if chain and chain.service_account:
            chain_steps.append(chain.service_account)
        if chain and chain.kubernetes_workload:
            chain_steps.append(chain.kubernetes_workload)

        # Append runtime actions
        if chain:
            for st in chain.stages:
                if st.get("domain") == "K8S_RUNTIME":
                    act = st.get("action", "")
                    clean_act = act.split(":")[-1] if ":" in act else act
                    if clean_act not in chain_steps:
                        chain_steps.append(clean_act)

        # Source event IDs
        ev_ids = [ev.event_id for ev in cluster.iam_events + cluster.runtime_events + cluster.admission_events]

        # Cloud and K8s contexts
        cloud_ctx = {}
        if cluster.binding:
            cloud_ctx = {
                "provider": cluster.binding.cloud_provider,
                "role": cluster.binding.cloud_identity,
                "mechanism": cluster.binding.mapping_mechanism,
            }
        if cluster.iam_events and cluster.iam_events[0].principal_arn:
            cloud_ctx["principal"] = cluster.iam_events[0].principal_arn

        k8s_ctx = {}
        if cluster.binding:
            k8s_ctx = {
                "cluster": cluster.binding.cluster,
                "namespace": cluster.binding.namespace,
                "workload": cluster.binding.workload,
                "service_account": cluster.binding.service_account,
            }

        # Remediation proposals (Dual-track)
        remediations: list[RemediationProposal] = []
        # Track 1: Cloud IAM
        if cluster.iam_events:
            for ev in cluster.iam_events:
                if ev.action and "PassRole" in ev.action:
                    remediations.append(
                        RemediationProposal(
                            domain="CLOUD_IAM",
                            title="Constrain IAM PassRole Delegation",
                            target=ev.principal_arn or "IAM Principal",
                            action="Remove wildcard iam:PassRole and restrict to explicit resource ARNs",
                            dry_run_command="aws iam get-user-policy --user-name <name> --policy-name <policy>",
                            rationale="Prevents arbitrary privilege escalation into compute service roles.",
                        )
                    )
                    break
            if not remediations:
                remediations.append(
                    RemediationProposal(
                        domain="CLOUD_IAM",
                        title="Enforce Least Privilege IAM Boundary",
                        target=cloud_ctx.get("role", "Target Role"),
                        action="Apply permission boundary limiting administrative API actions",
                        dry_run_command="aws iam put-role-permissions-boundary --role-name <name> --permissions-boundary <arn>",
                        rationale="Restricts blast radius of assumed cloud roles.",
                    )
                )

        # Track 2: Kubernetes Workload & Runtime
        if cluster.runtime_events:
            target_pod = cluster.runtime_events[0].pod or "target-pod"
            ns = cluster.binding.namespace if cluster.binding else "threatguard"
            remediations.append(
                RemediationProposal(
                    domain="KUBERNETES_RUNTIME",
                    title="Isolate Compromised Pod via NetworkPolicy",
                    target=f"{ns}/{target_pod}",
                    action="Apply zero-trust default-deny NetworkPolicy isolating workload egress",
                    dry_run_command=f"kubectl label pod {target_pod} -n {ns} security.threatguard.io/quarantine=true --dry-run=client",
                    rationale="Halts lateral movement and token exfiltration immediately.",
                )
            )

        title = "Potential Cloud Identity to Kubernetes Credential Compromise" if cluster.iam_events and cluster.runtime_events else "Kubernetes Security Threat Incident"

        incident = CrossDomainIncident(
            title=title,
            severity=sev,
            status=IncidentStatus.NEW,
            risk_score=risk,
            attack_chain=chain_steps,
            source_event_ids=ev_ids,
            evidence_summary={
                "iam_events_count": len(cluster.iam_events),
                "runtime_events_count": len(cluster.runtime_events),
                "admission_events_count": len(cluster.admission_events),
            },
            cloud_context=cloud_ctx,
            k8s_context=k8s_ctx,
            remediation_proposals=remediations,
        )

        self.register(incident)
        return incident

    def register(self, incident: CrossDomainIncident) -> None:
        """Adds an already-built incident (e.g. one reloaded via ``load()``) to this manager."""
        self._incidents[incident.incident_id] = incident

    def get_incident(self, incident_id: str) -> CrossDomainIncident | None:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: IncidentStatus | None = None) -> list[CrossDomainIncident]:
        if status:
            return [i for i in self._incidents.values() if i.status == status]
        return list(self._incidents.values())

    def update_status(self, incident_id: str, new_status: IncidentStatus) -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.status = new_status
        inc.updated_at = datetime.now(timezone.utc).isoformat()
        return True

    def to_dict(self) -> dict[str, Any]:
        return {"incidents": [i.model_dump(mode="json") for i in self._incidents.values()]}

    def save(self, path: str | Path) -> None:
        """
        Persists all tracked incidents to a JSON file. This is what lets a
        separate, long-running process (the Prometheus metrics exporter)
        observe incident state produced by another process (the cross-domain
        demo, or a future live pipeline) -- the two do not share memory.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "UnifiedIncidentManager":
        """
        Loads a previously saved incident collection. Returns an empty
        manager (not an error) if the file doesn't exist yet -- "no
        cross-domain incidents have been recorded" is a legitimate, honest
        state, not a failure.
        """
        manager = cls()
        path = Path(path)
        if not path.exists():
            return manager
        data = json.loads(path.read_text(encoding="utf-8"))
        for raw in data.get("incidents", []):
            incident = CrossDomainIncident(**raw)
            manager.register(incident)
        return manager
