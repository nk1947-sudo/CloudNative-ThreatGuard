"""
Cross-Domain Unified Security Incident Model and Lifecycle Manager.
Unifies CloudGraphGuard IAM compromise evidence with ThreatGuard runtime detection evidence.
Maintains separate remediation proposals for Cloud IAM and Kubernetes domains (dry-run only).
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, ConfigDict

from .event import Severity
from cloudnative_threatguard.correlation.cross_domain.engine.correlation_engine import CorrelatedCluster


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

    attack_chain: List[str] = Field(
        default_factory=list,
        description="Linear high-level attack progression (e.g. developer -> role -> EKS -> pod -> secret)"
    )
    source_event_ids: List[str] = Field(
        default_factory=list,
        description="IDs of all supporting UnifiedSecurityEvents"
    )
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    cloud_context: Dict[str, Any] = Field(default_factory=dict)
    k8s_context: Dict[str, Any] = Field(default_factory=dict)
    remediation_proposals: List[RemediationProposal] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class UnifiedIncidentManager:
    """
    State manager for cross-domain security incidents.
    """

    def __init__(self):
        self._incidents: Dict[str, CrossDomainIncident] = {}

    def create_from_cluster(self, cluster: CorrelatedCluster) -> CrossDomainIncident:
        chain = cluster.attack_chain
        risk = chain.composite_risk if chain else 75.0

        sev = Severity.HIGH
        if risk >= 85.0:
            sev = Severity.CRITICAL
        elif risk < 50.0:
            sev = Severity.MEDIUM

        # Build linear chain representation
        chain_steps: List[str] = []
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
        remediations: List[RemediationProposal] = []
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

        self._incidents[incident.incident_id] = incident
        return incident

    def get_incident(self, incident_id: str) -> Optional[CrossDomainIncident]:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: Optional[IncidentStatus] = None) -> List[CrossDomainIncident]:
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
