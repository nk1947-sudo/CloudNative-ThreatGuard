"""
Cross-Domain Security Event Correlation Engine.
Correlates CloudGraphGuard IAM identity risks with ThreatGuard Kubernetes runtime detections,
building unified multi-stage attack chains across the cloud-to-container boundary.
"""

from typing import List, Dict, Any, Optional, Set
import uuid
from pydantic import BaseModel, Field

from cloudnative_threatguard.correlation.cross_domain.models.event import UnifiedSecurityEvent, EventSource, EventType
from cloudnative_threatguard.correlation.cross_domain.models.mapping import IdentityMappingRegistry, IdentityBinding


class CorrelatedAttackChain(BaseModel):
    chain_id: str = Field(default_factory=lambda: f"CHAIN-{uuid.uuid4().hex[:8].upper()}")
    title: str
    cloud_principal: Optional[str] = None
    cloud_role: Optional[str] = None
    kubernetes_cluster: Optional[str] = None
    kubernetes_workload: Optional[str] = None
    kubernetes_pod: Optional[str] = None
    service_account: Optional[str] = None
    stages: List[Dict[str, Any]] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    composite_risk: float = 0.0
    is_cross_domain: bool = False


class CorrelatedCluster(BaseModel):
    cluster_id: str = Field(default_factory=lambda: f"CLUS-{uuid.uuid4().hex[:8].upper()}")
    binding: Optional[IdentityBinding] = None
    iam_events: List[UnifiedSecurityEvent] = Field(default_factory=list)
    runtime_events: List[UnifiedSecurityEvent] = Field(default_factory=list)
    admission_events: List[UnifiedSecurityEvent] = Field(default_factory=list)
    attack_chain: Optional[CorrelatedAttackChain] = None


class CrossDomainCorrelationEngine:
    """
    Ingests normalized events from both CloudGraphGuard and ThreatGuard,
    resolving relationships through the IdentityMappingRegistry.
    """

    def __init__(self, mapping_registry: Optional[IdentityMappingRegistry] = None):
        self.mapping_registry = mapping_registry or IdentityMappingRegistry()
        self._events: List[UnifiedSecurityEvent] = []
        self._seen_event_ids: Set[str] = set()

    def ingest_event(self, event: UnifiedSecurityEvent) -> bool:
        """Ingest event with automatic deduplication."""
        if event.event_id in self._seen_event_ids:
            return False
        self._seen_event_ids.add(event.event_id)
        self._events.append(event)
        return True

    def ingest_events(self, events: List[UnifiedSecurityEvent]) -> int:
        count = 0
        for e in events:
            if self.ingest_event(e):
                count += 1
        return count

    def correlate(self) -> List[CorrelatedCluster]:
        """
        Groups events into cross-domain clusters and builds causal attack chains.
        """
        clusters: List[CorrelatedCluster] = []
        registered_bindings = self.mapping_registry.get_all()

        # Index events by domain attributes
        iam_by_role: Dict[str, List[UnifiedSecurityEvent]] = {}
        runtime_by_workload: Dict[str, List[UnifiedSecurityEvent]] = {}
        admission_by_workload: Dict[str, List[UnifiedSecurityEvent]] = {}

        for ev in self._events:
            if ev.source == EventSource.CLOUDGRAPHGUARD:
                key = (ev.role_arn or ev.principal_arn or ev.principal_id or "").lower()
                iam_by_role.setdefault(key, []).append(ev)
            elif ev.source == EventSource.THREATGUARD:
                key = (ev.workload or ev.pod or "").lower()
                if ev.event_type == EventType.ADMISSION_VIOLATION:
                    admission_by_workload.setdefault(key, []).append(ev)
                else:
                    runtime_by_workload.setdefault(key, []).append(ev)

        # 1. Correlate using explicit Identity Bindings
        matched_binding_ids: Set[str] = set()
        for binding in registered_bindings:
            role_key = binding.cloud_identity.lower()
            workload_key = (binding.workload or "").lower()

            matched_iam = iam_by_role.get(role_key, [])
            matched_runtime = runtime_by_workload.get(workload_key, [])
            matched_admission = admission_by_workload.get(workload_key, [])

            if matched_iam or matched_runtime or matched_admission:
                cluster = CorrelatedCluster(
                    binding=binding,
                    iam_events=matched_iam,
                    runtime_events=matched_runtime,
                    admission_events=matched_admission,
                )
                cluster.attack_chain = self._build_attack_chain(cluster)
                clusters.append(cluster)
                matched_binding_ids.add(binding.binding_id)

        # 2. Correlate unmapped runtime events by workload
        for wk, r_events in runtime_by_workload.items():
            if not any(c.binding and (c.binding.workload or "").lower() == wk for c in clusters):
                adm_events = admission_by_workload.get(wk, [])
                cluster = CorrelatedCluster(
                    binding=None,
                    iam_events=[],
                    runtime_events=r_events,
                    admission_events=adm_events,
                )
                cluster.attack_chain = self._build_attack_chain(cluster)
                clusters.append(cluster)

        return clusters

    def _build_attack_chain(self, cluster: CorrelatedCluster) -> CorrelatedAttackChain:
        stages: List[Dict[str, Any]] = []
        event_ids: List[str] = []
        scores: List[float] = []

        binding = cluster.binding
        principal = None
        role = None
        workload = None
        cluster_name = None

        if binding:
            role = binding.cloud_identity
            workload = binding.workload
            cluster_name = binding.cluster

        # Stage 1: Cloud IAM privilege escalation or high-risk activity
        for ev in cluster.iam_events:
            event_ids.append(ev.event_id)
            scores.append(ev.risk_score)
            if not principal and ev.principal_arn:
                principal = ev.principal_arn
            stages.append({
                "step": len(stages) + 1,
                "domain": "CLOUD_IAM",
                "event_id": ev.event_id,
                "action": ev.action or "IAM Access",
                "entity": ev.principal_arn or ev.principal_id,
                "description": ev.description,
                "severity": ev.severity,
            })

        # Stage 2: Cloud Access to EKS Transition (if binding exists and IAM events present)
        if binding and cluster.iam_events and (cluster.runtime_events or cluster.admission_events):
            stages.append({
                "step": len(stages) + 1,
                "domain": "EKS_ACCESS_TRANSITION",
                "mechanism": binding.mapping_mechanism,
                "entity": f"{binding.cloud_identity} -> {binding.namespace}/{binding.service_account}",
                "description": f"Cloud IAM identity assumed access to Kubernetes ServiceAccount via {binding.mapping_mechanism}",
                "severity": "high",
            })

        # Stage 3: Admission violations (if any)
        for ev in cluster.admission_events:
            event_ids.append(ev.event_id)
            scores.append(ev.risk_score)
            stages.append({
                "step": len(stages) + 1,
                "domain": "K8S_ADMISSION",
                "event_id": ev.event_id,
                "action": ev.action or "admission_blocked",
                "entity": ev.pod or ev.workload,
                "description": ev.description,
                "severity": ev.severity,
            })

        # Stage 4: Runtime activity (sorted chronologically)
        sorted_runtime = sorted(cluster.runtime_events, key=lambda x: x.timestamp)
        for ev in sorted_runtime:
            event_ids.append(ev.event_id)
            scores.append(ev.risk_score)
            if not workload and ev.workload:
                workload = ev.workload
            stages.append({
                "step": len(stages) + 1,
                "domain": "K8S_RUNTIME",
                "event_id": ev.event_id,
                "action": ev.action or "runtime_activity",
                "entity": ev.pod or ev.workload,
                "description": ev.description,
                "severity": ev.severity,
            })

        is_cross = bool(cluster.iam_events and (cluster.runtime_events or cluster.admission_events))
        composite = max(scores) if scores else 0.0
        if is_cross and len(stages) >= 3:
            # Cross-domain multi-stage kill chain amplifier
            composite = min(100.0, composite + 5.0)

        title = "Multi-Stage Cross-Domain Attack Chain" if is_cross else "Kubernetes Workload Security Threat"

        return CorrelatedAttackChain(
            title=title,
            cloud_principal=principal,
            cloud_role=role,
            kubernetes_cluster=cluster_name,
            kubernetes_workload=workload,
            kubernetes_pod=cluster.runtime_events[0].pod if cluster.runtime_events else None,
            service_account=binding.service_account if binding else None,
            stages=stages,
            event_ids=event_ids,
            composite_risk=round(composite, 1),
            is_cross_domain=is_cross,
        )
