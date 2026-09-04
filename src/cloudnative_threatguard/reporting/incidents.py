"""
ThreatGuard Security Incident Management Engine.
Manages the end-to-end incident lifecycle (NEW -> TRIAGED -> INVESTIGATING -> CONTAINED -> RESOLVED),
attack chain reconstruction, and recommended containment actions.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from enum import Enum

from cloudnative_threatguard.runtime.events import SecurityEvent, SecurityIncident
from .risk import RiskScoringEngine


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentManager:
    """
    Stateful Incident Management Engine for CloudNative ThreatGuard.
    Tracks active security incidents, maintains audit trails of status updates,
    and enriches incidents with attack chain timelines and containment recommendations.

    The dict returned by ``create_incident_from_correlation`` (and stored in
    ``self.incidents``) is the canonical incident record schema for the whole
    package: ``incident_id``, ``title``, ``severity``, ``status``,
    ``affected_cluster``, ``affected_namespace``, ``affected_pod``,
    ``affected_container``, ``tactics``, ``techniques``, ``events``,
    ``timeline``, ``attack_chain``, ``risk_factors``, ``recommendations``,
    ``history``, and ``metadata``. Every consumer (the CLI, the evidence/
    report exporters) must read these exact keys.
    """
    def __init__(self, risk_engine: Optional[RiskScoringEngine] = None):
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.risk_engine = risk_engine or RiskScoringEngine()
        self.audit_log: List[Dict[str, Any]] = []

    def create_incident_from_correlation(
        self,
        correlated: SecurityIncident,
        workload_spec: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Creates and stores a managed security incident from a correlated incident object.
        """
        inc_id = correlated.incident_id
        events = [e.to_dict() if hasattr(e, "to_dict") else e for e in correlated.events]

        # Calculate chronological timeline and delta timestamps
        timeline = self._build_timeline(events)

        # Build attack chain graph
        attack_chain = self._build_attack_chain(events, correlated.tactics, correlated.techniques)

        # Generate actionable response recommendations
        recommendations = self._generate_recommendations(correlated.techniques, correlated.pod, correlated.namespace)

        # Evaluate risk score
        workload_ref = f"{correlated.namespace}/{correlated.pod}" if correlated.pod else correlated.namespace
        sec_events = []
        for e in correlated.events:
            if isinstance(e, SecurityEvent):
                sec_events.append(e)
            elif hasattr(e, "to_security_event"):
                sec_events.append(e.to_security_event())
            elif isinstance(e, dict):
                try:
                    sec_events.append(SecurityEvent(**e))
                except Exception:
                    pass

        risk_eval = self.risk_engine.evaluate_workload(
            events=sec_events,
            workload_ref=workload_ref,
            workload_spec=workload_spec
        )

        first_seen = timeline[0]["timestamp"] if timeline else correlated.created_at
        last_seen = timeline[-1]["timestamp"] if timeline else correlated.created_at

        incident_record = {
            "incident_id": inc_id,
            "title": correlated.title,
            "severity": correlated.severity,
            "risk_score": risk_eval.composite_risk_score,
            "risk_severity": risk_eval.risk_tier,
            "status": IncidentStatus.NEW.value,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "affected_cluster": correlated.cluster,
            "affected_namespace": correlated.namespace,
            "affected_pod": correlated.pod,
            "affected_container": correlated.container,
            "affected_node": "threatguard-local-control-plane",
            "tactics": correlated.tactics,
            "techniques": correlated.techniques,
            "event_count": len(events),
            "events": events,
            "timeline": timeline,
            "attack_chain": attack_chain,
            "risk_factors": [c.to_dict() for c in risk_eval.top_risk_contributors],
            "recommendations": recommendations,
            "history": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": "INCIDENT_CREATED",
                    "status": IncidentStatus.NEW.value,
                    "notes": f"Incident automatically correlated from {len(events)} security events."
                }
            ],
            "metadata": correlated.metadata
        }

        self.incidents[inc_id] = incident_record
        self._record_audit("CREATE_INCIDENT", inc_id, f"Created incident with severity {correlated.severity}")
        return incident_record

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self.incidents.get(incident_id)

    def get_incident_visualizations(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns JSON graph, Mermaid diagram, ASCII tree, and HTML snippet for an incident.
        """
        inc = self.get_incident(incident_id)
        if not inc:
            return None
        from .attack_chain import AttackChainVisualizer
        viz = AttackChainVisualizer(inc)
        return {
            "incident_id": incident_id,
            "json_graph": viz.to_json(),
            "mermaid": viz.to_mermaid(),
            "ascii": viz.to_ascii(),
            "html": viz.to_html_snippet()
        }

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        namespace: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        results = list(self.incidents.values())
        if status:
            results = [inc for inc in results if inc["status"].upper() == status.upper()]
        if severity:
            results = [inc for inc in results if inc["severity"].upper() == severity.upper()]
        if namespace:
            results = [inc for inc in results if inc["affected_namespace"] == namespace]
        return results

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        notes: str = "",
        actor: str = "security-analyst"
    ) -> Optional[Dict[str, Any]]:
        """
        Transition incident lifecycle status.
        """
        if incident_id not in self.incidents:
            return None

        # Validate status enum
        valid_statuses = [s.value for s in IncidentStatus]
        if new_status.upper() not in valid_statuses:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {valid_statuses}")

        inc = self.incidents[incident_id]
        old_status = inc["status"]
        inc["status"] = new_status.upper()
        history_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": f"STATUS_CHANGED_{old_status}_TO_{new_status.upper()}",
            "previous_status": old_status,
            "new_status": new_status.upper(),
            "notes": notes
        }
        inc["history"].append(history_entry)
        self._record_audit("UPDATE_INCIDENT_STATUS", incident_id, f"Status changed from {old_status} to {new_status.upper()} by {actor}")
        return inc

    def _build_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Produces an ordered event sequence with delta time annotations.
        """
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        timeline = []
        for idx, ev in enumerate(sorted_events):
            timeline.append({
                "step": idx + 1,
                "timestamp": ev.get("timestamp"),
                "event_id": ev.get("event_id"),
                "action": ev.get("action", "detected"),
                "process": ev.get("process", ""),
                "rule": ev.get("detection_rule", ""),
                "technique": ev.get("mitre_technique", ""),
                "tactic": ev.get("mitre_tactic", ""),
                "description": ev.get("description", ""),
                "severity": ev.get("severity", "MEDIUM")
            })
        return timeline

    def _build_attack_chain(
        self,
        events: List[Dict[str, Any]],
        tactics: List[str],
        techniques: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Constructs a structured directed attack-chain representation.
        """
        nodes = []
        for idx, ev in enumerate(events):
            nodes.append({
                "node_id": f"node-{idx+1}",
                "step": idx + 1,
                "tactic": ev.get("mitre_tactic") or "Unknown",
                "technique": ev.get("mitre_technique") or "Unknown",
                "label": ev.get("description") or ev.get("action", "Event"),
                "process": ev.get("process", ""),
                "severity": ev.get("severity", "MEDIUM"),
                "evidence": ev.get("metadata", {})
            })
        return nodes

    def _generate_recommendations(
        self,
        techniques: List[str],
        pod_name: str,
        namespace: str
    ) -> List[Dict[str, Any]]:
        """
        Generates non-destructive, actionable remediation guidance with dry-run kubectl commands.
        """
        from .recommendations import ResponseRecommendationEngine
        rec_engine = ResponseRecommendationEngine()
        recs = rec_engine.generate_recommendations(
            namespace=namespace,
            pod_name=pod_name,
            techniques=techniques,
            severity="CRITICAL" if any(t == "T1552.007" for t in techniques) else "HIGH"
        )
        return [r.to_dict() for r in recs]

    def _record_audit(self, action: str, resource_id: str, details: str):
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "resource_id": resource_id,
            "details": details
        })
