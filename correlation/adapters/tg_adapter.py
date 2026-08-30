"""
ThreatGuard Event Adapter.
Converts ThreatGuard admission violations, runtime eBPF detections,
and attack simulations into normalized UnifiedSecurityEvents.
"""

from typing import Union, Dict, Any, List, Optional
import re
from correlation.models.event import (
    UnifiedSecurityEvent,
    EventSource,
    EventType,
    CloudProvider,
    Severity,
)
from runtime.engine.models import SecurityEvent, SecurityEventType


class ThreatGuardAdapter:
    """
    Translates ThreatGuard Kubernetes security events into the platform-wide normalized event format.
    """

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.LOW,
    }

    SEVERITY_SCORE_MAP = {
        Severity.CRITICAL: 90.0,
        Severity.HIGH: 75.0,
        Severity.MEDIUM: 50.0,
        Severity.LOW: 25.0,
    }

    EVENT_TYPE_MAP = {
        SecurityEventType.RUNTIME_DETECTION.value: EventType.RUNTIME_DETECTION,
        SecurityEventType.ADMISSION_VIOLATION.value: EventType.ADMISSION_VIOLATION,
        SecurityEventType.NETWORK_ANOMALY.value: EventType.NETWORK_DETECTION,
        SecurityEventType.POLICY_VIOLATION.value: EventType.ADMISSION_VIOLATION,
        SecurityEventType.ATTACK_SIMULATION.value: EventType.ATTACK_SIMULATION,
        SecurityEventType.INCIDENT.value: EventType.INCIDENT,
    }

    @staticmethod
    def _infer_workload_name(pod_name: Optional[str], metadata: Dict[str, Any]) -> Optional[str]:
        if not pod_name and not metadata:
            return None
        if "workload" in metadata:
            return str(metadata["workload"])
        if pod_name:
            # Common k8s suffixes: -[replicaset-hash]-[pod-hash] or -[job-hash]
            clean = re.sub(r"-[0-9a-f]{5,10}-[a-z0-9]{5}$", "", pod_name)
            clean = re.sub(r"-[a-z0-9]{5}$", "", clean)
            return clean
        return None

    @classmethod
    def to_unified_event(cls, event: Union[SecurityEvent, Dict[str, Any]]) -> UnifiedSecurityEvent:
        if isinstance(event, dict):
            event_obj = SecurityEvent.from_dict(event)
        else:
            event_obj = event

        # Map event type
        ev_type_str = str(event_obj.event_type).lower()
        ev_type = cls.EVENT_TYPE_MAP.get(ev_type_str, EventType.RUNTIME_DETECTION)

        # Map severity
        sev_str = str(event_obj.severity).lower()
        sev = cls.SEVERITY_MAP.get(sev_str, Severity.HIGH)

        # Compute or extract risk score
        risk_score = float(event_obj.metadata.get("risk_score", cls.SEVERITY_SCORE_MAP[sev]))

        # Infer workload
        workload = cls._infer_workload_name(event_obj.pod, event_obj.metadata)

        # Compile evidence dictionary
        evidence: Dict[str, Any] = dict(event_obj.metadata)
        if event_obj.process:
            evidence["process"] = event_obj.process
        if event_obj.parent_process:
            evidence["parent_process"] = event_obj.parent_process
        if event_obj.executable:
            evidence["executable"] = event_obj.executable
        if event_obj.file_path:
            evidence["file_path"] = event_obj.file_path
        if event_obj.destination_ip:
            evidence["destination_ip"] = event_obj.destination_ip
            evidence["destination_port"] = event_obj.destination_port
        if event_obj.mitre_technique:
            evidence["mitre_technique"] = event_obj.mitre_technique
            evidence["mitre_tactic"] = event_obj.mitre_tactic

        # Determine primary action
        action = event_obj.action
        if not action or action == "detected":
            if event_obj.process:
                action = f"execve:{event_obj.process}"
            elif event_obj.file_path:
                action = f"openat:{event_obj.file_path}"
            elif event_obj.destination_ip:
                action = f"connect:{event_obj.destination_ip}:{event_obj.destination_port}"

        service_account = event_obj.metadata.get("service_account")
        if not service_account and workload:
            service_account = f"{workload}-sa"

        return UnifiedSecurityEvent(
            source=EventSource.THREATGUARD,
            event_type=ev_type,
            provider=CloudProvider.KUBERNETES,
            cluster_id=event_obj.cluster or "threatguard-cluster",
            namespace=event_obj.namespace or "threatguard",
            workload=workload,
            pod=event_obj.pod or None,
            service_account=service_account,
            resource_id=event_obj.file_path or event_obj.destination_ip or event_obj.pod or None,
            action=action,
            severity=sev,
            risk_score=risk_score,
            confidence=float(event_obj.confidence),
            detection_rule=event_obj.detection_rule or None,
            description=event_obj.description or "ThreatGuard security detection",
            evidence=evidence,
            metadata={
                "original_event_id": event_obj.event_id,
                "node": event_obj.node,
                "container": event_obj.container,
                "engine": "threatguard",
            },
        )

    @classmethod
    def batch_to_unified_events(cls, events: List[Union[SecurityEvent, Dict[str, Any]]]) -> List[UnifiedSecurityEvent]:
        return [cls.to_unified_event(e) for e in events]
