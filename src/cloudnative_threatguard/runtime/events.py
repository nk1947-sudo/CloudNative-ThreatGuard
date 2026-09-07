"""
Unified Security Event Model for CloudNative ThreatGuard.
Provides a standardized event envelope across admission, runtime eBPF,
network observability, configuration assessment, and attack simulations.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecurityEventType(str, Enum):
    ADMISSION_VIOLATION = "admission_violation"
    RUNTIME_DETECTION = "runtime_detection"
    NETWORK_ANOMALY = "network_anomaly"
    POLICY_VIOLATION = "policy_violation"
    CONFIGURATION_RISK = "configuration_risk"
    ATTACK_SIMULATION = "attack_simulation"
    INCIDENT = "incident"
    RESPONSE_ACTION = "response_action"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityEvent:
    """
    Standardized, normalized security event envelope for all ThreatGuard layers.
    """
    event_id: str = field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = SecurityEventType.RUNTIME_DETECTION.value
    source: str = "tetragon"  # opa_gatekeeper, tetragon, threatguard_engine, simulator
    cluster: str = "threatguard-local"
    namespace: str = "threatguard"
    pod: str = ""
    container: str = ""
    node: str = "threatguard-local-control-plane"
    process: str = ""
    parent_process: str = ""
    executable: str = ""
    action: str = "detected"  # blocked_admission, process_exec, file_read, net_connect
    severity: str = Severity.HIGH.value
    confidence: float = 0.90
    detection_rule: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    file_path: str = ""
    destination_ip: str = ""
    destination_port: int = 0
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert event to a standard JSON-serializable dictionary."""
        data = asdict(self)
        # Add backwards compatibility properties for legacy consumers
        data["rule_id"] = self.detection_rule
        data["technique"] = self.mitre_technique
        data["technique_name"] = self.metadata.get("technique_name", "")
        data["detection_name"] = self.description
        data["evidence"] = self.metadata
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Reconstruct event from dictionary representation with schema tolerance."""
        # Handle legacy field mappings
        event_id = data.get("event_id") or f"ev-{uuid.uuid4().hex[:12]}"
        timestamp = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        event_type = data.get("event_type", SecurityEventType.RUNTIME_DETECTION.value)
        source = data.get("source", "tetragon")
        cluster = data.get("cluster", "threatguard-local")
        namespace = data.get("namespace", "threatguard")
        pod = data.get("pod", "")
        container = data.get("container", "")
        node = data.get("node", "threatguard-local-control-plane")
        process = data.get("process", "")
        parent_process = data.get("parent_process", "")
        executable = data.get("executable", process)
        action = data.get("action", "detected")
        severity = data.get("severity", Severity.HIGH.value).upper()
        confidence = float(data.get("confidence", 0.90))
        detection_rule = data.get("detection_rule") or data.get("rule_id", "")
        mitre_technique = data.get("mitre_technique") or data.get("technique", "")
        mitre_tactic = data.get("mitre_tactic") or data.get("tactic", "")
        description = data.get("description") or data.get("detection_name", "")
        metadata = data.get("metadata") or data.get("evidence", {})

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            source=source,
            cluster=cluster,
            namespace=namespace,
            pod=pod,
            container=container,
            node=node,
            process=process,
            parent_process=parent_process,
            executable=executable,
            action=action,
            severity=severity,
            confidence=confidence,
            detection_rule=detection_rule,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            description=description,
            metadata=metadata
        )

    @classmethod
    def from_admission_denial(
        cls,
        rule_id: str,
        policy_name: str,
        resource_name: str,
        namespace: str,
        violation_message: str,
        mitre_technique: str = "T1610",
        mitre_tactic: str = "Defense Evasion",
        severity: str = "CRITICAL",
        confidence: float = 0.99
    ) -> "SecurityEvent":
        """Factory for admission webhook violations (OPA Gatekeeper)."""
        return cls(
            event_type=SecurityEventType.ADMISSION_VIOLATION.value,
            source="opa_gatekeeper",
            namespace=namespace,
            pod=resource_name,
            action="blocked_admission",
            severity=severity,
            confidence=confidence,
            detection_rule=rule_id,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            description=f"Admission blocked by {policy_name}: {violation_message}",
            metadata={
                "policy_name": policy_name,
                "resource_name": resource_name,
                "violation_details": violation_message,
                "enforcement_action": "deny"
            }
        )

    @classmethod
    def from_simulation(
        cls,
        scenario_id: str,
        name: str,
        pod: str,
        namespace: str,
        command: str,
        technique: str,
        tactic: str,
        severity: str = "HIGH"
    ) -> "SecurityEvent":
        """Factory for deterministic attack simulation events."""
        return cls(
            event_type=SecurityEventType.ATTACK_SIMULATION.value,
            source="threatguard_simulator",
            namespace=namespace,
            pod=pod,
            process=command.split()[0] if command else "",
            action="simulated_attack_execution",
            severity=severity,
            confidence=1.0,
            detection_rule=scenario_id,
            mitre_technique=technique,
            mitre_tactic=tactic,
            description=f"Simulated attack scenario {scenario_id}: {name}",
            metadata={
                "scenario_id": scenario_id,
                "command": command,
                "simulation": True,
                "verifiable": True
            }
        )


# Backward compatibility wrapper for existing ThreatGuardDetection callers
class ThreatGuardDetection(SecurityEvent):
    """
    Subclass of SecurityEvent maintaining backwards compatibility
    with existing tests and consumers.
    """
    def __init__(self, **kwargs):
        # Map legacy keys if present
        if "rule_id" in kwargs and "detection_rule" not in kwargs:
            kwargs["detection_rule"] = kwargs.pop("rule_id")
        if "technique" in kwargs and "mitre_technique" not in kwargs:
            kwargs["mitre_technique"] = kwargs.pop("technique")
        if "tactic" in kwargs and "mitre_tactic" not in kwargs:
            kwargs["mitre_tactic"] = kwargs.pop("tactic")
        if "detection_name" in kwargs and "description" not in kwargs:
            kwargs["description"] = kwargs.pop("detection_name")
        if "evidence" in kwargs and "metadata" not in kwargs:
            kwargs["metadata"] = kwargs.pop("evidence")
        if "command" in kwargs:
            cmd = kwargs.pop("command")
            if "metadata" not in kwargs:
                kwargs["metadata"] = {}
            kwargs["metadata"]["command"] = cmd
        if "technique_name" in kwargs:
            t_name = kwargs.pop("technique_name")
            if "metadata" not in kwargs:
                kwargs["metadata"] = {}
            kwargs["metadata"]["technique_name"] = t_name

        # Collect any extra kwargs that are not SecurityEvent dataclass fields into metadata
        allowed_fields = {
            "event_id", "timestamp", "event_type", "source", "cluster", "namespace",
            "pod", "container", "node", "process", "parent_process", "executable",
            "action", "severity", "confidence", "detection_rule", "mitre_technique",
            "mitre_tactic", "description", "metadata"
        }
        extras = {k: v for k, v in kwargs.items() if k not in allowed_fields}
        for k in extras:
            kwargs.pop(k)
        if "metadata" not in kwargs:
            kwargs["metadata"] = {}
        kwargs["metadata"].update(extras)
        super().__init__(**kwargs)

    @property
    def rule_id(self) -> str:
        return self.detection_rule

    @rule_id.setter
    def rule_id(self, val: str):
        self.detection_rule = val

    @property
    def technique(self) -> str:
        return self.mitre_technique

    @technique.setter
    def technique(self, val: str):
        self.mitre_technique = val

    @property
    def tactic(self) -> str:
        return self.mitre_tactic

    @tactic.setter
    def tactic(self, val: str):
        self.mitre_tactic = val

    @property
    def technique_name(self) -> str:
        return self.metadata.get("technique_name", "")

    @technique_name.setter
    def technique_name(self, val: str):
        self.metadata["technique_name"] = val

    @property
    def detection_name(self) -> str:
        return self.description

    @detection_name.setter
    def detection_name(self, val: str):
        self.description = val

    @property
    def evidence(self) -> dict[str, Any]:
        return self.metadata

    @evidence.setter
    def evidence(self, val: dict[str, Any]):
        self.metadata = val

    @property
    def command(self) -> str:
        return self.metadata.get("command", "")

    @command.setter
    def command(self, val: str):
        self.metadata["command"] = val

    def to_security_event(self) -> SecurityEvent:
        """Return as pure SecurityEvent base dataclass."""
        return SecurityEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            event_type=self.event_type,
            source=self.source,
            cluster=self.cluster,
            namespace=self.namespace,
            pod=self.pod,
            container=self.container,
            node=self.node,
            process=self.process,
            parent_process=self.parent_process,
            executable=self.executable,
            action=self.action,
            severity=self.severity,
            confidence=self.confidence,
            detection_rule=self.detection_rule,
            mitre_technique=self.mitre_technique,
            mitre_tactic=self.mitre_tactic,
            description=self.description,
            metadata=dict(self.metadata)
        )


@dataclass
class SecurityIncident:
    """
    Correlated multi-stage security incident representing an attack chain
    on a workload or cluster boundary.
    """
    incident_id: str = field(default_factory=lambda: f"#TG-{uuid.uuid4().hex[:6].upper()}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cluster: str = "threatguard-local"
    namespace: str = "threatguard"
    pod: str = ""
    container: str = ""
    severity: str = Severity.HIGH.value
    confidence: float = 0.90
    title: str = "Multi-Stage Workload Threat Chain"
    summary: str = ""
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    events: list[SecurityEvent] = field(default_factory=list)
    status: str = "OPEN"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "pod": self.pod,
            "container": self.container,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "title": self.title,
            "summary": self.summary,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "status": self.status,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "metadata": self.metadata
        }
