"""
Data models for CloudNative ThreatGuard Security Detections.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid

@dataclass
class ThreatGuardDetection:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    namespace: str = "threatguard"
    pod: str = ""
    container: str = ""
    process: str = ""
    command: str = ""
    event_type: str = "process_exec"  # process_exec, file_access, network_connect, priv_escalation
    severity: str = "HIGH"            # INFO, LOW, MEDIUM, HIGH, CRITICAL
    detection_name: str = ""
    rule_id: str = ""
    technique: str = ""               # MITRE ATT&CK ID e.g., T1059.004
    technique_name: str = ""
    source: str = "eBPF / Tetragon"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
