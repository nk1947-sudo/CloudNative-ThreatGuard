"""
Unified Security Event Model (v1.0).
Provides a provider-neutral normalized event schema for both
CloudGraphGuard (Cloud IAM/identity) and ThreatGuard (Kubernetes runtime/admission).
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventSource(str, Enum):
    CLOUDGRAPHGUARD = "cloudgraphguard"
    THREATGUARD = "threatguard"


class EventType(str, Enum):
    IAM_RISK = "iam_risk"
    RUNTIME_DETECTION = "runtime_detection"
    ADMISSION_VIOLATION = "admission_violation"
    NETWORK_DETECTION = "network_detection"
    INCIDENT = "incident"
    ATTACK_SIMULATION = "attack_simulation"


class CloudProvider(str, Enum):
    AWS = "aws"
    KUBERNETES = "kubernetes"
    GCP = "gcp"
    AZURE = "azure"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UnifiedSecurityEvent(BaseModel):
    """
    Normalized security event model version 1.0.
    Standardizes IAM findings, admission denials, and eBPF runtime events.
    """
    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)

    schema_version: str = Field(default="1.0", description="Schema version identifier")
    event_id: str = Field(
        default_factory=lambda: f"USE-{uuid.uuid4().hex[:12].upper()}",
        description="Unique event identifier",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp",
    )
    source: EventSource = Field(description="Originating security engine")
    event_type: EventType = Field(description="Classification of security event")
    provider: CloudProvider = Field(description="Target infrastructure provider")

    # Cloud Context (AWS / CloudGraphGuard)
    cluster_id: str | None = Field(default=None, description="Cloud or EKS cluster ID/ARN")
    account_id: str | None = Field(default=None, description="Cloud account ID (e.g. AWS 12-digit ID)")
    principal_id: str | None = Field(default=None, description="Identity principal ID (user, role, service)")
    principal_arn: str | None = Field(default=None, description="Complete ARN of identity principal")
    role_arn: str | None = Field(default=None, description="Assumed or target role ARN")

    # Kubernetes Context (ThreatGuard)
    namespace: str | None = Field(default=None, description="Target Kubernetes namespace")
    workload: str | None = Field(default=None, description="Workload deployment/daemonset name")
    pod: str | None = Field(default=None, description="Specific pod instance name")
    service_account: str | None = Field(default=None, description="Kubernetes ServiceAccount bound to workload")

    # Resource & Action Context
    resource_id: str | None = Field(default=None, description="Resource identifier (bucket name, secret, table)")
    resource_arn: str | None = Field(default=None, description="Resource ARN or URI")
    action: str | None = Field(default=None, description="Specific API action or syscall executed")

    # Security Scoring & Detection
    severity: Severity = Field(description="Normalized severity level")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Risk score from 0.0 to 100.0")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence 0.0 to 1.0")
    detection_rule: str | None = Field(default=None, description="Rule or policy ID that triggered")
    description: str = Field(description="Human-readable description of security finding")

    # Evidence & Metadata
    evidence: dict[str, Any] = Field(default_factory=dict, description="Detailed evidence dictionary")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary engine metadata")

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> str:
        if isinstance(v, datetime):
            return v.astimezone(timezone.utc).isoformat()
        if isinstance(v, str):
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                return dt.isoformat()
            except Exception:
                return v
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Export normalized event to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UnifiedSecurityEvent":
        """Construct normalized event from dictionary with defensive fallbacks."""
        return cls(**data)
