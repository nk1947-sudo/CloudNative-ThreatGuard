"""
CloudGraphGuard IAM Security Findings Models.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingType(str, Enum):
    IAM_PRIVILEGE_ESCALATION = "IAM_PRIVILEGE_ESCALATION"
    IAM_EXCESSIVE_PERMISSION = "IAM_EXCESSIVE_PERMISSION"
    IAM_WILDCARD_PERMISSION = "IAM_WILDCARD_PERMISSION"
    IAM_CROSS_ACCOUNT_TRUST = "IAM_CROSS_ACCOUNT_TRUST"
    IAM_SENSITIVE_RESOURCE_ACCESS = "IAM_SENSITIVE_RESOURCE_ACCESS"
    IAM_ATTACK_PATH = "IAM_ATTACK_PATH"


class PrivilegeEscalationVector(str, Enum):
    PASS_ROLE = "iam:PassRole"
    ATTACH_USER_POLICY = "iam:AttachUserPolicy"
    ATTACH_ROLE_POLICY = "iam:AttachRolePolicy"
    PUT_USER_POLICY = "iam:PutUserPolicy"
    PUT_ROLE_POLICY = "iam:PutRolePolicy"
    CREATE_POLICY_VERSION = "iam:CreatePolicyVersion"
    SET_DEFAULT_POLICY_VERSION = "iam:SetDefaultPolicyVersion"
    UPDATE_ASSUME_ROLE_POLICY = "iam:UpdateAssumeRolePolicy"
    ASSUME_ROLE = "sts:AssumeRole"


class IAMFinding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    finding_id: str = Field(default_factory=lambda: f"CGG-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finding_type: FindingType
    title: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    risk_score: float = Field(ge=0.0, le=100.0)
    principal_arn: str
    principal_name: str
    account_id: str
    target_role_arn: str | None = None
    target_resource_arn: str | None = None
    escalation_vector: PrivilegeEscalationVector | None = None
    attack_path: list[str] = Field(default_factory=list)
    effective_actions: list[str] = Field(default_factory=list)
    remediation_suggestion: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
