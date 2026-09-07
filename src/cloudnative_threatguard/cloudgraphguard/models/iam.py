"""
Core AWS IAM data models for CloudGraphGuard.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IAMPrincipalType(str, Enum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE = "service"
    FEDERATED = "federated"


class IAMPolicyStatement(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sid: str | None = None
    effect: str = "Allow"  # "Allow" or "Deny"
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    principals: list[str] = Field(default_factory=list)
    conditions: dict[str, Any] = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    policy_id: str
    name: str
    arn: str
    is_managed: bool = True
    statements: list[IAMPolicyStatement] = Field(default_factory=list)


class IAMPrincipal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    arn: str
    account_id: str
    principal_type: IAMPrincipalType
    attached_policies: list[IAMPolicy] = Field(default_factory=list)
    inline_policies: list[IAMPolicy] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class IAMUser(IAMPrincipal):
    groups: list[str] = Field(default_factory=list)
    has_mfa: bool = False
    access_keys_count: int = 1


class IAMRole(IAMPrincipal):
    trust_policy_statements: list[IAMPolicyStatement] = Field(default_factory=list)
    max_session_duration: int = 3600
    instance_profile_arns: list[str] = Field(default_factory=list)


class IAMResource(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    arn: str
    resource_type: str  # e.g. "s3", "secretsmanager", "dynamodb", "eks"
    account_id: str
    is_sensitive: bool = False
    data_classification: str = "internal"  # "public", "internal", "confidential", "restricted"
