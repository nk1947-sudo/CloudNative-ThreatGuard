"""
Core AWS IAM data models for CloudGraphGuard.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class IAMPrincipalType(str, Enum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE = "service"
    FEDERATED = "federated"


class IAMPolicyStatement(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sid: Optional[str] = None
    effect: str = "Allow"  # "Allow" or "Deny"
    actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    principals: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    policy_id: str
    name: str
    arn: str
    is_managed: bool = True
    statements: List[IAMPolicyStatement] = Field(default_factory=list)


class IAMPrincipal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    arn: str
    account_id: str
    principal_type: IAMPrincipalType
    attached_policies: List[IAMPolicy] = Field(default_factory=list)
    inline_policies: List[IAMPolicy] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)


class IAMUser(IAMPrincipal):
    groups: List[str] = Field(default_factory=list)
    has_mfa: bool = False
    access_keys_count: int = 1


class IAMRole(IAMPrincipal):
    trust_policy_statements: List[IAMPolicyStatement] = Field(default_factory=list)
    max_session_duration: int = 3600
    instance_profile_arns: List[str] = Field(default_factory=list)


class IAMResource(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    arn: str
    resource_type: str  # e.g. "s3", "secretsmanager", "dynamodb", "eks"
    account_id: str
    is_sensitive: bool = False
    data_classification: str = "internal"  # "public", "internal", "confidential", "restricted"
