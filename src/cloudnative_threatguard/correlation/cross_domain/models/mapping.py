"""
Cloud Identity to Kubernetes Relationship Model.
Represents bindings between Cloud IAM identities (AWS Roles/Users, GCP ServiceAccounts,
Azure Managed Identities) and Kubernetes runtime identities (Cluster, Namespace, ServiceAccount, Workload).
"""

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MappingMechanism(str, Enum):
    EKS_ACCESS_ENTRY = "eks_access_entry"
    AWS_AUTH_CONFIGMAP = "aws_auth_configmap"
    IRSA = "iam_roles_for_service_accounts"
    POD_IDENTITY = "eks_pod_identity"
    WORKLOAD_IDENTITY = "gcp_workload_identity"
    AZURE_WORKLOAD_IDENTITY = "azure_workload_identity"
    EXPLICIT_CONFIG = "explicit_config"


class IdentityBinding(BaseModel):
    """
    Explicit, evidence-backed relationship between a cloud identity and a Kubernetes entity.
    """
    model_config = ConfigDict(populate_by_name=True)

    binding_id: str = Field(default_factory=lambda: f"BIND-{uuid.uuid4().hex[:8].upper()}")
    cloud_provider: str = Field(default="aws", description="Cloud provider (aws, gcp, azure)")
    cloud_identity: str = Field(description="Cloud identity ARN or unique identifier")
    cloud_identity_type: str = Field(default="IAM_ROLE", description="IAM_ROLE, IAM_USER, etc.")
    cluster: str = Field(description="Target Kubernetes cluster name or ARN")
    kubernetes_identity: str = Field(description="Resolved Kubernetes RBAC username or group")
    namespace: str = Field(description="Target Kubernetes namespace")
    service_account: str = Field(description="Target Kubernetes ServiceAccount name")
    workload: str | None = Field(default=None, description="Bound Kubernetes deployment/statefulset")
    mapping_mechanism: MappingMechanism = Field(default=MappingMechanism.EXPLICIT_CONFIG)
    is_active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class IdentityMappingRegistry:
    """
    Registry and query engine for Cloud-to-Kubernetes identity bindings.
    """

    def __init__(self):
        self._bindings: dict[str, IdentityBinding] = {}

    def register(self, binding: IdentityBinding) -> IdentityBinding:
        self._bindings[binding.binding_id] = binding
        return binding

    def get_all(self) -> list[IdentityBinding]:
        return list(self._bindings.values())

    def find_by_cloud_identity(self, cloud_identity: str) -> list[IdentityBinding]:
        """Find all K8s bindings for a given IAM role/user."""
        return [
            b for b in self._bindings.values()
            if b.cloud_identity.lower() == cloud_identity.lower()
        ]

    def find_by_k8s_workload(self, namespace: str, workload: str) -> list[IdentityBinding]:
        """Find cloud identities bound to a specific Kubernetes workload."""
        return [
            b for b in self._bindings.values()
            if b.namespace.lower() == namespace.lower() and b.workload and b.workload.lower() == workload.lower()
        ]

    def find_by_service_account(self, namespace: str, service_account: str) -> list[IdentityBinding]:
        """Find cloud identities associated with a ServiceAccount."""
        return [
            b for b in self._bindings.values()
            if b.namespace.lower() == namespace.lower() and b.service_account.lower() == service_account.lower()
        ]

    def to_dict(self) -> dict[str, Any]:
        return {"bindings": [b.model_dump() for b in self._bindings.values()]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdentityMappingRegistry":
        reg = cls()
        for b in data.get("bindings", []):
            reg.register(IdentityBinding(**b))
        return reg
