"""
Kubernetes workload-ownership resolution for remediation targeting.

A Kubernetes Pod name is not a Deployment name: a Deployment-managed Pod is
named ``<deployment>-<replicaset-hash>-<pod-suffix>``, so treating the Pod
name as if it were the Deployment/StatefulSet/DaemonSet name (as the
remediation engine used to) generates commands that target a resource that
doesn't exist.

Resolution preference order:
1. Explicit ``ownerReferences`` (the same structure the Kubernetes API
   returns on a Pod's ``metadata.ownerReferences``), when the caller has
   them. This is the authoritative source.
2. A naming-pattern fallback on the Pod name itself, used when no owner
   reference data is available -- which is the common case in this project
   today, since raw Tetragon telemetry carries only ``pod.namespace``/
   ``pod.name``/``pod.container`` and never owner metadata. This fallback is
   inherently a best-effort inference, not a guarantee: it is documented on
   the returned ``WorkloadRef`` via ``inferred_from`` and is only applied for
   the naming shapes real Kubernetes controllers actually produce.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# <base>-<pod-template-hash (6-10 hex/alnum chars)>-<pod-suffix (5 alnum chars)>
# e.g. "web-app-7c9d8f6d7b-x2abc" -> base="web-app"
_DEPLOYMENT_POD_PATTERN = re.compile(r"^(?P<base>.+)-[0-9a-f]{6,10}-[a-z0-9]{5}$")

# <base>-<ordinal> e.g. "web-0" -> base="web"
_STATEFULSET_POD_PATTERN = re.compile(r"^(?P<base>.+)-\d+$")

# Kubernetes owner kind -> kubectl resource kind usable with `kubectl rollout restart`.
_ROLLOUT_RESTART_SUPPORTED_KINDS = {
    "Deployment": "deployment",
    "StatefulSet": "statefulset",
    "DaemonSet": "daemonset",
}

# Owner kinds that exist but are not safely auto-remediable via rollout restart
# (Jobs/CronJobs are run-to-completion workloads; "restarting" one is not a
# supported or generally safe operation).
_UNSUPPORTED_OWNER_KINDS = {"Job", "CronJob"}


@dataclass
class WorkloadRef:
    """
    Structured Kubernetes workload identity for a Pod, resolved from either
    real owner metadata or (failing that) the Pod's own naming pattern.
    """
    namespace: str
    pod_name: str | None
    owner_kind: str | None = None
    owner_name: str | None = None
    inferred_from: str | None = None  # "owner_references" | "pod_name_pattern" | None
    requires_manual_remediation: bool = False
    manual_reason: str = ""

    @property
    def remediation_target(self) -> str | None:
        """
        The kubectl resource reference (e.g. "deployment/web-app") to use for
        rollout-restart-style remediation, or None if remediation must be manual.
        """
        if self.requires_manual_remediation or not self.owner_kind or not self.owner_name:
            return None
        kubectl_kind = _ROLLOUT_RESTART_SUPPORTED_KINDS.get(self.owner_kind)
        if not kubectl_kind:
            return None
        return f"{kubectl_kind}/{self.owner_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "owner_kind": self.owner_kind,
            "owner_name": self.owner_name,
            "inferred_from": self.inferred_from,
            "requires_manual_remediation": self.requires_manual_remediation,
            "manual_reason": self.manual_reason,
            "remediation_target": self.remediation_target,
        }


def _owner_name_to_deployment_name(replicaset_name: str) -> str | None:
    """
    A Pod's direct owner is normally a ReplicaSet, not the Deployment itself
    (Deployment -> owns -> ReplicaSet -> owns -> Pod). Resolving the actual
    Deployment requires a second API call to fetch the ReplicaSet's own
    ownerReferences, which this offline/telemetry-driven system cannot make.
    As a documented, well-established fallback (the same one kubectl-adjacent
    tooling commonly uses), strip the ReplicaSet's pod-template-hash suffix.
    Returns None if the ReplicaSet name doesn't match the expected shape.
    """
    match = re.match(r"^(?P<base>.+)-[0-9a-f]{6,10}$", replicaset_name)
    return match.group("base") if match else None


def resolve_workload_owner(
    namespace: str,
    pod_name: str | None,
    owner_references: list[dict[str, Any]] | None = None,
) -> WorkloadRef:
    """
    Resolves the controller that owns a Pod, preferring real ownerReferences
    metadata and falling back to a documented naming-pattern heuristic.
    """
    owner_references = owner_references or []

    # 1. Authoritative: real ownerReferences, as returned by the K8s API.
    if owner_references:
        if len(owner_references) > 1:
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                requires_manual_remediation=True,
                manual_reason=(
                    f"Pod has {len(owner_references)} ownerReferences; ownership is ambiguous "
                    "and cannot be safely auto-resolved."
                ),
            )

        owner = owner_references[0]
        owner_kind = owner.get("kind")
        owner_name = owner.get("name")

        if not owner_kind or not owner_name:
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                requires_manual_remediation=True,
                manual_reason="ownerReferences entry is missing 'kind' or 'name'.",
            )

        if owner_kind in _UNSUPPORTED_OWNER_KINDS:
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                owner_kind=owner_kind,
                owner_name=owner_name,
                inferred_from="owner_references",
                requires_manual_remediation=True,
                manual_reason=(
                    f"Pod is owned by a {owner_kind} ('{owner_name}'), a run-to-completion "
                    "workload; 'kubectl rollout restart' is not a supported operation for it."
                ),
            )

        if owner_kind == "ReplicaSet":
            deployment_name = _owner_name_to_deployment_name(owner_name)
            if not deployment_name:
                return WorkloadRef(
                    namespace=namespace,
                    pod_name=pod_name,
                    owner_kind=owner_kind,
                    owner_name=owner_name,
                    inferred_from="owner_references",
                    requires_manual_remediation=True,
                    manual_reason=(
                        f"Pod is owned by ReplicaSet '{owner_name}', but its name doesn't match "
                        "the expected '<deployment>-<hash>' shape, so the owning Deployment name "
                        "could not be derived without a live cluster lookup."
                    ),
                )
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                owner_kind="Deployment",
                owner_name=deployment_name,
                inferred_from="owner_references",
            )

        if owner_kind in _ROLLOUT_RESTART_SUPPORTED_KINDS:
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                owner_kind=owner_kind,
                owner_name=owner_name,
                inferred_from="owner_references",
            )

        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            owner_kind=owner_kind,
            owner_name=owner_name,
            inferred_from="owner_references",
            requires_manual_remediation=True,
            manual_reason=f"Owner kind '{owner_kind}' is not one this engine knows how to remediate automatically.",
        )

    # 2. No owner metadata available: fall back to naming-pattern inference on the Pod name.
    if not pod_name:
        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            requires_manual_remediation=True,
            manual_reason="No pod name or owner reference metadata available.",
        )

    deployment_match = _DEPLOYMENT_POD_PATTERN.match(pod_name)
    if deployment_match:
        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            owner_kind="Deployment",
            owner_name=deployment_match.group("base"),
            inferred_from="pod_name_pattern",
        )

    statefulset_match = _STATEFULSET_POD_PATTERN.match(pod_name)
    if statefulset_match:
        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            owner_kind="StatefulSet",
            owner_name=statefulset_match.group("base"),
            inferred_from="pod_name_pattern",
        )

    # Standalone Pod, or a naming shape (e.g. a DaemonSet's single-suffix name)
    # this engine cannot distinguish confidently from a bare Pod without owner
    # metadata -- refuse to guess rather than risk an incorrect command.
    return WorkloadRef(
        namespace=namespace,
        pod_name=pod_name,
        requires_manual_remediation=True,
        manual_reason=(
            f"No owner reference metadata was available, and pod name '{pod_name}' does not "
            "match a recognized Deployment or StatefulSet naming pattern. Treating as a "
            "standalone Pod (or an owner kind, such as DaemonSet, that cannot be inferred "
            "safely from naming alone) rather than risk targeting the wrong resource."
        ),
    )
