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
   them. This is the authoritative source for the Pod's *immediate* owner.
2. An optional, injected live Kubernetes API lookup (``kubernetes_client``),
   used only when the caller opts in (see ``--live-k8s`` in ``cli/main.py``)
   and no ownerReferences were already supplied. Every other ThreatGuard
   function remains fully usable without a kubeconfig -- this is never
   attempted unless a client is explicitly passed in.
3. A naming-pattern fallback on the Pod name itself, used when neither of the
   above produced an answer -- which is the common case in this project
   today, since raw Tetragon telemetry carries only ``pod.namespace``/
   ``pod.name``/``pod.container`` and never owner metadata, and live lookup
   is opt-in. This fallback is inherently best-effort, not a guarantee: it is
   documented on the returned ``WorkloadRef`` via ``inferred_from`` and is
   only applied for the naming shapes real Kubernetes controllers actually
   produce.
4. Manual remediation, when none of the above can safely determine ownership.

A Pod's direct owner is normally a ReplicaSet, not the Deployment itself
(Deployment -> owns -> ReplicaSet -> owns -> Pod). Resolving the owning
Deployment authoritatively requires a second lookup of the ReplicaSet's own
ownerReferences; when a live client is available this is done for real
(``_resolve_replicaset_owner``), otherwise it falls back to the same
documented pod-template-hash-stripping heuristic this module has always used.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

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

# Kubernetes Kind -> kubectl resource name, for live ownership lookups.
_KUBECTL_RESOURCE_NAME = {
    "Pod": "pod",
    "ReplicaSet": "replicaset",
    "Deployment": "deployment",
    "StatefulSet": "statefulset",
    "DaemonSet": "daemonset",
}


class KubernetesOwnershipClient(Protocol):
    """
    Minimal interface a live Kubernetes ownership lookup must satisfy.
    Deliberately narrow (read-only, one method) so tests can supply a trivial
    fake instead of standing up or mocking a full Kubernetes API client.
    """

    def get_owner_references(self, namespace: str, kind: str, name: str) -> list[dict[str, Any]] | None:
        """
        Returns the ``metadata.ownerReferences`` of the named resource.

        Returns ``None`` if the lookup failed or is unavailable for any
        reason (API unreachable, permission denied, resource not found,
        timeout, kubectl not installed, no kubeconfig, etc.) -- callers must
        treat ``None`` as "unknown" and fall back safely, never as "no
        owner". Returns ``[]`` when the lookup succeeded and confirmed the
        resource genuinely has no owner references. Implementations must
        never raise.
        """
        ...


class KubectlOwnershipClient:
    """
    Live Kubernetes ownership lookups via the ``kubectl`` CLI -- the same
    subprocess-based, best-effort pattern already used elsewhere in this
    project for optional cluster access (see ``cli/main.py``'s
    ``cmd_status`` and ``reporting/evidence.py``'s
    ``collect_live_cluster_telemetry``), rather than introducing a new
    ``kubernetes`` PyPI client dependency this project has never needed.

    Read-only: every call is a plain ``kubectl get <resource> -o json``.
    See docs/security/kubernetes-ownership-rbac.md for the minimum RBAC this
    requires. Never raises -- any failure is reported as ``None`` so callers
    fall back safely instead of guessing.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def get_owner_references(self, namespace: str, kind: str, name: str) -> list[dict[str, Any]] | None:
        resource = _KUBECTL_RESOURCE_NAME.get(kind, kind.lower())
        try:
            result = subprocess.run(
                ["kubectl", "get", resource, name, "-n", namespace, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except Exception:
            # Covers: kubectl not installed, timeout, and any other
            # unexpected failure to even invoke the command.
            return None
        if result.returncode != 0:
            # Covers: resource not found, namespace not found, forbidden
            # (RBAC denial), API server unreachable -- kubectl reports all
            # of these as a non-zero exit rather than an exception.
            return None
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return None
        return data.get("metadata", {}).get("ownerReferences") or []


@dataclass
class WorkloadRef:
    """
    Structured Kubernetes workload identity for a Pod, resolved from real
    owner metadata (explicit or live-looked-up) or, failing that, the Pod's
    own naming pattern.
    """
    namespace: str
    pod_name: str | None
    owner_kind: str | None = None
    owner_name: str | None = None
    inferred_from: str | None = None  # "owner_references" | "live_api" | "pod_name_pattern" | None
    requires_manual_remediation: bool = False
    manual_reason: str = ""
    live_lookup_status: str | None = None  # "success" | "failed" | None (no live lookup attempted)

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
            "live_lookup_status": self.live_lookup_status,
        }


def _owner_name_to_deployment_name(replicaset_name: str) -> str | None:
    """
    Naming-pattern fallback for ReplicaSet -> Deployment: strips the
    ReplicaSet's pod-template-hash suffix. This is a documented, well-known
    heuristic (the same one kubectl-adjacent tooling commonly uses), used
    only when a live lookup of the ReplicaSet's own ownerReferences isn't
    available or didn't resolve a Deployment. Returns None if the ReplicaSet
    name doesn't match the expected shape.
    """
    match = re.match(r"^(?P<base>.+)-[0-9a-f]{6,10}$", replicaset_name)
    return match.group("base") if match else None


def _resolve_replicaset_owner(
    namespace: str,
    replicaset_name: str,
    kubernetes_client: KubernetesOwnershipClient | None,
) -> tuple[str | None, str]:
    """
    Resolves the Deployment that owns a ReplicaSet, authoritatively via a
    live lookup of the ReplicaSet's own ownerReferences when a client is
    available, falling back to name-stripping otherwise (or if the live
    lookup fails / finds no Deployment owner).

    Returns (deployment_name_or_None, method) where method is "live_api" or
    "naming_fallback".
    """
    if kubernetes_client is not None:
        owner_refs = kubernetes_client.get_owner_references(namespace, "ReplicaSet", replicaset_name)
        if owner_refs:
            deployment_ref = next(
                (o for o in owner_refs if o.get("kind") == "Deployment" and o.get("name")), None
            )
            if deployment_ref:
                return deployment_ref["name"], "live_api"
    return _owner_name_to_deployment_name(replicaset_name), "naming_fallback"


def _resolve_from_owner_references(
    namespace: str,
    pod_name: str | None,
    owner_references: list[dict[str, Any]],
    inferred_from: str,
    kubernetes_client: KubernetesOwnershipClient | None = None,
) -> WorkloadRef:
    """
    Builds a WorkloadRef from a Pod's ownerReferences, however they were
    obtained (explicit event data, or a live API lookup -- ``inferred_from``
    records which). Shared by both callers so the actual owner-kind handling
    logic exists exactly once.
    """
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
            inferred_from=inferred_from,
            requires_manual_remediation=True,
            manual_reason=(
                f"Pod is owned by a {owner_kind} ('{owner_name}'), a run-to-completion "
                "workload; 'kubectl rollout restart' is not a supported operation for it."
            ),
        )

    if owner_kind == "ReplicaSet":
        deployment_name, method = _resolve_replicaset_owner(namespace, owner_name, kubernetes_client)
        if not deployment_name:
            return WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                owner_kind=owner_kind,
                owner_name=owner_name,
                inferred_from=inferred_from,
                requires_manual_remediation=True,
                manual_reason=(
                    f"Pod is owned by ReplicaSet '{owner_name}', but its owning Deployment could "
                    "not be determined (no live cluster lookup available or it didn't resolve a "
                    "Deployment owner, and the ReplicaSet's name doesn't match the expected "
                    "'<deployment>-<hash>' shape)."
                ),
            )
        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            owner_kind="Deployment",
            owner_name=deployment_name,
            # The ReplicaSet -> Deployment hop is what actually decided this
            # answer; if that hop used a live lookup, the result as a whole
            # is live-API-derived even if the Pod -> ReplicaSet step came
            # from explicitly supplied ownerReferences.
            inferred_from="live_api" if method == "live_api" else inferred_from,
        )

    if owner_kind in _ROLLOUT_RESTART_SUPPORTED_KINDS:
        return WorkloadRef(
            namespace=namespace,
            pod_name=pod_name,
            owner_kind=owner_kind,
            owner_name=owner_name,
            inferred_from=inferred_from,
        )

    return WorkloadRef(
        namespace=namespace,
        pod_name=pod_name,
        owner_kind=owner_kind,
        owner_name=owner_name,
        inferred_from=inferred_from,
        requires_manual_remediation=True,
        manual_reason=f"Owner kind '{owner_kind}' is not one this engine knows how to remediate automatically.",
    )


def _resolve_via_naming_pattern(namespace: str, pod_name: str | None) -> WorkloadRef:
    """No owner metadata available: fall back to naming-pattern inference on the Pod name."""
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


def resolve_workload_owner(
    namespace: str,
    pod_name: str | None,
    owner_references: list[dict[str, Any]] | None = None,
    kubernetes_client: KubernetesOwnershipClient | None = None,
) -> WorkloadRef:
    """
    Resolves the controller that owns a Pod, preferring real ownerReferences
    metadata, then an optional live Kubernetes API lookup, then falling back
    to a documented naming-pattern heuristic.

    ``kubernetes_client`` is entirely optional dependency injection: passing
    None (the default) makes this function behave exactly as it always has,
    fully offline. It is never constructed by this module itself -- callers
    (see cli/main.py's ``--live-k8s`` flag) decide whether live lookups are
    enabled.
    """
    owner_references = owner_references or []

    # 1. Authoritative: real ownerReferences already supplied by the caller.
    if owner_references:
        return _resolve_from_owner_references(
            namespace, pod_name, owner_references, inferred_from="owner_references",
            kubernetes_client=kubernetes_client,
        )

    # 2. Optional live Kubernetes API lookup (opt-in only).
    if kubernetes_client is not None and pod_name:
        live_owner_refs = kubernetes_client.get_owner_references(namespace, "Pod", pod_name)

        if live_owner_refs is None:
            # Lookup unavailable for any reason -- fall back safely rather
            # than ever fabricating an owner.
            ref = _resolve_via_naming_pattern(namespace, pod_name)
            ref.live_lookup_status = "failed"
            return ref

        if not live_owner_refs:
            # Authoritative ground truth: the live API confirms this Pod has
            # no owner. Deliberately NOT run through the naming-pattern
            # guesser, which could be wrong for a standalone Pod that
            # happens to match a controller's naming shape.
            ref = WorkloadRef(
                namespace=namespace,
                pod_name=pod_name,
                inferred_from="live_api",
                requires_manual_remediation=True,
                manual_reason="Live Kubernetes lookup confirmed this Pod has no owner (standalone Pod).",
            )
            ref.live_lookup_status = "success"
            return ref

        ref = _resolve_from_owner_references(
            namespace, pod_name, live_owner_refs, inferred_from="live_api",
            kubernetes_client=kubernetes_client,
        )
        ref.live_lookup_status = "success"
        return ref

    # 3. No owner metadata available at all: fall back to naming-pattern
    #    inference on the Pod name itself.
    return _resolve_via_naming_pattern(namespace, pod_name)
