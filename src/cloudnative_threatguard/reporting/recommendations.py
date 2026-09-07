"""
ThreatGuard Incident Response Recommendation Engine.
Produces actionable, non-destructive, and dry-run safe remediation playbooks for SOC analysts.
Enforces the 'Human-in-the-loop' principle: provides copy-pasteable kubectl commands with
defined blast radiuses and reversibility notes rather than blind auto-mutations.
"""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from .workload_resolver import KubernetesOwnershipClient, resolve_workload_owner


class RecommendationPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ActionCategory(str, Enum):
    QUARANTINE = "QUARANTINE"
    CREDENTIALS = "CREDENTIALS"
    FORENSICS = "FORENSICS"
    CONTAINMENT = "CONTAINMENT"
    NODE_SECURITY = "NODE_SECURITY"
    HARDENING = "HARDENING"
    MANUAL_REVIEW = "MANUAL_REVIEW"


@dataclass
class ResponseRecommendation:
    recommendation_id: str
    title: str
    priority: str
    category: str
    rationale: str
    dry_run_command: str
    execution_command: str
    blast_radius: str
    reversibility: str
    requires_manual_review: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResponseRecommendationEngine:
    """
    Generates structured, safe incident response recommendations based on
    incident severity, detected MITRE techniques, and workload posture.
    """
    def generate_recommendations(
        self,
        namespace: str,
        pod_name: str,
        techniques: list[str],
        severity: str = "HIGH",
        node_name: str = "threatguard-local-control-plane",
        container_name: str = "app",
        owner_references: list[dict[str, Any]] | None = None,
        kubernetes_client: KubernetesOwnershipClient | None = None,
    ) -> list[ResponseRecommendation]:
        recs: list[ResponseRecommendation] = []
        rec_counter = 1

        # Resolve the Pod's actual owning controller before generating any
        # recommendation that targets a Deployment/StatefulSet/DaemonSet --
        # a Pod name (e.g. "web-app-7c9d8f6d7b-x2abc") is not that resource's
        # name (e.g. "web-app") and must never be substituted for it directly.
        # `kubernetes_client` is optional dependency injection: None (the
        # default) keeps this fully offline, exactly as before.
        workload = resolve_workload_owner(namespace, pod_name, owner_references, kubernetes_client)

        # 1. Forensic Acquisition (Always recommended first before modifying state)
        recs.append(ResponseRecommendation(
            recommendation_id=f"REC-{rec_counter:02d}-FORENSIC-CAPTURE",
            title=f"Acquire Forensic Artifacts for Pod {pod_name}",
            priority=RecommendationPriority.HIGH.value,
            category=ActionCategory.FORENSICS.value,
            rationale="Acquires process logs, pod manifest, and Tetragon event stream before any pod state alteration.",
            dry_run_command=f"echo 'Capturing forensics for {namespace}/{pod_name}'",
            execution_command=(
                f"mkdir -p /tmp/threatguard-forensics/{pod_name} && \\\n"
                f"kubectl get pod {pod_name} -n {namespace} -o yaml > /tmp/threatguard-forensics/{pod_name}/pod-spec.yaml && \\\n"
                f"kubectl logs {pod_name} -n {namespace} --all-containers=true > /tmp/threatguard-forensics/{pod_name}/pod.log"
            ),
            blast_radius=f"Zero impact. Non-destructive read-only operation on {namespace}/{pod_name}.",
            reversibility="N/A (Read-only data capture)"
        ))
        rec_counter += 1

        # 2. Network Quarantine (T1059 Shell Execution, T1071 C2, T1105 Ingress Transfer, T1496 Mining)
        if any(t in techniques for t in ["T1059", "T1059.004", "T1071", "T1071.001", "T1105", "T1496", "T1046"]):
            if not workload.requires_manual_remediation and workload.owner_name:
                # Selecting by the resolved workload name (shared across every
                # replica's pod template) rather than the individual pod's own
                # name -- a Pod's "app" label is set once on the controller's
                # pod template, never to that pod's own unique instance name,
                # so a selector using the raw pod name would silently match
                # zero pods and quarantine nothing. Isolating the whole
                # workload is also the safer containment action: a compromise
                # is normally at the image/application level, not specific to
                # one replica.
                quarantine_selector_label = workload.owner_name
                netpol_yaml = (
                    f"apiVersion: networking.k8s.io/v1\n"
                    f"kind: NetworkPolicy\n"
                    f"metadata:\n"
                    f"  name: tg-quarantine-{quarantine_selector_label}\n"
                    f"  namespace: {namespace}\n"
                    f"spec:\n"
                    f"  podSelector:\n"
                    f"    matchLabels:\n"
                    f"      app: {quarantine_selector_label}\n"
                    f"  policyTypes:\n"
                    f"  - Ingress\n"
                    f"  - Egress"
                )
                recs.append(ResponseRecommendation(
                    recommendation_id=f"REC-{rec_counter:02d}-NET-QUARANTINE",
                    title=f"Isolate {workload.owner_kind} {quarantine_selector_label} via Default-Deny NetworkPolicy",
                    priority=RecommendationPriority.CRITICAL.value if severity == "CRITICAL" else RecommendationPriority.HIGH.value,
                    category=ActionCategory.QUARANTINE.value,
                    rationale="Cuts off active reverse shells, C2 beacons, and lateral movement probes immediately.",
                    dry_run_command=f"cat << 'EOF' | kubectl apply --dry-run=client -f -\n{netpol_yaml}\nEOF",
                    execution_command=f"cat << 'EOF' | kubectl apply -f -\n{netpol_yaml}\nEOF",
                    blast_radius=f"Restricts inbound and outbound network connectivity for every pod of {workload.owner_kind.lower() if workload.owner_kind else 'workload'} {quarantine_selector_label} (all replicas), assuming its pods carry the conventional 'app: {quarantine_selector_label}' label.",
                    reversibility=f"Fully reversible: run 'kubectl delete networkpolicy tg-quarantine-{quarantine_selector_label} -n {namespace}'"
                ))
            else:
                # No owner could be resolved: a selector built from the pod
                # name alone would not reliably match anything (NetworkPolicy
                # selects by label, not by pod name), so don't emit one.
                # Label the pod directly first, then quarantine that label --
                # this is correct and safe, just not fully automatic.
                recs.append(ResponseRecommendation(
                    recommendation_id=f"REC-{rec_counter:02d}-NET-QUARANTINE-MANUAL",
                    title=f"Manually Isolate Pod {pod_name} via Default-Deny NetworkPolicy",
                    priority=RecommendationPriority.CRITICAL.value if severity == "CRITICAL" else RecommendationPriority.HIGH.value,
                    category=ActionCategory.MANUAL_REVIEW.value,
                    rationale=(
                        "Cuts off active reverse shells, C2 beacons, and lateral movement probes, but the "
                        f"owning workload could not be safely determined ({workload.manual_reason}), so no "
                        "existing label can be trusted to build a NetworkPolicy selector. Label the pod "
                        "directly first, then isolate that label."
                    ),
                    dry_run_command=f"kubectl label pod {pod_name} -n {namespace} security.threatguard.io/quarantine=true --overwrite --dry-run=client",
                    execution_command=(
                        f"kubectl label pod {pod_name} -n {namespace} security.threatguard.io/quarantine=true --overwrite && "
                        f"cat << 'EOF' | kubectl apply -f -\n"
                        f"apiVersion: networking.k8s.io/v1\n"
                        f"kind: NetworkPolicy\n"
                        f"metadata:\n"
                        f"  name: tg-quarantine-{pod_name}\n"
                        f"  namespace: {namespace}\n"
                        f"spec:\n"
                        f"  podSelector:\n"
                        f"    matchLabels:\n"
                        f"      security.threatguard.io/quarantine: \"true\"\n"
                        f"  policyTypes:\n"
                        f"  - Ingress\n"
                        f"  - Egress\n"
                        f"EOF"
                    ),
                    blast_radius=f"Once labeled and applied, restricts inbound and outbound network connectivity specifically for pod {pod_name}.",
                    reversibility=f"Fully reversible: run 'kubectl delete networkpolicy tg-quarantine-{pod_name} -n {namespace}' and remove the label.",
                    requires_manual_review=True,
                ))
            rec_counter += 1

        # 3. Credential Rotation (T1552.007 SA Token or /etc/shadow access)
        if "T1552.007" in techniques or "T1003" in techniques:
            if workload.remediation_target:
                recs.append(ResponseRecommendation(
                    recommendation_id=f"REC-{rec_counter:02d}-REVOKE-TOKEN",
                    title=f"Revoke Compromised ServiceAccount Credentials & Disable Auto-Mount on {workload.remediation_target}",
                    priority=RecommendationPriority.CRITICAL.value,
                    category=ActionCategory.CREDENTIALS.value,
                    rationale="ServiceAccount JWT token was accessed via unauthorized read; token must be invalidated to prevent cluster API pivoting.",
                    dry_run_command=f"kubectl patch {workload.remediation_target} -n {namespace} --dry-run=client -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"automountServiceAccountToken\":false}}}}}}}}'",
                    execution_command=f"kubectl patch {workload.remediation_target} -n {namespace} -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"automountServiceAccountToken\":false}}}}}}}}'",
                    blast_radius=f"Removes default API token mount on subsequent rollout of {workload.remediation_target}.",
                    reversibility="Reversible: patch automountServiceAccountToken back to true if required."
                ))
            else:
                recs.append(ResponseRecommendation(
                    recommendation_id=f"REC-{rec_counter:02d}-REVOKE-TOKEN-MANUAL",
                    title=f"Manually Revoke Compromised ServiceAccount Credentials for Pod {pod_name}",
                    priority=RecommendationPriority.CRITICAL.value,
                    category=ActionCategory.MANUAL_REVIEW.value,
                    rationale=(
                        "ServiceAccount JWT token was accessed via unauthorized read, but the "
                        f"owning controller could not be safely determined ({workload.manual_reason}) "
                        "so no automatic patch command was generated."
                    ),
                    dry_run_command=f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.metadata.ownerReferences}}'",
                    execution_command=f"# Manual remediation required: identify the controller owning pod {pod_name} in {namespace} and disable automountServiceAccountToken on it directly.",
                    blast_radius="N/A (no automatic action taken).",
                    reversibility="N/A (no automatic action taken).",
                    requires_manual_review=True,
                ))
            rec_counter += 1

        # 4. Suspected Node Compromise / Escape to Host (T1611 or SYS_ADMIN)
        if "T1611" in techniques or "T1548" in techniques:
            recs.append(ResponseRecommendation(
                recommendation_id=f"REC-{rec_counter:02d}-CORDON-NODE",
                title=f"Cordon Node {node_name} to Prevent Workload Contamination",
                priority=RecommendationPriority.CRITICAL.value,
                category=ActionCategory.NODE_SECURITY.value,
                rationale="Suspected container escape or host namespace abuse requires cordoning the host node while forensic triage continues.",
                dry_run_command=f"kubectl cordon {node_name} --dry-run=client",
                execution_command=f"kubectl cordon {node_name}",
                blast_radius=f"Prevents new pods from being scheduled onto node {node_name}.",
                reversibility=f"Reversible: run 'kubectl uncordon {node_name}'"
            ))
            rec_counter += 1

        # 5. Controlled Workload Termination / Restart
        if workload.remediation_target:
            recs.append(ResponseRecommendation(
                recommendation_id=f"REC-{rec_counter:02d}-CONTROLLED-DRAIN",
                title=f"Scale Down Compromised {workload.owner_kind} {workload.owner_name}",
                priority=RecommendationPriority.MEDIUM.value,
                category=ActionCategory.CONTAINMENT.value,
                rationale="Terminates rogue container instances once forensics have been captured to eradicate active adversary persistence.",
                dry_run_command=f"kubectl scale {workload.remediation_target} -n {namespace} --replicas=0 --dry-run=client",
                execution_command=f"kubectl scale {workload.remediation_target} -n {namespace} --replicas=0",
                blast_radius=f"Stops all running replica instances of {workload.remediation_target} in namespace {namespace}.",
                reversibility=f"Reversible: run 'kubectl scale {workload.remediation_target} -n {namespace} --replicas=1'"
            ))
        else:
            recs.append(ResponseRecommendation(
                recommendation_id=f"REC-{rec_counter:02d}-CONTROLLED-DRAIN-MANUAL",
                title=f"Manually Terminate Compromised Pod {pod_name}",
                priority=RecommendationPriority.MEDIUM.value,
                category=ActionCategory.MANUAL_REVIEW.value,
                rationale=(
                    "Rogue container instances should be terminated once forensics have been "
                    f"captured, but the owning controller could not be safely determined "
                    f"({workload.manual_reason}), so no automatic scale-down command was generated."
                ),
                dry_run_command=f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.metadata.ownerReferences}}'",
                execution_command=f"# Manual remediation required: confirm ownership of pod {pod_name} in {namespace} before terminating it directly with 'kubectl delete pod {pod_name} -n {namespace}'.",
                blast_radius="N/A (no automatic action taken).",
                reversibility="N/A (no automatic action taken; a standalone Pod deleted directly will not be recreated).",
                requires_manual_review=True,
            ))
        rec_counter += 1

        # 6. Policy Hardening (Gatekeeper Admission Enforcement)
        recs.append(ResponseRecommendation(
            recommendation_id=f"REC-{rec_counter:02d}-GATEKEEPER-ENFORCE",
            title="Enforce Gatekeeper Constraint & Baseline Pod Security Standard",
            priority=RecommendationPriority.LOW.value,
            category=ActionCategory.HARDENING.value,
            rationale="Prevents root escalation, host mounts, and privileged containers from being admitted into the namespace in the future.",
            dry_run_command=f"kubectl label namespace {namespace} pod-security.kubernetes.io/enforce=baseline --dry-run=client",
            execution_command=f"kubectl label namespace {namespace} pod-security.kubernetes.io/enforce=baseline --overwrite",
            blast_radius=f"Applies baseline admission validation to future pod creation requests in {namespace}.",
            reversibility="Reversible: adjust or remove namespace label."
        ))

        return recs
