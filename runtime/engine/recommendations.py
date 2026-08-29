"""
ThreatGuard Incident Response Recommendation Engine.
Produces actionable, non-destructive, and dry-run safe remediation playbooks for SOC analysts.
Enforces the 'Human-in-the-loop' principle: provides copy-pasteable kubectl commands with
defined blast radiuses and reversibility notes rather than blind auto-mutations.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


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

    def to_dict(self) -> Dict[str, Any]:
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
        techniques: List[str],
        severity: str = "HIGH",
        node_name: str = "threatguard-local-control-plane",
        container_name: str = "app"
    ) -> List[ResponseRecommendation]:
        recs: List[ResponseRecommendation] = []
        rec_counter = 1

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
            netpol_yaml = (
                f"apiVersion: networking.k8s.io/v1\n"
                f"kind: NetworkPolicy\n"
                f"metadata:\n"
                f"  name: tg-quarantine-{pod_name}\n"
                f"  namespace: {namespace}\n"
                f"spec:\n"
                f"  podSelector:\n"
                f"    matchLabels:\n"
                f"      app: {pod_name}\n"
                f"  policyTypes:\n"
                f"  - Ingress\n"
                f"  - Egress"
            )
            recs.append(ResponseRecommendation(
                recommendation_id=f"REC-{rec_counter:02d}-NET-QUARANTINE",
                title=f"Isolate Workload {pod_name} via Default-Deny NetworkPolicy",
                priority=RecommendationPriority.CRITICAL.value if severity == "CRITICAL" else RecommendationPriority.HIGH.value,
                category=ActionCategory.QUARANTINE.value,
                rationale="Cuts off active reverse shells, C2 beacons, and lateral movement probes immediately.",
                dry_run_command=f"cat << 'EOF' | kubectl apply --dry-run=client -f -\n{netpol_yaml}\nEOF",
                execution_command=f"cat << 'EOF' | kubectl apply -f -\n{netpol_yaml}\nEOF",
                blast_radius=f"Restricts inbound and outbound network connectivity specifically for pod {pod_name}.",
                reversibility=f"Fully reversible: run 'kubectl delete networkpolicy tg-quarantine-{pod_name} -n {namespace}'"
            ))
            rec_counter += 1

        # 3. Credential Rotation (T1552.007 SA Token or /etc/shadow access)
        if "T1552.007" in techniques or "T1003" in techniques:
            recs.append(ResponseRecommendation(
                recommendation_id=f"REC-{rec_counter:02d}-REVOKE-TOKEN",
                title="Revoke Compromised ServiceAccount Credentials & Disable Auto-Mount",
                priority=RecommendationPriority.CRITICAL.value,
                category=ActionCategory.CREDENTIALS.value,
                rationale="ServiceAccount JWT token was accessed via unauthorized read; token must be invalidated to prevent cluster API pivoting.",
                dry_run_command=f"kubectl patch deployment {pod_name} -n {namespace} --dry-run=client -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"automountServiceAccountToken\":false}}}}}}}}'",
                execution_command=f"kubectl patch deployment {pod_name} -n {namespace} -p '{{\"spec\":{{\"template\":{{\"spec\":{{\"automountServiceAccountToken\":false}}}}}}}}'",
                blast_radius=f"Removes default API token mount on subsequent rollout of {pod_name}.",
                reversibility="Reversible: patch automountServiceAccountToken back to true if required."
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
        recs.append(ResponseRecommendation(
            recommendation_id=f"REC-{rec_counter:02d}-CONTROLLED-DRAIN",
            title=f"Scale Down Compromised Deployment {pod_name}",
            priority=RecommendationPriority.MEDIUM.value,
            category=ActionCategory.CONTAINMENT.value,
            rationale="Terminates rogue container instances once forensics have been captured to eradicate active adversary persistence.",
            dry_run_command=f"kubectl scale deployment {pod_name} -n {namespace} --replicas=0 --dry-run=client",
            execution_command=f"kubectl scale deployment {pod_name} -n {namespace} --replicas=0",
            blast_radius=f"Stops all running replica instances of {pod_name} in namespace {namespace}.",
            reversibility=f"Reversible: run 'kubectl scale deployment {pod_name} -n {namespace} --replicas=1'"
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
