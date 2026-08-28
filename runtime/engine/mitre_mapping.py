"""
MITRE ATT&CK for Containers Matrix Mapping for CloudNative ThreatGuard.
Provides comprehensive taxonomy covering tactics, techniques, subtechniques,
data sources, detection rationales, prevention controls, and detection controls.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional


@dataclass
class MitreTechniqueMapping:
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str]
    subtechnique_name: Optional[str]
    data_source: str
    detection_rationale: str
    prevention_control: str
    detection_control: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


MITRE_CONTAINER_MATRIX: Dict[str, MitreTechniqueMapping] = {
    "T1190": MitreTechniqueMapping(
        tactic="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Network Traffic, Application Logs",
        detection_rationale="Adversaries exploit web application vulnerabilities (e.g. RCE, SQLi, command injection) to gain initial execution in the container.",
        prevention_control="WAF, Ingress TLS termination, container minimal base images, vulnerability scanning.",
        detection_control="Tetragon process_exec tracing spawning unexpected binaries from web server worker processes."
    ),
    "T1059.004": MitreTechniqueMapping(
        tactic="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.004",
        subtechnique_name="Unix Shell",
        data_source="Process Execution (sys_enter_execve)",
        detection_rationale="Spawning interactive Unix shells (/bin/sh, /bin/bash, /bin/zsh) inside running production workloads indicates interactive intrusion or script-based attack execution.",
        prevention_control="Distroless / scratch container images without shells; read-only root filesystems.",
        detection_control="ThreatGuard RULE-K8S-001 via Tetragon eBPF (sys_enter_execve filter on shell binary names)."
    ),
    "T1609": MitreTechniqueMapping(
        tactic="Execution",
        technique_id="T1609",
        technique_name="Container Administration Command",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Kubernetes API Audit Logs, Kubelet Exec",
        detection_rationale="Execution of commands inside a container via kubectl exec or container engine API.",
        prevention_control="RBAC restricting pods/exec permission; production namespace boundary policies.",
        detection_control="Tetragon execve tracing correlating process parentage with kubelet/containerd."
    ),
    "T1525": MitreTechniqueMapping(
        tactic="Persistence",
        technique_id="T1525",
        technique_name="Implant Internal Image",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Container Registry Logs, Image Digest Verification",
        detection_rationale="Adversaries tamper with container registries or CI build pipelines to inject malicious layers into trusted images.",
        prevention_control="Gatekeeper image registry whitelist, Cosign signature verification, immutable tags.",
        detection_control="Admission policy evaluation blocking unapproved image registries and non-pinned image tags."
    ),
    "T1053.007": MitreTechniqueMapping(
        tactic="Persistence",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        subtechnique_id="T1053.007",
        subtechnique_name="Container Crontab / Kubernetes CronJob",
        data_source="Kubernetes API Audit, Cron Service Logs",
        detection_rationale="Adversaries establish persistence by creating malicious Kubernetes CronJobs or in-container crontabs.",
        prevention_control="RBAC restricting batch/v1 CronJob creation; read-only root filesystem preventing /etc/cron edits.",
        detection_control="Gatekeeper admission validation on CronJob manifests and file-write monitoring on cron directories."
    ),
    "T1611": MitreTechniqueMapping(
        tactic="Privilege Escalation",
        technique_id="T1611",
        technique_name="Escape to Host",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Kernel Syscalls, Linux Namespace Events",
        detection_rationale="Adversaries break out of container containment into the host operating system using privileged capabilities, host mounts, or kernel vulnerabilities.",
        prevention_control="Gatekeeper blocking privileged containers, hostPID, hostIPC, hostNetwork, and docker.sock mounts.",
        detection_control="ThreatGuard RULE-K8S-005 and RULE-K8S-008 monitoring setns, unshare, and nsenter invocations."
    ),
    "T1068": MitreTechniqueMapping(
        tactic="Privilege Escalation",
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Process Capabilities, Setuid Executions",
        detection_rationale="Exploiting setuid binaries or Linux kernel vulnerabilities to elevate effective user ID or expand capability set.",
        prevention_control="Gatekeeper enforcing allowPrivilegeEscalation: false and dropping ALL capabilities.",
        detection_control="Tetragon kprobe monitoring capset and execve on setuid binaries."
    ),
    "T1610": MitreTechniqueMapping(
        tactic="Defense Evasion",
        technique_id="T1610",
        technique_name="Deploy Container",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Kubernetes API Admission Webhook",
        detection_rationale="Adversaries attempt to deploy insecure or malicious containers to bypass existing cluster controls.",
        prevention_control="OPA Gatekeeper validating admission webhooks enforcing Pod Security Standards.",
        detection_control="ThreatGuard Admission Violation Normalizer emitting SecurityEvent alerts for rejected requests."
    ),
    "T1562.001": MitreTechniqueMapping(
        tactic="Defense Evasion",
        technique_id="T1562",
        technique_name="Impair Defenses",
        subtechnique_id="T1562.001",
        subtechnique_name="Disable or Modify Tools",
        data_source="Process Signals, File Deletions",
        detection_rationale="Adversaries attempt to kill monitoring agents, delete audit logs, or unload eBPF programs.",
        prevention_control="Run monitoring agents as DaemonSets in protected, unprivileged namespaces with immutable configurations.",
        detection_control="Tetragon self-monitoring and alert emission on SIGKILL/SIGTERM signals to defense daemons."
    ),
    "T1552.007": MitreTechniqueMapping(
        tactic="Credential Access",
        technique_id="T1552",
        technique_name="Unsecured Credentials",
        subtechnique_id="T1552.007",
        subtechnique_name="Container and Resource Discovery",
        data_source="File System Access (security_file_open)",
        detection_rationale="Reading the projected Kubernetes ServiceAccount token from /var/run/secrets/kubernetes.io/serviceaccount/token to authenticate against the API server.",
        prevention_control="automountServiceAccountToken: false on Pod and ServiceAccount specifications.",
        detection_control="ThreatGuard RULE-K8S-004 eBPF kprobe on security_file_open targeting token paths."
    ),
    "T1003": MitreTechniqueMapping(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="File Access, Memory Inspection",
        detection_rationale="Accessing /etc/shadow, /etc/gshadow, or dumping process memory to extract cleartext passwords or hashes.",
        prevention_control="Gatekeeper enforcing runAsNonRoot: true; read-only root filesystems.",
        detection_control="ThreatGuard RULE-K8S-004 eBPF kprobe on security_file_open targeting /etc/shadow."
    ),
    "T1082": MitreTechniqueMapping(
        tactic="Discovery",
        technique_id="T1082",
        technique_name="System Information Discovery",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Process Execution",
        detection_rationale="Executing system discovery commands (uname, hostname, uptime) to profile host architecture and kernel version.",
        prevention_control="Minimal container images removing unnecessary command-line utilities.",
        detection_control="ThreatGuard RULE-K8S-003 monitoring execution of discovery binaries."
    ),
    "T1613": MitreTechniqueMapping(
        tactic="Discovery",
        technique_id="T1613",
        technique_name="Container and Resource Discovery",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Network Sockets, Process Arguments",
        detection_rationale="Querying Kubernetes API endpoints or cloud provider metadata services (169.254.169.254) to discover cluster resources.",
        prevention_control="NetworkPolicies blocking egress to cloud metadata endpoints and unauthorized API server access.",
        detection_control="Tetragon network connect tracing monitoring connections to 169.254.169.254 and the K8s API service."
    ),
    "T1210": MitreTechniqueMapping(
        tactic="Lateral Movement",
        technique_id="T1210",
        technique_name="Exploitation of Remote Services",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Network Connection Events (sys_enter_connect)",
        detection_rationale="Scanning and exploiting neighboring pods or cluster internal services from a compromised container.",
        prevention_control="Default-deny ingress and egress Kubernetes NetworkPolicies; Cilium network security policies.",
        detection_control="Tetragon network connect tracing monitoring internal port scanning and unauthorized cross-namespace traffic."
    ),
    "T1105": MitreTechniqueMapping(
        tactic="Command and Control",
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Process Execution, Network Connections",
        detection_rationale="Downloading remote attack payloads, scripts, or exploitation tools into the container using curl, wget, or nc.",
        prevention_control="Read-only root filesystems; strict egress NetworkPolicies restricting outbound Internet traffic.",
        detection_control="ThreatGuard RULE-K8S-002 monitoring network tool execution and payload staging."
    ),
    "T1071.001": MitreTechniqueMapping(
        tactic="Command and Control",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        subtechnique_id="T1071.001",
        subtechnique_name="Web Protocols",
        data_source="Socket Connections (sys_enter_connect)",
        detection_rationale="Establishing outbound HTTP/HTTPS connections to command-and-control servers or data exfiltration drop points.",
        prevention_control="Strict egress filtering via NetworkPolicy; DNS egress proxying.",
        detection_control="ThreatGuard RULE-K8S-006 monitoring outbound connections to external public IP addresses."
    ),
    "T1496": MitreTechniqueMapping(
        tactic="Impact",
        technique_id="T1496",
        technique_name="Resource Hijacking",
        subtechnique_id=None,
        subtechnique_name=None,
        data_source="Process Metrics, Outbound Mining Pools",
        detection_rationale="Deploying cryptocurrency mining malware inside pods to hijack cluster CPU and memory resources.",
        prevention_control="Workload resource quotas, CPU limits, admission image scanning.",
        detection_control="Tetragon network connect monitoring for connections to known cryptomining pool ports and domains."
    )
}


def get_mitre_mapping(technique_id: str) -> Optional[MitreTechniqueMapping]:
    """Retrieve mapping for a technique or subtechnique ID."""
    if technique_id in MITRE_CONTAINER_MATRIX:
        return MITRE_CONTAINER_MATRIX[technique_id]
    # Check if technique_id is a base technique or subtechnique match
    for k, v in MITRE_CONTAINER_MATRIX.items():
        if v.subtechnique_id == technique_id or v.technique_id == technique_id:
            return v
    return None


def list_tactics() -> List[str]:
    """Return all unique tactics represented in the matrix."""
    tactics = []
    for m in MITRE_CONTAINER_MATRIX.values():
        if m.tactic not in tactics:
            tactics.append(m.tactic)
    return tactics
