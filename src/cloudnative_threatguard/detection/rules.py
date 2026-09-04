"""
Extensible Runtime Detection Rule Engine for CloudNative ThreatGuard.
Defines modular detection rules with MITRE ATT&CK mappings, confidence scores,
condition predicates, false-positive considerations, and recommended responses.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable

from cloudnative_threatguard.runtime.events import Severity


@dataclass
class DetectionRule:
    """
    Extensible detection rule definition.
    """
    rule_id: str
    name: str
    description: str
    severity: str
    confidence: float
    mitre_technique: str
    mitre_tactic: str
    technique_name: str
    event_source: str = "tetragon"
    event_type: str = "process_exec"
    enabled: bool = True
    target_binaries: List[str] = field(default_factory=list)
    target_paths: List[str] = field(default_factory=list)
    predicate: Optional[Callable[[Dict[str, Any]], bool]] = None
    false_positive_considerations: str = ""
    recommended_response: str = ""

    def evaluate(self, event_context: Dict[str, Any]) -> bool:
        """Evaluate if an event context matches this rule."""
        if not self.enabled:
            return False

        if self.predicate:
            try:
                return self.predicate(event_context)
            except Exception:
                return False

        # Default binary basename matching
        binary = event_context.get("binary", "") or event_context.get("process", "")
        if binary and self.target_binaries:
            basename = os.path.basename(binary).lower()
            if basename in self.target_binaries or binary in self.target_binaries:
                return True

        # Default path matching
        path = event_context.get("path", "") or event_context.get("file_path", "")
        if path and self.target_paths:
            for target in self.target_paths:
                if target in path:
                    return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict format for serialization and legacy compatibility."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "detection_name": self.name,  # Legacy alias
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "mitre_technique": self.mitre_technique,
            "technique": self.mitre_technique,  # Legacy alias
            "mitre_tactic": self.mitre_tactic,
            "tactic": self.mitre_tactic,  # Legacy alias
            "technique_name": self.technique_name,
            "event_source": self.event_source,
            "event_type": self.event_type,
            "target_binaries": self.target_binaries,
            "target_paths": self.target_paths,
            "false_positive_considerations": self.false_positive_considerations,
            "recommended_response": self.recommended_response
        }


class RuleRegistry:
    """
    Central repository and registry of security detection rules.
    """
    def __init__(self):
        self._rules: Dict[str, DetectionRule] = {}
        self._initialize_default_rules()

    def register(self, rule: DetectionRule):
        """Register a new detection rule."""
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        """Retrieve a rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self, enabled_only: bool = False) -> List[DetectionRule]:
        """Return all registered rules."""
        if enabled_only:
            return [r for r in self._rules.values() if r.enabled]
        return list(self._rules.values())

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
            return True
        return False

    def to_legacy_dict(self) -> Dict[str, Dict[str, Any]]:
        """Return backward-compatible dictionary of rules."""
        return {k: r.to_dict() for k, r in self._rules.items()}

    def _initialize_default_rules(self):
        default_rules = [
            DetectionRule(
                rule_id="RUNTIME-001",
                name="Interactive Shell Execution in Workload Container",
                description="An interactive shell binary was spawned within an application container, indicating interactive access or post-exploitation execution.",
                severity="CRITICAL",
                confidence=0.98,
                mitre_technique="T1059.004",
                mitre_tactic="Execution",
                technique_name="Command and Scripting Interpreter: Unix Shell",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"],
                false_positive_considerations="Legitimate container entrypoint scripts or authorized kubectl exec debugging.",
                recommended_response="Review container process parentage. Terminate offending shell process or isolate pod if unauthorized."
            ),
            DetectionRule(
                rule_id="RUNTIME-002",
                name="Suspicious Network Utility Ingress/Egress Tool",
                description="A networking utility commonly used to stage secondary payloads, download external binaries, or establish reverse shells was executed.",
                severity="HIGH",
                confidence=0.92,
                mitre_technique="T1105",
                mitre_tactic="Command and Control",
                technique_name="Ingress Tool Transfer",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["curl", "wget", "nc", "netcat", "socat", "nmap", "/usr/bin/curl", "/usr/bin/wget"],
                false_positive_considerations="Workload health checks or initialization scripts downloading assets during startup.",
                recommended_response="Verify binary signature, destination IP/URL, and correlate with egress NetworkPolicy logs."
            ),
            DetectionRule(
                rule_id="RUNTIME-003",
                name="Host and Environment Reconnaissance Execution",
                description="Standard reconnaissance binaries were executed to gather information on permissions, operating environment, or container architecture.",
                severity="MEDIUM",
                confidence=0.88,
                mitre_technique="T1082",
                mitre_tactic="Discovery",
                technique_name="System Information Discovery",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["whoami", "id", "uname", "ps", "env", "/usr/bin/whoami", "/usr/bin/id", "/bin/uname"],
                false_positive_considerations="Automated application diagnostic routines or monitoring agent discovery scripts.",
                recommended_response="Inspect process arguments and environment variables; monitor for subsequent lateral movement."
            ),
            DetectionRule(
                rule_id="RUNTIME-004",
                name="Sensitive Credential or Filesystem Access",
                description="An attempt to read sensitive credential files or the Kubernetes ServiceAccount token was captured via kernel file-open tracing.",
                severity="CRITICAL",
                confidence=0.96,
                mitre_technique="T1552.007",
                mitre_tactic="Credential Access",
                technique_name="Unsecured Credentials: Container and Resource Discovery",
                event_source="tetragon",
                event_type="file_access",
                target_paths=[
                    "/var/run/secrets/kubernetes.io/serviceaccount/token",
                    "/etc/shadow",
                    "/etc/gshadow",
                    "/root/.ssh"
                ],
                false_positive_considerations="Legitimate in-cluster Kubernetes client libraries querying the API server.",
                recommended_response="Revoke compromised ServiceAccount token, rotate cluster secrets, and enforce automountServiceAccountToken: false."
            ),
            DetectionRule(
                rule_id="RUNTIME-005",
                name="Container Privilege Escalation Indicator",
                description="Execution of binaries designed to manipulate namespaces, inspect or modify process capability bounds, or attempt container breakout.",
                severity="CRITICAL",
                confidence=0.95,
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
                technique_name="Exploitation for Privilege Escalation",
                event_source="tetragon",
                event_type="priv_escalation",
                target_binaries=["nsenter", "unshare", "capsh", "chroot", "/usr/bin/nsenter", "/sbin/capsh"],
                false_positive_considerations="Rare in production workloads; occasionally observed in low-level node debugging agents.",
                recommended_response="Immediately quarantine the pod, cordon the hosting node, and inspect host dmesg/auditd logs."
            ),
            DetectionRule(
                rule_id="RUNTIME-006",
                name="Unexpected Outbound Network Connection",
                description="An unexpected outbound network socket connection was established by the application workload.",
                severity="HIGH",
                confidence=0.90,
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                technique_name="Application Layer Protocol",
                event_source="tetragon",
                event_type="network_connect",
                false_positive_considerations="Legitimate external API dependencies or external database endpoints.",
                recommended_response="Verify destination domain in threat intel feeds; enforce strict egress NetworkPolicy."
            ),
            DetectionRule(
                rule_id="RUNTIME-007",
                name="Cryptocurrency Mining Process Execution",
                description="A known cryptocurrency mining binary was executed inside an application container, indicating unauthorized resource hijacking.",
                severity="CRITICAL",
                confidence=0.96,
                mitre_technique="T1496",
                mitre_tactic="Impact",
                technique_name="Resource Hijacking",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["xmrig", "minerd", "ccminer", "cpuminer", "cgminer", "ethminer"],
                false_positive_considerations="Legitimate GPU/CPU benchmarking tools sharing similar binary names; verify hash and destination pool.",
                recommended_response="Terminate the process immediately, quarantine the pod, and inspect outbound connections for mining-pool endpoints."
            ),
            DetectionRule(
                rule_id="RULE-K8S-007",
                name="Unauthorized Package Manager Execution in Container",
                description="Execution of package manager utilities (apt, apk, yum, pip) inside a running production container.",
                severity="HIGH",
                confidence=0.94,
                mitre_technique="T1072",
                mitre_tactic="Execution",
                technique_name="Software Deployment Tools",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["apt", "apt-get", "apk", "yum", "dnf", "pip", "/usr/bin/apt-get", "/sbin/apk"],
                false_positive_considerations="Container build / docker build phases (should never execute in running production pods).",
                recommended_response="Enforce read-only root filesystems and immutable container image policies."
            ),
            DetectionRule(
                rule_id="RULE-K8S-008",
                name="Pod Namespace Escape Attempt",
                description="Use of setns or unshare syscalls attempting to join host Linux namespaces.",
                severity="CRITICAL",
                confidence=0.98,
                mitre_technique="T1611",
                mitre_tactic="Privilege Escalation",
                technique_name="Escape to Host",
                event_source="tetragon",
                event_type="process_exec",
                target_binaries=["nsenter", "/usr/bin/nsenter"],
                false_positive_considerations="Authorized node agent daemonsets (e.g. CNI plugins, CSI drivers).",
                recommended_response="Terminate pod immediately; verify Gatekeeper hostPID and privileged constraints."
            ),
            DetectionRule(
                rule_id="RULE-K8S-009",
                name="Admission Policy Violation Burst",
                description="Multiple rejected workload admission requests within a short time interval indicating probe testing or GitOps compromise.",
                severity="HIGH",
                confidence=0.91,
                mitre_technique="T1610",
                mitre_tactic="Defense Evasion",
                technique_name="Deploy Container",
                event_source="opa_gatekeeper",
                event_type="admission_violation",
                false_positive_considerations="Developer misconfiguration during active deployment iterations.",
                recommended_response="Audit API server audit logs for submitting identity and source IP address."
            )
        ]

        for rule in default_rules:
            self.register(rule)


# Singleton registry instance
registry = RuleRegistry()

# Backwards compatible dictionary exposed for legacy callers
DETECTION_RULES: Dict[str, Dict[str, Any]] = registry.to_legacy_dict()
