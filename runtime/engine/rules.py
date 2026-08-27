"""
Detection rules mapping runtime behaviors to structured security events and MITRE ATT&CK techniques.
"""

from typing import Dict, Any, List, Optional
from .models import ThreatGuardDetection

DETECTION_RULES = {
    "RUNTIME-001": {
        "rule_id": "RUNTIME-001",
        "detection_name": "Interactive Shell Execution in Workload Container",
        "technique": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "severity": "CRITICAL",
        "event_type": "process_exec",
        "target_binaries": ["sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"],
        "description": "An interactive shell binary was spawned within an application container, indicating interactive access or post-exploitation execution."
    },
    "RUNTIME-002": {
        "rule_id": "RUNTIME-002",
        "detection_name": "Suspicious Network Utility Ingress/Egress Tool",
        "technique": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "severity": "HIGH",
        "event_type": "process_exec",
        "target_binaries": ["curl", "wget", "nc", "netcat", "socat", "nmap", "/usr/bin/curl", "/usr/bin/wget"],
        "description": "A networking utility commonly used to stage secondary payloads, download external binaries, or establish reverse shells was executed."
    },
    "RUNTIME-003": {
        "rule_id": "RUNTIME-003",
        "detection_name": "Host and Environment Reconnaissance Execution",
        "technique": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "event_type": "process_exec",
        "target_binaries": ["whoami", "id", "uname", "ps", "env", "/usr/bin/whoami", "/usr/bin/id", "/bin/uname"],
        "description": "Standard reconnaissance binaries were executed to gather information on permissions, operating environment, or container architecture."
    },
    "RUNTIME-004": {
        "rule_id": "RUNTIME-004",
        "detection_name": "Sensitive Credential or Filesystem Access",
        "technique": "T1552.007",
        "technique_name": "Unsecured Credentials: Container and Resource Discovery",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "event_type": "file_access",
        "target_paths": [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/etc/shadow",
            "/etc/gshadow",
            "/root/.ssh"
        ],
        "description": "An attempt to read sensitive credential files or the Kubernetes ServiceAccount token was captured via kernel file-open tracing."
    },
    "RUNTIME-005": {
        "rule_id": "RUNTIME-005",
        "detection_name": "Container Privilege Escalation Indicator",
        "technique": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "severity": "CRITICAL",
        "event_type": "priv_escalation",
        "target_binaries": ["nsenter", "unshare", "capsh", "chroot", "/usr/bin/nsenter", "/sbin/capsh"],
        "description": "Execution of binaries designed to manipulate namespaces, inspect or modify process capability bounds, or attempt container breakout."
    },
    "RUNTIME-006": {
        "rule_id": "RUNTIME-006",
        "detection_name": "Unexpected Outbound Network Connection",
        "technique": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "severity": "HIGH",
        "event_type": "network_connect",
        "description": "An unexpected outbound network socket connection was established by the application workload."
    }
}
