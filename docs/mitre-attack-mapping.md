# CloudNative ThreatGuard — MITRE ATT&CK Mapping

This document provides technical mapping between CloudNative ThreatGuard runtime detection rules, MITRE ATT&CK Tactics, Techniques, threat rationales, and observed kernel-level eBPF telemetry.

---

## Technical Mapping Matrix

| Rule ID | Detection Name | MITRE ID | Tactic | Sub-technique / Name | Severity | Threat Rationale | Observed eBPF Telemetry |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RUNTIME-001** | Interactive Shell Execution | **T1059.004** | Execution | Command and Scripting Interpreter: Unix Shell | `CRITICAL` | Spawning `/bin/sh`, `/bin/bash`, or `/bin/zsh` inside an application container indicates interactive manual access, reverse shell initiation, or script exploitation. | `sys_enter_execve` syscall on binary matching `*sh` with PID, UID, and parent process binary. |
| **RUNTIME-002** | Suspicious Network Utility | **T1105** | Command and Control | Ingress Tool Transfer | `HIGH` | Utilities like `curl`, `wget`, `nc`, or `socat` are commonly used by attackers to stage secondary payloads or create ad-hoc data exfiltration tunnels. | `sys_enter_execve` syscall on networking binaries with CLI arguments capturing remote URLs or ports. |
| **RUNTIME-003** | Host & Environment Reconnaissance | **T1082** / **T1087** | Discovery | System Information Discovery / Account Discovery | `MEDIUM` | Attackers execute commands such as `id`, `whoami`, `uname -a`, and `env` immediately post-compromise to evaluate privilege boundaries and operating environment. | `sys_enter_execve` syscall capturing binary path, calling user ID, and process execution context. |
| **RUNTIME-004** | Sensitive Filesystem Access | **T1552.007** | Credential Access | Unsecured Credentials: Container and Resource Discovery | `CRITICAL` | Reading the projected ServiceAccount token (`/var/run/secrets/.../token`) or `/etc/shadow` enables API token theft and cluster-wide privilege escalation. | `security_file_open` LSM hook / kprobe capturing file path prefix and access flags. |
| **RUNTIME-005** | Privilege Escalation Indicator | **T1068** / **T1611** | Privilege Escalation | Exploitation for Privilege Escalation / Escape to Host | `CRITICAL` | Running binaries such as `nsenter`, `unshare`, `capsh`, or `chroot` indicates attempts to break out of namespace isolation or manipulate Linux capabilities. | `sys_enter_execve` on namespace tools, combined with process effective capability set inspection (`cap_effective`). |
| **RUNTIME-006** | Outbound Network Connection | **T1071** | Command and Control | Application Layer Protocol | `HIGH` | Unexpected outbound socket connections from the application container suggest command-and-control beacons or unauthorized data exfiltration. | `sys_enter_connect` syscall capturing socket file descriptor, destination IPv4/IPv6 address, and destination TCP/UDP port. |

---

## Telemetry Examples

### 1. RUNTIME-001: Shell Execution
```json
{
  "event_id": "30c28419-5e56-4f40-9ef9-89e224b849b9",
  "timestamp": "2026-09-05T18:30:01Z",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "simulation-target",
  "process": "/bin/sh",
  "command": "/bin/sh -c whoami",
  "event_type": "process_exec",
  "severity": "CRITICAL",
  "detection_name": "Interactive Shell Execution in Workload Container",
  "rule_id": "RUNTIME-001",
  "technique": "T1059.004",
  "technique_name": "Command and Scripting Interpreter: Unix Shell",
  "source": "eBPF / Tetragon",
  "evidence": {
    "binary": "/bin/sh",
    "arguments": "-c whoami",
    "pid": 5101,
    "uid": 10001
  }
}
```

### 2. RUNTIME-004: Sensitive Credential Access
```json
{
  "event_id": "84c01e82-e612-4217-bfbb-8b17326b52a1",
  "timestamp": "2026-09-05T18:30:04Z",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "simulation-target",
  "process": "/bin/cat",
  "command": "read /var/run/secrets/kubernetes.io/serviceaccount/token",
  "event_type": "file_access",
  "severity": "CRITICAL",
  "detection_name": "Sensitive Credential or Filesystem Access",
  "rule_id": "RUNTIME-004",
  "technique": "T1552.007",
  "technique_name": "Unsecured Credentials: Container and Resource Discovery",
  "source": "eBPF / Tetragon",
  "evidence": {
    "accessed_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "process": "/bin/cat",
    "syscall": "security_file_open"
  }
}
```
