# CloudNative ThreatGuard — MITRE ATT&CK for Containers Matrix Mapping

This document provides the authoritative technical mapping between CloudNative ThreatGuard security signals, MITRE ATT&CK for Containers Tactics & Techniques, threat rationales, prevention controls (OPA Gatekeeper), detection controls (Cilium Tetragon eBPF), and observable telemetry data sources.

---

## 1. Comprehensive MITRE ATT&CK for Containers Matrix

| Tactic | Technique ID | Technique / Subtechnique Name | Data Source | Prevention Control (Admission) | Detection Control (Runtime eBPF) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | **T1190** | Exploit Public-Facing Application | Network Traffic, Application Logs | Ingress TLS termination, minimal base images, image vulnerability scans | Tetragon `process_exec` tracing abnormal child processes spawned from web workers |
| **Execution** | **T1059.004** | Command & Scripting Interpreter: Unix Shell | Process Execution (`sys_enter_execve`) | Distroless images without `/bin/sh` or `/bin/bash`; Read-only rootfs | ThreatGuard `RUNTIME-001` tracing `*sh`, `bash`, `zsh` inside containers |
| **Execution** | **T1609** | Container Administration Command | Kubernetes API Audit, Kubelet Exec | RBAC restricting `pods/exec`; namespace isolation guardrails | Tetragon tracing process executions spawned via containerd shim / kubelet |
| **Persistence** | **T1525** | Implant Internal Image | Container Registry Logs, Image Digest | Gatekeeper allowed image registries constraint; Cosign signature verification | Admission webhook blocking unapproved registries and mutable latest tags |
| **Persistence** | **T1053.007** | Scheduled Task/Job: Container / K8s CronJob | K8s API Audit, In-container Crontab | RBAC restricting CronJob creation; Read-only root filesystem | Gatekeeper admission inspection and eBPF file-write tracing on `/etc/cron*` |
| **Privilege Escalation** | **T1611** | Escape to Host | Kernel Syscalls, Linux Namespace Events | Gatekeeper blocking `privileged: true`, `hostPID`, `hostIPC`, `hostNetwork`, `/var/run/docker.sock` | ThreatGuard `RUNTIME-005` & `RULE-K8S-008` tracing `setns`, `unshare`, and `nsenter` |
| **Privilege Escalation** | **T1068** | Exploitation for Privilege Escalation | Process Capabilities, Setuid Executions | Gatekeeper enforcing `allowPrivilegeEscalation: false` and dropping `ALL` capabilities | Tetragon kprobes on `capset` and `sys_enter_execve` on setuid binaries |
| **Defense Evasion** | **T1610** | Deploy Container | Kubernetes API Admission Webhook | OPA Gatekeeper validating admission webhooks enforcing Pod Security Standards | ThreatGuard Admission Violation Normalizer emitting structured `SecurityEvent` |
| **Defense Evasion** | **T1562.001** | Impair Defenses: Disable or Modify Tools | Process Signals, File Deletions | Running security agents as DaemonSets in protected system namespaces | Tetragon self-monitoring and alerting on `SIGKILL`/`SIGTERM` to security daemons |
| **Credential Access** | **T1552.007** | Unsecured Credentials: SA Token Access | Filesystem Access (`security_file_open`) | `automountServiceAccountToken: false` on Pod and ServiceAccount specs | ThreatGuard `RUNTIME-004` kprobe on `security_file_open` targeting token paths |
| **Credential Access** | **T1003** | OS Credential Dumping | File Access, Memory Inspection | Gatekeeper enforcing `runAsNonRoot: true`; read-only root filesystems | ThreatGuard `RUNTIME-004` eBPF kprobe targeting `/etc/shadow` and `/etc/gshadow` |
| **Discovery** | **T1082** | System Information Discovery | Process Execution | Minimal container images removing discovery utilities | ThreatGuard `RUNTIME-003` tracing `uname`, `whoami`, `id`, `env`, `ps` |
| **Discovery** | **T1613** | Container and Resource Discovery | Network Sockets, CLI Arguments | NetworkPolicies blocking egress to metadata endpoints (`169.254.169.254`) | Tetragon `sys_enter_connect` tracing connections to metadata and K8s API service |
| **Lateral Movement** | **T1210** | Exploitation of Remote Services | Network Connection Events (`sys_enter_connect`) | Default-deny ingress and egress Kubernetes NetworkPolicies | Tetragon network tracing monitoring internal port scanning and unauthorized cross-namespace traffic |
| **Exfiltration / C2** | **T1105** | Ingress Tool Transfer | Process Execution, Network Sockets | Read-only root filesystems; strict egress NetworkPolicy | ThreatGuard `RUNTIME-002` tracing `curl`, `wget`, `nc`, `socat`, `nmap` |
| **Exfiltration / C2** | **T1071.001** | Application Layer Protocol: Web Protocols | Socket Connections (`sys_enter_connect`) | Strict egress NetworkPolicy; egress DNS proxying | ThreatGuard `RUNTIME-006` monitoring outbound socket connections to public IPs |
| **Impact** | **T1496** | Resource Hijacking: Cryptomining | Process Metrics, Outbound Mining Ports | Workload resource quotas, CPU limits, admission image scanning | Tetragon network connect monitoring for connections to known cryptomining pool ports |

---

## 2. Telemetry and Event Schema Examples

### 2.1 RUNTIME-001 (Execution: T1059.004)
```json
{
  "event_id": "ev-7f41a8c0d12e",
  "timestamp": "2026-09-05T18:30:01Z",
  "event_type": "runtime_detection",
  "source": "tetragon",
  "cluster": "threatguard-local",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "simulation-target",
  "process": "/bin/sh",
  "action": "process_exec",
  "severity": "CRITICAL",
  "confidence": 0.98,
  "detection_rule": "RUNTIME-001",
  "mitre_technique": "T1059.004",
  "mitre_tactic": "Execution",
  "description": "Interactive Shell Execution in Workload Container",
  "metadata": {
    "binary": "/bin/sh",
    "arguments": "-i",
    "pid": 5101,
    "uid": 10001,
    "parent_process": "/usr/local/bin/python"
  }
}
```

### 2.2 RUNTIME-004 (Credential Access: T1552.007)
```json
{
  "event_id": "ev-9c12b4e3f810",
  "timestamp": "2026-09-05T18:30:04Z",
  "event_type": "runtime_detection",
  "source": "tetragon",
  "cluster": "threatguard-local",
  "namespace": "threatguard",
  "pod": "threatguard-target-pod",
  "container": "simulation-target",
  "process": "/bin/cat",
  "action": "file_read",
  "severity": "CRITICAL",
  "confidence": 0.96,
  "detection_rule": "RUNTIME-004",
  "mitre_technique": "T1552.007",
  "mitre_tactic": "Credential Access",
  "description": "Sensitive Credential or Filesystem Access",
  "metadata": {
    "accessed_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "process": "/bin/cat",
    "syscall": "security_file_open"
  }
}
```
