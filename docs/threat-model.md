# CloudNative ThreatGuard — Threat Model & Risk Analysis

This threat model outlines the adversarial scenarios, potential attack paths, preventive controls, detective controls, and residual risks across the lifecycle of containerized workloads.

---

## 1. Threat Analysis Matrix

| Threat ID | Threat Description | Attack Path | Preventive Control (Gatekeeper) | Detective Control (eBPF Runtime) | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | **Insecure Developer Deployment** | Developer or CI pushes a manifest requesting `privileged: true`, `hostPID: true`, or root filesystem access. | **k8sprivilegedcontainer** & **k8shostnamespaces**: Admission webhook blocks the manifest before creation. | Cluster-level audit logs capture rejected admission requests. | Misconfigurations applied before Gatekeeper webhook initialization or in exempt namespaces. |
| **THREAT-02** | **Host Filesystem / Socket Hijack** | Workload mounts `/var/run/docker.sock` or host root `/` to take over the underlying node. | **k8shostfilesystem**: Blocks mounts matching node root or container runtime sockets. | eBPF monitoring of unauthorized `openat` and `mount` calls on the host node. | Zero-day vulnerabilities in container runtime mount handlers. |
| **THREAT-03** | **Container Privilege Escalation** | Attacker executes a setuid/setgid binary or uses capability manipulation (`capsh`, `nsenter`) to escalate to root. | **k8sprivilegeescalation** (`allowPrivilegeEscalation: false`) & **k8sdropcapabilities** (drop `ALL`). | **RUNTIME-005**: Tetragon traces `sys_enter_execve` for `capsh`, `nsenter`, and namespace unsharing. | Unpatched Linux kernel privilege escalation vulnerabilities (e.g., Dirty COW, Dirty Pipe). |
| **THREAT-04** | **Application RCE & Shell Access** | Vulnerability in web application (SQLi, deserialization, command injection) allows attacker to spawn an interactive shell. | Cannot be prevented at admission time (application code is valid YAML). | **RUNTIME-001**: Tetragon detects `sys_enter_execve` for `/bin/sh`, `/bin/bash`, `/bin/dash` and terminates the process. | Sub-millisecond execution before eBPF signal termination or in-process memory-only code injection. |
| **THREAT-05** | **Ingress Tool Transfer (Staging)** | Attacker uses `curl` or `wget` inside the container to download secondary exploitation scripts. | **k8sreadonlyrootfs**: Prohibits saving binaries to root filesystem; NetworkPolicy restricts outbound egress. | **RUNTIME-002**: Tetragon traces execution of network tools (`curl`, `wget`, `nc`, `socat`). | Tool functionality implemented directly using language libraries (e.g., native Python `urllib` / sockets). |
| **THREAT-06** | **Environment Reconnaissance** | Attacker runs `id`, `whoami`, `uname -a`, and `env` to fingerprint container and secrets. | Non-root enforcement ensures limited user permissions (UID 10001). | **RUNTIME-003**: Tetragon detects reconnaissance binaries and flags Discovery behavior. | Reading environment variables directly from `/proc/self/environ` without spawning binaries. |
| **THREAT-07** | **ServiceAccount Token Theft** | Attacker accesses `/var/run/secrets/kubernetes.io/serviceaccount/token` to authenticate to the Kubernetes API. | `automountServiceAccountToken: false` where practical. | **RUNTIME-004**: Tetragon monitors `security_file_open` on the token path and raises a Critical alert. | Memory scraping of tokens loaded in-memory by Kubernetes SDKs. |
| **THREAT-08** | **C2 & Lateral Movement** | Compromised container initiates unauthorized TCP connections to external IP or cluster services. | **Kubernetes NetworkPolicy**: Restricts pod egress to CoreDNS (port 53) only. | **RUNTIME-006**: Tetragon monitors `sys_enter_connect` to flag unauthorized egress attempts. | DNS tunneling or authorized communication channels to permitted endpoints. |

---

## 2. STRIDE Threat Categorization

- **Spoofing**: Impersonation of cluster identities via stolen ServiceAccount tokens (**THREAT-07**).
- **Tampering**: Modifying binaries or configuration files on the container root filesystem (**THREAT-05**).
- **Repudiation**: Undetected malicious process execution inside approved containers (**THREAT-04**, **THREAT-06**).
- **Information Disclosure**: Exposing host files, kernel memory, or container tokens (**THREAT-02**, **THREAT-07**).
- **Denial of Service**: CPU/memory starvation or network interface flooding mitigated via resource limits and hostNetwork prohibition.
- **Elevation of Privilege**: Container breakouts and root user escalation (**THREAT-01**, **THREAT-03**).
