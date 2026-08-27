# CloudNative ThreatGuard — Cross-Platform Environment Guide

This guide details the operating system and kernel prerequisites for running, testing, and developing CloudNative ThreatGuard across Linux, macOS, and Windows with WSL2.

---

## 1. The Kernel Reality of eBPF

**Extended Berkeley Packet Filter (eBPF)** is an in-kernel virtual machine native to the **Linux Kernel**. It attaches bytecode directly to kernel tracepoints, kprobes, and Linux Security Module (LSM) hooks.

Because eBPF operates inside the Linux kernel:
- **eBPF programs CANNOT run natively on the Windows NT kernel or the macOS Darwin kernel.**
- Running live eBPF runtime detection (Tetragon) on macOS or Windows requires a Linux virtual machine (such as Docker Desktop Linux VM, Colima, or WSL2).

---

## 2. Platform Compatibility Matrix

| Component | Linux (Native) | Windows + WSL2 | macOS (Colima / Docker Desktop) | CI / GitHub Actions (Ubuntu) |
| :--- | :---: | :---: | :---: | :---: |
| **OPA Rego Policy Unit Tests** (`opa test`) | Full Native | Full Native | Full Native | Full Native |
| **Admission Manifest Validation** | Full Native | Full Native | Full Native | Full Native |
| **Static Security Scans & SBOM** | Full Native | Full Native | Full Native | Full Native |
| **Correlation & Detection Engine** | Full Native | Full Native | Full Native | Full Native |
| **Prometheus Exporter & Grafana** | Full Native | Full Native | Full Native | Full Native |
| **Kubernetes Admission Webhook** | Supported in KIND | Supported in KIND | Supported in KIND | Supported in KIND |
| **Live eBPF Runtime Tracing (Tetragon)** | **Native** (Kernel 5.4+) | **Supported via WSL2** (Kernel 5.15+ / 6.x) | **Supported via Linux VM** (Colima / OrbStack) | **Native** (Kernel 6.x runner) |

---

## 3. Platform-Specific Setup Instructions

### 3.1 Linux (Ubuntu, Debian, Fedora, RHEL)
Native Linux provides the ideal development and testing environment.
- **Kernel Requirement**: Linux Kernel 5.4 or higher (Kernel 5.15+ or 6.x recommended for full BTF / CO-RE and LSM support).
- **Mounts**: Ensure `/sys/kernel/debug` and `/sys/fs/bpf` are mounted:
  ```bash
  mount | grep bpf
  ```
- **KIND Cluster Creation**: Run `make cluster` or `bash scripts/setup-cluster.sh`.

### 3.2 Windows with WSL2
WSL2 runs a real Microsoft-maintained Linux kernel (Kernel 5.15+ / 6.x) inside a lightweight Hyper-V utility VM.
- **Prerequisites**: Windows 10/11 with WSL2 enabled and an Ubuntu distribution installed (`wsl --install -d Ubuntu-22.04`).
- **eBPF Support**: WSL2 kernel 5.15 and 6.x include BPF and BTF support enabled by default.
- **Docker Integration**: Enable "Use the WSL 2 based engine" and check "Enable integration with Ubuntu" under Docker Desktop settings.
- **Execution**: Run commands inside your WSL2 bash terminal:
  ```bash
  wsl -d Ubuntu-22.04
  cd /mnt/c/Users/<user>/Desktop/Project/Projects/CloudNative\ ThreatGuard
  make security-test
  ```

### 3.3 macOS (Apple Silicon / Intel)
macOS uses the Darwin kernel (XNU), not Linux.
- **Docker Desktop**: Runs a lightweight Linux VM under the hood. To mount eBPF debug filesystems, KIND must be configured with `extraMounts` as provided in `scripts/setup-cluster.sh`.
- **Alternative (Colima)**: Colima provides enhanced control over the Linux VM kernel:
  ```bash
  colima start --cpu 4 --memory 8
  make cluster
  ```

---

## 4. Offline / Local Test Mode

To ensure full reproducibility even on developer workstations where Docker or a live Kubernetes cluster may not be immediately running:
- The **OPA Rego policy test suite** runs 100% offline via `opa test`.
- The **Admission Manifest Validator** runs offline via `python policies/gatekeeper/tests/validate_admission_manifests.py`.
- The **ThreatGuard Correlation Engine** parses captured and simulated eBPF traces deterministically, verifying all detection rules and generating accurate scorecards in `artifacts/`.
