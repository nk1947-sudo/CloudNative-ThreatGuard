# CloudNative ThreatGuard — Troubleshooting & Diagnostic Guide

This document covers common diagnostic workflows, error messages, and operational fixes across the CloudNative ThreatGuard platform.

---

## 1. Quick Diagnostic Checklist

Run this command to check local dependencies and connectivity:
```bash
docker info >/dev/null 2>&1 && echo "Docker: OK" || echo "Docker: NOT RUNNING"
kubectl cluster-info >/dev/null 2>&1 && echo "Kubectl: OK" || echo "Kubectl: NOT CONNECTED"
kubectl get pods -n gatekeeper-system 2>/dev/null && echo "Gatekeeper: OK" || echo "Gatekeeper: NOT FOUND"
kubectl get pods -n tetragon 2>/dev/null && echo "Tetragon: OK" || echo "Tetragon: NOT FOUND"
```

---

## 2. Docker & Cluster Issues

### Problem: Docker daemon is not running
- **Symptom**: `ERROR: error during connect: open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.`
- **Cause**: Docker Desktop is stopped or failed to launch the Linux VM engine.
- **Resolution**:
  1. Launch Docker Desktop from the Start menu or Applications folder.
  2. In Windows/WSL2, verify the Docker service status: `sudo service docker status` (or `sudo systemctl status docker`).
  3. Wait until the whale icon in the taskbar indicates "Engine running".

### Problem: KIND cluster creation fails with mount errors
- **Symptom**: `failed to create cluster: error creating mount: no such file or directory`
- **Cause**: The host does not have `/sys/kernel/debug` or `/lib/modules` exposed to Docker.
- **Resolution**:
  Ensure Docker has administrative permissions to mount host filesystems, or run `make cluster` which provisions the compatible configuration automatically.

---

## 3. OPA Gatekeeper Issues

### Problem: Gatekeeper webhook timeout or connection refused
- **Symptom**: `Internal error occurred: failed calling webhook "check-ignore-label.gatekeeper.sh": Post "https://gatekeeper-webhook-service.gatekeeper-system.svc:443/...": dial tcp: lookup ... i/o timeout`
- **Cause**: Gatekeeper controller pods are still pulling container images or the validating webhook CA certificate is not yet injected.
- **Resolution**:
  Check controller pod status and wait for readiness:
  ```bash
  kubectl get pods -n gatekeeper-system
  kubectl rollout status deployment/gatekeeper-controller-manager -n gatekeeper-system --timeout=120s
  ```

### Problem: ConstraintTemplate CRDs fail to apply
- **Symptom**: `error: unable to recognize "deploy/gatekeeper/templates/...": no matches for kind "ConstraintTemplate"`
- **Cause**: Gatekeeper CRDs have not completed registration with the Kubernetes API server.
- **Resolution**:
  Re-apply the Gatekeeper deployment manifest and allow 10 seconds for CRD registration before applying templates:
  ```bash
  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.0/deploy/gatekeeper.yaml
  sleep 10
  kubectl apply -f deploy/gatekeeper/templates/
  ```

---

## 4. eBPF & Tetragon Runtime Issues

### Problem: Tetragon DaemonSet crashes with `CrashLoopBackOff`
- **Symptom**: `kubectl get ds -n tetragon` shows 0/1 ready pods.
- **Diagnostic Command**:
  ```bash
  kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon --tail=50
  ```
- **Common Cause 1**: Missing BPF filesystem mount (`/sys/fs/bpf`).
  - **Fix**: Mount the BPF filesystem on the node:
    ```bash
    sudo mount -t bpf bpf /sys/fs/bpf
    ```
- **Common Cause 2**: Kernel BTF (BPF Type Format) not supported.
  - **Check**: Verify `/sys/kernel/btf/vmlinux` exists on the Linux host:
    ```bash
    ls -l /sys/kernel/btf/vmlinux
    ```
  - **Fix**: Upgrade the host Linux kernel to 5.4 or higher (5.15+ recommended). In WSL2, run `wsl --update` to fetch the latest kernel.

### Problem: Tetragon TracingPolicy reports compilation or hook attachment failure
- **Symptom**: `kubectl describe tracingpolicy <policy-name>` reports `HookAttachmentFailed`.
- **Cause**: Kernel system call names differ across kernel architectures or kprobe is restricted.
- **Resolution**:
  ThreatGuard uses standardized syscall probes (`sys_enter_execve`, `security_file_open`, `sys_enter_connect`). Ensure the node is not in locked-down Secure Boot lockdown mode prohibiting kprobes (`cat /sys/kernel/security/lockdown` should be `[none]`).

---

## 5. Telemetry & Evidence Issues

### Problem: Telemetry events not writing to `artifacts/runtime/tetragon-raw.json`
- **Cause**: The export log path inside the Tetragon pod is not accessible or simulation was executed without target pod.
- **Resolution**:
  Stream logs directly via kubectl if live Tetragon is running:
  ```bash
  kubectl logs -n tetragon -l app.kubernetes.io/name=tetragon -c export-stdout -f > artifacts/runtime/tetragon-raw.json &
  ```
  Alternatively, use the built-in offline test engine (`make simulate`), which executes the deterministic verification harness.
