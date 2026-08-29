# CloudNative ThreatGuard — Operational Deployment Runbook

This operational runbook provides step-by-step procedures for deploying, bootstrapping, validating, and managing CloudNative ThreatGuard in local (KIND) and staging environments.

---

## 1. Prerequisites Checklist

Before provisioning the platform, verify that the local host satisfies the following software dependencies:

| Tool | Minimum Version | Verification Command | Purpose |
| :--- | :--- | :--- | :--- |
| **Docker Desktop / Engine** | 24.0+ | `docker --version` | Container runtime engine |
| **KIND (Kubernetes in Docker)** | 0.20.0+ | `kind --version` | Local multi-node Kubernetes cluster |
| **Kubectl CLI** | 1.28.0+ | `kubectl version --client` | Kubernetes API client |
| **Python** | 3.10+ | `python --version` | ThreatGuard runtime, correlation engine, and CLI |
| **Linux Kernel (for eBPF)** | 5.15+ (with BTF) | `uname -r` | In-kernel tracing support |

---

## 2. Step 1: Cluster Provisioning

ThreatGuard requires a KIND cluster configuration that mounts host kernel debug interfaces (`/sys/kernel/debug`) and the BPF filesystem into the cluster control plane and worker nodes.

### Provision Cluster via Makefile
```bash
make cluster
```

### Manual Cluster Provisioning
If provisioning manually:
```bash
kind create cluster --name threatguard-local --config infra/kind/kind-cluster.yaml
kubectl cluster-info --context kind-threatguard-local
```

### Verification
Verify that the cluster node is in `Ready` state:
```bash
kubectl get nodes -o wide
```

---

## 3. Step 2: OPA Gatekeeper Admission Controller Setup

OPA Gatekeeper enforces pre-deployment admission control via Kubernetes ValidatingWebhookConfiguration.

### Install Gatekeeper
Deploy official Gatekeeper v3.17.0:
```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.0/deploy/gatekeeper.yaml
```

Wait for Gatekeeper controller manager readiness (up to 120 seconds):
```bash
kubectl rollout status -n gatekeeper-system deployment/gatekeeper-controller-manager --timeout=120s
kubectl rollout status -n gatekeeper-system deployment/gatekeeper-audit --timeout=120s
```

### Apply ThreatGuard ConstraintTemplates & Constraints
Register the parameterized Rego templates and instantiate constraints:
```bash
kubectl apply -f policies/gatekeeper/templates/
kubectl apply -f policies/gatekeeper/constraints/
```

### Verification
Verify that constraints are active and enforced:
```bash
kubectl get constrainttemplates
kubectl get constraints
```

---

## 4. Step 3: Cilium Tetragon eBPF Runtime Setup

Tetragon provides real-time security observability and runtime enforcement directly within the Linux kernel.

### Install Tetragon DaemonSet
Deploy Tetragon into the `tetragon` namespace:
```bash
kubectl create namespace tetragon --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/v1.1.2/install/kubernetes/tetragon.yaml
```

Wait for the Tetragon DaemonSet to roll out:
```bash
kubectl rollout status -n tetragon daemonset/tetragon --timeout=180s
```

### Apply ThreatGuard TracingPolicies
Load eBPF kprobes and tracepoints into the kernel:
```bash
kubectl apply -f policies/tetragon/tracing-policy.yaml
```

### Verification
Verify that the TracingPolicy is applied:
```bash
kubectl get tracingpolicies
```

---

## 5. Step 4: Workload & Target Environment Setup

Deploy the target application pod inside the protected `threatguard` namespace:
```bash
kubectl create namespace threatguard --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f infra/k8s/target-pod.yaml
kubectl wait -n threatguard --for=condition=Ready pod/threatguard-target-pod --timeout=90s
```

Deploy the multi-workload simulation lab:
```bash
./simulations/lab/setup_lab.sh
```

---

## 6. Step 5: ThreatGuard Engine & Dashboard Initialization

### Launch Security API & SOC Console
Start the ThreatGuard web dashboard and API server:
```bash
python runtime/app.py
```
Access the SOC console at `http://127.0.0.1:8080`.

### Verify Operator CLI
Verify CLI accessibility:
```bash
python runtime/cli.py status
```
