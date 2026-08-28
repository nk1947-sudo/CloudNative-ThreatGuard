#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Cluster Setup Script
# Configures a local KIND cluster optimized for eBPF and OPA Gatekeeper.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

CLUSTER_NAME="threatguard-cluster"

log_step "Checking local prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
    log_error "Docker is required but not installed or not in PATH."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    log_error "Docker daemon is not running. Please start Docker Desktop or the dockerd daemon."
    exit 1
fi

if ! command -v kind >/dev/null 2>&1; then
    log_info "KIND not found, attempting auto-installation..."
    if [ "$(uname -s)" = "Linux" ]; then
        curl -Lo /tmp/kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
        chmod +x /tmp/kind
        sudo mv /tmp/kind /usr/local/bin/kind || mv /tmp/kind "${HOME}/.local/bin/kind" || true
    fi
fi

if ! command -v kind >/dev/null 2>&1; then
    log_error "KIND (Kubernetes in Docker) is required. Install via: go install sigs.k8s.io/kind@latest or your package manager."
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    log_error "kubectl is required. Please install kubectl."
    exit 1
fi

log_step "Verifying or creating KIND cluster: ${CLUSTER_NAME}..."

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_info "KIND cluster '${CLUSTER_NAME}' already exists."
else
    log_info "Creating KIND cluster '${CLUSTER_NAME}' with eBPF mount support..."
    cat << EOF | kind create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: kindest/node:v1.30.0
  extraMounts:
  - hostPath: /sys/kernel/debug
    containerPath: /sys/kernel/debug
  - hostPath: /sys/fs/bpf
    containerPath: /sys/fs/bpf
  - hostPath: /lib/modules
    containerPath: /lib/modules
    readOnly: true
EOF
    log_success "KIND cluster '${CLUSTER_NAME}' created successfully."
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}"
log_success "Cluster is online and ready for security stack deployment."
