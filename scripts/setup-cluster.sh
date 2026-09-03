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
    if [ -f "${HOME}/go/bin/kind.exe" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    elif [ -f "${HOME}/go/bin/kind" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    fi
fi

if ! command -v kind >/dev/null 2>&1; then
    log_info "KIND not found, attempting auto-installation..."
    if command -v go >/dev/null 2>&1; then
        log_info "Installing kind via go install..."
        go install sigs.k8s.io/kind@v0.24.0
        export PATH="${HOME}/go/bin:${PATH}"
    elif [ "$(uname -s)" = "Linux" ]; then
        curl -Lo /tmp/kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64
        chmod +x /tmp/kind
        sudo mv /tmp/kind /usr/local/bin/kind || mv /tmp/kind "${HOME}/.local/bin/kind" || true
    elif [[ "$(uname -s)" =~ (MINGW|MSYS) ]]; then
        mkdir -p "${HOME}/bin"
        curl -Lo "${HOME}/bin/kind.exe" https://kind.sigs.k8s.io/dl/v0.24.0/kind-windows-amd64.exe
        chmod +x "${HOME}/bin/kind.exe"
        export PATH="${HOME}/bin:${PATH}"
    fi
fi

if ! command -v kind >/dev/null 2>&1; then
    log_error "KIND (Kubernetes in Docker) is required. Install via: go install sigs.k8s.io/kind@latest or your package manager."
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    log_info "kubectl not found, attempting auto-installation..."
    if [ "$(uname -s)" = "Linux" ]; then
        curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
        chmod +x kubectl
        sudo mv kubectl /usr/local/bin/kubectl || mv kubectl "${HOME}/.local/bin/kubectl" || true
    fi
fi

if ! command -v kubectl >/dev/null 2>&1; then
    log_error "kubectl is required. Please install kubectl."
    exit 1
fi

log_step "Verifying or creating KIND cluster: ${CLUSTER_NAME}..."

if [ "$(uname -s)" = "Linux" ]; then
    sudo mkdir -p /sys/kernel/debug /sys/fs/bpf
    sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    sudo mount -t bpf none /sys/fs/bpf 2>/dev/null || true
fi

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_info "KIND cluster '${CLUSTER_NAME}' already exists."
else
    log_info "Creating KIND cluster '${CLUSTER_NAME}' with eBPF mount support..."
    kind create cluster --name "${CLUSTER_NAME}" --config "${SCRIPT_DIR}/kind-config.yaml"
    log_success "KIND cluster '${CLUSTER_NAME}' created successfully."
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}"
log_success "Cluster is online and ready for security stack deployment."
