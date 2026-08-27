#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Security Stack Installation Script
# Deploys OPA Gatekeeper, ConstraintTemplates, Constraints, Tetragon, and TracingPolicies.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

GATEKEEPER_VERSION="v3.17.0"
TETRAGON_VERSION="v1.1.2"

log_step "1. Creating protected namespace 'threatguard'..."
kubectl create namespace threatguard --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace threatguard security.threatguard.io/monitored=true --overwrite

log_step "2. Installing OPA Gatekeeper (${GATEKEEPER_VERSION})..."
kubectl apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/${GATEKEEPER_VERSION}/deploy/gatekeeper.yaml"

log_info "Waiting for Gatekeeper controller to become ready..."
kubectl rollout status deployment/gatekeeper-controller-manager -n gatekeeper-system --timeout=120s

log_step "3. Applying Gatekeeper ConstraintTemplates..."
kubectl apply -f "${REPO_ROOT}/policies/gatekeeper/templates/"

log_info "Waiting for ConstraintTemplate CRDs to register..."
sleep 5

log_step "4. Applying Gatekeeper Constraints..."
kubectl apply -f "${REPO_ROOT}/policies/gatekeeper/constraints/"
log_success "Gatekeeper admission policies applied successfully."

log_step "5. Installing Cilium Tetragon eBPF Runtime Security (${TETRAGON_VERSION})..."
if command -v helm >/dev/null 2>&1; then
    helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
    helm repo update
    helm upgrade --install tetragon cilium/tetragon \
        --namespace tetragon \
        --create-namespace \
        -f "${REPO_ROOT}/runtime/tetragon/values.yaml"
else
    kubectl apply -n tetragon -f "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-quickstart.yaml"
fi

log_info "Waiting for Tetragon DaemonSet to become ready..."
kubectl rollout status ds/tetragon -n tetragon --timeout=120s || log_warn "Tetragon rollout taking time; continuing..."

log_step "6. Applying Tetragon TracingPolicies..."
kubectl apply -f "${REPO_ROOT}/runtime/tetragon/policies/"
log_success "eBPF TracingPolicies loaded."

log_step "7. Deploying Attack Simulation Target Pod..."
kubectl apply -f "${REPO_ROOT}/simulations/manifests/test-pod.yaml"
log_info "Waiting for simulation target pod to be Running..."
kubectl wait --for=condition=Ready pod/threatguard-target-pod -n threatguard --timeout=60s || true

log_success "Security stack installation complete."
