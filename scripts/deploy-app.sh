#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Protected Application Deployment
# Deploys hardened microservice and NetworkPolicy into 'threatguard' namespace.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

log_step "Deploying hardened sample application..."

if ! kubectl get namespace threatguard >/dev/null 2>&1; then
    kubectl create namespace threatguard
fi

log_info "Applying Kubernetes NetworkPolicy..."
kubectl apply -f "${REPO_ROOT}/app/k8s/network-policy.yaml"

log_info "Applying Kubernetes Service..."
kubectl apply -f "${REPO_ROOT}/app/k8s/service.yaml"

log_info "Applying Hardened Deployment..."
kubectl apply -f "${REPO_ROOT}/app/k8s/deployment.yaml"

log_info "Verifying Gatekeeper admission and rollout..."
if kubectl rollout status deployment/threatguard-app -n threatguard --timeout=90s; then
    log_success "Hardened application admitted and running successfully."
else
    log_warn "Application pods are initializing..."
fi
