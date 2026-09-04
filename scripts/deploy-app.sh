#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Protected Application Deployment
# Deploys hardened microservice and NetworkPolicy into 'threatguard' namespace.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"

log_step "Deploying hardened sample application..."

if ! command -v kind >/dev/null 2>&1; then
    if [ -f "${HOME}/go/bin/kind.exe" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    elif [ -f "${HOME}/go/bin/kind" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    fi
fi

if command -v docker >/dev/null 2>&1; then
    log_info "Building application container image..."
    docker build -t cloudnative-threatguard/sample-app:v1.0.0 "${REPO_ROOT}/app/secure-web-app"
    if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q "^threatguard-cluster$"; then
        log_info "Loading image into KIND cluster..."
        kind load docker-image cloudnative-threatguard/sample-app:v1.0.0 --name threatguard-cluster
    fi
fi

log_info "Ensuring 'threatguard' namespace exists..."
kubectl apply -f "${REPO_ROOT}/deploy/kubernetes/namespace.yaml"

log_info "Applying Kubernetes NetworkPolicy..."
kubectl apply -f "${REPO_ROOT}/app/secure-web-app/k8s/network-policy.yaml"

log_info "Applying Kubernetes Service..."
kubectl apply -f "${REPO_ROOT}/app/secure-web-app/k8s/service.yaml"

log_info "Applying Hardened Deployment..."
kubectl apply -f "${REPO_ROOT}/app/secure-web-app/k8s/deployment.yaml"

log_info "Verifying Gatekeeper admission and rollout..."
if kubectl rollout status deployment/threatguard-app -n threatguard --timeout=90s; then
    log_success "Hardened application admitted and running successfully."
else
    log_warn "Application pods are initializing..."
fi
