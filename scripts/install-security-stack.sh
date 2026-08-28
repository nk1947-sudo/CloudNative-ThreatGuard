#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard — Security Stack Installation Script
# Deploys OPA Gatekeeper, ConstraintTemplates, Constraints, Tetragon, and TracingPolicies.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck disable=SC1091
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

# Ensure Helm is available
if ! command -v helm >/dev/null 2>&1; then
    if [ -f "${HOME}/go/bin/helm.exe" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    elif [ -f "${HOME}/go/bin/helm" ]; then
        export PATH="${HOME}/go/bin:${PATH}"
    fi
fi

if ! command -v helm >/dev/null 2>&1; then
    log_info "Helm not found, attempting auto-installation..."
    if [[ "$(uname -s)" =~ (MINGW|MSYS) ]]; then
        powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'https://get.helm.sh/helm-v3.15.4-windows-amd64.zip' -OutFile '\$env:TEMP\helm.zip'; Expand-Archive -Path '\$env:TEMP\helm.zip' -DestinationPath '\$env:TEMP\helm-extracted' -Force; Move-Item -Path '\$env:TEMP\helm-extracted\windows-amd64\helm.exe' -Destination '\$env:USERPROFILE\go\bin\helm.exe' -Force; Remove-Item -Path '\$env:TEMP\helm.zip', '\$env:TEMP\helm-extracted' -Recurse -Force"
        export PATH="${HOME}/go/bin:${PATH}"
    elif [ "$(uname -s)" = "Linux" ]; then
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
fi

log_step "5. Installing Cilium Tetragon eBPF Runtime Security (${TETRAGON_VERSION})..."
kubectl create namespace tetragon --dry-run=client -o yaml | kubectl apply -f -
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update
helm upgrade --install tetragon cilium/tetragon \
    --namespace tetragon \
    --create-namespace \
    -f "${REPO_ROOT}/runtime/tetragon/values.yaml"

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
