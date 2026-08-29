#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard: Deterministic Security Lab Setup
# Deploys standard benign and vulnerable target workloads into the threatguard namespace.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"
NAMESPACE="threatguard"

echo "============================================================"
echo "  ThreatGuard Deterministic Security Lab: Initializing"
echo "============================================================"

# Ensure namespace exists with proper audit labels
if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    echo "[*] Creating namespace '${NAMESPACE}'..."
    kubectl create namespace "${NAMESPACE}"
fi

kubectl label namespace "${NAMESPACE}" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted \
    threatguard.io/monitored=true --overwrite >/dev/null 2>&1 || true

echo "[*] Deploying benign baseline workload (web-frontend)..."
kubectl apply -f "${MANIFESTS_DIR}/01-benign-web-frontend.yaml"

echo "[*] Deploying vulnerable target workload (payment-service)..."
kubectl apply -f "${MANIFESTS_DIR}/02-target-payment-service.yaml"

echo "[*] Deploying analytics worker target (analytics-worker)..."
kubectl apply -f "${MANIFESTS_DIR}/03-target-analytics-worker.yaml"

echo "[*] Waiting for deployment rollout in namespace '${NAMESPACE}'..."
kubectl rollout status deployment/web-frontend -n "${NAMESPACE}" --timeout=60s || true
kubectl rollout status deployment/payment-service -n "${NAMESPACE}" --timeout=60s || true
kubectl rollout status deployment/analytics-worker -n "${NAMESPACE}" --timeout=60s || true

echo ""
echo "============================================================"
echo "  Deterministic Security Lab Workloads Active:"
kubectl get pods -n "${NAMESPACE}" -o wide
echo "============================================================"
