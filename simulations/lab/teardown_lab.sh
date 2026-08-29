#!/usr/bin/env bash
# ==============================================================================
# CloudNative ThreatGuard: Deterministic Security Lab Teardown
# Cleans up lab deployments and temporary misconfigured pods.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/manifests"
NAMESPACE="threatguard"

echo "[*] Cleaning up ThreatGuard deterministic security lab workloads..."

kubectl delete -f "${MANIFESTS_DIR}/01-benign-web-frontend.yaml" --ignore-not-found=true
kubectl delete -f "${MANIFESTS_DIR}/02-target-payment-service.yaml" --ignore-not-found=true
kubectl delete -f "${MANIFESTS_DIR}/03-target-analytics-worker.yaml" --ignore-not-found=true
kubectl delete pod privileged-debug-pod -n "${NAMESPACE}" --ignore-not-found=true
kubectl delete pod hostpath-mount-pod -n "${NAMESPACE}" --ignore-not-found=true
kubectl delete deployment unauthorized-cryptominer -n "${NAMESPACE}" --ignore-not-found=true

echo "[✓] Security lab teardown completed."
