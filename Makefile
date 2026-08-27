# ==============================================================================
# CloudNative ThreatGuard — Automation Makefile
# Production-grade Kubernetes defense-in-depth platform
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help setup cluster install-security deploy test test-admission test-runtime simulate metrics evidence security-test dashboard clean

help: ## Display this help message
	@echo "======================================================================"
	@echo "                   CloudNative ThreatGuard"
	@echo "    Kubernetes Defense-in-Depth: OPA Gatekeeper & eBPF Tetragon"
	@echo "======================================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Verify prerequisites and local tools
	@echo "[+] Checking development prerequisites..."
	@python --version || python3 --version
	@which opa >/dev/null 2>&1 && echo "OPA: OK" || echo "OPA: Use ./opa.exe or install in PATH"
	@which docker >/dev/null 2>&1 && echo "Docker: OK" || echo "Docker: Not found"
	@which kubectl >/dev/null 2>&1 && echo "Kubectl: OK" || echo "Kubectl: Not found"

cluster: ## Create KIND cluster with eBPF mount support
	@bash scripts/setup-cluster.sh

install-security: ## Install OPA Gatekeeper, Tetragon, and policies
	@bash scripts/install-security-stack.sh

deploy: ## Deploy hardened sample application and network policy
	@bash scripts/deploy-app.sh

test: test-admission test-runtime ## Run all unit tests (Rego and Runtime Engine)

test-admission: ## Run OPA Rego policy unit tests and manifest validation
	@echo "[+] Running Rego unit tests..."
	@if which opa >/dev/null 2>&1; then \
		opa test policies/gatekeeper/src policies/gatekeeper/tests/rego -v; \
	elif [ -f "./opa.exe" ]; then \
		./opa.exe test policies/gatekeeper/src policies/gatekeeper/tests/rego -v; \
	fi
	@echo "[+] Validating admission test manifests..."
	@python policies/gatekeeper/tests/validate_admission_manifests.py

test-runtime: ## Run Python correlation engine unit tests
	@echo "[+] Running Detection Engine unit tests..."
	@python -m unittest discover runtime/engine/

simulate: ## Execute all 6 behavioral attack simulation scenarios
	@bash simulations/run_simulations.sh

metrics: ## Generate Prometheus metrics snapshot from telemetry
	@python -c "from observability.exporter.metrics_exporter import MetricsHandler; print(MetricsHandler.generate_metrics(None))" > artifacts/metrics/security-metrics.prom
	@echo "[+] Metrics snapshot written to artifacts/metrics/security-metrics.prom"

evidence: ## Consolidate security evidence and generate final report
	@bash scripts/collect-evidence.sh

security-test: ## Run the complete 11-step end-to-end security test harness
	@bash scripts/run-security-validation.sh

dashboard: ## Run the Prometheus telemetry exporter on port 9100
	@python observability/exporter/metrics_exporter.py

clean: ## Clean up local artifacts and temporary files
	@rm -rf artifacts/admission/*.log artifacts/runtime/*.json artifacts/metrics/*.prom artifacts/reports/*.json
	@echo "[+] Cleaned up artifact logs."
