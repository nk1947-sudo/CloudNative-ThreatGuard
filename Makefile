# ==============================================================================
# CloudNative ThreatGuard — Automation Makefile
# Production-grade Kubernetes defense-in-depth platform
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help install test test-admission lint format typecheck validate \
        build cluster-up cluster-down install-security deploy simulate \
        evidence security-test dashboard demo-cloud verify clean

help: ## Display this help message
	@echo "======================================================================"
	@echo "                   CloudNative ThreatGuard"
	@echo "    Kubernetes Defense-in-Depth: OPA Gatekeeper & eBPF Tetragon"
	@echo "======================================================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the package and dev tooling (pip install -e ".[dev]")
	pip install -e ".[dev]"

test: ## Run the full pytest suite (unit + integration)
	pytest

test-admission: ## Run OPA Rego policy unit tests and manifest validation
	@echo "[+] Running Rego unit tests..."
	@if which opa >/dev/null 2>&1; then \
		opa test deploy/gatekeeper/src deploy/gatekeeper/tests/rego -v; \
	elif [ -f "./opa.exe" ]; then \
		./opa.exe test deploy/gatekeeper/src deploy/gatekeeper/tests/rego -v; \
	fi
	@echo "[+] Validating admission test manifests..."
	@threatguard admission validate

lint: ## Run ruff static analysis
	ruff check src tests

format: ## Auto-format with ruff
	ruff format src tests

typecheck: ## Advisory type checking with mypy (not enforced in CI)
	mypy src

validate: lint test-admission ## Run lint + admission policy validation

build: ## Build the sdist/wheel distribution
	python -m build

cluster-up: ## Create KIND cluster with eBPF mount support
	@bash scripts/setup-cluster.sh

cluster-down: ## Delete the local KIND cluster
	@bash scripts/teardown-cluster.sh

install-security: ## Install OPA Gatekeeper, Tetragon, and policies
	@bash scripts/install-security-stack.sh

deploy: ## Deploy hardened sample application and network policy
	@bash scripts/deploy-app.sh

simulate: ## Execute all attack simulation scenarios
	@bash simulations/run_simulations.sh

evidence: ## Consolidate security evidence and generate final report
	@bash scripts/collect-evidence.sh

security-test: ## Run the complete 11-step end-to-end security test harness
	@bash scripts/run-security-validation.sh

dashboard: ## Run the Prometheus telemetry exporter on port 9100
	python -m cloudnative_threatguard.observability.metrics_exporter

demo-cloud: ## Run deterministic cross-domain cloud security demo
	@threatguard demo cross-domain

verify: ## Run comprehensive end-to-end platform verification (all components)
	@threatguard verify

clean: ## Clean up local artifacts and temporary files
	@rm -rf artifacts/admission/*.log artifacts/runtime/*.json artifacts/metrics/*.prom artifacts/reports/*.json
	@echo "[+] Cleaned up artifact logs."
