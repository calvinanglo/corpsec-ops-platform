SHELL := /bin/bash
.DEFAULT_GOAL := help

# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Makefile
# ══════════════════════════════════════════════════════════════════════════════

COMPOSE_CORE     := docker compose -f docker-compose.yml
COMPOSE_FULL     := docker compose -f docker-compose.yml -f docker-compose.soar.yml -f docker-compose.phishing.yml
PROJECT_NAME     := corpsec

# ── Help ──────────────────────────────────────────────────────────────────────
help: ## Show this help
	@echo ""
	@echo "  corpsec-ops-platform — Corporate Security Operations Platform"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────
setup: certs env ## First-time setup — generate certs + .env
	@echo "[+] Setup complete. Edit .env then run 'make up'"

env: ## Create .env from .env.example if missing
	@if [ ! -f .env ]; then cp .env.example .env && echo "[+] .env created — EDIT THE CHANGE_ME VALUES"; else echo "[!] .env already exists"; fi

certs: ## Generate self-signed TLS certs
	@bash certs/generate-certs.sh

# ── Lifecycle ─────────────────────────────────────────────────────────────────
up: ## Start core stack (13 containers)
	$(COMPOSE_CORE) up -d
	@echo "[+] Core stack started. Run 'make health' to verify."

up-all: ## Start core + SOAR + phishing (all overlays)
	$(COMPOSE_FULL) up -d
	@echo "[+] Full stack started (17 containers)."

down: ## Stop all containers (preserves volumes)
	$(COMPOSE_FULL) down

restart: ## Restart all containers
	$(COMPOSE_FULL) restart

clean: ## Full teardown — containers + volumes + networks (destructive)
	$(COMPOSE_FULL) down -v --remove-orphans
	@echo "[!] All data destroyed."

# ── Monitoring ────────────────────────────────────────────────────────────────
health: ## Run health check on all services
	@bash scripts/health-check.sh

status: ## Container status + resource usage
	@docker ps --filter "name=$(PROJECT_NAME)" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@docker stats --no-stream --filter "name=$(PROJECT_NAME)" --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"

logs: ## Tail all container logs
	$(COMPOSE_FULL) logs -f --tail=100

logs-wazuh: ## Tail Wazuh manager logs
	$(COMPOSE_FULL) logs -f --tail=100 wazuh-manager

logs-thehive: ## Tail TheHive logs
	$(COMPOSE_FULL) logs -f --tail=100 thehive

# ── Security Operations ──────────────────────────────────────────────────────
dlp-scan: ## Run DLP scan against test data
	docker exec corpsec-python python -m dlp.scanner --path /testdata --policies all

ai-detect: ## Run AI exfiltration detection on sample logs
	docker exec corpsec-python python -m ai_detection.detector --sample

phish-launch: ## Launch a phishing campaign
	docker exec corpsec-python python -m integrations.gophish_client launch --campaign credential-harvest

phish-results: ## Pull current phishing campaign results
	docker exec corpsec-python python -m integrations.gophish_client results

# ── Real Production Integrations ─────────────────────────────────────────────
sync-okta: ## Pull Okta system logs into Wazuh
	docker exec corpsec-python python -m integrations.okta.log_streamer --since 1h

sync-crowdstrike: ## Pull CrowdStrike detections into Wazuh
	docker exec corpsec-python python -m integrations.crowdstrike.detection_streamer --since 1h

sync-gws: ## Pull Google Workspace audit logs into Wazuh
	docker exec corpsec-python python -m integrations.google_workspace.audit_log_streamer --since 1h

sync-1password: ## Pull 1Password audit events into Wazuh
	docker exec corpsec-python python -m integrations.onepassword.audit_log_streamer --since 1h

sync-intune: ## Pull Intune device events into Wazuh
	docker exec corpsec-python python -m integrations.intune.device_streamer --since 1h

sync-all: sync-okta sync-crowdstrike sync-gws sync-1password sync-intune ## Sync from all production tools

# ── Compliance ────────────────────────────────────────────────────────────────
compliance-audit: ## Run Ansible compliance audit
	cd ansible && ansible-playbook -i inventory/hosts.yml playbooks/compliance-audit.yml

evidence-collect: ## Collect compliance evidence (SOC 2 + ISO 27001)
	docker exec corpsec-python python -m compliance.evidence_collector --framework all

evidence-soc2: ## Collect SOC 2 evidence only
	docker exec corpsec-python python -m compliance.evidence_collector --framework soc2

evidence-iso: ## Collect ISO 27001 evidence only
	docker exec corpsec-python python -m compliance.evidence_collector --framework iso27001

# ── Demo ──────────────────────────────────────────────────────────────────────
seed: ## Seed demo data (alerts, cases, users)
	@bash scripts/seed-data.sh

demo: ## Run full incident lifecycle demo
	@bash scripts/demo-scenario.sh

# ── Testing ───────────────────────────────────────────────────────────────────
test: ## Run Python test suite
	docker exec corpsec-python pytest -v --tb=short

lint: ## Lint Python + YAML + Bash
	docker exec corpsec-python ruff check python/
	@find . -name "*.yml" -not -path "./node_modules/*" -exec yamllint -d relaxed {} \;
	@find scripts -name "*.sh" -exec shellcheck {} \;

validate: ## Validate all config files
	@bash scripts/validate-configs.sh

.PHONY: help setup env certs up up-all down restart clean health status logs logs-wazuh logs-thehive dlp-scan ai-detect phish-launch phish-results sync-okta sync-crowdstrike sync-gws sync-1password sync-intune sync-all compliance-audit evidence-collect evidence-soc2 evidence-iso seed demo test lint validate
