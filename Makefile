# Insight: one entry point for running, operating and developing Insight.  `make help` lists every target.
#
# Operating targets drive Docker Compose and work from the directory that holds compose.yaml and .env.
# Development targets use .venv/ when it exists (`make dev` creates it), otherwise the tools on PATH.
# POSIX shell (Linux, macOS, WSL). Every target wraps a command documented in README, docs/RUNBOOK.md,
# CONTRIBUTING.md or docs/TESTING.md, so the docs stay the reference for what each one does.
#
# MFA (an authenticator-app code at sign-in) is OFF by default: `make mfa-enable` / `make mfa-disable`.
# Colour theme: `system` (follow each device) by default; `make theme THEME=light|dark|system` or
# `make up THEME=dark` saves INSIGHT_THEME in .env. Every browser can still pick its own in the workspace header.

SHELL := /bin/sh
COMPOSE ?= docker compose
ENV_FILE ?= .env
SERVICE ?= insight
URL ?= http://127.0.0.1:8080
BACKUP_DIR ?= backups
EXPORT_DIR ?= exports
VENV ?= .venv
PYTHON ?= python3
UV_VERSION ?= 0.13.7
# Tools from .venv when it exists, else from PATH (an activated environment, CI).
BIN := $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/,)
# One timestamp per make run, so the file a recipe writes in the container is the one it copies out.
STAMP := $(shell date +%Y-%m-%d-%H%M%S)

.DEFAULT_GOAL := help

##@ First run

.PHONY: help
help: ## List the targets
	@awk 'BEGIN {FS = ":.*## "} \
	  /^##@ / {printf "\n%s\n", substr($$0, 5)} \
	  /^[a-z0-9-]+:.*## / {printf "  make %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
	@echo "Settings (make VAR=value): URL=$(URL) BACKUP_DIR=$(BACKUP_DIR) EXPORT_DIR=$(EXPORT_DIR) VENV=$(VENV)"

.PHONY: env
env: ## Create .env with a generated password and secret (never overwrites)
	@if [ -e $(ENV_FILE) ]; then echo "$(ENV_FILE) already exists; refusing to overwrite existing credentials." >&2; exit 1; fi
	@umask 077; \
	if command -v python3 >/dev/null 2>&1; then \
	  pw=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))'); \
	  secret=$$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))'); \
	elif command -v openssl >/dev/null 2>&1; then \
	  pw=$$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '='); \
	  secret=$$(openssl rand -base64 48 | tr -d '\n' | tr '+/' '-_' | tr -d '='); \
	else echo "Need python3 or openssl to generate credentials (or copy .env.example by hand)." >&2; exit 1; fi; \
	printf 'INSIGHT_PASSWORD=%s\nINSIGHT_SESSION_SECRET=%s\n' "$$pw" "$$secret" > $(ENV_FILE)
	@echo "Created $(ENV_FILE) (mode 600). Sign in with the INSIGHT_PASSWORD it contains. Keep the file private."

##@ Run (Docker)

.PHONY: up down stop restart ps logs health version
up: env-file ## Build and start Insight in the background; THEME=system|light|dark saves a theme
	$(if $(THEME),@$(check-theme) && $(call set-env,INSIGHT_THEME,$(THEME)))
	$(COMPOSE) up --build -d

down: ## Stop and remove the container (data stays in the volume)
	$(COMPOSE) down

stop: ## Stop the container without removing it
	$(COMPOSE) stop

restart: ## Restart the container
	$(COMPOSE) restart

ps: ## Show the container's status and health
	$(COMPOSE) ps

logs: ## Follow the logs (Ctrl-C to stop following)
	$(COMPOSE) logs -f $(SERVICE)

health: ## Ask the running instance for its public liveness status
	@curl -fsS $(URL)/health && echo

version: env-file ## Print the version of the built image
	$(COMPOSE) run --rm --no-deps $(SERVICE) insight --version

##@ Data (Docker)

.PHONY: backup restore export-iocs migrate db-shell delete-report attack-backfill exploit-backfill threat-library-sync
backup: env-file ## Online, integrity-checked backup (safe while running) into backups/
	@umask 077; mkdir -p $(BACKUP_DIR)
	$(COMPOSE) exec -T $(SERVICE) insight backup /data/backup-$(STAMP).db
	$(COMPOSE) cp $(SERVICE):/data/backup-$(STAMP).db $(BACKUP_DIR)/backup-$(STAMP).db
	$(COMPOSE) exec -T $(SERVICE) rm /data/backup-$(STAMP).db
	@chmod 600 $(BACKUP_DIR)/backup-$(STAMP).db
	@echo "Backup: $(BACKUP_DIR)/backup-$(STAMP).db  (it holds every report: protect it like the data)"

restore: env-file ## Replace the database with BACKUP=file.db (asks first; CONFIRM=yes)
	@test -n "$(BACKUP)" || { echo "usage: make restore BACKUP=$(BACKUP_DIR)/backup-YYYY-MM-DD-HHMMSS.db" >&2; exit 2; }
	@test -f "$(BACKUP)" || { echo "No such backup: $(BACKUP)" >&2; exit 1; }
	@if [ "$(CONFIRM)" != yes ]; then \
	  printf 'Replace the current database with %s? Take `make backup` first if you may need it. [y/N] ' "$(BACKUP)"; \
	  read answer; [ "$$answer" = y ] || [ "$$answer" = Y ] || { echo "Cancelled; nothing changed."; exit 1; }; \
	fi
	$(COMPOSE) stop
	$(COMPOSE) run --rm --no-deps -v "$(abspath $(dir $(BACKUP))):/restore:ro" --entrypoint sh $(SERVICE) \
	  -c 'cp "/restore/$(notdir $(BACKUP))" /data/insight.db'
	$(COMPOSE) up -d
	@echo "Restored $(BACKUP). Migrations run at start-up if it is older; sign in and check a known report."

export-iocs: env-file ## IOC export into exports/ (filters: EXPORT_ARGS="--max-tlp GREEN --defang")
	@umask 077; mkdir -p $(EXPORT_DIR)
	$(COMPOSE) exec -T $(SERVICE) insight export-iocs /data/iocs-$(STAMP).json $(EXPORT_ARGS)
	$(COMPOSE) cp $(SERVICE):/data/iocs-$(STAMP).json $(EXPORT_DIR)/iocs-$(STAMP).json
	$(COMPOSE) exec -T $(SERVICE) rm /data/iocs-$(STAMP).json
	@chmod 600 $(EXPORT_DIR)/iocs-$(STAMP).json
	@echo "Export: $(EXPORT_DIR)/iocs-$(STAMP).json  (handle it at the TLP label inside the file)"

migrate: env-file ## Apply database migrations explicitly (start-up does this too)
	$(COMPOSE) run --rm $(SERVICE) insight migrate

db-shell: env-file ## SQL shell on the database (RUNBOOK section 9: stop and back up first)
	$(COMPOSE) run --rm --no-deps --entrypoint python $(SERVICE) -m sqlite3 /data/insight.db

attack-backfill: env-file ## Tag ATT&CK technique IDs in reports stored before 0.7.0 (safe to rerun)
	$(COMPOSE) run --rm $(SERVICE) insight attack-backfill

exploit-backfill: env-file ## Note public-exploit mentions in reports stored before 0.9.0 (safe to rerun)
	$(COMPOSE) run --rm $(SERVICE) insight exploit-backfill

threat-library-sync: env-file ## Fetch the full threat library (pinned ATT&CK + MISP galaxy, SHA-256 checked)
	$(COMPOSE) run --rm $(SERVICE) insight threat-library-sync
	@echo "Restart to load it: make restart"

delete-report: env-file ## Delete a report (legal/retention): ID=... REASON='ticket 42' (asks first)
	@test -n $(call shell-quote,$(ID)) && test -n $(call shell-quote,$(REASON)) || { echo "usage: make delete-report ID=<report id> REASON='ticket 42: retention ended'" >&2; exit 2; }
	$(COMPOSE) run --rm $(SERVICE) insight delete-report $(call shell-quote,$(ID)) --reason $(call shell-quote,$(REASON))

# One argument as a single-quoted shell word, whatever it contains (a quote becomes '\'').
shell-quote = '$(subst ','\'',$(1))'

##@ API key (Docker; one key at a time, see docs/API.md)

.PHONY: api-key-create api-key-status api-key-rotate api-key-revoke
api-key-create: env-file ## Create the key: NAME=siem [ACCESS=read-rfi|read-write] [MAX_TLP=GREEN]
	@test -n "$(NAME)" || { echo "usage: make api-key-create NAME=siem [ACCESS=read-write] [MAX_TLP=GREEN] [EXPIRES=90]" >&2; exit 2; }
	$(COMPOSE) run --rm $(SERVICE) insight api-key create $(KEY_ARGS)

api-key-status: env-file ## Key ID, access, TLP limit, expiry and last use (never the key itself)
	$(COMPOSE) run --rm $(SERVICE) insight api-key status

api-key-rotate: env-file ## Replace the key; the old one stops at once (optional ACCESS, MAX_TLP, EXPIRES)
	$(COMPOSE) run --rm $(SERVICE) insight api-key rotate $(KEY_ARGS)

api-key-revoke: env-file ## Revoke the key immediately
	$(COMPOSE) run --rm $(SERVICE) insight api-key revoke

KEY_ARGS = $(if $(NAME),--name '$(NAME)') $(if $(ACCESS),--access $(ACCESS)) \
	$(if $(MAX_TLP),--max-tlp $(MAX_TLP)) $(if $(EXPIRES),--expires-days $(EXPIRES))

##@ Sign-in MFA (Docker; off by default)

.PHONY: mfa-enable mfa-disable mfa-status mfa-reset
mfa-enable: env-file ## Turn MFA on: pair an app (if none is), set INSIGHT_MFA=on, restart
	$(COMPOSE) run --rm $(SERVICE) insight migrate
	$(COMPOSE) run --rm $(SERVICE) insight mfa setup
	@$(call set-env,INSIGHT_MFA,on)
	$(COMPOSE) up -d
	@echo "MFA is on: sign-in now asks for the password and a code from your authenticator app."

mfa-disable: env-file ## Turn MFA off (password-only sign-in); the paired app is kept for later
	@$(call set-env,INSIGHT_MFA,off)
	$(COMPOSE) up -d
	@echo "MFA is off: sign-in asks for the password only. 'make mfa-enable' turns it back on."

mfa-status: env-file ## Show whether MFA is on and whether an authenticator app is paired
	$(COMPOSE) run --rm $(SERVICE) insight mfa status

mfa-reset: env-file ## Forget the paired app (lost phone); then `make mfa-enable` pairs a new one
	$(COMPOSE) run --rm $(SERVICE) insight mfa reset

##@ Appearance (Docker)

.PHONY: theme
theme: env-file ## Default colour theme THEME=system|light|dark: set INSIGHT_THEME in .env, restart
	@$(check-theme)
	@$(call set-env,INSIGHT_THEME,$(THEME))
	$(COMPOSE) up -d
	@echo "Default theme: $(THEME). Browsers that picked Light, Dark or System in the header keep their choice."

##@ Checks against a running instance

.PHONY: smoke test-e2e
smoke: env-file ## HTTP smoke test of the running instance (password from .env; MFA must be off)
	@INSIGHT_PASSWORD="$$(sed -n 's/^INSIGHT_PASSWORD=//p' $(ENV_FILE) | tail -n 1)" \
	  $(BIN)python scripts/smoke.py $(URL) $(SMOKE_ARGS)

test-e2e: env-file ## Browser tests against the running instance (see docs/TESTING.md)
	INSIGHT_E2E_URL=$(URL) INSIGHT_E2E_PASSWORD="$$(sed -n 's/^INSIGHT_PASSWORD=//p' $(ENV_FILE) | tail -n 1)" \
	  $(BIN)pytest tests/e2e -m e2e

SMOKE_ARGS ?= --no-demo

##@ Develop (local Python)

.PHONY: dev install-e2e serve test test-fast test-cov test-postgres test-live lint format typecheck
dev: ## Create .venv: pinned dev tools, Insight (editable), uv, git hooks
	test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --require-hashes -r requirements-dev.lock
	$(VENV)/bin/pip install --no-deps -e .
	$(VENV)/bin/pip install "uv==$(UV_VERSION)"
	$(VENV)/bin/pre-commit install --hook-type pre-commit --hook-type pre-push || echo "Git hooks not installed (not a git checkout?)"

install-e2e: ## Install the browser-test tools (Playwright and Chromium)
	$(BIN)pip install --require-hashes -r requirements-e2e.lock
	$(BIN)python -m playwright install chromium

serve: ## Run Insight locally without Docker (reads .env; http://127.0.0.1:8080)
	$(BIN)insight serve

test: ## Full offline test suite
	$(BIN)pytest

test-fast: ## Unit tests only (fast inner loop)
	$(BIN)pytest tests/unit -q

test-cov: ## Full suite with branch coverage and CI's 90% gate
	$(BIN)pytest --cov --cov-report=term-missing --cov-fail-under=90

test-postgres: ## Suite on PostgreSQL (set INSIGHT_TEST_DATABASE_URL)
	@test -n "$(INSIGHT_TEST_DATABASE_URL)" || { echo "Set INSIGHT_TEST_DATABASE_URL=postgresql+psycopg://postgres@localhost/postgres" >&2; exit 2; }
	INSIGHT_TEST_DATABASE_URL="$(INSIGHT_TEST_DATABASE_URL)" $(BIN)pytest -m "not slow"

test-live: ## Contact the real feeds and providers (internet; what the nightly job runs)
	INSIGHT_LIVE_TESTS=1 $(BIN)pytest tests/live -m live

lint: ## ruff lint and format check (no changes)
	$(BIN)ruff check src tests scripts
	$(BIN)ruff format --check src tests scripts

format: ## Apply ruff fixes and formatting
	$(BIN)ruff check --fix src tests scripts
	$(BIN)ruff format src tests scripts

typecheck: ## mypy --strict over src/, tests/ and scripts/
	$(BIN)mypy

##@ CI gates (what the pipeline runs)

.PHONY: check ci package benchmark drill
check: lint typecheck ## CI's quality job: lint, types, lock files, secrets, workflows, pinning report
	$(BIN)pip check
	$(BIN)python scripts/lock.py --check
	$(BIN)python scripts/check_forbidden_files.py
	$(BIN)check-jsonschema --builtin-schema vendor.github-workflows .github/workflows/*.yml
	$(BIN)zizmor --offline --min-severity medium --config .github/zizmor.yml .github/workflows
	$(BIN)python scripts/check_pins.py

ci: check test-cov package ## The Tier 1 jobs that run without Docker: quality, tests with coverage, package

package: ## Build the wheel as Docker does, install it cleanly, migrate, check licences
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	rm -f dist/insight-*.whl; \
	$(PYTHON) -m venv "$$tmp/build"; "$$tmp/build/bin/pip" install -q --require-hashes -r requirements-build.lock; \
	"$$tmp/build/bin/pip" wheel -q --no-deps --no-build-isolation --wheel-dir dist .; \
	$(PYTHON) -m venv "$$tmp/runtime"; "$$tmp/runtime/bin/pip" install -q --require-hashes -r requirements.lock; \
	"$$tmp/runtime/bin/pip" install -q --no-deps --no-index dist/insight-*.whl; \
	"$$tmp/runtime/bin/pip" check; "$$tmp/runtime/bin/insight" --version; \
	cp tests/fixtures/releases/insight-0.1.0.sqlite3 "$$tmp/upgrade.db"; \
	INSIGHT_DATABASE_URL="sqlite:///$$tmp/upgrade.db" "$$tmp/runtime/bin/insight" migrate; \
	"$$tmp/runtime/bin/python" scripts/check_licenses.py > /dev/null; \
	echo "Package OK: $$(ls dist/insight-*.whl)"

benchmark: ## Extraction quality (vs. the committed baseline) and the performance budget
	$(BIN)python scripts/benchmark_extraction.py
	$(BIN)python scripts/benchmark_performance.py

drill: ## Backup-and-restore drill against a real `insight serve` (milestone gate)
	$(BIN)python scripts/backup_restore_drill.py

##@ Maintenance

.PHONY: locks locks-upgrade ioc-example update-tlds release-fixture release-check clean
locks: ## Refresh the lock files after editing pyproject.toml (needs uv)
	$(BIN)python scripts/lock.py

locks-upgrade: ## Upgrade every pinned dependency (review the diff and run `make ci`)
	$(BIN)python scripts/lock.py --upgrade

ioc-example: ## Regenerate docs/examples/insight-iocs-example.json after an export-format change
	$(BIN)python scripts/make_ioc_example.py

update-tlds: ## Refresh the bundled TLD list from the Public Suffix List (internet)
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -sSf -o "$$tmp/public_suffix_list.dat" https://publicsuffix.org/list/public_suffix_list.dat; \
	$(BIN)python scripts/update_tlds.py "$$tmp/public_suffix_list.dat"
	$(BIN)python scripts/benchmark_extraction.py

release-fixture: ## Create the upgrade fixture for this version (once per final release)
	$(BIN)python scripts/make_release_fixture.py

release-check: ## Release-gate checks for TAG=vX.Y.Z (version, changelog, strict pins)
	@test -n "$(TAG)" || { echo "usage: make release-check TAG=vX.Y.Z" >&2; exit 2; }
	$(BIN)python scripts/check_release.py $(TAG)
	$(BIN)python scripts/check_pins.py --strict
	$(BIN)python scripts/release_notes.py $(TAG) > /dev/null && echo "Release notes for $(TAG) found in CHANGELOG.md"

clean: ## Remove caches and build output (never data, backups, exports or .env)
	rm -rf .pytest_cache .ruff_cache .mypy_cache .hypothesis htmlcov .coverage .coverage.* coverage.xml \
	  junit*.xml build dist mutants src/insight.egg-info
	find src tests scripts -name __pycache__ -type d -prune -exec rm -rf {} +

# --------------------------------------------------------------------------- helpers

.PHONY: env-file
env-file:
	@test -f $(ENV_FILE) || { echo "No $(ENV_FILE) here: run 'make env' first (or see README, Quick start)." >&2; exit 1; }

# check-theme: THEME must be one of the three themes (Insight refuses to start with anything else).
check-theme = case "$(THEME)" in system|light|dark) ;; \
	*) echo "usage: make theme THEME=system|light|dark (current: $$(sed -n 's/^INSIGHT_THEME=//p' $(ENV_FILE) | \
	  tail -n 1 | grep . || echo 'system, the default'))" >&2; exit 2 ;; esac

# set-env KEY,VALUE: replace (or add) KEY=VALUE in $(ENV_FILE), keeping every other line. The file holds the
# password, so its permissions must never loosen: the temporary copy is private (umask 077) and the result
# is written back into the original file rather than replacing it.
set-env = tmp="$(ENV_FILE).tmp.$$$$"; umask 077; \
	{ grep -v '^$(1)=' $(ENV_FILE) || true; } > "$$tmp" && echo '$(1)=$(2)' >> "$$tmp" && \
	cat "$$tmp" > $(ENV_FILE); status=$$?; rm -f "$$tmp"; \
	test $$status -eq 0 && echo "Set $(1)=$(2) in $(ENV_FILE)"
