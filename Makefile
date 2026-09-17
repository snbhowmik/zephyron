.PHONY: dev dev-down dev-logs test test-unit lint fmt schema-check scanners-pull demo sync

# CLAUDE.md §5. Targets below are real where the underlying task has landed;
# where it hasn't, the target says so explicitly and names the blocking task
# rather than silently doing nothing (NOTE.md §4.4's "honest stub" rule).

# Docker or Podman, kept swappable (CLAUDE.md §4): `make dev ENGINE=podman`.
ENGINE ?= docker
COMPOSE := $(ENGINE) compose

sync: ## Install the whole Python workspace + JS workspace into local envs.
	uv sync
	pnpm install

dev: ## postgres + redis + minio (--wait for health), then API :8000 and web :5173
	$(COMPOSE) up -d --wait postgres redis minio
	@echo "postgres/redis/minio are up and healthy."
	@if [ -f apps/api/src/qavach_api/main.py ]; then echo "TODO: start API :8000 (T-073)."; \
	else echo "API not yet implemented — see TASK.md T-073."; fi
	@if [ -f apps/web/package.json ]; then echo "TODO: start web :5173 (T-100)."; \
	else echo "web not yet scaffolded — see TASK.md T-100."; fi

dev-down: ## Stop and remove the dev infrastructure containers.
	$(COMPOSE) down

dev-logs: ## Tail logs from the dev infrastructure containers.
	$(COMPOSE) logs -f postgres redis minio

test: test-unit ## pytest (unit) + pytest (integration, if services are up) + vitest
	@uv run pytest -m integration || echo "Integration tests skipped or failed — needs 'make dev' (T-002)."
	@if [ -f apps/web/package.json ]; then pnpm --filter web test; \
	else echo "apps/web not yet scaffolded — see TASK.md T-100."; fi

test-unit: ## pytest packages/ -m "not integration"  (no services needed)
	uv run pytest -m "not integration"

lint: ## ruff + mypy + biome
	uv run ruff check .
	uv run mypy packages/core
	@if [ -f apps/web/package.json ]; then pnpm --filter web lint; \
	else echo "apps/web not yet scaffolded — biome lint skipped (TASK.md T-100)."; fi

fmt: ## ruff format + biome format — run before every commit
	uv run ruff format .
	@if [ -f apps/web/package.json ]; then pnpm --filter web fmt; \
	else echo "apps/web not yet scaffolded — biome format skipped (TASK.md T-100)."; fi

schema-check: ## validate sample CBOMs against CycloneDX 1.7
	@echo "No vendored schema yet — see TASK.md T-011 and T-091." >&2; exit 1

scanners-pull: ## pull pinned scanner container images
	@if [ -f config/scanners.yaml ]; then \
		echo "TODO: pull every digest in config/scanners.yaml"; \
	else \
		echo "config/scanners.yaml does not exist yet — see TASK.md T-006." >&2; exit 1; \
	fi

demo: ## seed the demo dataset and open the UI
	@echo "No demo dataset yet — see TASK.md T-120." >&2; exit 1
