.PHONY: knowledge-check build-agent build-theia build-images dev dev-down dev-logs test test-unit lint fmt schema-check scanners-pull demo sync

# CLAUDE.md §5. Targets below are real where the underlying task has landed;
# where it hasn't, the target says so explicitly and names the blocking task
# rather than silently doing nothing (NOTE.md §4.4's "honest stub" rule).

# Docker or Podman, kept swappable (CLAUDE.md §4): `make dev ENGINE=podman`.
ENGINE ?= docker
COMPOSE := $(ENGINE) compose

sync: ## Install the whole Python workspace + JS workspace into local envs.
	uv sync
	pnpm install

DEV_DB ?= postgresql+psycopg://qavach:qavach_dev_only@localhost:5432/qavach
DEV_REDIS ?= redis://localhost:6379/0

dev: ## postgres + redis + minio, migrate, then API :8000 + RQ worker + web :5173 (Postgres, RQ)
	$(COMPOSE) up -d --wait postgres redis minio
	@echo "postgres/redis/minio are up and healthy."
	cd packages/storage && QAVACH_DATABASE_URL=$(DEV_DB) uv run alembic upgrade head
	@echo "API :8000, worker, web :5173 — Ctrl-C stops all."
	@trap 'kill 0' INT TERM EXIT; \
	QAVACH_DATABASE_URL=$(DEV_DB) QAVACH_REDIS_URL=$(DEV_REDIS) uv run uvicorn qavach_api.main:app --port 8000 & \
	QAVACH_DATABASE_URL=$(DEV_DB) QAVACH_REDIS_URL=$(DEV_REDIS) uv run python -m qavach_worker & \
	pnpm --filter web dev --port 5173 & \
	wait

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

lint: ## ruff + mypy (strict on packages/core, standard elsewhere it exists) + biome
	uv run ruff check .
	uv run mypy packages/core
	@for pkg in collectors sandbox storage; do \
		if [ -n "$$(find packages/$$pkg/src -name '*.py' ! -name '__init__.py' 2>/dev/null)" ]; then \
			uv run mypy packages/$$pkg/src/qavach_$$pkg; \
		fi; \
	done
	@for app in api worker agent; do \
		if [ -n "$$(find apps/$$app/src -name '*.py' ! -name '__init__.py' 2>/dev/null)" ]; then \
			uv run mypy apps/$$app/src/qavach_$$app; \
		fi; \
	done
	@if [ -f apps/web/package.json ]; then pnpm --filter web lint; \
	else echo "apps/web not yet scaffolded — biome lint skipped (TASK.md T-100)."; fi

fmt: ## ruff format + biome format — run before every commit
	uv run ruff format .
	@if [ -f apps/web/package.json ]; then pnpm --filter web fmt; \
	else echo "apps/web not yet scaffolded — biome format skipped (TASK.md T-100)."; fi

schema-check: ## CBOM valid against CycloneDX 1.7 offline, no risk data in it, register valid, docs consistent (I5)
	uv run python scripts/schema_check.py

scanners-pull: ## pull pinned scanner container images
	ENGINE=$(ENGINE) uv run python3 scripts/pull_scanners.py

demo: ## real recorded scanner output through every layer; validates the CBOM (T-120)
	uv run python scripts/demo.py

demo-ui: ## the UI over the demo dataset: API :8000 (QAVACH_DEMO=1, SQLite, no Docker) + web :5173
	@echo "Demo UI: http://localhost:5173  (recorded scanner output; a planted root-CA/leaf pair)"
	@trap 'kill 0' INT TERM EXIT; \
	QAVACH_DEMO=1 uv run uvicorn qavach_api.main:app --port 8000 & \
	pnpm --filter web dev --port 5173 & \
	wait

build-images: ## build QAVACH-owned scanner images and print their content-addressed IDs
	$(ENGINE) build -t qavach/cbomkit-lib:dev docker/cbomkit-lib
	@echo "cbomkit-lib image ID: $$($(ENGINE) image inspect --format '{{.Id}}' qavach/cbomkit-lib:dev)"
	$(ENGINE) build -t qavach/certipy:dev docker/certipy
	@echo "certipy image ID: $$($(ENGINE) image inspect --format '{{.Id}}' qavach/certipy:dev)"
	$(ENGINE) build --build-context rules=config/opengrep-rules -t qavach/opengrep:dev docker/opengrep
	@echo "opengrep image ID: $$($(ENGINE) image inspect --format '{{.Id}}' qavach/opengrep:dev)"
	$(ENGINE) build -t qavach/tracebom:dev docker/tracebom
	@echo "tracebom image ID: $$($(ENGINE) image inspect --format '{{.Id}}' qavach/tracebom:dev)"

build-theia: ## cross-compile CBOMkit-theia from pinned source for the agent (5 OS/arch targets -> dist/theia)
	rm -rf dist/theia
	DOCKER_BUILDKIT=1 $(ENGINE) build --target artifacts --output type=local,dest=dist/theia docker/theia-build
	@cat dist/theia/SHA256SUMS

build-agent: build-theia ## freeze the agent for THIS OS/arch (PyInstaller does not cross-compile) -> dist/agent
	uv sync --all-packages --group dev
	uv run --all-packages python scripts/build_agent.py --theia-dir dist/theia

knowledge-check: ## fail if any knowledge-base entry was verified more than 180 days ago (T-081)
	uv run python scripts/check_knowledge_freshness.py
