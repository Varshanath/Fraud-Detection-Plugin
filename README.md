# Fraud Detection Platform

An adaptive fraud, phishing, and scam detection platform. The system is being built incrementally across 13 phases (rule-based detection → sender/URL/reputation analysis → risk scoring → detection orchestration → plugin → agentic investigation → threat intelligence → adaptive learning → hardening/deployment).

**This repository currently contains only Phase 1: project foundation.** No detection logic, ingestion API, agent, ML, RAG, or plugin exists yet — those arrive in later phases. What's here is the backend skeleton: app bootstrap, configuration, a FastAPI app, a health endpoint, and Postgres/SQLAlchemy wiring.

## Prerequisites

- Python 3.11+ (developed against 3.14)
- Docker + Docker Compose (optional, for containerized Postgres/API)

## Local setup

```bash
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Windows (Git Bash) / macOS / Linux
source .venv/Scripts/activate  # or .venv/bin/activate on macOS/Linux

pip install -r requirements-dev.txt
cp .env.example .env
```

## Running tests

```bash
pytest -v
```

Tests do not require a live Postgres instance — the SQLAlchemy engine is lazy and no query runs at import/startup time.

## Running the backend locally (no Docker)

```bash
uvicorn app.main:app --reload
```

Then:

```bash
curl http://localhost:8000/health
# {"status":"healthy"}
```

## Running with Docker Compose

```bash
docker compose up --build
```

This starts a `postgres:16-alpine` container and the API container (waits for Postgres's healthcheck before starting). The API is available at `http://localhost:8000`.

## Configuration

Settings are managed via `pydantic-settings` (`app/config.py`), reading from environment variables and an optional `.env` file (see `.env.example`). All fields have defaults, so the app runs out of the box in development without any `.env` file present.

| Variable | Default | Purpose |
|---|---|---|
| `APP_NAME` | `Fraud Detection Platform` | FastAPI app title |
| `ENVIRONMENT` | `development` | Environment label |
| `DEBUG` | `true` | FastAPI debug mode |
| `POSTGRES_USER` | `fraud_detection` | Postgres username |
| `POSTGRES_PASSWORD` | `fraud_detection` | Postgres password |
| `POSTGRES_HOST` | `localhost` | Postgres host (set to `db` under Docker Compose) |
| `POSTGRES_PORT` | `5432` | Postgres port |
| `POSTGRES_DB` | `fraud_detection` | Postgres database name |
| `LOG_LEVEL` | `INFO` | Logging level |

## Project structure

```
app/
├── main.py            # create_app() factory + ASGI entrypoint
├── config.py           # Settings (pydantic-settings)
├── logging.py           # logging setup
├── database.py           # SQLAlchemy engine/session/Base (Phase 1: unused by any route)
├── api/
│   ├── router.py          # aggregates all API routers
│   └── health.py           # GET /health
├── ingestion/              # stub — Phase 2: SecurityEvent model + ingestion API
├── detection/               # stub — Phase 3+: detection mechanisms
├── risk_scoring/              # stub — later phase: risk scoring / decision engine
├── agent/                       # stub — later phase: agentic investigation
├── intelligence/                  # stub — later phase: threat intelligence
└── learning/                        # stub — later phase: adaptive learning
tests/
├── conftest.py             # shared TestClient fixture
├── test_app_startup.py      # app factory, route registration, DB module import
├── test_health.py             # /health contract
└── test_config.py               # settings defaults, env overrides, caching
```

The stub packages under `app/` contain only an `__init__.py` with a one-line docstring naming the phase that owns them. They exist so later phases have an agreed import location, not because anything is implemented there yet.

## Architectural decisions (Phase 1)

- **App factory pattern** (`create_app()`) so tests can build isolated `FastAPI` instances instead of relying on a single module-level singleton.
- **Postgres driver: `psycopg` (v3)**, not `psycopg2`, since it's SQLAlchemy 2.0's forward-recommended driver, has native async support the project will likely need once external I/O (threat intel, LLM calls) arrives in later phases, and is actively maintained.
- **Lazy database engine**: `create_engine()` never opens a connection by itself; nothing in Phase 1 queries the database, so the whole app runs and tests pass with no Postgres running. `get_db()` and `Base` exist now, unused, for Phase 2's `SecurityEvent` model and endpoints to build on.
- **Minimum-version dependency pins** (`>=`, no `==`, no upper bounds) rather than exact pins, since Python 3.14 is very new and hard-pinning today risks locking in a version predating some dependency's wheel for it. Exact pins/lockfile are deferred to the deployment-hardening phase.
- **`pyproject.toml` for pytest config** (`pythonpath = ["."]`) rather than an installable package or `sys.path` hacks — the simplest option given the app is only ever run via `uvicorn app.main:app`, never installed as a distributable package.
