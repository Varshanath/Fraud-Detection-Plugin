# Fraud Detection Platform

An adaptive fraud, phishing, and scam detection platform. The system is being built incrementally across 13 phases (rule-based detection → sender/URL/reputation analysis → risk scoring → detection orchestration → plugin → agentic investigation → threat intelligence → adaptive learning → hardening/deployment).

**This repository currently contains Phase 1 (project foundation) and Phase 2 (SecurityEvent model and ingestion API).** No detection logic, risk scoring, agent, ML, RAG, threat intelligence, or plugin exists yet — those arrive in later phases. What's here is the backend skeleton plus the platform's first real domain object: a channel-independent `SecurityEvent` that can be ingested, validated, normalized, and persisted.

## SecurityEvent concept

The platform is designed to eventually ingest security-relevant events from many channels — email, SMS, chat, reported URLs, and others — without hard-coding "email" as the primary shape of the data. Instead of an `EmailEvent`, every channel is represented as a generic `SecurityEvent` (`app/ingestion/models.py`) with:

- **Identity**: `event_id` (server-generated UUID), `event_type` (`EMAIL` / `SMS` / `CHAT` / `URL` / `OTHER`), `source` (free-text origin/connector name)
- **Sender**: `sender_email`, `sender_display_name`, `sender_domain` (derived from `sender_email` if not supplied), `reply_to`
- **Recipients**: `recipients` — plain strings, since the shape depends on channel (email address, phone number, username)
- **Content**: `subject`, `content`
- **Security-relevant data**: `urls`, `attachments` (metadata only — filename/content_type/size/sha256, **never raw file bytes**), `headers` (free-form dict)
- **Timestamps**: `event_timestamp` (when the source event occurred, client-supplied, optional), `ingested_at` (server-set on persist)

Almost every field is optional except `event_type` — a URL-type event has no `subject`/`recipients`, an SMS event has no `sender_email`. `event_type` is stored as a plain string (not a native database enum), so adding a new channel later (e.g. `TEAMS`) is a code-only change, no migration required.

**Ingestion is intentionally "dumb" by design**: it only validates, normalizes, and stores. It never fetches URLs, opens/executes attachments, makes external network calls, or treats event content as instructions — all content is untrusted data. Detection, scoring, and any AI/agent reasoning are later phases (`app/detection`, `app/risk_scoring`, `app/agent`), kept strictly separate from `app/ingestion`.

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

## Database setup

Tables are created with `Base.metadata.create_all()` via a small helper — no migration tool (e.g. Alembic) yet, since there's only one table and no schema history to manage. To create tables against your configured Postgres database:

```bash
python -c "from app.database import init_db; init_db()"
```

This requires a reachable Postgres instance (e.g. via `docker compose up db`) matching your `.env` settings. `init_db()` is create-only — it won't alter an already-existing table's columns, so once the model changes against a database that already holds data, introduce Alembic rather than re-running `init_db()`.

## API endpoints

| Method | Path | Description | Status codes |
|---|---|---|---|
| `GET` | `/health` | Liveness check | 200 |
| `POST` | `/api/v1/security-events` | Create a `SecurityEvent` | 201 created, 422 validation error |
| `GET` | `/api/v1/security-events/{event_id}` | Retrieve a `SecurityEvent` by id | 200 found, 404 not found, 422 malformed id |

### Example POST request

```bash
curl -X POST http://localhost:8000/api/v1/security-events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "EMAIL",
    "sender_email": "Attacker@Evil.EXAMPLE",
    "recipients": ["victim@example.com"],
    "subject": "Urgent: verify your account",
    "content": "Click here to verify",
    "urls": ["https://evil.example/login"],
    "attachments": [
      {
        "filename": "invoice.pdf",
        "content_type": "application/pdf",
        "size": 102400,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    ]
  }'
```

### Example response (`201 Created`)

```json
{
  "event_id": "3f1b2c4a-1234-4a5b-9c6d-abcdef123456",
  "event_type": "EMAIL",
  "source": null,
  "sender_email": "attacker@evil.example",
  "sender_display_name": null,
  "sender_domain": "evil.example",
  "reply_to": null,
  "recipients": ["victim@example.com"],
  "subject": "Urgent: verify your account",
  "content": "Click here to verify",
  "urls": ["https://evil.example/login"],
  "attachments": [
    {
      "filename": "invoice.pdf",
      "content_type": "application/pdf",
      "size": 102400,
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ],
  "headers": {},
  "event_timestamp": null,
  "ingested_at": "2026-08-13T12:00:00+00:00"
}
```

Note `sender_email` is lowercased/trimmed and `sender_domain` is derived automatically — this is normalization, not detection (no risk/classification happens in this phase).

## Running tests

```bash
pytest -v
```

Tests do not require a live Postgres instance. Route/config tests never touch the database (lazy engine, no query at import/startup). `SecurityEvent` persistence and API tests run against an **in-memory SQLite database** (`tests/conftest.py`), not Postgres — the ORM model uses portable SQLAlchemy types (`Uuid`, generic `JSON`) so the same model works against SQLite in tests and Postgres in Docker/prod unmodified. This is a documented stand-in, not a claim that SQLite and Postgres behave identically (see Known limitations below).

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
├── database.py           # SQLAlchemy engine/session/Base/get_db + init_db()
├── api/
│   ├── router.py          # aggregates all API routers
│   ├── health.py           # GET /health
│   └── security_events.py   # POST/GET /api/v1/security-events
├── ingestion/                # Phase 2: SecurityEvent model + ingestion API
│   ├── enums.py                # EventType
│   ├── models.py                 # SecurityEvent ORM model
│   ├── schemas.py                  # Pydantic request/response schemas
│   ├── normalization.py              # pure trim/lowercase/dedupe/tz functions, no I/O
│   └── service.py                      # create_security_event, get_security_event
├── detection/               # stub — Phase 3+: detection mechanisms
├── risk_scoring/              # stub — later phase: risk scoring / decision engine
├── agent/                       # stub — later phase: agentic investigation
├── intelligence/                  # stub — later phase: threat intelligence
└── learning/                        # stub — later phase: adaptive learning
tests/
├── conftest.py                          # TestClient fixture + SQLite test DB fixtures
├── test_app_startup.py                   # app factory, route registration, DB module import
├── test_health.py                         # /health contract
├── test_config.py                          # settings defaults, env overrides, caching
├── test_security_event_normalization.py     # pure unit tests on normalization.py
├── test_security_event_schemas.py            # Pydantic validation tests
├── test_security_event_model.py                # ORM persistence tests (SQLite)
├── test_security_events_api.py                   # full-stack POST/GET tests
└── test_security_events_security.py                # no-network-call / no-file-open proofs
```

The stub packages under `app/` contain only an `__init__.py` with a one-line docstring naming the phase that owns them. They exist so later phases have an agreed import location, not because anything is implemented there yet.

## Architectural decisions

**Phase 1**
- **App factory pattern** (`create_app()`) so tests can build isolated `FastAPI` instances instead of relying on a single module-level singleton.
- **Postgres driver: `psycopg` (v3)**, not `psycopg2`, since it's SQLAlchemy 2.0's forward-recommended driver, has native async support the project will likely need once external I/O (threat intel, LLM calls) arrives in later phases, and is actively maintained.
- **Lazy database engine**: `create_engine()` never opens a connection by itself; route/config tests pass with no Postgres running.
- **Minimum-version dependency pins** (`>=`, no `==`, no upper bounds) rather than exact pins, since Python 3.14 is very new and hard-pinning today risks locking in a version predating some dependency's wheel for it. Exact pins/lockfile are deferred to the deployment-hardening phase.
- **`pyproject.toml` for pytest config** (`pythonpath = ["."]`) rather than an installable package or `sys.path` hacks — the simplest option given the app is only ever run via `uvicorn app.main:app`, never installed as a distributable package.

**Phase 2**
- **Generic `SecurityEvent`, not `EmailEvent`**: every field that's channel-specific (recipients, sender, urls) is optional and untyped enough to cover email/SMS/chat/URL/other without a schema change per channel.
- **`event_type` stored as `String`, not a native Postgres `ENUM`**: validated by a Python `str, Enum` at the Pydantic layer instead. Adding a new channel later is a code change, not a migration.
- **Portable SQLAlchemy types** (`sqlalchemy.Uuid`, generic `JSON` not `JSONB`) so the same `SecurityEvent` model works unmodified against SQLite (tests, this sandbox) and Postgres (Docker/prod). `event_id`/`ingested_at` use Python-side defaults (`uuid.uuid4`, `datetime.now(timezone.utc)`) rather than `server_default`, since `gen_random_uuid()`/`func.now()` behave differently or don't exist across dialects.
- **Attachments are metadata-only** — `filename`/`content_type`/`size`/`sha256` stored as a JSON list column; no separate table (no independent lifecycle yet to justify a join) and no raw file bytes anywhere in the schema.
- **Plain service functions, not a repository class** (`app/ingestion/service.py`) — a full repository abstraction isn't justified for one table and two operations.
- **Lenient URL validation, not Pydantic's strict `AnyUrl`**: rejects obviously-malformed input but accepts scheme-prefixed, deliberately-obfuscated attacker URLs, since capturing those as evidence is the point of ingestion, not sanitizing them away.
- **`email-validator` added as a new dependency** — required for Pydantic's `EmailStr` to exist at all. Confirmed in pydantic's own source that `EmailStr` hardcodes `check_deliverability=False`, so validating an email address never triggers a DNS lookup or any other network call.
- **No Alembic yet** — a single `init_db()` (`Base.metadata.create_all()`) is enough for one table with no migration history. Introduce Alembic once the model needs to change against a Postgres database that already holds data.

## Known limitations

- **SQLite is a test-only stand-in for Postgres**, not a dialect-identical one. It's used because this dev environment has no Postgres/Docker available. Two concrete gaps: (1) `JSON` columns are generic on both dialects by choice, so there's no real JSONB indexing/containment querying yet on Postgres either — a future phase needing to query *inside* `headers`/`attachments` will need a `JSONB` column change (and, since `create_all()` can't alter existing tables, an Alembic migration at that point); (2) SQLite's `DATETIME` storage has no timezone-offset component, so a tz-aware value written to SQLite reads back naive — mitigated in `SecurityEventResponse` by re-attaching UTC to naive timestamps (a no-op on Postgres, where values are already aware), so the API contract stays consistently tz-aware regardless of which dialect served the read.
- **`init_db()` is create-only.** It will not add/alter columns on a table that already exists. Fine for fresh test databases and fresh `docker compose up` bring-ups; once a Postgres instance holds real data, schema changes need Alembic, not another `init_db()` call.
- **`recipients` has no per-entry format validation**, by design — its shape (email, phone number, username) depends on `event_type`, so only trimming/empty-filtering is applied, not email/phone validation.
- **The live `uvicorn`/Docker Postgres path is unverified end-to-end in this environment** (no Postgres or Docker installed here). The full create→persist→retrieve cycle is verified via the SQLite-backed test suite (`tests/test_security_events_api.py`), and the ORM model's DDL was verified by generating it against a real (file-based) SQLite database and inspecting the resulting table/columns/indexes — but a live run against Postgres itself has not been performed and should be done before relying on this in a real deployment.
