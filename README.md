# Fraud Detection Platform

An adaptive fraud, phishing, and scam detection platform. The system is being built incrementally across 13 phases (rule-based detection → sender/URL/reputation analysis → risk scoring → detection orchestration → plugin → agentic investigation → threat intelligence → adaptive learning → hardening/deployment).

**This repository currently contains Phase 1 (project foundation), Phase 2 (SecurityEvent model and ingestion API), Phase 3 (rule-based detection engine), and Phase 4 (sender and URL intelligence).** No risk scoring, ML, agent, RAG, threat intelligence, or plugin exists yet — those arrive in later phases. What's here: the backend skeleton, a channel-independent `SecurityEvent` that can be ingested/validated/normalized/persisted, and a deterministic detection layer (content rules + sender analysis + URL analysis) that inspects an event and produces structured *evidence* — never a final verdict.

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

## Detection architecture

```
SecurityEvent
      │
      ▼
DetectionEngine
      │
      ├──▶ RuleEngine       ──┐
      ├──▶ SenderAnalyzer   ──┼──▶ DetectionEvidence (aggregated)
      └──▶ URLAnalyzer      ──┘
```

`DetectionEngine` (`app/detection/engine.py`) coordinates three detectors by default — `RuleEngine` (content rules), `SenderAnalyzer`, `URLAnalyzer` — and aggregates whatever `DetectionEvidence` they produce. **It never computes an overall risk score and never decides SAFE/PHISHING/BLOCK/QUARANTINE.** Those are later phases (Risk Engine, decision engine). It's built to accept further detectors later (ReputationAnalyzer, ML/anomaly/similarity detectors — none implemented yet) without any change to its own code — any object with `.evaluate(event) -> <something with .evidence>` plugs in.

`RuleEngine` (`app/detection/rule_engine.py`) owns and runs a list of deterministic `Rule`s. Each `Rule` (`app/detection/rule.py`, a `typing.Protocol`) inspects a `SecurityEvent` and returns **at most one** `DetectionEvidence`, never `True`/`False` and never a list — all matched signals from one rule's evaluation are aggregated into that single object's `details`, which is what keeps one OTP request (or one suspicious sender) from producing five near-identical pieces of evidence. `SenderAnalyzer` and `URLAnalyzer` (`app/detection/sender_analyzer.py` / `url_analyzer.py`) are thin wrappers that each run their own small `RuleEngine` internally — reusing the same aggregation/isolation logic rather than reimplementing it — over sender-specific and URL-specific rule sets.

Both `RuleEngine` and `DetectionEngine` isolate failures at their own level: if one rule (or detector) raises, it's logged, skipped, and every other rule/detector still runs — no raw exception text is ever exposed in a result.

New rules never require modifying `RuleEngine`: add a file under `app/detection/rules/` (content), `app/detection/sender_rules/` (sender), or `app/detection/url_rules/` (URL), and add one instance to the relevant list in `app/detection/registry.py` / `sender_analyzer.py` / `url_analyzer.py`.

### DetectionEvidence concept

```python
class DetectionEvidence(BaseModel):
    rule_id: str
    category: EvidenceCategory   # SOCIAL_ENGINEERING | CREDENTIAL_THEFT | FINANCIAL_FRAUD |
                                  # SENSITIVE_INFORMATION_REQUEST | SUSPICIOUS_ATTACHMENT |
                                  # SENDER_SPOOFING | SUSPICIOUS_URL
    severity: Severity           # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float            # 0.0-1.0
    description: str
    details: dict                # rule-specific, e.g. matched phrases / flagged attachments
```

**Evidence, severity, confidence, and final classification are four different things, and only the first three exist in this phase:**
- **Evidence** is a single rule's structured observation ("this text matched a credential-request pattern"), not a conclusion about the whole message.
- **Severity** describes how serious *that one signal* is in isolation (e.g. an executable attachment is inherently more serious than a generic "click here"), not the event's overall risk.
- **Confidence** is how strongly *that one rule* believes its own specific signal is genuinely present — never an overall phishing probability, never a final risk score, never an ML model's confidence (there is no ML in this phase).
- **Classification** (SAFE / PHISHING / BLOCK / QUARANTINE) doesn't exist yet at all — it's produced later by the Risk Engine (Phase 5) from the evidence this engine collects.

### Implemented rules — content (`RuleEngine`, `app/detection/rules/`)

| `rule_id` | Category | Signal |
|---|---|---|
| `URGENCY_PRESSURE` | `SOCIAL_ENGINEERING` | Multi-word urgency/pressure phrases ("act immediately", "account will be suspended", "final warning"...) |
| `CREDENTIAL_REQUEST` | `CREDENTIAL_THEFT` | A request verb (enter/provide/share/send/confirm...) co-occurring with a credential noun (password/OTP/PIN/verification code...) in the same sentence |
| `FINANCIAL_REQUEST` | `FINANCIAL_FRAUD` | A request verb co-occurring with a financial noun (payment/bank details/card details/wire transfer...) |
| `SENSITIVE_INFORMATION_REQUEST` | `SENSITIVE_INFORMATION_REQUEST` | A request verb co-occurring with an identity-verification noun (SSN, date of birth, passport number...) |
| `SUSPICIOUS_CALL_TO_ACTION` | `SOCIAL_ENGINEERING` | Generic imperative phrases ("click here", "verify now", "unlock account"...); severity escalates on 3+ distinct phrases |
| `IMPERSONATION_LANGUAGE` | `SOCIAL_ENGINEERING` | Generic institutional role-claim templates ("this is your bank", "on behalf of the delivery company"...) — no brand-name detection here, that's `SenderAnalyzer` below |
| `SUSPICIOUS_ATTACHMENT_REFERENCE` | `SUSPICIOUS_ATTACHMENT` | Attachment **metadata only** (filename/content_type/size/sha256): executable/script/macro extensions, double extensions (`invoice.pdf.exe`) — never opens or reads attachment bytes |

The `CREDENTIAL_REQUEST`/`FINANCIAL_REQUEST`/`SENSITIVE_INFORMATION_REQUEST` rules are **affirmative-only**: they fire only when a request verb genuinely co-occurs near the relevant noun, not merely when the noun is mentioned. `"Please use the OTP sent to your registered number."` does not trigger `CREDENTIAL_REQUEST` (no request verb — "use" is deliberately excluded), and `"Your payment of ₹500 was successful."` does not trigger `FINANCIAL_REQUEST` (no request verb near "payment") — both verified by dedicated tests using the exact wording from the design brief.

### SenderAnalyzer (`app/detection/sender_analyzer.py`, `app/detection/sender_rules/`)

Deterministic, fully offline sender intelligence — no DNS, no WHOIS, no reputation lookups (that's Phase 9 threat intelligence).

| `rule_id` | Signal |
|---|---|
| `SUSPICIOUS_SENDER_DOMAIN` | Aggregates structural anomalies of `sender_domain` into one evidence object: missing/malformed domain, unusually long domain, excessive subdomain labels, numeric character substitution (`paypa1`), suspicious hyphenation, random-looking labels |
| `SENDER_REPLY_TO_MISMATCH` | `reply_to` domain differs from `sender_domain` — never treated as automatically malicious (`MEDIUM`, fixed confidence) |
| `DISPLAY_NAME_DOMAIN_MISMATCH` | Display name claims a protected brand (via `ProtectedBrandRegistry`) but `sender_domain` doesn't match that brand's canonical domain |
| `LOOKALIKE_DOMAIN` | `sender_domain` closely resembles a protected brand's domain (via `DomainSimilarityAnalyzer`) |

### URLAnalyzer (`app/detection/url_analyzer.py`, `app/detection/url_rules/`)

Inspects every URL already present in `SecurityEvent.urls` as a **string only** — parsed via `urllib.parse` (zero network capability). Never performs HTTP requests, DNS resolution, redirect-following, content download, or contacts any external service.

| `rule_id` | Signal | Severity |
|---|---|---|
| `IP_ADDRESS_URL` | Hostname is a raw IP literal | `MEDIUM` (not automatically critical) |
| `INSECURE_HTTP_URL` | Scheme is `http` | `LOW` (a signal only, not malicious) |
| `EXCESSIVE_URL_LENGTH` | URL length exceeds a configurable threshold (default 200) | `LOW`/`MEDIUM`, scaled |
| `EXCESSIVE_SUBDOMAINS` | Hostname has more subdomain labels than a configurable threshold (default 3) | `MEDIUM` |
| `OBFUSCATED_URL` | Percent-encoding count *and* ratio both exceed conservative thresholds — a single ordinary `%20` never fires this | `MEDIUM` |
| `SUSPICIOUS_QUERY_PARAMETER` | A redirect/return/destination/next/continue/token/login parameter whose *value* itself looks URL-shaped (open-redirect pattern) — presence alone never fires this | `MEDIUM`/`HIGH` |
| `SUSPICIOUS_URL_PATH` | A sensitive path keyword (`/login`, `/verify`, `/account`...) **combined with** at least one other structural signal on the same URL — `https://paypal.com/login` alone never fires this | `LOW`/`MEDIUM` |
| `LOOKALIKE_URL_DOMAIN` | URL hostname closely resembles a protected brand's domain — reuses the exact same `DomainSimilarityAnalyzer` as `SenderAnalyzer`, not a duplicate implementation | `HIGH` |

### DomainSimilarityAnalyzer (`app/detection/domain_similarity.py`)

A reusable, deterministic lookalike-domain detector shared by `SenderAnalyzer` and `URLAnalyzer` (implemented once, not duplicated). Normalizes a domain (lowercase, strip `www.`, collapse to a practical last-two-labels registrable-domain approximation — not a full public suffix list), then compares it against a reference domain using a hand-rolled, bounded Levenshtein distance (`similarity = 1 - edit_distance / max(len_a, len_b)`), with a second pass undoing common leetspeak substitutions (`0→o, 1→l, 3→e, 4→a, 5→s, 7→t, @→a`) so `paypa1.com` scores as a near-perfect match against `paypal.com`. No external library is used — domain strings are short and the reference set is tiny, so a hand-rolled stdlib implementation is fast and genuinely sufficient. **Bounded**: any input longer than 253 characters (DNS's own domain length limit) is skipped rather than compared, so an attacker-supplied huge string can't force excessive computation. Conservative threshold (`0.85` by default) — an exact match is explicitly excluded (that's the legitimate domain, not a lookalike), and only genuinely close domains cross it (`mypal.com` vs `paypal.com`, for example, does not).

### ProtectedBrandRegistry (`app/detection/protected_brands.py`)

A small, hardcoded registry (`PayPal`, `Microsoft`, `Amazon`, `Google`, `Apple`, `Netflix`, `LinkedIn`, each with a canonical domain and a few display-name aliases) used by both `DISPLAY_NAME_DOMAIN_MISMATCH` and both `LOOKALIKE_DOMAIN`/`LOOKALIKE_URL_DOMAIN` rules, so brand names are never scattered across individual rule files. **This is intentionally small test data, not a threat-intelligence database** — it stands in for what a later phase (Phase 9) would replace with a real, larger, continuously-updated intelligence source.

### Example detection response

```json
{
  "event_id": "3f1b2c4a-1234-4a5b-9c6d-abcdef123456",
  "evidence": [
    {
      "rule_id": "URGENCY_PRESSURE",
      "category": "SOCIAL_ENGINEERING",
      "severity": "HIGH",
      "confidence": 0.5,
      "description": "Message contains urgency/pressure language commonly associated with social engineering.",
      "details": {"matched_phrases": ["act immediately", "will be suspended"]}
    },
    {
      "rule_id": "CREDENTIAL_REQUEST",
      "category": "CREDENTIAL_THEFT",
      "severity": "HIGH",
      "confidence": 0.65,
      "description": "Message requests that the recipient provide a password, OTP, PIN, or other login credential.",
      "details": {"matched_phrases": ["password", "pin"]}
    },
    {
      "rule_id": "LOOKALIKE_DOMAIN",
      "category": "SENDER_SPOOFING",
      "severity": "HIGH",
      "confidence": 1.0,
      "description": "Observed domain closely resembles a protected organization domain.",
      "details": {
        "observed_domain": "paypa1.com",
        "reference_domain": "paypal.com",
        "similarity": 1.0,
        "reason": "character_substitution"
      }
    }
  ]
}
```

No overall score, no verdict — just the structured evidence, ready for the Risk Engine to consume in a later phase.

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
├── detection/                # Phase 3-4: deterministic detection engine
│   ├── enums.py                 # EvidenceCategory, Severity
│   ├── evidence.py                # DetectionEvidence
│   ├── matching.py                  # shared phrase/regex helpers + confidence formula, no I/O
│   ├── rule.py                        # Rule Protocol + BaseRule
│   ├── rule_engine.py                   # RuleEngine, RuleEngineResult
│   ├── engine.py                          # Detector Protocol, DetectionResult, DetectionEngine
│   ├── registry.py                          # DEFAULT_RULES, build_default_rule_engine(), build_default_detectors()
│   ├── rules/                                 # Phase 3: one file per content rule (7 files)
│   ├── domain_similarity.py                     # Phase 4: DomainSimilarityAnalyzer (shared, bounded Levenshtein)
│   ├── protected_brands.py                        # Phase 4: ProtectedBrand, ProtectedBrandRegistry (test data)
│   ├── url_parsing.py                                # Phase 4: urlparse wrapper + shared URL structural checks
│   ├── sender_analyzer.py                              # Phase 4: SenderAnalyzer (wraps an internal RuleEngine)
│   ├── sender_rules/                                     # Phase 4: one file per sender rule (4 files)
│   ├── url_analyzer.py                                     # Phase 4: URLAnalyzer (wraps an internal RuleEngine)
│   └── url_rules/                                            # Phase 4: one file per URL rule (8 files)
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
├── test_security_events_security.py                # no-network-call / no-file-open proofs (ingestion)
├── detection_fixtures.py                             # 10 named SecurityEvent fixtures (not a test file)
├── test_detection_evidence_schema.py                   # DetectionEvidence validation/immutability
├── test_detection_rule_*.py (×7)                         # one file per rule, positive/negative/edge cases
├── test_detection_rule_engine.py                            # registration, isolation, determinism
├── test_detection_engine.py                                   # aggregation, future-detector accommodation
├── test_detection_fixture_cases.py                              # all 10 Phase 3 fixtures through the full engine
├── test_detection_security.py                                     # no-network-call / no-file-open / no-DNS proofs
├── test_domain_similarity.py                                        # Phase 4: DomainSimilarityAnalyzer unit tests
├── test_protected_brand_registry.py                                   # Phase 4: ProtectedBrandRegistry unit tests
├── test_detection_rule_suspicious_sender_domain.py, ...(×4)             # Phase 4: one file per sender rule
├── test_detection_rule_ip_address_url.py, ...(×8)                         # Phase 4: one file per URL rule
├── test_sender_analyzer.py, test_url_analyzer.py                            # Phase 4: analyzer-level aggregation/isolation
├── test_detection_engine_phase4.py                                           # Phase 4: 3-detector wiring, isolation
└── test_detection_fixture_cases_phase4.py                                      # Phase 4: sender/URL fixtures, mandated FPs
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

**Phase 3**
- **Rules consume `app.ingestion.schemas.SecurityEventResponse` directly**, not a new parallel model — it's already a plain, DB-free Pydantic object, so this satisfies "RuleEngine independent of the database" without inventing a duplicate schema that could drift out of sync. The coupling this creates (`app/detection → app/ingestion.schemas`) is one-directional onto a module with zero DB/session imports.
- **`Rule` as a `typing.Protocol`**, not an ABC — structural typing, no forced inheritance; a `BaseRule` convenience class is available but optional.
- **Each rule returns at most one `DetectionEvidence`, never a list** — this, combined with giving each rule category a distinct trigger vocabulary, is what makes duplicate near-identical evidence for one ask structurally impossible rather than needing dedup logic in `RuleEngine`.
- **`SENSITIVE_INFORMATION_REQUEST` uses a vocabulary deliberately disjoint from `CREDENTIAL_REQUEST`/`FINANCIAL_REQUEST`** (identity-verification terms only — SSN, date of birth, passport number — never password/OTP/card/bank terms). This is a considered resolution of an internal tension in the original design brief (its own examples for this rule listed passwords/OTPs/card details, which overlap with the other two rules) in favor of the brief's explicit anti-duplication instruction.
- **Context-aware "request" detection, not keyword presence**: `CREDENTIAL_REQUEST`/`FINANCIAL_REQUEST`/`SENSITIVE_INFORMATION_REQUEST` only fire when a request verb (enter/provide/share/confirm...) co-occurs with the relevant noun in the same sentence within a small word-gap window — affirmative pattern matching, not a keyword blocklist with hand-carved exceptions. This is what correctly excludes purely informational sentences ("use the OTP you were sent", "your payment was successful") without any message-specific special-casing.
- **Rule and detector-level failure isolation**: both `RuleEngine.evaluate()` and `DetectionEngine.evaluate()` catch and log exceptions per rule/detector rather than letting one failure abort the whole batch — applied at both layers since a future ML/anomaly detector is more failure-prone than a regex rule.
- **No new dependencies** — pure stdlib `re`/`enum` + the existing Pydantic stack, per the phase's own constraint against introducing ML/embeddings/vector-db/LLM libraries this early.

**Phase 4**
- **`SenderAnalyzer`/`URLAnalyzer` are siblings of `RuleEngine` under `DetectionEngine`**, both wired into its now-3-detector default. (The user's own architecture diagram drew `URLAnalyzer` visually nested under `SenderAnalyzer`; the instruction text — "extend `DetectionEngine` with two new detectors" — was treated as authoritative over the ASCII layout, since a 3-way branch is awkward to draw in box art. Flagged explicitly here in case that reading should be revisited.)
- **Each analyzer wraps its own internal `RuleEngine`** rather than reimplementing aggregation/isolation — `SenderAnalyzer`/`URLAnalyzer` are thin, and all the actual resilience logic (try/except per rule, failed-rule tracking) is written once and reused, not three times.
- **`DomainSimilarityAnalyzer` uses a hand-rolled Levenshtein distance, not an external library** — domain strings are short and the comparison set (the protected-brand registry) is tiny, so a small stdlib DP implementation is fast, bounded, and fully sufficient; a dependency wasn't "genuinely necessary" here.
- **Registrable-domain approximation, not a full public suffix list**: `DomainSimilarityAnalyzer.normalize()` collapses anything beyond 2 labels down to the last 2 (`mail.paypal.com` → `paypal.com`). This mishandles multi-part TLDs like `.co.uk` (would collapse to `co.uk`, losing the actual registrable label) — accepted as a documented simplification since the phase's comparison set is a small, curated `.com`-style registry, not general-purpose domain analysis.
- **`SUSPICIOUS_URL_PATH`/`SUSPICIOUS_QUERY_PARAMETER` are combination-only signals, not standalone triggers** — a sensitive path keyword or a redirect-family parameter alone is common in entirely legitimate URLs (`https://paypal.com/login` is real), so each only fires when combined with another structural signal (path) or when the parameter's *value* itself looks URL-shaped (query) — computed via shared pure functions rather than one rule depending on another rule's output, keeping rules independent of each other and of evaluation order.
- **`SUSPICIOUS_SENDER_DOMAIN` aggregates 6 structural sub-checks into one evidence object**, mirroring the Phase 3 attachment-rule pattern, rather than 6 separate `rule_id`s for what are all facets of "this domain string looks structurally off."
- **Similarity threshold (`0.85`) calibrated empirically**, not picked in the abstract: high enough that a plausible-but-unrelated word (`mypal.com` vs `paypal.com`, 0.80) does not cross it, low enough that every worked single-character-substitution example from the design brief (`paypa1`/`micros0ft`/`amaz0n`) scores a clean match. Documented here since "conservative" is inherently a judgment call, not a provable constant.
- **No new runtime dependencies** — `urllib.parse` and `ipaddress` (both stdlib) cover all URL/IP parsing; `urllib.parse` specifically makes zero network calls (confirmed distinct from `urllib.request`, which remains forbidden), so it's safe to use freely under the existing "no network calls" invariant.

## Known limitations

- **SQLite is a test-only stand-in for Postgres**, not a dialect-identical one. It's used because this dev environment has no Postgres/Docker available. Two concrete gaps: (1) `JSON` columns are generic on both dialects by choice, so there's no real JSONB indexing/containment querying yet on Postgres either — a future phase needing to query *inside* `headers`/`attachments` will need a `JSONB` column change (and, since `create_all()` can't alter existing tables, an Alembic migration at that point); (2) SQLite's `DATETIME` storage has no timezone-offset component, so a tz-aware value written to SQLite reads back naive — mitigated in `SecurityEventResponse` by re-attaching UTC to naive timestamps (a no-op on Postgres, where values are already aware), so the API contract stays consistently tz-aware regardless of which dialect served the read.
- **`init_db()` is create-only.** It will not add/alter columns on a table that already exists. Fine for fresh test databases and fresh `docker compose up` bring-ups; once a Postgres instance holds real data, schema changes need Alembic, not another `init_db()` call.
- **`recipients` has no per-entry format validation**, by design — its shape (email, phone number, username) depends on `event_type`, so only trimming/empty-filtering is applied, not email/phone validation.
- **The live `uvicorn`/Docker Postgres path is unverified end-to-end in this environment** (no Postgres or Docker installed here). The full create→persist→retrieve cycle is verified via the SQLite-backed test suite (`tests/test_security_events_api.py`), and the ORM model's DDL was verified by generating it against a real (file-based) SQLite database and inspecting the resulting table/columns/indexes — but a live run against Postgres itself has not been performed and should be done before relying on this in a real deployment.
- **The detection engine has no API route in this phase** — nothing in `app/api` calls `DetectionEngine` yet. It's a standalone, independently-testable Python component (matches the phase's own "keep detection independent of the UI/plugin" principle); wiring it into the ingestion flow or a dedicated endpoint is a later-phase decision, not made here.
- **Rules are keyword/phrase/regex-based on English text only** — no stemming, no other-language support, no semantic/embedding matching (explicitly out of scope this phase). A rephrased attack that avoids every listed phrase and verb will not be flagged by this layer alone; that's expected — this is the cheap, fast, low-signal-noise first layer, not the whole detection story.
- **`ProtectedBrandRegistry` covers only 7 brands** (PayPal, Microsoft, Amazon, Google, Apple, Netflix, LinkedIn) — explicitly test data standing in for a future real intelligence source (Phase 9), not exhaustive or authoritative. `DISPLAY_NAME_DOMAIN_MISMATCH`/`LOOKALIKE_DOMAIN`/`LOOKALIKE_URL_DOMAIN` cannot flag impersonation of any brand outside this list.
- **No live/offline WHOIS, DNS, domain-age, or reputation data is used anywhere in Phase 4** — every sender/URL signal is derived purely from string structure already present on the ingested `SecurityEvent`. This is by design (explicitly forbidden this phase), not an oversight — it's what makes the whole detection layer through Phase 4 deterministic, offline, and side-effect-free.
