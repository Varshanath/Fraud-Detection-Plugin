# Fraud Detection Platform

Adaptive fraud/phishing/scam detection platform, built incrementally across 13 planned phases.

- **Implemented (Phases 1-8)**: `SecurityEvent` ingestion, rule-based detection, sender/URL intelligence, risk scoring, confidence-based escalation, agent investigation, real LLM-backed investigation reasoner.
- **Not yet implemented**: ML, RAG, threat intelligence, browser/email plugin, adaptive learning.
- **Pipeline**: `SecurityEvent → DetectionEngine → RiskEngine → EscalationPolicy → (if ESCALATE) AgentInvestigationEngine [FakeAgentReasoner | LLMReasoner] → RiskEngine (reassessment)`.
- Detection produces *evidence*, never a verdict. The agent — deterministic or LLM-backed — investigates but never decides the final action. **Final risk and action are always determined by the deterministic RiskEngine.**

## SecurityEvent

`app/ingestion/models.py` — one generic model for every channel (email/SMS/chat/URL/other), not per-channel models.

- **Identity**: `event_id`, `event_type`, `source`
- **Sender**: `sender_email`, `sender_display_name`, `sender_domain` (derived if omitted), `reply_to`
- **Recipients**: plain strings (shape varies by channel)
- **Content**: `subject`, `content`
- **Security data**: `urls`, `attachments` (metadata only, never raw bytes), `headers`
- **Timestamps**: `event_timestamp`, `ingested_at`
- Only `event_type` is required.
- Ingestion only validates/normalizes/stores — no URL fetching, no attachment opening, no network calls. Content is always untrusted data, never instructions.

## Detection architecture

```
SecurityEvent
      │
      ▼
DetectionEngine
      │
      ├──▶ RuleEngine       ──┐
      ├──▶ SenderAnalyzer   ──┼──▶ DetectionEvidence[]
      └──▶ URLAnalyzer      ──┘
```

- `DetectionEngine` (`app/detection/engine.py`) runs 3 detectors, aggregates evidence — never scores or classifies.
- Detectors are pluggable: any object with `.evaluate(event) -> <has .evidence>`.
- `RuleEngine` runs `Rule`s (`app/detection/rule.py`, a `Protocol`); each returns **at most one** evidence item.
- `SenderAnalyzer`/`URLAnalyzer` wrap their own internal `RuleEngine`.
- All three isolate failures — one rule/detector raising never aborts the batch.
- New rule = new file under `rules/` / `sender_rules/` / `url_rules/` + one registration line.

```python
class DetectionEvidence(BaseModel):
    rule_id: str
    category: EvidenceCategory   # SOCIAL_ENGINEERING | CREDENTIAL_THEFT | FINANCIAL_FRAUD |
                                  # SENSITIVE_INFORMATION_REQUEST | SUSPICIOUS_ATTACHMENT |
                                  # SENDER_SPOOFING | SUSPICIOUS_URL
    severity: Severity           # LOW | MEDIUM | HIGH | CRITICAL
    confidence: float            # 0.0-1.0 -- this rule's confidence in its own signal
    description: str
    details: dict
```

### Content rules (`app/detection/rules/`)

| `rule_id` | Category | Signal |
|---|---|---|
| `URGENCY_PRESSURE` | SOCIAL_ENGINEERING | Urgency/pressure phrases |
| `CREDENTIAL_REQUEST` | CREDENTIAL_THEFT | Request verb + credential noun (password/OTP/PIN) |
| `FINANCIAL_REQUEST` | FINANCIAL_FRAUD | Request verb + financial noun (payment/bank details) |
| `SENSITIVE_INFORMATION_REQUEST` | SENSITIVE_INFORMATION_REQUEST | Request verb + identity noun (SSN, DOB, passport) |
| `SUSPICIOUS_CALL_TO_ACTION` | SOCIAL_ENGINEERING | Generic imperatives; escalates on 3+ phrases |
| `IMPERSONATION_LANGUAGE` | SOCIAL_ENGINEERING | Generic institutional role-claims |
| `SUSPICIOUS_ATTACHMENT_REFERENCE` | SUSPICIOUS_ATTACHMENT | Executable/script/double extensions, metadata only |

- The three "request" rules are **affirmative-only** — need a request verb co-occurring with the noun, not just the noun.

### SenderAnalyzer (`app/detection/sender_analyzer.py`)

Deterministic, offline — no DNS/WHOIS/reputation lookups.

| `rule_id` | Signal |
|---|---|
| `SUSPICIOUS_SENDER_DOMAIN` | Structural anomalies (malformed, excessive length/subdomains, numeric substitution) |
| `SENDER_REPLY_TO_MISMATCH` | `reply_to` domain ≠ `sender_domain` (MEDIUM, not automatically malicious) |
| `DISPLAY_NAME_DOMAIN_MISMATCH` | Display name claims a protected brand, domain doesn't match |
| `LOOKALIKE_DOMAIN` | Domain closely resembles a protected brand's domain |

### URLAnalyzer (`app/detection/url_analyzer.py`)

String-only inspection (`urllib.parse` — zero network capability). Never fetches, resolves, or follows.

| `rule_id` | Signal |
|---|---|
| `IP_ADDRESS_URL` | Hostname is a raw IP |
| `INSECURE_HTTP_URL` | `http` scheme |
| `EXCESSIVE_URL_LENGTH` | Over configurable length threshold |
| `EXCESSIVE_SUBDOMAINS` | Over configurable subdomain-count threshold |
| `OBFUSCATED_URL` | Heavy percent-encoding (count and ratio) |
| `SUSPICIOUS_QUERY_PARAMETER` | Redirect/login param whose value looks URL-shaped |
| `SUSPICIOUS_URL_PATH` | Sensitive path keyword + another structural signal |
| `LOOKALIKE_URL_DOMAIN` | Hostname resembles a protected brand |

- **DomainSimilarityAnalyzer**: shared by both analyzers; hand-rolled bounded Levenshtein + leetspeak-substitution pass (`0→o, 1→l, 3→e...`); threshold `0.85`; bounded to 253 chars; no external library.
- **ProtectedBrandRegistry**: small hardcoded set (PayPal, Microsoft, Amazon, Google, Apple, Netflix, LinkedIn) — test data, not exhaustive.

## Risk Engine

```
DetectionEvidence[] → RiskEngine → risk_score (0-100) + confidence (0.0-1.0) + classification + recommended_action
```

- `RiskEngine` (`app/risk_scoring/risk_engine.py`) is a pure function, no FastAPI/SQLAlchemy/network/filesystem access.
- `DetectionEngine` discovers evidence; `RiskEngine` evaluates it — never merged.
- `DetectionPipeline` (`app/pipeline.py`) chains them: `.evaluate(event) -> PipelineResult`.

**Five separate concepts:**
- **Evidence** — one detector's signal.
- **Risk score** (0-100) — aggregate concern, from a configurable policy.
- **Confidence** (0.0-1.0) — trust in the assessment. **Not** `risk_score / 100`.
- **Classification** — coarse bucket of risk score.
- **Recommended action** — derived only from classification, never raw evidence.
- No `CONFIRMED_FRAUD` anywhere — only risk-assessment language.

**Scoring** (`ScoringPolicy`, `app/risk_scoring/scoring_policy.py`, frozen self-validating Pydantic):
1. `contribution = severity_weight[severity] × confidence`. Weights: `LOW=10, MEDIUM=30, HIGH=55, CRITICAL=85`.
2. Correlated evidence deduped via `rule_id → correlation_group` map (default: `LOOKALIKE_DOMAIN` + `LOOKALIKE_URL_DOMAIN`). Only the max-contribution item per group counts.
3. `risk_score = floor(min(100, max(0, sum(counted contributions))))`.
4. Same-category-different-rule_id evidence stays fully additive (category ≠ correlation group).
5. Explainability invariant: `raw_score_before_cap == sum(counted contributions)`.

**Confidence** (independent of risk_score): `confidence = clamp(0.6 × avg_confidence_of_counted + 0.4 × diversity_ratio, 0, 1)`, `diversity_ratio = min(distinct_correlation_groups / 4, 1.0)`.

| Scenario | risk_score | confidence |
|---|---|---|
| One `CRITICAL`, confidence 1.0 | 85 | **0.70** |
| Four independent `LOW`, confidence 0.95 each | 38 | **0.97** |

**Classification thresholds**: 0-19 `SAFE` · 20-39 `LOW_RISK` · 40-69 `SUSPICIOUS` · 70-89 `HIGH_RISK` · 90-100 `CRITICAL` (configurable, contiguous 0-100).

**Action mapping**: `SAFE→ALLOW` · `LOW_RISK→MONITOR` · `SUSPICIOUS→WARN` · `HIGH_RISK→QUARANTINE` · `CRITICAL→BLOCK`.

```json
{
  "risk_score": 63, "confidence": 0.6, "classification": "SUSPICIOUS", "recommended_action": "WARN",
  "scoring_breakdown": [
    {"rule_id": "URGENCY_PRESSURE", "severity": "HIGH", "evidence_confidence": 0.5, "contribution": 27.5, "counted": true},
    {"rule_id": "CREDENTIAL_REQUEST", "severity": "HIGH", "evidence_confidence": 0.65, "contribution": 35.75, "counted": true}
  ]
}
```

> **The scoring policy and thresholds are initial deterministic heuristics and must be calibrated against a labeled evaluation dataset before production use.**

## Escalation & Orchestration

```
RiskAssessment → EscalationPolicy ──┬── Sufficient evidence ──▶ DECIDE
                                     └── Insufficient evidence ──▶ ESCALATE ──▶ Agent (Phase 7)
```

- `AnalysisOrchestrator` (`app/orchestrator.py`, app root): `DetectionEngine → DetectionCoverage → RiskEngine → EscalationPolicy → (Agent, if escalating) → AnalysisResult`.
- Each detector runs exactly once — no retry loop.
- **DetectionCoverage** (`app/escalation/detection_coverage.py`): tracks per-detector success/failure (`DetectorStatus`, `app/detection/coverage.py`) instead of silently swallowing it. Exposes `detectors_attempted/succeeded/failed`, `failed_detector_names`, `is_complete`.
- **EscalationPolicy** — `evaluate(RiskAssessment, evidence, DetectionCoverage) -> EscalationDecision`, checked in order:
  1. `INSUFFICIENT_DETECTOR_COVERAGE` — any detector failed
  2. `INSUFFICIENT_EVIDENCE` — below `min_evidence_count` (default 1); **skipped when evidence is zero and every detector succeeded** — see [CLEAN vs INCOMPLETE detection coverage](#clean-vs-incomplete-detection-coverage)
  3. `HIGH_RISK_LOW_CONFIDENCE` — risk ≥ 70 and confidence < 0.6
  4. `AMBIGUOUS_SIGNAL` — confidence < 0.6, classification `SUSPICIOUS`
  5. `LOW_CONFIDENCE` — confidence < 0.6, otherwise (also skipped in the same zero-evidence/complete-coverage case)

| # | risk | confidence | Decision | Reason |
|---|---|---|---|---|
| 1 | 15 | 0.95 | `NO_ESCALATION` | — |
| 2 | 88 | 0.95 | `NO_ESCALATION` | — |
| 3 | 58 | 0.45 | `ESCALATE` | `AMBIGUOUS_SIGNAL` |
| 4 | 82 | 0.52 | `ESCALATE` | `HIGH_RISK_LOW_CONFIDENCE` |
| 5 | 25 | 0.35 | `ESCALATE` | `LOW_CONFIDENCE` |

- High risk + high confidence never escalates (case 2) — already actionable.
- Low risk + low confidence still escalates (case 5) — "probably safe" ≠ "we don't know."
- `priority` derives from risk band alone. `recommended_next_stage` is `NONE`/`DEEP_ANALYSIS` only.

## CLEAN vs INCOMPLETE detection coverage

Zero evidence is ambiguous on its own, so `EscalationPolicy.evaluate()` resolves it using the existing `DetectionCoverage.is_complete` flag rather than a new model or duplicated state:

- **CLEAN** — every detector ran successfully and still found nothing (`len(evidence) == 0 and coverage.is_complete`). This means "we looked, using every available deterministic mechanism, and found no suspicious signal" — not low confidence. `ConfidenceCalculator` returning `0.0` here is a definitional artifact (there is nothing to average), not a trust signal. **Zero evidence does not mean low confidence.** → `NO_ESCALATION`, agent not invoked.
- **INCOMPLETE** — one or more detectors failed (`coverage.detectors_failed > 0`). Zero evidence here means "we don't know", not "clean". **A failed detector is not the same as a clean result.** → still escalates via `INSUFFICIENT_DETECTOR_COVERAGE`, unchanged.

The agent/LLM investigation layer is an uncertainty-resolution mechanism for genuinely ambiguous or incomplete cases — not a default path every event passes through. This distinction exists partly to control unnecessary token/LLM usage: without it, every zero-signal benign event (a large share of real traffic) would trigger an agent investigation and, with `LLM_ENABLED=true`, a real billed LLM call, for no benefit.

## Agent Investigation Engine

```
EscalationPolicy ── ESCALATE ──▶ AgentInvestigationEngine ──▶ InvestigationResult ──▶ Additional Evidence ──▶ RiskEngine ──▶ Final RiskAssessment
```

> **The agent is only invoked after the deterministic escalation policy determines that deeper investigation is required.**

> **The agent does not directly determine the final security action.**

- `AgentInvestigationEngine` (`app/agent/engine.py`) runs at most once per `evaluate()`, only on `ESCALATE`. Produces more `DetectionEvidence` only — never a verdict or hand-set score.
- **InvestigationContext** (`app/agent/models.py`): reuses existing models (event, evidence, risk_assessment, escalation_decision, detection_coverage) + `context_depth`.
- **ToolRegistry** (`app/agent/tool_registry.py`): fixed `dict[name, Tool]`, no arbitrary-callable execution. 4 pure, local, no-I/O tools (`app/agent/tools.py`):

| Tool | Returns |
|---|---|
| `inspect_sender` | Sender/reply-to domains, match check, existing sender evidence |
| `inspect_urls` | Per-URL parsed structure, existing URL evidence |
| `inspect_content` | Subject/content, existing content evidence |
| `inspect_existing_evidence` | Evidence grouped by category and rule_id |

- No shell/subprocess/filesystem/HTTP/database/code-exec tool exists.
- **Tool selection** (`select_tools_for()`): reason-specific subset, not all 4 blindly. `INSUFFICIENT_DETECTOR_COVERAGE` maps each failed detector to its matching tool.
- **AgentReasoner**: `Protocol` (`reason(context, tool_results) -> AgentReasoningResult`). `FakeAgentReasoner` is the only implementation — deterministic, reasons only over structured `ToolResult.data`, never raw text. Produces agent-sourced evidence (e.g. `AGENT_SENDER_REPLY_TO_MISMATCH`) when warranted.
- **Prompt injection defense**: `app/agent/prompts.py` delimits untrusted content (`<UNTRUSTED_EMAIL_CONTENT>` tags, forged-tag neutralization) for a future prompt-based reasoner. `FakeAgentReasoner` doesn't use it — structured-data-only reasoning is the actual defense. Verified against the required injection phrases: identical tool selection/evidence as benign content.
- **Budget**: `max_tool_calls=4` hard cap; truncation → `status=PARTIAL`. No loop/retry/recursion.
- **Failure handling**: failing tool → `ToolResult(success=False)`, investigation continues; failing/malformed reasoner → `InvestigationResult(status=FAILED)`. `investigate()` never raises.
- **Reassessment**: only when `investigation.recommended_reassessment` is `True` — `final_risk_assessment = RiskEngine.evaluate(initial_evidence + additional_evidence)`. Otherwise stays `None`. `AnalysisResult` always distinguishes initial vs. final.
- **Token optimization**: `ContextDepth` defined but not yet enforced by `FakeAgentReasoner` (no prompt is rendered). Real lever today: `select_tools_for()` + the escalation gate itself. `LLMReasoner` (below) is the first consumer of a rendered, bounded prompt.

## Real LLM Investigation Reasoner

```
EscalationPolicy ── ESCALATE ──▶ AgentInvestigationEngine ──▶ LLMReasoner ──▶ AnthropicLLMClient (1 call)
                                                                    │
                                                        structured JSON, strictly validated
                                                                    │
                                                                    ▼
                                                          Additional Evidence ──▶ RiskEngine ──▶ Final RiskAssessment
```

> **The LLM is an investigator, not the final security authority.**

> **Final risk and action are always determined by the deterministic RiskEngine.**

- `LLMReasoner` (`app/agent/llm_reasoner.py`) is a second `AgentReasoner` implementation, behind the exact same Protocol as `FakeAgentReasoner` — `AgentInvestigationEngine` doesn't know or care which one it's talking to. **`AgentInvestigationEngine()`'s own default is still `FakeAgentReasoner()`** — `LLMReasoner` is opt-in via `reasoner=build_reasoner(settings)`, not a new default.
- **Provider**: Anthropic (`anthropic` SDK, Messages API) — the one supported provider, no provider registry/router/factory. `anthropic` is imported **lazily inside `AnthropicLLMClient.complete()`**, not at module level, so the test suite runs fully offline without the package installed.
- **Configuration** (`app/config.py`, same `pydantic-settings` pattern as everything else): `LLM_ENABLED` (default `false`), `LLM_MODEL` (default `claude-sonnet-5`), `LLM_API_KEY` (`SecretStr`, never logged/repr'd), `LLM_TIMEOUT` (default 20s), `LLM_MAX_OUTPUT_TOKENS` (default 1024). `build_reasoner(settings)` is the only place enablement is decided: disabled, or enabled with no key → `DisabledLLMReasoner()` (no LLM call, returns a clearly-flagged skipped result — `InvestigationResult.status = SKIPPED`); enabled + key → real `LLMReasoner`. The application is fully functional with the LLM disabled.
- **Targeted context**: `build_prompt()` (`app/agent/prompts.py`) renders 6 explicit, delimited sections — SYSTEM INSTRUCTIONS / INVESTIGATION OBJECTIVE / TRUSTED STRUCTURED CONTEXT (risk score, confidence, classification, escalation reason, detector coverage, existing evidence) / UNTRUSTED EVENT CONTENT / TOOL RESULTS / REQUIRED OUTPUT FORMAT. The full `SecurityEvent` is never sent — `ContentLimits` (`max_subject_chars`, `max_content_chars`, `max_urls`, `max_url_chars`, `max_evidence_items`, `max_tool_result_chars`) hard-caps everything, and truncation is recorded explicitly in the prompt (`content_truncated: true/false`) so the LLM is told, not left to assume, that it saw everything.
- **Structured output**: the LLM must return one JSON object matching `LLMInvestigationResponse`/`LLMFinding` (strict Pydantic — enum-constrained `finding_type`/`severity`/`uncertainty`, `confidence` bounded 0.0-1.0, length-capped strings, capped finding count). **No `risk_score`/`classification`/`recommended_action` field exists in this schema** — the LLM is structurally incapable of setting them. Any validation failure (bad JSON, wrong enum, out-of-bounds value, oversized response) raises and is caught by `AgentInvestigationEngine`'s existing failure handling (Phase 7, unchanged) → `InvestigationResult(status=FAILED)`, never a crash.
- **Prompt injection defense**: `wrap_untrusted_content()` delimits event content and neutralizes forged tags (Phase 7, reused). The LLM never receives tool-calling capability — it only ever sees already-executed `ToolResult`s as text and returns findings, so it cannot invent a new tool by construction, not just by instruction.
- **One call, no loop**: `LLMReasoner.reason()` calls `client.complete()` **exactly once**. No retry, self-reflection, or planner loop.
- **Evidence**: each validated finding becomes a real `DetectionEvidence` with an LLM-sourced `rule_id` (`AGENT_LLM_SENDER_ANALYSIS` / `AGENT_LLM_URL_ANALYSIS` / `AGENT_LLM_CONTENT_ANALYSIS` / `AGENT_LLM_INVESTIGATION`). LLM confidence is evidence confidence only — never a final phishing probability.
- **Failure handling**: client timeout/auth/HTTP error/malformed/empty response — all caught, `investigation.status = FAILED`, the initial `RiskAssessment` is preserved, `final_risk_assessment` stays `None`. Never crashes.
- **Privacy**: event content leaves the local process only when `LLM_ENABLED=true`. Logging records event_id/model/duration/finding-count/failure-category only — never the prompt, response, or API key.
- **Caching**: not implemented this phase — the `AgentReasoner`/`LLMClient` seams mean a caching layer can wrap either later without changing `AgentInvestigationEngine`.

## Setup

```bash
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Windows (Git Bash) / macOS / Linux
source .venv/Scripts/activate

pip install -r requirements-dev.txt
cp .env.example .env
```

- Python 3.11+ (developed against 3.14). Docker + Docker Compose optional.

**Database** (create-only, no migration tool yet):
```bash
python -c "from app.database import init_db; init_db()"
```
Requires a reachable Postgres (e.g. `docker compose up db`).

**Run locally**:
```bash
uvicorn app.main:app --reload
curl http://localhost:8000/health   # {"status":"healthy"}
```

**Run with Docker**:
```bash
docker compose up --build
```

**Run tests**:
```bash
pytest -v
```
No live Postgres required — `SecurityEvent` tests run against in-memory SQLite (`tests/conftest.py`).

## API endpoints

| Method | Path | Description | Status codes |
|---|---|---|---|
| `GET` | `/health` | Liveness check | 200 |
| `POST` | `/api/v1/security-events` | Create a `SecurityEvent` | 201, 422 |
| `GET` | `/api/v1/security-events/{event_id}` | Retrieve by id | 200, 404, 422 |

```bash
curl -X POST http://localhost:8000/api/v1/security-events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "EMAIL",
    "sender_email": "Attacker@Evil.EXAMPLE",
    "recipients": ["victim@example.com"],
    "subject": "Urgent: verify your account",
    "content": "Click here to verify",
    "urls": ["https://evil.example/login"]
  }'
```

`sender_email` is lowercased/trimmed, `sender_domain` derived automatically — normalization, not detection.

## Configuration

`app/config.py` (`pydantic-settings`), env vars + optional `.env`, all fields default.

| Variable | Default | Purpose |
|---|---|---|
| `APP_NAME` | `Fraud Detection Platform` | FastAPI app title |
| `ENVIRONMENT` | `development` | Environment label |
| `DEBUG` | `true` | FastAPI debug mode |
| `POSTGRES_USER` / `PASSWORD` / `HOST` / `PORT` / `DB` | `fraud_detection` / ... / `localhost` / `5432` / `fraud_detection` | Postgres connection |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LLM_ENABLED` | `false` | Enables `LLMReasoner` (Anthropic); app runs fully without it |
| `LLM_MODEL` | `claude-sonnet-5` | Model id passed to the Anthropic Messages API |
| `LLM_API_KEY` | *(empty)* | Anthropic API key; required only if `LLM_ENABLED=true` |
| `LLM_TIMEOUT` | `20` | LLM request timeout, seconds |
| `LLM_MAX_OUTPUT_TOKENS` | `1024` | Hard output token cap per investigation |

## Project structure

```
app/
├── main.py, config.py, logging.py, database.py
├── api/                       # router.py, health.py, security_events.py
├── ingestion/                 # Phase 2: SecurityEvent model + ingestion API
├── detection/                 # Phase 3-4: RuleEngine, SenderAnalyzer, URLAnalyzer, DetectionEngine
│   ├── rules/, sender_rules/, url_rules/     # one file per rule
│   ├── domain_similarity.py, protected_brands.py, url_parsing.py
│   └── coverage.py            # Phase 6: DetectorStatus/DetectorOutcome
├── risk_scoring/               # Phase 5: ScoringPolicy, RiskEngine, RiskAssessment
├── pipeline.py                  # Phase 5: DetectionPipeline (app root)
├── escalation/                   # Phase 6: EscalationPolicy, DetectionCoverage, EscalationDecision
├── orchestrator.py                # Phase 6-7: AnalysisOrchestrator, AnalysisResult (app root)
├── agent/                          # Phase 7-8: agent investigation engine
│   ├── enums.py, models.py, context.py, tools.py, tool_registry.py, investigation.py, prompts.py, engine.py
│   └── llm_reasoner.py               # Phase 8: LLMClient, AnthropicLLMClient, LLMReasoner, build_reasoner()
├── intelligence/                    # stub — later phase
└── learning/                          # stub — later phase
tests/
├── conftest.py, detection_fixtures.py, risk_fixtures.py, escalation_fixtures.py, agent_fixtures.py,
│   llm_fixtures.py                                                # fixtures
├── test_security_event_*.py, test_security_events_*.py         # Phase 2
├── test_detection_*.py, test_domain_similarity.py, test_protected_brand_registry.py,
│   test_sender_analyzer.py, test_url_analyzer.py                # Phase 3-4
├── test_risk_*.py, test_classifier.py, test_confidence_calculator.py,
│   test_scoring_policy.py, test_detection_pipeline.py            # Phase 5
├── test_escalation_*.py, test_analysis_orchestrator.py,
│   test_clean_vs_incomplete_detection.py                          # Phase 6
├── test_agent_*.py, test_orchestrator_agent_integration.py       # Phase 7
└── test_llm_*.py, test_orchestrator_llm_integration.py           # Phase 8
```

Stub packages under `app/` contain only an `__init__.py` naming the phase that owns them.

## Key design decisions

- App factory pattern (`create_app()`) for isolated test instances; lazy DB engine (no connection at import).
- `psycopg` v3 driver; portable SQLAlchemy types (`Uuid`, generic `JSON`) — same model on SQLite and Postgres.
- Generic `SecurityEvent`, not per-channel models; `event_type` is a validated string, not a DB enum.
- Attachments are metadata-only; no Alembic yet (single table, no migration history).
- Rules consume `SecurityEventResponse` directly (no duplicate schema); `Rule` is a `Protocol`.
- Each rule returns at most one evidence item — makes duplicate evidence structurally impossible.
- Context-aware "request" detection (verb + noun co-occurrence), not keyword presence.
- `SenderAnalyzer`/`URLAnalyzer` wrap their own internal `RuleEngine`; hand-rolled Levenshtein (no external lib).
- Additive-with-cap risk scoring (not probabilistic) — keeps the explainability invariant exactly verifiable.
- `floor()`, not `round()`, for risk_score — always conservative at classification boundaries.
- `ScoringPolicy`/`EscalationPolicy` are frozen, self-validating Pydantic — malformed policies can't be constructed.
- Confidence excludes severity (would entangle risk/confidence) and evidence diversity checks aren't duplicated in `EscalationPolicy` (already in `RiskAssessment.confidence`).
- `DetectionPipeline`/`AnalysisOrchestrator` have no try/except — each stage already isolates its own failures; a failure at composition level is a real bug.
- The agent is invoked only from `AnalysisOrchestrator`; `EscalationPolicy`/`RiskEngine` stay agent-unaware.
- CLEAN vs INCOMPLETE reuses the existing `DetectionCoverage.is_complete` flag rather than a new `DetectionOutcome` model — the distinction was already representable without duplicated state.
- `FakeAgentReasoner` reasons over structured tool data only, never rendered prompt text — makes injection structurally impossible.
- Reassessment is gated on `recommended_reassessment`, not `ESCALATE` alone — avoids a duplicate assessment when nothing new is found.
- `LLMReasoner` is a second `AgentReasoner`, not a replacement — `AgentInvestigationEngine`'s default stays `FakeAgentReasoner()`; `LLMReasoner` is opt-in via `build_reasoner(settings)`.
- `anthropic` is imported lazily inside `AnthropicLLMClient.complete()`, not at module level — the test suite never needs the package installed.
- The LLM's response schema has no risk/classification/action field at all — enforced structurally, not by prompt instruction alone.
- The LLM gets no tool-calling capability — it only ever sees already-executed `ToolResult`s as text, so it cannot invent a new tool by construction.
- `InvestigationStatus.SKIPPED` and `AgentReasoningResult.skipped` are additive, backward-compatible extensions of the Phase 7 contract (default `False`) — not a redesign.

## Known limitations

- SQLite is a test-only Postgres stand-in (no Postgres/Docker in this environment) — no JSONB indexing yet on either dialect.
- `init_db()` is create-only — Alembic needed once Postgres holds real data.
- Detection rules are English keyword/phrase/regex-based only — no stemming, other languages, or semantic matching.
- `ProtectedBrandRegistry` covers only 7 brands — test data, not authoritative.
- No WHOIS/DNS/domain-age/reputation data used anywhere — by design.
- **Scoring and escalation thresholds are initial heuristics, not calibrated against labeled data. The scoring policy and thresholds are initial deterministic heuristics and must be calibrated against a labeled evaluation dataset before production use.**
- The correlation-group mechanism only catches the one case it was built for (not general redundant-evidence detection).
- No expensive intelligence layer exists yet — `DEEP_ANALYSIS`/`EXTERNAL_INTELLIGENCE`/`AGENT_INVESTIGATION`/`NOVEL_SIGNAL` are unused routing abstractions.
- `FakeAgentReasoner` remains the default reasoner; `LLMReasoner` (Anthropic) exists but must be explicitly wired via `build_reasoner(settings)` — no code path enables it automatically.
- The agent's tool set is fixed at 4 read-only tools; `max_tool_calls=4` is an uncalibrated heuristic.
- `LLMReasoner` has not been exercised against a real Anthropic API call in this environment (no network access, no installed SDK) — verified via `FakeLLMClient` only; a live smoke test should be run before relying on this in production.
- `ContentLimits` defaults (200/2000/10/300/15/1500 chars/items) are heuristics, not tuned against real token-cost data.
- No caching layer exists yet — every escalated event that reaches `LLMReasoner` makes a fresh API call, even for a re-investigated/duplicate event.
- None of `DetectionEngine`/`RiskEngine`/`EscalationPolicy`/`AgentInvestigationEngine` are exposed via an API route yet — reachable only through `AnalysisOrchestrator`.
