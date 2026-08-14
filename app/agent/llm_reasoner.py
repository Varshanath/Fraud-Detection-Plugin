"""Real LLM-backed AgentReasoner (Phase 8). Implements the exact same
`AgentReasoner` Protocol as `FakeAgentReasoner` (app.agent.engine) -- the
engine that calls it has no idea which implementation it's talking to.

The LLM is an investigator, not the final security authority: it never
computes risk, never calls RiskEngine, never selects a final action, never
touches escalation policy or application configuration, never accesses a
database or filesystem, and makes no network call other than the single
`client.complete()` request per investigation. Final risk and action are
always determined by the deterministic RiskEngine.
"""

import json
import logging
import time
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.agent.enums import InvestigationStatus, Uncertainty
from app.agent.models import AgentReasoningResult, InvestigationContext, ToolResult
from app.agent.prompts import DEFAULT_CONTENT_LIMITS, ContentLimits, build_prompt
from app.config import Settings
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence

logger = logging.getLogger(__name__)

_MAX_RESPONSE_CHARS = 20_000
_MAX_FINDINGS = 8

_CONTENT_LIKE_CATEGORIES = {
    EvidenceCategory.SOCIAL_ENGINEERING,
    EvidenceCategory.CREDENTIAL_THEFT,
    EvidenceCategory.FINANCIAL_FRAUD,
    EvidenceCategory.SENSITIVE_INFORMATION_REQUEST,
    EvidenceCategory.SUSPICIOUS_ATTACHMENT,
}
_RULE_ID_FOR_CATEGORY = {
    EvidenceCategory.SENDER_SPOOFING: "AGENT_LLM_SENDER_ANALYSIS",
    EvidenceCategory.SUSPICIOUS_URL: "AGENT_LLM_URL_ANALYSIS",
}


def _rule_id_for(category: EvidenceCategory) -> str:
    if category in _RULE_ID_FOR_CATEGORY:
        return _RULE_ID_FOR_CATEGORY[category]
    if category in _CONTENT_LIKE_CATEGORIES:
        return "AGENT_LLM_CONTENT_ANALYSIS"
    return "AGENT_LLM_INVESTIGATION"


class LLMResponseError(Exception):
    """Raised whenever the LLM's raw output fails validation (not valid
    JSON, wrong schema, out-of-bounds values, too large). Deliberately not
    caught here -- AgentInvestigationEngine.investigate() already wraps the
    whole `reasoner.reason()` call and turns any exception into
    InvestigationResult(status=FAILED, ...), so malformed output can never
    crash the application.
    """


class LLMFinding(BaseModel):
    """One structured finding from the LLM's raw JSON output. Strictly
    validated: enum-constrained category/severity, confidence bounded to
    0.0-1.0, and length caps on every string so a single finding can't blow
    up the response.
    """

    model_config = ConfigDict(frozen=True)

    finding_type: EvidenceCategory
    description: str = Field(min_length=1, max_length=500)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_observations: list[str] = Field(default_factory=list, max_length=10)


class LLMInvestigationResponse(BaseModel):
    """Strict schema the LLM's raw JSON output must validate against.

    `status` is parsed for schema completeness only -- InvestigationResult.status
    remains engine-computed (see AgentInvestigationEngine.investigate()),
    never LLM-controlled. There is deliberately no risk_score/classification/
    recommended_action field anywhere in this schema: the LLM is structurally
    incapable of setting them, not merely instructed not to.
    """

    model_config = ConfigDict(frozen=True)

    status: InvestigationStatus
    summary: str = Field(min_length=1, max_length=1000)
    findings: list[LLMFinding] = Field(default_factory=list, max_length=_MAX_FINDINGS)
    uncertainty: Uncertainty
    recommended_reassessment: bool


def _parse_and_validate(raw: str) -> LLMInvestigationResponse:
    if not raw or not raw.strip():
        raise LLMResponseError("empty LLM response")
    if len(raw) > _MAX_RESPONSE_CHARS:
        raise LLMResponseError("LLM response exceeds maximum allowed size")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMResponseError("LLM response is not valid JSON") from exc
    try:
        return LLMInvestigationResponse.model_validate(payload)
    except ValidationError as exc:
        raise LLMResponseError(f"LLM response failed schema validation: {exc}") from exc


def _to_reasoning_result(response: LLMInvestigationResponse) -> AgentReasoningResult:
    findings_text = [
        f"[{f.finding_type.value}/{f.severity.value}] {f.description}" for f in response.findings
    ]
    additional_evidence = [
        DetectionEvidence(
            rule_id=_rule_id_for(f.finding_type),
            category=f.finding_type,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            details={
                "supporting_observations": f.supporting_observations,
                "source": "llm_investigation",
            },
        )
        for f in response.findings
    ]
    return AgentReasoningResult(
        summary=response.summary,
        findings=findings_text,
        additional_evidence=additional_evidence,
        uncertainty=response.uncertainty,
        recommended_reassessment=response.recommended_reassessment,
    )


class LLMClient(Protocol):
    """The only network boundary Phase 8 introduces. Exactly one production
    implementation (AnthropicLLMClient); tests always inject a fake.
    """

    def complete(self, prompt: str, *, model: str, max_output_tokens: int, timeout: float) -> str: ...


class AnthropicLLMClient:
    """Thin wrapper around the Anthropic Messages API. `anthropic` is
    imported lazily inside `complete()` -- not at module level -- so
    importing this module (and therefore running the test suite) never
    requires the package installed. Only an actual LLM call does.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def complete(self, prompt: str, *, model: str, max_output_tokens: int, timeout: float) -> str:
        import anthropic  # lazy: only the real network call needs this installed

        client = anthropic.Anthropic(api_key=self._api_key, timeout=timeout)
        response = client.messages.create(
            model=model,
            max_tokens=max_output_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )


class DisabledLLMReasoner:
    """Used when LLM_ENABLED is false, or true with no API key configured.
    Makes no LLM call and does no tool-result reasoning -- returns a
    clearly-flagged skipped result so callers can tell "the LLM investigated
    and found nothing" apart from "the LLM never ran".
    """

    def reason(
        self, context: InvestigationContext, tool_results: list[ToolResult]
    ) -> AgentReasoningResult:
        return AgentReasoningResult(
            summary="LLM investigation skipped: LLM_DISABLED",
            findings=[],
            additional_evidence=[],
            uncertainty=Uncertainty.HIGH,
            recommended_reassessment=False,
            skipped=True,
        )


class LLMReasoner:
    """Real LLM-backed AgentReasoner. Builds a targeted, size-bounded prompt
    (app.agent.prompts.build_prompt), calls the configured LLMClient exactly
    once, strictly validates the structured JSON response, and maps it into
    the existing AgentReasoningResult contract. Raises on any failure --
    never catches its own errors, so AgentInvestigationEngine's existing
    failure handling (Phase 7) is the single place investigation failures
    are turned into a safe result.
    """

    def __init__(
        self,
        client: LLMClient,
        model: str,
        max_output_tokens: int = 1024,
        timeout: float = 20.0,
        content_limits: ContentLimits | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.timeout = timeout
        self.content_limits = content_limits or DEFAULT_CONTENT_LIMITS

    def reason(
        self, context: InvestigationContext, tool_results: list[ToolResult]
    ) -> AgentReasoningResult:
        event_id = context.event.event_id
        logger.info(
            "llm investigation invocation started event_id=%s model=%s context_depth=%s "
            "escalation_reason=%s",
            event_id,
            self.model,
            context.context_depth,
            context.escalation_decision.reason,
        )

        prompt = build_prompt(context, tool_results, limits=self.content_limits)
        started = time.monotonic()
        try:
            raw = self.client.complete(
                prompt,
                model=self.model,
                max_output_tokens=self.max_output_tokens,
                timeout=self.timeout,
            )
        except Exception:
            logger.exception(
                "llm client call failed event_id=%s duration=%.3f",
                event_id,
                time.monotonic() - started,
            )
            raise

        try:
            response = _parse_and_validate(raw)
        except LLMResponseError:
            logger.exception("llm response validation failed event_id=%s", event_id)
            raise

        duration = time.monotonic() - started
        logger.info(
            "llm investigation invocation completed event_id=%s duration=%.3f findings=%d",
            event_id,
            duration,
            len(response.findings),
        )
        return _to_reasoning_result(response)


def build_reasoner(settings: Settings):
    """Chooses the AgentReasoner implementation from application settings.
    This is the only place LLM enablement is decided -- AgentInvestigationEngine
    stays reasoner-agnostic, and its own default (FakeAgentReasoner) is
    unaffected by this function existing; it's opt-in wiring, not a new
    default path.
    """
    if not settings.llm_enabled:
        return DisabledLLMReasoner()
    if settings.llm_api_key is None or not settings.llm_api_key.get_secret_value():
        logger.warning("LLM_ENABLED is true but LLM_API_KEY is not set; using DisabledLLMReasoner")
        return DisabledLLMReasoner()
    client = AnthropicLLMClient(api_key=settings.llm_api_key.get_secret_value())
    return LLMReasoner(
        client=client,
        model=settings.llm_model,
        max_output_tokens=settings.llm_max_output_tokens,
        timeout=settings.llm_timeout,
    )
