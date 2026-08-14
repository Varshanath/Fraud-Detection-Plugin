from pydantic import SecretStr

from app.agent.enums import InvestigationStatus
from app.agent.engine import AgentInvestigationEngine
from app.agent.llm_reasoner import AnthropicLLMClient, LLMReasoner, build_reasoner
from app.config import Settings
from app.escalation.escalation_policy import EscalationPolicy
from app.orchestrator import AnalysisOrchestrator
from app.risk_scoring.risk_engine import RiskEngine
from tests.detection_fixtures import build_event, phishing_credential_request
from tests.llm_fixtures import FakeLLMClient, valid_llm_response_json

_ALWAYS_ESCALATE_POLICY = EscalationPolicy(
    confidence_threshold=1.0,
    high_risk_score_threshold=70,
    medium_priority_score_threshold=40,
    min_evidence_count=1,
)
_NEVER_ESCALATE_POLICY = EscalationPolicy(
    confidence_threshold=0.0,
    high_risk_score_threshold=100,
    medium_priority_score_threshold=100,
    min_evidence_count=0,
)


def _orchestrator_with_llm(client: FakeLLMClient, escalation_policy: EscalationPolicy) -> AnalysisOrchestrator:
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    agent_engine = AgentInvestigationEngine(reasoner=reasoner)
    return AnalysisOrchestrator(escalation_policy=escalation_policy, agent_engine=agent_engine)


def test_no_escalation_never_calls_the_llm():
    client = FakeLLMClient(response_text=valid_llm_response_json())
    orchestrator = _orchestrator_with_llm(client, _NEVER_ESCALATE_POLICY)
    result = orchestrator.evaluate(build_event(content="Hello, meeting moved to 3pm."))

    assert len(client.calls) == 0
    assert result.investigation is None


def test_escalation_calls_the_llm_exactly_once():
    client = FakeLLMClient(response_text=valid_llm_response_json())
    orchestrator = _orchestrator_with_llm(client, _ALWAYS_ESCALATE_POLICY)
    result = orchestrator.evaluate(phishing_credential_request())

    assert len(client.calls) == 1
    assert result.investigation is not None
    assert result.investigation.status == InvestigationStatus.COMPLETED


def test_reassessment_flows_through_the_real_risk_engine():
    client = FakeLLMClient(response_text=valid_llm_response_json(recommended_reassessment=True))
    orchestrator = _orchestrator_with_llm(client, _ALWAYS_ESCALATE_POLICY)
    event = phishing_credential_request()
    result = orchestrator.evaluate(event)

    assert result.final_risk_assessment is not None
    combined_evidence = list(result.evidence) + list(result.investigation.additional_evidence)
    independent = RiskEngine().evaluate(combined_evidence)
    assert result.final_risk_assessment == independent
    # The initial assessment stays available and distinguishable.
    assert result.risk_assessment is not None
    assert result.risk_assessment != result.final_risk_assessment or not result.investigation.additional_evidence


def test_llm_disabled_mode_leaves_orchestrator_functional():
    settings = Settings(llm_enabled=False)
    reasoner = build_reasoner(settings)
    agent_engine = AgentInvestigationEngine(reasoner=reasoner)
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY, agent_engine=agent_engine)

    result = orchestrator.evaluate(phishing_credential_request())

    assert result.investigation is not None
    assert result.investigation.status == InvestigationStatus.SKIPPED
    assert result.final_risk_assessment is None
    assert result.risk_assessment is not None
    assert result.risk_assessment.risk_score > 0


def test_llm_client_timeout_preserves_initial_assessment_and_marks_investigation_failed():
    client = FakeLLMClient(exception=TimeoutError("simulated timeout"))
    orchestrator = _orchestrator_with_llm(client, _ALWAYS_ESCALATE_POLICY)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.risk_assessment is not None
    assert result.risk_assessment.risk_score > 0
    assert result.investigation.status == InvestigationStatus.FAILED
    assert result.final_risk_assessment is None


def test_llm_malformed_response_preserves_initial_assessment_and_marks_investigation_failed():
    client = FakeLLMClient(response_text="{not valid json")
    orchestrator = _orchestrator_with_llm(client, _ALWAYS_ESCALATE_POLICY)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.risk_assessment is not None
    assert result.investigation.status == InvestigationStatus.FAILED
    assert result.final_risk_assessment is None


def test_llm_empty_response_does_not_crash_orchestrator():
    client = FakeLLMClient(response_text="")
    orchestrator = _orchestrator_with_llm(client, _ALWAYS_ESCALATE_POLICY)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result is not None
    assert result.investigation.status == InvestigationStatus.FAILED


def test_build_reasoner_wiring_with_real_api_key_produces_llm_reasoner_without_calling_it():
    settings = Settings(llm_enabled=True, llm_api_key=SecretStr("fake-key-for-wiring-test"))
    reasoner = build_reasoner(settings)
    assert isinstance(reasoner, LLMReasoner)
    assert isinstance(reasoner.client, AnthropicLLMClient)
    # Never call reasoner.reason() here -- that would require the anthropic
    # package installed and real network access, which the test suite must
    # never depend on.


def test_default_agent_investigation_engine_still_uses_fake_reasoner():
    # Phase 7's default wiring must be completely unaffected by Phase 8.
    from app.agent.engine import FakeAgentReasoner

    engine = AgentInvestigationEngine()
    assert isinstance(engine.reasoner, FakeAgentReasoner)
