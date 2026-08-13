from app.agent.enums import InvestigationStatus, Uncertainty
from app.agent.models import InvestigationResult
from app.escalation.escalation_policy import EscalationPolicy
from app.orchestrator import AnalysisOrchestrator
from tests.detection_fixtures import build_event, phishing_credential_request

_ALWAYS_ESCALATE_POLICY = EscalationPolicy(
    confidence_threshold=1.0,
    high_risk_score_threshold=70,
    medium_priority_score_threshold=40,
    min_evidence_count=1,
)

# confidence_threshold=0.0 means "low confidence" can never be true (confidence
# is always >= 0.0), and min_evidence_count=0 means an evidence-free event
# never triggers INSUFFICIENT_EVIDENCE either -- this isolates the
# invocation-gating tests below from EscalationPolicy's own threshold logic
# (already covered by tests/test_escalation_policy.py).
_NEVER_ESCALATE_POLICY = EscalationPolicy(
    confidence_threshold=0.0,
    high_risk_score_threshold=100,
    medium_priority_score_threshold=100,
    min_evidence_count=0,
)


class _SpyAgentEngine:
    def __init__(self, result: InvestigationResult):
        self._result = result
        self.call_count = 0
        self.received_context = None

    def investigate(self, context):
        self.call_count += 1
        self.received_context = context
        return self._result


def _canned_result(additional_evidence=None, recommended_reassessment=False) -> InvestigationResult:
    return InvestigationResult(
        status=InvestigationStatus.COMPLETED,
        summary="stub investigation",
        findings=["stub finding"],
        additional_evidence=additional_evidence or [],
        uncertainty=Uncertainty.LOW,
        recommended_reassessment=recommended_reassessment,
    )


def test_no_escalation_never_invokes_the_agent():
    spy = _SpyAgentEngine(_canned_result())
    orchestrator = AnalysisOrchestrator(escalation_policy=_NEVER_ESCALATE_POLICY, agent_engine=spy)
    result = orchestrator.evaluate(build_event(content="Hello, meeting moved to 3pm."))

    assert spy.call_count == 0
    assert result.escalation.state.value == "NO_ESCALATION"
    assert result.investigation is None
    assert result.final_risk_assessment is None


def test_escalation_invokes_the_agent_exactly_once():
    spy = _SpyAgentEngine(_canned_result())
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY, agent_engine=spy)
    result = orchestrator.evaluate(phishing_credential_request())

    assert spy.call_count == 1
    assert result.escalation.state.value == "ESCALATE"
    assert result.investigation is not None
    assert result.investigation.summary == "stub investigation"


def test_agent_receives_the_correct_investigation_context():
    spy = _SpyAgentEngine(_canned_result())
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY, agent_engine=spy)
    event = phishing_credential_request()
    result = orchestrator.evaluate(event)

    assert spy.received_context.event.event_id == event.event_id
    assert spy.received_context.escalation_decision == result.escalation
    assert spy.received_context.risk_assessment == result.risk_assessment


def test_no_reassessment_when_agent_finds_nothing_new():
    spy = _SpyAgentEngine(_canned_result(recommended_reassessment=False))
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY, agent_engine=spy)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.investigation is not None
    assert result.final_risk_assessment is None


def test_reassessment_happens_when_agent_recommends_it():
    from tests.risk_fixtures import make_evidence

    new_evidence = [make_evidence(rule_id="AGENT_TEST_EVIDENCE")]
    spy = _SpyAgentEngine(_canned_result(additional_evidence=new_evidence, recommended_reassessment=True))
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY, agent_engine=spy)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.final_risk_assessment is not None
    assert result.final_risk_assessment.risk_score >= result.risk_assessment.risk_score


def test_real_end_to_end_investigation_and_reassessment():
    event = build_event(
        sender_email="a@bank.com",
        sender_domain="bank.com",
        reply_to="r@evil.example",
        subject="Urgent: verify your account",
        content="Act immediately. Please enter your password now.",
    )
    orchestrator = AnalysisOrchestrator(escalation_policy=_ALWAYS_ESCALATE_POLICY)
    result = orchestrator.evaluate(event)

    assert result.escalation.state.value == "ESCALATE"
    assert result.investigation is not None
    # Initial and final assessments remain independently inspectable.
    assert result.risk_assessment is not None
    if result.investigation.recommended_reassessment:
        assert result.final_risk_assessment is not None
        assert len(result.final_risk_assessment.scoring_breakdown) >= len(
            result.risk_assessment.scoring_breakdown
        )


def test_default_construction_needs_no_arguments():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(build_event(content="Hello there"))
    assert result.risk_assessment.risk_score == 0
    # Zero evidence trips the default policy's own min_evidence_count check
    # (see tests/test_escalation_policy.py) -- this test only proves
    # AnalysisOrchestrator() with no constructor arguments does not crash and
    # produces a coherent result either way.
    assert (result.investigation is None) == (result.escalation.state.value == "NO_ESCALATION")
