from app.agent.enums import InvestigationStatus, Uncertainty
from app.agent.engine import AgentInvestigationEngine, FakeAgentReasoner
from app.agent.models import AgentReasoningResult
from app.agent.tool_registry import Tool, ToolRegistry
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.escalation.enums import EscalationReason
from app.risk_scoring.risk_engine import RiskEngine
from tests.agent_fixtures import make_escalation_decision, make_investigation_context
from tests.detection_fixtures import build_event


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_context_produces_identical_investigation_result():
    context = make_investigation_context(
        event=build_event(sender_email="a@bank.com", sender_domain="bank.com", reply_to="r@evil.example"),
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE),
    )
    engine = AgentInvestigationEngine()
    first = engine.investigate(context)
    second = engine.investigate(context)
    assert first.model_dump() == second.model_dump()


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------


def _counting_registry(call_counts: dict) -> ToolRegistry:
    from app.agent.tools import inspect_content, inspect_existing_evidence, inspect_sender, inspect_urls

    real_fns = {
        "inspect_existing_evidence": inspect_existing_evidence,
        "inspect_sender": inspect_sender,
        "inspect_urls": inspect_urls,
        "inspect_content": inspect_content,
    }
    registry = ToolRegistry()
    for name, fn in real_fns.items():
        call_counts[name] = 0

        def make_wrapper(name=name, fn=fn):
            def wrapper(context):
                call_counts[name] += 1
                return fn(context)

            return wrapper

        registry.register(
            Tool(name=name, description="test", input_schema="x", output_schema="y", fn=make_wrapper())
        )
    return registry


def test_budget_limits_tool_calls_and_marks_partial():
    call_counts: dict = {}
    registry = _counting_registry(call_counts)
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(tool_registry=registry, max_tool_calls=1)
    result = engine.investigate(context)

    assert sum(call_counts.values()) == 1
    assert call_counts["inspect_existing_evidence"] == 1
    assert call_counts["inspect_sender"] == 0
    assert call_counts["inspect_urls"] == 0
    assert result.status == InvestigationStatus.PARTIAL


def test_budget_of_zero_runs_no_tools_and_still_returns_a_result():
    call_counts: dict = {}
    registry = _counting_registry(call_counts)
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(tool_registry=registry, max_tool_calls=0)
    result = engine.investigate(context)
    assert sum(call_counts.values()) == 0
    assert result.status == InvestigationStatus.PARTIAL
    assert result.summary


def test_no_budget_truncation_when_candidates_fit():
    call_counts: dict = {}
    registry = _counting_registry(call_counts)
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.NOVEL_SIGNAL)
    )
    engine = AgentInvestigationEngine(tool_registry=registry, max_tool_calls=4)
    result = engine.investigate(context)
    assert sum(call_counts.values()) == 1
    assert result.status == InvestigationStatus.COMPLETED


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_tool_failure_is_recorded_and_investigation_continues():
    def _raising_tool(context):
        raise RuntimeError("boom")

    from app.agent.tools import inspect_existing_evidence

    registry = ToolRegistry()
    registry.register(
        Tool(
            name="inspect_content",
            description="test",
            input_schema="x",
            output_schema="y",
            fn=_raising_tool,
        )
    )
    registry.register(
        Tool(
            name="inspect_existing_evidence",
            description="test",
            input_schema="x",
            output_schema="y",
            fn=inspect_existing_evidence,
        )
    )
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(tool_registry=registry)
    result = engine.investigate(context)

    assert result.status == InvestigationStatus.PARTIAL
    assert any("inspect_content" in f and "failed" in f for f in result.findings)


def test_reasoner_exception_is_caught_and_reported_as_failed():
    class _RaisingReasoner:
        def reason(self, context, tool_results):
            raise RuntimeError("boom")

    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(reasoner=_RaisingReasoner())
    result = engine.investigate(context)

    assert result.status == InvestigationStatus.FAILED
    assert result.findings == []
    assert result.additional_evidence == []
    assert result.uncertainty == Uncertainty.HIGH
    assert result.recommended_reassessment is False


def test_malformed_reasoner_result_is_caught_and_reported_as_failed():
    class _MalformedReasoner:
        def reason(self, context, tool_results):
            return {"summary": "not a real AgentReasoningResult"}

    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(reasoner=_MalformedReasoner())
    result = engine.investigate(context)

    assert result.status == InvestigationStatus.FAILED


def test_all_tools_missing_from_registry_does_not_crash():
    empty_registry = ToolRegistry()
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine(tool_registry=empty_registry)
    result = engine.investigate(context)
    assert result.status == InvestigationStatus.COMPLETED
    assert result.summary


# ---------------------------------------------------------------------------
# Evidence generation and risk reassessment
# ---------------------------------------------------------------------------


def test_agent_produces_real_detection_evidence_instances():
    context = make_investigation_context(
        event=build_event(sender_email="a@bank.com", sender_domain="bank.com", reply_to="r@evil.example"),
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE),
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)

    assert len(result.additional_evidence) == 1
    item = result.additional_evidence[0]
    assert isinstance(item, DetectionEvidence)
    assert item.rule_id == "AGENT_SENDER_REPLY_TO_MISMATCH"
    assert 0.0 <= item.confidence <= 1.0
    assert result.recommended_reassessment is True


def test_no_new_finding_does_not_recommend_reassessment():
    context = make_investigation_context(
        event=build_event(sender_email="a@bank.com", sender_domain="bank.com", reply_to="r@bank.com"),
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE),
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)
    assert result.additional_evidence == []
    assert result.recommended_reassessment is False


def test_combined_evidence_can_be_passed_through_real_risk_engine():
    context = make_investigation_context(
        event=build_event(sender_email="a@bank.com", sender_domain="bank.com", reply_to="r@evil.example"),
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE),
        evidence=[],
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)

    combined = list(context.evidence) + list(result.additional_evidence)
    assessment = RiskEngine().evaluate(combined)
    assert assessment.risk_score >= 0
    assert assessment.confidence >= 0.0
