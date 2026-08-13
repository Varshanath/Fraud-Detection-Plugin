from app.agent.investigation import determine_investigation_objective, select_tools_for
from app.escalation.enums import EscalationReason
from tests.agent_fixtures import make_escalation_decision
from tests.escalation_fixtures import coverage_with_failures, complete_coverage


def test_high_risk_low_confidence_selects_evidence_sender_url():
    decision = make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    tools = select_tools_for(decision, complete_coverage())
    assert tools == ["inspect_existing_evidence", "inspect_sender", "inspect_urls"]


def test_ambiguous_signal_selects_evidence_sender_url():
    decision = make_escalation_decision(reason=EscalationReason.AMBIGUOUS_SIGNAL)
    tools = select_tools_for(decision, complete_coverage())
    assert tools == ["inspect_existing_evidence", "inspect_sender", "inspect_urls"]


def test_low_confidence_selects_evidence_and_content():
    decision = make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    tools = select_tools_for(decision, complete_coverage())
    assert tools == ["inspect_existing_evidence", "inspect_content"]


def test_insufficient_evidence_selects_sender_url_content():
    decision = make_escalation_decision(reason=EscalationReason.INSUFFICIENT_EVIDENCE)
    tools = select_tools_for(decision, complete_coverage())
    assert tools == ["inspect_sender", "inspect_urls", "inspect_content"]


def test_novel_signal_selects_existing_evidence_only():
    decision = make_escalation_decision(reason=EscalationReason.NOVEL_SIGNAL)
    tools = select_tools_for(decision, complete_coverage())
    assert tools == ["inspect_existing_evidence"]


def test_insufficient_detector_coverage_focuses_on_failed_detectors_only():
    decision = make_escalation_decision(reason=EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE)
    coverage = coverage_with_failures(["URLAnalyzer"], ["RuleEngine", "SenderAnalyzer"])
    tools = select_tools_for(decision, coverage)
    assert "inspect_urls" in tools
    assert "inspect_sender" not in tools
    assert "inspect_content" not in tools
    assert "inspect_existing_evidence" in tools


def test_insufficient_detector_coverage_multiple_failed_detectors():
    decision = make_escalation_decision(reason=EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE)
    coverage = coverage_with_failures(["URLAnalyzer", "SenderAnalyzer"])
    tools = select_tools_for(decision, coverage)
    assert "inspect_urls" in tools
    assert "inspect_sender" in tools
    assert "inspect_content" not in tools


def test_sender_related_investigation_uses_sender_tool():
    decision = make_escalation_decision(reason=EscalationReason.AMBIGUOUS_SIGNAL)
    tools = select_tools_for(decision, complete_coverage())
    assert "inspect_sender" in tools


def test_url_related_investigation_uses_url_tool():
    decision = make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    tools = select_tools_for(decision, complete_coverage())
    assert "inspect_urls" in tools


def test_content_investigation_uses_content_tool():
    decision = make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    tools = select_tools_for(decision, complete_coverage())
    assert "inspect_content" in tools


def test_existing_evidence_can_be_inspected():
    # INSUFFICIENT_EVIDENCE deliberately skips re-inspecting evidence (there
    # is too little of it to be worth reviewing) -- every other reason
    # includes it.
    for reason in EscalationReason:
        if reason == EscalationReason.INSUFFICIENT_EVIDENCE:
            continue
        decision = make_escalation_decision(reason=reason)
        tools = select_tools_for(decision, complete_coverage())
        assert "inspect_existing_evidence" in tools, reason


def test_objective_is_non_empty_for_every_reason():
    for reason in EscalationReason:
        decision = make_escalation_decision(reason=reason)
        assert determine_investigation_objective(decision)
