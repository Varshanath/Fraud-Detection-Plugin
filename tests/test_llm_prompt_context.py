from app.agent.enums import ContextDepth
from app.agent.models import ToolResult
from app.agent.prompts import ContentLimits, build_prompt
from app.escalation.enums import EscalationReason
from tests.agent_fixtures import make_escalation_decision, make_investigation_context
from tests.detection_fixtures import build_event
from tests.risk_fixtures import make_evidence


def test_all_six_required_sections_present():
    context = make_investigation_context()
    prompt = build_prompt(context, [])
    for header in (
        "SYSTEM INSTRUCTIONS:",
        "INVESTIGATION OBJECTIVE:",
        "TRUSTED STRUCTURED CONTEXT",
        "UNTRUSTED EVENT CONTENT",
        "TOOL RESULTS",
        "REQUIRED OUTPUT FORMAT:",
    ):
        assert header in prompt


def test_backward_compatible_two_argument_call():
    # Matches the exact call Phase 7's own test used -- must still work.
    context = make_investigation_context()
    prompt = build_prompt(context, tool_results=[])
    assert "SYSTEM INSTRUCTIONS:" in prompt
    assert "UNTRUSTED EVENT CONTENT" in prompt


def test_targeted_context_is_the_default_depth():
    context = make_investigation_context()
    assert context.context_depth == ContextDepth.TARGETED_CONTEXT


def test_trusted_context_includes_escalation_risk_confidence_classification_coverage():
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.AMBIGUOUS_SIGNAL),
        risk_score=58,
        confidence=0.45,
    )
    prompt = build_prompt(context, [])
    assert "escalation_reason: AMBIGUOUS_SIGNAL" in prompt
    assert "current_risk_score: 58" in prompt
    assert "current_confidence: 0.45" in prompt
    assert "classification: SUSPICIOUS" in prompt
    assert "detector_coverage:" in prompt


def test_existing_evidence_is_included():
    evidence = [make_evidence(rule_id="URGENCY_PRESSURE")]
    context = make_investigation_context(evidence=evidence)
    prompt = build_prompt(context, [])
    assert "URGENCY_PRESSURE" in prompt


def test_subject_and_content_truncated_per_limits():
    limits = ContentLimits(max_subject_chars=10, max_content_chars=20)
    event = build_event(subject="x" * 100, content="y" * 100)
    context = make_investigation_context(event=event)
    prompt = build_prompt(context, [], limits=limits)
    assert "x" * 10 in prompt
    assert "x" * 11 not in prompt
    assert "y" * 20 in prompt
    assert "y" * 21 not in prompt


def test_truncation_is_recorded_in_the_prompt():
    limits = ContentLimits(max_content_chars=5)
    event = build_event(content="this is much longer than five chars")
    context = make_investigation_context(event=event)
    prompt = build_prompt(context, [], limits=limits)
    assert "content_truncated: true" in prompt


def test_no_truncation_recorded_when_content_fits():
    limits = ContentLimits(max_content_chars=1000)
    event = build_event(subject="short", content="also short")
    context = make_investigation_context(event=event)
    prompt = build_prompt(context, [], limits=limits)
    assert "content_truncated: false" in prompt


def test_urls_capped_by_count_and_length():
    limits = ContentLimits(max_urls=2, max_url_chars=10)
    event = build_event(urls=[f"https://example.com/{'a' * 20}/{i}" for i in range(5)])
    context = make_investigation_context(event=event)
    prompt = build_prompt(context, [], limits=limits)
    assert "urls (2 of 5)" in prompt


def test_evidence_capped_with_showing_note():
    limits = ContentLimits(max_evidence_items=2)
    evidence = [make_evidence(rule_id=f"RULE_{i}") for i in range(5)]
    context = make_investigation_context(evidence=evidence)
    prompt = build_prompt(context, [], limits=limits)
    assert "(showing 2 of 5)" in prompt


def test_tool_results_include_actual_data_not_just_status():
    tool_results = [ToolResult(tool_name="inspect_sender", success=True, data={"sender_domain": "bank.com"})]
    context = make_investigation_context()
    prompt = build_prompt(context, tool_results)
    assert "bank.com" in prompt


def test_tool_result_data_truncated_per_limit():
    limits = ContentLimits(max_tool_result_chars=10)
    tool_results = [
        ToolResult(tool_name="inspect_content", success=True, data={"content": "z" * 1000})
    ]
    context = make_investigation_context()
    prompt = build_prompt(context, tool_results, limits=limits)
    assert "[truncated]" in prompt
    assert "z" * 1000 not in prompt


def test_failed_tool_result_shows_failure_not_data():
    tool_results = [ToolResult(tool_name="inspect_urls", success=False, data={}, error="boom")]
    context = make_investigation_context()
    prompt = build_prompt(context, tool_results)
    assert "inspect_urls: failed (boom)" in prompt


def test_required_output_format_lists_real_enum_values():
    context = make_investigation_context()
    prompt = build_prompt(context, [])
    assert "SENDER_SPOOFING" in prompt
    assert "CRITICAL" in prompt
    assert "recommended_reassessment" in prompt


def test_huge_content_still_produces_a_bounded_prompt():
    event = build_event(subject="s" * 100_000, content="c" * 100_000)
    context = make_investigation_context(event=event)
    prompt = build_prompt(context, [])
    # Default limits (200 subject / 2000 content chars) must dominate --
    # the raw 200k-char input must never appear verbatim.
    assert len(prompt) < 10_000
