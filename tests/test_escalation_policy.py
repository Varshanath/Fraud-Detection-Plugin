from app.escalation.enums import EscalationPriority, EscalationReason, EscalationState, NextStage
from app.escalation.escalation_policy import default_escalation_policy
from app.risk_scoring.enums import RiskClassification
from tests.escalation_fixtures import (
    complete_coverage,
    coverage_with_failures,
    make_risk_assessment,
)
from tests.risk_fixtures import make_evidence

policy = default_escalation_policy()
some_evidence = [make_evidence(rule_id="A"), make_evidence(rule_id="B")]
full_coverage = complete_coverage()


# ---------------------------------------------------------------------------
# The 5 required cases
# ---------------------------------------------------------------------------


def test_case1_low_risk_high_confidence_no_escalation():
    assessment = make_risk_assessment(risk_score=15, confidence=0.95)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.NO_ESCALATION
    assert decision.requires_escalation is False
    assert decision.reason is None
    assert decision.priority is None
    assert decision.recommended_next_stage == NextStage.NONE


def test_case2_high_risk_high_confidence_no_escalation():
    assessment = make_risk_assessment(risk_score=88, confidence=0.95)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.NO_ESCALATION
    assert decision.requires_escalation is False
    assert decision.recommended_next_stage == NextStage.NONE


def test_case3_medium_risk_low_confidence_escalates_as_ambiguous():
    assessment = make_risk_assessment(risk_score=58, confidence=0.45)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.AMBIGUOUS_SIGNAL
    assert decision.priority == EscalationPriority.MEDIUM
    assert decision.recommended_next_stage == NextStage.DEEP_ANALYSIS


def test_case4_high_risk_low_confidence_escalates_high_priority():
    assessment = make_risk_assessment(risk_score=82, confidence=0.52)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.HIGH_RISK_LOW_CONFIDENCE
    assert decision.priority == EscalationPriority.HIGH


def test_case5_low_risk_low_confidence_does_not_assume_safe():
    assessment = make_risk_assessment(risk_score=25, confidence=0.35)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.LOW_CONFIDENCE
    assert decision.priority == EscalationPriority.LOW


def test_case5_variant_with_sparse_evidence_flags_insufficient_evidence():
    assessment = make_risk_assessment(risk_score=25, confidence=0.35)
    decision = policy.evaluate(assessment, [], full_coverage)
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.INSUFFICIENT_EVIDENCE
    assert EscalationReason.LOW_CONFIDENCE in decision.contributing_reasons


# ---------------------------------------------------------------------------
# Escalation is not driven by risk or confidence alone
# ---------------------------------------------------------------------------


def test_no_escalation_is_not_simply_risk_above_threshold():
    high_risk_high_confidence = make_risk_assessment(
        risk_score=95, confidence=0.98, classification=RiskClassification.CRITICAL
    )
    decision = policy.evaluate(high_risk_high_confidence, some_evidence, full_coverage)
    assert decision.state == EscalationState.NO_ESCALATION


def test_escalation_is_not_simply_confidence_below_threshold():
    # Confidence is high, but incomplete detector coverage still escalates --
    # proves the decision is not solely a function of confidence.
    assessment = make_risk_assessment(risk_score=15, confidence=0.95)
    decision = policy.evaluate(
        assessment, some_evidence, coverage_with_failures(["URLAnalyzer"], ["RuleEngine"])
    )
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE


def test_low_risk_low_confidence_can_escalate_high_risk_high_confidence_cannot():
    low = policy.evaluate(
        make_risk_assessment(risk_score=25, confidence=0.35), some_evidence, full_coverage
    )
    high = policy.evaluate(
        make_risk_assessment(risk_score=88, confidence=0.95), some_evidence, full_coverage
    )
    assert low.state == EscalationState.ESCALATE
    assert high.state == EscalationState.NO_ESCALATION


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def test_detector_failure_escalates_even_with_high_confidence_and_low_risk():
    assessment = make_risk_assessment(risk_score=10, confidence=0.99)
    decision = policy.evaluate(
        assessment, some_evidence, coverage_with_failures(["SenderAnalyzer"], ["RuleEngine"])
    )
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE


def test_multiple_detector_failures_still_reported_as_coverage_reason():
    assessment = make_risk_assessment(risk_score=10, confidence=0.99)
    decision = policy.evaluate(
        assessment, some_evidence, coverage_with_failures(["SenderAnalyzer", "URLAnalyzer"])
    )
    assert decision.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE


def test_full_coverage_with_high_confidence_low_risk_does_not_escalate():
    assessment = make_risk_assessment(risk_score=10, confidence=0.99)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.state == EscalationState.NO_ESCALATION


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_no_evidence_flags_insufficient_evidence():
    assessment = make_risk_assessment(risk_score=0, confidence=0.0)
    decision = policy.evaluate(assessment, [], full_coverage)
    assert decision.state == EscalationState.ESCALATE
    assert decision.reason == EscalationReason.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# Explanations and structured output
# ---------------------------------------------------------------------------


def test_escalation_decision_carries_current_risk_and_confidence():
    assessment = make_risk_assessment(risk_score=58, confidence=0.45)
    decision = policy.evaluate(assessment, some_evidence, full_coverage)
    assert decision.current_risk_score == 58
    assert decision.current_confidence == 0.45


def test_explanation_is_non_empty_for_every_case():
    for risk_score, confidence in ((15, 0.95), (88, 0.95), (58, 0.45), (82, 0.52), (25, 0.35)):
        assessment = make_risk_assessment(risk_score=risk_score, confidence=confidence)
        decision = policy.evaluate(assessment, some_evidence, full_coverage)
        assert decision.explanation


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_same_inputs_produce_identical_decision():
    assessment = make_risk_assessment(risk_score=58, confidence=0.45)
    first = policy.evaluate(assessment, some_evidence, full_coverage)
    second = policy.evaluate(assessment, some_evidence, full_coverage)
    assert first == second
