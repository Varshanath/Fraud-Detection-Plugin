from app.detection.enums import Severity
from app.risk_scoring.confidence_calculator import calculate_confidence
from app.risk_scoring.risk_calculator import calculate_risk
from app.risk_scoring.scoring_policy import default_scoring_policy
from tests.risk_fixtures import make_evidence

policy = default_scoring_policy()


def test_no_evidence_gives_zero_confidence():
    assert calculate_confidence([], policy) == 0.0


def test_weak_evidence_produces_lower_confidence_than_strong_evidence():
    weak_breakdown = calculate_risk(
        [make_evidence(rule_id="A", severity=Severity.LOW, confidence=0.1)], policy
    )[2]
    strong_breakdown = calculate_risk(
        [make_evidence(rule_id="A", severity=Severity.LOW, confidence=0.95)], policy
    )[2]
    weak_confidence = calculate_confidence(weak_breakdown, policy)
    strong_confidence = calculate_confidence(strong_breakdown, policy)
    assert weak_confidence < strong_confidence


def test_multiple_independent_high_quality_signals_increase_confidence():
    single_breakdown = calculate_risk(
        [make_evidence(rule_id="A", severity=Severity.LOW, confidence=0.9)], policy
    )[2]
    multiple_breakdown = calculate_risk(
        [
            make_evidence(rule_id=f"RULE_{i}", severity=Severity.LOW, confidence=0.9)
            for i in range(4)
        ],
        policy,
    )[2]
    single_confidence = calculate_confidence(single_breakdown, policy)
    multiple_confidence = calculate_confidence(multiple_breakdown, policy)
    assert multiple_confidence > single_confidence


def test_confidence_is_bounded_between_zero_and_one():
    breakdown = calculate_risk(
        [
            make_evidence(rule_id=f"RULE_{i}", severity=Severity.CRITICAL, confidence=1.0)
            for i in range(10)
        ],
        policy,
    )[2]
    confidence = calculate_confidence(breakdown, policy)
    assert 0.0 <= confidence <= 1.0


def test_confidence_is_not_risk_score_divided_by_100_case_a():
    # One CRITICAL, confidence 1.0 -> risk=85, confidence should NOT be 0.85.
    evidence = [make_evidence(rule_id="A", severity=Severity.CRITICAL, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    confidence = calculate_confidence(breakdown, policy)
    assert score == 85
    assert confidence != round(score / 100, 4)
    assert confidence == 0.7


def test_confidence_is_not_risk_score_divided_by_100_case_b():
    # Four independent LOW-severity, high-confidence items -> risk=38 (low),
    # confidence=0.97 (very high) -- the two move in opposite directions.
    evidence = [
        make_evidence(rule_id=f"RULE_{i}", severity=Severity.LOW, confidence=0.95)
        for i in range(4)
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    confidence = calculate_confidence(breakdown, policy)
    assert score == 38
    assert confidence == 0.97
    assert confidence != round(score / 100, 4)


def test_high_risk_low_corroboration_gives_only_moderate_confidence():
    evidence = [make_evidence(rule_id="A", severity=Severity.CRITICAL, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    confidence = calculate_confidence(breakdown, policy)
    assert score >= 70  # HIGH_RISK or above
    assert confidence < 0.8  # only one uncorroborated source


def test_suppressed_correlated_evidence_does_not_inflate_confidence():
    correlated_breakdown = calculate_risk(
        [
            make_evidence(rule_id="LOOKALIKE_DOMAIN", severity=Severity.HIGH, confidence=0.9),
            make_evidence(rule_id="LOOKALIKE_URL_DOMAIN", severity=Severity.HIGH, confidence=0.95),
        ],
        policy,
    )[2]
    single_breakdown = calculate_risk(
        [make_evidence(rule_id="LOOKALIKE_URL_DOMAIN", severity=Severity.HIGH, confidence=0.95)],
        policy,
    )[2]
    assert calculate_confidence(correlated_breakdown, policy) == calculate_confidence(
        single_breakdown, policy
    )
