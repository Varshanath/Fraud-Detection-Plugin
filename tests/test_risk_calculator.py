from app.detection.enums import Severity
from app.risk_scoring.risk_calculator import calculate_risk
from app.risk_scoring.scoring_policy import default_scoring_policy
from tests.risk_fixtures import make_evidence

policy = default_scoring_policy()


def test_no_evidence_gives_zero_score():
    score, raw, breakdown = calculate_risk([], policy)
    assert score == 0
    assert raw == 0.0
    assert breakdown == []


def test_one_low_evidence():
    evidence = [make_evidence(rule_id="A", severity=Severity.LOW, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == policy.severity_weights.low
    assert breakdown[0].counted is True


def test_one_medium_evidence():
    evidence = [make_evidence(rule_id="A", severity=Severity.MEDIUM, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == policy.severity_weights.medium


def test_one_high_evidence():
    evidence = [make_evidence(rule_id="A", severity=Severity.HIGH, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == policy.severity_weights.high


def test_one_critical_evidence():
    evidence = [make_evidence(rule_id="A", severity=Severity.CRITICAL, confidence=1.0)]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == policy.severity_weights.critical


def test_multiple_independent_evidence_is_additive():
    evidence = [
        make_evidence(rule_id="A", severity=Severity.LOW, confidence=1.0),
        make_evidence(rule_id="B", severity=Severity.MEDIUM, confidence=1.0),
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == policy.severity_weights.low + policy.severity_weights.medium


def test_low_confidence_evidence_contributes_less():
    low_conf = calculate_risk(
        [make_evidence(rule_id="A", severity=Severity.HIGH, confidence=0.1)], policy
    )[0]
    high_conf = calculate_risk(
        [make_evidence(rule_id="A", severity=Severity.HIGH, confidence=0.9)], policy
    )[0]
    assert low_conf < high_conf


def test_score_never_exceeds_100():
    evidence = [
        make_evidence(rule_id=f"RULE_{i}", severity=Severity.CRITICAL, confidence=1.0)
        for i in range(10)
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert score == 100
    assert raw > 100  # raw is unclamped, proving the cap actually did work


def test_score_never_below_zero():
    score, raw, breakdown = calculate_risk([], policy)
    assert score >= 0


def test_maximum_score_is_bounded_int():
    evidence = [
        make_evidence(rule_id=f"RULE_{i}", severity=Severity.CRITICAL, confidence=1.0)
        for i in range(20)
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    assert isinstance(score, int)
    assert score == 100


def test_breakdown_sums_to_raw_score_before_cap():
    evidence = [
        make_evidence(rule_id="A", severity=Severity.HIGH, confidence=0.8),
        make_evidence(rule_id="B", severity=Severity.MEDIUM, confidence=0.6),
    ]
    score, raw, breakdown = calculate_risk(evidence, policy)
    counted_sum = sum(entry.contribution for entry in breakdown if entry.counted)
    assert counted_sum == raw
