import math

from app.detection.enums import EvidenceCategory, Severity
from app.risk_scoring.enums import RecommendedAction, RiskClassification
from app.risk_scoring.risk_engine import RiskEngine
from tests.risk_fixtures import make_evidence

engine = RiskEngine()


def test_evaluate_with_no_evidence_is_safe():
    assessment = engine.evaluate([])
    assert assessment.risk_score == 0
    assert assessment.confidence == 0.0
    assert assessment.classification == RiskClassification.SAFE
    assert assessment.recommended_action == RecommendedAction.ALLOW
    assert assessment.scoring_breakdown == []


def test_explainability_invariant_holds():
    evidence = [
        make_evidence(rule_id="A", severity=Severity.HIGH, confidence=0.8),
        make_evidence(rule_id="B", severity=Severity.MEDIUM, confidence=0.6),
        make_evidence(rule_id="LOOKALIKE_DOMAIN", severity=Severity.HIGH, confidence=0.9),
        make_evidence(rule_id="LOOKALIKE_URL_DOMAIN", severity=Severity.HIGH, confidence=0.95),
    ]
    assessment = engine.evaluate(evidence)

    counted_sum = sum(e.contribution for e in assessment.scoring_breakdown if e.counted)
    assert counted_sum == assessment.raw_score_before_cap
    assert assessment.risk_score == math.floor(min(100.0, assessment.raw_score_before_cap))


def test_worked_example_from_readme():
    evidence = [
        make_evidence(
            rule_id="URGENCY_PRESSURE",
            category=EvidenceCategory.SOCIAL_ENGINEERING,
            severity=Severity.HIGH,
            confidence=0.5,
        ),
        make_evidence(
            rule_id="CREDENTIAL_REQUEST",
            category=EvidenceCategory.CREDENTIAL_THEFT,
            severity=Severity.HIGH,
            confidence=0.65,
        ),
    ]
    assessment = engine.evaluate(evidence)
    assert assessment.risk_score == math.floor(55 * 0.5 + 55 * 0.65)
    assert assessment.classification in (RiskClassification.SUSPICIOUS, RiskClassification.HIGH_RISK)


def test_every_breakdown_entry_traceable_to_a_rule_id():
    evidence = [make_evidence(rule_id="X", severity=Severity.LOW, confidence=0.5)]
    assessment = engine.evaluate(evidence)
    assert assessment.scoring_breakdown[0].rule_id == "X"


def test_classification_language_never_claims_confirmed_fraud():
    values = {c.value for c in RiskClassification}
    assert "CONFIRMED_FRAUD" not in values
    assert values == {"SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"}


def test_custom_policy_can_be_injected():
    from app.risk_scoring.scoring_policy import ScoringPolicy, SeverityWeights, default_scoring_policy

    base = default_scoring_policy()
    custom_policy = ScoringPolicy(
        severity_weights=SeverityWeights(low=5, medium=15, high=25, critical=40),
        correlation_groups=base.correlation_groups,
        classification_thresholds=base.classification_thresholds,
        action_map=base.action_map,
        confidence_weights=base.confidence_weights,
    )
    custom_engine = RiskEngine(policy=custom_policy)
    assessment = custom_engine.evaluate(
        [make_evidence(rule_id="A", severity=Severity.CRITICAL, confidence=1.0)]
    )
    assert assessment.risk_score == 40
