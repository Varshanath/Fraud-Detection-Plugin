import pytest
from pydantic import ValidationError

from app.risk_scoring.enums import RiskClassification
from app.risk_scoring.scoring_policy import (
    ClassificationThreshold,
    ConfidenceWeights,
    DEFAULT_SCORING_POLICY,
    ScoringPolicy,
    SeverityWeights,
    default_scoring_policy,
)


def test_default_policy_severity_weights_are_ascending():
    weights = DEFAULT_SCORING_POLICY.severity_weights
    assert weights.low < weights.medium < weights.high < weights.critical


def test_default_policy_thresholds_cover_0_to_100():
    ordered = sorted(DEFAULT_SCORING_POLICY.classification_thresholds, key=lambda t: t.min_score)
    assert ordered[0].min_score == 0
    assert ordered[-1].max_score == 100
    for previous, current in zip(ordered, ordered[1:]):
        assert current.min_score == previous.max_score + 1


def test_default_policy_action_map_covers_all_classifications():
    assert set(DEFAULT_SCORING_POLICY.action_map.keys()) == set(RiskClassification)


def test_default_scoring_policy_factory_returns_valid_policy():
    policy = default_scoring_policy()
    assert isinstance(policy, ScoringPolicy)


def test_severity_weights_reject_non_ascending():
    with pytest.raises(ValidationError):
        SeverityWeights(low=50, medium=30, high=55, critical=85)


def test_classification_threshold_rejects_invalid_range():
    with pytest.raises(ValidationError):
        ClassificationThreshold(classification=RiskClassification.SAFE, min_score=20, max_score=10)


def test_confidence_weights_must_sum_to_one():
    with pytest.raises(ValidationError):
        ConfidenceWeights(
            evidence_confidence_weight=0.5, diversity_weight=0.3, signals_for_full_diversity=4
        )


def test_scoring_policy_rejects_gapped_thresholds():
    with pytest.raises(ValidationError):
        ScoringPolicy(
            severity_weights=SeverityWeights(low=10, medium=30, high=55, critical=85),
            correlation_groups={},
            classification_thresholds=(
                ClassificationThreshold(
                    classification=RiskClassification.SAFE, min_score=0, max_score=19
                ),
                ClassificationThreshold(
                    classification=RiskClassification.CRITICAL, min_score=25, max_score=100
                ),
            ),
            action_map={c: DEFAULT_SCORING_POLICY.action_map[c] for c in RiskClassification},
            confidence_weights=ConfidenceWeights(
                evidence_confidence_weight=0.6, diversity_weight=0.4, signals_for_full_diversity=4
            ),
        )


def test_scoring_policy_rejects_incomplete_action_map():
    with pytest.raises(ValidationError):
        ScoringPolicy(
            severity_weights=SeverityWeights(low=10, medium=30, high=55, critical=85),
            correlation_groups={},
            classification_thresholds=DEFAULT_SCORING_POLICY.classification_thresholds,
            action_map={RiskClassification.SAFE: DEFAULT_SCORING_POLICY.action_map[RiskClassification.SAFE]},
            confidence_weights=ConfidenceWeights(
                evidence_confidence_weight=0.6, diversity_weight=0.4, signals_for_full_diversity=4
            ),
        )


def test_correlation_group_for_unmapped_rule_id_defaults_to_itself():
    assert DEFAULT_SCORING_POLICY.correlation_group_for("SOME_UNMAPPED_RULE") == "SOME_UNMAPPED_RULE"


def test_correlation_group_for_mapped_rule_id():
    assert DEFAULT_SCORING_POLICY.correlation_group_for("LOOKALIKE_DOMAIN") == "domain_lookalike"
    assert DEFAULT_SCORING_POLICY.correlation_group_for("LOOKALIKE_URL_DOMAIN") == "domain_lookalike"


def test_policy_is_frozen():
    with pytest.raises(ValidationError):
        DEFAULT_SCORING_POLICY.correlation_groups = {}
