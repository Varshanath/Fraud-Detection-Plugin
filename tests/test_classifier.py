import pytest

from app.risk_scoring.classifier import classify, recommend_action
from app.risk_scoring.enums import RecommendedAction, RiskClassification
from app.risk_scoring.scoring_policy import default_scoring_policy

policy = default_scoring_policy()


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskClassification.SAFE),
        (19, RiskClassification.SAFE),
        (20, RiskClassification.LOW_RISK),
        (39, RiskClassification.LOW_RISK),
        (40, RiskClassification.SUSPICIOUS),
        (69, RiskClassification.SUSPICIOUS),
        (70, RiskClassification.HIGH_RISK),
        (89, RiskClassification.HIGH_RISK),
        (90, RiskClassification.CRITICAL),
        (100, RiskClassification.CRITICAL),
    ],
)
def test_classification_boundaries(score, expected):
    assert classify(score, policy) == expected


@pytest.mark.parametrize(
    "classification,expected_action",
    [
        (RiskClassification.SAFE, RecommendedAction.ALLOW),
        (RiskClassification.LOW_RISK, RecommendedAction.MONITOR),
        (RiskClassification.SUSPICIOUS, RecommendedAction.WARN),
        (RiskClassification.HIGH_RISK, RecommendedAction.QUARANTINE),
        (RiskClassification.CRITICAL, RecommendedAction.BLOCK),
    ],
)
def test_action_mapping(classification, expected_action):
    assert recommend_action(classification, policy) == expected_action


def test_recommend_action_signature_only_takes_classification():
    import inspect

    params = list(inspect.signature(recommend_action).parameters)
    assert "evidence" not in params
    assert "risk_score" not in params
