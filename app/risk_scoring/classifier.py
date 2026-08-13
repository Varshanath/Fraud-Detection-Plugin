from app.risk_scoring.enums import RecommendedAction, RiskClassification
from app.risk_scoring.scoring_policy import ScoringPolicy


def classify(risk_score: int, policy: ScoringPolicy) -> RiskClassification:
    return policy.classify(risk_score)


def recommend_action(classification: RiskClassification, policy: ScoringPolicy) -> RecommendedAction:
    """Derived ONLY from classification, never from raw evidence."""
    return policy.recommend_action(classification)
