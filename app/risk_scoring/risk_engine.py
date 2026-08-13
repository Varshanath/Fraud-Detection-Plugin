from app.detection.evidence import DetectionEvidence
from app.risk_scoring.classifier import classify, recommend_action
from app.risk_scoring.confidence_calculator import calculate_confidence
from app.risk_scoring.risk_assessment import RiskAssessment
from app.risk_scoring.risk_calculator import calculate_risk
from app.risk_scoring.scoring_policy import ScoringPolicy, default_scoring_policy


class RiskEngine:
    """Pure, deterministic function of DetectionEvidence -> RiskAssessment.

    Independent of FastAPI/SQLAlchemy/Postgres/network -- operates entirely
    on in-memory evidence, the same independence bar RuleEngine is held to.
    Never claims a final "truth"; only a risk assessment.
    """

    def __init__(self, policy: ScoringPolicy | None = None) -> None:
        self.policy = policy or default_scoring_policy()

    def evaluate(self, evidence: list[DetectionEvidence]) -> RiskAssessment:
        risk_score, raw_score_before_cap, breakdown = calculate_risk(evidence, self.policy)
        confidence = calculate_confidence(breakdown, self.policy)
        classification = classify(risk_score, self.policy)
        action = recommend_action(classification, self.policy)

        return RiskAssessment(
            risk_score=risk_score,
            confidence=confidence,
            classification=classification,
            recommended_action=action,
            scoring_breakdown=breakdown,
            raw_score_before_cap=raw_score_before_cap,
        )
