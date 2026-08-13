from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detection.enums import Severity
from app.risk_scoring.enums import RecommendedAction, RiskClassification


class SeverityWeights(BaseModel):
    model_config = ConfigDict(frozen=True)

    low: int = Field(ge=0, le=100)
    medium: int = Field(ge=0, le=100)
    high: int = Field(ge=0, le=100)
    critical: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _ascending(self) -> "SeverityWeights":
        if not (self.low < self.medium < self.high < self.critical):
            raise ValueError(
                "severity weights must be strictly ascending: low < medium < high < critical"
            )
        return self

    def weight_for(self, severity: Severity) -> int:
        return {
            Severity.LOW: self.low,
            Severity.MEDIUM: self.medium,
            Severity.HIGH: self.high,
            Severity.CRITICAL: self.critical,
        }[severity]


class ClassificationThreshold(BaseModel):
    model_config = ConfigDict(frozen=True)

    classification: RiskClassification
    min_score: int = Field(ge=0, le=100)
    max_score: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _valid_range(self) -> "ClassificationThreshold":
        if self.min_score > self.max_score:
            raise ValueError("min_score must be <= max_score")
        return self


class ConfidenceWeights(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_confidence_weight: float = Field(ge=0.0, le=1.0)
    diversity_weight: float = Field(ge=0.0, le=1.0)
    signals_for_full_diversity: int = Field(ge=1)

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> "ConfidenceWeights":
        total = self.evidence_confidence_weight + self.diversity_weight
        if abs(total - 1.0) > 1e-9:
            raise ValueError("evidence_confidence_weight + diversity_weight must equal 1.0")
        return self


class ScoringPolicy(BaseModel):
    """Centralized, configurable scoring policy. Every evidence item's
    contribution to risk_score, and every confidence/classification/action
    computation, flows through this policy -- nothing is hard-coded inside
    individual rules or the calculators themselves.
    """

    model_config = ConfigDict(frozen=True)

    severity_weights: SeverityWeights
    correlation_groups: dict[str, str]  # rule_id -> correlation_group name
    classification_thresholds: tuple[ClassificationThreshold, ...]
    action_map: dict[RiskClassification, RecommendedAction]
    confidence_weights: ConfidenceWeights

    @model_validator(mode="after")
    def _thresholds_cover_0_to_100_contiguously(self) -> "ScoringPolicy":
        ordered = sorted(self.classification_thresholds, key=lambda t: t.min_score)
        if not ordered or ordered[0].min_score != 0:
            raise ValueError("classification thresholds must start at 0")
        if ordered[-1].max_score != 100:
            raise ValueError("classification thresholds must end at 100")
        for previous, current in zip(ordered, ordered[1:]):
            if current.min_score != previous.max_score + 1:
                raise ValueError(
                    "classification thresholds must be contiguous with no gaps or overlaps"
                )
        return self

    @model_validator(mode="after")
    def _action_map_covers_all_classifications(self) -> "ScoringPolicy":
        missing = set(RiskClassification) - set(self.action_map.keys())
        if missing:
            raise ValueError(f"action_map missing classifications: {missing}")
        return self

    def correlation_group_for(self, rule_id: str) -> str:
        return self.correlation_groups.get(rule_id, rule_id)

    def classify(self, risk_score: int) -> RiskClassification:
        for threshold in self.classification_thresholds:
            if threshold.min_score <= risk_score <= threshold.max_score:
                return threshold.classification
        raise ValueError(f"risk_score {risk_score} is not covered by any classification threshold")

    def recommend_action(self, classification: RiskClassification) -> RecommendedAction:
        return self.action_map[classification]


DEFAULT_SCORING_POLICY = ScoringPolicy(
    severity_weights=SeverityWeights(low=10, medium=30, high=55, critical=85),
    correlation_groups={
        "LOOKALIKE_DOMAIN": "domain_lookalike",
        "LOOKALIKE_URL_DOMAIN": "domain_lookalike",
    },
    classification_thresholds=(
        ClassificationThreshold(classification=RiskClassification.SAFE, min_score=0, max_score=19),
        ClassificationThreshold(
            classification=RiskClassification.LOW_RISK, min_score=20, max_score=39
        ),
        ClassificationThreshold(
            classification=RiskClassification.SUSPICIOUS, min_score=40, max_score=69
        ),
        ClassificationThreshold(
            classification=RiskClassification.HIGH_RISK, min_score=70, max_score=89
        ),
        ClassificationThreshold(
            classification=RiskClassification.CRITICAL, min_score=90, max_score=100
        ),
    ),
    action_map={
        RiskClassification.SAFE: RecommendedAction.ALLOW,
        RiskClassification.LOW_RISK: RecommendedAction.MONITOR,
        RiskClassification.SUSPICIOUS: RecommendedAction.WARN,
        RiskClassification.HIGH_RISK: RecommendedAction.QUARANTINE,
        RiskClassification.CRITICAL: RecommendedAction.BLOCK,
    },
    confidence_weights=ConfidenceWeights(
        evidence_confidence_weight=0.6, diversity_weight=0.4, signals_for_full_diversity=4
    ),
)


def default_scoring_policy() -> ScoringPolicy:
    return DEFAULT_SCORING_POLICY
