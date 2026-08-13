from pydantic import BaseModel, ConfigDict, Field

from app.detection.enums import EvidenceCategory, Severity
from app.risk_scoring.enums import RecommendedAction, RiskClassification


class ScoringBreakdownEntry(BaseModel):
    """One evidence item's traceable contribution to the risk score."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: EvidenceCategory
    severity: Severity
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    severity_weight: int
    contribution: float
    correlation_group: str
    counted: bool
    suppressed_reason: str | None = None


class RiskAssessment(BaseModel):
    """Pure function of a list of DetectionEvidence -- a risk ASSESSMENT, not
    a verdict. Never claims certainty; classification/action vocabulary is
    deliberately risk-language only (SAFE/LOW_RISK/SUSPICIOUS/HIGH_RISK/
    CRITICAL), never "CONFIRMED_FRAUD" or similar.
    """

    model_config = ConfigDict(frozen=True)

    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    classification: RiskClassification
    recommended_action: RecommendedAction
    scoring_breakdown: list[ScoringBreakdownEntry] = Field(default_factory=list)
    raw_score_before_cap: float = 0.0
