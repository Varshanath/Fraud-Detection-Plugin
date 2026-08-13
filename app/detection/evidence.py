from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.detection.enums import EvidenceCategory, Severity


class DetectionEvidence(BaseModel):
    """A single rule's structured signal about a SecurityEvent.

    `confidence` is how strongly THIS rule believes its own specific signal
    is present -- it is never an overall phishing probability, a final risk
    score, or an ML model's confidence. Those belong to later phases
    (Risk Engine, ML detector). `severity` describes how serious this
    individual signal is on its own, not a final SAFE/PHISHING/BLOCK
    classification.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: EvidenceCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
