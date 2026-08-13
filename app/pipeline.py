from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.detection.engine import DetectionEngine
from app.detection.evidence import DetectionEvidence
from app.ingestion.schemas import SecurityEventResponse
from app.risk_scoring.risk_assessment import RiskAssessment
from app.risk_scoring.risk_engine import RiskEngine


class PipelineResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    risk_assessment: RiskAssessment


class DetectionPipeline:
    """Composes DetectionEngine (discovers evidence) and RiskEngine
    (evaluates evidence) without merging their logic -- this class only
    sequences the two stages. No try/except here: both stages already
    isolate their own internal failures (RuleEngine/DetectionEngine per
    rule/detector); if evaluate() itself raises, that's a real bug in a
    pure computation with no sensible partial result, so it propagates.
    """

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.detection_engine = detection_engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()

    def evaluate(self, event: SecurityEventResponse) -> PipelineResult:
        detection_result = self.detection_engine.evaluate(event)
        risk_assessment = self.risk_engine.evaluate(detection_result.evidence)
        return PipelineResult(
            event_id=detection_result.event_id,
            evidence=detection_result.evidence,
            risk_assessment=risk_assessment,
        )
