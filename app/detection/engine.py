import logging
import uuid
from collections.abc import Iterable
from typing import Protocol

from pydantic import BaseModel, Field

from app.detection.evidence import DetectionEvidence
from app.detection.registry import build_default_rule_engine
from app.ingestion.schemas import SecurityEventResponse

logger = logging.getLogger(__name__)


class HasEvidence(Protocol):
    evidence: list[DetectionEvidence]


class Detector(Protocol):
    def evaluate(self, event: SecurityEventResponse) -> HasEvidence: ...


class DetectionResult(BaseModel):
    event_id: uuid.UUID
    evidence: list[DetectionEvidence] = Field(default_factory=list)


class DetectionEngine:
    """Coordinates detection mechanisms. Currently wraps RuleEngine only, but is
    designed so future detectors (SenderAnalyzer, URLAnalyzer, ReputationAnalyzer,
    ML/anomaly/similarity detectors -- none implemented yet) can be added by
    passing additional detectors in; this class's implementation does not
    need to change.
    """

    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors: list[Detector] = (
            list(detectors) if detectors is not None else [build_default_rule_engine()]
        )

    def evaluate(self, event: SecurityEventResponse) -> DetectionResult:
        evidence: list[DetectionEvidence] = []
        for detector in self._detectors:
            try:
                result = detector.evaluate(event)
            except Exception:
                logger.exception("Detector %r raised an exception during evaluation", detector)
                continue
            evidence.extend(result.evidence)
        return DetectionResult(event_id=event.event_id, evidence=evidence)
