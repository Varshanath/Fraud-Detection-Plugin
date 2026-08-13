import logging
import uuid
from collections.abc import Iterable
from typing import Protocol

from pydantic import BaseModel, Field

from app.detection.coverage import DetectorOutcome, DetectorStatus
from app.detection.evidence import DetectionEvidence
from app.detection.registry import build_default_detectors
from app.ingestion.schemas import SecurityEventResponse

logger = logging.getLogger(__name__)


class HasEvidence(Protocol):
    evidence: list[DetectionEvidence]


class Detector(Protocol):
    def evaluate(self, event: SecurityEventResponse) -> HasEvidence: ...


class DetectionResult(BaseModel):
    event_id: uuid.UUID
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    detector_statuses: list[DetectorStatus] = Field(default_factory=list)


class DetectionEngine:
    """Coordinates detection mechanisms. By default runs RuleEngine,
    SenderAnalyzer, and URLAnalyzer; designed so further detectors
    (ReputationAnalyzer, ML/anomaly/similarity detectors -- none implemented
    yet) can be added by passing additional detectors in; this class's
    implementation does not need to change.
    """

    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors: list[Detector] = (
            list(detectors) if detectors is not None else build_default_detectors()
        )

    def evaluate(self, event: SecurityEventResponse) -> DetectionResult:
        evidence: list[DetectionEvidence] = []
        detector_statuses: list[DetectorStatus] = []
        for detector in self._detectors:
            name = type(detector).__name__
            try:
                result = detector.evaluate(event)
            except Exception:
                logger.exception("Detector %r raised an exception during evaluation", detector)
                detector_statuses.append(
                    DetectorStatus(detector_name=name, outcome=DetectorOutcome.FAILED)
                )
                continue
            evidence.extend(result.evidence)
            detector_statuses.append(
                DetectorStatus(detector_name=name, outcome=DetectorOutcome.SUCCEEDED)
            )
        return DetectionResult(
            event_id=event.event_id, evidence=evidence, detector_statuses=detector_statuses
        )
