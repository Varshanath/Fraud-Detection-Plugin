from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.detection.coverage import DetectorOutcome, DetectorStatus


class DetectionCoverage(BaseModel):
    """Which detection mechanisms actually ran for one event, and which
    failed. A failed detector means the system has incomplete visibility --
    it must never be treated as evidence of absence.
    """

    model_config = ConfigDict(frozen=True)

    detector_statuses: list[DetectorStatus] = Field(default_factory=list)

    @computed_field  # type: ignore[misc]
    @property
    def detectors_attempted(self) -> int:
        return len(self.detector_statuses)

    @computed_field  # type: ignore[misc]
    @property
    def detectors_succeeded(self) -> int:
        return sum(
            1 for s in self.detector_statuses if s.outcome == DetectorOutcome.SUCCEEDED
        )

    @computed_field  # type: ignore[misc]
    @property
    def detectors_failed(self) -> int:
        return sum(1 for s in self.detector_statuses if s.outcome == DetectorOutcome.FAILED)

    @computed_field  # type: ignore[misc]
    @property
    def failed_detector_names(self) -> list[str]:
        return [
            s.detector_name for s in self.detector_statuses if s.outcome == DetectorOutcome.FAILED
        ]

    @computed_field  # type: ignore[misc]
    @property
    def is_complete(self) -> bool:
        return self.detectors_failed == 0
