from enum import Enum

from pydantic import BaseModel, ConfigDict


class DetectorOutcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class DetectorStatus(BaseModel):
    """Whether one detector run by DetectionEngine succeeded or failed.

    Exists so a detector failure can be reported upward instead of silently
    swallowed -- a failed detector is missing visibility, not evidence of
    absence.
    """

    model_config = ConfigDict(frozen=True)

    detector_name: str
    outcome: DetectorOutcome
