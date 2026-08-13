from app.detection.coverage import DetectorOutcome, DetectorStatus
from app.escalation.detection_coverage import DetectionCoverage


def test_all_detectors_succeeded():
    coverage = DetectionCoverage(
        detector_statuses=[
            DetectorStatus(detector_name="A", outcome=DetectorOutcome.SUCCEEDED),
            DetectorStatus(detector_name="B", outcome=DetectorOutcome.SUCCEEDED),
        ]
    )
    assert coverage.detectors_attempted == 2
    assert coverage.detectors_succeeded == 2
    assert coverage.detectors_failed == 0
    assert coverage.failed_detector_names == []
    assert coverage.is_complete is True


def test_one_detector_failed():
    coverage = DetectionCoverage(
        detector_statuses=[
            DetectorStatus(detector_name="A", outcome=DetectorOutcome.SUCCEEDED),
            DetectorStatus(detector_name="B", outcome=DetectorOutcome.FAILED),
        ]
    )
    assert coverage.detectors_attempted == 2
    assert coverage.detectors_succeeded == 1
    assert coverage.detectors_failed == 1
    assert coverage.failed_detector_names == ["B"]
    assert coverage.is_complete is False


def test_multiple_detectors_failed():
    coverage = DetectionCoverage(
        detector_statuses=[
            DetectorStatus(detector_name="A", outcome=DetectorOutcome.FAILED),
            DetectorStatus(detector_name="B", outcome=DetectorOutcome.FAILED),
            DetectorStatus(detector_name="C", outcome=DetectorOutcome.SUCCEEDED),
        ]
    )
    assert coverage.detectors_failed == 2
    assert coverage.detectors_succeeded == 1
    assert coverage.failed_detector_names == ["A", "B"]
    assert coverage.is_complete is False


def test_all_detectors_failed():
    coverage = DetectionCoverage(
        detector_statuses=[
            DetectorStatus(detector_name="A", outcome=DetectorOutcome.FAILED),
            DetectorStatus(detector_name="B", outcome=DetectorOutcome.FAILED),
        ]
    )
    assert coverage.detectors_succeeded == 0
    assert coverage.detectors_failed == 2
    assert coverage.is_complete is False


def test_empty_coverage_is_vacuously_complete():
    coverage = DetectionCoverage()
    assert coverage.detectors_attempted == 0
    assert coverage.is_complete is True


def test_computed_fields_appear_in_serialized_output():
    coverage = DetectionCoverage(
        detector_statuses=[DetectorStatus(detector_name="A", outcome=DetectorOutcome.SUCCEEDED)]
    )
    dumped = coverage.model_dump()
    assert dumped["detectors_attempted"] == 1
    assert dumped["detectors_succeeded"] == 1
    assert dumped["detectors_failed"] == 0
    assert dumped["failed_detector_names"] == []
    assert dumped["is_complete"] is True


def test_coverage_is_frozen():
    import pytest
    from pydantic import ValidationError

    coverage = DetectionCoverage()
    with pytest.raises(ValidationError):
        coverage.detector_statuses = []
