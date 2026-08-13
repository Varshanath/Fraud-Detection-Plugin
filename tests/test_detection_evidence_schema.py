import pytest
from pydantic import ValidationError

from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence


def _make(**overrides) -> DetectionEvidence:
    defaults = dict(
        rule_id="URGENCY_PRESSURE",
        category=EvidenceCategory.SOCIAL_ENGINEERING,
        severity=Severity.MEDIUM,
        confidence=0.5,
        description="test",
        details={},
    )
    defaults.update(overrides)
    return DetectionEvidence(**defaults)


def test_valid_evidence_constructs():
    evidence = _make()
    assert evidence.confidence == 0.5


def test_confidence_rejects_below_zero():
    with pytest.raises(ValidationError):
        _make(confidence=-0.1)


def test_confidence_rejects_above_one():
    with pytest.raises(ValidationError):
        _make(confidence=1.1)


def test_confidence_accepts_boundaries():
    assert _make(confidence=0.0).confidence == 0.0
    assert _make(confidence=1.0).confidence == 1.0


def test_invalid_category_rejected():
    with pytest.raises(ValidationError):
        _make(category="NOT_A_CATEGORY")


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        _make(severity="NOT_A_SEVERITY")


def test_details_defaults_to_empty_dict():
    evidence = DetectionEvidence(
        rule_id="X",
        category=EvidenceCategory.SOCIAL_ENGINEERING,
        severity=Severity.LOW,
        confidence=0.1,
        description="d",
    )
    assert evidence.details == {}


def test_evidence_is_immutable():
    evidence = _make()
    with pytest.raises(ValidationError):
        evidence.confidence = 0.9
