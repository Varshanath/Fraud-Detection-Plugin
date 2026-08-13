from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.suspicious_call_to_action import SuspiciousCallToActionRule
from tests.detection_fixtures import build_event

rule = SuspiciousCallToActionRule()


def test_positive_single_phrase():
    event = build_event(content="Click here to view your document.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SUSPICIOUS_CALL_TO_ACTION"
    assert evidence.category == EvidenceCategory.SOCIAL_ENGINEERING
    assert evidence.severity == Severity.MEDIUM


def test_negative_no_signal():
    event = build_event(content="Have a great weekend!")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="CLICK HERE NOW.")
    assert rule.evaluate(event) is not None


def test_punctuation_variation():
    event = build_event(content="Click here!! Verify now!!")
    assert rule.evaluate(event) is not None


def test_multiple_phrases_escalate_severity():
    event = build_event(
        content="Click here, verify now, and confirm account to avoid interruption."
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.severity == Severity.HIGH


def test_missing_subject_field_does_not_error():
    event = build_event(subject=None, content="download now")
    assert rule.evaluate(event) is not None
