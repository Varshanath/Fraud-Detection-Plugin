from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.urgency_pressure import UrgencyPressureRule
from tests.detection_fixtures import build_event

rule = UrgencyPressureRule()


def test_positive_single_phrase():
    event = build_event(content="This is your final warning.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "URGENCY_PRESSURE"
    assert evidence.category == EvidenceCategory.SOCIAL_ENGINEERING


def test_negative_no_signal():
    event = build_event(content="Thanks for your order, see you soon.")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="ACT IMMEDIATELY to save your account.")
    assert rule.evaluate(event) is not None


def test_punctuation_variation():
    event = build_event(content="Act immediately!!! Your account will be suspended.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.severity == Severity.HIGH


def test_multiple_signals_increase_confidence():
    single = rule.evaluate(build_event(content="This is your final warning."))
    multiple = rule.evaluate(
        build_event(
            content=(
                "Final warning: act now, respond immediately, "
                "this is urgent action required."
            )
        )
    )
    assert multiple.confidence > single.confidence


def test_threat_phrase_sets_high_severity():
    event = build_event(content="Your account will be suspended.")
    evidence = rule.evaluate(event)
    assert evidence.severity == Severity.HIGH


def test_non_threat_phrase_sets_medium_severity():
    event = build_event(content="This is a limited time offer.")
    evidence = rule.evaluate(event)
    assert evidence.severity == Severity.MEDIUM


def test_soft_case_produces_evidence_but_is_not_a_hard_requirement():
    event = build_event(
        content="Your account will be closed if you do not update your details."
    )
    evidence = rule.evaluate(event)
    assert evidence is not None


def test_missing_subject_field_does_not_error():
    event = build_event(subject=None, content="act now")
    assert rule.evaluate(event) is not None


def test_matched_phrases_recorded_in_details():
    event = build_event(content="Final warning: act now.")
    evidence = rule.evaluate(event)
    assert "final warning" in evidence.details["matched_phrases"]
    assert "act now" in evidence.details["matched_phrases"]
