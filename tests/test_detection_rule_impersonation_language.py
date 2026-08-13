from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.impersonation_language import ImpersonationLanguageRule
from tests.detection_fixtures import build_event

rule = ImpersonationLanguageRule()


def test_positive_this_is_your_bank():
    event = build_event(content="This is your bank. We need to verify your recent activity.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "IMPERSONATION_LANGUAGE"
    assert evidence.category == EvidenceCategory.SOCIAL_ENGINEERING
    assert evidence.severity == Severity.MEDIUM
    assert "bank" in evidence.details["matched_roles"]


def test_positive_on_behalf_of_delivery_company():
    event = build_event(content="On behalf of the delivery company, your parcel is delayed.")
    assert rule.evaluate(event) is not None


def test_negative_role_word_without_claim_template():
    event = build_event(content="I bank with a local credit union near my house.")
    assert rule.evaluate(event) is None


def test_negative_no_signal():
    event = build_event(content="See you at the meeting tomorrow.")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="THIS IS YOUR BANK.")
    assert rule.evaluate(event) is not None


def test_missing_subject_field_does_not_error():
    event = build_event(subject=None, content="this is your employer with an update.")
    assert rule.evaluate(event) is not None
