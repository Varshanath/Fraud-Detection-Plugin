from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.credential_request import CredentialRequestRule
from tests.detection_fixtures import build_event

rule = CredentialRequestRule()


def test_positive_verb_then_noun():
    event = build_event(content="Please enter your password below to continue.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "CREDENTIAL_REQUEST"
    assert evidence.category == EvidenceCategory.CREDENTIAL_THEFT
    assert evidence.severity == Severity.HIGH


def test_positive_multiple_nouns_in_one_sentence():
    event = build_event(content="Please enter your password and PIN below to verify your account.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "password" in evidence.details["matched_phrases"]
    assert "pin" in evidence.details["matched_phrases"]


def test_mandated_false_positive_otp_notification():
    event = build_event(content="Please use the OTP sent to your registered number.")
    assert rule.evaluate(event) is None


def test_negative_no_credential_noun():
    event = build_event(content="Please enter the building through the main door.")
    assert rule.evaluate(event) is None


def test_negative_credential_noun_without_request_verb():
    event = build_event(content="Your password was changed successfully yesterday.")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="PLEASE ENTER YOUR PASSWORD NOW.")
    assert rule.evaluate(event) is not None


def test_punctuation_variation():
    event = build_event(content="Enter your PIN, please!")
    assert rule.evaluate(event) is not None


def test_verb_gap_too_large_does_not_match():
    event = build_event(
        content=(
            "Enter the code we mailed to your old address on your birthday last "
            "year written on a card near the password."
        )
    )
    # "enter" and "password" are far apart (well beyond the word-gap window)
    assert rule.evaluate(event) is None


def test_missing_subject_field_does_not_error():
    event = build_event(subject=None, content="please share your otp")
    assert rule.evaluate(event) is not None
