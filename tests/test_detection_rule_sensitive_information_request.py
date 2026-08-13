from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.credential_request import CredentialRequestRule
from app.detection.rules.financial_request import FinancialRequestRule
from app.detection.rules.sensitive_information_request import (
    SensitiveInformationRequestRule,
)
from tests.detection_fixtures import build_event

rule = SensitiveInformationRequestRule()


def test_positive_verb_then_noun():
    event = build_event(content="Please provide your date of birth to verify your identity.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SENSITIVE_INFORMATION_REQUEST"
    assert evidence.category == EvidenceCategory.SENSITIVE_INFORMATION_REQUEST
    assert evidence.severity == Severity.MEDIUM


def test_positive_ssn_request():
    event = build_event(content="Please confirm your social security number below.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "social security number" in evidence.details["matched_phrases"]


def test_negative_mention_without_request_verb():
    event = build_event(content="Your date of birth was recorded when you signed up.")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="PLEASE SHARE YOUR PASSPORT NUMBER.")
    assert rule.evaluate(event) is not None


def test_no_overlap_with_credential_or_financial_rules():
    event = build_event(
        content="Please enter your password and make a payment to confirm your identity."
    )

    identity_evidence = rule.evaluate(event)
    credential_evidence = CredentialRequestRule().evaluate(event)
    financial_evidence = FinancialRequestRule().evaluate(event)

    assert identity_evidence is None
    assert credential_evidence is not None
    assert financial_evidence is not None
