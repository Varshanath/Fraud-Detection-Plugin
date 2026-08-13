from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.financial_request import FinancialRequestRule
from tests.detection_fixtures import build_event

rule = FinancialRequestRule()


def test_positive_verb_then_noun():
    event = build_event(content="Please make a payment immediately to avoid penalty.")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "FINANCIAL_REQUEST"
    assert evidence.category == EvidenceCategory.FINANCIAL_FRAUD
    assert evidence.severity == Severity.HIGH


def test_positive_multiple_signals():
    event = build_event(
        content="Send your bank details and card details to confirm your payment."
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "bank details" in evidence.details["matched_phrases"]
    assert "card details" in evidence.details["matched_phrases"]


def test_mandated_false_positive_payment_confirmation():
    event = build_event(content="Your payment of ₹500 was successful.")
    assert rule.evaluate(event) is None


def test_negative_no_financial_noun():
    event = build_event(content="Please send the report by end of day.")
    assert rule.evaluate(event) is None


def test_negative_financial_noun_without_request_verb():
    event = build_event(content="Your payment was processed successfully yesterday.")
    assert rule.evaluate(event) is None


def test_empty_content_returns_none():
    event = build_event(content=None, subject=None)
    assert rule.evaluate(event) is None


def test_case_insensitivity():
    event = build_event(content="PLEASE TRANSFER FUNDS IMMEDIATELY.")
    assert rule.evaluate(event) is not None


def test_malformed_currency_only_content():
    event = build_event(content="₹₹₹ $$$ !!!")
    assert rule.evaluate(event) is None


def test_missing_subject_field_does_not_error():
    event = build_event(subject=None, content="please wire money now")
    assert rule.evaluate(event) is not None
