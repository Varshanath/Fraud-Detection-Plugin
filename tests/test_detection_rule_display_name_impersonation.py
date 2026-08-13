from app.detection.enums import EvidenceCategory, Severity
from app.detection.sender_rules.display_name_impersonation import DisplayNameImpersonationRule
from tests.detection_fixtures import build_event

rule = DisplayNameImpersonationRule()


def test_legitimate_brand_sender_produces_no_evidence():
    event = build_event(
        sender_display_name="PayPal", sender_email="service@paypal.com", sender_domain="paypal.com"
    )
    assert rule.evaluate(event) is None


def test_display_name_impersonation_flagged():
    event = build_event(
        sender_display_name="PayPal Security",
        sender_email="security@paypa1-example.com",
        sender_domain="paypa1-example.com",
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "DISPLAY_NAME_DOMAIN_MISMATCH"
    assert evidence.category == EvidenceCategory.SENDER_SPOOFING
    assert evidence.severity == Severity.HIGH
    assert evidence.details["claimed_brand"] == "PayPal"
    assert evidence.details["expected_domain"] == "paypal.com"


def test_no_brand_claimed_produces_no_evidence():
    event = build_event(
        sender_display_name="John Smith", sender_email="john@example.com", sender_domain="example.com"
    )
    assert rule.evaluate(event) is None


def test_missing_display_name_produces_no_evidence():
    event = build_event(sender_display_name=None, sender_email="a@example.com", sender_domain="example.com")
    assert rule.evaluate(event) is None


def test_missing_sender_domain_produces_no_evidence():
    event = build_event(sender_display_name="PayPal Support", sender_domain=None)
    assert rule.evaluate(event) is None


def test_alternate_alias_matches():
    event = build_event(
        sender_display_name="Microsoft Support",
        sender_email="attacker@evil.example",
        sender_domain="evil.example",
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.details["claimed_brand"] == "Microsoft"
