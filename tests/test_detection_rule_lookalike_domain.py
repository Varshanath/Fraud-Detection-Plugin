from app.detection.enums import EvidenceCategory, Severity
from app.detection.sender_rules.lookalike_domain import LookalikeSenderDomainRule
from tests.detection_fixtures import build_event

rule = LookalikeSenderDomainRule()


def test_legitimate_domain_produces_no_evidence():
    event = build_event(sender_email="service@paypal.com", sender_domain="paypal.com")
    assert rule.evaluate(event) is None


def test_lookalike_domain_flagged():
    event = build_event(sender_email="security@paypa1.com", sender_domain="paypa1.com")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "LOOKALIKE_DOMAIN"
    assert evidence.category == EvidenceCategory.SENDER_SPOOFING
    assert evidence.severity == Severity.HIGH
    assert evidence.details["observed_domain"] == "paypa1.com"
    assert evidence.details["reference_domain"] == "paypal.com"
    assert evidence.confidence == evidence.details["similarity"]


def test_completely_unrelated_domain_not_flagged():
    event = build_event(sender_email="hello@myowncompany.example", sender_domain="myowncompany.example")
    assert rule.evaluate(event) is None


def test_missing_sender_domain_produces_no_evidence():
    event = build_event(sender_domain=None)
    assert rule.evaluate(event) is None


def test_does_not_flag_every_similar_domain_conservative_threshold():
    event = build_event(sender_email="a@mypal.com", sender_domain="mypal.com")
    assert rule.evaluate(event) is None
