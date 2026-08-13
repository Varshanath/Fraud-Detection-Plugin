from app.detection.enums import EvidenceCategory, Severity
from app.detection.sender_rules.suspicious_sender_domain import SuspiciousSenderDomainRule
from tests.detection_fixtures import build_event

rule = SuspiciousSenderDomainRule()


def test_normal_domain_produces_no_evidence():
    event = build_event(sender_email="alerts@examplebank.com", sender_domain="examplebank.com")
    assert rule.evaluate(event) is None


def test_no_sender_email_produces_no_evidence():
    event = build_event(sender_email=None, sender_domain=None)
    assert rule.evaluate(event) is None


def test_missing_domain_flagged():
    event = build_event(sender_email="user@example.com", sender_domain=None)
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "missing_domain" in evidence.details["signals"]
    assert evidence.category == EvidenceCategory.SENDER_SPOOFING


def test_malformed_domain_flagged():
    event = build_event(sender_email="user@examplebank.com", sender_domain="localhost")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "malformed_domain" in evidence.details["signals"]


def test_unusually_long_domain_flagged():
    long_label = "a" * 45
    event = build_event(sender_email=f"user@{long_label}.com", sender_domain=f"{long_label}.com")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "unusually_long_domain" in evidence.details["signals"]


def test_excessive_domain_labels_flagged():
    domain = "login.verify.account.security.example.com"
    event = build_event(sender_email=f"user@{domain}", sender_domain=domain)
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "excessive_domain_labels" in evidence.details["signals"]


def test_numeric_substitution_flagged():
    event = build_event(sender_email="user@paypa1.com", sender_domain="paypa1.com")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "numeric_substitution" in evidence.details["signals"]
    assert evidence.severity == Severity.MEDIUM


def test_suspicious_hyphenation_flagged():
    event = build_event(
        sender_email="user@secure-verify-account-now.com",
        sender_domain="secure-verify-account-now.com",
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "suspicious_hyphenation" in evidence.details["signals"]


def test_random_looking_label_flagged():
    event = build_event(sender_email="user@xqzvbmwklp.com", sender_domain="xqzvbmwklp.com")
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert "random_looking_label" in evidence.details["signals"]


def test_multiple_signals_increase_confidence():
    single = rule.evaluate(
        build_event(sender_email="user@paypa1.com", sender_domain="paypa1.com")
    )
    multiple = rule.evaluate(
        build_event(
            sender_email="user@secure-paypa1-verify-now.com",
            sender_domain="secure-paypa1-verify-now.com",
        )
    )
    assert multiple.confidence > single.confidence
