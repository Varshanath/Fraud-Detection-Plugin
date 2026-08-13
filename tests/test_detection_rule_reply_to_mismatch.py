from app.detection.enums import EvidenceCategory, Severity
from app.detection.sender_rules.reply_to_mismatch import SenderReplyToMismatchRule
from tests.detection_fixtures import build_event

rule = SenderReplyToMismatchRule()


def test_matching_reply_to_produces_no_evidence():
    event = build_event(
        sender_email="alerts@examplebank.com", reply_to="support@examplebank.com"
    )
    assert rule.evaluate(event) is None


def test_mismatched_reply_to_flagged():
    event = build_event(
        sender_email="alerts@examplebank.com", reply_to="reply@attacker.example"
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SENDER_REPLY_TO_MISMATCH"
    assert evidence.category == EvidenceCategory.SENDER_SPOOFING
    # Not automatically malicious -- MEDIUM, not HIGH/CRITICAL.
    assert evidence.severity == Severity.MEDIUM


def test_case_insensitive_domain_comparison():
    event = build_event(
        sender_email="alerts@ExampleBank.com", reply_to="support@examplebank.COM"
    )
    assert rule.evaluate(event) is None


def test_missing_reply_to_produces_no_evidence():
    event = build_event(sender_email="alerts@examplebank.com", reply_to=None)
    assert rule.evaluate(event) is None


def test_missing_sender_email_produces_no_evidence():
    event = build_event(sender_email=None, reply_to="reply@attacker.example")
    assert rule.evaluate(event) is None


def test_details_contain_both_domains():
    event = build_event(
        sender_email="alerts@examplebank.com", reply_to="reply@attacker.example"
    )
    evidence = rule.evaluate(event)
    assert evidence.details["sender_domain"] == "examplebank.com"
    assert evidence.details["reply_to_domain"] == "attacker.example"
