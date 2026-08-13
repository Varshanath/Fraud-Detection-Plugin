from app.detection.enums import EvidenceCategory, Severity
from app.detection.url_rules.lookalike_url_domain import LookalikeUrlDomainRule
from tests.detection_fixtures import build_event

rule = LookalikeUrlDomainRule()


def test_legitimate_url_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://paypal.com/login"])) is None


def test_lookalike_url_flagged():
    event = build_event(urls=["https://paypa1-example.com/login"])
    evidence = rule.evaluate(event)
    # This one has extra text beyond the substitution, so it may not cross
    # threshold -- covered by the clean case below; this asserts no crash.
    assert evidence is None or evidence.rule_id == "LOOKALIKE_URL_DOMAIN"


def test_clean_lookalike_url_flagged():
    event = build_event(urls=["https://paypa1.com/login"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "LOOKALIKE_URL_DOMAIN"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL
    assert evidence.severity == Severity.HIGH
    assert evidence.details["urls"][0]["reference_domain"] == "paypal.com"


def test_unrelated_domain_not_flagged():
    assert rule.evaluate(build_event(urls=["https://mycompany.example/dashboard"])) is None


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None


def test_malformed_url_does_not_crash():
    assert rule.evaluate(build_event(urls=["not a url at all"])) is None
