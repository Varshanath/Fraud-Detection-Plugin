from app.detection.enums import EvidenceCategory, Severity
from app.detection.url_rules.excessive_subdomains import ExcessiveSubdomainsRule
from tests.detection_fixtures import build_event

rule = ExcessiveSubdomainsRule()


def test_normal_url_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://example.com/"])) is None


def test_one_subdomain_is_not_excessive():
    assert rule.evaluate(build_event(urls=["https://mail.example.com/"])) is None


def test_excessive_subdomains_flagged():
    event = build_event(urls=["https://login.verify.account.security.example.com/"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "EXCESSIVE_SUBDOMAINS"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL
    assert evidence.severity == Severity.MEDIUM


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None


def test_malformed_url_does_not_crash():
    assert rule.evaluate(build_event(urls=["not a url at all"])) is None
