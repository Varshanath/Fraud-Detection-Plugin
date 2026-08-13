from app.detection.enums import EvidenceCategory, Severity
from app.detection.url_rules.ip_address_url import IpAddressUrlRule
from tests.detection_fixtures import build_event

rule = IpAddressUrlRule()


def test_normal_domain_url_produces_no_evidence():
    event = build_event(urls=["https://example.com/dashboard"])
    assert rule.evaluate(event) is None


def test_ip_address_url_flagged_moderate_severity():
    event = build_event(urls=["http://192.168.1.10/login"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "IP_ADDRESS_URL"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL
    # Explicitly not CRITICAL, per spec.
    assert evidence.severity == Severity.MEDIUM


def test_ipv6_host_flagged():
    event = build_event(urls=["http://[2001:db8::1]/login"])
    evidence = rule.evaluate(event)
    assert evidence is not None


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None


def test_malformed_url_does_not_crash():
    assert rule.evaluate(build_event(urls=["not a url at all"])) is None


def test_multiple_ip_urls_all_listed():
    event = build_event(urls=["http://10.0.0.1/a", "http://10.0.0.2/b"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert len(evidence.details["urls"]) == 2
