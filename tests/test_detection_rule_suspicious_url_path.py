from app.detection.enums import EvidenceCategory
from app.detection.url_rules.suspicious_url_path import SuspiciousUrlPathRule
from tests.detection_fixtures import build_event

rule = SuspiciousUrlPathRule()


def test_sensitive_path_alone_on_legitimate_url_not_flagged():
    # "https://paypal.com/login" -- a sensitive path keyword alone must not fire.
    assert rule.evaluate(build_event(urls=["https://paypal.com/login"])) is None


def test_sensitive_path_alone_on_microsoft_not_flagged():
    assert rule.evaluate(build_event(urls=["https://microsoft.com/account"])) is None


def test_ordinary_path_not_flagged():
    assert rule.evaluate(build_event(urls=["https://example.com/dashboard"])) is None


def test_sensitive_path_combined_with_ip_host_flagged():
    event = build_event(urls=["http://192.168.1.10/login"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SUSPICIOUS_URL_PATH"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL


def test_sensitive_path_combined_with_http_flagged():
    event = build_event(urls=["http://example.com/verify"])
    evidence = rule.evaluate(event)
    assert evidence is not None


def test_sensitive_path_combined_with_excessive_subdomains_flagged():
    event = build_event(urls=["https://login.verify.account.security.example.com/confirm"])
    evidence = rule.evaluate(event)
    assert evidence is not None


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None
