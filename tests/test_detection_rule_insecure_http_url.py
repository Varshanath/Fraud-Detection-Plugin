from app.detection.enums import EvidenceCategory, Severity
from app.detection.url_rules.insecure_http_url import InsecureHttpUrlRule
from tests.detection_fixtures import build_event

rule = InsecureHttpUrlRule()


def test_https_url_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://example.com/"])) is None


def test_http_url_flagged_low_severity():
    event = build_event(urls=["http://example.com/"])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "INSECURE_HTTP_URL"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL
    # Not classified as malicious -- LOW severity only, a signal.
    assert evidence.severity == Severity.LOW


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None


def test_malformed_url_does_not_crash():
    assert rule.evaluate(build_event(urls=["not a url at all"])) is None
