from app.detection.enums import EvidenceCategory
from app.detection.url_rules.suspicious_query_parameter import SuspiciousQueryParameterRule
from tests.detection_fixtures import build_event

rule = SuspiciousQueryParameterRule()


def test_ordinary_query_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://example.com/search?q=hello"])) is None


def test_redirect_param_with_ordinary_path_value_not_flagged():
    # Presence alone must not be malicious -- value isn't URL-shaped.
    assert rule.evaluate(build_event(urls=["https://example.com/go?next=/dashboard"])) is None


def test_redirect_param_with_url_value_flagged():
    event = build_event(
        urls=["https://example.com/go?redirect=https://evil.example/harvest"]
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SUSPICIOUS_QUERY_PARAMETER"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL


def test_token_param_with_opaque_value_not_flagged():
    assert rule.evaluate(build_event(urls=["https://example.com/verify?token=abc123"])) is None


def test_token_param_with_url_value_flagged():
    event = build_event(urls=["https://example.com/verify?token=//evil.example/steal"])
    evidence = rule.evaluate(event)
    assert evidence is not None


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None


def test_malformed_url_does_not_crash():
    assert rule.evaluate(build_event(urls=["not a url at all"])) is None
