from app.detection.enums import EvidenceCategory, Severity
from app.detection.url_rules.obfuscated_url import ObfuscatedUrlRule
from tests.detection_fixtures import build_event

rule = ObfuscatedUrlRule()


def test_normal_url_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://example.com/dashboard"])) is None


def test_single_ordinary_encoded_character_not_flagged():
    # Avoid flagging ordinary encoded URLs (e.g. a single %20 for a space).
    assert rule.evaluate(build_event(urls=["https://example.com/search?q=a%20b"])) is None


def test_heavily_obfuscated_url_flagged():
    event = build_event(
        urls=["https://example.com/%70%61%79%70%61%6c%2d%73%65%63%75%72%65/%6c%6f%67%69%6e"]
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "OBFUSCATED_URL"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL
    assert evidence.severity == Severity.MEDIUM


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None
