from app.detection.enums import EvidenceCategory
from app.detection.url_rules.excessive_url_length import ExcessiveUrlLengthRule
from tests.detection_fixtures import build_event

rule = ExcessiveUrlLengthRule()


def test_normal_length_url_produces_no_evidence():
    assert rule.evaluate(build_event(urls=["https://example.com/dashboard"])) is None


def test_long_url_flagged():
    event = build_event(urls=["https://example.com/path?" + "a" * 250])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "EXCESSIVE_URL_LENGTH"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_URL


def test_configurable_threshold():
    strict_rule = ExcessiveUrlLengthRule(threshold=10)
    event = build_event(urls=["https://example.com/dashboard"])
    assert strict_rule.evaluate(event) is not None


def test_empty_url_list_produces_no_evidence():
    assert rule.evaluate(build_event(urls=[])) is None
