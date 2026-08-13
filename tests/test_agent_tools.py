from app.agent.tools import inspect_content, inspect_existing_evidence, inspect_sender, inspect_urls
from tests.agent_fixtures import make_investigation_context
from tests.detection_fixtures import build_event
from tests.risk_fixtures import make_evidence
from app.detection.enums import EvidenceCategory, Severity


def test_inspect_sender_detects_reply_to_mismatch():
    event = build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        reply_to="reply@attacker.example",
    )
    context = make_investigation_context(event=event)
    data = inspect_sender(context)
    assert data["sender_domain"] == "examplebank.com"
    assert data["reply_to_domain"] == "attacker.example"
    assert data["reply_to_domain_matches_sender"] is False


def test_inspect_sender_matching_domains():
    event = build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        reply_to="support@examplebank.com",
    )
    context = make_investigation_context(event=event)
    data = inspect_sender(context)
    assert data["reply_to_domain_matches_sender"] is True


def test_inspect_sender_no_reply_to_is_none_not_false():
    event = build_event(sender_email="alerts@examplebank.com", sender_domain="examplebank.com")
    context = make_investigation_context(event=event)
    data = inspect_sender(context)
    assert data["reply_to_domain_matches_sender"] is None


def test_inspect_sender_includes_existing_sender_evidence():
    evidence = [make_evidence(rule_id="LOOKALIKE_DOMAIN", category=EvidenceCategory.SENDER_SPOOFING)]
    context = make_investigation_context(evidence=evidence)
    data = inspect_sender(context)
    assert data["existing_sender_evidence"] == [
        {"rule_id": "LOOKALIKE_DOMAIN", "severity": "MEDIUM", "confidence": 0.5}
    ]


def test_inspect_urls_parses_hostname_and_path():
    event = build_event(urls=["https://paypa1.com/login"])
    context = make_investigation_context(event=event)
    data = inspect_urls(context)
    assert data["url_count"] == 1
    assert data["urls"][0]["hostname"] == "paypa1.com"
    assert data["urls"][0]["path"] == "/login"
    assert data["urls"][0]["scheme"] == "https"


def test_inspect_urls_empty_list():
    context = make_investigation_context(event=build_event(urls=[]))
    data = inspect_urls(context)
    assert data["url_count"] == 0
    assert data["urls"] == []


def test_inspect_urls_includes_existing_url_evidence():
    evidence = [make_evidence(rule_id="LOOKALIKE_URL_DOMAIN", category=EvidenceCategory.SUSPICIOUS_URL)]
    context = make_investigation_context(evidence=evidence)
    data = inspect_urls(context)
    assert len(data["existing_url_evidence"]) == 1
    assert data["existing_url_evidence"][0]["rule_id"] == "LOOKALIKE_URL_DOMAIN"


def test_inspect_content_returns_subject_and_content():
    event = build_event(subject="Urgent: verify your account", content="Click here now")
    context = make_investigation_context(event=event)
    data = inspect_content(context)
    assert data["subject"] == "Urgent: verify your account"
    assert data["content"] == "Click here now"


def test_inspect_content_includes_existing_content_evidence():
    evidence = [make_evidence(rule_id="URGENCY_PRESSURE", category=EvidenceCategory.SOCIAL_ENGINEERING)]
    context = make_investigation_context(evidence=evidence)
    data = inspect_content(context)
    assert len(data["existing_content_evidence"]) == 1


def test_inspect_content_excludes_sender_and_url_evidence():
    evidence = [
        make_evidence(rule_id="LOOKALIKE_DOMAIN", category=EvidenceCategory.SENDER_SPOOFING),
        make_evidence(rule_id="LOOKALIKE_URL_DOMAIN", category=EvidenceCategory.SUSPICIOUS_URL),
    ]
    context = make_investigation_context(evidence=evidence)
    data = inspect_content(context)
    assert data["existing_content_evidence"] == []


def test_inspect_existing_evidence_groups_by_category_and_rule_id():
    evidence = [
        make_evidence(rule_id="URGENCY_PRESSURE", category=EvidenceCategory.SOCIAL_ENGINEERING, severity=Severity.HIGH, confidence=0.5),
        make_evidence(rule_id="CREDENTIAL_REQUEST", category=EvidenceCategory.CREDENTIAL_THEFT, severity=Severity.HIGH, confidence=0.65),
    ]
    context = make_investigation_context(evidence=evidence)
    data = inspect_existing_evidence(context)
    assert data["total_count"] == 2
    assert data["by_category"]["SOCIAL_ENGINEERING"] == ["URGENCY_PRESSURE"]
    assert data["by_category"]["CREDENTIAL_THEFT"] == ["CREDENTIAL_REQUEST"]
    assert data["by_rule_id"]["URGENCY_PRESSURE"]["confidence"] == 0.5


def test_inspect_existing_evidence_empty():
    context = make_investigation_context(evidence=[])
    data = inspect_existing_evidence(context)
    assert data["total_count"] == 0
    assert data["by_category"] == {}
    assert data["by_rule_id"] == {}
