from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.url_analyzer import URLAnalyzer
from tests.detection_fixtures import build_event


class _AlwaysRaisesRule:
    rule_id = "ALWAYS_RAISES"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "test"

    def evaluate(self, event):
        raise RuntimeError("boom")


class _AlwaysFiresRule:
    rule_id = "ALWAYS_FIRES"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "test"

    def evaluate(self, event):
        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.LOW,
            confidence=0.5,
            description=self.description,
        )


def test_default_construction_runs_all_eight_rules():
    analyzer = URLAnalyzer()
    event = build_event(
        urls=[
            "http://192.168.1.10/login",
            "https://paypa1.com/verify",
            "https://example.com/go?redirect=https://evil.example",
        ]
    )
    result = analyzer.evaluate(event)
    rule_ids = {e.rule_id for e in result.evidence}
    assert "IP_ADDRESS_URL" in rule_ids
    assert "INSECURE_HTTP_URL" in rule_ids
    assert "LOOKALIKE_URL_DOMAIN" in rule_ids
    assert "SUSPICIOUS_QUERY_PARAMETER" in rule_ids


def test_benign_urls_produce_no_evidence():
    analyzer = URLAnalyzer()
    event = build_event(
        urls=["https://paypal.com/login", "https://microsoft.com/account", "https://amazon.com/orders"]
    )
    result = analyzer.evaluate(event)
    assert result.evidence == []


def test_empty_url_list_produces_no_evidence():
    analyzer = URLAnalyzer()
    result = analyzer.evaluate(build_event(urls=[]))
    assert result.evidence == []


def test_rule_isolation_within_analyzer():
    analyzer = URLAnalyzer(rules=[_AlwaysRaisesRule(), _AlwaysFiresRule()])
    result = analyzer.evaluate(build_event(urls=["https://example.com/"]))
    assert "ALWAYS_RAISES" in result.failed_rule_ids
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "ALWAYS_FIRES"
