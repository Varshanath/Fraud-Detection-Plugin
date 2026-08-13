from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.sender_analyzer import SenderAnalyzer
from tests.detection_fixtures import build_event


class _AlwaysRaisesRule:
    rule_id = "ALWAYS_RAISES"
    category = EvidenceCategory.SENDER_SPOOFING
    description = "test"

    def evaluate(self, event):
        raise RuntimeError("boom")


class _AlwaysFiresRule:
    rule_id = "ALWAYS_FIRES"
    category = EvidenceCategory.SENDER_SPOOFING
    description = "test"

    def evaluate(self, event):
        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.LOW,
            confidence=0.5,
            description=self.description,
        )


def test_default_construction_runs_all_four_rules():
    analyzer = SenderAnalyzer()
    event = build_event(
        sender_display_name="PayPal Security",
        sender_email="security@paypa1.com",
        sender_domain="paypa1.com",
        reply_to="reply@attacker.example",
    )
    result = analyzer.evaluate(event)
    rule_ids = {e.rule_id for e in result.evidence}
    assert "DISPLAY_NAME_DOMAIN_MISMATCH" in rule_ids
    assert "LOOKALIKE_DOMAIN" in rule_ids
    assert "SENDER_REPLY_TO_MISMATCH" in rule_ids


def test_legitimate_sender_produces_no_evidence():
    analyzer = SenderAnalyzer()
    event = build_event(
        sender_display_name="PayPal",
        sender_email="service@paypal.com",
        sender_domain="paypal.com",
    )
    result = analyzer.evaluate(event)
    assert result.evidence == []


def test_rule_isolation_within_analyzer():
    analyzer = SenderAnalyzer(rules=[_AlwaysRaisesRule(), _AlwaysFiresRule()])
    result = analyzer.evaluate(build_event())
    assert "ALWAYS_RAISES" in result.failed_rule_ids
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "ALWAYS_FIRES"


def test_result_has_evidence_attribute_for_detection_engine_protocol():
    analyzer = SenderAnalyzer()
    result = analyzer.evaluate(build_event())
    assert hasattr(result, "evidence")
