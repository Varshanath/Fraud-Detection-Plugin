from app.detection.engine import DetectionEngine
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from tests.detection_fixtures import (
    build_event,
    display_name_impersonation,
    lookalike_sender_domain,
    reply_to_mismatch,
)


class _RaisingDetector:
    def evaluate(self, event):
        raise RuntimeError("boom")


class _EvidenceDetectorResult:
    def __init__(self, evidence):
        self.evidence = evidence


class _StubDetector:
    def __init__(self, evidence):
        self._evidence = evidence

    def evaluate(self, event):
        return _EvidenceDetectorResult(self._evidence)


def test_default_engine_runs_rule_engine_sender_and_url_analyzers():
    engine = DetectionEngine()
    event = build_event(
        content="Act immediately and enter your password.",
        sender_display_name="PayPal Security",
        sender_email="security@paypa1.com",
        sender_domain="paypa1.com",
        urls=["http://192.168.1.10/login"],
    )
    result = engine.evaluate(event)
    rule_ids = {e.rule_id for e in result.evidence}
    # RuleEngine (content rules)
    assert "URGENCY_PRESSURE" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    # SenderAnalyzer
    assert "DISPLAY_NAME_DOMAIN_MISMATCH" in rule_ids
    assert "LOOKALIKE_DOMAIN" in rule_ids
    # URLAnalyzer
    assert "IP_ADDRESS_URL" in rule_ids


def test_top_level_detector_failure_isolation():
    engine = DetectionEngine(
        detectors=[
            _RaisingDetector(),
            _StubDetector(
                [
                    DetectionEvidence(
                        rule_id="SURVIVOR",
                        category=EvidenceCategory.SENDER_SPOOFING,
                        severity=Severity.LOW,
                        confidence=0.5,
                        description="test",
                    )
                ]
            ),
        ]
    )
    result = engine.evaluate(build_event())
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "SURVIVOR"


def test_exception_details_never_leak_into_result():
    engine = DetectionEngine(detectors=[_RaisingDetector()])
    result = engine.evaluate(build_event())
    assert result.evidence == []
    # Nothing in the result should ever contain raw exception text.
    assert "boom" not in str(result.model_dump())


def test_no_risk_score_or_classification_fields_on_result():
    engine = DetectionEngine()
    result = engine.evaluate(display_name_impersonation())
    dumped = result.model_dump()
    for forbidden_key in ("risk_score", "overall_confidence", "classification", "recommended_action"):
        assert forbidden_key not in dumped


def test_reply_to_mismatch_fixture_via_full_engine():
    engine = DetectionEngine()
    result = engine.evaluate(reply_to_mismatch())
    rule_ids = {e.rule_id for e in result.evidence}
    assert "SENDER_REPLY_TO_MISMATCH" in rule_ids


def test_lookalike_sender_domain_fixture_via_full_engine():
    engine = DetectionEngine()
    result = engine.evaluate(lookalike_sender_domain())
    rule_ids = {e.rule_id for e in result.evidence}
    assert "LOOKALIKE_DOMAIN" in rule_ids
