from app.detection.enums import EvidenceCategory, Severity
from app.detection.engine import DetectionEngine
from app.detection.evidence import DetectionEvidence
from app.detection.registry import build_default_rule_engine
from tests.detection_fixtures import build_event, phishing_credential_request


class _FakeDetectorResult:
    def __init__(self, evidence):
        self.evidence = evidence


class _FakeDetector:
    """Stands in for a future detector (SenderAnalyzer, ML detector, etc.)."""

    def __init__(self, evidence):
        self._evidence = evidence

    def evaluate(self, event):
        return _FakeDetectorResult(self._evidence)


class _FakeRaisingDetector:
    def evaluate(self, event):
        raise RuntimeError("boom")


def _evidence(rule_id: str) -> DetectionEvidence:
    return DetectionEvidence(
        rule_id=rule_id,
        category=EvidenceCategory.SOCIAL_ENGINEERING,
        severity=Severity.LOW,
        confidence=0.5,
        description="test",
    )


def test_default_construction_wraps_rule_engine():
    engine = DetectionEngine()
    event = phishing_credential_request()
    result = engine.evaluate(event)
    rule_ids = {e.rule_id for e in result.evidence}
    assert "URGENCY_PRESSURE" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids


def test_evidence_aggregated_across_detectors():
    engine = DetectionEngine(
        detectors=[
            build_default_rule_engine(),
            _FakeDetector([_evidence("FAKE_FUTURE_DETECTOR")]),
        ]
    )
    result = engine.evaluate(build_event())
    rule_ids = {e.rule_id for e in result.evidence}
    assert "FAKE_FUTURE_DETECTOR" in rule_ids


def test_future_detector_accommodated_without_engine_changes():
    # No modification to DetectionEngine's implementation was needed to plug
    # in a brand-new kind of detector -- only the constructor argument.
    fake_evidence = [_evidence("FUTURE_ML_DETECTOR")]
    engine = DetectionEngine(detectors=[_FakeDetector(fake_evidence)])
    result = engine.evaluate(build_event())
    assert result.evidence == fake_evidence


def test_detector_level_isolation():
    engine = DetectionEngine(
        detectors=[_FakeRaisingDetector(), _FakeDetector([_evidence("SURVIVOR")])]
    )
    result = engine.evaluate(build_event())
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "SURVIVOR"


def test_result_carries_event_id():
    engine = DetectionEngine()
    event = build_event()
    result = engine.evaluate(event)
    assert result.event_id == event.event_id


def test_benign_event_produces_no_evidence():
    engine = DetectionEngine()
    event = build_event(content="Hey, are we still meeting for lunch tomorrow?")
    result = engine.evaluate(event)
    assert result.evidence == []
