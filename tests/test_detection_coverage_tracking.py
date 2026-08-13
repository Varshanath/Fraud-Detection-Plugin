from app.detection.coverage import DetectorOutcome
from app.detection.engine import DetectionEngine
from tests.detection_fixtures import build_event, phishing_credential_request
from tests.risk_fixtures import make_evidence


class _FakeDetectorResult:
    def __init__(self, evidence):
        self.evidence = evidence


class _FakeDetector:
    def __init__(self, evidence):
        self._evidence = evidence

    def evaluate(self, event):
        return _FakeDetectorResult(self._evidence)


class _FakeRaisingDetector:
    def evaluate(self, event):
        raise RuntimeError("boom")


def test_all_default_detectors_succeed_reports_full_coverage():
    engine = DetectionEngine()
    result = engine.evaluate(phishing_credential_request())
    assert len(result.detector_statuses) == 3
    assert all(s.outcome == DetectorOutcome.SUCCEEDED for s in result.detector_statuses)
    names = {s.detector_name for s in result.detector_statuses}
    assert names == {"RuleEngine", "SenderAnalyzer", "URLAnalyzer"}


def test_one_detector_failure_is_recorded_not_silently_swallowed():
    engine = DetectionEngine(detectors=[_FakeRaisingDetector(), _FakeDetector([])])
    result = engine.evaluate(build_event())
    outcomes = {s.detector_name: s.outcome for s in result.detector_statuses}
    assert outcomes["_FakeRaisingDetector"] == DetectorOutcome.FAILED
    assert outcomes["_FakeDetector"] == DetectorOutcome.SUCCEEDED


def test_multiple_detector_failures_all_recorded():
    engine = DetectionEngine(
        detectors=[_FakeRaisingDetector(), _FakeRaisingDetector(), _FakeDetector([])]
    )
    result = engine.evaluate(build_event())
    assert len(result.detector_statuses) == 3
    failed = [s for s in result.detector_statuses if s.outcome == DetectorOutcome.FAILED]
    assert len(failed) == 2


def test_all_detectors_failing_still_returns_a_result():
    engine = DetectionEngine(detectors=[_FakeRaisingDetector(), _FakeRaisingDetector()])
    result = engine.evaluate(build_event())
    assert result.evidence == []
    assert len(result.detector_statuses) == 2
    assert all(s.outcome == DetectorOutcome.FAILED for s in result.detector_statuses)


def test_evidence_from_succeeding_detector_preserved_despite_other_failure():
    survivor_evidence = [make_evidence(rule_id="SURVIVOR")]
    engine = DetectionEngine(detectors=[_FakeRaisingDetector(), _FakeDetector(survivor_evidence)])
    result = engine.evaluate(build_event())
    assert result.evidence == survivor_evidence
    assert result.detector_statuses[0].outcome == DetectorOutcome.FAILED
    assert result.detector_statuses[1].outcome == DetectorOutcome.SUCCEEDED
