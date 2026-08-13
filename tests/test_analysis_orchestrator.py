from app.detection.coverage import DetectorOutcome, DetectorStatus
from app.detection.engine import DetectionEngine, DetectionResult
from app.detection.registry import build_default_rule_engine
from app.escalation.enums import EscalationReason, EscalationState
from app.orchestrator import AnalysisOrchestrator
from tests.detection_fixtures import build_event, phishing_credential_request
from tests.escalation_fixtures import make_risk_assessment
from tests.risk_fixtures import make_evidence


class _StubDetectionEngine:
    def __init__(self, result):
        self._result = result
        self.evaluate_called_with = None

    def evaluate(self, event):
        self.evaluate_called_with = event
        return self._result


class _StubRiskEngine:
    def __init__(self, assessment):
        self._assessment = assessment
        self.evaluate_called_with = None

    def evaluate(self, evidence):
        self.evaluate_called_with = evidence
        return self._assessment


class _StubEscalationPolicy:
    def __init__(self, decision):
        self._decision = decision
        self.evaluate_called_with = None

    def evaluate(self, risk_assessment, evidence, coverage):
        self.evaluate_called_with = (risk_assessment, evidence, coverage)
        return self._decision


def _no_escalation_decision():
    from app.escalation.enums import NextStage
    from app.escalation.escalation_decision import EscalationDecision

    return EscalationDecision(
        state=EscalationState.NO_ESCALATION,
        requires_escalation=False,
        recommended_next_stage=NextStage.NONE,
        current_risk_score=0,
        current_confidence=0.0,
        explanation="stub",
    )


def test_orchestrator_composes_three_stages_without_merging_logic():
    event = build_event()
    fake_evidence = [make_evidence(rule_id="FAKE")]
    detection_result = DetectionResult(
        event_id=event.event_id,
        evidence=fake_evidence,
        detector_statuses=[DetectorStatus(detector_name="Fake", outcome=DetectorOutcome.SUCCEEDED)],
    )
    fake_assessment = make_risk_assessment(risk_score=42, confidence=0.5)
    fake_decision = _no_escalation_decision()

    stub_detection = _StubDetectionEngine(detection_result)
    stub_risk = _StubRiskEngine(fake_assessment)
    stub_escalation = _StubEscalationPolicy(fake_decision)

    orchestrator = AnalysisOrchestrator(
        detection_engine=stub_detection, risk_engine=stub_risk, escalation_policy=stub_escalation
    )
    result = orchestrator.evaluate(event)

    assert stub_detection.evaluate_called_with is event
    assert stub_risk.evaluate_called_with == fake_evidence
    risk_arg, evidence_arg, coverage_arg = stub_escalation.evaluate_called_with
    assert risk_arg == fake_assessment
    assert evidence_arg == fake_evidence
    assert coverage_arg.detector_statuses == detection_result.detector_statuses

    assert result.event_id == event.event_id
    assert result.evidence == fake_evidence
    assert result.risk_assessment == fake_assessment
    assert result.escalation == fake_decision
    assert result.detection_coverage.detectors_attempted == 1


def test_orchestrator_end_to_end_with_real_components():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(phishing_credential_request())
    assert len(result.evidence) > 0
    assert result.risk_assessment.risk_score > 0
    assert result.detection_coverage.detectors_attempted == 3
    assert result.detection_coverage.is_complete is True
    assert result.escalation.current_risk_score == result.risk_assessment.risk_score
    assert result.escalation.current_confidence == result.risk_assessment.confidence


def test_default_construction_needs_no_arguments():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(build_event(content="Hello there"))
    assert result.risk_assessment.risk_score == 0


def test_determinism_same_event_produces_identical_result():
    orchestrator = AnalysisOrchestrator()
    event = phishing_credential_request()
    first = orchestrator.evaluate(event)
    second = orchestrator.evaluate(event)
    assert first.model_dump() == second.model_dump()


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


class _RaisingDetector:
    def evaluate(self, event):
        raise RuntimeError("boom")


def test_one_detector_failure_does_not_crash_orchestrator_and_is_visible_in_coverage():
    engine = DetectionEngine(detectors=[_RaisingDetector(), build_default_rule_engine()])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.detection_coverage.detectors_failed == 1
    assert result.detection_coverage.is_complete is False
    assert len(result.evidence) > 0
    assert EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE in result.escalation.contributing_reasons


def test_all_detectors_failing_still_produces_a_result():
    engine = DetectionEngine(detectors=[_RaisingDetector(), _RaisingDetector()])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    result = orchestrator.evaluate(build_event())

    assert result.evidence == []
    assert result.detection_coverage.detectors_failed == 2
    assert result.risk_assessment.risk_score == 0
    assert result.escalation.state == EscalationState.ESCALATE
    assert result.escalation.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE


def test_detector_failure_does_not_artificially_inflate_confidence():
    partial_engine = DetectionEngine(detectors=[_RaisingDetector(), build_default_rule_engine()])
    full_engine = DetectionEngine(detectors=[build_default_rule_engine()])

    partial_result = AnalysisOrchestrator(detection_engine=partial_engine).evaluate(
        phishing_credential_request()
    )
    full_result = AnalysisOrchestrator(detection_engine=full_engine).evaluate(
        phishing_credential_request()
    )

    assert partial_result.risk_assessment.confidence <= full_result.risk_assessment.confidence
    assert partial_result.escalation.state == EscalationState.ESCALATE


# ---------------------------------------------------------------------------
# No retry loop
# ---------------------------------------------------------------------------


class _CountingDetectorResult:
    def __init__(self, evidence):
        self.evidence = evidence


class _CountingDetector:
    def __init__(self):
        self.call_count = 0

    def evaluate(self, event):
        self.call_count += 1
        return _CountingDetectorResult([])


def test_each_detector_is_evaluated_exactly_once():
    counting = _CountingDetector()
    engine = DetectionEngine(detectors=[counting])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    orchestrator.evaluate(build_event())
    assert counting.call_count == 1
