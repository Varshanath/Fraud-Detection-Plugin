from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.pipeline import DetectionPipeline
from app.risk_scoring.risk_assessment import RiskAssessment
from tests.detection_fixtures import build_event, phishing_credential_request


class _StubDetectionResult:
    def __init__(self, event_id, evidence):
        self.event_id = event_id
        self.evidence = evidence


class _StubDetectionEngine:
    def __init__(self, evidence):
        self._evidence = evidence
        self.evaluate_called_with = None

    def evaluate(self, event):
        self.evaluate_called_with = event
        return _StubDetectionResult(event.event_id, self._evidence)


class _StubRiskEngine:
    def __init__(self, assessment):
        self._assessment = assessment
        self.evaluate_called_with = None

    def evaluate(self, evidence):
        self.evaluate_called_with = evidence
        return self._assessment


def _stub_assessment() -> RiskAssessment:
    from app.risk_scoring.enums import RecommendedAction, RiskClassification

    return RiskAssessment(
        risk_score=42,
        confidence=0.5,
        classification=RiskClassification.SUSPICIOUS,
        recommended_action=RecommendedAction.WARN,
        scoring_breakdown=[],
        raw_score_before_cap=42.0,
    )


def test_pipeline_composes_detection_and_risk_engines_without_merging_logic():
    fake_evidence = [
        DetectionEvidence(
            rule_id="FAKE",
            category=EvidenceCategory.SOCIAL_ENGINEERING,
            severity=Severity.LOW,
            confidence=0.5,
            description="test",
        )
    ]
    stub_detection = _StubDetectionEngine(fake_evidence)
    stub_risk = _StubRiskEngine(_stub_assessment())

    pipeline = DetectionPipeline(detection_engine=stub_detection, risk_engine=stub_risk)
    event = build_event()
    result = pipeline.evaluate(event)

    assert stub_detection.evaluate_called_with is event
    assert stub_risk.evaluate_called_with == fake_evidence
    assert result.event_id == event.event_id
    assert result.evidence == fake_evidence
    assert result.risk_assessment.risk_score == 42


def test_pipeline_end_to_end_with_real_engines():
    pipeline = DetectionPipeline()
    result = pipeline.evaluate(phishing_credential_request())
    assert len(result.evidence) > 0
    assert result.risk_assessment.risk_score > 0
    assert result.risk_assessment.classification is not None


def test_pipeline_default_construction_needs_no_arguments():
    pipeline = DetectionPipeline()
    result = pipeline.evaluate(build_event(content="Hello there"))
    assert result.risk_assessment.risk_score == 0
