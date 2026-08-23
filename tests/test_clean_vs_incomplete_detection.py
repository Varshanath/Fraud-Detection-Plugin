"""Regression tests for the CLEAN vs INCOMPLETE detection-coverage
architecture (see EscalationPolicy.evaluate and the README section of the
same name).

Architectural rule under test:
    NO EVIDENCE != LOW CONFIDENCE
    DETECTOR FAILURE != CLEAN

Zero evidence collected while every relevant detector ran successfully is a
genuine "looked and found nothing" result (CLEAN) and must not, on its own,
trigger an agent investigation. Zero evidence while one or more detectors
failed means detection coverage is incomplete, which is a different, valid
reason to escalate. These tests exercise the full production pipeline via
AnalysisOrchestrator (real DetectionEngine/RiskEngine/EscalationPolicy, and
the default FakeAgentReasoner-backed AgentInvestigationEngine) end-to-end,
rather than EscalationPolicy in isolation (see tests/test_escalation_policy.py
for the policy-level unit tests of the same rule).
"""

from app.detection.engine import DetectionEngine
from app.detection.registry import build_default_rule_engine
from app.escalation.enums import EscalationReason, EscalationState
from app.orchestrator import AnalysisOrchestrator
from tests.detection_fixtures import (
    build_event,
    completely_benign_message,
    legitimate_otp_notification,
    legitimate_payment_notification,
    phishing_credential_request,
)


class _RaisingDetector:
    """Stand-in for a detector that fails during evaluation."""

    def evaluate(self, event):
        raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# 1-3: genuinely clean events -- all detectors succeed, zero evidence
# ---------------------------------------------------------------------------


def test_completely_benign_event_is_clean_and_agent_not_invoked():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(completely_benign_message())

    assert result.evidence == []
    assert result.detection_coverage.is_complete is True
    assert result.escalation.state == EscalationState.NO_ESCALATION
    assert result.escalation.reason is None
    assert result.investigation is None


def test_otp_informational_message_is_clean_and_agent_not_invoked():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(legitimate_otp_notification())

    assert result.evidence == []
    assert result.detection_coverage.is_complete is True
    assert result.escalation.state == EscalationState.NO_ESCALATION
    assert result.investigation is None


def test_successful_payment_message_is_clean_and_agent_not_invoked():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(legitimate_payment_notification())

    assert result.evidence == []
    assert result.detection_coverage.is_complete is True
    assert result.escalation.state == EscalationState.NO_ESCALATION
    assert result.investigation is None


# ---------------------------------------------------------------------------
# 4-5: zero evidence + incomplete coverage must NOT be treated as clean
# ---------------------------------------------------------------------------


def test_detector_failure_with_zero_evidence_escalates_via_coverage_policy():
    engine = DetectionEngine(detectors=[_RaisingDetector()])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    result = orchestrator.evaluate(build_event())

    assert result.evidence == []
    assert result.detection_coverage.detectors_failed == 1
    assert result.detection_coverage.is_complete is False
    assert result.escalation.state == EscalationState.ESCALATE
    assert result.escalation.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE
    # The existing coverage policy MAY invoke the agent for an incomplete
    # picture -- unlike the clean case, this is not suppressed.
    assert result.investigation is not None


def test_detector_failure_with_benign_content_is_not_treated_as_clean():
    # Same benign wording as the completely-clean test above, but one
    # detector fails this time -- the outcome must differ (ESCALATE, not
    # NO_ESCALATION), proving the pipeline does not conflate "zero evidence"
    # with "clean" when coverage is incomplete.
    engine = DetectionEngine(detectors=[_RaisingDetector(), build_default_rule_engine()])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    result = orchestrator.evaluate(
        build_event(content="Hi team, just confirming our meeting tomorrow at 10 AM.")
    )

    assert result.evidence == []
    assert result.detection_coverage.is_complete is False
    assert result.escalation.state == EscalationState.ESCALATE
    assert result.escalation.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE


# ---------------------------------------------------------------------------
# 6-7: existing risk/confidence-driven escalation behavior is unchanged
# ---------------------------------------------------------------------------


def test_high_risk_high_confidence_still_does_not_escalate():
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(phishing_credential_request())

    assert result.risk_assessment.risk_score >= 70
    assert result.risk_assessment.confidence >= 0.6
    assert result.escalation.state == EscalationState.NO_ESCALATION
    assert result.investigation is None


def test_low_confidence_event_with_real_evidence_still_escalates():
    # Evidence IS present here (unlike the clean-event tests above), so the
    # CLEAN short-circuit must not apply -- ordinary low-confidence
    # escalation behavior must still fire exactly as before this change.
    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(
        build_event(content="Please click here to confirm your account.")
    )

    assert len(result.evidence) > 0
    assert result.risk_assessment.confidence < 0.6
    assert result.escalation.state == EscalationState.ESCALATE
    assert result.escalation.reason == EscalationReason.LOW_CONFIDENCE
    assert result.investigation is not None


# ---------------------------------------------------------------------------
# 8: partial detector failure -- identity and coverage stay correct
# ---------------------------------------------------------------------------


def test_partial_detector_failure_preserves_failed_detector_identity():
    engine = DetectionEngine(detectors=[_RaisingDetector(), build_default_rule_engine()])
    orchestrator = AnalysisOrchestrator(detection_engine=engine)
    result = orchestrator.evaluate(build_event())

    coverage = result.detection_coverage
    assert coverage.detectors_attempted == 2
    assert coverage.detectors_succeeded == 1
    assert coverage.detectors_failed == 1
    assert coverage.is_complete is False
    assert "_RaisingDetector" in coverage.failed_detector_names
    assert "RuleEngine" not in coverage.failed_detector_names
