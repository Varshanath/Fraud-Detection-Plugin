from pydantic import BaseModel, ConfigDict, Field

from app.detection.evidence import DetectionEvidence
from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.enums import EscalationPriority, EscalationReason, EscalationState, NextStage
from app.escalation.escalation_decision import EscalationDecision
from app.risk_scoring.enums import RiskClassification
from app.risk_scoring.risk_assessment import RiskAssessment

_EXPLANATIONS: dict[EscalationReason, str] = {
    EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE: (
        "One or more detectors failed to run; detection coverage is incomplete "
        "and the assessment may be missing signals."
    ),
    EscalationReason.INSUFFICIENT_EVIDENCE: (
        "Too little evidence is available to make a confident determination."
    ),
    EscalationReason.HIGH_RISK_LOW_CONFIDENCE: (
        "Potentially serious event with insufficient confidence; this is a "
        "high-priority escalation."
    ),
    EscalationReason.AMBIGUOUS_SIGNAL: (
        "Suspicious but insufficiently certain; the signal is ambiguous and "
        "warrants deeper investigation."
    ),
    EscalationReason.LOW_CONFIDENCE: (
        "Confidence in the current assessment is too low to make a reliable "
        "decision without further investigation."
    ),
}

_NO_ESCALATION_HIGH_RISK_EXPLANATION = (
    "Current detection is sufficiently confident despite an elevated risk "
    "score; no additional investigation is required at this time."
)
_NO_ESCALATION_EXPLANATION = (
    "Strong evidence indicates the current risk and confidence are sufficient "
    "to make a decision without further investigation."
)
_NO_ESCALATION_CLEAN_EXPLANATION = (
    "All relevant detectors ran successfully and found no suspicious signal; "
    "this event is clean and requires no further investigation."
)


class EscalationPolicy(BaseModel):
    """Centralized, configurable policy deciding whether an event's current
    evidence is sufficient to make a decision, or whether it should be
    routed toward a future, more expensive investigation stage.

    Deliberately does not re-derive evidence diversity/quality: those are
    already independently encoded in RiskAssessment.confidence (Phase 5's
    diversity-ratio and avg-evidence-confidence terms), so confidence_threshold
    transitively gates on them. This policy adds only the dimensions
    confidence does not capture: a hard floor on evidence count, and
    visibility into whether every detector actually ran.

    CLEAN vs INCOMPLETE: zero evidence means two different things depending
    on detection coverage. If every detector ran successfully and still
    found nothing, that is a genuine "looked and found nothing" result
    (CLEAN) -- not evidence of an untrustworthy assessment, and confidence's
    0.0 value in that specific case is a definitional artifact (there is
    nothing to average), not a real trust signal. NO EVIDENCE != LOW
    CONFIDENCE. If instead one or more detectors FAILED, detection coverage
    is incomplete and zero evidence means "we don't know" rather than
    "clean" -- DETECTOR FAILURE != CLEAN -- and that already escalates via
    INSUFFICIENT_DETECTOR_COVERAGE below, independently of this distinction.
    """

    model_config = ConfigDict(frozen=True)

    confidence_threshold: float = Field(ge=0.0, le=1.0)
    high_risk_score_threshold: int = Field(ge=0, le=100)
    medium_priority_score_threshold: int = Field(ge=0, le=100)
    min_evidence_count: int = Field(ge=0)

    def evaluate(
        self,
        risk_assessment: RiskAssessment,
        evidence: list[DetectionEvidence],
        coverage: DetectionCoverage,
    ) -> EscalationDecision:
        risk_score = risk_assessment.risk_score
        confidence = risk_assessment.confidence
        is_low_confidence = confidence < self.confidence_threshold
        is_high_risk = risk_score >= self.high_risk_score_threshold

        # CLEAN / NO_SIGNAL: every detector ran and none of them found
        # anything. Confidence is 0.0 here only because ConfidenceCalculator
        # has no evidence to average, not because the event is untrusted --
        # so neither the evidence-count floor nor the confidence threshold
        # applies to this specific case. If coverage is incomplete instead
        # (a detector failed), this stays False and INSUFFICIENT_DETECTOR_
        # COVERAGE below escalates regardless, exactly as before.
        clean_no_signal = len(evidence) == 0 and coverage.is_complete

        reasons: list[EscalationReason] = []

        if coverage.detectors_failed > 0:
            reasons.append(EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE)

        if not clean_no_signal:
            if len(evidence) < self.min_evidence_count:
                reasons.append(EscalationReason.INSUFFICIENT_EVIDENCE)

            if is_high_risk and is_low_confidence:
                reasons.append(EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
            elif is_low_confidence and risk_assessment.classification == RiskClassification.SUSPICIOUS:
                reasons.append(EscalationReason.AMBIGUOUS_SIGNAL)
            elif is_low_confidence:
                reasons.append(EscalationReason.LOW_CONFIDENCE)

        if not reasons:
            if clean_no_signal:
                explanation = _NO_ESCALATION_CLEAN_EXPLANATION
            elif is_high_risk:
                explanation = _NO_ESCALATION_HIGH_RISK_EXPLANATION
            else:
                explanation = _NO_ESCALATION_EXPLANATION
            return EscalationDecision(
                state=EscalationState.NO_ESCALATION,
                requires_escalation=False,
                reason=None,
                contributing_reasons=[],
                priority=None,
                recommended_next_stage=NextStage.NONE,
                current_risk_score=risk_score,
                current_confidence=confidence,
                explanation=explanation,
            )

        primary_reason = reasons[0]
        priority = self._priority_for(risk_score)
        return EscalationDecision(
            state=EscalationState.ESCALATE,
            requires_escalation=True,
            reason=primary_reason,
            contributing_reasons=reasons,
            priority=priority,
            recommended_next_stage=NextStage.DEEP_ANALYSIS,
            current_risk_score=risk_score,
            current_confidence=confidence,
            explanation=_EXPLANATIONS[primary_reason],
        )

    def _priority_for(self, risk_score: int) -> EscalationPriority:
        if risk_score >= self.high_risk_score_threshold:
            return EscalationPriority.HIGH
        if risk_score >= self.medium_priority_score_threshold:
            return EscalationPriority.MEDIUM
        return EscalationPriority.LOW


DEFAULT_ESCALATION_POLICY = EscalationPolicy(
    confidence_threshold=0.6,
    high_risk_score_threshold=70,
    medium_priority_score_threshold=40,
    min_evidence_count=1,
)


def default_escalation_policy() -> EscalationPolicy:
    return DEFAULT_ESCALATION_POLICY
