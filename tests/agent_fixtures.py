from app.agent.context import build_investigation_context
from app.agent.models import InvestigationContext
from app.detection.evidence import DetectionEvidence
from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.enums import EscalationPriority, EscalationReason, EscalationState, NextStage
from app.escalation.escalation_decision import EscalationDecision
from app.ingestion.schemas import SecurityEventResponse
from tests.detection_fixtures import build_event
from tests.escalation_fixtures import complete_coverage, make_risk_assessment


def make_escalation_decision(
    reason: EscalationReason | None = EscalationReason.LOW_CONFIDENCE,
    risk_score: int = 25,
    confidence: float = 0.35,
    priority: EscalationPriority | None = EscalationPriority.LOW,
) -> EscalationDecision:
    if reason is None:
        return EscalationDecision(
            state=EscalationState.NO_ESCALATION,
            requires_escalation=False,
            reason=None,
            contributing_reasons=[],
            priority=None,
            recommended_next_stage=NextStage.NONE,
            current_risk_score=risk_score,
            current_confidence=confidence,
            explanation="test: no escalation",
        )
    return EscalationDecision(
        state=EscalationState.ESCALATE,
        requires_escalation=True,
        reason=reason,
        contributing_reasons=[reason],
        priority=priority,
        recommended_next_stage=NextStage.DEEP_ANALYSIS,
        current_risk_score=risk_score,
        current_confidence=confidence,
        explanation="test: escalation",
    )


def make_investigation_context(
    event: SecurityEventResponse | None = None,
    evidence: list[DetectionEvidence] | None = None,
    escalation_decision: EscalationDecision | None = None,
    coverage: DetectionCoverage | None = None,
    risk_score: int = 25,
    confidence: float = 0.35,
) -> InvestigationContext:
    event = event or build_event()
    evidence = evidence if evidence is not None else []
    coverage = coverage or complete_coverage()
    escalation_decision = escalation_decision or make_escalation_decision(
        risk_score=risk_score, confidence=confidence
    )
    risk_assessment = make_risk_assessment(risk_score=risk_score, confidence=confidence)
    return build_investigation_context(
        event=event,
        evidence=evidence,
        risk_assessment=risk_assessment,
        escalation_decision=escalation_decision,
        detection_coverage=coverage,
    )
