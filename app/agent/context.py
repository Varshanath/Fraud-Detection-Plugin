from app.agent.enums import ContextDepth
from app.agent.models import InvestigationContext
from app.detection.evidence import DetectionEvidence
from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.escalation_decision import EscalationDecision
from app.ingestion.schemas import SecurityEventResponse
from app.risk_scoring.risk_assessment import RiskAssessment


def build_investigation_context(
    event: SecurityEventResponse,
    evidence: list[DetectionEvidence],
    risk_assessment: RiskAssessment,
    escalation_decision: EscalationDecision,
    detection_coverage: DetectionCoverage,
    context_depth: ContextDepth = ContextDepth.TARGETED_CONTEXT,
) -> InvestigationContext:
    return InvestigationContext(
        event=event,
        evidence=evidence,
        risk_assessment=risk_assessment,
        escalation_decision=escalation_decision,
        detection_coverage=detection_coverage,
        context_depth=context_depth,
    )
