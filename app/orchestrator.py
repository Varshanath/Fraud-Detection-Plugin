from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.agent.context import build_investigation_context
from app.agent.engine import AgentInvestigationEngine
from app.agent.models import InvestigationResult
from app.detection.engine import DetectionEngine
from app.detection.evidence import DetectionEvidence
from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.enums import EscalationState
from app.escalation.escalation_decision import EscalationDecision
from app.escalation.escalation_policy import EscalationPolicy, default_escalation_policy
from app.ingestion.schemas import SecurityEventResponse
from app.risk_scoring.risk_assessment import RiskAssessment
from app.risk_scoring.risk_engine import RiskEngine


class AnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    detection_coverage: DetectionCoverage
    escalation: EscalationDecision
    investigation: InvestigationResult | None = None
    final_risk_assessment: RiskAssessment | None = None


class AnalysisOrchestrator:
    """Executes detection, calculates risk, evaluates detection coverage,
    evaluates the escalation policy, and -- only when escalation is
    required -- runs a bounded agent investigation and a final risk
    reassessment. Composes DetectionEngine, RiskEngine, EscalationPolicy,
    and AgentInvestigationEngine without merging their logic.

    Runs each detector exactly once via DetectionEngine, and the agent
    investigation at most once. No retry loop, no recursive orchestrator
    invocation, no second escalation pass after reassessment, no try/except
    here: each stage already isolates its own internal failures
    (DetectionEngine isolates per-detector failures; RiskEngine/
    EscalationPolicy are pure functions of already-computed inputs;
    AgentInvestigationEngine never raises), so a failure at this level is a
    real bug that should propagate.
    """

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        risk_engine: RiskEngine | None = None,
        escalation_policy: EscalationPolicy | None = None,
        agent_engine: AgentInvestigationEngine | None = None,
    ) -> None:
        self.detection_engine = detection_engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.escalation_policy = escalation_policy or default_escalation_policy()
        self.agent_engine = agent_engine or AgentInvestigationEngine()

    def evaluate(self, event: SecurityEventResponse) -> AnalysisResult:
        detection_result = self.detection_engine.evaluate(event)
        coverage = DetectionCoverage(detector_statuses=detection_result.detector_statuses)
        risk_assessment = self.risk_engine.evaluate(detection_result.evidence)
        escalation = self.escalation_policy.evaluate(
            risk_assessment, detection_result.evidence, coverage
        )

        investigation: InvestigationResult | None = None
        final_risk_assessment: RiskAssessment | None = None
        if escalation.state == EscalationState.ESCALATE:
            context = build_investigation_context(
                event=event,
                evidence=detection_result.evidence,
                risk_assessment=risk_assessment,
                escalation_decision=escalation,
                detection_coverage=coverage,
            )
            investigation = self.agent_engine.investigate(context)
            if investigation.recommended_reassessment:
                combined_evidence = list(detection_result.evidence) + list(
                    investigation.additional_evidence
                )
                final_risk_assessment = self.risk_engine.evaluate(combined_evidence)

        return AnalysisResult(
            event_id=detection_result.event_id,
            evidence=detection_result.evidence,
            risk_assessment=risk_assessment,
            detection_coverage=coverage,
            escalation=escalation,
            investigation=investigation,
            final_risk_assessment=final_risk_assessment,
        )
