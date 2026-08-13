from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.agent.enums import ContextDepth, InvestigationStatus, Uncertainty
from app.detection.evidence import DetectionEvidence
from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.escalation_decision import EscalationDecision
from app.ingestion.schemas import SecurityEventResponse
from app.risk_scoring.risk_assessment import RiskAssessment


class InvestigationContext(BaseModel):
    """Everything an investigation needs, reusing existing models directly
    rather than duplicating them. Tools operate on `event`/`evidence`
    in-memory only -- no database or application-internals access.
    """

    model_config = ConfigDict(frozen=True)

    event: SecurityEventResponse
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    escalation_decision: EscalationDecision
    detection_coverage: DetectionCoverage
    context_depth: ContextDepth = ContextDepth.TARGETED_CONTEXT


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_name: str
    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class AgentReasoningResult(BaseModel):
    """Raw output of an AgentReasoner -- the LLM boundary's contract."""

    model_config = ConfigDict(frozen=True)

    summary: str
    findings: list[str] = Field(default_factory=list)
    additional_evidence: list[DetectionEvidence] = Field(default_factory=list)
    uncertainty: Uncertainty
    recommended_reassessment: bool


class InvestigationResult(BaseModel):
    """Engine-level investigation output. Adds `status`, which depends on
    budget/tool-failure outcomes the reasoner itself never sees.
    """

    model_config = ConfigDict(frozen=True)

    status: InvestigationStatus
    summary: str
    findings: list[str] = Field(default_factory=list)
    additional_evidence: list[DetectionEvidence] = Field(default_factory=list)
    uncertainty: Uncertainty
    recommended_reassessment: bool
