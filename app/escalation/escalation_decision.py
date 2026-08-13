from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.escalation.enums import EscalationPriority, EscalationReason, EscalationState, NextStage


class EscalationDecision(BaseModel):
    """Whether an event's current evidence is sufficient to make a decision,
    or whether it should be routed toward a future, more expensive
    investigation stage. Never invokes that future stage -- only decides.
    """

    model_config = ConfigDict(frozen=True)

    state: EscalationState
    requires_escalation: bool
    reason: EscalationReason | None = None
    contributing_reasons: list[EscalationReason] = Field(default_factory=list)
    priority: EscalationPriority | None = None
    recommended_next_stage: NextStage
    current_risk_score: int = Field(ge=0, le=100)
    current_confidence: float = Field(ge=0.0, le=1.0)
    explanation: str

    @model_validator(mode="after")
    def _requires_escalation_matches_state(self) -> "EscalationDecision":
        if self.requires_escalation != (self.state == EscalationState.ESCALATE):
            raise ValueError("requires_escalation must match state == ESCALATE")
        return self

    @model_validator(mode="after")
    def _reason_and_priority_only_when_escalating(self) -> "EscalationDecision":
        escalating = self.state == EscalationState.ESCALATE
        if escalating and (self.reason is None or self.priority is None):
            raise ValueError("reason and priority are required when escalating")
        if not escalating and (self.reason is not None or self.priority is not None):
            raise ValueError("reason and priority must be None when not escalating")
        return self
