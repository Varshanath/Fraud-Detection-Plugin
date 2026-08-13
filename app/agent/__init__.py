"""Agent investigation layer: invoked only when EscalationPolicy decides
ESCALATE. Investigates using controlled, deterministic, local tools over the
already-ingested SecurityEvent and produces additional DetectionEvidence.

The agent does not decide the final security action -- RiskEngine remains
authoritative for risk_score/classification/recommended_action. No real LLM,
no agent framework, no multi-agent system exists in this phase; the
reasoning boundary (AgentReasoner) is deliberately swappable and proven here
with a deterministic FakeAgentReasoner.
"""
