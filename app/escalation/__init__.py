"""Escalation decision layer: RiskAssessment + DetectionCoverage -> EscalationDecision.

Decides whether current evidence is sufficient to make a decision, or
whether the event should be routed toward a future, more expensive
investigation stage. No such expensive stage (agent/LLM/ML/external
intelligence) exists yet -- this package only produces the routing
decision.
"""
