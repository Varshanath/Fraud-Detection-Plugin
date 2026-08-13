from enum import Enum


class EscalationState(str, Enum):
    NO_ESCALATION = "NO_ESCALATION"
    ESCALATE = "ESCALATE"


class EscalationReason(str, Enum):
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    AMBIGUOUS_SIGNAL = "AMBIGUOUS_SIGNAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    HIGH_RISK_LOW_CONFIDENCE = "HIGH_RISK_LOW_CONFIDENCE"
    INSUFFICIENT_DETECTOR_COVERAGE = "INSUFFICIENT_DETECTOR_COVERAGE"
    # No logic currently produces this reason. It exists only as the
    # abstraction a future novelty/anomaly detector would plug into --
    # implementing novelty detection itself is out of scope for this phase.
    NOVEL_SIGNAL = "NOVEL_SIGNAL"


class EscalationPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class NextStage(str, Enum):
    """Routing abstraction for a future expensive-intelligence layer.

    Only NONE and DEEP_ANALYSIS are ever produced today. EXTERNAL_INTELLIGENCE
    and AGENT_INVESTIGATION are defined so a future phase can route into them
    without changing this enum, but no logic here selects between them yet.
    """

    NONE = "NONE"
    DEEP_ANALYSIS = "DEEP_ANALYSIS"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    AGENT_INVESTIGATION = "AGENT_INVESTIGATION"
