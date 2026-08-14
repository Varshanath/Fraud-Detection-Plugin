from enum import Enum


class InvestigationStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class Uncertainty(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ContextDepth(str, Enum):
    """Token-optimization hook for a future prompt-based reasoner. Not used
    by FakeAgentReasoner (which reasons over structured tool output, not a
    rendered prompt), but named here so context-building has a place to grow
    into once a real LLM reasoner exists.
    """

    FULL_CONTEXT = "FULL_CONTEXT"
    REDUCED_CONTEXT = "REDUCED_CONTEXT"
    TARGETED_CONTEXT = "TARGETED_CONTEXT"
