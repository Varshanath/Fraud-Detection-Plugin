from collections.abc import Iterable

from app.detection.rule import Rule
from app.detection.rule_engine import RuleEngine, RuleEngineResult
from app.detection.sender_rules.display_name_impersonation import DisplayNameImpersonationRule
from app.detection.sender_rules.lookalike_domain import LookalikeSenderDomainRule
from app.detection.sender_rules.reply_to_mismatch import SenderReplyToMismatchRule
from app.detection.sender_rules.suspicious_sender_domain import SuspiciousSenderDomainRule
from app.ingestion.schemas import SecurityEventResponse

DEFAULT_SENDER_RULES: list[Rule] = [
    SuspiciousSenderDomainRule(),
    SenderReplyToMismatchRule(),
    DisplayNameImpersonationRule(),
    LookalikeSenderDomainRule(),
]


class SenderAnalyzer:
    """Deterministic, offline sender intelligence. Reuses RuleEngine
    internally for evidence aggregation and failure isolation rather than
    reimplementing that logic -- this already satisfies DetectionEngine's
    Detector protocol (`.evaluate(event) -> <has .evidence>`) for free.
    """

    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self._engine = RuleEngine(rules=rules if rules is not None else DEFAULT_SENDER_RULES)

    def evaluate(self, event: SecurityEventResponse) -> RuleEngineResult:
        return self._engine.evaluate(event)
