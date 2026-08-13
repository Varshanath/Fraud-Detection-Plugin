import logging
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from app.detection.evidence import DetectionEvidence
from app.detection.rule import Rule
from app.ingestion.schemas import SecurityEventResponse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleEngineResult:
    event_id: uuid.UUID
    evidence: list[DetectionEvidence]
    failed_rule_ids: list[str] = field(default_factory=list)


class RuleEngine:
    """Owns and executes rules. Never scores, never decides -- collects evidence only.

    Independent of the database: operates purely on an in-memory
    `SecurityEventResponse`, never a DB session or the SQLAlchemy model.
    """

    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules) if rules is not None else []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def evaluate(self, event: SecurityEventResponse) -> RuleEngineResult:
        evidence: list[DetectionEvidence] = []
        failed_rule_ids: list[str] = []

        for rule in self._rules:
            try:
                result = rule.evaluate(event)
            except Exception:
                logger.exception("Rule %s raised an exception during evaluation", rule.rule_id)
                failed_rule_ids.append(rule.rule_id)
                continue
            if result is not None:
                evidence.append(result)

        return RuleEngineResult(
            event_id=event.event_id, evidence=evidence, failed_rule_ids=failed_rule_ids
        )
