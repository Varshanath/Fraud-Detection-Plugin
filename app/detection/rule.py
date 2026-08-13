from typing import Protocol, runtime_checkable

from app.detection.enums import EvidenceCategory
from app.detection.evidence import DetectionEvidence
from app.ingestion.schemas import SecurityEventResponse


@runtime_checkable
class Rule(Protocol):
    rule_id: str
    category: EvidenceCategory
    description: str

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None: ...


class BaseRule:
    """Optional convenience base for concrete rules. Not required by `Rule`."""

    rule_id: str
    category: EvidenceCategory
    description: str

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        raise NotImplementedError

    @staticmethod
    def _searchable_text(event: SecurityEventResponse) -> str:
        return "\n".join(part for part in (event.subject, event.content) if part)
