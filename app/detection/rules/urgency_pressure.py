from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import find_matches, scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

_PHRASES = [
    "act immediately",
    "act now",
    "urgent action required",
    "urgent action needed",
    "immediate action required",
    "respond immediately",
    "final warning",
    "final notice",
    "limited time",
    "limited time offer",
    "time-sensitive",
    "failure to respond",
    "failure to act",
    "within 24 hours",
    "within 48 hours",
    "account will be closed",
    "account will be suspended",
    "account will be terminated",
    "account will be locked",
    "will be suspended",
    "will be closed",
    "will be terminated",
    "will be locked",
]

_THREAT_PHRASES = {
    "account will be closed",
    "account will be suspended",
    "account will be terminated",
    "account will be locked",
    "will be suspended",
    "will be closed",
    "will be terminated",
    "will be locked",
}


class UrgencyPressureRule(BaseRule):
    rule_id = "URGENCY_PRESSURE"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = (
        "Message contains urgency/pressure language commonly associated with social engineering."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        matches = find_matches(text, _PHRASES)
        if not matches:
            return None

        severity = (
            Severity.HIGH if any(m in _THREAT_PHRASES for m in matches) else Severity.MEDIUM
        )
        confidence = scored_confidence(len(matches), base=0.35, cap=0.9)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            description=self.description,
            details={"matched_phrases": matches},
        )
