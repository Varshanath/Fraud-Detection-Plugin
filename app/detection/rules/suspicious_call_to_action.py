from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import find_matches, scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

_PHRASES = [
    "click here",
    "verify now",
    "confirm account",
    "confirm your account",
    "update payment",
    "update your payment",
    "unlock account",
    "unlock your account",
    "download now",
    "open attachment",
    "open the attachment",
    "click the link below",
    "click below",
    "verify your account now",
]


class SuspiciousCallToActionRule(BaseRule):
    rule_id = "SUSPICIOUS_CALL_TO_ACTION"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = "Message contains generic imperative call-to-action language."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        matches = find_matches(text, _PHRASES)
        if not matches:
            return None

        severity = Severity.HIGH if len(matches) >= 3 else Severity.MEDIUM
        confidence = scored_confidence(len(matches), base=0.3, cap=0.85)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            description=self.description,
            details={"matched_phrases": matches},
        )
