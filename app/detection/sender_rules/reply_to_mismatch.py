from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.ingestion.schemas import SecurityEventResponse


class SenderReplyToMismatchRule:
    rule_id = "SENDER_REPLY_TO_MISMATCH"
    category = EvidenceCategory.SENDER_SPOOFING
    description = "Reply-To address domain differs from the sender's domain."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        if not event.sender_email or not event.reply_to:
            return None

        sender_domain = event.sender_email.split("@")[-1].lower()
        reply_to_domain = event.reply_to.split("@")[-1].lower()

        if sender_domain == reply_to_domain:
            return None

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=0.4,
            description=self.description,
            details={"sender_domain": sender_domain, "reply_to_domain": reply_to_domain},
        )
