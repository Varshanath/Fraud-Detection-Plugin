from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import is_obfuscated
from app.ingestion.schemas import SecurityEventResponse


class ObfuscatedUrlRule:
    rule_id = "OBFUSCATED_URL"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL contains an unusually high level of percent-encoding."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            if is_obfuscated(url):
                flagged.append({"url": url})

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.4, cap=0.75)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged},
        )
