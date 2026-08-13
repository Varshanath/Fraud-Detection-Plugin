from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.url_parsing import is_excessive_length
from app.ingestion.schemas import SecurityEventResponse

_DEFAULT_THRESHOLD = 200


class ExcessiveUrlLengthRule:
    rule_id = "EXCESSIVE_URL_LENGTH"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL length exceeds the configured threshold."

    def __init__(self, threshold: int = _DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            if is_excessive_length(url, self.threshold):
                flagged.append({"url": url, "length": len(url)})

        if not flagged:
            return None

        longest = max(item["length"] for item in flagged)
        overflow_ratio = (longest - self.threshold) / self.threshold
        confidence = min(0.3 + overflow_ratio * 0.3, 0.7)
        severity = Severity.MEDIUM if overflow_ratio > 0.5 else Severity.LOW

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged, "threshold": self.threshold},
        )
