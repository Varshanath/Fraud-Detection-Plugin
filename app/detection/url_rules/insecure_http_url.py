from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import is_insecure_http, parse_url
from app.ingestion.schemas import SecurityEventResponse


class InsecureHttpUrlRule:
    rule_id = "INSECURE_HTTP_URL"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL uses HTTP instead of HTTPS. This is only a signal, not a classification."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None:
                continue
            if is_insecure_http(parsed.scheme):
                flagged.append({"url": url})

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.25, cap=0.5)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.LOW,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged},
        )
