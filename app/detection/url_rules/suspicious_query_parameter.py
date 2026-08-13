from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import find_suspicious_query_params, parse_url
from app.ingestion.schemas import SecurityEventResponse


class SuspiciousQueryParameterRule:
    rule_id = "SUSPICIOUS_QUERY_PARAMETER"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = (
        "URL query parameter value looks like it points to another destination "
        "(open-redirect style pattern)."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None:
                continue
            for finding in find_suspicious_query_params(parsed.query):
                flagged.append({"url": url, **finding})

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.5, cap=0.85)
        severity = Severity.HIGH if len(flagged) >= 2 else Severity.MEDIUM

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            description=self.description,
            details={"findings": flagged},
        )
