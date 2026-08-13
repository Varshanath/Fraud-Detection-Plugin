from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import has_excessive_subdomains, parse_url, subdomain_label_count
from app.ingestion.schemas import SecurityEventResponse

_DEFAULT_THRESHOLD = 3


class ExcessiveSubdomainsRule:
    rule_id = "EXCESSIVE_SUBDOMAINS"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL hostname has an unusually high number of subdomain labels."

    def __init__(self, threshold: int = _DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None:
                continue
            if has_excessive_subdomains(parsed.hostname, self.threshold):
                flagged.append(
                    {
                        "url": url,
                        "hostname": parsed.hostname,
                        "subdomain_labels": subdomain_label_count(parsed.hostname),
                    }
                )

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.35, cap=0.75)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged},
        )
