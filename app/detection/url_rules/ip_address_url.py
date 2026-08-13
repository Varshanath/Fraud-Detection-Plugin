from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import is_ip_host, parse_url
from app.ingestion.schemas import SecurityEventResponse


class IpAddressUrlRule:
    rule_id = "IP_ADDRESS_URL"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL uses a raw IP address instead of a domain name."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None:
                continue
            if is_ip_host(parsed.hostname):
                flagged.append({"url": url, "hostname": parsed.hostname})

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.4, cap=0.7)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged},
        )
