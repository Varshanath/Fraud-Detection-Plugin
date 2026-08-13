from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import has_other_suspicious_signal, has_sensitive_path_keyword, parse_url
from app.ingestion.schemas import SecurityEventResponse


class SuspiciousUrlPathRule:
    """Sensitive-looking path keywords alone are NOT suspicious (a legitimate
    login page has a /login path too) -- this only fires when a keyword is
    combined with at least one other structural URL signal. Computed via the
    shared pure functions in url_parsing.py directly, not by depending on
    other rules' output, so rules stay independent of each other.
    """

    rule_id = "SUSPICIOUS_URL_PATH"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = (
        "URL path references a sensitive action, combined with another "
        "suspicious URL characteristic."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None:
                continue
            keyword = has_sensitive_path_keyword(parsed.path)
            if keyword is None:
                continue
            if not has_other_suspicious_signal(parsed):
                continue
            flagged.append({"url": url, "path_keyword": keyword})

        if not flagged:
            return None

        confidence = scored_confidence(len(flagged), base=0.35, cap=0.6)
        severity = Severity.MEDIUM if len(flagged) > 1 else Severity.LOW

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            description=self.description,
            details={"urls": flagged},
        )
