from app.detection.domain_similarity import DomainSimilarityAnalyzer
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.protected_brands import ProtectedBrandRegistry, default_protected_brand_registry
from app.detection.url_parsing import parse_url
from app.ingestion.schemas import SecurityEventResponse


class LookalikeUrlDomainRule:
    """Uses the SAME DomainSimilarityAnalyzer + ProtectedBrandRegistry as
    LookalikeSenderDomainRule -- reused, not duplicated.
    """

    rule_id = "LOOKALIKE_URL_DOMAIN"
    category = EvidenceCategory.SUSPICIOUS_URL
    description = "URL hostname closely resembles a protected organization domain."

    def __init__(
        self,
        registry: ProtectedBrandRegistry | None = None,
        similarity: DomainSimilarityAnalyzer | None = None,
    ) -> None:
        self._registry = registry or default_protected_brand_registry()
        self._similarity = similarity or DomainSimilarityAnalyzer()

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged = []
        for url in event.urls:
            parsed = parse_url(url)
            if parsed is None or not parsed.hostname:
                continue
            match = self._similarity.find_best_match(parsed.hostname, self._registry.all_domains())
            if match is None:
                continue
            flagged.append(
                {
                    "url": url,
                    "observed_domain": match.observed_domain,
                    "reference_domain": match.reference_domain,
                    "similarity": round(match.similarity, 2),
                    "reason": match.reason,
                }
            )

        if not flagged:
            return None

        best_similarity = max(item["similarity"] for item in flagged)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.HIGH,
            confidence=best_similarity,
            description=self.description,
            details={"urls": flagged},
        )
