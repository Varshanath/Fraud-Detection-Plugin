from app.detection.domain_similarity import DomainSimilarityAnalyzer
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.protected_brands import ProtectedBrandRegistry, default_protected_brand_registry
from app.ingestion.schemas import SecurityEventResponse


class LookalikeSenderDomainRule:
    rule_id = "LOOKALIKE_DOMAIN"
    category = EvidenceCategory.SENDER_SPOOFING
    description = "Observed domain closely resembles a protected organization domain."

    def __init__(
        self,
        registry: ProtectedBrandRegistry | None = None,
        similarity: DomainSimilarityAnalyzer | None = None,
    ) -> None:
        self._registry = registry or default_protected_brand_registry()
        self._similarity = similarity or DomainSimilarityAnalyzer()

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        if not event.sender_domain:
            return None

        match = self._similarity.find_best_match(
            event.sender_domain, self._registry.all_domains()
        )
        if match is None:
            return None

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.HIGH,
            confidence=round(match.similarity, 2),
            description=self.description,
            details={
                "observed_domain": match.observed_domain,
                "reference_domain": match.reference_domain,
                "similarity": round(match.similarity, 2),
                "reason": match.reason,
            },
        )
