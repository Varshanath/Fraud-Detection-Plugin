from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.protected_brands import ProtectedBrandRegistry, default_protected_brand_registry
from app.ingestion.schemas import SecurityEventResponse


class DisplayNameImpersonationRule:
    rule_id = "DISPLAY_NAME_DOMAIN_MISMATCH"
    category = EvidenceCategory.SENDER_SPOOFING
    description = (
        "Display name appears to claim a protected brand, but the sender domain "
        "does not match that brand's canonical domain."
    )

    def __init__(self, registry: ProtectedBrandRegistry | None = None) -> None:
        self._registry = registry or default_protected_brand_registry()

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        if not event.sender_display_name or not event.sender_domain:
            return None

        brand = self._registry.match_display_name(event.sender_display_name)
        if brand is None:
            return None

        observed_domain = event.sender_domain.strip().lower()
        if observed_domain == brand.canonical_domain.lower():
            return None

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.HIGH,
            confidence=0.75,
            description=self.description,
            details={
                "claimed_brand": brand.name,
                "expected_domain": brand.canonical_domain,
                "observed_domain": observed_domain,
            },
        )
