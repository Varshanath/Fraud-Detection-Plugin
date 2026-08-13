"""A small, hardcoded registry of brands SenderAnalyzer/URLAnalyzer check
impersonation claims against.

This is intentionally small TEST DATA, not a threat-intelligence database.
It exists so brand checks aren't scattered across individual rules, and is
expected to later be replaced or extended by a proper intelligence source
(Phase 9) -- nothing here should be treated as exhaustive or authoritative.
"""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class ProtectedBrand:
    name: str
    canonical_domain: str
    aliases: tuple[str, ...]


DEFAULT_PROTECTED_BRANDS: tuple[ProtectedBrand, ...] = (
    ProtectedBrand("PayPal", "paypal.com", ("paypal", "paypal security", "paypal support")),
    ProtectedBrand(
        "Microsoft", "microsoft.com", ("microsoft", "microsoft support", "microsoft security")
    ),
    ProtectedBrand("Amazon", "amazon.com", ("amazon", "amazon support", "amazon security")),
    ProtectedBrand("Google", "google.com", ("google", "google support", "google security")),
    ProtectedBrand("Apple", "apple.com", ("apple", "apple support", "apple security")),
    ProtectedBrand("Netflix", "netflix.com", ("netflix", "netflix support", "netflix billing")),
    ProtectedBrand("LinkedIn", "linkedin.com", ("linkedin", "linkedin support")),
)


class ProtectedBrandRegistry:
    def __init__(self, brands: Iterable[ProtectedBrand] | None = None) -> None:
        self._brands: list[ProtectedBrand] = (
            list(brands) if brands is not None else list(DEFAULT_PROTECTED_BRANDS)
        )

    def all_domains(self) -> list[str]:
        return [brand.canonical_domain for brand in self._brands]

    def get(self, name: str) -> ProtectedBrand | None:
        lowered = name.strip().lower()
        for brand in self._brands:
            if brand.name.lower() == lowered:
                return brand
        return None

    def match_display_name(self, text: str | None) -> ProtectedBrand | None:
        if not text:
            return None
        lowered = text.lower()

        best: ProtectedBrand | None = None
        best_alias_length = 0
        for brand in self._brands:
            for alias in brand.aliases:
                if alias in lowered and len(alias) > best_alias_length:
                    best = brand
                    best_alias_length = len(alias)
        return best


def default_protected_brand_registry() -> ProtectedBrandRegistry:
    return ProtectedBrandRegistry()
