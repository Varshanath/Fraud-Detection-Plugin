from app.detection.protected_brands import (
    ProtectedBrand,
    ProtectedBrandRegistry,
    default_protected_brand_registry,
)


def test_default_registry_contains_expected_brands():
    registry = default_protected_brand_registry()
    names = {brand.name for brand in registry._brands}
    assert names == {"PayPal", "Microsoft", "Amazon", "Google", "Apple", "Netflix", "LinkedIn"}


def test_all_domains_returns_canonical_domains():
    registry = default_protected_brand_registry()
    assert "paypal.com" in registry.all_domains()
    assert "microsoft.com" in registry.all_domains()


def test_match_display_name_matches_brand_alias():
    registry = default_protected_brand_registry()
    brand = registry.match_display_name("PayPal Security")
    assert brand is not None
    assert brand.name == "PayPal"


def test_match_display_name_case_insensitive():
    registry = default_protected_brand_registry()
    brand = registry.match_display_name("MICROSOFT SUPPORT TEAM")
    assert brand is not None
    assert brand.name == "Microsoft"


def test_match_display_name_returns_none_when_no_brand_mentioned():
    registry = default_protected_brand_registry()
    assert registry.match_display_name("John Smith") is None


def test_match_display_name_returns_none_for_empty_text():
    registry = default_protected_brand_registry()
    assert registry.match_display_name(None) is None
    assert registry.match_display_name("") is None


def test_get_returns_brand_by_name():
    registry = default_protected_brand_registry()
    brand = registry.get("paypal")
    assert brand is not None
    assert brand.canonical_domain == "paypal.com"


def test_get_returns_none_for_unknown_brand():
    registry = default_protected_brand_registry()
    assert registry.get("not a real brand") is None


def test_custom_registry_is_isolated_from_default():
    custom = ProtectedBrandRegistry(
        [ProtectedBrand("Acme", "acme.example", ("acme",))]
    )
    assert custom.match_display_name("PayPal Security") is None
    assert custom.match_display_name("Acme Support") is not None
