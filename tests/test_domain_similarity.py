from app.detection.domain_similarity import DomainSimilarityAnalyzer

analyzer = DomainSimilarityAnalyzer()


def test_normalize_lowercases_and_strips():
    assert analyzer.normalize("  PayPal.COM. ") == "paypal.com"


def test_normalize_strips_www_prefix():
    assert analyzer.normalize("www.paypal.com") == "paypal.com"


def test_normalize_collapses_to_last_two_labels():
    assert analyzer.normalize("login.verify.paypal.com") == "paypal.com"


def test_exact_match_reason():
    result = analyzer.compare("paypal.com", "paypal.com")
    assert result.similarity == 1.0
    assert result.reason == "exact_match"


def test_numeric_substitution_detected_as_character_substitution():
    result = analyzer.compare("paypa1.com", "paypal.com")
    assert result.reason == "character_substitution"
    assert result.similarity >= 0.9


def test_microsoft_numeric_substitution():
    result = analyzer.compare("micros0ft.com", "microsoft.com")
    assert result.similarity >= 0.85


def test_amazon_numeric_substitution():
    result = analyzer.compare("amaz0n.com", "amazon.com")
    assert result.similarity >= 0.8


def test_completely_different_domain_has_low_similarity():
    result = analyzer.compare("totallydifferent.com", "paypal.com")
    assert result.similarity < analyzer.threshold


def test_find_best_match_excludes_exact_match():
    match = analyzer.find_best_match("paypal.com", ["paypal.com", "microsoft.com"])
    assert match is None


def test_find_best_match_returns_best_above_threshold():
    match = analyzer.find_best_match(
        "paypa1.com", ["paypal.com", "microsoft.com", "amazon.com"]
    )
    assert match is not None
    assert match.reference_domain == "paypal.com"


def test_find_best_match_returns_none_when_nothing_close_enough():
    match = analyzer.find_best_match("mycompany.example", ["paypal.com", "microsoft.com"])
    assert match is None


def test_conservative_threshold_does_not_flag_every_similar_domain():
    # Same length, same TLD, but genuinely different word -- must not flag.
    match = analyzer.find_best_match("mypal.com", ["paypal.com"])
    assert match is None


def test_bounded_length_guard_does_not_crash_on_huge_input():
    huge = "a" * 10_000 + ".com"
    result = analyzer.compare(huge, "paypal.com")
    assert result.similarity == 0.0
    assert result.reason == "too_long_to_compare"


def test_empty_string_handled_gracefully():
    result = analyzer.compare("", "paypal.com")
    assert 0.0 <= result.similarity <= 1.0
