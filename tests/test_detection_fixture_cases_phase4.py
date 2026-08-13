from app.detection.engine import DetectionEngine
from tests import detection_fixtures as fx

engine = DetectionEngine()


def _fired_rule_ids(event) -> set[str]:
    return {e.rule_id for e in engine.evaluate(event).evidence}


# ---------------------------------------------------------------------------
# Mandated false positives (must produce zero evidence from the named rule,
# even with SenderAnalyzer/URLAnalyzer now wired into the default engine).
# ---------------------------------------------------------------------------


def test_otp_notification_false_positive_still_holds():
    event = fx.build_event(content="Please use the OTP sent to your registered number.")
    assert "CREDENTIAL_REQUEST" not in _fired_rule_ids(event)


def test_payment_notification_false_positive_still_holds():
    event = fx.build_event(content="Your payment of ₹500 was successful.")
    assert "FINANCIAL_REQUEST" not in _fired_rule_ids(event)


def test_paypal_login_url_produces_no_evidence():
    assert _fired_rule_ids(fx.build_event(urls=["https://paypal.com/login"])) == set()


def test_microsoft_account_url_produces_no_evidence():
    assert _fired_rule_ids(fx.build_event(urls=["https://microsoft.com/account"])) == set()


def test_amazon_orders_url_produces_no_evidence():
    assert _fired_rule_ids(fx.build_event(urls=["https://amazon.com/orders"])) == set()


# ---------------------------------------------------------------------------
# Legitimate brand senders -- must not trigger any sender/URL evidence
# ---------------------------------------------------------------------------


def test_legitimate_paypal_produces_no_evidence():
    assert _fired_rule_ids(fx.legitimate_paypal_sender()) == set()


def test_legitimate_microsoft_produces_no_evidence():
    assert _fired_rule_ids(fx.legitimate_microsoft_sender()) == set()


def test_legitimate_amazon_produces_no_evidence():
    assert _fired_rule_ids(fx.legitimate_amazon_sender()) == set()


def test_legitimate_google_produces_no_evidence():
    assert _fired_rule_ids(fx.legitimate_google_sender()) == set()


def test_legitimate_netflix_produces_no_evidence():
    assert _fired_rule_ids(fx.legitimate_netflix_sender()) == set()


# ---------------------------------------------------------------------------
# Sender minimum cases
# ---------------------------------------------------------------------------


def test_normal_sender_produces_no_evidence():
    assert _fired_rule_ids(fx.normal_sender()) == set()


def test_reply_to_matches_produces_no_evidence():
    assert _fired_rule_ids(fx.reply_to_matches()) == set()


def test_reply_to_mismatch_fires():
    assert "SENDER_REPLY_TO_MISMATCH" in _fired_rule_ids(fx.reply_to_mismatch())


def test_display_name_impersonation_fires():
    assert "DISPLAY_NAME_DOMAIN_MISMATCH" in _fired_rule_ids(fx.display_name_impersonation())


def test_numeric_substitution_domain_fires():
    fired = _fired_rule_ids(fx.numeric_substitution_domain())
    assert "SUSPICIOUS_SENDER_DOMAIN" in fired


def test_lookalike_sender_domain_fires():
    assert "LOOKALIKE_DOMAIN" in _fired_rule_ids(fx.lookalike_sender_domain())


def test_excessive_subdomains_sender_fires():
    fired = _fired_rule_ids(fx.excessive_subdomains_sender())
    assert "SUSPICIOUS_SENDER_DOMAIN" in fired


def test_malformed_sender_fires():
    fired = _fired_rule_ids(fx.malformed_sender())
    assert "SUSPICIOUS_SENDER_DOMAIN" in fired


def test_missing_optional_sender_fields_does_not_crash():
    # No sender data at all -- must run cleanly with no evidence.
    assert _fired_rule_ids(fx.missing_optional_sender_fields()) == set()


# ---------------------------------------------------------------------------
# URL minimum cases
# ---------------------------------------------------------------------------


def test_normal_https_url_produces_no_evidence():
    assert _fired_rule_ids(fx.normal_https_url()) == set()


def test_http_url_fires_insecure_http():
    assert "INSECURE_HTTP_URL" in _fired_rule_ids(fx.http_url())


def test_ip_address_url_fires():
    assert "IP_ADDRESS_URL" in _fired_rule_ids(fx.ip_address_url())


def test_long_url_fires():
    assert "EXCESSIVE_URL_LENGTH" in _fired_rule_ids(fx.long_url())


def test_excessive_subdomains_url_fires():
    assert "EXCESSIVE_SUBDOMAINS" in _fired_rule_ids(fx.excessive_subdomains_url())


def test_encoded_url_fires():
    assert "OBFUSCATED_URL" in _fired_rule_ids(fx.encoded_url())


def test_suspicious_query_url_fires():
    assert "SUSPICIOUS_QUERY_PARAMETER" in _fired_rule_ids(fx.suspicious_query_url())


def test_suspicious_path_only_url_does_not_fire_alone():
    fired = _fired_rule_ids(fx.suspicious_path_only_url())
    assert "SUSPICIOUS_URL_PATH" not in fired


def test_lookalike_url_fires():
    assert "LOOKALIKE_URL_DOMAIN" in _fired_rule_ids(fx.lookalike_url())


def test_malformed_url_does_not_crash():
    assert _fired_rule_ids(fx.malformed_url()) == set()


def test_multiple_urls_aggregate_across_rules():
    fired = _fired_rule_ids(fx.multiple_urls())
    assert "IP_ADDRESS_URL" in fired
    assert "LOOKALIKE_URL_DOMAIN" in fired


def test_empty_url_list_produces_no_evidence():
    assert _fired_rule_ids(fx.empty_url_list()) == set()
