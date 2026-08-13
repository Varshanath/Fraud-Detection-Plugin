from app.detection.engine import DetectionEngine
from tests import detection_fixtures as fx

engine = DetectionEngine()


def _fired_rule_ids(event) -> set[str]:
    return {e.rule_id for e in engine.evaluate(event).evidence}


def test_legitimate_bank_notification_fires_nothing():
    assert _fired_rule_ids(fx.legitimate_bank_notification()) == set()


def test_phishing_credential_request_fires_expected_rules():
    fired = _fired_rule_ids(fx.phishing_credential_request())
    assert fired == {"URGENCY_PRESSURE", "CREDENTIAL_REQUEST", "SUSPICIOUS_CALL_TO_ACTION"}


def test_fake_account_suspension_fires_expected_rules():
    fired = _fired_rule_ids(fx.fake_account_suspension())
    assert "URGENCY_PRESSURE" in fired
    assert "SUSPICIOUS_CALL_TO_ACTION" in fired


def test_financial_payment_scam_fires_financial_request():
    fired = _fired_rule_ids(fx.financial_payment_scam())
    assert "FINANCIAL_REQUEST" in fired


def test_fake_delivery_message_fires_impersonation_and_cta():
    fired = _fired_rule_ids(fx.fake_delivery_message())
    assert "IMPERSONATION_LANGUAGE" in fired
    assert "SUSPICIOUS_CALL_TO_ACTION" in fired


def test_fake_job_recruitment_scam_fires_financial_and_sensitive_info_distinctly():
    fired = _fired_rule_ids(fx.fake_job_recruitment_scam())
    assert "FINANCIAL_REQUEST" in fired
    assert "SENSITIVE_INFORMATION_REQUEST" in fired


def test_legitimate_otp_notification_does_not_fire_credential_request():
    fired = _fired_rule_ids(fx.legitimate_otp_notification())
    assert "CREDENTIAL_REQUEST" not in fired


def test_legitimate_payment_notification_does_not_fire_financial_request():
    fired = _fired_rule_ids(fx.legitimate_payment_notification())
    assert "FINANCIAL_REQUEST" not in fired


def test_suspicious_attachment_metadata_fires_attachment_rule_only():
    fired = _fired_rule_ids(fx.suspicious_attachment_metadata())
    assert fired == {"SUSPICIOUS_ATTACHMENT_REFERENCE"}


def test_completely_benign_message_fires_nothing():
    assert _fired_rule_ids(fx.completely_benign_message()) == set()
