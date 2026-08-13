import uuid
from datetime import datetime, timezone

from app.ingestion.enums import EventType
from app.ingestion.schemas import AttachmentMetadataSchema, SecurityEventResponse


def build_event(**overrides) -> SecurityEventResponse:
    defaults = dict(
        event_id=uuid.uuid4(),
        event_type=EventType.EMAIL,
        source=None,
        sender_email=None,
        sender_display_name=None,
        sender_domain=None,
        reply_to=None,
        recipients=[],
        subject=None,
        content=None,
        urls=[],
        attachments=[],
        headers={},
        event_timestamp=None,
        ingested_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return SecurityEventResponse(**defaults)


def legitimate_bank_notification() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        subject="Your monthly statement is ready",
        content=(
            "Your account statement for July is now available in your online "
            "banking portal. No action is required."
        ),
    )


def phishing_credential_request() -> SecurityEventResponse:
    return build_event(
        sender_email="security@examplebank-alerts.com",
        sender_domain="examplebank-alerts.com",
        subject="Urgent: Verify your account now",
        content=(
            "Act immediately. Please enter your password and PIN below to verify "
            "your account or it will be suspended. Click here to confirm your account."
        ),
    )


def fake_account_suspension() -> SecurityEventResponse:
    return build_event(
        subject="Final notice",
        content=(
            "This is your final warning. Your account will be suspended within 24 "
            "hours if you do not respond immediately. Click here to avoid suspension."
        ),
    )


def financial_payment_scam() -> SecurityEventResponse:
    return build_event(
        subject="Payment Required to Avoid Penalty",
        content=(
            "Please make a payment immediately to avoid account penalty. Send your "
            "bank details and card details to confirm your payment."
        ),
    )


def fake_delivery_message() -> SecurityEventResponse:
    return build_event(
        event_type=EventType.SMS,
        sender_email=None,
        content=(
            "This is your delivery company. Your package could not be delivered. "
            "Click here to update payment and confirm your delivery details."
        ),
    )


def fake_job_recruitment_scam() -> SecurityEventResponse:
    return build_event(
        subject="Job Offer - Immediate Start",
        content=(
            "Congratulations, you have been selected. To confirm your position, "
            "please provide your bank details and social security number for "
            "payroll setup. Respond immediately to secure this offer."
        ),
    )


def legitimate_otp_notification() -> SecurityEventResponse:
    return build_event(
        event_type=EventType.SMS,
        content="Please use the OTP sent to your registered number to complete your login.",
    )


def legitimate_payment_notification() -> SecurityEventResponse:
    return build_event(
        subject="Payment Successful",
        content="Your payment of ₹500 was successful.",
        sender_email="noreply@paymentsapp.com",
        sender_domain="paymentsapp.com",
    )


def suspicious_attachment_metadata() -> SecurityEventResponse:
    return build_event(
        subject="Invoice attached",
        content="Please find your invoice attached.",
        attachments=[
            AttachmentMetadataSchema(
                filename="invoice.pdf.exe",
                content_type="application/x-msdownload",
                size=245678,
                sha256="b" * 64,
            ),
            AttachmentMetadataSchema(
                filename="terms.pdf",
                content_type="application/pdf",
                size=10240,
                sha256="c" * 64,
            ),
        ],
    )


def completely_benign_message() -> SecurityEventResponse:
    return build_event(
        event_type=EventType.CHAT,
        subject=None,
        content="Hey, are we still meeting for lunch tomorrow at 1pm?",
        sender_email="friend@example.com",
        sender_domain="example.com",
    )


# ---------------------------------------------------------------------------
# Phase 4 -- SenderAnalyzer / URLAnalyzer fixtures
# ---------------------------------------------------------------------------


def normal_sender() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        subject="Your statement is ready",
        content="Your monthly statement is now available.",
    )


def reply_to_matches() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        reply_to="support@examplebank.com",
    )


def reply_to_mismatch() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="examplebank.com",
        reply_to="reply@attacker.example",
    )


def legitimate_paypal_sender() -> SecurityEventResponse:
    return build_event(
        sender_display_name="PayPal",
        sender_email="service@paypal.com",
        sender_domain="paypal.com",
        content="Your PayPal receipt for your recent purchase.",
        urls=["https://paypal.com/login"],
    )


def legitimate_microsoft_sender() -> SecurityEventResponse:
    return build_event(
        sender_display_name="Microsoft",
        sender_email="account-security@microsoft.com",
        sender_domain="microsoft.com",
        urls=["https://microsoft.com/account"],
    )


def legitimate_amazon_sender() -> SecurityEventResponse:
    return build_event(
        sender_display_name="Amazon",
        sender_email="orders@amazon.com",
        sender_domain="amazon.com",
        urls=["https://amazon.com/orders"],
    )


def legitimate_google_sender() -> SecurityEventResponse:
    return build_event(
        sender_display_name="Google",
        sender_email="no-reply@google.com",
        sender_domain="google.com",
    )


def legitimate_netflix_sender() -> SecurityEventResponse:
    return build_event(
        sender_display_name="Netflix",
        sender_email="info@netflix.com",
        sender_domain="netflix.com",
    )


def display_name_impersonation() -> SecurityEventResponse:
    return build_event(
        sender_display_name="PayPal Security",
        sender_email="security@paypa1-example.com",
        sender_domain="paypa1-example.com",
        subject="Your account needs verification",
    )


def numeric_substitution_domain() -> SecurityEventResponse:
    return build_event(
        sender_email="support@micros0ft-verify.com",
        sender_domain="micros0ft-verify.com",
    )


def lookalike_sender_domain() -> SecurityEventResponse:
    return build_event(
        sender_email="security@paypa1.com",
        sender_domain="paypa1.com",
    )


def excessive_subdomains_sender() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@login.verify.account.security.example.com",
        sender_domain="login.verify.account.security.example.com",
    )


def malformed_sender() -> SecurityEventResponse:
    return build_event(
        sender_email="alerts@examplebank.com",
        sender_domain="localhost",
    )


def missing_optional_sender_fields() -> SecurityEventResponse:
    return build_event(event_type=EventType.SMS, sender_email=None, sender_domain=None)


def normal_https_url() -> SecurityEventResponse:
    return build_event(urls=["https://example.com/dashboard"])


def http_url() -> SecurityEventResponse:
    return build_event(urls=["http://example.com/dashboard"])


def ip_address_url() -> SecurityEventResponse:
    return build_event(urls=["http://192.168.1.10/login"])


def long_url() -> SecurityEventResponse:
    return build_event(urls=["https://example.com/path?" + "a" * 250])


def excessive_subdomains_url() -> SecurityEventResponse:
    return build_event(urls=["https://login.verify.account.security.example.com/"])


def encoded_url() -> SecurityEventResponse:
    return build_event(
        urls=["https://example.com/%70%61%79%70%61%6c%2d%73%65%63%75%72%65/%6c%6f%67%69%6e"]
    )


def suspicious_query_url() -> SecurityEventResponse:
    return build_event(urls=["https://example.com/go?redirect=https://evil.example/harvest"])


def suspicious_path_only_url() -> SecurityEventResponse:
    # A sensitive path keyword with nothing else suspicious must NOT fire alone.
    return build_event(urls=["https://paypal.com/login"])


def lookalike_url() -> SecurityEventResponse:
    return build_event(urls=["https://paypa1.com/login"])


def malformed_url() -> SecurityEventResponse:
    return build_event(urls=["not a url at all"])


def multiple_urls() -> SecurityEventResponse:
    return build_event(
        urls=[
            "https://example.com/dashboard",
            "http://192.168.1.10/login",
            "https://paypa1.com/verify",
        ]
    )


def empty_url_list() -> SecurityEventResponse:
    return build_event(urls=[])
