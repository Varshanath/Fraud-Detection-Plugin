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
        subject="Your monthly statement is ready",
        content=(
            "Your account statement for July is now available in your online "
            "banking portal. No action is required."
        ),
    )


def phishing_credential_request() -> SecurityEventResponse:
    return build_event(
        sender_email="security@examplebank-alerts.com",
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
    )
