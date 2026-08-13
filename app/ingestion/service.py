import uuid

from sqlalchemy.orm import Session

from app.ingestion import normalization
from app.ingestion.models import SecurityEvent
from app.ingestion.schemas import SecurityEventCreate


def create_security_event(db: Session, payload: SecurityEventCreate) -> SecurityEvent:
    sender_email = normalization.normalize_email(payload.sender_email)
    reply_to = normalization.normalize_email(payload.reply_to)
    sender_domain = normalization.derive_sender_domain(sender_email, payload.sender_domain)

    event = SecurityEvent(
        event_type=payload.event_type.value,
        source=payload.source,
        sender_email=sender_email,
        sender_display_name=payload.sender_display_name,
        sender_domain=sender_domain,
        reply_to=reply_to,
        recipients=normalization.normalize_recipients(payload.recipients),
        subject=payload.subject,
        content=payload.content,
        urls=normalization.normalize_urls(payload.urls),
        attachments=[
            normalization.normalize_attachment(attachment.model_dump())
            for attachment in payload.attachments
        ],
        headers=payload.headers,
        event_timestamp=normalization.normalize_timestamp(payload.event_timestamp),
    )

    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def get_security_event(db: Session, event_id: uuid.UUID) -> SecurityEvent | None:
    return db.get(SecurityEvent, event_id)
