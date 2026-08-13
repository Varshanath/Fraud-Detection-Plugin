import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    event_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)

    sender_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    sender_display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    reply_to: Mapped[str | None] = mapped_column(String(320), nullable=True)

    recipients: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    urls: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    attachments: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    headers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    event_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
