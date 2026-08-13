import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.ingestion.enums import EventType
from app.ingestion.normalization import empty_str_to_none, is_url_shaped, is_valid_sha256


class AttachmentMetadataSchema(BaseModel):
    filename: str
    content_type: str | None = None
    size: int = Field(ge=0)
    sha256: str | None = None

    @field_validator("filename")
    @classmethod
    def _filename_not_blank(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("filename must not be blank")
        return trimmed

    @field_validator("sha256")
    @classmethod
    def _sha256_format(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not is_valid_sha256(value):
            raise ValueError("sha256 must be a 64-character hex string")
        return value


class SecurityEventCreate(BaseModel):
    event_type: EventType
    source: str | None = None

    sender_email: EmailStr | None = None
    sender_display_name: str | None = None
    sender_domain: str | None = None
    reply_to: EmailStr | None = None

    recipients: list[str] = Field(default_factory=list)

    subject: str | None = None
    content: str | None = None

    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadataSchema] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)

    event_timestamp: datetime | None = None

    @field_validator(
        "source",
        "sender_email",
        "sender_display_name",
        "sender_domain",
        "reply_to",
        "subject",
        "content",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, value: Any) -> Any:
        if isinstance(value, str):
            return empty_str_to_none(value)
        return value

    @field_validator("urls")
    @classmethod
    def _validate_urls(cls, value: list[str]) -> list[str]:
        for url in value:
            if not is_url_shaped(url):
                raise ValueError(f"malformed URL: {url!r}")
        return value


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: uuid.UUID
    event_type: EventType
    source: str | None = None

    sender_email: EmailStr | None = None
    sender_display_name: str | None = None
    sender_domain: str | None = None
    reply_to: EmailStr | None = None

    recipients: list[str] = Field(default_factory=list)

    subject: str | None = None
    content: str | None = None

    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadataSchema] = Field(default_factory=list)
    headers: dict[str, Any] = Field(default_factory=dict)

    event_timestamp: datetime | None = None
    ingested_at: datetime

    @field_validator("event_timestamp", "ingested_at", mode="after")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
