import re
from datetime import datetime, timezone

_URL_MAX_LENGTH = 2048
_URL_SHAPE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
_WWW_SHAPE_RE = re.compile(r"^www\.\S+$", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def empty_str_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def normalize_email(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip().lower()
    return trimmed if trimmed else None


def derive_sender_domain(sender_email: str | None, provided_domain: str | None) -> str | None:
    if provided_domain:
        trimmed = provided_domain.strip().lower()
        if trimmed:
            return trimmed
    if sender_email and "@" in sender_email:
        return sender_email.rsplit("@", 1)[1]
    return None


def normalize_recipients(recipients: list[str] | None) -> list[str]:
    if not recipients:
        return []
    normalized = []
    for recipient in recipients:
        trimmed = recipient.strip()
        if trimmed:
            normalized.append(trimmed)
    return normalized


def is_url_shaped(value: str) -> bool:
    trimmed = value.strip()
    if not trimmed or len(trimmed) > _URL_MAX_LENGTH:
        return False
    return bool(_URL_SHAPE_RE.match(trimmed) or _WWW_SHAPE_RE.match(trimmed))


def normalize_urls(urls: list[str] | None) -> list[str]:
    if not urls:
        return []
    seen: set[str] = set()
    normalized = []
    for url in urls:
        trimmed = url.strip()
        if trimmed and trimmed not in seen:
            seen.add(trimmed)
            normalized.append(trimmed)
    return normalized


def normalize_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_valid_sha256(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


def normalize_attachment(attachment: dict) -> dict:
    filename = attachment.get("filename", "").strip()
    sha256 = attachment.get("sha256")
    if sha256:
        sha256 = sha256.strip().lower()
    return {
        "filename": filename,
        "content_type": attachment.get("content_type"),
        "size": attachment.get("size"),
        "sha256": sha256,
    }
