import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.ingestion.enums import EventType
from app.ingestion.schemas import SecurityEventCreate, SecurityEventResponse


def test_create_schema_accepts_minimal_email_event():
    event = SecurityEventCreate(event_type="EMAIL")
    assert event.event_type == EventType.EMAIL
    assert event.recipients == []
    assert event.urls == []


def test_create_schema_rejects_missing_event_type():
    with pytest.raises(ValidationError):
        SecurityEventCreate()


def test_create_schema_rejects_invalid_event_type_value():
    with pytest.raises(ValidationError):
        SecurityEventCreate(event_type="carrier_pigeon")


def test_create_schema_rejects_invalid_email():
    with pytest.raises(ValidationError):
        SecurityEventCreate(event_type="EMAIL", sender_email="not-an-email")


def test_create_schema_accepts_empty_string_email_as_none():
    event = SecurityEventCreate(event_type="EMAIL", sender_email="")
    assert event.sender_email is None


def test_create_schema_rejects_malformed_url_in_list():
    with pytest.raises(ValidationError):
        SecurityEventCreate(event_type="URL", urls=["not a url"])


def test_create_schema_accepts_attacker_style_obfuscated_url():
    event = SecurityEventCreate(event_type="URL", urls=["hxxp://evil.example/login"])
    assert event.urls == ["hxxp://evil.example/login"]


def test_create_schema_rejects_negative_attachment_size():
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            event_type="EMAIL",
            attachments=[{"filename": "a.txt", "size": -1}],
        )


def test_create_schema_rejects_malformed_sha256():
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            event_type="EMAIL",
            attachments=[{"filename": "a.txt", "size": 10, "sha256": "not-hex"}],
        )


def test_create_schema_accepts_attachment_without_sha256():
    event = SecurityEventCreate(
        event_type="EMAIL",
        attachments=[{"filename": "a.txt", "size": 10}],
    )
    assert event.attachments[0].sha256 is None


def test_create_schema_rejects_invalid_timestamp_format():
    with pytest.raises(ValidationError):
        SecurityEventCreate(event_type="EMAIL", event_timestamp="not-a-timestamp")


def test_response_schema_builds_from_orm_like_object():
    class FakeOrmEvent:
        event_id = uuid.uuid4()
        event_type = "EMAIL"
        source = "test"
        sender_email = "user@example.com"
        sender_display_name = "User"
        sender_domain = "example.com"
        reply_to = None
        recipients = ["a@example.com"]
        subject = "hello"
        content = "body"
        urls = []
        attachments = []
        headers = {}
        event_timestamp = None
        ingested_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    response = SecurityEventResponse.model_validate(FakeOrmEvent(), from_attributes=True)
    assert response.sender_email == "user@example.com"
    assert response.ingested_at.tzinfo is not None


def test_response_schema_reattaches_timezone_to_naive_datetime():
    class FakeOrmEvent:
        event_id = uuid.uuid4()
        event_type = "EMAIL"
        source = None
        sender_email = None
        sender_display_name = None
        sender_domain = None
        reply_to = None
        recipients = []
        subject = None
        content = None
        urls = []
        attachments = []
        headers = {}
        event_timestamp = datetime(2026, 1, 1, 12, 0, 0)  # naive, as SQLite returns
        ingested_at = datetime(2026, 1, 1, 12, 0, 0)  # naive

    response = SecurityEventResponse.model_validate(FakeOrmEvent(), from_attributes=True)
    assert response.event_timestamp.tzinfo == timezone.utc
    assert response.ingested_at.tzinfo == timezone.utc
