from app.ingestion.models import SecurityEvent


def test_persist_and_reload_email_event(db_session):
    event = SecurityEvent(
        event_type="EMAIL",
        source="test-connector",
        sender_email="user@example.com",
        sender_display_name="User",
        sender_domain="example.com",
        recipients=["victim@example.com"],
        subject="Hello",
        content="Body text",
        urls=["https://example.com/"],
        attachments=[{"filename": "a.txt", "content_type": "text/plain", "size": 10, "sha256": None}],
        headers={"X-Mailer": "test"},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    reloaded = db_session.get(SecurityEvent, event.event_id)
    assert reloaded is not None
    assert reloaded.sender_email == "user@example.com"
    assert reloaded.recipients == ["victim@example.com"]
    assert reloaded.subject == "Hello"


def test_persist_minimal_url_event(db_session):
    event = SecurityEvent(event_type="URL", urls=["https://example.com/"])
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    reloaded = db_session.get(SecurityEvent, event.event_id)
    assert reloaded.subject is None
    assert reloaded.recipients == []
    assert reloaded.sender_email is None


def test_event_id_is_server_generated_uuid(db_session):
    first = SecurityEvent(event_type="OTHER")
    second = SecurityEvent(event_type="OTHER")
    db_session.add_all([first, second])
    db_session.commit()

    assert first.event_id is not None
    assert second.event_id is not None
    assert first.event_id != second.event_id


def test_ingested_at_is_set_automatically(db_session):
    event = SecurityEvent(event_type="CHAT")
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    assert event.ingested_at is not None


def test_default_json_columns_are_empty_containers_not_none(db_session):
    event = SecurityEvent(event_type="SMS")
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    assert event.recipients == []
    assert event.urls == []
    assert event.attachments == []
    assert event.headers == {}
