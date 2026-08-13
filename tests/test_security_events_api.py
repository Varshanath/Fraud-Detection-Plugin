import uuid

EVENTS_URL = "/api/v1/security-events"


def test_create_event_email_channel_returns_201(client):
    payload = {
        "event_type": "EMAIL",
        "sender_email": "attacker@evil.example",
        "recipients": ["victim@example.com"],
        "subject": "Urgent: verify your account",
        "content": "Click here",
        "urls": ["https://evil.example/login"],
    }
    response = client.post(EVENTS_URL, json=payload)
    assert response.status_code == 201
    body = response.json()
    assert "event_id" in body
    assert body["event_type"] == "EMAIL"


def test_create_event_sms_channel_returns_201(client):
    payload = {
        "event_type": "SMS",
        "source": "sms-gateway",
        "recipients": ["+15551234567"],
        "content": "Your package could not be delivered, click here",
    }
    response = client.post(EVENTS_URL, json=payload)
    assert response.status_code == 201


def test_create_event_chat_channel_returns_201(client):
    payload = {"event_type": "CHAT", "source": "slack", "content": "hey click this link"}
    response = client.post(EVENTS_URL, json=payload)
    assert response.status_code == 201


def test_create_event_url_channel_returns_201(client):
    payload = {"event_type": "URL", "urls": ["https://evil.example/phish"]}
    response = client.post(EVENTS_URL, json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["subject"] is None
    assert body["recipients"] == []


def test_create_event_other_channel_returns_201(client):
    payload = {"event_type": "OTHER", "content": "unspecified channel event"}
    response = client.post(EVENTS_URL, json=payload)
    assert response.status_code == 201


def test_create_event_minimal_fields_returns_201(client):
    response = client.post(EVENTS_URL, json={"event_type": "OTHER"})
    assert response.status_code == 201


def test_create_event_missing_required_field_returns_422(client):
    response = client.post(EVENTS_URL, json={"content": "no event_type"})
    assert response.status_code == 422


def test_create_event_invalid_event_type_returns_422(client):
    response = client.post(EVENTS_URL, json={"event_type": "CARRIER_PIGEON"})
    assert response.status_code == 422


def test_create_event_invalid_email_returns_422(client):
    response = client.post(
        EVENTS_URL, json={"event_type": "EMAIL", "sender_email": "not-an-email"}
    )
    assert response.status_code == 422


def test_create_event_malformed_url_returns_422(client):
    response = client.post(EVENTS_URL, json={"event_type": "URL", "urls": ["not a url"]})
    assert response.status_code == 422


def test_create_event_invalid_attachment_metadata_returns_422(client):
    response = client.post(
        EVENTS_URL,
        json={
            "event_type": "EMAIL",
            "attachments": [{"filename": "a.txt", "size": -5}],
        },
    )
    assert response.status_code == 422


def test_create_event_invalid_timestamp_returns_422(client):
    response = client.post(
        EVENTS_URL, json={"event_type": "EMAIL", "event_timestamp": "not-a-timestamp"}
    )
    assert response.status_code == 422


def test_create_event_derives_sender_domain_when_omitted(client):
    response = client.post(
        EVENTS_URL, json={"event_type": "EMAIL", "sender_email": "user@example.com"}
    )
    assert response.status_code == 201
    assert response.json()["sender_domain"] == "example.com"


def test_create_event_normalizes_whitespace_and_case(client):
    response = client.post(
        EVENTS_URL, json={"event_type": "EMAIL", "sender_email": "  User@EXAMPLE.com  "}
    )
    assert response.status_code == 201
    assert response.json()["sender_email"] == "user@example.com"


def test_get_event_after_create_returns_200_and_matches(client):
    create_response = client.post(
        EVENTS_URL, json={"event_type": "EMAIL", "subject": "test subject"}
    )
    event_id = create_response.json()["event_id"]

    get_response = client.get(f"{EVENTS_URL}/{event_id}")
    assert get_response.status_code == 200
    assert get_response.json()["subject"] == "test subject"
    assert get_response.json()["event_id"] == event_id


def test_get_event_nonexistent_returns_404(client):
    response = client.get(f"{EVENTS_URL}/{uuid.uuid4()}")
    assert response.status_code == 404


def test_get_event_invalid_uuid_format_returns_422(client):
    response = client.get(f"{EVENTS_URL}/not-a-uuid")
    assert response.status_code == 422


def test_create_event_response_matches_documented_schema(client):
    response = client.post(EVENTS_URL, json={"event_type": "OTHER"})
    body = response.json()
    expected_keys = {
        "event_id",
        "event_type",
        "source",
        "sender_email",
        "sender_display_name",
        "sender_domain",
        "reply_to",
        "recipients",
        "subject",
        "content",
        "urls",
        "attachments",
        "headers",
        "event_timestamp",
        "ingested_at",
    }
    assert set(body.keys()) == expected_keys


def test_health_still_works_alongside_ingestion(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
