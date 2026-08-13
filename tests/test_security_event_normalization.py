from datetime import datetime, timedelta, timezone

from app.ingestion import normalization


def test_empty_str_to_none_blank_string():
    assert normalization.empty_str_to_none("") is None


def test_empty_str_to_none_whitespace_only():
    assert normalization.empty_str_to_none("   ") is None


def test_empty_str_to_none_trims_and_preserves_content():
    assert normalization.empty_str_to_none(" hi ") == "hi"


def test_empty_str_to_none_none_passthrough():
    assert normalization.empty_str_to_none(None) is None


def test_normalize_email_lowercases_and_trims():
    assert normalization.normalize_email("  Foo@Bar.COM ") == "foo@bar.com"


def test_normalize_email_none_passthrough():
    assert normalization.normalize_email(None) is None


def test_derive_sender_domain_from_email():
    assert normalization.derive_sender_domain("user@example.com", None) == "example.com"


def test_derive_sender_domain_prefers_explicit_value():
    assert (
        normalization.derive_sender_domain("user@example.com", "override.com")
        == "override.com"
    )


def test_derive_sender_domain_none_when_no_email_or_domain():
    assert normalization.derive_sender_domain(None, None) is None


def test_normalize_recipients_trims_and_drops_empties():
    assert normalization.normalize_recipients(["  a@b.com ", "", "   "]) == ["a@b.com"]


def test_normalize_recipients_none_becomes_empty_list():
    assert normalization.normalize_recipients(None) == []


def test_normalize_urls_trims_dedupes_preserves_order():
    urls = ["https://b.example/", "  https://a.example/  ", "https://b.example/"]
    assert normalization.normalize_urls(urls) == ["https://b.example/", "https://a.example/"]


def test_is_url_shaped_accepts_scheme_and_www():
    assert normalization.is_url_shaped("http://x")
    assert normalization.is_url_shaped("hxxp://evil.example/path")
    assert normalization.is_url_shaped("www.evil.example")


def test_is_url_shaped_rejects_garbage():
    assert not normalization.is_url_shaped("")
    assert not normalization.is_url_shaped("not a url")
    assert not normalization.is_url_shaped("x" * 3000)


def test_normalize_timestamp_naive_becomes_utc():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    result = normalization.normalize_timestamp(naive)
    assert result.tzinfo == timezone.utc


def test_normalize_timestamp_aware_converts_to_utc():
    aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    result = normalization.normalize_timestamp(aware)
    assert result.tzinfo == timezone.utc
    assert result == aware


def test_normalize_timestamp_none_passthrough():
    assert normalization.normalize_timestamp(None) is None


def test_normalize_attachment_trims_filename_and_lowercases_sha256():
    attachment = {
        "filename": "  invoice.pdf  ",
        "content_type": "application/pdf",
        "size": 1024,
        "sha256": "A" * 64,
    }
    result = normalization.normalize_attachment(attachment)
    assert result["filename"] == "invoice.pdf"
    assert result["sha256"] == "a" * 64


def test_normalize_attachment_handles_missing_sha256():
    attachment = {"filename": "file.txt", "content_type": None, "size": 0, "sha256": None}
    result = normalization.normalize_attachment(attachment)
    assert result["sha256"] is None


def test_is_valid_sha256_accepts_valid_hex():
    assert normalization.is_valid_sha256("a" * 64)


def test_is_valid_sha256_rejects_wrong_length():
    assert not normalization.is_valid_sha256("a" * 63)


def test_is_valid_sha256_rejects_non_hex():
    assert not normalization.is_valid_sha256("z" * 64)
