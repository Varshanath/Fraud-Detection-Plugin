from app.detection.enums import EvidenceCategory, Severity
from app.detection.rules.suspicious_attachment_reference import (
    SuspiciousAttachmentReferenceRule,
)
from app.ingestion.schemas import AttachmentMetadataSchema
from tests.detection_fixtures import build_event

rule = SuspiciousAttachmentReferenceRule()


def _attachment(**overrides) -> AttachmentMetadataSchema:
    defaults = dict(filename="file.txt", content_type=None, size=100, sha256=None)
    defaults.update(overrides)
    return AttachmentMetadataSchema(**defaults)


def test_executable_extension_flagged_critical():
    event = build_event(attachments=[_attachment(filename="invoice.exe")])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.rule_id == "SUSPICIOUS_ATTACHMENT_REFERENCE"
    assert evidence.category == EvidenceCategory.SUSPICIOUS_ATTACHMENT
    assert evidence.severity == Severity.CRITICAL


def test_script_extension_flagged_high():
    event = build_event(attachments=[_attachment(filename="run.ps1")])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.severity == Severity.HIGH


def test_macro_enabled_extension_flagged_medium():
    event = build_event(attachments=[_attachment(filename="report.docm")])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.severity == Severity.MEDIUM


def test_double_extension_flagged_critical():
    event = build_event(attachments=[_attachment(filename="invoice.pdf.exe")])
    evidence = rule.evaluate(event)
    assert evidence is not None
    assert evidence.severity == Severity.CRITICAL
    signals = evidence.details["attachments"][0]["signals"]
    assert "double_extension" in signals
    assert "executable_extension" in signals


def test_no_attachments_returns_none():
    event = build_event(attachments=[])
    assert rule.evaluate(event) is None


def test_benign_attachment_returns_none():
    event = build_event(attachments=[_attachment(filename="terms.pdf")])
    assert rule.evaluate(event) is None


def test_mixed_attachments_only_flags_suspicious_one():
    event = build_event(
        attachments=[
            _attachment(filename="invoice.pdf.exe"),
            _attachment(filename="terms.pdf"),
        ]
    )
    evidence = rule.evaluate(event)
    assert evidence is not None
    flagged_names = [a["filename"] for a in evidence.details["attachments"]]
    assert flagged_names == ["invoice.pdf.exe"]


def test_missing_optional_fields_does_not_error():
    event = build_event(
        attachments=[
            AttachmentMetadataSchema(
                filename="malware.exe", content_type=None, size=0, sha256=None
            )
        ]
    )
    assert rule.evaluate(event) is not None


def test_filename_without_extension_returns_none():
    event = build_event(attachments=[_attachment(filename="README")])
    assert rule.evaluate(event) is None


def test_uppercase_extension_still_detected():
    event = build_event(attachments=[_attachment(filename="invoice.EXE")])
    assert rule.evaluate(event) is not None
