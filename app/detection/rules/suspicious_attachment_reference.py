from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.ingestion.schemas import SecurityEventResponse

_EXECUTABLE_EXTS = {"exe", "bat", "cmd", "scr", "msi", "com", "pif", "gadget", "msp", "hta"}
_SCRIPT_EXTS = {"ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "jar", "sh"}
_MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "ppam", "sldm"}
_BENIGN_LOOKING_EXTS = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "jpg",
    "jpeg",
    "png",
    "zip",
    "txt",
    "csv",
    "gif",
    "bmp",
}
_DANGEROUS_EXTS = _EXECUTABLE_EXTS | _SCRIPT_EXTS

_SEVERITY_ORDER = {Severity.MEDIUM: 0, Severity.HIGH: 1, Severity.CRITICAL: 2}
_CONFIDENCE_BASE = {Severity.CRITICAL: 0.6, Severity.HIGH: 0.45, Severity.MEDIUM: 0.35}


def _classify_attachment(filename: str) -> tuple[Severity, list[str]] | None:
    """Inspect only the filename (metadata) -- never attachment content."""
    name = (filename or "").strip()
    parts = name.split(".")
    if len(parts) < 2:
        return None

    ext = parts[-1].lower()
    signals: list[str] = []
    severity: Severity | None = None

    if ext in _EXECUTABLE_EXTS:
        signals.append("executable_extension")
        severity = Severity.CRITICAL
    elif ext in _SCRIPT_EXTS:
        signals.append("script_extension")
        severity = Severity.HIGH
    elif ext in _MACRO_EXTS:
        signals.append("macro_enabled_extension")
        severity = Severity.MEDIUM

    if len(parts) >= 3:
        second_last = parts[-2].lower()
        if second_last in _BENIGN_LOOKING_EXTS and ext in _DANGEROUS_EXTS:
            signals.append("double_extension")
            severity = Severity.CRITICAL

    if not signals:
        return None
    return severity, signals


class SuspiciousAttachmentReferenceRule:
    rule_id = "SUSPICIOUS_ATTACHMENT_REFERENCE"
    category = EvidenceCategory.SUSPICIOUS_ATTACHMENT
    description = (
        "Event includes attachment metadata with executable, script, macro-enabled, "
        "or double-extension characteristics."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        flagged: list[dict] = []
        worst_severity: Severity | None = None

        for attachment in event.attachments:
            result = _classify_attachment(attachment.filename)
            if result is None:
                continue
            severity, signals = result
            flagged.append({"filename": attachment.filename, "signals": signals})
            if worst_severity is None or _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[worst_severity]:
                worst_severity = severity

        if not flagged or worst_severity is None:
            return None

        confidence = min(_CONFIDENCE_BASE[worst_severity] + 0.1 * (len(flagged) - 1), 0.95)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=worst_severity,
            confidence=confidence,
            description=self.description,
            details={"attachments": flagged},
        )
