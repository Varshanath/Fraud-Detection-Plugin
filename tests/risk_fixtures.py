from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence


def make_evidence(**overrides) -> DetectionEvidence:
    defaults = dict(
        rule_id="TEST_RULE",
        category=EvidenceCategory.SOCIAL_ENGINEERING,
        severity=Severity.MEDIUM,
        confidence=0.5,
        description="test evidence",
        details={},
    )
    defaults.update(overrides)
    return DetectionEvidence(**defaults)
