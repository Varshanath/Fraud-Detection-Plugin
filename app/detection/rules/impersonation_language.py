import re

from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

# Generic institutional roles -- NOT brand-name detection, which belongs to a
# later sender-analysis phase.
_ROLES = [
    "bank",
    "support team",
    "delivery company",
    "employer",
    "service provider",
    "it department",
    "help desk",
    "security team",
]

_CLAIM_PATTERN = re.compile(
    r"\b(?:we are from|this is|representing|on behalf of|official notice from|"
    r"authorized representative of)\s+(?:your|the)\s+("
    + "|".join(re.escape(role) for role in _ROLES)
    + r")\b",
    re.IGNORECASE,
)


class ImpersonationLanguageRule(BaseRule):
    rule_id = "IMPERSONATION_LANGUAGE"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = (
        "Message claims to represent an organization, institution, or support team."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        if not text:
            return None

        matched_roles: list[str] = []
        for match in _CLAIM_PATTERN.finditer(text):
            role = match.group(1).lower()
            if role not in matched_roles:
                matched_roles.append(role)

        if not matched_roles:
            return None

        confidence = scored_confidence(len(matched_roles), base=0.4, cap=0.85)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"matched_roles": matched_roles},
        )
