from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import find_requested_terms, scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

_REQUEST_VERBS = [
    "provide",
    "share",
    "send",
    "confirm",
    "verify",
    "submit",
    "enter",
    "give",
]

# Deliberately disjoint from CredentialRequestRule / FinancialRequestRule's
# vocabulary (password/OTP/PIN/bank/card) -- identity-verification data only.
# This is what prevents one OTP ask from producing duplicate near-identical
# evidence across multiple "sensitive info" style rules.
_IDENTITY_NOUNS = [
    "social security number",
    "ssn",
    "date of birth",
    "mother's maiden name",
    "passport number",
    "national id",
    "national identification number",
    "government id",
    "driver's license number",
]


class SensitiveInformationRequestRule(BaseRule):
    rule_id = "SENSITIVE_INFORMATION_REQUEST"
    category = EvidenceCategory.SENSITIVE_INFORMATION_REQUEST
    description = "Message requests identity-verification information such as a government ID or date of birth."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        matches = find_requested_terms(text, _REQUEST_VERBS, _IDENTITY_NOUNS)
        if not matches:
            return None

        confidence = scored_confidence(len(matches), base=0.4, cap=0.85)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"matched_phrases": matches},
        )
