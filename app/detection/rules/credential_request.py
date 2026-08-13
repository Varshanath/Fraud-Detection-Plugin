from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import find_requested_terms, scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

# "use" is deliberately excluded: "Please use the OTP sent to your registered
# number" is informational (the sender is giving the user a code), not a
# request for the user to hand a credential back.
_REQUEST_VERBS = [
    "enter",
    "provide",
    "share",
    "send",
    "submit",
    "confirm",
    "give",
    "disclose",
    "resend",
    "reply with",
    "input",
]

_CREDENTIAL_NOUNS = [
    "password",
    "otp",
    "one-time password",
    "one time password",
    "verification code",
    "login credentials",
    "pin",
    "security code",
    "one-time code",
    "access code",
]


class CredentialRequestRule(BaseRule):
    rule_id = "CREDENTIAL_REQUEST"
    category = EvidenceCategory.CREDENTIAL_THEFT
    description = (
        "Message requests that the recipient provide a password, OTP, PIN, "
        "or other login credential."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        matches = find_requested_terms(text, _REQUEST_VERBS, _CREDENTIAL_NOUNS)
        if not matches:
            return None

        confidence = scored_confidence(len(matches), base=0.5, cap=0.95)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.HIGH,
            confidence=confidence,
            description=self.description,
            details={"matched_phrases": matches},
        )
