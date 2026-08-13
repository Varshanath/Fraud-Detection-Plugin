from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import find_requested_terms, scored_confidence
from app.detection.rule import BaseRule
from app.ingestion.schemas import SecurityEventResponse

# "update" is deliberately excluded here: it lives in the suspicious
# call-to-action rule's "update payment" phrase instead, avoiding an
# unhelpful dual-fire on that exact bigram.
_REQUEST_VERBS = [
    "make",
    "send",
    "transfer",
    "provide",
    "confirm",
    "process",
    "complete",
    "submit",
    "share",
    "wire",
]

_FINANCIAL_NOUNS = [
    "payment",
    "money",
    "funds",
    "bank details",
    "bank account details",
    "card details",
    "card number",
    "wire transfer",
    "money transfer",
    "gift card",
    "gift cards",
    "invoice payment",
    "account payment",
]


class FinancialRequestRule(BaseRule):
    rule_id = "FINANCIAL_REQUEST"
    category = EvidenceCategory.FINANCIAL_FRAUD
    description = (
        "Message requests a payment, money transfer, or financial account details."
    )

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        text = self._searchable_text(event)
        matches = find_requested_terms(text, _REQUEST_VERBS, _FINANCIAL_NOUNS)
        if not matches:
            return None

        confidence = scored_confidence(len(matches), base=0.45, cap=0.9)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.HIGH,
            confidence=confidence,
            description=self.description,
            details={"matched_phrases": matches},
        )
