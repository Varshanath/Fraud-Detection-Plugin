from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.matching import scored_confidence
from app.detection.url_parsing import has_excessive_subdomains
from app.ingestion.schemas import SecurityEventResponse

_MAX_NORMAL_DOMAIN_LENGTH = 40
_SUBSTITUTION_DIGITS = set("013457")
_VOWELS = set("aeiou")


def _is_malformed(domain: str) -> bool:
    return "." not in domain


def _is_unusually_long(domain: str) -> bool:
    return len(domain) > _MAX_NORMAL_DOMAIN_LENGTH


def _has_numeric_substitution(domain: str) -> bool:
    for label in domain.split("."):
        letters = sum(1 for ch in label if ch.isalpha())
        substituted_digits = sum(1 for ch in label if ch in _SUBSTITUTION_DIGITS)
        if substituted_digits >= 1 and letters >= 2:
            return True
    return False


def _has_suspicious_hyphenation(domain: str) -> bool:
    if domain.count("-") >= 3:
        return True
    return any(label.count("-") >= 2 for label in domain.split("."))


def _looks_random(domain: str) -> bool:
    labels = domain.split(".")
    for label in labels[:-1] if len(labels) > 1 else labels:
        if len(label) < 8:
            continue
        letters = [ch for ch in label if ch.isalpha()]
        if not letters:
            continue
        vowel_ratio = sum(1 for ch in letters if ch in _VOWELS) / len(letters)
        if vowel_ratio < 0.2:
            return True
    return False


class SuspiciousSenderDomainRule:
    """Aggregates all structural sender-domain anomaly checks into one
    evidence object (mirrors the Phase 3 attachment-rule pattern) rather
    than a separate rule_id per sub-signal, since these are correlated
    structural properties of the same domain string.
    """

    rule_id = "SUSPICIOUS_SENDER_DOMAIN"
    category = EvidenceCategory.SENDER_SPOOFING
    description = "Sender domain has structurally suspicious characteristics."

    def evaluate(self, event: SecurityEventResponse) -> DetectionEvidence | None:
        if not event.sender_email:
            return None

        domain = event.sender_domain
        signals: list[str] = []

        if not domain:
            signals.append("missing_domain")
        elif _is_malformed(domain):
            signals.append("malformed_domain")
        else:
            if _is_unusually_long(domain):
                signals.append("unusually_long_domain")
            if has_excessive_subdomains(domain):
                signals.append("excessive_domain_labels")
            if _has_numeric_substitution(domain):
                signals.append("numeric_substitution")
            if _has_suspicious_hyphenation(domain):
                signals.append("suspicious_hyphenation")
            if _looks_random(domain):
                signals.append("random_looking_label")

        if not signals:
            return None

        confidence = scored_confidence(len(signals), base=0.3, cap=0.75)

        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=confidence,
            description=self.description,
            details={"domain": domain, "signals": signals},
        )
