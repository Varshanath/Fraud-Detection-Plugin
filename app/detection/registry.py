from app.detection.rule import Rule
from app.detection.rule_engine import RuleEngine
from app.detection.rules.credential_request import CredentialRequestRule
from app.detection.rules.financial_request import FinancialRequestRule
from app.detection.rules.impersonation_language import ImpersonationLanguageRule
from app.detection.rules.sensitive_information_request import SensitiveInformationRequestRule
from app.detection.rules.suspicious_attachment_reference import SuspiciousAttachmentReferenceRule
from app.detection.rules.suspicious_call_to_action import SuspiciousCallToActionRule
from app.detection.rules.urgency_pressure import UrgencyPressureRule

# Adding a new rule: create a file under app/detection/rules/, then add one
# instance here. RuleEngine's implementation never needs to change.
DEFAULT_RULES: list[Rule] = [
    UrgencyPressureRule(),
    CredentialRequestRule(),
    FinancialRequestRule(),
    SensitiveInformationRequestRule(),
    SuspiciousCallToActionRule(),
    ImpersonationLanguageRule(),
    SuspiciousAttachmentReferenceRule(),
]


def build_default_rule_engine() -> RuleEngine:
    return RuleEngine(rules=DEFAULT_RULES)
