from collections.abc import Iterable

from app.detection.rule import Rule
from app.detection.rule_engine import RuleEngine, RuleEngineResult
from app.detection.url_rules.excessive_subdomains import ExcessiveSubdomainsRule
from app.detection.url_rules.excessive_url_length import ExcessiveUrlLengthRule
from app.detection.url_rules.insecure_http_url import InsecureHttpUrlRule
from app.detection.url_rules.ip_address_url import IpAddressUrlRule
from app.detection.url_rules.lookalike_url_domain import LookalikeUrlDomainRule
from app.detection.url_rules.obfuscated_url import ObfuscatedUrlRule
from app.detection.url_rules.suspicious_query_parameter import SuspiciousQueryParameterRule
from app.detection.url_rules.suspicious_url_path import SuspiciousUrlPathRule
from app.ingestion.schemas import SecurityEventResponse

DEFAULT_URL_RULES: list[Rule] = [
    IpAddressUrlRule(),
    InsecureHttpUrlRule(),
    ExcessiveUrlLengthRule(),
    ExcessiveSubdomainsRule(),
    ObfuscatedUrlRule(),
    SuspiciousQueryParameterRule(),
    SuspiciousUrlPathRule(),
    LookalikeUrlDomainRule(),
]


class URLAnalyzer:
    """Deterministic, offline URL intelligence -- inspects the URL string
    only (via urllib.parse, which makes zero network calls). Never fetches,
    resolves, or follows anything. Reuses RuleEngine internally, same as
    SenderAnalyzer.
    """

    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self._engine = RuleEngine(rules=rules if rules is not None else DEFAULT_URL_RULES)

    def evaluate(self, event: SecurityEventResponse) -> RuleEngineResult:
        return self._engine.evaluate(event)
