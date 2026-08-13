"""URL structure parsing/inspection -- string analysis only.

`urllib.parse` (used here) is pure string parsing with zero network
capability: no socket is opened, no DNS lookup occurs, nothing is fetched.
This is deliberately distinct from `urllib.request`, which this project's
security tests forbid everywhere under `app/detection`.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_REDIRECT_PARAM_NAMES = {
    "redirect",
    "redirecturl",
    "redirect_url",
    "return",
    "returnurl",
    "return_url",
    "destination",
    "next",
    "continue",
    "redirect_uri",
    "redirecturi",
}
_SENSITIVE_PARAM_NAMES = {"token", "login"}

_SENSITIVE_PATH_KEYWORDS = ["login", "verify", "account", "security", "password", "confirm", "update"]


@dataclass(frozen=True)
class ParsedUrl:
    original: str
    scheme: str
    hostname: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    netloc: str


def parse_url(url: str) -> ParsedUrl | None:
    if not url or not url.strip():
        return None
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    return ParsedUrl(
        original=url,
        scheme=parsed.scheme or "",
        hostname=hostname,
        port=port,
        path=parsed.path or "",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        netloc=parsed.netloc or "",
    )


def is_ip_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_insecure_http(scheme: str) -> bool:
    return scheme.lower() == "http"


def is_excessive_length(url: str, threshold: int = 200) -> bool:
    return len(url) > threshold


def subdomain_label_count(hostname: str | None) -> int:
    if not hostname:
        return 0
    labels = [label for label in hostname.split(".") if label]
    return max(len(labels) - 2, 0)


def has_excessive_subdomains(hostname: str | None, threshold: int = 3) -> bool:
    return subdomain_label_count(hostname) > threshold


def is_obfuscated(url: str, min_encoded: int = 4, min_ratio: float = 0.15) -> bool:
    """Flags heavy percent-encoding, not ordinary one-off encoded characters."""
    if not url:
        return False
    matches = _PERCENT_ENCODED_RE.findall(url)
    if len(matches) < min_encoded:
        return False
    ratio = (len(matches) * 3) / len(url)
    return ratio >= min_ratio


def find_suspicious_query_params(query: str) -> list[dict]:
    if not query:
        return []
    findings = []
    params = parse_qs(query, keep_blank_values=True)
    for name, values in params.items():
        lowered_name = name.lower()
        if lowered_name in _REDIRECT_PARAM_NAMES:
            reason = "redirect_target_like_url"
        elif lowered_name in _SENSITIVE_PARAM_NAMES:
            reason = "sensitive_parameter_with_url_value"
        else:
            continue
        for value in values:
            if _looks_like_external_target(value):
                findings.append({"parameter": name, "value": value, "reason": reason})
    return findings


def _looks_like_external_target(value: str) -> bool:
    decoded = unquote(value).strip()
    if not decoded:
        return False
    lowered = decoded.lower()
    return lowered.startswith("http://") or lowered.startswith("https://") or lowered.startswith("//")


def has_sensitive_path_keyword(path: str) -> str | None:
    if not path:
        return None
    lowered = path.lower()
    stripped = lowered.strip("/")
    for keyword in _SENSITIVE_PATH_KEYWORDS:
        if stripped == keyword or f"/{keyword}" in lowered:
            return keyword
    return None


def has_other_suspicious_signal(parsed: ParsedUrl) -> bool:
    """Used by SUSPICIOUS_URL_PATH to require combination with another
    structural signal, without depending on other rules' evaluation order."""
    return (
        is_ip_host(parsed.hostname)
        or is_insecure_http(parsed.scheme)
        or has_excessive_subdomains(parsed.hostname)
        or is_excessive_length(parsed.original)
        or is_obfuscated(parsed.original)
    )
