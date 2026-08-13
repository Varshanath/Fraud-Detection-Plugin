"""Controlled investigation tools. Each tool is a plain, deterministic,
local function operating only on data already present in `InvestigationContext`
(the ingested SecurityEvent + prior DetectionEvidence). No I/O of any kind --
no network, no DNS, no filesystem, no database, no subprocess.
"""

from typing import Any

from app.agent.models import InvestigationContext
from app.detection.enums import EvidenceCategory
from app.detection.url_parsing import parse_url

_CONTENT_CATEGORIES = {
    EvidenceCategory.SOCIAL_ENGINEERING,
    EvidenceCategory.CREDENTIAL_THEFT,
    EvidenceCategory.FINANCIAL_FRAUD,
    EvidenceCategory.SENSITIVE_INFORMATION_REQUEST,
    EvidenceCategory.SUSPICIOUS_ATTACHMENT,
}


def _domain_of(email: str | None) -> str | None:
    if not email or "@" not in email:
        return None
    return email.rsplit("@", 1)[-1].lower()


def _evidence_summary(evidence) -> list[dict[str, Any]]:
    return [
        {"rule_id": e.rule_id, "severity": e.severity.value, "confidence": e.confidence}
        for e in evidence
    ]


def inspect_sender(context: InvestigationContext) -> dict[str, Any]:
    event = context.event
    reply_to_domain = _domain_of(event.reply_to)
    sender_domain = event.sender_domain
    reply_to_domain_matches_sender = (
        None if reply_to_domain is None or sender_domain is None
        else reply_to_domain == sender_domain.lower()
    )
    existing_sender_evidence = [
        e for e in context.evidence if e.category == EvidenceCategory.SENDER_SPOOFING
    ]
    return {
        "sender_email": event.sender_email,
        "sender_domain": sender_domain,
        "sender_display_name": event.sender_display_name,
        "reply_to": event.reply_to,
        "reply_to_domain": reply_to_domain,
        "reply_to_domain_matches_sender": reply_to_domain_matches_sender,
        "existing_sender_evidence": _evidence_summary(existing_sender_evidence),
    }


def inspect_urls(context: InvestigationContext) -> dict[str, Any]:
    event = context.event
    parsed_urls = []
    for url in event.urls:
        parsed = parse_url(url)
        parsed_urls.append(
            {
                "original": url,
                "hostname": parsed.hostname if parsed else None,
                "scheme": parsed.scheme if parsed else None,
                "path": parsed.path if parsed else None,
                "query": parsed.query if parsed else None,
                "parsed": parsed is not None,
            }
        )
    existing_url_evidence = [
        e for e in context.evidence if e.category == EvidenceCategory.SUSPICIOUS_URL
    ]
    return {
        "url_count": len(event.urls),
        "urls": parsed_urls,
        "existing_url_evidence": _evidence_summary(existing_url_evidence),
    }


def inspect_content(context: InvestigationContext) -> dict[str, Any]:
    event = context.event
    existing_content_evidence = [e for e in context.evidence if e.category in _CONTENT_CATEGORIES]
    return {
        "subject": event.subject,
        "content": event.content,
        "existing_content_evidence": _evidence_summary(existing_content_evidence),
    }


def inspect_existing_evidence(context: InvestigationContext) -> dict[str, Any]:
    by_category: dict[str, list[str]] = {}
    by_rule_id: dict[str, dict[str, Any]] = {}
    for item in context.evidence:
        by_category.setdefault(item.category.value, []).append(item.rule_id)
        by_rule_id[item.rule_id] = {
            "category": item.category.value,
            "severity": item.severity.value,
            "confidence": item.confidence,
        }
    return {
        "total_count": len(context.evidence),
        "by_category": by_category,
        "by_rule_id": by_rule_id,
    }
