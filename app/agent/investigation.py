from app.escalation.detection_coverage import DetectionCoverage
from app.escalation.enums import EscalationReason
from app.escalation.escalation_decision import EscalationDecision

_REASON_TOOLS: dict[EscalationReason, list[str]] = {
    EscalationReason.HIGH_RISK_LOW_CONFIDENCE: [
        "inspect_existing_evidence",
        "inspect_sender",
        "inspect_urls",
    ],
    EscalationReason.AMBIGUOUS_SIGNAL: [
        "inspect_existing_evidence",
        "inspect_sender",
        "inspect_urls",
    ],
    EscalationReason.LOW_CONFIDENCE: ["inspect_existing_evidence", "inspect_content"],
    EscalationReason.INSUFFICIENT_EVIDENCE: [
        "inspect_sender",
        "inspect_urls",
        "inspect_content",
    ],
    EscalationReason.NOVEL_SIGNAL: ["inspect_existing_evidence"],
}

# Which tool re-inspects the area a given detector is responsible for --
# used when INSUFFICIENT_DETECTOR_COVERAGE so the agent focuses on exactly
# the missing information rather than running every tool blindly.
_DETECTOR_TO_TOOL: dict[str, str] = {
    "SenderAnalyzer": "inspect_sender",
    "URLAnalyzer": "inspect_urls",
    "RuleEngine": "inspect_content",
}

_DEFAULT_TOOLS = ["inspect_existing_evidence"]


def select_tools_for(
    escalation_decision: EscalationDecision, detection_coverage: DetectionCoverage
) -> list[str]:
    if escalation_decision.reason == EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE:
        tools = ["inspect_existing_evidence"]
        for failed_name in detection_coverage.failed_detector_names:
            tool_name = _DETECTOR_TO_TOOL.get(failed_name)
            if tool_name and tool_name not in tools:
                tools.append(tool_name)
        return tools

    if escalation_decision.reason is None:
        return list(_DEFAULT_TOOLS)

    return list(_REASON_TOOLS.get(escalation_decision.reason, _DEFAULT_TOOLS))


_OBJECTIVE_FOR_REASON: dict[EscalationReason, str] = {
    EscalationReason.HIGH_RISK_LOW_CONFIDENCE: (
        "Confirm or weaken the current high-risk assessment by looking for "
        "corroborating or contradicting sender/URL/evidence signals."
    ),
    EscalationReason.AMBIGUOUS_SIGNAL: (
        "Resolve an ambiguous mid-range risk assessment by inspecting sender, "
        "URL, and existing evidence for anything the deterministic detectors "
        "under-weighted."
    ),
    EscalationReason.LOW_CONFIDENCE: (
        "Increase or decrease confidence by re-examining the message content "
        "and existing evidence for consistency."
    ),
    EscalationReason.INSUFFICIENT_EVIDENCE: (
        "Broadly investigate sender, URLs, and content since very little "
        "evidence currently exists for this event."
    ),
    EscalationReason.INSUFFICIENT_DETECTOR_COVERAGE: (
        "Compensate for one or more detectors that failed to run by directly "
        "inspecting the area they would have covered."
    ),
    EscalationReason.NOVEL_SIGNAL: (
        "Review existing evidence for a signal pattern not covered by "
        "current deterministic rules."
    ),
}


def determine_investigation_objective(escalation_decision: EscalationDecision) -> str:
    if escalation_decision.reason is None:
        return "Investigate this event; no specific escalation reason was recorded."
    return _OBJECTIVE_FOR_REASON.get(
        escalation_decision.reason,
        "Investigate this event using the available tools.",
    )
