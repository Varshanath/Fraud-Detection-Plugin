import logging
from typing import Protocol

from app.agent.enums import InvestigationStatus, Uncertainty
from app.agent.investigation import select_tools_for
from app.agent.models import (
    AgentReasoningResult,
    InvestigationContext,
    InvestigationResult,
    ToolResult,
)
from app.agent.tool_registry import ToolRegistry, build_default_tool_registry
from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence

logger = logging.getLogger(__name__)


class AgentReasoner(Protocol):
    """The LLM boundary. A production implementation (not built in this
    phase) would render a prompt (see app.agent.prompts) and call a real
    model here. AgentInvestigationEngine only depends on this Protocol, not
    on any concrete reasoner.
    """

    def reason(
        self, context: InvestigationContext, tool_results: list[ToolResult]
    ) -> AgentReasoningResult: ...


class FakeAgentReasoner:
    """Deterministic stand-in for a real LLM reasoner. Reasons only over the
    structured dict fields already present in `ToolResult.data` -- never
    over raw free text -- so untrusted event content has no code path
    through which it could influence behavior, regardless of what it says.
    """

    def reason(
        self, context: InvestigationContext, tool_results: list[ToolResult]
    ) -> AgentReasoningResult:
        findings: list[str] = []
        additional_evidence: list[DetectionEvidence] = []

        for result in tool_results:
            if not result.success:
                findings.append(f"Tool '{result.tool_name}' failed; unable to inspect that area.")
                continue

            data = result.data
            if result.tool_name == "inspect_sender":
                self._reason_about_sender(data, findings, additional_evidence)
            elif result.tool_name == "inspect_urls":
                self._reason_about_urls(data, findings)
            elif result.tool_name == "inspect_content":
                findings.append(
                    "Reviewed message content; no additional structural signal identified."
                )
            elif result.tool_name == "inspect_existing_evidence":
                total = data.get("total_count", 0)
                findings.append(f"Reviewed {total} existing evidence item(s) for consistency.")

        uncertainty = Uncertainty.LOW if additional_evidence else Uncertainty.MEDIUM
        summary = (
            f"Investigated using {len(tool_results)} tool(s); "
            f"{len(additional_evidence)} new evidence item(s) produced."
        )
        return AgentReasoningResult(
            summary=summary,
            findings=findings,
            additional_evidence=additional_evidence,
            uncertainty=uncertainty,
            recommended_reassessment=bool(additional_evidence),
        )

    @staticmethod
    def _reason_about_sender(data: dict, findings: list[str], additional_evidence: list) -> None:
        if data.get("reply_to_domain_matches_sender") is False:
            findings.append("Reply-to domain differs from sender domain.")
            already_flagged = any(
                item["rule_id"] == "SENDER_REPLY_TO_MISMATCH"
                for item in data.get("existing_sender_evidence", [])
            )
            if not already_flagged:
                additional_evidence.append(
                    DetectionEvidence(
                        rule_id="AGENT_SENDER_REPLY_TO_MISMATCH",
                        category=EvidenceCategory.SENDER_SPOOFING,
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        description=(
                            "Investigation confirmed the reply-to domain differs from the "
                            "sender domain."
                        ),
                        details={
                            "sender_domain": data.get("sender_domain"),
                            "reply_to_domain": data.get("reply_to_domain"),
                        },
                    )
                )
        else:
            findings.append("Sender and reply-to domains are consistent or not comparable.")

    @staticmethod
    def _reason_about_urls(data: dict, findings: list[str]) -> None:
        url_count = data.get("url_count", 0)
        existing = data.get("existing_url_evidence", [])
        if url_count > 0 and not existing:
            findings.append(f"{url_count} URL(s) present but no existing URL evidence was recorded.")
        else:
            findings.append(f"Reviewed {url_count} URL(s); consistent with existing evidence.")


class AgentInvestigationEngine:
    """Runs a bounded, single-pass investigation: select tools -> execute
    tools -> reason over tool output -> return a structured
    InvestigationResult. Never raises -- tool failures and reasoner
    failures/malformed results are all caught and represented in the
    result, matching the failure-isolation pattern already used by
    RuleEngine/DetectionEngine. Not recursive: each tool runs at most once,
    the reasoner runs at most once, there is no loop back into this engine.
    """

    def __init__(
        self,
        reasoner: AgentReasoner | None = None,
        tool_registry: ToolRegistry | None = None,
        max_tool_calls: int = 4,
    ) -> None:
        self.reasoner = reasoner or FakeAgentReasoner()
        self.tool_registry = tool_registry or build_default_tool_registry()
        self.max_tool_calls = max_tool_calls

    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        event_id = context.event.event_id
        reason = context.escalation_decision.reason
        logger.info("investigation started event_id=%s escalation_reason=%s", event_id, reason)

        candidate_tools = select_tools_for(context.escalation_decision, context.detection_coverage)
        selected_tools = candidate_tools[: self.max_tool_calls]
        budget_reached = len(candidate_tools) > self.max_tool_calls
        if budget_reached:
            logger.info(
                "investigation budget reached event_id=%s max_tool_calls=%d candidate_count=%d",
                event_id,
                self.max_tool_calls,
                len(candidate_tools),
            )
        logger.info("tools selected event_id=%s tools=%s", event_id, selected_tools)

        tool_results: list[ToolResult] = []
        any_tool_failed = False
        for name in selected_tools:
            tool = self.tool_registry.get(name)
            if tool is None:
                continue
            try:
                data = tool.fn(context)
            except Exception:
                logger.exception("tool failed event_id=%s tool=%s", event_id, name)
                tool_results.append(
                    ToolResult(tool_name=name, success=False, data={}, error="tool execution failed")
                )
                any_tool_failed = True
                continue
            logger.info("tool succeeded event_id=%s tool=%s", event_id, name)
            tool_results.append(ToolResult(tool_name=name, success=True, data=data))

        try:
            reasoning = self.reasoner.reason(context, tool_results)
            status = (
                InvestigationStatus.PARTIAL
                if (budget_reached or any_tool_failed)
                else InvestigationStatus.COMPLETED
            )
            result = InvestigationResult(
                status=status,
                summary=reasoning.summary,
                findings=list(reasoning.findings),
                additional_evidence=list(reasoning.additional_evidence),
                uncertainty=reasoning.uncertainty,
                recommended_reassessment=bool(reasoning.recommended_reassessment),
            )
        except Exception:
            logger.exception("reasoner failed event_id=%s", event_id)
            result = InvestigationResult(
                status=InvestigationStatus.FAILED,
                summary="Investigation failed due to an internal reasoning error.",
                findings=[],
                additional_evidence=[],
                uncertainty=Uncertainty.HIGH,
                recommended_reassessment=False,
            )

        logger.info(
            "investigation completed event_id=%s status=%s findings=%d evidence=%d",
            event_id,
            result.status,
            len(result.findings),
            len(result.additional_evidence),
        )
        return result
