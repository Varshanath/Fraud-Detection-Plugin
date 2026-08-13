from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.agent.models import InvestigationContext
from app.agent.tools import inspect_content, inspect_existing_evidence, inspect_sender, inspect_urls


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: str
    output_schema: str
    fn: Callable[[InvestigationContext], dict[str, Any]]


class ToolRegistry:
    """Enforces that the agent can only ever invoke approved, registered
    tools -- never an arbitrary function. There is no method here that
    accepts and executes a caller-supplied callable; the only way a
    function runs is via a `Tool` object that was `register()`-ed ahead of
    time by application code, and the only way to invoke it is `get(name).fn`
    for a name that came from `available_tools()`.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def available_tools(self) -> list[str]:
        return list(self._tools.keys())


def build_default_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        Tool(
            name="inspect_sender",
            description="Inspect sender email/domain/reply-to/display-name and existing sender evidence.",
            input_schema="InvestigationContext",
            output_schema=(
                "{sender_email, sender_domain, sender_display_name, reply_to, reply_to_domain, "
                "reply_to_domain_matches_sender, existing_sender_evidence}"
            ),
            fn=inspect_sender,
        )
    )
    registry.register(
        Tool(
            name="inspect_urls",
            description="Inspect URLs present on the event (structure only, no fetching) and existing URL evidence.",
            input_schema="InvestigationContext",
            output_schema="{url_count, urls: [{original, hostname, scheme, path, query, parsed}], existing_url_evidence}",
            fn=inspect_urls,
        )
    )
    registry.register(
        Tool(
            name="inspect_content",
            description="Inspect subject/content and existing content-related evidence.",
            input_schema="InvestigationContext",
            output_schema="{subject, content, existing_content_evidence}",
            fn=inspect_content,
        )
    )
    registry.register(
        Tool(
            name="inspect_existing_evidence",
            description="Summarize existing DetectionEvidence grouped by category and rule_id.",
            input_schema="InvestigationContext",
            output_schema="{total_count, by_category, by_rule_id}",
            fn=inspect_existing_evidence,
        )
    )
    return registry
