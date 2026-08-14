import json

from app.detection.enums import EvidenceCategory, Severity


class FakeLLMClient:
    """Test double for app.agent.llm_reasoner.LLMClient. Records every call
    so tests can assert call count and passed-through parameters. Never
    touches a network.
    """

    def __init__(self, response_text: str | None = None, exception: Exception | None = None):
        self.response_text = response_text
        self.exception = exception
        self.calls: list[dict] = []

    def complete(self, prompt: str, *, model: str, max_output_tokens: int, timeout: float) -> str:
        self.calls.append(
            {
                "prompt": prompt,
                "model": model,
                "max_output_tokens": max_output_tokens,
                "timeout": timeout,
            }
        )
        if self.exception is not None:
            raise self.exception
        return self.response_text


def valid_llm_response_json(
    findings: list[dict] | None = None,
    recommended_reassessment: bool = True,
    uncertainty: str = "MEDIUM",
    summary: str = "Investigation complete.",
    status: str = "COMPLETED",
) -> str:
    if findings is None:
        findings = [
            {
                "finding_type": EvidenceCategory.SENDER_SPOOFING.value,
                "description": "Reply-to domain differs from sender domain.",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.6,
                "supporting_observations": ["reply_to_domain_matches_sender=False"],
            }
        ]
    return json.dumps(
        {
            "status": status,
            "summary": summary,
            "findings": findings,
            "uncertainty": uncertainty,
            "recommended_reassessment": recommended_reassessment,
        }
    )
