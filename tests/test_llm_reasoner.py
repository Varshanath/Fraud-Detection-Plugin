import json

import pytest
from pydantic import SecretStr

from app.agent.enums import Uncertainty
from app.agent.llm_reasoner import (
    AnthropicLLMClient,
    DisabledLLMReasoner,
    LLMInvestigationResponse,
    LLMReasoner,
    LLMResponseError,
    build_reasoner,
)
from app.config import Settings
from app.detection.evidence import DetectionEvidence
from app.escalation.enums import EscalationReason
from tests.agent_fixtures import make_escalation_decision, make_investigation_context
from tests.llm_fixtures import FakeLLMClient, valid_llm_response_json


def _settings(**overrides) -> Settings:
    defaults = dict(
        llm_enabled=False,
        llm_model="claude-sonnet-5",
        llm_api_key=None,
        llm_timeout=20.0,
        llm_max_output_tokens=1024,
    )
    defaults.update(overrides)
    return Settings(**defaults)


# ---------------------------------------------------------------------------
# Configuration / factory
# ---------------------------------------------------------------------------


def test_build_reasoner_disabled_returns_disabled_reasoner():
    reasoner = build_reasoner(_settings(llm_enabled=False))
    assert isinstance(reasoner, DisabledLLMReasoner)


def test_build_reasoner_enabled_without_api_key_falls_back_to_disabled():
    reasoner = build_reasoner(_settings(llm_enabled=True, llm_api_key=None))
    assert isinstance(reasoner, DisabledLLMReasoner)


def test_build_reasoner_enabled_with_empty_api_key_falls_back_to_disabled():
    reasoner = build_reasoner(_settings(llm_enabled=True, llm_api_key=SecretStr("")))
    assert isinstance(reasoner, DisabledLLMReasoner)


def test_build_reasoner_enabled_with_api_key_returns_llm_reasoner():
    reasoner = build_reasoner(
        _settings(
            llm_enabled=True,
            llm_api_key=SecretStr("test-key"),
            llm_model="claude-opus-5",
            llm_timeout=5.0,
            llm_max_output_tokens=256,
        )
    )
    assert isinstance(reasoner, LLMReasoner)
    assert isinstance(reasoner.client, AnthropicLLMClient)
    assert reasoner.model == "claude-opus-5"
    assert reasoner.timeout == 5.0
    assert reasoner.max_output_tokens == 256


# ---------------------------------------------------------------------------
# DisabledLLMReasoner
# ---------------------------------------------------------------------------


def test_disabled_reasoner_returns_skipped_result_deterministically():
    reasoner = DisabledLLMReasoner()
    context = make_investigation_context()
    first = reasoner.reason(context, [])
    second = reasoner.reason(context, [])
    assert first == second
    assert first.skipped is True
    assert first.additional_evidence == []
    assert first.recommended_reassessment is False


# ---------------------------------------------------------------------------
# Structured output: valid case + mapping correctness
# ---------------------------------------------------------------------------


def test_valid_response_maps_to_agent_reasoning_result():
    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE)
    )
    result = reasoner.reason(context, [])

    assert len(client.calls) == 1
    assert result.summary == "Investigation complete."
    assert result.uncertainty == Uncertainty.MEDIUM
    assert result.recommended_reassessment is True
    assert len(result.additional_evidence) == 1
    evidence = result.additional_evidence[0]
    assert isinstance(evidence, DetectionEvidence)
    assert evidence.rule_id == "AGENT_LLM_SENDER_ANALYSIS"
    assert evidence.confidence == 0.6
    assert evidence.details["source"] == "llm_investigation"
    assert len(result.findings) == 1
    assert "SENDER_SPOOFING" in result.findings[0]


def test_content_category_finding_maps_to_content_analysis_rule_id():
    findings = [
        {
            "finding_type": "SOCIAL_ENGINEERING",
            "description": "Urgent tone combined with unusual request.",
            "severity": "MEDIUM",
            "confidence": 0.4,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result.additional_evidence[0].rule_id == "AGENT_LLM_CONTENT_ANALYSIS"


def test_url_category_finding_maps_to_url_analysis_rule_id():
    findings = [
        {
            "finding_type": "SUSPICIOUS_URL",
            "description": "URL path suggests credential harvesting.",
            "severity": "HIGH",
            "confidence": 0.7,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result.additional_evidence[0].rule_id == "AGENT_LLM_URL_ANALYSIS"


def test_no_findings_produces_no_evidence_and_no_reassessment():
    client = FakeLLMClient(
        response_text=valid_llm_response_json(findings=[], recommended_reassessment=False)
    )
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result.additional_evidence == []
    assert result.recommended_reassessment is False


# ---------------------------------------------------------------------------
# Structured output: malformed / out-of-bounds cases
# ---------------------------------------------------------------------------


def test_empty_response_raises():
    client = FakeLLMClient(response_text="")
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_whitespace_only_response_raises():
    client = FakeLLMClient(response_text="   \n  ")
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_malformed_json_raises():
    client = FakeLLMClient(response_text="{not valid json")
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_missing_required_field_raises():
    payload = json.loads(valid_llm_response_json())
    del payload["summary"]
    client = FakeLLMClient(response_text=json.dumps(payload))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_invalid_status_enum_raises():
    client = FakeLLMClient(response_text=valid_llm_response_json(status="NOT_A_REAL_STATUS"))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_invalid_uncertainty_enum_raises():
    client = FakeLLMClient(response_text=valid_llm_response_json(uncertainty="EXTREME"))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_invalid_finding_severity_enum_raises():
    findings = [
        {
            "finding_type": "SENDER_SPOOFING",
            "description": "x",
            "severity": "SUPER_HIGH",
            "confidence": 0.5,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_invalid_finding_category_enum_raises():
    findings = [
        {
            "finding_type": "NOT_A_REAL_CATEGORY",
            "description": "x",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_confidence_below_zero_raises():
    findings = [
        {
            "finding_type": "SENDER_SPOOFING",
            "description": "x",
            "severity": "MEDIUM",
            "confidence": -0.1,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_confidence_above_one_raises():
    findings = [
        {
            "finding_type": "SENDER_SPOOFING",
            "description": "x",
            "severity": "MEDIUM",
            "confidence": 1.5,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_excessive_findings_count_raises():
    findings = [
        {
            "finding_type": "SENDER_SPOOFING",
            "description": "x",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "supporting_observations": [],
        }
        for _ in range(20)
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_oversized_description_raises():
    findings = [
        {
            "finding_type": "SENDER_SPOOFING",
            "description": "x" * 5000,
            "severity": "MEDIUM",
            "confidence": 0.5,
            "supporting_observations": [],
        }
    ]
    client = FakeLLMClient(response_text=valid_llm_response_json(findings=findings))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_oversized_summary_raises():
    client = FakeLLMClient(response_text=valid_llm_response_json(summary="x" * 5000))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


def test_oversized_raw_response_raises():
    huge = valid_llm_response_json(summary="x" * 30000)
    client = FakeLLMClient(response_text=huge)
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(LLMResponseError):
        reasoner.reason(make_investigation_context(), [])


# ---------------------------------------------------------------------------
# Client failures propagate (caught by AgentInvestigationEngine, not here)
# ---------------------------------------------------------------------------


def test_client_exception_propagates():
    client = FakeLLMClient(exception=TimeoutError("simulated timeout"))
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    with pytest.raises(TimeoutError):
        reasoner.reason(make_investigation_context(), [])


# ---------------------------------------------------------------------------
# Token/call controls
# ---------------------------------------------------------------------------


def test_exactly_one_client_call_per_reason_call():
    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    reasoner.reason(make_investigation_context(), [])
    assert len(client.calls) == 1


def test_model_timeout_and_max_tokens_passed_through():
    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-opus-5", max_output_tokens=42, timeout=7.5)
    reasoner.reason(make_investigation_context(), [])
    call = client.calls[0]
    assert call["model"] == "claude-opus-5"
    assert call["max_output_tokens"] == 42
    assert call["timeout"] == 7.5


# ---------------------------------------------------------------------------
# Structural proof: the LLM cannot set risk_score/classification/action
# ---------------------------------------------------------------------------


def test_llm_response_schema_has_no_risk_authority_fields():
    fields = set(LLMInvestigationResponse.model_fields.keys())
    assert "risk_score" not in fields
    assert "classification" not in fields
    assert "recommended_action" not in fields
