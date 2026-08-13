import ast
import inspect

from app.detection.enums import EvidenceCategory, Severity
from app.detection.evidence import DetectionEvidence
from app.detection.rule_engine import RuleEngine
from app.detection.rules.urgency_pressure import UrgencyPressureRule
from tests.detection_fixtures import build_event


class _AlwaysFiresRule:
    rule_id = "ALWAYS_FIRES"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = "Always fires for testing."

    def evaluate(self, event):
        return DetectionEvidence(
            rule_id=self.rule_id,
            category=self.category,
            severity=Severity.LOW,
            confidence=0.5,
            description=self.description,
        )


class _AlwaysRaisesRule:
    rule_id = "ALWAYS_RAISES"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = "Always raises for testing rule isolation."

    def evaluate(self, event):
        raise RuntimeError("boom")


class _NeverFiresRule:
    rule_id = "NEVER_FIRES"
    category = EvidenceCategory.SOCIAL_ENGINEERING
    description = "Never fires."

    def evaluate(self, event):
        return None


def test_no_rules_registered_returns_empty_evidence():
    engine = RuleEngine()
    result = engine.evaluate(build_event())
    assert result.evidence == []
    assert result.failed_rule_ids == []


def test_one_triggered_rule():
    engine = RuleEngine(rules=[_AlwaysFiresRule()])
    result = engine.evaluate(build_event())
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "ALWAYS_FIRES"


def test_multiple_triggered_rules():
    engine = RuleEngine(rules=[_AlwaysFiresRule(), UrgencyPressureRule()])
    event = build_event(content="Act immediately, final warning.")
    result = engine.evaluate(event)
    rule_ids = {e.rule_id for e in result.evidence}
    assert "ALWAYS_FIRES" in rule_ids
    assert "URGENCY_PRESSURE" in rule_ids


def test_rule_that_never_fires_produces_no_evidence():
    engine = RuleEngine(rules=[_NeverFiresRule()])
    result = engine.evaluate(build_event())
    assert result.evidence == []


def test_registration_via_constructor_and_register_method():
    engine = RuleEngine(rules=[_AlwaysFiresRule()])
    engine.register(_NeverFiresRule())
    assert {r.rule_id for r in engine.rules} == {"ALWAYS_FIRES", "NEVER_FIRES"}


def test_rule_isolation_failing_rule_does_not_break_others():
    engine = RuleEngine(rules=[_AlwaysRaisesRule(), _AlwaysFiresRule()])
    result = engine.evaluate(build_event())
    assert "ALWAYS_RAISES" in result.failed_rule_ids
    assert len(result.evidence) == 1
    assert result.evidence[0].rule_id == "ALWAYS_FIRES"


def test_deterministic_output_for_same_event():
    engine = RuleEngine(rules=[UrgencyPressureRule()])
    event = build_event(content="Act immediately, final warning.")
    first = engine.evaluate(event)
    second = engine.evaluate(event)
    assert first.evidence == second.evidence


def test_result_carries_event_id():
    engine = RuleEngine()
    event = build_event()
    result = engine.evaluate(event)
    assert result.event_id == event.event_id


def test_rule_engine_has_no_database_coupling():
    source = inspect.getsource(RuleEngine)
    tree = ast.parse(source)
    param_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                param_names.add(arg.arg)
    assert "db" not in param_names
    assert "session" not in param_names
