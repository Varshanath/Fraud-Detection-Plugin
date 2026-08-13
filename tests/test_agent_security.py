import ast
import builtins
import socket
from pathlib import Path

from app.agent.engine import AgentInvestigationEngine
from app.escalation.enums import EscalationReason
from app.escalation.escalation_policy import EscalationPolicy
from app.orchestrator import AnalysisOrchestrator
from tests.agent_fixtures import make_escalation_decision, make_investigation_context
from tests.detection_fixtures import build_event, phishing_credential_request

_FORBIDDEN_MODULES = {
    "socket",
    "requests",
    "httpx",
    "urllib",
    "urllib.request",
    "http",
    "http.client",
    "subprocess",
    "ftplib",
    "smtplib",
    "sqlalchemy",
    "os",
    "shutil",
    "app.database",
    "app.ingestion.models",
}


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_no_agent_module_imports_forbidden_dependencies():
    agent_dir = Path(__file__).resolve().parent.parent / "app" / "agent"
    offenders = {}
    for py_file in agent_dir.rglob("*.py"):
        forbidden = _imported_modules(py_file) & _FORBIDDEN_MODULES
        if forbidden:
            offenders[str(py_file)] = forbidden
    assert offenders == {}


def test_no_agent_module_contains_eval_or_exec_calls():
    agent_dir = Path(__file__).resolve().parent.parent / "app" / "agent"
    offenders = []
    for py_file in agent_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec", "compile", "__import__"}:
                    offenders.append((str(py_file), node.func.id))
    assert offenders == []


def test_agent_engine_never_opens_a_network_socket(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("agent attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    context = make_investigation_context(
        event=build_event(sender_email="a@bank.com", sender_domain="bank.com", reply_to="r@evil.example"),
        escalation_decision=make_escalation_decision(reason=EscalationReason.HIGH_RISK_LOW_CONFIDENCE),
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)
    assert result.status is not None


def test_agent_engine_never_resolves_dns(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("agent attempted a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", _raise_if_called)
    monkeypatch.setattr(socket, "gethostbyname", _raise_if_called)

    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.INSUFFICIENT_EVIDENCE)
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)
    assert result.status is not None


def test_agent_engine_never_opens_files(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("agent attempted to open a file")

    monkeypatch.setattr(builtins, "open", _raise_if_called)

    context = make_investigation_context(
        escalation_decision=make_escalation_decision(reason=EscalationReason.LOW_CONFIDENCE)
    )
    engine = AgentInvestigationEngine()
    result = engine.investigate(context)
    assert result.status is not None


def test_orchestrator_with_escalating_event_never_opens_a_network_socket(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("orchestrator/agent attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    always_escalate_policy = EscalationPolicy(
        confidence_threshold=1.0,
        high_risk_score_threshold=70,
        medium_priority_score_threshold=40,
        min_evidence_count=1,
    )
    orchestrator = AnalysisOrchestrator(escalation_policy=always_escalate_policy)
    result = orchestrator.evaluate(phishing_credential_request())
    assert result.escalation is not None


def test_orchestrator_with_escalating_event_never_opens_files(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("orchestrator/agent attempted to open a file")

    monkeypatch.setattr(builtins, "open", _raise_if_called)

    always_escalate_policy = EscalationPolicy(
        confidence_threshold=1.0,
        high_risk_score_threshold=70,
        medium_priority_score_threshold=40,
        min_evidence_count=1,
    )
    orchestrator = AnalysisOrchestrator(escalation_policy=always_escalate_policy)
    result = orchestrator.evaluate(phishing_credential_request())
    assert result.escalation is not None
