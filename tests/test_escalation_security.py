import ast
import builtins
import socket
from pathlib import Path

from app.orchestrator import AnalysisOrchestrator
from tests.detection_fixtures import phishing_credential_request

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


def test_no_escalation_module_imports_forbidden_dependencies():
    escalation_dir = Path(__file__).resolve().parent.parent / "app" / "escalation"
    offenders = {}
    for py_file in escalation_dir.rglob("*.py"):
        forbidden = _imported_modules(py_file) & _FORBIDDEN_MODULES
        if forbidden:
            offenders[str(py_file)] = forbidden
    assert offenders == {}


def test_orchestrator_module_imports_no_forbidden_dependencies():
    orchestrator_path = Path(__file__).resolve().parent.parent / "app" / "orchestrator.py"
    forbidden = _imported_modules(orchestrator_path) & _FORBIDDEN_MODULES
    assert forbidden == set()


def test_orchestrator_never_opens_a_network_socket_end_to_end(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("orchestrator attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(phishing_credential_request())
    assert result.risk_assessment.risk_score >= 0


def test_orchestrator_never_resolves_dns_end_to_end(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("orchestrator attempted a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", _raise_if_called)
    monkeypatch.setattr(socket, "gethostbyname", _raise_if_called)

    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(phishing_credential_request())
    assert result.escalation is not None


def test_orchestrator_never_opens_files(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("orchestrator attempted to open a file")

    monkeypatch.setattr(builtins, "open", _raise_if_called)

    orchestrator = AnalysisOrchestrator()
    result = orchestrator.evaluate(phishing_credential_request())
    assert result.detection_coverage.detectors_attempted == 3
