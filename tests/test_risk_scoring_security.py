import ast
import builtins
import socket
from pathlib import Path

from app.pipeline import DetectionPipeline
from app.risk_scoring.risk_engine import RiskEngine
from tests.detection_fixtures import phishing_credential_request
from tests.risk_fixtures import make_evidence

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


def test_no_risk_scoring_module_imports_forbidden_dependencies():
    risk_scoring_dir = Path(__file__).resolve().parent.parent / "app" / "risk_scoring"
    offenders = {}
    for py_file in risk_scoring_dir.rglob("*.py"):
        forbidden = _imported_modules(py_file) & _FORBIDDEN_MODULES
        if forbidden:
            offenders[str(py_file)] = forbidden
    assert offenders == {}


def test_pipeline_module_imports_no_forbidden_dependencies():
    pipeline_path = Path(__file__).resolve().parent.parent / "app" / "pipeline.py"
    forbidden = _imported_modules(pipeline_path) & _FORBIDDEN_MODULES
    assert forbidden == set()


def test_risk_engine_never_opens_a_network_socket(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("RiskEngine attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    engine = RiskEngine()
    evidence = [make_evidence(rule_id="A"), make_evidence(rule_id="B")]
    assessment = engine.evaluate(evidence)
    assert assessment.risk_score >= 0


def test_risk_engine_never_opens_files(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("RiskEngine attempted to open a file")

    monkeypatch.setattr(builtins, "open", _raise_if_called)

    engine = RiskEngine()
    assessment = engine.evaluate([make_evidence(rule_id="A")])
    assert assessment.risk_score >= 0


def test_pipeline_never_opens_a_network_socket_end_to_end(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("pipeline attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    pipeline = DetectionPipeline()
    result = pipeline.evaluate(phishing_credential_request())
    assert result.risk_assessment.risk_score >= 0


def test_pipeline_never_resolves_dns_end_to_end(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("pipeline attempted a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", _raise_if_called)
    monkeypatch.setattr(socket, "gethostbyname", _raise_if_called)

    pipeline = DetectionPipeline()
    result = pipeline.evaluate(phishing_credential_request())
    assert result.risk_assessment.risk_score >= 0
