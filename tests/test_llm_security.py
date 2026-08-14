import ast
import builtins
import socket
from pathlib import Path

from app.agent.llm_reasoner import LLMReasoner
from tests.agent_fixtures import make_investigation_context
from tests.llm_fixtures import FakeLLMClient, valid_llm_response_json

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


def _module_path() -> Path:
    return Path(__file__).resolve().parent.parent / "app" / "agent" / "llm_reasoner.py"


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


def _top_level_imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in tree.body:  # only direct children of the module -- top level
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_llm_reasoner_module_imports_no_forbidden_dependencies():
    forbidden = _imported_modules(_module_path()) & _FORBIDDEN_MODULES
    assert forbidden == set()


def test_anthropic_is_not_imported_at_module_level():
    """The `anthropic` SDK must only be imported inside complete() -- lazily,
    at call time -- so importing llm_reasoner.py never requires the package
    installed. This is what keeps the test suite fully offline."""
    top_level = _top_level_imported_modules(_module_path())
    assert "anthropic" not in top_level


def test_anthropic_is_imported_somewhere_in_the_module():
    # Sanity check the lazy import genuinely exists (not just absent everywhere).
    all_imports = _imported_modules(_module_path())
    assert "anthropic" in all_imports


def test_llm_reasoner_never_opens_a_network_socket(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("LLMReasoner's own code attempted to open a network socket")

    monkeypatch.setattr(socket.socket, "connect", _raise_if_called)

    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result is not None


def test_llm_reasoner_never_resolves_dns(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("LLMReasoner's own code attempted a DNS lookup")

    monkeypatch.setattr(socket, "getaddrinfo", _raise_if_called)
    monkeypatch.setattr(socket, "gethostbyname", _raise_if_called)

    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result is not None


def test_llm_reasoner_never_opens_files(monkeypatch):
    def _raise_if_called(*args, **kwargs):
        raise AssertionError("LLMReasoner's own code attempted to open a file")

    monkeypatch.setattr(builtins, "open", _raise_if_called)

    client = FakeLLMClient(response_text=valid_llm_response_json())
    reasoner = LLMReasoner(client=client, model="claude-sonnet-5")
    result = reasoner.reason(make_investigation_context(), [])
    assert result is not None
