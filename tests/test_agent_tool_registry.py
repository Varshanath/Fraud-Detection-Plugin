from app.agent.tool_registry import Tool, ToolRegistry, build_default_tool_registry


def test_default_registry_has_exactly_the_four_required_tools():
    registry = build_default_tool_registry()
    assert set(registry.available_tools()) == {
        "inspect_sender",
        "inspect_urls",
        "inspect_content",
        "inspect_existing_evidence",
    }


def test_unregistered_tool_lookup_returns_none():
    registry = build_default_tool_registry()
    assert registry.get("shell") is None
    assert registry.get("subprocess") is None
    assert registry.get("delete_file") is None
    assert registry.get("execute_python") is None
    assert registry.get("http_get") is None


def test_no_shell_filesystem_or_network_tool_registered():
    registry = build_default_tool_registry()
    forbidden_substrings = ("shell", "subprocess", "exec", "eval", "file", "http", "socket", "db", "sql")
    for name in registry.available_tools():
        lowered = name.lower()
        assert not any(bad in lowered for bad in forbidden_substrings), name


def test_every_registered_tool_has_metadata():
    registry = build_default_tool_registry()
    for name in registry.available_tools():
        tool = registry.get(name)
        assert tool.name == name
        assert tool.description
        assert tool.input_schema
        assert tool.output_schema
        assert callable(tool.fn)


def test_registry_only_exposes_registered_tools_via_register():
    registry = ToolRegistry()
    assert registry.available_tools() == []
    registry.register(
        Tool(
            name="custom_tool",
            description="test",
            input_schema="x",
            output_schema="y",
            fn=lambda context: {},
        )
    )
    assert registry.available_tools() == ["custom_tool"]
    assert registry.get("custom_tool") is not None
