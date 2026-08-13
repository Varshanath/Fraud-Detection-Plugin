from app.config import Settings, get_settings


def test_default_settings_load_without_env():
    settings = Settings(_env_file=None)
    assert settings.app_name == "Fraud Detection Platform"
    assert settings.postgres_host == "localhost"
    assert settings.database_url.startswith("postgresql+psycopg://")


def test_env_vars_override_defaults(monkeypatch):
    monkeypatch.setenv("POSTGRES_DB", "override_db")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.postgres_db == "override_db"
        assert "override_db" in settings.database_url
    finally:
        get_settings.cache_clear()


def test_get_settings_is_cached():
    get_settings.cache_clear()
    try:
        first = get_settings()
        second = get_settings()
        assert first is second
    finally:
        get_settings.cache_clear()
