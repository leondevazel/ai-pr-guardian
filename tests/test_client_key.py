import pytest

from guardian.llm import client as client_module


def test_environment_variable_wins(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    assert client_module.load_api_key() == "from-env"


def test_reads_key_from_dotenv_when_env_is_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text('ANTHROPIC_API_KEY="from-dotenv"\n', encoding="utf-8")
    monkeypatch.setattr(client_module, "__file__", str(tmp_path / "src/guardian/llm/client.py"))

    assert client_module.load_api_key() == "from-dotenv"


def test_missing_key_raises_with_instructions(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(client_module, "__file__", str(tmp_path / "src/guardian/llm/client.py"))

    with pytest.raises(RuntimeError, match=".env"):
        client_module.load_api_key()
