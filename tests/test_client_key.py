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


@pytest.mark.parametrize(
    "pasted",
    [
        "sk-ant-abc\n",
        "  sk-ant-abc  ",
        '"sk-ant-abc"',
        "ANTHROPIC_API_KEY=sk-ant-abc",
        "ANTHROPIC_API_KEY = 'sk-ant-abc'",
    ],
)
def test_common_paste_mistakes_in_a_hosting_dashboard_are_absorbed(monkeypatch, pasted):
    # The first live deploy failed authentication; dashboards make these mistakes easy.
    monkeypatch.setenv("ANTHROPIC_API_KEY", pasted)
    assert client_module.load_api_key() == "sk-ant-abc"
