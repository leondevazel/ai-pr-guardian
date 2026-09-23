import json
from pathlib import Path

from guardian.agents.architecture import ArchitectureAgent
from guardian.agents.business_logic import BusinessLogicAgent
from guardian.diff_parser import parse_diff
from guardian.tools.repo_context import FileContext

SAMPLE_DIFF = (Path(__file__).parent / "fixtures" / "sample.diff").read_text()

ONE_FINDING = json.dumps(
    [
        {
            "file": "app/db.py",
            "line": 12,
            "severity": "warn",
            "category": "boundary",
            "claim": "user_id is never validated.",
            "evidence": "def get_user(conn, user_id):",
            "confidence": 0.6,
        }
    ]
)

CONTEXT = FileContext(
    enclosing_function="def get_user(conn, user_id):\n    ...",
    related_tests=["tests/test_db.py"],
    imports=["sqlite3"],
)


class FakeClient:
    def __init__(self, response: str):
        self.response = response
        self.calls: list[dict] = []

    def complete(self, system: str, user: str, model: str) -> str:
        self.calls.append({"system": system, "user": user, "model": model})
        return self.response


def test_architecture_agent_tags_its_own_name():
    findings = ArchitectureAgent(FakeClient(ONE_FINDING)).review(parse_diff(SAMPLE_DIFF), tools=[])
    assert findings[0].agent == "architecture"


def test_business_logic_agent_tags_its_own_name():
    findings = BusinessLogicAgent(FakeClient(ONE_FINDING)).review(parse_diff(SAMPLE_DIFF), tools=[])
    assert findings[0].agent == "business_logic"


def test_architecture_prompt_includes_imports_not_tests():
    client = FakeClient(ONE_FINDING)
    ArchitectureAgent(client).review(parse_diff(SAMPLE_DIFF), tools=[], contexts=[CONTEXT])
    prompt = client.calls[0]["user"]
    assert "sqlite3" in prompt
    assert "tests/test_db.py" not in prompt


def test_business_logic_prompt_includes_enclosing_function_and_tests():
    client = FakeClient(ONE_FINDING)
    BusinessLogicAgent(client).review(parse_diff(SAMPLE_DIFF), tools=[], contexts=[CONTEXT])
    prompt = client.calls[0]["user"]
    assert "def get_user(conn, user_id):" in prompt
    assert "tests/test_db.py" in prompt


def test_agents_have_distinct_mandates():
    mandates = {
        ArchitectureAgent.mandate,
        BusinessLogicAgent.mandate,
    }
    assert len(mandates) == 2
