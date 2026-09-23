import json
from pathlib import Path

from guardian.agents.base import parse_findings
from guardian.agents.security import SecurityAgent
from guardian.diff_parser import parse_diff
from guardian.models import ToolFinding

SAMPLE_DIFF = (Path(__file__).parent / "fixtures" / "sample.diff").read_text()

TWO_FINDINGS = json.dumps(
    [
        {
            "file": "app/db.py",
            "line": 12,
            "severity": "block",
            "category": "sql-injection",
            "claim": "User input is interpolated into SQL via f-string.",
            "evidence": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            "confidence": 0.9,
        },
        {
            "file": "app/db.py",
            "line": 13,
            "severity": "nit",
            "category": "error-handling",
            "claim": "fetchone() result is not checked for None.",
            "evidence": "return conn.execute(query).fetchone()",
            "confidence": 0.4,
        },
    ]
)


class FakeClient:
    def __init__(self, response: str):
        self.response = response
        self.calls: list[dict] = []

    def complete(self, system: str, user: str, model: str) -> str:
        self.calls.append({"system": system, "user": user, "model": model})
        return self.response


def test_parses_well_formed_findings():
    findings = parse_findings(TWO_FINDINGS, agent="security")
    assert len(findings) == 2
    assert findings[0].category == "sql-injection"
    assert findings[0].agent == "security"


def test_drops_finding_missing_line():
    raw = json.dumps([{"file": "app/db.py", "severity": "block", "claim": "x", "confidence": 0.9}])
    assert parse_findings(raw, agent="security") == []


def test_drops_finding_missing_file():
    raw = json.dumps([{"line": 12, "severity": "block", "claim": "x", "confidence": 0.9}])
    assert parse_findings(raw, agent="security") == []


def test_returns_empty_list_for_garbage():
    assert parse_findings("I could not find any issues.", agent="security") == []


def test_extracts_json_from_markdown_fence():
    fenced = f"Here you go:\n```json\n{TWO_FINDINGS}\n```\n"
    assert len(parse_findings(fenced, agent="security")) == 2


def test_clamps_out_of_range_confidence():
    raw = json.dumps(
        [{"file": "a.py", "line": 1, "severity": "warn", "category": "c", "claim": "x",
          "evidence": "y", "confidence": 5}]
    )
    assert parse_findings(raw, agent="security")[0].confidence == 1.0


def test_unknown_severity_falls_back_to_nit():
    raw = json.dumps(
        [{"file": "a.py", "line": 1, "severity": "CATASTROPHIC", "category": "c", "claim": "x",
          "evidence": "y", "confidence": 0.5}]
    )
    assert parse_findings(raw, agent="security")[0].severity == "nit"


def test_review_returns_parsed_findings():
    client = FakeClient(TWO_FINDINGS)
    findings = SecurityAgent(client).review(parse_diff(SAMPLE_DIFF), tools=[])
    assert [f.category for f in findings] == ["sql-injection", "error-handling"]


def test_review_prompt_includes_diff_and_tool_findings():
    client = FakeClient(TWO_FINDINGS)
    tools = [ToolFinding("app/db.py", 12, "rule.sqli", "SQL injection", "block")]
    SecurityAgent(client).review(parse_diff(SAMPLE_DIFF), tools=tools)

    prompt = client.calls[0]["user"]
    assert "SELECT * FROM users" in prompt
    assert "rule.sqli" in prompt
