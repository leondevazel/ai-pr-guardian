import json
import re

from guardian.llm.client import HAIKU
from guardian.models import Finding, PRContext, ToolFinding

VALID_SEVERITIES = {"block", "warn", "nit"}

OUTPUT_CONTRACT = """
Respond with a JSON array and nothing else. Each element:
{"file": str, "line": int, "severity": "block"|"warn"|"nit", "category": str,
 "claim": str, "evidence": str, "confidence": float}

Rules:
- "line" must be a line number that appears in the diff. A finding without a concrete
  file and line is worthless and will be discarded.
- "evidence" must be a literal quote of the code you are judging, copied from the diff.
- "confidence" is your own calibration, 0.0-1.0. Be honest: 0.9 means you would stake
  your reputation on it, 0.5 means it is worth a human glance.
- If you find nothing in your mandate, return []. An empty array is a valid, useful answer.
"""


def parse_findings(raw: str, agent: str) -> list[Finding]:
    """Never raises. Anything malformed or unlocatable is dropped, by design (agent.md §2)."""
    data = _extract_json_array(raw)
    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue
        file, line = item.get("file"), item.get("line")
        if not file or not isinstance(line, int) or isinstance(line, bool):
            continue
        severity = item.get("severity")
        findings.append(
            Finding(
                agent=agent,
                file=str(file),
                line=line,
                severity=severity if severity in VALID_SEVERITIES else "nit",
                category=str(item.get("category", "unspecified")),
                claim=str(item.get("claim", "")),
                evidence=str(item.get("evidence", "")),
                confidence=_clamp(item.get("confidence", 0.5)),
            )
        )
    return findings


def _extract_json_array(raw: str) -> list:
    fenced = re.search(r"```(?:json)?\s*(.+?)```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw
    start, end = candidate.find("["), candidate.rfind("]")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        parsed = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _clamp(value) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.5


class ReviewAgent:
    name: str
    mandate: str
    must_not: str
    model: str = HAIKU

    def __init__(self, client):
        self.client = client

    def review(self, ctx: PRContext, tools: list[ToolFinding]) -> list[Finding]:
        raw = self.client.complete(
            system=self._system_prompt(),
            user=self._user_prompt(ctx, tools),
            model=self.model,
        )
        return parse_findings(raw, agent=self.name)

    def _system_prompt(self) -> str:
        return (
            f"You are the {self.name} reviewer on a pull-request review board.\n"
            f"Your mandate: {self.mandate}\n"
            f"You must NOT: {self.must_not}\n"
            "Other reviewers cover the areas outside your mandate. Staying in your lane is not "
            "laziness, it is the point: duplicate and off-mandate findings are what make review "
            "tools unusable.\n"
            f"{OUTPUT_CONTRACT}"
        )

    def _user_prompt(self, ctx: PRContext, tools: list[ToolFinding]) -> str:
        return "\n\n".join([self._render_diff(ctx), self._render_tools(tools), *self._extra_context(ctx)])

    def _extra_context(self, ctx: PRContext) -> list[str]:
        return []

    @staticmethod
    def _render_diff(ctx: PRContext) -> str:
        blocks = ["## Diff under review"]
        for file in ctx.files:
            blocks.append(f"### {file.path}")
            for hunk in file.hunks:
                numbered = "\n".join(f"{line_no}: {text}" for line_no, text in hunk.added_lines)
                blocks.append(f"Added lines (line_number: code):\n{numbered}")
                blocks.append(f"Full hunk with context:\n{hunk.context}")
        return "\n".join(blocks)

    @staticmethod
    def _render_tools(tools: list[ToolFinding]) -> str:
        if not tools:
            return (
                "## Static analyzer findings\n(none — note that the analyzer's rules miss whole "
                "vulnerability classes, so absence of findings is not evidence of safety)"
            )
        lines = "\n".join(
            f"- {t.file}:{t.line} [{t.severity}] {t.rule_id} — {t.message}" for t in tools
        )
        return f"## Static analyzer findings\n{lines}"
