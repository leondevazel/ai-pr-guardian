import json
import re

from guardian.llm.client import SONNET
from guardian.agents.base import language_instruction
from guardian.models import Finding

SYSTEM = """You are the chief reviewer on a pull-request review board.

Three specialist reviewers (security, architecture, business_logic) have each filed findings and
then adjusted their own confidence after seeing their peers' work. Your job is selection, not
discovery: decide which findings a human reviewer should actually spend attention on.

You cannot add findings. You can only keep or drop the ones listed, by their key.

Drop a finding when: it is speculative, it restates another kept finding, it is a style nit dressed
up as a defect, or its evidence does not support its claim. Keeping everything is a failure — an
unfiltered list is exactly what makes review tools get ignored.

Respond with JSON and nothing else:
{"kept": [<keys of findings worth a human's attention, copied exactly>],
 "rationale": "<2-4 sentences citing the specific findings you kept and why the dropped ones did not survive>"}

The rationale is shown to the pull request's author. Refer to findings the way a person would —
"the SQL injection on demo/export.py:9" — not by their key.
"""


class ChiefReviewer:
    model = SONNET

    def __init__(self, client, language: str = "en"):
        self.client = client
        self.language = language

    def select(self, findings: list[Finding]) -> tuple[list[Finding], str]:
        if not findings:
            return [], "No findings survived the specialist round."

        raw = self.client.complete(
            system=SYSTEM + language_instruction(self.language),
            user=_render(findings),
            model=self.model,
        )
        kept_refs, rationale = _parse(raw)
        by_key = {finding_key(f, findings): f for f in findings}
        kept = []
        for ref in kept_refs:
            # Keys are the contract; a bare index is still honoured so older replies parse.
            chosen = by_key.get(ref) if isinstance(ref, str) else (
                findings[ref] if 0 <= ref < len(findings) else None
            )
            if chosen is not None and chosen not in kept:
                kept.append(chosen)
        return kept, scrub_indices(rationale)


def finding_key(finding: Finding, all_findings: list[Finding]) -> str:
    """agent@file:line, which reads as a location rather than a number.

    Run 01 of the web demo showed that labelling findings [0], [1] gets those labels echoed into
    the rationale in every language and phrasing ("finding 2", "indices 2 and 3", "[5]가"). A key
    made of what the finding already is leaves the model nothing arbitrary to repeat."""
    base = f"{finding.agent}@{finding.file}:{finding.line}"
    same = [f for f in all_findings if f"{f.agent}@{f.file}:{f.line}" == base]
    if len(same) == 1:
        return base
    return f"{base}#{same.index(finding) + 1}"


PAREN_INDEX = re.compile(
    r"\s*\((?:findings?|indices|index|items?|#)\s*\d+(?:\s*(?:,|and|&)\s*\d+)*\)", re.IGNORECASE
)
BARE_INDEX = re.compile(r"\b[Ff]indings?\s+\d+(?:\s*(?:,|and|&)\s*\d+)*\b")


def scrub_indices(rationale: str) -> str:
    """Remove "(finding 2)"-style references the prompt forbids but the model still writes.

    The author reading the PR comment never sees the numbered list, so an index is noise. Asking
    nicely reduced these; it did not stop them, so the rule is enforced here instead."""
    text = PAREN_INDEX.sub("", rationale)
    text = BARE_INDEX.sub("one finding", text)
    text = re.sub(r"(^|[.!?]\s+)one finding", lambda m: m.group(1) + "One finding", text)
    return re.sub(r"\s{2,}", " ", text).strip()


def _render(findings: list[Finding]) -> str:
    blocks = []
    for f in findings:
        blocks.append(
            f"key: {finding_key(f, findings)}\n"
            f"    severity={f.severity} confidence={f.confidence:.2f} category={f.category}\n"
            f"    claim: {f.claim}\n"
            f"    evidence: {f.evidence}"
        )
    return "## Findings\n" + "\n".join(blocks)


def _parse(raw: str) -> tuple[list[str | int], str]:
    fenced = re.search(r"```(?:json)?\s*(.+?)```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1:
        return [], "Chief reviewer returned an unparseable response; no findings were promoted."
    try:
        data = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return [], "Chief reviewer returned an unparseable response; no findings were promoted."

    kept = [
        ref
        for ref in data.get("kept", [])
        if isinstance(ref, str) or (isinstance(ref, int) and not isinstance(ref, bool))
    ]
    return kept, str(data.get("rationale", ""))
