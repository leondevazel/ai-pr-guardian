import json
import re

from guardian.llm.client import SONNET
from guardian.models import Finding

SYSTEM = """You are the chief reviewer on a pull-request review board.

Three specialist reviewers (security, architecture, business_logic) have each filed findings and
then adjusted their own confidence after seeing their peers' work. Your job is selection, not
discovery: decide which findings a human reviewer should actually spend attention on.

You cannot add findings. You can only keep or drop the ones listed, by index.

Drop a finding when: it is speculative, it restates another kept finding, it is a style nit dressed
up as a defect, or its evidence does not support its claim. Keeping everything is a failure — an
unfiltered list is exactly what makes review tools get ignored.

Respond with JSON and nothing else:
{"kept": [<indices of findings worth a human's attention>],
 "rationale": "<2-4 sentences citing the specific findings you kept and why the dropped ones did not survive>"}

The rationale is shown to the pull request's author, who never sees the numbered list. Refer to
findings by what they are and where — "the SQL injection on demo/export.py:9" — never by index
("finding 0"). The indices exist only for the "kept" array.
"""


class ChiefReviewer:
    model = SONNET

    def __init__(self, client):
        self.client = client

    def select(self, findings: list[Finding]) -> tuple[list[Finding], str]:
        if not findings:
            return [], "No findings survived the specialist round."

        raw = self.client.complete(system=SYSTEM, user=_render(findings), model=self.model)
        kept_indices, rationale = _parse(raw)
        kept = [findings[i] for i in kept_indices if 0 <= i < len(findings)]
        return kept, scrub_indices(rationale)


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
    for index, f in enumerate(findings):
        blocks.append(
            f"[{index}] agent={f.agent} {f.file}:{f.line} severity={f.severity} "
            f"confidence={f.confidence:.2f} category={f.category}\n"
            f"    claim: {f.claim}\n"
            f"    evidence: {f.evidence}"
        )
    return "## Findings\n" + "\n".join(blocks)


def _parse(raw: str) -> tuple[list[int], str]:
    fenced = re.search(r"```(?:json)?\s*(.+?)```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1:
        return [], "Chief reviewer returned an unparseable response; no findings were promoted."
    try:
        data = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError:
        return [], "Chief reviewer returned an unparseable response; no findings were promoted."

    kept = [i for i in data.get("kept", []) if isinstance(i, int) and not isinstance(i, bool)]
    return kept, str(data.get("rationale", ""))
