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
        return kept, rationale


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
