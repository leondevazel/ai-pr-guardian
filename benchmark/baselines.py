"""The bar the multi-agent pipeline has to clear.

If running three LLM agents cannot beat "flag anything Semgrep mentions", the thesis in agent.md §1
is wrong, and the honest move is to report that (agent.md §5).
"""

import tempfile
from pathlib import Path

from guardian.diff_parser import parse_diff
from guardian.models import Decision
from guardian.tools.semgrep_runner import run_semgrep


def semgrep_baseline(diff_text: str, repo_path: str, runner=run_semgrep) -> tuple[Decision, int]:
    """Returns the decision and the number of findings, so noise can be compared too."""
    ctx = parse_diff(diff_text)
    findings = runner(repo_path, [f.path for f in ctx.files])
    decision: Decision = "request_changes" if findings else "approve"
    return decision, len(findings)


def semgrep_baseline_on_added_lines(diff_text: str, runner=run_semgrep) -> tuple[Decision, int]:
    """Scans the added lines alone, for benchmark diffs with no repo checkout to hand.

    Writing the added lines to a temp file loses cross-file context, which is exactly the
    handicap Semgrep operates under in this setting — worth stating rather than hiding."""
    ctx = parse_diff(diff_text)
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for changed in ctx.files:
            suffix = Path(changed.path).suffix
            if suffix not in (".py", ".js", ".ts", ".jsx", ".tsx"):
                continue
            target = Path(tmp) / Path(changed.path).name
            target.write_text(
                "\n".join(text for hunk in changed.hunks for _, text in hunk.added_lines),
                encoding="utf-8",
            )
            paths.append(target.name)

        if not paths:
            return "approve", 0
        findings = runner(tmp, paths)

    return ("request_changes" if findings else "approve"), len(findings)
