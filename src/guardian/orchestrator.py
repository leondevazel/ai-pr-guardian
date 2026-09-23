from concurrent.futures import ThreadPoolExecutor

from guardian.agents.architecture import ArchitectureAgent
from guardian.agents.business_logic import BusinessLogicAgent
from guardian.agents.chief import ChiefReviewer
from guardian.agents.security import SecurityAgent
from guardian.diff_parser import parse_diff
from guardian.models import Decision, Finding, Verdict
from guardian.tools.repo_context import get_context
from guardian.tools.semgrep_runner import run_semgrep as _run_semgrep

BLOCK_THRESHOLD = 0.7
WARN_THRESHOLD = 0.5

AGENT_CLASSES = (SecurityAgent, ArchitectureAgent, BusinessLogicAgent)


def decide(findings: list[Finding]) -> Decision:
    if any(f.severity == "block" and f.confidence >= BLOCK_THRESHOLD for f in findings):
        return "block"
    if any(f.severity == "warn" and f.confidence >= WARN_THRESHOLD for f in findings):
        return "request_changes"
    return "approve"


def review_pr(repo_path: str, diff_text: str, client, run_semgrep=_run_semgrep) -> Verdict:
    ctx = parse_diff(diff_text)
    changed_files = [f.path for f in ctx.files]
    tools = run_semgrep(repo_path, changed_files)
    contexts = _repo_contexts(repo_path, ctx)

    agents = [cls(client) for cls in AGENT_CLASSES]

    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        round1 = list(pool.map(lambda a: a.review(ctx, tools, contexts), agents))

    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        round2 = list(
            pool.map(
                lambda pair: pair[0].rebut(pair[1], _peers_on_same_files(pair[1], round1, pair[0].name)),
                zip(agents, round1),
            )
        )

    all_findings = [f for group in round2 for f in group]
    kept, rationale = ChiefReviewer(client).select(all_findings)
    kept.sort(key=lambda f: (_severity_rank(f.severity), -f.confidence))

    return Verdict(decision=decide(kept), findings=kept, rationale=rationale)


def _repo_contexts(repo_path: str, ctx) -> list:
    contexts = []
    for file in ctx.files:
        for hunk in file.hunks:
            line = hunk.added_lines[0][0] if hunk.added_lines else hunk.start_line
            contexts.append(get_context(repo_path, file.path, line))
    return contexts


def _peers_on_same_files(own: list[Finding], round1: list[list[Finding]], own_agent: str) -> list[Finding]:
    own_files = {f.file for f in own}
    return [
        f
        for group in round1
        for f in group
        if f.agent != own_agent and f.file in own_files
    ]


def _severity_rank(severity: str) -> int:
    return {"block": 0, "warn": 1, "nit": 2}.get(severity, 3)
