from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

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

# Only the security agent can hold up a merge. On the 38-example benchmark it filed 6 findings,
# all 6 genuine vulnerabilities, 0 false positives; architecture and business_logic together
# produced all 13 false positives while adding real recall. So they advise, they do not gate.
# See RESULTS.md, "Two operating points, not one".
BLOCKING_AGENTS = {"security"}


def decide(findings: list[Finding]) -> Decision:
    return decide_on_all([f for f in findings if f.agent in BLOCKING_AGENTS])


def decide_on_all(findings: list[Finding]) -> Decision:
    """Thresholds applied to every finding regardless of author — the benchmark's comparison view."""
    if any(f.severity == "block" and f.confidence >= BLOCK_THRESHOLD for f in findings):
        return "block"
    if any(f.severity == "warn" and f.confidence >= WARN_THRESHOLD for f in findings):
        return "request_changes"
    return "approve"


def review_pr(
    repo_path: str, diff_text: str, client, run_semgrep=_run_semgrep, on_event=None
) -> Verdict:
    ctx = parse_diff(diff_text)
    changed_files = [f.path for f in ctx.files]
    tools = run_semgrep(repo_path, changed_files)
    contexts = _repo_contexts(repo_path, ctx)

    agents = [cls(client) for cls in AGENT_CLASSES]
    emit = on_event or (lambda event: None)

    def reviewed(agent):
        found = agent.review(ctx, tools, contexts)
        emit(_findings_event(1, agent.name, found))
        return found

    def rebutted(pair):
        agent, own = pair
        adjusted = agent.rebut(own, _peers_on_same_files(own, round1, agent.name))
        if own:
            emit(_findings_event(2, agent.name, adjusted))
        return adjusted

    emit({"type": "stage", "stage": "round1"})
    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        round1 = list(pool.map(reviewed, agents))

    emit({"type": "stage", "stage": "rebuttal"})
    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        round2 = list(pool.map(rebutted, zip(agents, round1)))

    emit({"type": "stage", "stage": "chief"})
    all_findings = [f for group in round2 for f in group]
    kept, rationale = ChiefReviewer(client).select(all_findings)
    kept.sort(key=lambda f: (_severity_rank(f.severity), -f.confidence))

    blocking = [f for f in kept if f.agent in BLOCKING_AGENTS]
    advisory = [f for f in kept if f.agent not in BLOCKING_AGENTS]

    return Verdict(
        decision=decide(blocking), findings=blocking, advisory=advisory, rationale=rationale
    )


def _findings_event(round_number: int, agent: str, findings: list[Finding]) -> dict:
    return {
        "type": "findings",
        "round": round_number,
        "agent": agent,
        "findings": [asdict(f) for f in findings],
    }


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
