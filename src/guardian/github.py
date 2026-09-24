"""GitHub integration: fetch a PR's diff, post the verdict as one comment.

One comment, updated in place on every re-run. A tool that posts a comment per finding is the
thing this project exists to avoid, and a tool that posts a fresh comment per push becomes the
same noise by a different route.
"""

import json
import urllib.error
import urllib.request

from guardian.models import Finding, Verdict

API = "https://api.github.com"
MARKER = "<!-- ai-pr-guardian -->"

DECISION_HEADING = {
    "block": "Blocking: a likely vulnerability is being introduced",
    "request_changes": "Worth a look before merging",
    "approve": "No blocking security findings",
}


def render_comment(verdict: Verdict) -> str:
    lines = [MARKER, f"## {DECISION_HEADING[verdict.decision]}", "", verdict.rationale, ""]

    if verdict.findings:
        lines.append("### Blocking (security)")
        lines.extend(_render_finding(f) for f in verdict.findings)

    if verdict.advisory:
        lines.append("")  # a heading glued to a closing code fence renders badly
        lines.append("### Advisory - does not block the merge")
        lines.extend(_render_finding(f, advisory=True) for f in verdict.advisory)

    lines.append("")
    lines.append(
        "<sub>Security findings gate the merge; advisory findings are for a human to judge. "
        "Measured precision and recall are in RESULTS.md.</sub>"
    )
    return "\n".join(lines)


ADVISORY_SEVERITY = {"block": "high", "warn": "medium", "nit": "low"}


def _render_finding(f: Finding, advisory: bool = False) -> str:
    # Under a "does not block" heading, the word "block" reads as a contradiction.
    severity = ADVISORY_SEVERITY.get(f.severity, f.severity) if advisory else f.severity
    return (
        f"\n**`{f.file}:{f.line}`** - {f.category} "
        f"({severity}, confidence {f.confidence:.2f}, via {f.agent})\n\n"
        f"{f.claim}\n\n"
        f"```\n{f.evidence}\n```"
    )


def find_existing_comment(comments: list[dict]) -> int | None:
    """Our own comment starts with the marker. A marker quoted inside someone else's comment
    does not count, or replying to us would let a human's comment be overwritten."""
    for comment in comments:
        if comment.get("body", "").startswith(MARKER):
            return comment["id"]
    return None


def _request(method: str, url: str, token: str, payload: dict | None = None) -> dict | list:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ai-pr-guardian",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8", errors="replace")
    return json.loads(body) if body.strip() else {}


def fetch_pr_diff(repo: str, pr_number: int, token: str) -> str:
    request = urllib.request.Request(
        f"{API}/repos/{repo}/pulls/{pr_number}",
        headers={
            "Accept": "application/vnd.github.diff",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ai-pr-guardian",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def publish_comment(repo: str, pr_number: int, token: str, body: str) -> str:
    comments = _request("GET", f"{API}/repos/{repo}/issues/{pr_number}/comments?per_page=100", token)
    existing = find_existing_comment(comments if isinstance(comments, list) else [])

    if existing is not None:
        _request("PATCH", f"{API}/repos/{repo}/issues/comments/{existing}", token, {"body": body})
        return f"updated comment {existing}"

    _request("POST", f"{API}/repos/{repo}/issues/{pr_number}/comments", token, {"body": body})
    return "posted a new comment"
