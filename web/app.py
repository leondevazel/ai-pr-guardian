"""Public playground: paste a diff (or a GitHub PR link), watch the board argue, vote on findings.

Two things make this more than a demo. Every run is real — there is no canned output — and every
thumbs up/down lands in feedback.jsonl, which is the only honest source of real-usage labels this
project has.
"""

import json
import queue
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

MAX_DIFF_LINES = 400
# Sized for a $5 prepaid balance: even a bot hammering the site gets ten days, not five.
DEFAULT_DAILY_BUDGET_USD = 0.5
PAUSED_MESSAGE = (
    "The live demo is paused because its review budget is used up. "
    "The example pull request on GitHub shows a full review in the meantime."
)
PR_URL = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)/?$")
STATIC = Path(__file__).parent / "static"


def validate_diff(diff_text: str) -> str | None:
    if not diff_text.strip():
        return "The diff is empty."
    if "@@" not in diff_text or not re.search(r"(?m)^\+\+\+ ", diff_text):
        return "That does not look like a unified diff (expected `+++` and `@@` lines)."
    if len(diff_text.splitlines()) > MAX_DIFF_LINES:
        return f"Diff too large for the public demo (limit {MAX_DIFF_LINES} lines)."
    return None


def parse_pr_url(url: str) -> tuple[str, int] | None:
    match = PR_URL.match(url.strip())
    return (match.group(1), int(match.group(2))) if match else None


@dataclass
class UsageGuard:
    """Per-visitor and site-wide daily ceilings.

    In memory, so a restart forgets today's spend. ponytail: acceptable for a portfolio demo with a
    $1/day cap; persist to disk if the site ever gets real traffic."""

    per_visitor: int
    daily_budget_usd: float
    _day: str = field(default_factory=lambda: date.today().isoformat())
    _spent: float = 0.0
    _counts: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _roll(self) -> None:
        today = date.today().isoformat()
        if today != self._day:
            self._day, self._spent, self._counts = today, 0.0, {}

    def check(self, visitor: str) -> str | None:
        with self._lock:
            self._roll()
            if self._spent >= self.daily_budget_usd:
                return "Today's demo budget is used up. It resets at midnight UTC."
            if self._counts.get(visitor, 0) >= self.per_visitor:
                return f"You have reached today's limit of {self.per_visitor} reviews."
            return None

    def record(self, visitor: str, cost_usd: float) -> None:
        with self._lock:
            self._roll()
            self._spent += cost_usd
            self._counts[visitor] = self._counts.get(visitor, 0) + 1


class ReviewRequest(BaseModel):
    diff: str | None = None
    pr_url: str | None = None


class FeedbackRequest(BaseModel):
    review_id: str
    finding: int
    vote: Literal["up", "down"]


def default_review(diff_text: str, on_event) -> tuple:
    from guardian.llm.client import AnthropicClient
    from guardian.orchestrator import review_pr

    client = AnthropicClient()
    # No repository checkout on the server: the board sees the diff alone, exactly as in the
    # benchmark, so the numbers in RESULTS.md describe what visitors get.
    verdict = review_pr(".", diff_text, client, run_semgrep=lambda *_: [], on_event=on_event)
    return verdict, client.total_cost_usd()


def default_fetch_pr(repo: str, number: int) -> str:
    import os

    from guardian.github import fetch_pr_diff

    return fetch_pr_diff(repo, number, os.environ.get("GITHUB_TOKEN", ""))


def create_app(review_fn=default_review, fetch_pr=default_fetch_pr, data_dir=None, guard=None):
    data_dir = Path(data_dir or Path(__file__).parent / "data")
    data_dir.mkdir(parents=True, exist_ok=True)
    guard = guard or UsageGuard(per_visitor=5, daily_budget_usd=DEFAULT_DAILY_BUDGET_USD)
    reviews: dict[str, list[dict]] = {}
    # Set once the API reports an empty balance, so later visitors hear it before waiting.
    # ponytail: cleared only by a restart; redeploying after a top-up is the reset.
    state = {"paused": False}

    app = FastAPI(title="AI PR Guardian")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.post("/api/review")
    def review(body: ReviewRequest, request: Request):
        diff_text = body.diff or ""
        if body.pr_url:
            parsed = parse_pr_url(body.pr_url)
            if not parsed:
                raise HTTPException(400, "Paste a link like https://github.com/owner/repo/pull/123")
            try:
                diff_text = fetch_pr(*parsed)
            except Exception:
                raise HTTPException(400, "Could not fetch that pull request. Is it public?")

        if problem := validate_diff(diff_text):
            raise HTTPException(400, problem)

        if state["paused"]:
            raise HTTPException(503, PAUSED_MESSAGE)

        visitor = request.client.host if request.client else "unknown"
        if problem := guard.check(visitor):
            raise HTTPException(429, problem)

        events: queue.Queue = queue.Queue()

        def work():
            try:
                verdict, cost = review_fn(diff_text, events.put)
                guard.record(visitor, cost)
                review_id = uuid.uuid4().hex[:12]
                ordered = verdict.findings + verdict.advisory
                reviews[review_id] = [asdict(f) for f in ordered]
                _append(data_dir / "reviews.jsonl", {"review_id": review_id, "cost": cost,
                                                     "verdict": asdict(verdict)})
                events.put({"type": "verdict", "review_id": review_id, **asdict(verdict),
                            "cost_usd": round(cost, 4)})
            except Exception as error:  # surfaced to the page instead of hanging the stream
                if "credit balance" in str(error).lower():
                    state["paused"] = True
                    message = PAUSED_MESSAGE
                else:
                    message = "The review could not finish. Try again in a minute."
                events.put({"type": "error", "message": message})
            finally:
                events.put(None)

        threading.Thread(target=work, daemon=True).start()

        def stream():
            while (event := events.get()) is not None:
                yield f"data: {json.dumps(event)}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.post("/api/feedback")
    def feedback(body: FeedbackRequest):
        findings = reviews.get(body.review_id)
        if findings is None:
            raise HTTPException(404, "Unknown review.")
        if not 0 <= body.finding < len(findings):
            raise HTTPException(400, "Unknown finding.")
        _append(data_dir / "feedback.jsonl", {"review_id": body.review_id, "vote": body.vote,
                                              "finding": findings[body.finding]})
        return {"ok": True}

    return app


def _append(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


app = create_app()
