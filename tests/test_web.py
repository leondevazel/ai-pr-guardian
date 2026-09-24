import json

import pytest
from fastapi.testclient import TestClient

from guardian.models import Finding, Verdict
from web.app import UsageGuard, create_app, parse_pr_url, validate_diff

DIFF = (
    "diff --git a/app/db.py b/app/db.py\n"
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -1 +1 @@\n"
    "-safe()\n"
    '+query = f"SELECT * FROM t WHERE id = {x}"\n'
)


# --- input guards ---


def test_accepts_a_small_diff():
    assert validate_diff(DIFF) is None


def test_rejects_empty_input():
    assert "empty" in validate_diff("   ")


def test_rejects_text_that_is_not_a_diff():
    assert "unified diff" in validate_diff("please review my code")


def test_rejects_oversized_diff_to_cap_cost_per_request():
    huge = DIFF + "".join(f"+line {i}\n" for i in range(1000))
    assert "too large" in validate_diff(huge)


def test_parses_a_pull_request_url():
    assert parse_pr_url("https://github.com/leondevazel/ai-pr-guardian/pull/1") == (
        "leondevazel/ai-pr-guardian",
        1,
    )


def test_rejects_urls_that_are_not_github_prs():
    assert parse_pr_url("https://evil.example.com/a/b/pull/1") is None
    assert parse_pr_url("https://github.com/a/b/issues/1") is None


# --- usage guard: one visitor, and the whole site, each get a ceiling ---


def test_guard_allows_until_the_per_visitor_limit():
    guard = UsageGuard(per_visitor=2, daily_budget_usd=1.0)
    assert guard.check("1.2.3.4") is None
    guard.record("1.2.3.4", 0.01)
    guard.record("1.2.3.4", 0.01)
    assert "limit" in guard.check("1.2.3.4")


def test_guard_limits_are_per_visitor():
    guard = UsageGuard(per_visitor=1, daily_budget_usd=1.0)
    guard.record("1.1.1.1", 0.01)
    assert guard.check("2.2.2.2") is None


def test_guard_stops_everyone_once_the_daily_budget_is_spent():
    guard = UsageGuard(per_visitor=100, daily_budget_usd=0.05)
    guard.record("1.1.1.1", 0.05)
    assert "budget" in guard.check("9.9.9.9")


def test_guard_resets_on_a_new_day():
    guard = UsageGuard(per_visitor=1, daily_budget_usd=1.0)
    guard.record("1.1.1.1", 0.5)
    guard._day = "1999-01-01"
    assert guard.check("1.1.1.1") is None


# --- endpoints, with the review stubbed out: no API calls in tests ---


def fake_review(diff_text, on_event):
    on_event({"type": "stage", "stage": "round1"})
    finding = Finding("security", "app/db.py", 1, "block", "SQL injection", "c", "e", 0.95)
    return Verdict("block", [finding], "Injection on line 1."), 0.012


@pytest.fixture
def client(tmp_path):
    app = create_app(review_fn=fake_review, data_dir=tmp_path, guard=UsageGuard(5, 1.0))
    return TestClient(app)


def events_of(response):
    return [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]


def test_review_streams_progress_then_a_verdict(client):
    response = client.post("/api/review", json={"diff": DIFF})
    events = events_of(response)
    assert events[0] == {"type": "stage", "stage": "round1"}
    assert events[-1]["type"] == "verdict"
    assert events[-1]["decision"] == "block"
    assert events[-1]["review_id"]


def test_review_rejects_bad_input_before_spending_anything(client):
    response = client.post("/api/review", json={"diff": "not a diff"})
    assert response.status_code == 400


def test_feedback_is_stored_against_the_review(client, tmp_path):
    verdict = events_of(client.post("/api/review", json={"diff": DIFF}))[-1]
    response = client.post(
        "/api/feedback",
        json={"review_id": verdict["review_id"], "finding": 0, "vote": "up"},
    )
    assert response.status_code == 200

    rows = [json.loads(l) for l in (tmp_path / "feedback.jsonl").read_text().splitlines()]
    assert rows[-1]["vote"] == "up"
    assert rows[-1]["finding"]["category"] == "SQL injection"


def test_feedback_for_an_unknown_review_is_rejected(client):
    response = client.post("/api/feedback", json={"review_id": "nope", "finding": 0, "vote": "up"})
    assert response.status_code == 404


def test_feedback_vote_must_be_up_or_down(client):
    verdict = events_of(client.post("/api/review", json={"diff": DIFF}))[-1]
    response = client.post(
        "/api/feedback", json={"review_id": verdict["review_id"], "finding": 0, "vote": "maybe"}
    )
    assert response.status_code == 422


# --- out of credits: a live portfolio demo must fail gracefully ---


def out_of_credits(diff_text, on_event):
    raise RuntimeError("Error code: 400 - Your credit balance is too low to access the Anthropic API.")


@pytest.fixture
def broke_client(tmp_path):
    app = create_app(review_fn=out_of_credits, data_dir=tmp_path, guard=UsageGuard(5, 1.0))
    return TestClient(app)


def test_running_out_of_credits_shows_a_plain_message(broke_client):
    events = events_of(broke_client.post("/api/review", json={"diff": DIFF}))
    assert events[-1]["type"] == "error"
    assert "paused" in events[-1]["message"]
    assert "BadRequest" not in events[-1]["message"]
    assert "RuntimeError" not in events[-1]["message"]


def test_after_credits_run_out_later_visitors_are_told_before_waiting(broke_client):
    broke_client.post("/api/review", json={"diff": DIFF})
    second = broke_client.post("/api/review", json={"diff": DIFF})
    assert second.status_code == 503
    assert "paused" in second.json()["detail"]


def test_default_daily_budget_protects_a_five_dollar_balance():
    from web.app import DEFAULT_DAILY_BUDGET_USD
    assert DEFAULT_DAILY_BUDGET_USD <= 0.5
