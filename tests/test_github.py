from guardian.github import MARKER, find_existing_comment, render_comment
from guardian.models import Finding, Verdict


def finding(agent="security", severity="block", category="sql-injection", confidence=0.95):
    return Finding(
        agent=agent,
        file="app/db.py",
        line=12,
        severity=severity,
        category=category,
        claim="user_id is interpolated into SQL without parameterization.",
        evidence='query = f"SELECT * FROM users WHERE id = {user_id}"',
        confidence=confidence,
    )


def test_blocking_comment_names_the_decision():
    body = render_comment(Verdict("block", [finding()], "Confirmed injection."))
    assert "Blocking" in body
    assert "app/db.py:12" in body


def test_comment_carries_the_marker_so_it_can_be_updated_in_place():
    assert MARKER in render_comment(Verdict("approve", [], "Nothing found."))


def test_advisory_findings_are_clearly_non_blocking():
    verdict = Verdict(
        "approve", [], "No security issues.", advisory=[finding(agent="business_logic", severity="warn")]
    )
    body = render_comment(verdict)
    assert "does not block" in body.lower()
    assert "business_logic" in body


def test_clean_pr_gets_a_short_comment_not_an_empty_one():
    body = render_comment(Verdict("approve", [], "Nothing worth flagging."))
    assert "No blocking security findings" in body
    assert len(body.splitlines()) < 12


def test_confidence_is_shown_so_a_human_can_weigh_it():
    assert "0.95" in render_comment(Verdict("block", [finding()], "x"))


def test_evidence_is_quoted_in_a_code_block():
    body = render_comment(Verdict("block", [finding()], "x"))
    assert "```" in body
    assert "SELECT * FROM users" in body


def test_finds_our_own_previous_comment():
    comments = [
        {"id": 1, "body": "looks good to me"},
        {"id": 2, "body": f"{MARKER}\nprevious run"},
    ]
    assert find_existing_comment(comments) == 2


def test_returns_none_when_we_have_not_commented_yet():
    assert find_existing_comment([{"id": 1, "body": "unrelated"}]) is None


def test_does_not_mistake_a_quoted_marker_in_someone_elses_comment():
    # A human quoting our comment should not make us overwrite theirs.
    comments = [{"id": 7, "body": f"> {MARKER} someone pasted this"}]
    assert find_existing_comment(comments) is None


def test_advisory_heading_is_not_glued_to_a_code_fence():
    body = render_comment(
        Verdict("block", [finding()], "x", advisory=[finding(agent="business_logic")])
    )
    lines = body.splitlines()
    heading = next(i for i, line in enumerate(lines) if line.startswith("### Advisory"))
    assert lines[heading - 1] == ""


def test_advisory_findings_never_say_block():
    body = render_comment(
        Verdict("approve", [], "x", advisory=[finding(agent="business_logic", severity="block")])
    )
    advisory = body.split("### Advisory")[1]
    assert "(block," not in advisory
    assert "(high," in advisory
