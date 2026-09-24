from guardian.agents.chief import scrub_indices

LIVE_RATIONALE = (
    "SQL injection at export.py:9 is confirmed; dropped the architecture duplicates "
    "(findings 2 and 3) as redundant. Kept the off-by-one at export.py:21 (finding 5)."
)


def test_removes_parenthetical_index_references():
    # Observed live after prompting against it: the chief still wrote "(findings 2 and 3)".
    scrubbed = scrub_indices(LIVE_RATIONALE)
    assert "finding" not in scrubbed.lower()
    assert "(" not in scrubbed


def test_removes_the_indices_wording_it_switched_to_next():
    # Second live run, after the first scrubber shipped: "(indices 2 and 3)".
    scrubbed = scrub_indices("the duplicates of the same two issues (indices 2 and 3) add nothing.")
    assert scrubbed == "the duplicates of the same two issues add nothing."


def test_keeps_the_substance():
    scrubbed = scrub_indices(LIVE_RATIONALE)
    assert "export.py:9" in scrubbed and "export.py:21" in scrubbed


def test_cleans_up_spacing_left_behind():
    assert scrub_indices("Dropped the duplicate (finding 4) as redundant.") == (
        "Dropped the duplicate as redundant."
    )


def test_rewrites_a_bare_index_reference():
    assert scrub_indices("Finding 0 is the injection.") == "One finding is the injection."


def test_leaves_ordinary_prose_alone():
    text = "No findings survived the specialist round."
    assert scrub_indices(text) == text


# --- selection by key: the chief never sees a number it could echo ---

import json

from guardian.agents.chief import ChiefReviewer, finding_key
from guardian.models import Finding


def f(agent, line, category="c"):
    return Finding(agent, "demo/export.py", line, "block", category, "claim", "evidence", 0.9)


class Capture:
    def __init__(self, reply):
        self.reply, self.user = reply, None

    def complete(self, system, user, model):
        self.user = user
        return self.reply


def test_the_prompt_contains_no_index_labels():
    # Live Korean run: the chief wrote "([0],[1])" and "[5]가" because it was shown "[0]".
    client = Capture(json.dumps({"kept": [], "rationale": "x"}))
    ChiefReviewer(client).select([f("security", 9), f("architecture", 14)])
    assert "[0]" not in client.user and "[1]" not in client.user


def test_selects_findings_by_agent_and_location():
    findings = [f("security", 9), f("architecture", 9), f("business_logic", 21)]
    reply = json.dumps({"kept": ["security@demo/export.py:9", "business_logic@demo/export.py:21"],
                        "rationale": "kept two"})
    kept, _ = ChiefReviewer(Capture(reply)).select(findings)
    assert [(k.agent, k.line) for k in kept] == [("security", 9), ("business_logic", 21)]


def test_unknown_keys_cannot_add_findings():
    reply = json.dumps({"kept": ["security@evil.py:1"], "rationale": "x"})
    kept, _ = ChiefReviewer(Capture(reply)).select([f("security", 9)])
    assert kept == []


def test_two_findings_from_one_agent_on_one_line_stay_distinct():
    findings = [f("security", 9, "sqli"), f("security", 9, "logging")]
    assert finding_key(findings[0], findings) != finding_key(findings[1], findings)
