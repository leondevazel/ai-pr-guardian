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
