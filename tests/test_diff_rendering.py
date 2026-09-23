"""Regression tests for the rendering that caused most false positives in run 01.

A benign Pillow refactor replaced an if/else with one line. Shown a raw diff, the business-logic
agent read the removed if/else as still present and blocked the PR for "unreachable dead code" at
0.92 confidence. The resulting-code view exists to make that misreading impossible.
"""

from guardian.agents.security import SecurityAgent
from guardian.diff_parser import parse_diff

REFACTOR_DIFF = """diff --git a/src/PIL/Image.py b/src/PIL/Image.py
--- a/src/PIL/Image.py
+++ b/src/PIL/Image.py
@@ -2161,6 +2161,3 @@ def putpalette(
         if isinstance(data, ImagePalette.ImagePalette):
-            if data.rawmode is not None:
-                palette = ImagePalette.raw(data.rawmode, data.palette)
-            else:
-                palette = ImagePalette.ImagePalette(palette=data.palette)
+            palette = ImagePalette.raw(data.rawmode or "RGB", data.palette)
         else:
"""


class CapturingClient:
    def __init__(self):
        self.calls = []

    def complete(self, system, user, model):
        self.calls.append(user)
        return "[]"


def rendered_prompt():
    client = CapturingClient()
    SecurityAgent(client).review(parse_diff(REFACTOR_DIFF), tools=[])
    return client.calls[0]


def test_resulting_code_excludes_removed_lines():
    after = rendered_prompt().split("Lines this change ADDS:")[0]
    assert "if data.rawmode is not None:" not in after
    assert 'palette = ImagePalette.raw(data.rawmode or "RGB", data.palette)' in after


def test_removed_lines_are_labeled_as_gone():
    prompt = rendered_prompt()
    assert "REMOVES (no longer present)" in prompt
    assert "if data.rawmode is not None:" in prompt  # still shown, but in the removed section


def test_prompt_states_removed_lines_must_not_be_reasoned_about():
    assert "must not reason about them as if they were still in the file" in rendered_prompt()


def test_resulting_code_is_numbered_from_the_hunk_start():
    after = rendered_prompt()
    assert "2161: " in after


def test_no_raw_diff_markers_in_the_resulting_code_view():
    after = rendered_prompt().split("Lines this change ADDS:")[0]
    code_lines = [line for line in after.splitlines() if ": " in line and line.startswith("  ")]
    assert code_lines
    assert not any(line.split(": ", 1)[1].startswith(("+", "-")) for line in code_lines)
