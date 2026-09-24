import json

import pytest

from benchmark.evaluate import run
from guardian.models import Verdict


class MeteredClient:
    """Charges $0.01 per review, like a real run's per-example cost."""

    def __init__(self):
        self.spent = 0.0

    def total_cost_usd(self):
        return self.spent


class CreditsRanOut(RuntimeError):
    pass


def make_manifest(tmp_path, n=4):
    entries = []
    for i in range(n):
        diff = tmp_path / f"{i}.diff"
        diff.write_text("diff", encoding="utf-8")
        entries.append(
            {"id": f"ex{i}", "repo": "a/b", "commit": "c", "diff_path": str(diff),
             "is_vulnerable": i % 2 == 0, "split": "dev"}
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(entries), encoding="utf-8")
    return manifest


def reviewer(fail_on_call=None):
    calls = []

    def review(diff_text, client):
        calls.append(diff_text)
        if fail_on_call is not None and len(calls) == fail_on_call:
            raise CreditsRanOut("Your credit balance is too low")
        client.spent += 0.01
        return Verdict("block", [], "")

    review.calls = calls
    return review


def baseline(entry, diff_text, cache_dir):
    return "approve", 0


def test_a_run_that_dies_keeps_what_it_finished(tmp_path):
    manifest, checkpoint = make_manifest(tmp_path), tmp_path / "ckpt.jsonl"
    with pytest.raises(CreditsRanOut):
        run(manifest, None, tmp_path / "out", "dev", checkpoint,
            MeteredClient(), reviewer(fail_on_call=3), baseline)

    assert len(checkpoint.read_text(encoding="utf-8").splitlines()) == 2


def test_resuming_does_not_pay_twice(tmp_path):
    manifest, checkpoint = make_manifest(tmp_path), tmp_path / "ckpt.jsonl"
    with pytest.raises(CreditsRanOut):
        run(manifest, None, tmp_path / "out", "dev", checkpoint,
            MeteredClient(), reviewer(fail_on_call=3), baseline)

    second = reviewer()
    results = run(manifest, None, tmp_path / "out", "dev", checkpoint,
                  MeteredClient(), second, baseline)

    assert len(second.calls) == 2  # only the two it had not reached
    assert results["n_examples"] == 4
    assert results["cost_usd"] == pytest.approx(0.04)  # both halves counted once each


def test_checkpoint_is_removed_once_the_run_completes(tmp_path):
    manifest, checkpoint = make_manifest(tmp_path), tmp_path / "ckpt.jsonl"
    run(manifest, None, tmp_path / "out", "dev", checkpoint, MeteredClient(), reviewer(), baseline)
    assert not checkpoint.exists()
