"""Scores the pipeline against the labeled benchmark, next to the Semgrep baseline.

Raw counts are reported alongside percentages: with a 50-example set, "80% precision" without
"4 of 5" behind it is not a number anyone should trust (agent.md §7).
"""

import argparse
import json
import random
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from benchmark.baselines import semgrep_baseline_at
from benchmark.build_dataset import GITHUB_API, _get
from guardian.llm.client import AnthropicClient
from guardian.models import Verdict
from guardian.orchestrator import decide_on_all, review_pr

FLAGGED = {"block", "request_changes"}


@dataclass
class Metrics:
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    tn: int
    fn: int


def score(predictions: list[str], labels: list[bool]) -> Metrics:
    tp = sum(1 for p, y in zip(predictions, labels) if p in FLAGGED and y)
    fp = sum(1 for p, y in zip(predictions, labels) if p in FLAGGED and not y)
    fn = sum(1 for p, y in zip(predictions, labels) if p not in FLAGGED and y)
    tn = sum(1 for p, y in zip(predictions, labels) if p not in FLAGGED and not y)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return Metrics(precision, recall, f1, tp, fp, tn, fn)


def f1_confidence_interval(
    predictions: list[str], labels: list[bool], n_resamples: int = 2000, seed: int = 0
) -> tuple[float, float]:
    """95% percentile-bootstrap interval for F1.

    Resamples examples with replacement. At this sample size the interval, not the point, is the
    honest thing to report: two configurations whose intervals overlap heavily have not been shown
    to differ."""
    rng = random.Random(seed)
    pairs = list(zip(predictions, labels))
    f1s = sorted(
        score(*zip(*[rng.choice(pairs) for _ in pairs])).f1 for _ in range(n_resamples)
    )
    return round(f1s[int(0.025 * n_resamples)], 3), round(f1s[int(0.975 * n_resamples) - 1], 3)


def all_findings_decision(verdict: Verdict) -> str:
    """What the verdict would be if advisory findings could gate a merge too.

    This is no longer what the product does (RESULTS.md), but it stays scored: it is the view that
    shows how much recall the architecture and business-logic agents contribute, and how much
    precision that recall costs."""
    return decide_on_all(verdict.findings + verdict.advisory)


def noise_ratio(verdicts: list[Verdict], labels: list[bool]) -> float:
    benign = [v for v, y in zip(verdicts, labels) if not y]
    if not benign:
        return 0.0
    return sum(len(v.findings) + len(v.advisory) for v in benign) / len(benign)


def _post_change_ref(entry: dict) -> str:
    """The commit whose tree matches what the reviewer is being asked to approve.

    A positive example is a fix commit read backwards, so the state it produces is the fix's
    parent — the code while it was still vulnerable. A benign example produces its own commit."""
    if not entry["is_vulnerable"]:
        return entry["commit"]

    raw = _get(f"{GITHUB_API}/repos/{entry['repo']}/commits/{entry['commit']}")
    parents = json.loads(raw).get("parents", [])
    return parents[0]["sha"] if parents else entry["commit"]


def _default_review(diff_text: str, client):
    return review_pr(repo_path=".", diff_text=diff_text, client=client, run_semgrep=lambda *_: [])


def _default_baseline(entry: dict, diff_text: str, cache_dir: Path):
    return semgrep_baseline_at(entry["repo"], _post_change_ref(entry), diff_text, cache_dir)


def run(
    manifest_path: Path,
    limit: int | None,
    out_dir: Path,
    split: str = "all",
    checkpoint: Path | None = None,
    client=None,
    review_fn=_default_review,
    baseline_fn=_default_baseline,
) -> dict:
    """Scores every example, appending each result to `checkpoint` as soon as it exists.

    A run that dies partway (credits ran out 55 examples into a dev run) resumes from the
    checkpoint instead of paying again for the examples it already finished."""
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    if split != "all":
        entries = [e for e in entries if e.get("split") == split]
    entries = entries[:limit]
    cache_dir = manifest_path.parent / "files"
    client = client or AnthropicClient()

    done: dict[str, dict] = {}
    if checkpoint and checkpoint.is_file():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            done[record["id"]] = record
        print(f"resuming: {len(done)} examples already scored in {checkpoint.name}")

    for i, entry in enumerate(entries, 1):
        if entry["id"] in done:
            continue
        diff_text = Path(entry["diff_path"]).read_text(encoding="utf-8")
        print(f"[{i}/{len(entries)}] {entry['id']} (vulnerable={entry['is_vulnerable']})")

        cost_before = client.total_cost_usd()
        # The agents see only the diff; Semgrep gets the whole post-change file (baselines.py).
        verdict = review_fn(diff_text, client)
        baseline_decision, baseline_count = baseline_fn(entry, diff_text, cache_dir)

        record = {
            "id": entry["id"],
            "is_vulnerable": entry["is_vulnerable"],
            "pipeline": all_findings_decision(verdict),
            "pipeline_security_only": verdict.decision,
            "pipeline_findings": [asdict(f) for f in verdict.findings],
            "advisory_findings": [asdict(f) for f in verdict.advisory],
            "rationale": verdict.rationale,
            "baseline": baseline_decision,
            "baseline_findings": baseline_count,
            "cost_usd": round(client.total_cost_usd() - cost_before, 6),
        }
        done[entry["id"]] = record
        if checkpoint:
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            with checkpoint.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")

    per_example = [done[e["id"]] for e in entries]
    results = summarize(per_example, split)

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{datetime.now():%Y%m%d-%H%M%S}.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    _print_summary(results, out_path)
    if checkpoint and checkpoint.is_file():
        checkpoint.unlink()  # complete: the results file is now the record
    return results


def summarize(per_example: list[dict], split: str) -> dict:
    labels = [bool(r["is_vulnerable"]) for r in per_example]
    pipeline = [r["pipeline"] for r in per_example]
    security = [r["pipeline_security_only"] for r in per_example]
    baseline = [r["baseline"] for r in per_example]
    benign = [r for r in per_example if not r["is_vulnerable"]]

    def per_benign(count) -> float:
        return round(sum(count(r) for r in benign) / len(benign), 3) if benign else 0.0

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "n_examples": len(per_example),
        "split": split,
        "pipeline": asdict(score(pipeline, labels)),
        "pipeline_security_only": asdict(score(security, labels)),
        "baseline": asdict(score(baseline, labels)),
        "f1_ci95": {
            "pipeline": f1_confidence_interval(pipeline, labels),
            "pipeline_security_only": f1_confidence_interval(security, labels),
            "baseline": f1_confidence_interval(baseline, labels),
        },
        "pipeline_noise_ratio": per_benign(
            lambda r: len(r["pipeline_findings"]) + len(r["advisory_findings"])
        ),
        "baseline_noise_ratio": per_benign(lambda r: r["baseline_findings"]),
        "cost_usd": round(sum(r.get("cost_usd", 0) for r in per_example), 4),
        "examples": per_example,
    }


def _print_summary(results: dict, out_path: Path) -> None:
    p, b = results["pipeline"], results["baseline"]
    print(f"\n{'':<12}{'precision':>11}{'recall':>9}{'f1':>8}{'tp':>5}{'fp':>5}{'fn':>5}{'tn':>5}")
    for name, m in (
        ("pipeline", p),
        ("security-only", results["pipeline_security_only"]),
        ("semgrep", b),
    ):
        print(
            f"{name:<12}{m['precision']:>11.2f}{m['recall']:>9.2f}{m['f1']:>8.2f}"
            f"{m['tp']:>5}{m['fp']:>5}{m['fn']:>5}{m['tn']:>5}"
        )
    # ASCII only: Windows consoles default to cp949/cp1252, where an em dash aborts the run
    # after the benchmark has already been paid for.
    print(
        f"\nfindings per benign PR: pipeline {results['pipeline_noise_ratio']}, "
        f"semgrep {results['baseline_noise_ratio']}"
    )
    print(f"cost ${results['cost_usd']}   results: {out_path}")


def summarize_repeats(runs: list[dict]) -> None:
    """Reports the spread across identical runs.

    The Messages API exposes no temperature, so the pipeline is not deterministic. A single run's
    F1 is one draw from a distribution; quoting it alone would let run-to-run noise pass as the
    effect of a change."""
    if len(runs) < 2:
        return

    print(f"\n=== {len(runs)} identical runs ===")
    for view in ("pipeline", "pipeline_security_only", "baseline"):
        f1s = [r[view]["f1"] for r in runs]
        print(f"{view:<24} f1 min {min(f1s):.2f}  max {max(f1s):.2f}  mean {sum(f1s)/len(f1s):.2f}")

    per_example = [{e["id"]: e["pipeline_security_only"] for e in r["examples"]} for r in runs]
    ids = set(per_example[0])
    unstable = [i for i in ids if len({d.get(i) for d in per_example}) > 1]
    print(f"verdicts that differ between runs: {len(unstable)} of {len(ids)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="score the pipeline against the benchmark")
    parser.add_argument("--manifest", default="benchmark/dataset/manifest.json")
    parser.add_argument("--limit", type=int, default=None, help="only the first N examples")
    parser.add_argument("--out", default="benchmark/results")
    parser.add_argument(
        "--repeats", type=int, default=1, help="run the benchmark N times to measure variance"
    )
    parser.add_argument(
        "--split",
        choices=("dev", "test", "all"),
        default="dev",
        help="tune on dev; touch test only to report a final number",
    )
    args = parser.parse_args()

    out = Path(args.out)
    runs = [
        run(Path(args.manifest), args.limit, out, args.split, out / f"inprogress-{args.split}-r{k}.jsonl")
        for k in range(1, args.repeats + 1)
    ]
    summarize_repeats(runs)


if __name__ == "__main__":
    main()
