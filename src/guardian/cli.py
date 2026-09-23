import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from guardian.llm.client import AnthropicClient
from guardian.orchestrator import review_pr

DECISION_LABEL = {"block": "BLOCK", "request_changes": "REQUEST CHANGES", "approve": "APPROVE"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="guardian")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="review a diff against a repo checkout")
    review.add_argument("repo", help="path to the repo the diff applies to")
    review.add_argument("diff", help="path to a unified diff file, or - for stdin")
    review.add_argument("--json", action="store_true", help="print the verdict as JSON")

    args = parser.parse_args(argv)

    diff_text = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(encoding="utf-8")
    client = AnthropicClient()
    verdict = review_pr(args.repo, diff_text, client)

    run_path = _log_run(verdict, client)

    if args.json:
        print(json.dumps(asdict(verdict), indent=2))
    else:
        _print_verdict(verdict, client, run_path)

    return 1 if verdict.decision == "block" else 0


def _print_verdict(verdict, client, run_path: Path) -> None:
    print(f"\n=== {DECISION_LABEL[verdict.decision]} ===\n")
    print(verdict.rationale + "\n")
    for f in verdict.findings:
        print(f"  [{f.severity}] {f.file}:{f.line}  ({f.category}, confidence {f.confidence:.2f})")
        print(f"      {f.claim}")
        print(f"      via {f.agent}\n")
    if not verdict.findings:
        print("  no findings worth your attention\n")
    print(f"cost: ${client.total_cost_usd():.4f}   run log: {run_path}")


def _log_run(verdict, client) -> Path:
    runs = Path("runs")
    runs.mkdir(exist_ok=True)
    path = runs / f"{datetime.now():%Y%m%d-%H%M%S}.json"
    path.write_text(
        json.dumps(
            {
                "verdict": asdict(verdict),
                "usage": client.usage,
                "cost_usd": round(client.total_cost_usd(), 6),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":
    raise SystemExit(main())
