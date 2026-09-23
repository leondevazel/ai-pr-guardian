import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from guardian.github import fetch_pr_diff, publish_comment, render_comment
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

    pr = sub.add_parser("review-pr", help="review a GitHub pull request and comment on it")
    pr.add_argument("--repo", required=True, help="owner/name")
    pr.add_argument("--pr", required=True, type=int, help="pull request number")
    pr.add_argument("--checkout", default=".", help="path to the checked-out repo")
    pr.add_argument(
        "--fail-on-block",
        action="store_true",
        help="exit non-zero when a security finding blocks, failing the check",
    )

    args = parser.parse_args(argv)

    if args.command == "review-pr":
        return _review_pull_request(args)

    diff_text = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text(encoding="utf-8")
    client = AnthropicClient()
    verdict = review_pr(args.repo, diff_text, client)

    run_path = _log_run(verdict, client)

    if args.json:
        print(json.dumps(asdict(verdict), indent=2))
    else:
        _print_verdict(verdict, client, run_path)

    return 1 if verdict.decision == "block" else 0


def _review_pull_request(args) -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set; cannot read the pull request or comment on it.")
        return 2

    diff_text = fetch_pr_diff(args.repo, args.pr, token)
    client = AnthropicClient()
    verdict = review_pr(args.checkout, diff_text, client)

    run_path = _log_run(verdict, client)
    print(publish_comment(args.repo, args.pr, token, render_comment(verdict)))
    _print_verdict(verdict, client, run_path)

    return 1 if (args.fail_on_block and verdict.decision == "block") else 0


def _print_verdict(verdict, client, run_path: Path) -> None:
    print(f"\n=== {DECISION_LABEL[verdict.decision]} ===\n")
    print(verdict.rationale + "\n")

    if verdict.findings:
        print("BLOCKING (security):")
        for f in verdict.findings:
            _print_finding(f)
    else:
        print("BLOCKING (security): none\n")

    if verdict.advisory:
        print("ADVISORY (does not block the merge):")
        for f in verdict.advisory:
            _print_finding(f)

    print(f"cost: ${client.total_cost_usd():.4f}   run log: {run_path}")


def _print_finding(f) -> None:
    print(f"  [{f.severity}] {f.file}:{f.line}  ({f.category}, confidence {f.confidence:.2f})")
    print(f"      {f.claim}")
    print(f"      via {f.agent}\n")


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
