# AI PR Guardian

A multi-agent review board for pull requests. Three specialist reviewers (security, architecture,
business logic) read a diff independently, rebut each other, and a chief reviewer keeps only the
findings worth a human's attention. The point is not to find more — it is to hand back fewer, better
findings than a static analyzer does on its own.

Design lives in [agent.md](agent.md); the build order lives in [plan.md](plan.md).

## Setup

```bash
pip install -e .
```

Create a `.env` in the project root (gitignored):

```
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...      # only needed to build the benchmark dataset
```

## Review a diff

```bash
python -m guardian.cli review <path-to-repo> <path-to-diff>
```

Measured cost: **$0.0124 per PR** (Haiku for the specialists, Sonnet for the chief reviewer).

## Benchmark

```bash
python -m benchmark.build_dataset --per-class 25 --minimum 30
python -m benchmark.evaluate
```

Positives are real CVE fix commits read backwards, so the vulnerable side is code that actually
shipped. Negatives are ordinary commits from the same repositories. Both classes are reduced to
production source files, so the label cannot leak through deleted regression tests or release notes.

Results, including the failure analysis and the comparison against a plain Semgrep baseline, are in
`RESULTS.md`.
