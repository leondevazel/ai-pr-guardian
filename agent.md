# AI PR Guardian — Agent & System Design

**One-line pitch:** A multi-agent review board that reads a pull request diff, cross-examines it from
security / architecture / business-logic angles, and outputs a calibrated merge verdict — benchmarked
against real vulnerable-commit datasets so the numbers are honest, not a demo.

**What this is NOT:** Not a code-writing agent. Not a replacement for Semgrep/CodeQL — it *uses* them
as tools. Not a "beat Snyk" claim — success is a published precision/recall number on a public
benchmark, not a vibe.

---

## 1. Problem framing

AI-generated code ships fast and has a measurably higher defect rate than human-written code in the
same repos. The gap isn't detection tooling (Semgrep/CodeQL/Bandit already exist) — it's **triage**:
static analyzers are noisy, so nobody reads their output. The bet here is that a small committee of
LLM reviewers, each with a narrow mandate, arguing over the *same* static-analysis findings plus the
diff itself, can turn "47 Semgrep warnings nobody reads" into "3 findings with a reason to care."

## 2. Agent roster

Every agent is a pure function: `(PRContext, ToolFindings) -> list[Finding]`. No agent calls another
agent directly — all cross-talk happens through the Orchestrator (§4).

| Agent | Mandate | Reads | Must NOT do |
|---|---|---|---|
| `SecurityAgent` | Injection, auth/authz bypass, secrets, unsafe deserialization, SSRF, path traversal | diff + Semgrep/Bandit findings | Comment on style or naming |
| `ArchitectureAgent` | Breaking interface changes, layering violations, error-handling gaps that lose data | diff + repo file tree + import graph | Re-flag pure style nits |
| `BusinessLogicAgent` | Off-by-one/boundary bugs, incorrect conditionals, silent behavior changes vs. existing tests | diff + surrounding function context + existing tests touching changed lines | Flag anything without pointing to a specific line |
| `ChiefReviewer` (aggregator, not a peer) | Reads all three agents' findings + their rebuttals, assigns final confidence, issues verdict | everything above | Introduce new findings not raised by a peer agent |

Each `Finding`:

```python
@dataclass
class Finding:
    agent: str
    file: str
    line: int
    severity: Literal["block", "warn", "nit"]
    category: str              # e.g. "sql-injection", "auth-bypass"
    claim: str                 # one sentence, plain language
    evidence: str              # quoted code / tool output this is based on
    confidence: float          # 0-1, agent's own calibration
```

Findings without a `file`+`line` are dropped before reaching the Chief Reviewer — this is the single
biggest lever against noise, and it's enforced in code, not by prompting.

## 3. Tool layer (deterministic, not LLM)

Agents don't detect vulnerabilities from scratch — that's what makes this tractable solo. They
consume the output of real static analyzers and reason about *relevance*, not perform pattern
matching an LLM is bad at anyway.

- `tools/semgrep_runner.py` — runs `semgrep --config=p/security-audit` (or Bandit for Python-only
  repos) on the changed files, parses JSON output into `ToolFindings`.
- `tools/repo_context.py` — given a file path, returns: surrounding function, its existing tests (by
  grepping `test_*` files that import/reference the changed symbol), and the import graph one hop out.

`ToolFindings` are handed to every agent identically — agents differ in *interpretation*, not input.

## 4. Orchestration protocol

Sequential, not a free-for-all debate (free-for-all is expensive and non-deterministic — bad for a
benchmark). Three rounds:

1. **Round 1 — Independent review.** All three agents run in parallel (separate API calls) against
   the same `PRContext` + `ToolFindings`. No agent sees another's output yet.
2. **Round 2 — Rebuttal.** Each agent receives the *other two* agents' Round-1 findings that touch
   files/lines it also reviewed, and may (a) raise its confidence, (b) lower it, or (c) add one
   rebuttal sentence. Agents cannot add brand-new findings in this round — keeps the round bounded and
   cheap (short prompts, no new tool calls).
3. **Round 3 — Verdict.** `ChiefReviewer` receives all findings + rebuttals and outputs:

```python
@dataclass
class Verdict:
    decision: Literal["approve", "request_changes", "block"]
    findings: list[Finding]     # final, post-rebuttal, sorted by severity
    rationale: str              # 2-4 sentences, cites specific findings
```

Decision rule (deterministic, in code, not left to the LLM to decide the threshold):
`block` if any `Finding` has `severity=="block"` and `confidence >= 0.7` after rebuttal;
`request_changes` if any `warn` finding has `confidence >= 0.5`; else `approve`.

## 5. Evaluation methodology (this is the actual deliverable)

A demo without numbers is not "professional level" — this is the part that makes the project real.

- **Dataset:** start with 40-60 examples pulled from public CVE-fixing commits (e.g. a curated slice
  of the BigVul or CVEfixes dataset, filtered to Python/JS since Semgrep coverage is best there) —
  each example is a `(pre-fix diff, is_vulnerable=True, cve_category)` pair, plus an equal number of
  *benign* diffs (real merged PRs from the same repos with no associated CVE) as negative controls.
  Negative controls matter more than the positive set: without them you can't measure false-positive
  rate, and false-positive rate is the whole thesis (§1).
- **Metrics:** precision, recall, F1 on `decision != "approve"` vs. ground truth `is_vulnerable`;
  reported separately from a **noise ratio** = findings per PR on the negative set (this is the number
  that proves the multi-agent debate actually suppresses noise vs. raw Semgrep output).
- **Baseline to beat:** raw Semgrep output alone (flag PR if Semgrep emits ≥1 finding). If the
  full pipeline doesn't beat this trivial baseline on F1 *and* noise ratio, the project's thesis is
  wrong and that's a legitimate, reportable result — not a failure to hide.

## 6. Cost control

- Diffs are truncated to changed files + 20 lines of context per hunk — never whole-repo context.
- Round 2 prompts include only the *other agents' findings text* (a few hundred tokens), not a re-send
  of the full diff.
- Target: < $0.15 per PR reviewed end-to-end (3 agents × 2 rounds + 1 chief pass) using Claude Haiku
  for Round 1/2 and Claude Sonnet only for the Chief Reviewer's final pass. Verify this in Task 6 of
  `plan.md` before running the full benchmark — a 50-example benchmark run should cost single-digit
  dollars.

## 7. Known limitations (state these up front, don't discover them in a demo)

- Static-analyzer coverage bounds recall — a vuln class Semgrep's ruleset doesn't cover, this system
  won't catch either. This is fine: the claim is "better triage of what's flagged," not "finds
  everything."
- No cross-file data-flow analysis beyond the one-hop import graph — deep taint tracking across many
  files is out of scope.
- Benchmark size (40-60 examples) is small enough that reported precision/recall has real variance;
  report confidence intervals or at minimum raw counts, not just a percentage.
