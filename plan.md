# AI PR Guardian — Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans
> to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Build a multi-agent PR reviewer that turns noisy static-analysis output into a small number
of high-confidence findings, and prove it works with precision/recall numbers on a public
vulnerable-commit benchmark.

**Architecture:** Deterministic tool layer (Semgrep + repo context) feeds three specialist LLM agents
that review independently, then rebut each other, then a Chief Reviewer issues a verdict under a
hard-coded decision rule. An offline benchmark harness scores the whole pipeline against labeled
CVE-fix commits plus benign controls.

**Tech Stack:** Python 3.11+, `anthropic` SDK (Claude Haiku for agents, Sonnet for Chief Reviewer),
`semgrep`, `unidiff` for diff parsing, `pytest`, plain JSON for result storage (no DB until one is
needed).

**Spec:** `agent.md` (read it first — agent roster, orchestration protocol, and evaluation
methodology live there; this plan only says how to build it)

## Global Constraints

- Python 3.11+. Dependencies pinned in `requirements.txt`.
- **No LLM calls in unit tests.** Every agent test uses a recorded/stubbed response. The only code
  that talks to the API lives behind `llm/client.py` so it can be swapped for a fake in tests.
- Every `Finding` must carry `file` + `line` or it is dropped — enforced in code (`orchestrator.py`),
  covered by a test.
- Cost ceiling: < $0.15 per PR end-to-end. Measured, not assumed (Task 6).
- Never commit API keys. `.env` is gitignored; config reads `ANTHROPIC_API_KEY` from environment.

---

## Phase 1 — Deterministic foundation (no LLM yet)

### Task 1: Project scaffold + diff parsing

**Files:**
- Create: `requirements.txt`, `.gitignore`, `src/guardian/__init__.py`
- Create: `src/guardian/models.py` (the `Finding` / `Verdict` / `PRContext` dataclasses from `agent.md`)
- Create: `src/guardian/diff_parser.py`
- Test: `tests/test_diff_parser.py`, `tests/fixtures/sample.diff`

**Interfaces:**
- Produces: `parse_diff(diff_text: str) -> PRContext` where
  `PRContext(files: list[ChangedFile])` and
  `ChangedFile(path: str, hunks: list[Hunk])`, `Hunk(start_line: int, added_lines: list[tuple[int, str]], context: str)`

- [x] **Step 1: Write the failing test**

```python
# tests/test_diff_parser.py
from guardian.diff_parser import parse_diff

SAMPLE = open("tests/fixtures/sample.diff").read()

def test_parses_changed_file_paths():
    ctx = parse_diff(SAMPLE)
    assert [f.path for f in ctx.files] == ["app/db.py"]

def test_captures_added_lines_with_absolute_line_numbers():
    ctx = parse_diff(SAMPLE)
    added = ctx.files[0].hunks[0].added_lines
    assert (12, '    query = f"SELECT * FROM users WHERE id = {user_id}"') in added
```

  Fixture `tests/fixtures/sample.diff` is a real unified diff introducing an f-string SQL query at
  line 12 of `app/db.py` (write it by hand; keep it under 20 lines).

- [x] **Step 2: Run test, verify it fails** — `pytest tests/test_diff_parser.py -v` → `ModuleNotFoundError: guardian.diff_parser`
- [x] **Step 3: Implement** `parse_diff` using `unidiff.PatchSet`, mapping `line.target_line_no` for added lines.
- [x] **Step 4: Run tests, verify pass**
- [x] **Step 5: Commit** — `feat: parse unified diffs into PRContext`

### Task 2: Semgrep tool wrapper

**Files:**
- Create: `src/guardian/tools/semgrep_runner.py`
- Test: `tests/test_semgrep_runner.py`, `tests/fixtures/semgrep_output.json`

**Interfaces:**
- Consumes: `PRContext` (Task 1)
- Produces: `run_semgrep(repo_path: str, changed_files: list[str]) -> list[ToolFinding]` where
  `ToolFinding(file: str, line: int, rule_id: str, message: str, severity: str)`
- Also produces: `parse_semgrep_json(raw: dict) -> list[ToolFinding]` — the pure function the test targets

- [x] **Step 1: Write the failing test** against `parse_semgrep_json` using a saved real Semgrep JSON
  fixture (generate it once by running Semgrep on the Task-1 fixture file, save the output). Assert
  rule_id, file, and line are extracted and that `severity` maps `ERROR->block`, `WARNING->warn`,
  `INFO->nit`.
- [x] **Step 2: Run test, verify it fails**
- [x] **Step 3: Implement** — `run_semgrep` shells out to
  `semgrep --config=p/security-audit --json <files>`; `parse_semgrep_json` does the pure parsing.
  Subprocess call is NOT under test; the parser is.
- [x] **Step 4: Run tests, verify pass**
- [x] **Step 5: Commit** — `feat: wrap semgrep as a tool returning ToolFindings`

### Task 3: Repo context extractor

**Files:**
- Create: `src/guardian/tools/repo_context.py`
- Test: `tests/test_repo_context.py` (uses a tiny fake repo under `tests/fixtures/fakerepo/`)

**Interfaces:**
- Produces: `get_context(repo_path: str, file: str, line: int) -> FileContext` where
  `FileContext(enclosing_function: str, related_tests: list[str], imports: list[str])`

- [x] **Step 1: Write failing tests** — enclosing function is found for a line inside a function;
  a test file referencing that function name is listed in `related_tests`; imports are extracted.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement** using `ast` for Python files (walk `FunctionDef` nodes, pick the one whose
  line range contains `line`), and a plain filename+symbol grep for `related_tests`. Non-Python files:
  return ±20 raw lines as `enclosing_function` and empty lists — do not build a multi-language parser.
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Commit** — `feat: extract enclosing function, related tests, imports`

---

## Phase 2 — Agents

### Task 4: LLM client seam + SecurityAgent

**Files:**
- Create: `src/guardian/llm/client.py` (thin wrapper: `complete(system: str, user: str, model: str) -> str`)
- Create: `src/guardian/agents/base.py` (shared prompt assembly + `Finding` JSON parsing/validation)
- Create: `src/guardian/agents/security.py`
- Test: `tests/test_security_agent.py`

**Interfaces:**
- Consumes: `PRContext`, `list[ToolFinding]`, `FileContext`
- Produces: `SecurityAgent().review(ctx: PRContext, tools: list[ToolFinding]) -> list[Finding]`
- Produces: `parse_findings(raw: str, agent: str) -> list[Finding]` in `base.py` — drops any finding
  missing `file`/`line` or with malformed JSON, never raises

- [x] **Step 1: Write failing tests** — feed `parse_findings` (a) well-formed JSON → 2 findings,
  (b) JSON with one finding missing `line` → that one dropped, (c) non-JSON garbage → empty list.
  Then test `review()` with a fake client injected, asserting it returns parsed findings.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement.** System prompt states the mandate and the "must NOT" line from `agent.md`
  §2 verbatim, demands JSON array output matching the `Finding` schema, and requires `evidence` to be
  a literal quote from the diff. Model: Haiku.
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Commit** — `feat: add LLM client seam and SecurityAgent`

### Task 5: ArchitectureAgent + BusinessLogicAgent

**Files:**
- Create: `src/guardian/agents/architecture.py`, `src/guardian/agents/business_logic.py`
- Test: `tests/test_agents.py`

- [x] **Step 1: Write failing tests** — each agent, with a fake client, returns parsed findings and
  tags `finding.agent` with its own name.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement** both as subclasses of the Task-4 base; only the system prompt and the
  context they request differ (Architecture gets imports + file tree, BusinessLogic gets enclosing
  function + related tests — per `agent.md` §2).
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Commit** — `feat: add architecture and business-logic reviewer agents`

### Task 6: Orchestrator (3 rounds) + verdict rule + cost meter

**Files:**
- Create: `src/guardian/orchestrator.py`, `src/guardian/agents/chief.py`
- Create: `src/guardian/cli.py` (`python -m guardian.cli review <repo> <diff-file>`)
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Produces: `review_pr(repo_path: str, diff_text: str, client) -> Verdict`
- Produces: `decide(findings: list[Finding]) -> Literal["approve","request_changes","block"]` — pure
  function implementing `agent.md` §4's threshold rule

- [x] **Step 1: Write failing tests** for `decide()` first (pure, no LLM): block finding at 0.7 → block;
  block finding at 0.69 → falls through to warn rules; warn at 0.5 → request_changes; nothing → approve.
  Then an end-to-end `review_pr` test with a fake client scripted for all three rounds, asserting
  Round 2 prompts contain other agents' findings and that findings lacking `line` never reach the chief.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement** rounds per `agent.md` §4 — Round 1 agents in parallel
  (`concurrent.futures.ThreadPoolExecutor`), Round 2 rebuttals (findings text only, no diff re-send),
  Round 3 chief pass on Sonnet. Log per-call token usage to `runs/<timestamp>.json`.
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Measure real cost** — measured 2026-09-23: **$0.0124/PR** (ceiling $0.15). — run the CLI against the Task-1 fixture diff with real API keys
  once; confirm total cost < $0.15 and record it in `runs/`. If over, cut Round 2 context first.
- [x] **Step 6: Commit** — `feat: orchestrate 3-round review with deterministic verdict rule`

---

## Phase 3 — The part that makes it real: benchmark

### Task 7: Benchmark dataset builder

**Files:**
- Create: `benchmark/build_dataset.py`, `benchmark/dataset/` (gitignored raw data, committed manifest)
- Test: `tests/test_dataset_builder.py`

**Interfaces:**
- Produces: `benchmark/dataset/manifest.json` — list of
  `{id, repo, commit, diff_path, is_vulnerable: bool, cve_id: str|None, category: str|None}`

- [x] **Step 1: Write failing test** — manifest builder rejects an entry missing `is_vulnerable`, and
  produces balanced counts (equal positives and negatives) or fails loudly.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement.** Positives: CVE-fixing commits from a public dataset (CVEfixes/BigVul
  slice), filtered to Python/JS, taking the **pre-fix** diff. Negatives: merged PRs from the same
  repos with no linked CVE. Target 40-60 total, balanced. Store diffs as files, commit the manifest
  only.
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Commit** — `feat: build balanced benchmark dataset from CVE-fix commits`

### Task 8: Evaluation harness + Semgrep baseline

**Files:**
- Create: `benchmark/evaluate.py`, `benchmark/baselines.py`
- Test: `tests/test_evaluate.py`

**Interfaces:**
- Produces: `score(predictions: list[str], labels: list[bool]) -> Metrics` with
  `Metrics(precision, recall, f1, tp, fp, tn, fn)`
- Produces: `noise_ratio(verdicts, labels) -> float` — mean findings per *benign* PR
- Produces: `semgrep_baseline(diff, repo) -> str` — `"request_changes"` if ≥1 Semgrep finding else `"approve"`

- [x] **Step 1: Write failing tests** for `score()` with hand-computed tiny cases (3 TP, 1 FP, 2 FN →
  known precision/recall), and for `noise_ratio` ignoring vulnerable examples.
- [x] **Step 2: Run, verify fail**
- [x] **Step 3: Implement** metrics + baseline; `evaluate.py` runs both the full pipeline and the
  baseline over the manifest, writes `benchmark/results/<timestamp>.json` with raw counts (not just
  percentages, per `agent.md` §7).
- [x] **Step 4: Run, verify pass**
- [x] **Step 5: Commit** — `feat: evaluation harness with semgrep baseline comparison`

### Task 9: Calibration loop + results writeup

**Files:**
- Modify: agent system prompts, `orchestrator.decide` thresholds
- Create: `RESULTS.md`

- [x] **Step 1: Run the full benchmark** — record baseline vs. pipeline F1 and noise ratio.
- [x] **Step 2: Inspect every false positive and false negative by hand** — categorize causes
  (prompt issue / threshold issue / Semgrep coverage gap). This is the actual engineering work; budget
  the most time here.
- [x] **Step 3: Change ONE variable at a time** (a prompt, or a threshold — never both), re-run, record.
  Keep every run's JSON; the run history is portfolio evidence.
- [x] **Step 4: Write `RESULTS.md`** — table of pipeline vs. Semgrep baseline (precision/recall/F1/noise
  ratio with raw counts), the failure-mode breakdown from Step 2, and an honest limitations section
  copied from `agent.md` §7. If the pipeline loses to the baseline, report that — it's still a result.
- [x] **Step 5: Commit** — `docs: benchmark results and failure analysis`

---

## Phase 4 — Optional, only after Phase 3 produces numbers

### Task 10: GitHub Action wrapper

- [x] Package the CLI as a GitHub Action that runs on `pull_request`, posts the `Verdict` as a single
  review comment (one comment, not one per finding — noise is the enemy, §1).
- [ ] Dogfood it on this repo's own PRs for a week before showing anyone.

**Do not start Phase 4 before `RESULTS.md` exists.** A shipped integration with no numbers behind it
is exactly the "impressive demo, no substance" outcome this project is designed to avoid.
