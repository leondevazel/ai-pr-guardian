# Benchmark Results

**Dataset:** 38 PR-sized diffs — 19 built from real CVE fix commits read backwards, 19 ordinary
commits from the same five repositories (Django, Pillow, aiohttp, Flask, requests). Both classes are
reduced to production source files, so the label cannot leak through deleted regression tests or
release notes. Median changed lines: 10 (vulnerable) vs 9 (benign).

**Cost:** $0.97 per full run, ~$0.026 per PR reviewed.

## Headline

| view | precision | recall | F1 | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|
| full pipeline | 0.58 | 0.95 | **0.72** | 18 | 13 | 1 | 6 |
| security findings only | **1.00** | 0.32 | 0.48 | 6 | 0 | 13 | 19 |
| Semgrep baseline | 0.33 | 0.11 | 0.16 | 2 | 4 | 17 | 15 |

Findings per benign PR: pipeline 1.11, Semgrep 0.58.

Semgrep is handed the **complete post-change file** — the setting its rules are written for — while
the agents see only the diff. The comparison is tilted toward the baseline on purpose.

## Read the variance before the numbers

The Messages API in the current SDK exposes no temperature, so the pipeline is not deterministic.
Across runs with **identical code**:

| run | pipeline F1 |
|---|---|
| 02 | 0.55 |
| 03 | 0.67 |
| 04 | 0.72 |

Mean 0.65, spread 0.17. Two back-to-back runs disagreed on **14 of 38 verdicts (37%)**. The Semgrep
baseline scored 0.16 in every run.

**So: at n=38, any F1 difference under roughly 0.15 is not interpretable.** The pipeline beating the
baseline (0.65 vs 0.16) clears that bar comfortably. Nothing smaller in this document should be read
as an effect.

## Two operating points, not one

The three agents behave so differently that averaging them into a single verdict hides the result.

- **The security agent is precise and narrow.** Six findings, six real vulnerabilities, zero false
  positives: path traversal (×2), regex injection, auth/authz bypass (×2), unsafe deserialization.
  Confidence 0.75–0.98. It never spoke up on a benign PR in either run.
- **The architecture and business-logic agents are sensitive and noisy.** They caught 12 further
  vulnerable PRs that the security agent missed — but described them as `inverted conditional`,
  `incomplete_conditional`, `boundary-condition-change`, `silent_behavior_change`. They also produced
  **every one of the 13 false positives**.

That second group is not wrong to exist: many CVEs *are* logic bugs, and framing them as logic bugs
is a fair reading. But it means recall of 0.95 is bought entirely with precision of 0.58.

The product conclusion is to stop forcing one verdict: **security findings block a merge; the other
agents' findings post as advisory comments that never block.** That configuration ships at precision
1.00 on the blocking path while still surfacing the rest for a human.

## What the benchmark actually caught: three measurement bugs

Two full runs ($1.90) produced no usable score. They produced this instead, which was worth more:

1. **The diff parser silently deleted `+`/`-` markers.** `unidiff`'s `line.value` omits them, and the
   hunk context was built by joining those values — so agents were shown removed and added lines
   concatenated into code that never existed. They correctly reported the result as unreachable or
   duplicated logic. That single bug produced 15 of the first run's false positives; after the fix,
   that category went to **zero**. The agents were not misreading diffs — they were reading fabricated
   code accurately.
2. **The Semgrep baseline was crippled.** It scanned added lines written to a temp file: unparseable
   fragments, so Semgrep matched nothing anywhere and scored 0.00 across the board. A baseline that
   loses by being broken proves nothing. Fixed to scan the real post-change file.
3. **Run-to-run variance was never measured.** The first comparison (0.65 → 0.55) was read as a
   regression. It was noise, as the 0.55/0.67/0.72 spread on identical code later showed.

## Limitations

- **n = 38.** Every percentage here rests on single-digit counts; that is why raw counts are printed
  beside them. A 0.05 F1 difference means roughly two examples.
- **Python only, five repositories.** Semgrep's Python rules are its strongest, which again favors
  the baseline, but nothing here says anything about other languages.
- **Positives are reversed fix commits.** The vulnerable code is real and shipped, but a real PR
  introducing that bug would rarely look exactly like a patch applied backwards.
- **Agents see the diff, not the repository.** No cross-file taint analysis. A vulnerability that is
  only visible in a caller elsewhere is out of reach by construction.
- **The benchmark label is "contains a known CVE".** It cannot credit a correct architecture or
  business-logic finding, and it cannot detect a vulnerability the diff introduces that nobody ever
  filed a CVE for. Benign examples are assumed clean because no advisory names them.
