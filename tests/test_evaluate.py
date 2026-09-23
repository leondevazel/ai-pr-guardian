from benchmark.evaluate import noise_ratio, score
from guardian.models import Finding, Verdict


def verdict(decision, n_findings=0):
    findings = [
        Finding("security", "a.py", i + 1, "warn", "c", "claim", "evidence", 0.6)
        for i in range(n_findings)
    ]
    return Verdict(decision=decision, findings=findings, rationale="")


# --- score(): hand-computed so a regression in the metric itself is visible ---

PREDICTIONS = ["block", "block", "block", "request_changes", "approve", "approve", "approve", "approve"]
LABELS = [True, True, True, False, True, True, False, False]
# 3 TP, 1 FP, 2 FN, 2 TN


def test_counts_confusion_matrix():
    m = score(PREDICTIONS, LABELS)
    assert (m.tp, m.fp, m.fn, m.tn) == (3, 1, 2, 2)


def test_precision_and_recall():
    m = score(PREDICTIONS, LABELS)
    assert m.precision == 0.75
    assert m.recall == 0.6


def test_f1_is_harmonic_mean():
    m = score(PREDICTIONS, LABELS)
    assert round(m.f1, 4) == 0.6667


def test_request_changes_counts_as_flagged():
    m = score(["request_changes"], [True])
    assert m.tp == 1


def test_perfect_predictions():
    m = score(["block", "approve"], [True, False])
    assert (m.precision, m.recall, m.f1) == (1.0, 1.0, 1.0)


def test_no_predictions_at_all_does_not_divide_by_zero():
    m = score(["approve", "approve"], [True, True])
    assert (m.precision, m.recall, m.f1) == (0.0, 0.0, 0.0)


# --- noise_ratio(): findings per benign PR, the number the thesis lives on ---


def test_noise_ratio_ignores_vulnerable_examples():
    verdicts = [verdict("block", 5), verdict("approve", 1), verdict("approve", 3)]
    labels = [True, False, False]
    assert noise_ratio(verdicts, labels) == 2.0


def test_noise_ratio_is_zero_when_benign_prs_are_clean():
    assert noise_ratio([verdict("approve", 0), verdict("approve", 0)], [False, False]) == 0.0


def test_noise_ratio_without_benign_examples_is_zero():
    assert noise_ratio([verdict("block", 4)], [True]) == 0.0
