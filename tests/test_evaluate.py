from benchmark.evaluate import all_findings_decision, f1_confidence_interval, noise_ratio, score
from guardian.models import Finding, Verdict


def f(agent, severity="block", confidence=0.9):
    return Finding(agent, "a.py", 1, severity, "cat", "claim", "evidence", confidence)


# all_findings_decision is the comparison view: it asks what would happen if advisory findings
# could gate a merge too. The product itself gates on security findings only (orchestrator.decide).


def test_all_findings_view_counts_advisory_findings():
    v = Verdict(decision="approve", findings=[], rationale="", advisory=[f("architecture")])
    assert all_findings_decision(v) == "block"


def test_all_findings_view_counts_security_findings():
    v = Verdict(decision="block", findings=[f("security")], rationale="")
    assert all_findings_decision(v) == "block"


def test_all_findings_view_applies_the_same_thresholds():
    v = Verdict(decision="approve", findings=[f("security", confidence=0.69)], rationale="")
    assert all_findings_decision(v) == "approve"


def test_all_findings_view_approves_when_nothing_was_raised():
    assert all_findings_decision(Verdict(decision="approve", findings=[], rationale="")) == "approve"


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


# --- bootstrap CI: a 38- or 200-example F1 needs an interval, not just a point ---


def test_ci_brackets_the_point_estimate():
    low, high = f1_confidence_interval(PREDICTIONS, LABELS, seed=0)
    point = score(PREDICTIONS, LABELS).f1
    assert low <= point <= high


def test_ci_is_reproducible_with_a_seed():
    assert f1_confidence_interval(PREDICTIONS, LABELS, seed=1) == f1_confidence_interval(
        PREDICTIONS, LABELS, seed=1
    )


def test_perfect_predictions_have_a_degenerate_interval():
    preds, labels = ["block", "approve"] * 10, [True, False] * 10
    assert f1_confidence_interval(preds, labels, seed=0) == (1.0, 1.0)


def test_small_samples_give_wide_intervals():
    low, high = f1_confidence_interval(PREDICTIONS, LABELS, seed=0)
    assert high - low > 0.2
