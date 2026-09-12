"""The eval harness's own correctness.

Published precision and recall are only worth as much as the code computing them.
These tests run no inference; they check the metric definitions and the corpus's
integrity, so that a number in ``docs/methodology/ai-advisory-evals.md`` can be
trusted to mean what it says.
"""

from __future__ import annotations

import pytest

from tests.advisors.evals.corpus import CORPUS, EvalCase, EvalOutcome, score


def case(label: str = "false_positive") -> EvalCase:
    """Build a labeled case."""
    return EvalCase(
        case_id="c",
        fixture="f",
        rule_id="r",
        label=label,  # type: ignore[arg-type]
        justification="j",
    )


# --- Metric definitions ----------------------------------------------------------


def test_a_correct_false_positive_call_counts_as_a_true_positive():
    """Identifying a false positive is the task being measured."""
    metrics = score([EvalOutcome(case("false_positive"), "likely_false_positive")])

    assert metrics.true_positives == 1
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_calling_a_real_finding_a_false_positive_is_penalized():
    """The costly error: a real vulnerability dismissed.

    This is the number that should make a reader nervous, so it must be counted and
    published rather than folded into an aggregate.
    """
    metrics = score([EvalOutcome(case("true_positive"), "likely_false_positive")])

    assert metrics.false_positives == 1
    assert metrics.precision == 0.0


def test_missing_a_false_positive_lowers_recall_not_precision():
    """Failing to spot a false positive is a miss, not a wrong call."""
    metrics = score([EvalOutcome(case("false_positive"), "likely_exploitable")])

    assert metrics.false_negatives == 1
    assert metrics.recall == 0.0


def test_abstaining_is_not_counted_as_an_error():
    """``unclear`` is a valid answer; scoring it as wrong would punish honesty."""
    metrics = score([EvalOutcome(case("false_positive"), "unclear")])

    assert metrics.abstentions == 1
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0


def test_abstention_rate_is_reported_separately():
    """A model that abstains on everything scores 0/0, which must be visible."""
    metrics = score([EvalOutcome(case(), "unclear") for _ in range(4)])

    assert metrics.abstention_rate == 1.0
    assert metrics.precision == 0.0


def test_a_missing_advisory_is_tracked_distinctly():
    """A provider outage is not a model error and must not pollute precision."""
    metrics = score([EvalOutcome(case(), None)])

    assert metrics.no_advisory == 1
    assert metrics.precision == 0.0
    assert metrics.total == 1


def test_metrics_do_not_divide_by_zero_on_an_empty_corpus():
    """Empty input yields zeros, never a crash."""
    metrics = score([])

    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.abstention_rate == 0.0
    assert metrics.total == 0


def test_total_accounts_for_every_outcome():
    """No outcome may be silently dropped from the denominator."""
    outcomes = [
        EvalOutcome(case("false_positive"), "likely_false_positive"),
        EvalOutcome(case("true_positive"), "likely_false_positive"),
        EvalOutcome(case("false_positive"), "likely_exploitable"),
        EvalOutcome(case("false_positive"), "unclear"),
        EvalOutcome(case("false_positive"), None),
    ]

    assert score(outcomes).total == len(outcomes)


def test_a_mixed_run_computes_the_expected_rates():
    """An end-to-end arithmetic check on a hand-worked example."""
    outcomes = [
        EvalOutcome(case("false_positive"), "likely_false_positive"),
        EvalOutcome(case("false_positive"), "likely_false_positive"),
        EvalOutcome(case("true_positive"), "likely_false_positive"),
        EvalOutcome(case("false_positive"), "likely_exploitable"),
    ]

    metrics = score(outcomes)

    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == pytest.approx(2 / 3)


# --- Corpus integrity ------------------------------------------------------------


def test_the_corpus_is_not_empty():
    """A harness with no cases publishes nothing."""
    assert CORPUS


def test_every_case_has_a_unique_id():
    """IDs are cited in published results, so collisions would be misleading."""
    ids = [c.case_id for c in CORPUS]
    assert len(ids) == len(set(ids))


def test_every_label_carries_a_written_justification():
    """An unjustified label is an opinion.

    Publishing precision measured against opinions would be exactly the unmeasured
    claim this harness exists to prevent, so the check is structural.
    """
    for entry in CORPUS:
        assert entry.justification.strip(), f"{entry.case_id} has no justification"
        assert len(entry.justification) > 40, f"{entry.case_id}'s justification is too thin"


def test_the_corpus_contains_both_labels():
    """A single-label corpus makes precision or recall meaningless."""
    labels = {c.label for c in CORPUS}
    assert labels == {"true_positive", "false_positive"}
