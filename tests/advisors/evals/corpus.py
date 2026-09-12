"""The labeled eval corpus and the metrics computed over it.

An advisory layer nobody has measured is a liability. This module holds the labels
and the scoring; ``run_evals.py`` drives real inference against them.

**Labels are human judgments, not model output.** Each carries a written
justification, and a label nobody can defend in review does not belong here. The
corpus is small on purpose — a hand-checked corpus of thirty is worth more than a
thousand auto-labeled ones, because the whole point is to have ground truth the
model never saw.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Label = Literal["true_positive", "false_positive"]


@dataclass(frozen=True)
class EvalCase:
    """One labeled finding.

    Attributes:
        case_id: Stable identifier, cited in published results.
        fixture: Which Phase 1 fixture repository this came from.
        rule_id: The scanner rule that produced the finding.
        label: The human ground-truth judgment.
        justification: Why a human labeled it this way. Required — an unjustified
            label is an opinion, and publishing precision against opinions would be
            exactly the unmeasured claim this harness exists to avoid.
        notes: Optional context on what makes the case hard.
    """

    case_id: str
    fixture: str
    rule_id: str
    label: Label
    justification: str
    notes: str = ""


@dataclass(frozen=True)
class EvalOutcome:
    """What the model said about one case.

    Attributes:
        case: The labeled case.
        assessment: The model's assessment, or ``None`` when no advisory was
            produced (a failure, a malformed reply, or a budget cut).
        confidence: The model's stated confidence, when it produced one.
        rationale: The model's rationale, retained so published results can quote
            the bad ones as well as the good.
    """

    case: EvalCase
    assessment: str | None
    confidence: str | None = None
    rationale: str = ""


@dataclass(frozen=True)
class Metrics:
    """Precision and recall on false-positive identification.

    The task being measured is specifically *"did the model correctly identify a
    false positive"*, because that is the judgment a maintainer would act on. Calling
    a true finding a false positive is the expensive error — it is how a real
    vulnerability gets ignored — so precision matters more than recall here, and the
    published results say so.

    Attributes:
        true_positives: Correctly called a false positive.
        false_positives: Called a false positive when it was real. The costly error.
        false_negatives: Was a false positive, but not identified as one.
        abstentions: Answered ``unclear``. Counted separately, never as a mistake.
        no_advisory: No advisory was produced at all.
    """

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    abstentions: int = 0
    no_advisory: int = 0

    @property
    def precision(self) -> float:
        """Share of false-positive calls that were correct.

        Returns:
            Precision in ``[0, 1]``, or ``0.0`` when no calls were made.
        """
        called = self.true_positives + self.false_positives
        return self.true_positives / called if called else 0.0

    @property
    def recall(self) -> float:
        """Share of actual false positives that were identified.

        Returns:
            Recall in ``[0, 1]``, or ``0.0`` when the corpus has no false positives.
        """
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else 0.0

    @property
    def abstention_rate(self) -> float:
        """Share of cases answered ``unclear``.

        A high rate is not automatically bad — abstaining beats guessing — but a
        model that abstains on everything is useless, so it is reported rather than
        hidden inside recall.

        Returns:
            Abstention rate in ``[0, 1]``.
        """
        total = self.total
        return self.abstentions / total if total else 0.0

    @property
    def total(self) -> int:
        """Return the number of cases scored."""
        return (
            self.true_positives
            + self.false_positives
            + self.false_negatives
            + self.abstentions
            + self.no_advisory
        )


def score(outcomes: list[EvalOutcome]) -> Metrics:
    """Compute metrics over a set of outcomes.

    Args:
        outcomes: One outcome per case.

    Returns:
        The aggregated metrics.
    """
    true_positives = false_positives = false_negatives = abstentions = no_advisory = 0

    for outcome in outcomes:
        if outcome.assessment is None:
            no_advisory += 1
        elif outcome.assessment == "unclear":
            abstentions += 1
        elif outcome.assessment == "likely_false_positive":
            if outcome.case.label == "false_positive":
                true_positives += 1
            else:
                false_positives += 1
        elif outcome.case.label == "false_positive":
            false_negatives += 1

    return Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        abstentions=abstentions,
        no_advisory=no_advisory,
    )


CORPUS: list[EvalCase] = [
    EvalCase(
        case_id="fixture-lodash-prototype-pollution",
        fixture="tests/fixtures/",
        rule_id="CVE-2020-8203",
        label="false_positive",
        justification=(
            "lodash@4.17.20 appears only in a parser test fixture, never in a "
            "dependency manifest that ships. The vulnerable `zipObjectDeep` path is "
            "not reachable from any entrypoint in this repository."
        ),
        notes="Tests whether the model uses the fixture path as evidence.",
    ),
    EvalCase(
        case_id="fixture-requests-cve",
        fixture="tests/fixtures/",
        rule_id="CVE-2018-18074",
        label="false_positive",
        justification=(
            "requests@2.19.0 is sample data inside an OSV-Scanner output fixture, "
            "not an installed dependency. No Python code in this repository imports it."
        ),
    ),
    EvalCase(
        case_id="selfscan-curl-pipe-sh",
        fixture="self",
        rule_id="curl-pipe-sh",
        label="true_positive",
        justification=(
            "self-scan.yml installs scanner binaries by piping curl output into sh. "
            "This is a genuine supply chain exposure in our own CI, is reachable on "
            "every run, and is tracked as real work rather than excluded."
        ),
        notes="Our own finding. A model that calls this a false positive is wrong.",
    ),
]
"""Hand-labeled cases.

Deliberately seeded rather than exhaustive. Growing this corpus is the highest-value
contribution to the advisory layer, and ``docs/contributing/`` should say so. Each
new case needs a written justification a reviewer can disagree with.
"""


__all__ = ["CORPUS", "EvalCase", "EvalOutcome", "Label", "Metrics", "score"]
