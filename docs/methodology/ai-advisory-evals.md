# AI advisory evals

**Status: harness built, results not yet published.**

This page will carry measured precision and recall for the AI advisory layer, per
model and per prompt version, including the cases where it performs badly. Until it
does, treat the advisory layer as **unproven** — the code is tested, the quality is
not measured.

That distinction is the whole point of this page existing before it has numbers in
it. Publishing a security feature with no measurement and letting readers assume it
works is the pattern this project was built to avoid.

---

## What will be measured

The task is **false-positive identification**: given a finding a scanner reported,
did the model correctly recognize it as not genuinely exploitable in this codebase?

That framing is deliberate. It is the judgment a maintainer would actually act on,
and it is the one where being wrong is expensive.

| Metric | Meaning | Why it matters |
|---|---|---|
| Precision | Of the findings called false positives, how many were | A wrong call here means a real vulnerability gets ignored. **This is the number to watch.** |
| Recall | Of the actual false positives, how many were identified | Low recall is a missed convenience, not a safety problem |
| Abstention rate | Share answered `unclear` | Abstaining beats guessing, but a model that abstains on everything is useless |
| No advisory | Share where no advisory was produced at all | Provider failures, malformed replies, budget cuts — not model errors |

**Precision is weighted above recall**, and the published results will say so. A
model that misses false positives wastes a maintainer's time. A model that confidently
dismisses a real vulnerability causes the harm the tool exists to prevent.

Abstentions are counted separately and never scored as errors. The prompt tells the
model that "not enough context" is a correct answer; penalizing that in the metrics
would contradict the prompt and train the corpus toward overconfidence.

---

## The corpus

Hand-labeled cases live in `tests/advisors/evals/corpus.py`. Each carries:

- the finding and the fixture it came from
- a human label: `true_positive` or `false_positive`
- **a written justification** — enforced by a test, because a label nobody can
  defend in review is an opinion, and precision measured against opinions is not a
  measurement

The corpus is deliberately small and hand-checked rather than large and
auto-labeled. Ground truth the model never saw is the only thing that makes these
numbers mean anything.

**Growing the corpus is the highest-value contribution to this layer.** A case needs
a finding, a label, and a justification a reviewer can disagree with.

---

## How results will be gated

Once numbers are published:

- A prompt change that lowers precision does not merge.
- Each prompt version is measured separately, so a regression is attributable.
- Results are published per model, because they will differ — especially between a
  local 8B model and a frontier one, and users deserve to know which they are getting.

---

## What is already enforced

Ahead of any measurement, these hold today and are covered by tests:

- A malformed reply drops the advisory rather than degrading the finding
- A fourth assessment value is rejected, never coerced into one of the three
- An empty rationale is rejected
- Advisory content cannot influence the score, the grade, the SARIF `level`, or the
  exit code, whatever it says
- Every advisory records its provider, model ID, and prompt version, so any output
  traces back to what produced it

Those are correctness properties, not quality ones. They guarantee the layer cannot
cause harm through the scoring path; they say nothing about whether its rationales
are any good. That is what this page is for.
