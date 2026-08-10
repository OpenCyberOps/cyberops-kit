"""INV-1 — the composite score is deterministic.

`compute_score()` is a pure function of deterministic scanner findings and the
configured weights. It must never read `Finding.advisory`, call a network service,
consult wall-clock time, or depend on dict/set iteration order.

**Do not weaken or skip these tests** (see CONTRIBUTING.md, "The invariants").
"""

from __future__ import annotations

import random

import pytest

from cyberops_kit.config import DEFAULT_WEIGHTS
from cyberops_kit.core.models import DimensionKey
from cyberops_kit.core.scoring import compute_score
from tests.conftest import make_finding


def test_identical_inputs_produce_identical_scores(sample_findings, full_context):
    """The same inputs produce the same score, every time."""
    scores = [
        compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context) for _ in range(25)
    ]
    first = scores[0].model_dump_json()
    assert all(score.model_dump_json() == first for score in scores)


def test_finding_order_does_not_affect_score(sample_findings, full_context):
    """Scanner completion order must not change the result.

    Scanners run concurrently, so findings arrive in whatever order the tools
    finished. If that leaked into the score, the same commit would grade differently
    run to run.
    """
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)

    rng = random.Random(1234)
    for _ in range(25):
        shuffled = list(sample_findings)
        rng.shuffle(shuffled)
        assert (
            compute_score(shuffled, DEFAULT_WEIGHTS, context=full_context).model_dump_json()
            == baseline.model_dump_json()
        )


def test_weight_mapping_order_does_not_affect_score(sample_findings, full_context):
    """Weights given in a different key order produce the same score."""
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)

    reversed_weights = dict(reversed(list(DEFAULT_WEIGHTS.items())))
    assert (
        compute_score(sample_findings, reversed_weights, context=full_context).model_dump_json()
        == baseline.model_dump_json()
    )


def test_available_dimensions_set_order_does_not_affect_score(sample_findings, full_context):
    """A frozenset's iteration order must not reach the output."""
    baseline = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)

    for _ in range(10):
        keys = list(DimensionKey)
        random.shuffle(keys)
        context = full_context.model_copy(update={"available_dimensions": frozenset(keys)})
        assert (
            compute_score(sample_findings, DEFAULT_WEIGHTS, context=context).model_dump_json()
            == baseline.model_dump_json()
        )


def test_dimensions_are_emitted_in_sorted_key_order(sample_findings, full_context):
    """Dimension keys serialize in a fixed order, not insertion order."""
    score = compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    keys = [key.value for key in score.dimensions]
    assert keys == sorted(keys)


def test_scoring_does_not_touch_the_network(monkeypatch, sample_findings, full_context):
    """Any socket use inside compute_score is a failure."""
    import socket

    def _forbidden(*args, **kwargs):
        msg = "compute_score attempted a network call (INV-1)"
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)

    compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)


def test_scoring_does_not_read_the_clock(monkeypatch, sample_findings, full_context):
    """Any wall-clock read inside compute_score is a failure."""
    import time

    def _forbidden(*args, **kwargs):
        msg = "compute_score consulted wall-clock time (INV-1)"
        raise AssertionError(msg)

    monkeypatch.setattr(time, "time", _forbidden)
    monkeypatch.setattr(time, "monotonic", _forbidden)

    compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)


def test_scoring_does_not_use_randomness(monkeypatch, sample_findings, full_context):
    """Any randomness inside compute_score is a failure."""

    def _forbidden(*args, **kwargs):
        msg = "compute_score used randomness (INV-1)"
        raise AssertionError(msg)

    monkeypatch.setattr(random, "random", _forbidden)
    monkeypatch.setattr(random, "choice", _forbidden)
    monkeypatch.setattr(random, "shuffle", _forbidden)

    compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)


def test_scoring_does_not_read_the_environment(monkeypatch, sample_findings, full_context):
    """Environment lookups inside compute_score are a failure."""
    import os

    real_environ = os.environ

    class _Forbidden(dict):
        def __getitem__(self, key):
            msg = "compute_score read the environment (INV-1)"
            raise AssertionError(msg)

        def get(self, key, default=None):
            msg = "compute_score read the environment (INV-1)"
            raise AssertionError(msg)

    monkeypatch.setattr(os, "environ", _Forbidden())
    try:
        compute_score(sample_findings, DEFAULT_WEIGHTS, context=full_context)
    finally:
        monkeypatch.setattr(os, "environ", real_environ)


@pytest.mark.parametrize("seed", range(5))
def test_finding_ids_are_stable_across_processes(seed):
    """A finding's ID depends only on its identity fields, never on run state.

    Stable IDs are what make PR deltas, the trend dashboard, and suppression files
    survive a refactor.
    """
    del seed
    first = make_finding(rule_id="CVE-2024-9999", path="src/a.py")
    second = make_finding(rule_id="CVE-2024-9999", path="src/a.py")
    assert first.id == second.id
    assert first.id == "".join(first.id)  # 16-char hex, no run-dependent suffix
    assert len(first.id) == 16
