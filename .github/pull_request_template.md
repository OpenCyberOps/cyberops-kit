## What this changes

<!-- One logical change per PR. Never bundle a refactor with a feature. -->

## Why

## Checklist

- [ ] `make lint` passes
- [ ] `make typecheck` passes
- [ ] `make test` passes
- [ ] `make invariants` passes (**required** for any change under `core/`)
- [ ] Commits use [Conventional Commits](https://www.conventionalcommits.org/) and are signed off (`git commit -s`)

### If this adds a dependency

- [ ] Justified below: what it does, why the stdlib is insufficient, and its own dependency tree

### If this changes scoring behavior

- [ ] `docs/methodology/scoring.md` updated **in this commit** (INV-7)
- [ ] `SCORING_MODEL_VERSION` bumped
- [ ] Not rewritten to improve any specific repository's score

### If this adds a scanner

- [ ] Fixture added under `tests/fixtures/` with known expected findings
- [ ] Registered in `scanners/registry.py`
- [ ] `Finding.raw` preserves the tool's original record
- [ ] Correct `execution_mode` and `requires_network` declared
