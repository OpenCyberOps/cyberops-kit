# Contributing to CyberOps Kit

Thanks for helping. The most valuable contribution is usually a **new scanner
plugin**, and that path is deliberately short — see
[docs/contributing/add-a-scanner.md](docs/contributing/add-a-scanner.md).

## Setup

```bash
git clone https://github.com/OpenCyberOps/cyberops-kit
cd cyberops-kit
make install     # editable install + dev extras + pre-commit hooks
make test        # should pass immediately
```

## The commands you need

```bash
make lint             # ruff check + ruff format --check
make typecheck        # mypy --strict on src/
make test             # pytest, unit + invariants
make invariants       # the INV-* guards — run before every commit
make coverage         # enforce the 80% floor on core/
make test-integration # requires Docker and the scanner binaries
make selfscan         # run CyberOps Kit against itself
```

**`make invariants` must pass before any commit that touches `core/`.** The
pre-commit hook runs it for you.

## The invariants

Seven rules make this project trustworthy. A change that violates any of them is
wrong even if it passes tests, and each is enforced by a test in
[`tests/invariants/`](tests/invariants/):

| | |
|---|---|
| **INV-1** | The composite score is deterministic — pure function, no clock, no network, no iteration-order dependence. |
| **INV-2** | AI output never influences the score. |
| **INV-3** | Same commit + tool versions + config ⇒ byte-identical `results`. |
| **INV-4** | No secret leaves the process unredacted. No bypass flag. |
| **INV-5** | Untrusted code is never executed on the host. |
| **INV-6** | `--offline` is absolute; code that cannot honor it fails loudly. |
| **INV-7** | Scoring methodology stays public and versioned. |

If your change conflicts with one of these, please open an issue to discuss it
before writing code. We would rather talk it through than reject a finished PR.

## Code conventions

- Python 3.11+, full type annotations, `mypy --strict` clean.
- Pydantic v2 for every structure crossing a module boundary. No bare dicts in
  public signatures.
- `ruff` for lint and format. No competing formatter.
- `asyncio` for concurrency; scanner execution is I/O-bound subprocess work.
- Structured logging via `structlog`. Never `print()` outside `cli.py`.
- Custom exceptions from `core/errors.py`. Never raise bare `Exception`.
- Docstrings on every public function, class, and module.
- Coverage floor: **80% on `src/cyberops_kit/core/`**.

Write code that reads like the code around it.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
  `docs:`, `chore:`, `refactor:`, `test:`, `ci:`. The changelog is generated from
  these.
- **Sign off your commits (DCO):** `git commit -s`.
- **One logical change per PR.** Never bundle a refactor with a feature.
- Semantic versioning.

### Adding a dependency

Every dependency is supply chain surface, and we would fail our own audit if we
were careless about it. Justify any new dependency in the PR description: what it
does, why the standard library is not enough, and what its own dependency tree
looks like.

### Changing the scoring model

Scoring changes require, **in the same commit**:

1. The code change in `core/scoring.py`
2. An update to [`docs/methodology/scoring.md`](docs/methodology/scoring.md)
3. A bump to `SCORING_MODEL_VERSION`
4. Green invariants

Scoring is never rewritten to improve the score of any specific repository,
including our own.

## Phase discipline

The project ships in two phases, and **Phase 1 is the current one**: the
deterministic core, with no AI involvement anywhere.

Phase 2 will add an optional AI advisory layer, bounded by
[ADR 0004](docs/adr/0004-ai-boundary.md). Do not implement Phase 2 features yet, and
do not delete the `enrich` stage or the `advisors/` package because they look
unused — they are load-bearing seams that let Phase 2 add files instead of
rewriting the pipeline. `src/cyberops_kit/advisors/README.md` explains what goes
there and what the boundary forbids.

## Reporting security issues

Not here. See [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
