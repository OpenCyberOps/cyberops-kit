# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are generated from [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- **Deterministic core pipeline**: `ingest → detect → scan → normalize → enrich →
  score → report`.
- **Canonical data model** (`core/models.py`) including the fully-specified
  `Advisory` model, reserved and always `None` in Phase 1 (SEAM-1).
- **Seven scanner integrations**: OpenSSF Scorecard, OSV-Scanner, Semgrep,
  Gitleaks, Trivy, Syft, and a derived SLSA build-track evaluator.
- **Stable finding IDs** — `sha256(scanner | rule | path | purl | anchor)[:16]`,
  anchored on content or symbol rather than line number, so PR deltas and the trend
  dashboard survive refactors.
- **Deterministic scoring model** (`SCORING_MODEL_VERSION 1.0.0`) with six weighted
  dimensions, grade bands, three hard caps, and proportional weight redistribution
  for excluded dimensions.
- **Excluded scanners distinguish `not_run` from `failed` and `timed_out`.** A
  scanner that was never installed and one that crashed both cost the run a
  dimension, but only one is a bug; reporting both as "skipped" let two real CI
  timeouts hide behind benign-sounding language. `Results.excluded_scanners`
  (formerly `skipped_scanners`) now carries an `outcome`, and the CLI, Markdown,
  HTML and PR comment surface failures separately and prominently.
- **Coverage reporting**: runs that could evaluate less than half the scoring model
  report `NOT SCORED` rather than a misleading grade, and do not fail `--fail-below`.
- **Report renderers**: JSON, SARIF 2.1.0, Markdown, HTML, shields.io badge, and PR
  comment, all with the dormant advisory block in place (SEAM-4).
- **Redaction boundary** (`core/redaction.py`) applied to logs, reports, and
  artifacts, with no bypass flag (SEAM-5, INV-4).
- **Sandboxed execution** (`core/sandbox.py`); `run_host()` structurally refuses to
  execute package managers and build tools (INV-5).
- **Absolute offline mode** — network-requiring scanners skip loudly, and
  `--offline` with AI enabled is a configuration error (INV-6).
- **Config schema** with the reserved, disabled `ai` block (SEAM-3).
- **Enrichment passthrough stage** with runtime contract enforcement (SEAM-2).
- **Historical storage and delta comparison** keyed by commit SHA.
- **GitHub Action**, Dockerfile bundling every scanner, and CI workflows including
  a self-scan that publishes our own result.
- **Public scoring methodology** at `docs/methodology/scoring.md`, including known
  limitations (INV-7).
- **Invariant test suite** covering INV-1 through INV-7 and all six seams.
- **Every GitHub Action pinned to a full commit SHA**, with the version kept as a
  trailing comment. Our own SLSA evaluator reported 19 `slsa-unpinned-action`
  findings against us on the first self-scan; this brings that to zero and flips the
  `pinned-build-dependencies` evidence check to passing.

### Known issues

- SBOM component freshness is not measured; the sub-metric is excluded from
  `sbom_health` rather than assumed healthy.
- Semgrep's `--config=auto` ruleset is not pinned, so static analysis scores can
  move between runs on an unchanged commit.

[Unreleased]: https://github.com/OpenCyberOps/cyberops-kit/commits/main
