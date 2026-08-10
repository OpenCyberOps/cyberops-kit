# Workflows — action pinning status

## ⚠️ Open item before `v1.0.0`

Our trust posture (SECURITY.md) requires that **every GitHub Action is pinned to a full commit SHA,
not a tag**. The workflows in this directory currently reference tags
(`actions/checkout@v4`, etc.).

This is tracked, deliberate, and visible rather than silently wrong:

- A tag is mutable. Whoever controls the action can change what `@v4` resolves to
  after it was reviewed. That is the exact supply chain weakness this project
  reports on other people's repositories.
- Our own SLSA evaluator (`src/cyberops_kit/scanners/slsa.py`) emits a
  `slsa-unpinned-action` finding for every reference below, and the self-scan
  workflow publishes that result. We do not exempt ourselves.

## How to fix it

Resolve each tag to its current commit SHA and rewrite the reference, keeping the
tag as a trailing comment so humans can still read it:

```bash
# One action:
gh api repos/actions/checkout/git/refs/tags/v4 --jq .object.sha

# All of them, automatically:
go install github.com/suzuki-shunsuke/pinact/cmd/pinact@latest
pinact run .github/workflows/*.yml
```

The result should look like:

```yaml
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
```

Then re-run `make selfscan` and confirm the `slsa-unpinned-action` findings are
gone and `supply_chain_integrity` improves.

## Why this was not done automatically

Pinning requires resolving each tag against the GitHub API. Writing SHAs that were
not actually looked up would produce workflows that fail to run, and would be
precisely the kind of unverified claim this project exists to catch.
