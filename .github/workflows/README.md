# Workflows — action pinning

**Every GitHub Action in this repository is pinned to a full commit SHA**, with the
human-readable version kept as a trailing comment:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

## Why

A tag is mutable. Whoever controls an action can change what `@v4` resolves to after
you reviewed it, and your workflow will silently run the new code with whatever
permissions the job holds. A commit SHA is immutable, so what you reviewed is what
runs.

This is the exact supply chain weakness CyberOps Kit reports on other people's
repositories — our SLSA evaluator emits a `slsa-unpinned-action` finding for every
unpinned reference it finds. Leaving our own workflows unpinned while shipping that
check would have been indefensible, and our self-scan reported all 19 of them against
us until this was fixed.

## Keeping pins current

Pinning does not mean freezing. Dependabot is configured for `github-actions` in
[`dependabot.yml`](../dependabot.yml) and understands SHA pins — it opens PRs that
bump both the SHA and the version comment together.

To re-pin by hand:

```bash
# Resolve one action to the SHA of its latest release
gh api repos/actions/checkout/releases/latest --jq .tag_name
gh api repos/actions/checkout/commits/v7.0.1 --jq .sha

# Or do the whole tree at once
go install github.com/suzuki-shunsuke/pinact/cmd/pinact@latest
pinact run .github/workflows/*.yml action.yml
```

After any change, confirm nothing regressed:

```bash
make selfscan   # expect zero slsa-unpinned-action findings
```

## Verifying

Every `uses:` reference must end in a 40-character hex SHA:

```bash
grep -rhoE 'uses:\s*\S+' .github/workflows/*.yml action.yml \
  | sed 's/uses:\s*//' | grep -vE '@[0-9a-f]{40}$'
```

That command printing nothing is the passing state.
