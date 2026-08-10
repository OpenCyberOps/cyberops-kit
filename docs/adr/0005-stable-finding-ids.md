# ADR 0005 — Content-anchored finding IDs

**Status:** Accepted

## Context

Three features depend on recognizing "the same finding" across two runs:

- PR comment deltas ("3 new, 5 fixed since `main`")
- The historical trend dashboard
- A suppression / accepted-risk file that survives refactors

The naive identity is `(file, line, rule)`. It breaks immediately: adding an import
at the top of a file shifts every line below it, and every finding in that file
appears to be simultaneously fixed and newly introduced.

## Decision

```
Finding.id = sha256(scanner | rule_id | normalized_path | package_purl | line_anchor)[:16]
```

Two properties matter:

**The path is normalized.** Repo-relative, POSIX separators, no `./` prefix. The same
file yields the same ID whether checked out to `/home/x/repo` or `C:\repo`, in CI or
locally.

**The anchor prefers content over position.** In order:

1. A content hash from the tool, or one we compute from the matched text
2. An enclosing symbol name
3. A line number — only when the tool offers nothing better

Semgrep findings hash the matched source text; Gitleaks findings hash the tool's own
fingerprint; SLSA findings anchor on the action reference. So `subprocess.run(user_input,
shell=True)` keeps its identity when it moves from line 42 to line 500.

**The version is deliberately excluded.** A tool upgrade must not renumber every
finding, or every scanner update would report the entire backlog as new. Versions are
recorded in `run_metadata.tool_versions` so a score change remains traceable.

## Consequences

**Good:**

- Deltas survive refactors, reformatting, and file moves within the same path.
- Suppression files stay valid across unrelated changes.
- IDs are computed in exactly one place (`compute_finding_id`), called through one
  entry point (`Finding.build`).

**Bad, and accepted:**

- Editing the flagged line itself changes the ID, so a finding reappears as "new"
  even if the fix was cosmetic. The alternative — fuzzy matching — risks silently
  hiding a real regression, which is worse.
- Tools that report neither a fingerprint nor a symbol fall back to line numbers and
  get the fragile behavior. Nothing we can do beyond documenting which do.
- 16 hex characters is 64 bits. Collisions are implausible but not impossible;
  `normalize.assert_unique_ids()` checks rather than assumes.
- Cross-scanner deduplication is **not** attempted. Two scanners reporting the same
  CVE produce two findings. We configure Trivy to misconfig-only so the Phase 1 set
  does not overlap, and we prefer a visible duplicate to a heuristic that drops a
  real finding.
