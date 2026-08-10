# Architecture Decision Records

These record decisions that would otherwise be re-litigated every six months. Each
states the context, the decision, and the consequences — including the bad ones.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-orchestrate-dont-reimplement.md) | Orchestrate existing tools; never reimplement scanning | Accepted |
| [0002](0002-no-telemetry.md) | No hosted backend, telemetry, or phone-home | Accepted (permanent) |
| [0003](0003-scoring-weights.md) | The six dimensions and their weights | Accepted |
| [0004](0004-ai-boundary.md) | The AI layer annotates; it never grades | Accepted |
| [0005](0005-stable-finding-ids.md) | Content-anchored finding IDs | Accepted |
| [0006](0006-missing-scanner-is-not-a-failure.md) | Exclude dimensions without data; never score them zero | Accepted |
