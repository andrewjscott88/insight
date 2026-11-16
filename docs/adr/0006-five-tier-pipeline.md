# ADR 0006: Five-tier CI/CD; CD means publishing

Status: accepted (0.2.0)

## Decision
The pipeline has five tiers: pre-commit, CI (blocks merge), nightly (advisory, opens an issue), milestone gate
(release candidates) and release (human approval, then publish).

Insight is published (signed image and GitHub Release), not deployed. Every gate is a tested script in
`scripts/`. Gates must fail loudly rather than pass vacuously: `pip-audit --strict`, a non-empty SBOM check,
and a corpus fingerprint for the extraction baseline. These came from dry runs that found vacuous passes.

## Consequences
A release requires a passing release candidate of the same commit. Tiers are documented in docs/CI_CD.md.
