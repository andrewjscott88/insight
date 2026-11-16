# ADR 0005: Hardened container and hash-pinned supply chain

Status: accepted (0.2.0)

## Decision
- Multi-stage build; the build backend is hash-pinned and used without build isolation.
- The runtime image holds only runtime dependencies (`--require-hashes`), runs as UID 10001 with a read-only
  root filesystem and no capabilities, and keeps NiceGUI storage on `/data`.
- Four lock files are generated from `pyproject.toml` by `uv`, and CI fails on drift.
- Releases are cosign-signed (keyless) with SBOM and provenance attestations.
- Base images and actions must be pinned by digest and SHA before a release can publish.

## Consequences
Rebuilds are reproducible and a tampered dependency fails installation. Pinning needs network access the
build sandbox did not have, so it is an operator task (docs/CI_CD.md "Inputs needed").
