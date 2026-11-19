# CI/CD pipeline

Insight is a local, single-operator tool, so **"CD" here means publishing, not deploying**. A release produces a
signed, scanned, attested container image (GHCR) and wheel that operators pull. Nothing is pushed to a server.
A staging deployment stage only becomes relevant at Milestone 3 (multi-user accounts).

```
 Tier 0  pre-commit (local)   .pre-commit-config.yaml           every commit / push
 Tier 1  CI                   .github/workflows/ci.yml          every push & PR - blocks merge
 Tier 2  Nightly              .github/workflows/nightly.yml     03:17 UTC - advisory, opens an issue
 Tier 3  Milestone gate       .github/workflows/milestone-gate.yml   tag vX.Y.Z-rc.N - blocks the release
 Tier 4  Release              .github/workflows/release.yml     tag vX.Y.Z - human approval, publishes
         + codeql.yml (SAST), lock-refresh.yml (weekly dependency PR), dependabot.yml (actions, base image)
```

Every gate is a script in `scripts/` with unit tests in `tests/unit/test_scripts.py`. A gate that silently
passes is worse than no gate, so the pipeline's own logic is tested like the product.

## Tier 0 - pre-commit

```sh
pre-commit install --hook-type pre-commit --hook-type pre-push
```

| Stage | Hooks |
| --- | --- |
| commit | forbidden files/secrets (`.env`, databases, keys, credentials, `backups/` and `exports/`, Insight API keys `insk_…`), ruff check + format, mypy --strict, workflow schema + zizmor (when workflows change) |
| push | lock files match `pyproject.toml`, unit tests |

All hooks call the tools pinned in `requirements-dev.lock`, so local results match CI.

Local equivalents from the Makefile: `make check` (Tier 1's quality job; a test keeps its commands identical to
`ci.yml`), `make test-cov`, `make test-postgres`, `make package`, and `make ci` for all Tier 1 jobs that need no
Docker. Milestone-gate pieces: `make benchmark`, `make drill`, `make test-e2e`; release checks:
`make release-check TAG=vX.Y.Z`.

## Tier 1 - CI (blocks merge)

| Job | What it proves |
| --- | --- |
| `quality` | ruff, format, mypy --strict over `src`, `tests`, `scripts`; `pip check`; **lock files match pyproject** (the 0.1.0 root cause); forbidden files; workflow schema; **zizmor** workflow security audit; pinning report |
| `test` (3.11-3.14) | Full suite on SQLite: unit, API, NiceGUI simulation, migrations, architecture rules, extraction-quality and query-count regressions; **coverage ≥ 90%** |
| `test-postgres` | The same suite against PostgreSQL 16 (throwaway database per test) |
| `security` | `pip-audit` on the runtime lock (OSV); gitleaks over the full git history |
| `package` | Wheel built exactly like the image; clean install from the runtime lock; `insight migrate` upgrades the oldest release fixture; runtime **licence policy** |
| `container` | `docker build`; **Trivy** (CRITICAL/HIGH, fixed only); run with `--read-only --cap-drop ALL`; `scripts/smoke.py` (health, headers, auth, forged CSRF, demo, render) |

Make these **required status checks** on `main`: `Lint, types, locks, workflow security`, all four
`Tests (Python …, SQLite)`, `Tests (Python 3.13, PostgreSQL 16)`, `Dependency audit and secret scan`,
`Wheel build, clean install, licences` and `Container build, scan, read-only smoke test`.

## Tier 2 - nightly (advisory)

| Job | Why |
| --- | --- |
| Live contract tests (`tests/live`, `INSIGHT_LIVE_TESTS=1`) | The only network-enabled tests. Real CISA/SANS/NCSC feeds and EPSS/NVD must still download, parse and validate. Catches moved URLs and format changes early. |
| Property tests, 5,000 examples (`HYPOTHESIS_PROFILE=nightly`) | Deeper search for extraction edge cases |
| Mutation testing (mutmut on extraction, connectors, services) | Finds assertions that are missing. Every run so far has found real gaps (0.2.0: the wrapped-hash join, URL-host boundaries, fragment checks), which are now tested. Fails below the ratchet in `nightly.yml` (`MUTATION_SCORE_MIN`). Raise it as the score improves; never lower it. |
| Newest allowed dependencies | Early warning of breaking upgrades within the declared ranges |
| Trivy re-scan of the latest released image | New CVEs in already shipped images |

Any failure opens (or comments on) a "Nightly pipeline failure" issue.

> mutmut 3.8 is not yet compatible with pytest 9, so the mutation job installs `pytest<9` in its own
> environment without installing the project (see `[tool.mutmut]` in `pyproject.toml`).

## Tier 3 - milestone gate (blocks the release candidate)

Triggered by `vX.Y.Z-rc.N` tags (or manually). Re-runs **all of Tier 1** (`workflow_call`), then:

| Job | Gate |
| --- | --- |
| Release metadata | Tag = `__version__`, `CHANGELOG.md` section, `VALIDATION.md` updated |
| Extraction quality | Labelled corpus (`tests/corpus/extraction.json`): no kind may lose > 1 point of precision or recall vs `benchmarks/extraction-baseline.json` |
| Performance budget | 1,000-document ingest, search p95, detail p95, list query count, on SQLite **and** PostgreSQL (`benchmarks/performance-budget.json`) |
| Backup/restore drill | Online `insight backup` from a running server, restore into a second server, verify data |
| Browser E2E (Playwright) | Real Chromium against the read-only container: sign-in, security headers, demo, ingest → review → note, search, sign-out revokes other tabs |
| OWASP ZAP baseline | Signed-in passive scan of the container; fails on FAIL-level alerts |
| Licences + SBOM | Runtime licence policy; CycloneDX SBOM artifact |

Reports are attached to the run summary and as artifacts (90 days).

### Milestone-specific gates to add when each milestone starts

| Milestone | Gate to add |
| --- | --- |
| M1 Pilot & extraction quality | Grow `tests/corpus/extraction.json` with real, permitted reports; ratchet the baseline up as the extractor improves (defanged indicators are the known gap) |
| M2 PostgreSQL, cursors | Datetime-column migration (see ARCHITECTURE.md); cursor-resume tests with fake feeds; tighten the PostgreSQL performance budget |
| M3 Identity provider & groups | OIDC tests against a containerised IdP; role × endpoint authorisation matrix; authenticated ZAP active scan; staging deployment environment |
| M4 Notifications | Delivery tests against a fake SMTP/webhook sink |
| M5 Structured export | `stix2-validator` on every export; import/export round-trip; retention/licence rule tests |
| M6 LLM enrichment | The `docs/LLM_EXTENSION.md` evaluation set (span correctness, unsupported claims, prompt-injection corpus) with thresholds; a test that no RED/AMBER+STRICT text reaches an external provider |

## Tier 4 - release (publishes)

Final tags `vX.Y.Z` only. See `docs/RELEASING.md` for the step-by-step procedure.

1. **verify**: release metadata and upgrade fixture; `check_pins.py --strict` (every base image by digest,
   every action by commit SHA); the **same commit** has a successful milestone-gate run.
2. **publish**: runs in the protected `release` environment, which **requires a human approval**. Builds
   wheel and image; pushes to GHCR with BuildKit SBOM and `provenance: mode=max`; **cosign keyless
   signature**; GitHub build-provenance attestations for image and wheel; GitHub Release with the changelog
   section, wheel, runtime lock and validation report.
3. **post-release**: `cosign verify` against this repository's workflow identity; pull **by digest**,
   run read-only, smoke test.

Operators verify an image with:

```sh
cosign verify ghcr.io/<org>/insight@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/<org>/insight/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Dependency updates

- **Python**: `lock-refresh.yml` runs `python scripts/lock.py --upgrade` weekly and opens a PR. It keeps all
  four hash-pinned locks consistent (`requirements.lock` runtime, `-dev`, `-e2e`, `-build`).
- **Actions and base image**: Dependabot, weekly.
- By hand: edit `pyproject.toml`, run `python scripts/lock.py`, commit both. CI fails if you forget.

## Permissions and secrets

- Every workflow defaults to `contents: read`; jobs add only what they need (`packages: write`,
  `id-token: write`, `attestations: write`, `issues: write`, `security-events: write`).
- `actions/checkout` never persists credentials.
- No long-lived signing keys: cosign and attestations use GitHub OIDC.
- Untrusted values (tag names, run URLs) reach shell scripts only through `env:`, never inline `${{ }}`
  (zizmor enforces this).
- Only the nightly live job and the E2E/DAST job use the network during tests.

## Inputs needed before the first release

| # | Input | Why / how |
| --- | --- | --- |
| 1 | **Repository layout**: `insight/` must be the git repository root | GitHub only reads `.github/` at the root. |
| 2 | **Pin actions to commit SHAs and the base image to a digest** | Not possible offline. Run `pinact run` (or `ratchet pin`) and `docker buildx imagetools inspect python:3.13-slim`, update both `FROM` lines, then switch `.github/zizmor.yml` to `hash-pin`. The release gate enforces this. |
| 3 | **Confirm action and tool versions** | Written against `checkout@v5`, `setup-python@v6`, `upload-artifact@v4`, `docker/*@v3/v5/v6`, `cosign-installer@v3`, `attest-build-provenance@v2`, `codeql-action@v3`, `trivy-action@0.28.0`, `gitleaks v8.18.4`, `uv 0.13.7`. Pinning (2) also confirms these exist. |
| 4 | **Branch protection** on `main` | Required checks listed under Tier 1; require PR review; block force-push. |
| 5 | **`release` environment** with required reviewers | Settings → Environments. Publishing waits for a named approver. |
| 6 | **GHCR visibility** | Private by default; decide who may pull. |
| 7 | **`LOCK_REFRESH_TOKEN`** (optional) | PRs opened with `GITHUB_TOKEN` do not trigger CI. A fine-grained PAT or GitHub App token fixes that. Also enable "Allow GitHub Actions to create pull requests". |
| 8 | **CodeQL availability** | Free on public repositories; private ones need GitHub Advanced Security. Otherwise delete `codeql.yml` (ruff's bandit rules and zizmor still run). |
| 9 | ~~Next version number~~ | Done: **0.2.0** is prepared (version, changelog, validation report, upgrade fixture). Next step: tag `v0.2.0-rc.1` once 1-6 are in place. |
