# Validation report · 0.2.0

What was verified for release 0.2.0, what was not, and how. Update this file for every release (see
[RELEASING.md](RELEASING.md)).

## Unreleased: API platform, deployment settings, MFA, Makefile (verified so far)

Recorded while the work was done, for whoever prepares the next release to confirm in the release gates.

- **Tests:** 1,143 pass on each of CPython 3.11, 3.12, 3.13 and 3.14 (2 skipped: browser and live suites);
  1,073 pass against PostgreSQL 16 (`-m "not slow"`). Branch coverage 97.1% (gate 90%). `ruff`, `ruff format`,
  `mypy --strict`, lock check, forbidden-files scan, workflow schema and zizmor clean (`make ci` end to end).
- **Schema:** migrations `0004` and `0005` reversible, models equal migrations, and the 0.1.0 and 0.2.0 release
  databases upgrade to `0005` from the installed wheel.
- **Security properties, each with a test that was checked by breaking the code:** no report above a key's TLP
  limit leaks through any API route (removing the limit from one route fails the sweep and the architecture
  test); invalid-key floods never lock out the valid key; a clock stepping backwards cannot drain a rate-limit
  bucket; non-ASCII digits in an MFA code are refused instead of causing a server error; a limit of RED lifts a
  key's TLP limit.
- **Live server walkthroughs** (`insight serve`, curl): API key create/use/rotate/revoke without restart; bad
  keys `401` then `429`; TLP:RED refused; GREEN-limited key sees only GREEN; the 31st IOC export in an hour
  `429` with `Retry-After: 120`; audit actors; MFA off by default, then on with code, replay refused; sign-in
  through a simulated HTTPS reverse proxy (`403` before `INSIGHT_TRUSTED_PROXIES`, `303` after; `Secure`
  cookie; untrusted peers cannot forge headers); HSTS.
- **[API guide](API_GUIDE.md):** every `sh` block executed in order against a live server (exit 0, no errors);
  the SIEM script and the Python example run, including the failure path with a revoked key.
- **Makefile:** every non-Docker target run for real (`env`, `serve`, `health`, `smoke`, `check`, `ci`,
  `package`, `benchmark`, `drill`, `test-postgres`, `clean`); Docker targets verified against a recording
  stand-in for `docker compose`.

**Not yet verified** (no Docker or internet in the build environment): `docker build` and the image with the new
`LICENSE`/`NOTICE` copy step, the Makefile's Docker targets against real containers (including the interactive
`make mfa-enable` prompt through `docker compose run`), Trivy, gitleaks, `pip-audit`, the Playwright browser
suite, the ZAP scan and mutation testing. `make release-check` currently fails on unpinned GitHub Actions, as
the release gate intends, until the workflows are pinned by commit SHA.

## Verified in the build environment

**Test suite**
- Clean `--require-hashes` installs of `requirements-dev.lock` on CPython 3.11, 3.12, 3.13 and 3.14;
  `pip check` clean.
- **675 tests pass on each of the four Python versions** (2 skipped: the browser and live suites, which run in
  their own gates). **671 pass against PostgreSQL 16.** Warnings are errors. **No expected failures:** the
  known-defects register is empty.
- Coverage: 95.9% branch overall; 98–100% for backend modules.
- Mutation testing (mutmut 3.8 on extraction, connectors and services, against the unit and API tests):
  1,910 mutants, **86.5% killed**. The run found real test gaps (wrapped-hash join, URL-host boundaries,
  fragment checks), all now tested. The nightly ratchet is 86%.
- Repository hygiene: no package file is gitignored. A `data/` rule had been excluding the TLD list; this is
  now fixed and tested.
- Static checks, clean:
  - `ruff` (expanded ruleset incl. bandit), `ruff format`;
  - `mypy --strict` over `src/`, `tests/` and `scripts/`;
  - lock files match `pyproject.toml`;
  - the forbidden-files scan;
  - GitHub workflow schema and zizmor.
- Documentation gate: every relative link in every Markdown file resolves, every API route is documented, and
  every ADR is indexed.

**Migrations and data**
- Fresh install, full downgrade and upgrade, and models equal migrations, on SQLite and PostgreSQL.
- Databases written by **0.1.0** and by **0.2.0** (`tests/fixtures/releases/`) upgrade with data preserved,
  clean foreign keys, and fingerprints that still de-duplicate.
- Migration `0003` backfills searchable text.
- The installed wheel migrates both fixtures (`insight migrate`), and schema changes are logged.

**Extraction**
- Labelled corpus including two full synthetic intrusion reports: **precision 97.9%, recall 98.9%** (0.1.x:
  67.8% / 78.4%).
- GLASS HARBOR report: exact match with ground truth.
- SALT MERIDIAN report: exact match except the documented even-split hash limitation.
- No fabricated or truncated indicators in either report (tested).

**Application**
- Real-browser E2E (Playwright 1.58, Chromium 141): 8 tests, 3 of 3 consecutive green runs, against the
  emulated container **started on a copy of a 0.1.0 database** (the upgrade path). The tests cover:
  - sign-in, security headers and cookie flags;
  - demo, ingest → review → note, search, and sign-out revoking other tabs;
  - both synthetic reports pasted through the real dialog (inert HTML, TLP:RED enforcement, JavaScript-exact
    UTF-16 offsets).
- Container emulation (Docker unavailable here):
  - the wheel was built exactly as the Dockerfile's build stage does (hash-pinned setuptools, no build
    isolation, includes `data/tlds.txt` and all migrations);
  - it was installed from the runtime lock into a fresh Python 3.13 environment, with the install tree and
    working directory made read-only (non-root, enforced);
  - the smoke test and all browser tests passed with zero server errors.
- Scale: 300 reports sharing indicators render the workspace in 0.76 s (1,633 UI elements, 292 KB). In 0.1.x,
  100 such reports took 3.7 s (5,196 elements, 1.7 MB).
- Performance budget (1,000 documents):
  - SQLite: 238 docs/s ingest, search p95 12.9 ms, detail p95 1.8 ms, 2 queries per list page;
  - PostgreSQL: 112 docs/s ingest. Timings on this sandbox's PostgreSQL varied between runs, so treat the
    CI service-container run as authoritative.
- Backup/restore drill: an online `insight backup` from a running server, restored into a second server,
  returned identical data. The manual deletion procedure in RUNBOOK §9 was executed against a database with a
  revision chain. The first draft failed the partial unique index, which testing caught; the published version
  passes the foreign-key and integrity checks.
- Release gates: `check_release.py` passes for `v0.2.0-rc.1` and `v0.2.0`; `check_pins.py --strict` fails as
  designed until actions and base images are pinned (see below).

## Not verified here (needs your environment)

- `docker build` / `docker compose up`, Trivy, gitleaks and OWASP ZAP: there is no Docker in this sandbox.
  The Dockerfile's exact commands were executed outside Docker.
- GitHub Actions runs, and whether the referenced action versions exist. GitHub is unreachable from here.
  Actions and the base image are **not yet pinned** (docs/CI_CD.md "Inputs needed").
- `pip-audit` and SBOM generation: the vulnerability databases were unreachable. Both steps are `--strict`, so
  they fail rather than pass vacuously.
- Live publisher contract tests (no internet beyond PyPI); Firefox/WebKit; Windows/macOS; penetration testing.

Do not treat this as production certification. The first-run checklist below is the acceptance test for a new
installation.

## First-run checklist

1. Generate private credentials; build/start Docker Compose; `docker compose ps` shows `healthy`.
2. `curl http://localhost:8080/health` reports `"version":"0.2.0"`; the workspace requires sign-in.
3. Load demo twice: second load adds zero new documents.
4. Open a demo report; accept/reject/reset an observation; add a note.
5. Search a CVE/IP (try an accented word too) and pivot to its related documents via the entity explorer.
6. Add a watch term and check its inbox match badge.
7. Ingest a report containing `TLP:RED` with the default AMBER label: it is stored as RED and you are warned.
8. Run one source; inspect success/error history. Sync again later: edited items appear as revisions.
9. Explicitly approve one optional CVE lookup and inspect the provider timestamp.
10. Sign out and check that another open tab cannot make further changes.
11. `docker compose exec insight insight backup /data/test-backup.db`; restore it into a separate instance
    (RUNBOOK §5).
