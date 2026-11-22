# Validation report · 0.8.0

What was verified for each release, what was not, and how. Update this file for every release (see
[RELEASING.md](RELEASING.md)).

## 0.8.0: PDF import, actors and campaigns, YARA and Sigma rules, MFA encryption, hardened mode, TAXII 2.1

Recorded while the work was done (pull requests #67, #69–#71, #74–#77). As for earlier releases, the release
workflow runs the whole milestone gate on the tagged commit before publishing can be approved; its reports
(benchmark, performance, backup drill, browser E2E with axe, ZAP, licences, SBOM) are attached to that run, not
repeated here.

- **Tests:** every pull request merged since 0.7.0 passed Tier 1 on SQLite and PostgreSQL 16 before it merged,
  and CI and CodeQL are green on the `main` commit this release was prepared from. #67 (which carries #69, #70
  and #71) and #76 (TAXII) also passed the full milestone gate on their branches, including browser E2E and the
  signed-in ZAP scan.
- **Schema:** migrations `0015` to `0018` (manual threat links, PDF provenance, MFA seed encryption,
  `observations.reviewed_at`) are tested by CI against the 0.1.0, 0.2.0, 0.5.0, 0.6.0 and 0.7.0 release
  databases. `0017` encrypts an existing authenticator pairing with a key derived from `INSIGHT_SESSION_SECRET`
  and refuses, leaving the database unchanged, if the secret is missing. The 0.8.0 upgrade fixture was created
  with the Release fixture workflow on the release branch, so later versions must upgrade it too.
- **Security review:** every pull request merged on 2026-11-21 was reviewed for parsing of untrusted files
  (PDF sandbox, STIX and MISP import), outbound requests (MISP, GreyNoise, OTX, abuse.ch: pinned addresses, no
  redirects, no proxy from the environment), TLP and publisher reuse rules, and the MFA encryption. No security
  defect was found; two limitations are noted below.
- **Release metadata:** version, changelog section, this report and the upgrade fixture are checked by
  `scripts/check_release.py` in the release run.

**Not verified for 0.8.0 before tagging:** no benchmark, performance, ZAP or browser-E2E numbers are recorded
here; they come from the milestone gate in the release run. The TAXII server was tested with its own HTTP
tests, not with `taxii2-client` or a real SIEM. Live calls to optional external services were not exercised
against real accounts. Since 0.9.0 a PDF import parses before it opens a database session, and a MISP instance
on a private network can be reached once `INSIGHT_MISP_PRIVATE_NETWORK=on` (off by default).

## 0.7.0: STIX 2.1 and MISP exchange, ATT&CK techniques, alerts, threat guides, CVE enrichment, more feeds

Recorded while the work was done (pull requests #40–#72). As for 0.6.0, the release workflow runs the whole
milestone gate on the tagged commit before publishing can be approved; its reports (benchmark, performance, backup
drill, browser E2E with axe, ZAP, licences, SBOM) are attached to that run, not repeated here.

- **Tests:** every pull request merged since 0.6.0 passed Tier 1 on SQLite and PostgreSQL 16 before it merged,
  and CI and CodeQL are green on the `main` commit this release was prepared from.
- **Schema:** migrations `0009` to `0014` (ATT&CK technique tags, source switches, alerts, CVE lookup failures,
  KEV fields, threat guides) are tested by CI against the 0.1.0, 0.2.0, 0.5.0 and 0.6.0 release databases. The
  0.7.0 upgrade fixture was created with the Release fixture workflow on the release branch, so later versions
  must upgrade it too.
- **Release metadata:** version, changelog section, this report and the upgrade fixture are checked by
  `scripts/check_release.py` in the release run.

**Not verified for 0.7.0 before tagging:** no benchmark, performance, ZAP or browser-E2E numbers are recorded
here; they come from the milestone gate in the release run, which the approver reviews before publishing. Live
calls to the optional external services (GreyNoise, NVD, EPSS, abuse.ch, OTX, MISP, alert destinations) were
not exercised against real accounts. `make attack-backfill` on a real 0.6.0 database was not run here. One
CodeQL alert was open when this report was written. The Makefile's Docker targets were not run against real
containers.

## 0.6.0: verdicts and a blocklist, report deletion, scheduled syncs, stored sessions, lighter pipeline

Recorded while the work was done (pull requests #19–#34). Since 0.6.0 the release workflow runs the whole
milestone gate on the tagged commit before publishing can be approved; its reports are attached to that run.

- **Tests:** every pull request passed Tier 1 on SQLite and PostgreSQL 16 before it merged; `ruff`,
  `ruff format`, `mypy --strict`, lock check, workflow schema and zizmor clean on each.
- **Schema:** migrations `0006`, `0007` and `0008` reversible and equal to the models; the 0.1.0, 0.2.0 and
  0.5.0 release databases upgrade to `0008` in CI. The 0.6.0 fixture holds rows in every table except the MFA
  pairing (a test now requires that), so later migrations are tested against verdicts, schedules, jobs, feed
  downloads, sessions and API keys too.
- **TLP safety of the new outputs:** the key-limit sweep plants an AMBER verdict with a marker and checks that a
  GREEN-limited key never sees it, through entity detail, the IOC export and both blocklist formats; a limited
  key can neither set nor replace a verdict above its limit; first and last seen are computed from the reports
  the caller can see.
- **Blocklist rules,** each tested: only `malicious`, unexpired (own date, or 30 days for IP addresses and 90
  for domains and URLs), with an accepted mention, no warning flag, within the caller's TLP limit. Property
  tests cover every special-purpose address range.
- **Report deletion:** tested for manual reports, middle and current revisions, and a reactivated first revision
  (the old manual SQL left that item with no current revision); the audit event keeps the reason and hash,
  never the title; `make delete-report` passes a reason containing quotes, commas, `;` and `$HOME` as one word.
- **Stored sessions:** a restart keeps the operator signed in; a new password, or turning MFA on, ends every
  session; **Sign out everywhere** ends sessions in two browsers and is audited; the database holds neither a
  session ID nor its plain hash. Each has a test against the full app.
- **Workspace:** verdict dialog, warning badges and glossary entries covered by the NiceGUI simulation and the
  plain-language tests. A milestone-gate run on the workspace branch passed 45 browser tests with the verdict
  dialog in the axe walk, and ZAP reported 0 FAIL, 8 WARN (as in 0.5.0).
- **CodeQL:** all 13 open alerts reviewed and dismissed with reasons (false positives, intended one-time
  output of a new key, test code); none was a vulnerability.
- **Nightly pipeline:** mutation testing and the image re-scan had failed since 17 November for reasons in the
  pipeline, not the product (mutmut's copy lacked the Makefile, pytest's import mode and the logger reset; the
  re-scan used a `v`-prefixed image tag). Both are fixed (#33): the re-scan passes, and mutation testing runs
  its 4,245 mutants again. It runs weekly now, so its first full score since 0.5.0 comes with the next Sunday
  run, after this release.

**Not verified for 0.6.0:** the Makefile's Docker targets against real containers (including `make
delete-report`; verified only against a recording stand-in); a full mutation score (see above); the new
release flow end to end, which the 0.6.0 tag itself exercises before anything is published.

## 0.5.0: API platform, deployment settings, MFA, Makefile, themes, readability

Recorded while the work was done, then confirmed by the release gates below.

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

**Release gates on GitHub Actions** (Tier 1 CI and the milestone gate for `v0.5.0-rc.2`, commit `6b16d39`):
- **Tier 1:** 1,575 tests pass on each of CPython 3.11–3.14 (SQLite) and 1,493 on PostgreSQL 16; lint,
  types, lock files, workflow schema and zizmor (`hash-pin`) clean; `pip-audit` finds no known vulnerabilities in
  the runtime lock; gitleaks clean over the full history (one documented test-value false positive in
  `.gitleaksignore`).
- **Container:** `docker build` with the `LICENSE`/`NOTICE` copy step; Trivy finds no fixable CRITICAL or HIGH
  vulnerabilities (after applying Debian security updates and removing `pip` from the runtime image); the
  read-only, no-capabilities smoke test passes.
- **Browser end-to-end:** 45 Playwright (Chromium) tests pass against the container, including the axe-core
  readability checks.
- **OWASP ZAP baseline, signed in:** 0 FAIL, 8 WARN (missing Cross-Origin-Embedder-Policy, NiceGUI's bundled
  JavaScript patterns, "modern web application", a private-IP note on the loopback test address), 60 rules pass.
- **Extraction benchmark:** 97.9% precision and 98.9% recall overall on the labelled corpus, no regression
  against the baseline. **Performance budget:** no violations on SQLite or PostgreSQL.
- **Backup and restore drill** against a real `insight serve`: passed. **Licences:** every runtime dependency
  on the allowed list; CycloneDX SBOM of 53 components.
- **Upgrade fixture:** `tests/fixtures/releases/insight-0.5.0.sqlite3` committed; the 0.1.0, 0.2.0 and 0.5.0
  databases upgrade in CI. All actions and the base image are pinned (`check_pins.py --strict` passes).

**Not verified for 0.5.0:** the Makefile's Docker targets against real containers (including the interactive
`make mfa-enable` prompt through `docker compose run`; verified only against a recording stand-in), and
mutation testing, which runs nightly and had not completed a run on 0.5.0 when this was written.

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
