# Roadmap

Planned work for Insight, in rough priority order. Each item links to its GitHub issue. The design
background lives in [docs/CI_CD.md](docs/CI_CD.md) (milestones), [docs/VALIDATION.md](docs/VALIDATION.md) (what is
not yet verified) and the README's "Scope and known limits".

## Now: finish the 0.5.0 release

- [ ] [#4](https://github.com/andrewjscott88/insight/issues/4) **Pin GitHub Actions to commit SHAs and the base image to a digest.** Run `pinact run` (or `ratchet pin`),
      update both `FROM` lines in the `Dockerfile`, and switch `.github/zizmor.yml` to `hash-pin`. The release gate
      fails until this is done.
- [ ] [#5](https://github.com/andrewjscott88/insight/issues/5) **Get the `v0.5.0-rc.1` milestone gate green.** Still unverified for 0.5.0: `docker build` and the image,
      the Makefile's Docker targets against real containers (including `make mfa-enable`), Trivy, gitleaks,
      `pip-audit`, the Playwright browser and accessibility suites, the ZAP scan and mutation testing.
- [ ] [#6](https://github.com/andrewjscott88/insight/issues/6) **Commit the 0.5.0 upgrade fixture** (`python scripts/make_release_fixture.py`), update `docs/VALIDATION.md`
      with what the gate verified, and tag the final `v0.5.0`.
- [ ] [#7](https://github.com/andrewjscott88/insight/issues/7) **Repository settings:** branch protection on `main`, a `release` environment with a required reviewer, and
      a decision on GHCR image visibility.
- [ ] [#8](https://github.com/andrewjscott88/insight/issues/8) **Fix:** a CVE-enrichment request for a well-formed CVE that no report mentions is refused (`422`) but still
      starts the 6.5 s enrichment window.
- [ ] Review and merge the open Dependabot updates (Python base image, GitHub Actions).

## Next

- [ ] [#9](https://github.com/andrewjscott88/insight/issues/9) **Extraction quality (M1).** Grow `tests/corpus/extraction.json` with real, permitted reports; close the
      defanged-indicator gaps listed in [docs/EXTRACTION.md](docs/EXTRACTION.md); ratchet the benchmark baseline.
- [ ] [#10](https://github.com/andrewjscott88/insight/issues/10) **Scheduled source syncs.** Run the CISA, SANS ISC and NCSC connectors on a schedule instead of only on demand,
      with visible failures and no duplicate reports.
- [ ] [#11](https://github.com/andrewjscott88/insight/issues/11) **PostgreSQL and feed cursors (M2).** Native datetime columns (migration), cursor-based resume for feeds,
      and a tighter PostgreSQL performance budget.
- [ ] [#12](https://github.com/andrewjscott88/insight/issues/12) **STIX 2.1 export (M5).** Export reports and indicators as STIX bundles, validated with `stix2-validator` on
      every export, with an import/export round-trip test and retention/licence rules.
- [ ] [#13](https://github.com/andrewjscott88/insight/issues/13) **PDF report ingestion.** Extract text from PDF advisories, keeping the original file hash as evidence.

## Later

- [ ] [#14](https://github.com/andrewjscott88/insight/issues/14) **Identity provider and groups (M3).** OIDC sign-in, roles and an authorisation matrix per endpoint, and an
      authenticated ZAP active scan against a staging deployment.
- [ ] [#15](https://github.com/andrewjscott88/insight/issues/15) **Notifications (M4).** E-mail or webhook alerts when a new report matches a watch term or a KEV entry.
- [ ] [#16](https://github.com/andrewjscott88/insight/issues/16) **Multi-worker deployments.** Move sessions and rate-limit state out of process memory.
- [ ] [#17](https://github.com/andrewjscott88/insight/issues/17) **Search and pivots.** Full-text relevance ranking and a graph view of reports, indicators and CVEs.
