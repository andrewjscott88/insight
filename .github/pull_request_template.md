## What and why

<!-- One topic per pull request. Link the issue or decision record (docs/adr/) if there is one. -->

## Checklist

- [ ] Tests added or updated. Bug fixes include a `Regression:` test that failed before the fix.
- [ ] `pre-commit run --all-files` passes (ruff, format, mypy --strict, forbidden files, workflow lint).
- [ ] Schema changes: migration added (`--rev-id` next number), reversible, tested on SQLite **and** PostgreSQL.
- [ ] Dependency changes: `python scripts/lock.py` run and all lock files committed.
- [ ] Extraction changes: `python scripts/benchmark_extraction.py` reviewed; baseline updated only for
      intentional improvements.
- [ ] User-visible change recorded in `CHANGELOG.md` (`## Unreleased`), with upgrade notes if behaviour or data
      changes.
- [ ] Documentation updated (README, docs/RUNBOOK.md, docs/API.md, docs/EXTRACTION.md as relevant).
- [ ] Security-sensitive area (auth, middleware, connectors, TLP)? A second reviewer is requested.
