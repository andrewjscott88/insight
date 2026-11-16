# Contributing to Insight

## Set up

```sh
python -m venv .venv && source .venv/bin/activate      # Python 3.11-3.14
pip install --require-hashes -r requirements-dev.lock
pip install --no-deps -e .
pre-commit install --hook-type pre-commit --hook-type pre-push
```

Optional:
- PostgreSQL for database tests: `INSIGHT_TEST_DATABASE_URL=postgresql+psycopg://postgres@localhost/postgres`.
- Browser tests: `pip install --require-hashes -r requirements-e2e.lock && python -m playwright install chromium`.

## Everyday commands

```sh
pytest tests/unit -q                 # fast loop (~20 s)
pytest                               # everything offline (~2 min)
ruff check --fix src tests scripts && ruff format src tests scripts
mypy                                 # strict, over src/, tests/ and scripts/
pre-commit run --all-files           # what CI's quality job runs
python scripts/benchmark_extraction.py
```

## Rules the tooling enforces

| Rule | Enforced by |
| --- | --- |
| Front ends (`main.py`, `ui/`) never build SQL; the UI never imports ORM classes | `tests/unit/test_architecture.py` |
| Models and migrations agree; every migration is reversible; every released database upgrades | `tests/unit/test_migrations.py` |
| Lock files match `pyproject.toml` | `scripts/lock.py --check` (pre-push and CI) |
| No `.env`, databases, keys or credentials in git | `scripts/check_forbidden_files.py`, gitleaks |
| Warnings are errors | `filterwarnings = error` in `pyproject.toml` |
| Coverage ≥ 90% (backend modules are at 98–100%; keep them there) | CI |
| Extraction precision/recall never drops > 1 point | `scripts/benchmark_extraction.py` |
| Hypothesis example counts come from profiles, never `@settings(max_examples=…)` | `tests/unit/test_scripts.py` |

## Common changes

**Schema change.** Edit `models.py`, then generate a migration with the next number:
```sh
INSIGHT_DATABASE_URL=sqlite:///data/dev.db alembic revision --autogenerate --rev-id 0004 -m "describe it"
```
Review the generated file:
- keep it free of application imports;
- snapshot any logic it needs (see `0003`);
- make `downgrade()` work.

Run `pytest tests/unit/test_migrations.py`, on PostgreSQL as well.

**New dependency.** Add it to `pyproject.toml`, then run `python scripts/lock.py` (needs `uv`) and commit both.
Runtime dependencies must pass `scripts/check_licenses.py`.

**Extraction rule.** Follow "Adding or changing a rule" in [docs/EXTRACTION.md](docs/EXTRACTION.md). Start
with a failing test; a wrong indicator is worse than a missed one.

**New source connector.** Add it to `SOURCES` in `connectors.py`, after reviewing:
- the publisher's terms, redirects and payload size;
- whether items carry a stable identity (link or GUID) for revisions.

Public data is `tlp='CLEAR'` explicitly. Add offline fixture tests and a case in `tests/live/`.

**IOC export format.** Fields may be added to `insight-ioc-v1`; renaming or removing one needs `insight-ioc-v2` and
an upgrade note. With any format change:
- update `docs/schemas/insight-ioc-v1.schema.json` (the tests validate real exports against it, and fail on
  undocumented fields);
- regenerate the example with `python scripts/make_ioc_example.py` (a test fails while it is stale);
- update [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md) and [docs/API.md](docs/API.md).

**UI change.** Put data access in `services.py`, and put new UI in the relevant `ui/` panel module (keep
modules under 300 lines). Test with the NiceGUI user simulation (`tests/ui/`). Use `should_see()` before
`find()`: refreshes run asynchronously.

**Bug fix.** Add a test whose docstring starts with `Regression:` and describes the old behaviour.

## Pull requests

- One topic per pull request, a clear description, and the checklist from the template.
- User-visible changes go into `CHANGELOG.md` under `## Unreleased`, with upgrade notes for anything that
  changes behaviour or data.
- Security-sensitive changes (authentication, middleware, connectors, TLP handling) need a second reviewer.

See also [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/TESTING.md](docs/TESTING.md) and
[docs/CI_CD.md](docs/CI_CD.md).
