# Instructions for coding agents

Read this before changing anything. It adds to [CONTRIBUTING.md](CONTRIBUTING.md) (setup, commands, the rules the
tooling enforces) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); read both too. Task briefs for coding agents
are in [docs/briefs/](docs/briefs/).

## What Insight is

A self-hosted threat-intelligence platform for analysts: reports in, indicators reviewed, intelligence out over
TAXII 2.1, STIX 2.1, MISP and an API. It owns the intelligence cycle (requirements, collection, analysis,
products, dissemination). Hunting in an organisation's own telemetry, detections and incident response belong
to separate tools, which Insight feeds and which send back only **sightings** and **requests for information**.
Insight never records what was done about an indicator, and never writes anything with a language model.

Stack: Python 3.11-3.15, FastAPI, NiceGUI 3, SQLAlchemy 2, Alembic, SQLite or PostgreSQL 16.

## Ground rules

- **Never weaken an existing security control to make a change easier.** If a change needs a design decision
  this file does not settle, choose the more conservative option and say so in the commit message.
- **TLP everywhere.** Every read takes the caller's limit (`max_tlp`) and every service that returns stored
  intelligence filters by it. Something above a caller's limit must look exactly like something missing
  (`404`, never `403`). A container (case, requirement, hunt package) takes the strictest label of what it
  holds and keeps it when items are removed. Labelled writes above the caller's or the instance limit are
  refused (`403`). Routes use `write_limit(app, request)` or `reader_limit(request)`.
- **Outbound connections** go only to HTTPS hosts on an allowlist, through `connectors.download` and the
  checks in `egress.py`, with timeouts and size caps. Anything sent to a third party about an indicator
  follows the existing rule: a reviewed indicator in a current TLP:CLEAR report, approved by the operator for
  each uncached lookup, cached, audited, throttled ([ADR 0031](docs/adr/0031-shodan.md)). Nothing runs on a
  schedule unless the operator turns it on.
- **Every write is audited** (`services.audit`), with the actor from the session or API key.
- **Never run detection rules** (YARA, Sigma, Suricata, Snort): store and show them as text.
- **Dependencies:** prefer none. A new one needs `pyproject.toml`, `python scripts/lock.py` (hash-locked
  files), a passing `scripts/check_licenses.py`, and a reason in the ADR.
- **No secrets, `.env` files, databases or keys in git.** Use only the local test instance and test values;
  never enter real credentials anywhere.
- **Nothing about any real deployment** (host names, findings, configuration) goes into this public
  repository.
- If a network request is refused by a proxy or policy, stop and report it; never route around it.
- Mutation testing runs on its weekly schedule only; do not start it by hand.

## Where things go

| Change | Where |
| --- | --- |
| Data access and logic | `src/insight/services/<domain>.py`, under 400 lines a module; every public name re-exported in `services/__init__.py` (helpers start with `_`) |
| HTTP routes | `src/insight/web/routes/<domain>.py`, registered in `web/app.py`; no SQL in `web/` |
| Workspace UI | `src/insight/ui/<panel>.py`, under 300 lines a module; no ORM imports, no SQL |
| Request bodies | `src/insight/schemas.py` (Pydantic, `extra='forbid'`) |
| Tables | `src/insight/models.py` plus the next numbered migration in `src/insight/migrations/versions/` |
| Design decisions | A new ADR in `docs/adr/` with a row in `docs/adr/README.md` |

Migrations form one chain. If `main` gained a migration while you worked, rebase, renumber yours to follow it
and fix `down_revision`. ADR numbers are reserved in each brief.

## Checklist for every feature

The test suite enforces most of these; skipping one fails CI.

1. Services take `max_tlp`; add each new TLP-aware service name to `TLP_AWARE_SERVICES` and each new model to
   `ORM_CLASSES` in `tests/unit/test_architecture.py`.
2. Add every new route to `PROTECTED` in `tests/api/test_auth.py`, and every new `GET` route to the
   GREEN-key sweep in `tests/api/test_key_tlp_limit.py`, with AMBER data planted in its `world` fixture so a
   leak would fail.
3. Give every new route a permission in `src/insight/web/route_permissions.py`; a route without one is
   refused to everyone. In the workspace, check and write with the permission the action needs:
   `ws.allowed(Permission.X)`, then `ws.write(Permission.X)`, and `actor=ws.actor(Permission.X)` for lookups
   and syncs. Choose the lowest role the matrix in [ADR 0046](docs/adr/0046-sso-sign-in-and-roles.md) allows,
   and the more conservative one when it is unclear. A new kind of action may need a new `Permission`.
4. Give every new table rows in `scripts/make_release_fixture.py` (a test checks that every table has data).
5. Document every route in `docs/API.md` and give it a `curl` example in `docs/API_GUIDE.md`.
6. Interface text: grade 9 or below, sentence case, every abbreviation in the glossary
   (`ui/glossary_terms.py` is near its 300-line limit: split it if you add terms), headings through
   `typography.heading()`, messages through `messages.tell()`.
7. User-visible changes go in `CHANGELOG.md` under `## Unreleased`, with an upgrade note for any migration;
   update `README.md`, `ROADMAP.md` and `docs/ROADMAP-TIP.md` when a roadmap item is done.
8. Tests: unit tests for the service, API tests through the real middleware, UI tests with the NiceGUI user
   simulation (`await user.should_see(...)` before `user.find(...)`), and a `Regression:` test for each bug.

## Before you open a pull request

```sh
ruff check src tests scripts && ruff format --check src tests scripts
mypy                                  # strict, over src, tests and scripts
pytest                                # also with INSIGHT_TEST_DATABASE_URL set to a PostgreSQL 16 database
```

Lines are at most 110 characters; strings use single quotes.

## Git and pull requests

- Branch from `main`; one roadmap item (or one part of it) per pull request.
- Commits are authored as `andrewjscott88 <andrewjscott88@users.noreply.github.com>`.
- Open the pull request against `main` and run the milestone gate on your branch
  (`gh workflow run "Milestone gate" --ref <branch>`).
- Merge only when CI, the milestone gate and CodeQL ("No new alerts in code changed by this pull request")
  have passed, and only if the maintainer asked you to merge.
- Never create, move or push tags, and never start a release: the maintainer cuts releases.
