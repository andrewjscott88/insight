# Architecture and design decisions

## Local modular monolith

Browser → NiceGUI Python page callbacks / FastAPI API → **services** → SQLAlchemy → SQLite or PostgreSQL.

`services.py` is the only query and command layer. Neither front end (`main.py` for the JSON API, `ui/` for the workspace) builds SQL or, in the UI's case, imports ORM classes. `tests/unit/test_architecture.py` enforces this, so search semantics, revision handling and auditing cannot drift apart between the API and the UI again.

Explicit source sync → fixed HTTPS connector → bounded parse → document/entity/observation transaction.

The narrower first release trades the research report's React, RabbitMQ/Celery, PostgreSQL and object-storage fleet for a directly runnable local container. Python owns both backend and GUI. Business/data modules are separate so a job queue, PostgreSQL and stronger authentication can be introduced later.

## Repository

- `config.py`: validated environment configuration.
- `models.py`: relational schema (kept in sync with the migrations by a test).
- `migrations/`: Alembic revisions, shipped inside the package and applied automatically at start-up.
- `schemas.py`: bounded validated inputs.
- `extraction.py`: deterministic mention extraction (`regex-v2`: refanging, TLD validation, context rules). See [EXTRACTION.md](EXTRACTION.md).
- `data/tlds.txt`: bundled ICANN TLD list (from the Public Suffix List; see `NOTICE`).
- `services.py`: ingestion, revisions, search, read models, IOC export queries and analyst actions (the only SQL layer).
- `ioc_export.py`: the cross-report IOC export format (`insight-ioc-v1`): grouping, TLP labelling and defanging. Pure functions, no SQL.
- `connectors.py`: curated feed/KEV/NVD/EPSS integration.
- `main.py`: authentication, sessions, CSRF, API and security boundary. `create_app` only composes: state, middleware, then one `_register_*` function per route group (pages, login, workspace, documents, triage, exports, entities, sources, enrichment). Shared pieces (`session_checker`, `auth_dependency`, `start_session`, `get_document_or_404`, `ioc_export_query`) are module-level so they can be tested alone (`tests/api/test_app_factory.py`).
- `ui/`: NiceGUI workspace, one module per panel (`inbox`, `entities`, `watch_terms`, `sources`, `enrichment`, `ingest`, `ioc_export`, `stats`), plus `workspace.py` (typed per-tab state and cross-panel hooks) and `page.py` (layout).
- `demo.py`: synthetic reserved-namespace examples.
- `cli.py`: `init`, `serve`, `migrate`, `backup`, `export-iocs`.
- `scripts/` (repository only): CI/CD gates, benchmarks and release tooling. See `docs/CI_CD.md`.

## Evidence and deduplication

Bodies remain exact text. Observations keep start/end character offsets and evidence excerpts. Canonical entities allow cross-document lookup; accepting an observation is not a maliciousness verdict. SHA-256 is a content integrity reference, not a signature.

Exact reimports with identical title, body, source, URL and TLP return the existing document. Different sources or handling labels remain separate documents even when their content hashes match. This preserves source histories rather than merging them. Repeated mentions within a document remain distinct evidence spans.

### Source items and revisions

Documents synced from a curated source carry a stable identity, `(source_key, external_id)`: the CVE for KEV, and the link (or `<guid>`/Atom `<id>`) for RSS/Atom. When a publisher changes an item, Insight creates a **new revision**. `supersedes_id` points at the previous one, and a partial unique index allows exactly one `is_current` revision per item. Stored bodies are never edited, because observations store exact character offsets into them. The inbox, search and stats show current revisions by default (`include_superseded=true` shows all). Entity pivots show every revision, marked. If a publisher reverts to an earlier text, that exact revision becomes current again. Manual submissions have no source identity and keep the original exact-duplicate semantics.

NVD/EPSS enrichments are separate provider-labeled JSON payloads with fetch timestamps. KEV context is stored separately from extraction. Analyst notes never overwrite source text.

### Search, TLP policy and large pivots

- **Search** matches a folded copy of each document (`documents.search_text`: NFKD, strip marks and zero-width
  characters, casefold, NFC). Queries are folded the same way, so results are identical on SQLite and
  PostgreSQL and independent of case, accents, width and Unicode normal form
  ([ADR 0008](adr/0008-folded-search-text.md)).
- **TLP**: default AMBER. `services.apply_tlp_policy` raises the label to the most restrictive `TLP:` marking
  in the text and never lowers it. It runs inside `ingest`, so UI, API and connectors behave the same
  ([ADR 0009](adr/0009-tlp-policy.md)).
- **IOC export** (`services.export_iocs` → `ioc_export.build_export`): one entry per canonical entity with its
  source reports. Reports are selected with the same conditions as the inbox search (`_document_conditions`).
  The file and every IOC carry the most restrictive TLP of their reports, so the export never appears less
  restricted than its sources; unknown labels count as more restrictive than RED. Rejected mentions are left out
  by default. `document_ids` limits an export to chosen reports (included even if superseded). The workspace
  previews counts with `services.ioc_export_counts` (one aggregate query, not audited) and refuses empty or
  over-limit downloads. Only the needed columns are queried (never report bodies), and an export is capped at 100,000
  mentions. The API, the workspace (which downloads through the API) and `insight export-iocs` share this code
  and the `ioc.export` audit event, whose object ID is the `export_id` written into the file. User guide:
  [IOC_EXPORT.md](IOC_EXPORT.md); format: [schemas/insight-ioc-v1.schema.json](schemas/insight-ioc-v1.schema.json).
- **Entity pivots** are paginated in the service layer and loaded lazily in the UI. Page size no longer grows
  with how often indicators recur.
- **Offsets** are code points; the API adds UTF-16 offsets for JavaScript
  ([ADR 0011](adr/0011-offsets-code-points-and-utf16.md)).
- **Logging**: `insight serve` configures the `insight.*` loggers (`insight.auth`, `insight.migrations`) on
  stderr.

## Schema migrations

Alembic owns the schema (revisions: `0001` baseline = 0.1.0, `0002` document revisions, `0003` folded search text and truncation flag). `database()` runs `insight.migrations.upgrade()` on every start. A 0.1.0 database (tables created by `create_all`, no `alembic_version`) is first stamped at the baseline revision `0001`, which reproduces the 0.1.0 schema exactly, then upgraded. `insight migrate` does the same explicitly. SQLite migrations run in batch mode with foreign keys temporarily disabled and a `foreign_key_check` before commit, which is SQLite's documented procedure.

To add a migration: change `models.py`, then run
`INSIGHT_DATABASE_URL=sqlite:///data/dev.db alembic revision --autogenerate --rev-id 0004 -m "..."` (using the repository's `alembic.ini`), review the file, and run the tests. `test_models_match_migrations` fails if the models and migrations disagree; `test_every_revision_is_reversible` checks `downgrade()`.

**Timestamps stay ISO-8601 UTC strings for now (deliberate).** They sort correctly because every writer uses `models.now()`. Switching to datetime columns only pays off with PostgreSQL's `timestamptz`. On SQLite, SQLAlchemy's `DateTime(timezone=True)` **silently drops the UTC offset**: we verified that `12:00+05:00` is read back as a naive `12:00`. When that conversion happens (PostgreSQL milestone), use a `TypeDecorator` that normalises to UTC on write and returns aware datetimes, plus a data migration.

## API

Session-authenticated JSON routes live under `/api`. `/api/session` exposes the CSRF token after authentication; writes require `X-CSRF-Token`. A valid browser session is required for JSON exports too. API contracts are initial and not yet versioned.

No live connection happens at startup. Sources must be run manually. Syncs share an in-process lock. Provider lookups are explicitly requested and globally throttled for the single operator. There is no durable queue/retry scheduler; failed jobs produce an error record and are manually retried.

## Next milestones

1. Validate pilot workflow and extraction quality with real permitted reports.
2. Add migration/versioning, search pagination and robust per-source incremental cursors.
3. Introduce identity-provider accounts and recipient/group handling before collaboration.
4. Add asset inventory relevance, investigations and watchlist notifications.
5. Add structured import/export and source-specific licensing/retention controls.
6. Add opt-in LLM enrichment behind the independent contract, only after evaluations and routing policies.
