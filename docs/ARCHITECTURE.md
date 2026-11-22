# Architecture and design decisions

## Local modular monolith

Browser → NiceGUI Python page callbacks / FastAPI API → **services** → SQLAlchemy → SQLite or PostgreSQL.

The `insight.services` package is the only query and command layer. Neither front end (`web/` for the JSON API, `ui/` for the workspace) builds SQL or, in the UI's case, imports ORM classes. `tests/unit/test_architecture.py` enforces this, so search semantics, revision handling and auditing cannot drift apart between the API and the UI again.

Explicit source sync → fixed HTTPS connector → bounded parse → document/entity/observation transaction.

The narrower first release trades the research report's React, RabbitMQ/Celery, PostgreSQL and object-storage fleet for a directly runnable local container. Python owns both backend and GUI. Business/data modules are separate so a job queue, PostgreSQL and stronger authentication can be introduced later.

## Repository

- `config.py`: validated environment configuration.
- `models.py`: relational schema (kept in sync with the migrations by a test).
- `migrations/`: Alembic revisions, shipped inside the package and applied automatically at start-up.
- `schemas.py`: bounded validated inputs.
- `extraction.py`: deterministic mention extraction (`regex-v5`: refanging, TLD validation, context rules). See [EXTRACTION.md](EXTRACTION.md).
- `data/tlds.txt`: bundled ICANN TLD list (from the Public Suffix List; see `NOTICE`).
- `services/`: the only SQL layer, one module per domain. `__init__` re-exports every public name, so callers
  write `services.ingest(...)` without knowing the module. `tlp` (levels and visibility, the security core;
  imports nothing from its siblings), `audit`, `common` (text folding, LIKE patterns, timestamps),
  `documents` (ingest, fingerprints, revisions), `search` (search, summaries, the reader view, stats),
  `entities` (pivots), `triage` (review, notes, watch terms), `brief` (the intel brief's facts), `exports`
  (IOC export queries), `sources` (source runs, enrichment cache, fetch state), `jobs` (queue and schedules),
  `access` (API keys, MFA), and for threat guides ([ADR 0025](adr/0025-threat-guides.md)) `actors` (actors,
  report links, industry decisions), `threat_profiles` (an industry's top ten), `threat_guides` (a guide's
  facts and the sweep list), `rules` (YARA, Sigma, Suricata and Snort as text) and `hunts` (hunt records).
- `industries.py`: the fixed industry list and the reviewed words that map catalog labels and ATT&CK prose to it.
  `threat_library_build.py` builds the threat-group library from ATT&CK and the MISP galaxy (pure);
  `threat_library.py` loads the bundled `data/actors.json` or the synced full edition; `threat_library_sync.py`
  fetches the pinned releases (`insight threat-library-sync`). `threat_guide.py` and `threat_guide_markdown.py`
  compose a guide and its exports (JSON, Markdown, Navigator layer, sweep CSV/JSON). Pure functions, no SQL.
- `ioc_export.py`: the cross-report IOC export format (`insight-ioc-v1`): grouping, TLP labelling and defanging. Pure functions, no SQL.
- `connectors.py`: curated feed/KEV/CSAF/NVD/EPSS integration, one source at a time or all in turn (`sync_all`).
  Conditional fetching (`ETag` / `Last-Modified`, then a payload hash) skips unchanged feeds.
- `jobs.py`: the in-process job runner for opt-in scheduled syncs ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)) and alert delivery.
- `alerts.py`: what an alert says under each TLP label, signed webhooks and e-mail ([ADR 0022](adr/0022-alerts.md)); `services/alerts.py` decides when alerts fire and queues them.
  No SQL: the queue, schedules and fetch state are service functions.
- `brief.py`: the intel brief's wording (headline and sections) from facts that `services.brief_data` gathers.
  Pure functions, no SQL, no AI.
- `apikeys.py`: API key format, generation and hashing (pure functions). `totp.py`: RFC 6238 codes for the sign-in second factor (pure, standard library only). `ratelimit.py`: in-process per-caller token buckets and the API's policies ([ADR 0012](adr/0012-single-api-key-and-rate-limits.md)).
- `web/`: the JSON API and the security boundary. `app.py` holds `create_app`, which only composes: state, middleware, then one `_register_*` function per route group. `boundary.py` is the ASGI boundary (body-size limit, authentication gate, CSRF, rate limits, security headers); `auth.py` holds callers, sessions, API-key checks and sign-in; `routes/` has one module per area (`pages`, `documents`, `triage`, `exports`, `entities`, `sources`, `workspace`, `threats`, `hunting`, and others). Shared pieces (`session_checker`, `auth_dependency`, `start_session`, `get_document_or_404`, `ioc_export_query`) are module-level so they can be tested alone (`tests/api/test_app_factory.py`). `main.py` remains as a compatibility module: `insight.main:create_app` still works.
- `ui/`: NiceGUI workspace, one module per panel (`inbox`, `entities`, `watch_terms`, `sources`, `enrichment`, `ingest`, `ioc_export`, `stats`, `brief`, `schedules`; for threat guides `threats`, `threat_guide`, `hunts`, `rules`, `actors`), plus `workspace.py` (typed per-tab state and cross-panel hooks), `page.py` (layout), `reader.py` (the report reader), `theme.py` (light and dark colour tokens), `styles.py` (the style sheet: type scale, reading width, focus outline, phone rules), `typography.py` (real headings, new-tab links), `messages.py` (messages that stay until dismissed), `glossary.py` ("What the words mean"), `appearance.py` (the Light/Dark/System and "Larger text" buttons) and `mobile.py` (phone inbox navigation). Readability rules: [ADR 0017](adr/0017-readability-standard.md).
- `appearance.py`: the theme vocabulary shared by the configuration, the sign-in pages and the workspace (`INSIGHT_THEME`, the per-device `insight_theme` cookie). See [ADR 0016](adr/0016-colour-themes-and-per-device-choice.md).
- `templates/`, `static/app.css`: the sign-in and sign-out pages, in the same themes.
- `demo.py`: synthetic reserved-namespace examples.
- `cli.py`: `init`, `serve`, `migrate`, `backup`, `export-iocs`, `api-key`, `mfa`, and more; `cli_threats.py` holds `threat-library-sync`, `industries`, `threat-profile`, `threat-guide` and `rule-add`.
- `Makefile` (repository): shortcuts for Docker operations, keys, MFA, tests and CI gates (`make help`).
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
  `INSIGHT_MAX_TLP` (default `AMBER+STRICT`) then refuses manual submissions whose label is above the limit
  ([ADR 0013](adr/0013-instance-tlp-limit.md)).
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

Alembic owns the schema (revisions: `0001` baseline = 0.1.0, `0002` document revisions, `0003` folded search text and truncation flag, `0004` API keys, `0005` audit actor, per-key TLP limit and MFA). `database()` runs `insight.migrations.upgrade()` on every start. A 0.1.0 database (tables created by `create_all`, no `alembic_version`) is first stamped at the baseline revision `0001`, which reproduces the 0.1.0 schema exactly, then upgraded. `insight migrate` does the same explicitly. SQLite migrations run in batch mode with foreign keys temporarily disabled and a `foreign_key_check` before commit, which is SQLite's documented procedure.

To add a migration: change `models.py`, then run
`INSIGHT_DATABASE_URL=sqlite:///data/dev.db alembic revision --autogenerate --rev-id 0004 -m "..."` (using the repository's `alembic.ini`), review the file, and run the tests. `test_models_match_migrations` fails if the models and migrations disagree; `test_every_revision_is_reversible` checks `downgrade()`.

**Timestamps are ISO-8601 UTC strings in Python, and `timestamptz` on PostgreSQL** ([ADR 0030](adr/0030-postgres-timestamps-and-feed-cursors.md)). Timestamp columns use `models.UtcTimestamp`: on PostgreSQL the database stores, compares and indexes real moments; on SQLite the column stays text, because SQLAlchemy's `DateTime(timezone=True)` **silently drops the UTC offset** there (we verified that `12:00+05:00` is read back as a naive `12:00`). Code writes `models.now()` or `services.stamp(...)` and compares with such strings either way. A new timestamp column should use `UtcTimestamp()`, never `String(40)`.

## API

JSON routes live under `/api`. Each is reachable with the browser session (cookie plus `X-CSRF-Token` on writes;
`/api/session` hands out the token) or the single API key (`Authorization: Bearer`, no CSRF). Contracts are not
versioned yet; breaking changes are listed in the CHANGELOG. Usage: [API_GUIDE](API_GUIDE.md); fields:
[API](API.md).

### Request pipeline

```
TLS reverse proxy (optional; the container listens on loopback)
 → ProxyHeaders       only from INSIGHT_TRUSTED_PROXIES: real client address and scheme (uvicorn's middleware)
 → TrustedHost        Host must be in INSIGHT_ALLOWED_HOSTS
 → Session            signed cookie; the session ID must be stored and unexpired (operator_sessions)
 → Boundary           Origin check, 2 MB body limit, security headers (+ HSTS, RateLimit headers)
 → require_auth       one FastAPI dependency on every /api route, in this order:
      1. credential   Bearer key (hash lookup; uniform 401; invalid keys throttled per address)
                      or session (401) + CSRF on writes (403)
      2. authorise    read-only key: GET only; browser-only routes; TLP-limited key: no audit, no enrichment
      3. rate limit   token bucket per caller and policy (read / write / ioc-export) → 429 + Retry-After
 → route              opens the transaction with the caller as audit actor and passes its TLP limit
 → services           the only SQL layer; TLP limits become one condition on Document.tlp
```

- **API key** (`apikeys.py`, ADR 0012): `insk_<key id>_<secret>`; SHA-256 stored; one active key, managed only
  from the CLI/Makefile on the host, so neither a browser session nor a key can mint keys.
- **Rate limiting** (`ratelimit.py`): in-process token buckets behind one method (`RateLimiter.hit`), with an
  injectable clock; authenticated callers and per-address invalid-key counting use separate limiters so one
  cannot evict the other. Moving to several workers means a shared store (e.g. Redis) behind the same method.
- **TLP enforcement**: the instance limit (`INSIGHT_MAX_TLP`, ADR 0013) is applied in `services.ingest` after
  marking-based raising; a key's limit (ADR 0014) is a `max_tlp` argument on every report query, guarded by an
  architecture test and a leak-sweep test.
- **Audit actor**: `services.set_actor(db, ...)` names the caller on the database session; `services.audit`
  records it on every event, so service signatures did not change.
- **Sign-in MFA** is optional. The host CLI pairs the authenticator, and `INSIGHT_MFA=on` requires a code.
  The database stores an AES-256-GCM ciphertext under a key derived from `INSIGHT_SESSION_SECRET`.
  [ADR 0015](adr/0015-totp-second-factor.md)

No live connection happens at startup. Sources sync when the operator asks (**Sync now**, **Sync all sources**)
or on opt-in schedules, off by default ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)): both go through the
`jobs` table, and one in-process runner (`INSIGHT_RUN_JOBS`) works through it, one sync at a time under the same
lock as **Sync now**. A failed scheduled sync is tried again after 5, then 10 minutes, then recorded as failed;
every attempt appears in *Recent sync activity*. Provider lookups (NVD, EPSS) are explicitly requested and
globally throttled for the single operator.

## Next milestones

1. Validate pilot workflow and extraction quality with real permitted reports.
2. Add migration/versioning, search pagination and robust per-source incremental cursors.
3. Introduce identity-provider accounts and recipient/group handling before collaboration.
   API work designed but deferred so far (single operator, no Redis/PostgreSQL in production yet): a versioned
   `/api/v1` with deprecation headers, a published OpenAPI contract with response models, RFC 9457 problem
   details, cursor pagination, `202 Accepted` jobs for syncs and large exports, `Idempotency-Key`, shared
   sessions and rate limits (Redis) for several workers, and several named keys per user.
4. Add asset inventory relevance, investigations and watchlist notifications.
5. Add structured import/export and source-specific licensing/retention controls.
6. Add opt-in LLM enrichment behind the independent contract, only after evaluations and routing policies.

Actor activity is read through `services/actor_timeline.py`, with shared bounded report references in
`actor_reports.py` and explicit, audited campaign associations in `actor_campaigns.py`. The guide, JSON API,
Markdown export and narrow-screen UI share event DTOs. `software_navigator.py` is a pure projection and does
not change direct group techniques or hunt hypotheses. Campaign label raises advance `updated_at` for TAXII.
