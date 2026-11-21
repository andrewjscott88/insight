# Test suite design

About 630 offline tests run in about two minutes per Python version (3.11–3.14), on SQLite and on PostgreSQL 16.
Branch coverage is about 95% overall and 98–100% for every backend module; CI requires at least 90%. Separate
suites cover real browsers (`tests/e2e`) and real publishers (`tests/live`). The pipeline's own scripts are
tested too.

## Principles

1. **Offline by construction.** An autouse fixture (`_no_network`) makes DNS and outbound TCP fail (loopback is
   allowed for local databases and servers). Only `live` and `e2e` tests are exempt, and they only run when
   explicitly enabled.
2. **Isolated state.** Every test gets a fresh, migrated database, cloned from a per-session template on SQLite
   (file copy) and on PostgreSQL (`CREATE DATABASE … TEMPLATE`). Migrations run once, not 500 times.
3. **Both databases.** `INSIGHT_TEST_DATABASE_URL=postgresql+psycopg://…/postgres` runs every database-backed
   test against its own throwaway PostgreSQL database.
4. **Test the real stack.** API tests use the full middleware chain and the real sign-in form. UI tests drive
   the real authenticated app. Browser tests drive the real container.
5. **Fakes at the boundary only.** Only the network (`connectors.download`, or `httpx.MockTransport` plus a fake
   resolver) and occasionally the clock are replaced.
6. **Warnings are errors.** This has caught a SQLAlchemy 2.1 deprecation and leaked SQLite connections on
   Python 3.13+.
7. **Every fixed bug has a named `Regression:` test.** Each was checked by re-introducing the bug and confirming
   that the test fails. Mutation testing (nightly) checks this systematically.

## Layout

| Path | What it protects |
| --- | --- |
| `unit/test_extraction.py` | Per-kind detection, canonicalisation, refanging, context rules (fragments, TLDs, URL paths, CIDR, versions), offsets, limits; Hypothesis invariants for any input |
| `unit/test_extraction_passes.py` | Each extraction pass and predicate in isolation (URL, domain, IP, hash and CVE passes; fragments, file-like names, span containment; the mention limit) |
| `unit/test_notional_report.py`, `api/test_notional_report.py` | Both synthetic reports against ground truth, on both databases and over HTTP |
| `unit/test_schemas.py`, `test_config.py` | Validation boundaries; fail-closed configuration (including `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_MAX_TLP`, `INSIGHT_MFA`: typos stop start-up) |
| `unit/test_models.py` | Foreign keys, unique and partial-unique (one current revision) constraints, in-memory DB across threads |
| `unit/test_migrations.py` | Fresh install, models = migrations (`alembic check`), every revision reversible, **every committed release database upgrades** with data preserved and fingerprints still de-duplicating, 0.1.0 duplicates become revisions, PostgreSQL legacy backfill |
| `unit/test_jobs.py` | Scheduled syncs: schedules (off by default, audited, no catch-up burst), one active job per source (also enforced by the database), claiming, retries with back-off, crash recovery, pruning, and the runner driven by a fake clock (waits for a manual sync, survives unknown job kinds) |
| `unit/test_conditional_fetch.py` | Fetching less: `If-None-Match` / `If-Modified-Since`, `304`, unusable validators, unchanged payloads, re-reading after an upgrade, failures never remembered, and both CISA CSAF indexes |
| `unit/test_brief.py` | Intel brief: facts gathered (window, TLP visibility, KEV, mentions, watch terms), what counts as new (publication dates, demo left out), the executive summary (order, federal deadlines, plain-language grade of every sentence), sections, vendor spellings, and the contract with the CSAF connector's lines |
| `unit/test_landscape.py`, `unit/test_landscape_data.py` | Threat landscape: rising / new / steady / quieter against the 4 periods before, the share test that stops a busy source from making everything rise, no and partial history, tactics in plain words, demo left out, the most restrictive TLP, KEV growth, a cut-off read; themes (folded words, valid techniques, no match on common advisory wording, plain explanations); the TLP limit on every row read; the Markdown briefing (TLP lines, escaping); plain-language grade of every sentence |
| `unit/test_threat_sources.py`, `api/test_threat_sources_api.py`, `ui/test_sources_switches.py` | Threat-research sources: every source HTTPS on an allowed host, optional sources off and metadata-only, a research feed keeps the excerpt and never `content:encoded`; switches (audited, switching off turns the schedule off), a switched-off source is never contacted or recorded, *Sync all* covers the sources in use, `409` for sync and schedule; reuse rules (report export without text and evidence, IOC export `evidence: null`), the Sources tab |
| `unit/test_services.py` | Ingest, revisions (supersede / no-op / revert / rollback safety / source scoping), unified search semantics, **query-count regressions** (list and ingest), stats, entities, analyst actions, golden fingerprint |
| `unit/test_feeds.py`, `test_kev.py`, `test_csaf.py`, `test_download.py`, `test_sync_and_enrichment.py` | Connectors: parsing, identity, validation, SSRF controls, redirects, size limits, error mapping. `test_csaf.py` uses two real CISA advisories from `tests/fixtures/csaf/` |
| `unit/test_cli.py` | `init`, `serve` (.env from CWD), `migrate`, `backup`, `api-key` (lifecycle, one active key, TLP limit, usage errors), `mfa` (pairing only after a matching code, idempotent setup, status for every switch/pairing combination, reset, cancel) |
| `unit/test_apikeys.py`, `test_api_key_service.py` | Key format and parsing, hash-only storage, one active key, rotation, revocation, expiry, throttled `last_used_at`, audit events without the secret |
| `unit/test_ratelimit.py` | Token buckets on a fake clock: bursts, continuous refill, separate callers and policies, `RateLimit`/`Retry-After` headers, bounded memory without forgetting partly used buckets, a clock stepping backwards, thread safety |
| `unit/test_totp.py` | RFC 6238 reference vectors, drift window, replay refusal, malformed and non-ASCII codes, provisioning URI |
| `unit/test_tlp_limit.py` | `INSIGHT_MAX_TLP` in `services.ingest`: refusal before anything is stored, markings cannot slip past, content never logged |
| `unit/test_makefile.py` | Every target documented and listed; Docker targets against a recording stand-in for `docker compose`; Python targets against a stand-in virtualenv; `.env` stays `0600`; restore asks first; failed MFA pairing never switches MFA on; `make check` matches CI |
| `unit/test_ioc_export.py` | IOC export: grouping, TLP labelling (never lowered, unknown labels fail safe), defanging (values, titles, evidence, e-mail domains, CIDR ranges, file-like names, words cut at excerpt edges) and its round trip (Hypothesis over IP addresses), filters (including chosen reports and superseded revisions), evidence on/off, preview counts equal to the export, KEV context, auditing, size cap, JSON Schema conformance (closed schema: no undocumented fields), error messages named as the caller typed them, and `insight export-iocs` (no overwrite, `0600`, schema check, unwritable directory and write failures without tracebacks, help text) |
| `unit/test_architecture.py` | Layering: front ends never build SQL; the UI never touches ORM classes; UI modules stay small; **every API call to a report query passes the caller's TLP limit**; panels use theme colours only (no hex values or fixed Tailwind shades); no `hidden sm:block` (Quasar's `!important` `.hidden` hides it at every width) |
| `unit/test_theme.py` | Colour themes and text size: `INSIGHT_THEME` and cookie parsing (Hypothesis: any cookie yields a known theme and text size), cookie attributes, both palettes complete, **WCAG AAA (7:1) and APCA contrast** (formula checked against the reference implementation) of every text colour on every background in both themes, messages, TLP badges and button labels, 3:1 field borders and focus outline, `app.css` identical to the workspace palettes, the type scale (16 px minimum, 1.5 line height, ~70-character lines, no capitals, `rem`), the focus outline, reduced motion, "Larger text", the sign-in card fitting a phone |
| `unit/test_plain_language.py` | Every interface string, collected from the code and templates: **Flesch-Kincaid grade 9 or below** per sentence and about age 12 overall, no all-caps labels, **every abbreviation explained in the glossary**, plain validation messages for every ingest field, messages that stay until dismissed and replace each other |
| `unit/test_docs.py` | Links resolve; required documents exist; every route appears in `API.md` **and has a `curl` command in `API_GUIDE.md`**; every `make` target the docs mention exists |
| `unit/test_scripts.py` | The CI/CD gates themselves (release metadata, pins, licences, forbidden files including backups, exports and API keys, locks, benchmarks, smoke test, backup drill, release fixtures, the committed IOC export example). This includes the **extraction-quality gate**, so it runs on every push. |
| `api/*` | Auth/CSRF/sessions/throttling, middleware (headers, Origin, body limits, caching), documents, entities, sources, schedules and jobs (read by anyone signed in, changed by a browser session only), the job runner starting and stopping with the app, enrichment, IOC export over HTTP (`test_ioc_export.py`: filters, TLP, defanging, evidence, audit, 422s), the IOC export end to end on both synthetic reports (`test_ioc_export_reports.py`: ground truth, TLP policy, nothing live when defanged, rejected victim data kept out when sharing, CLI = API), and the app factory's building blocks in isolation (`test_app_factory.py`: session check, auth dependency, session rotation, one route group on a bare app). API platform: `test_api_keys.py` (every route with read and read-write keys, uniform 401s, CSRF split, rate limits and headers, invalid-key flood without locking out the real key, keys never logged), `test_key_tlp_limit.py` (**a marker planted in an AMBER report must not appear in any API response to a GREEN key**), `test_tlp_limit.py` (TLP:RED refused over HTTP), `test_proxy.py` (sign-in through an HTTPS proxy, forged headers ignored, per-client limits), `test_mfa_login.py` (off by default, codes once only, locked when on without pairing), `test_audit_actor.py` |
| `ui/test_appearance.py` | Light/Dark/System buttons: default System, each switches at once and writes the cookie (with `Secure` behind HTTPS), the cookie and `INSIGHT_THEME` are honoured on the next visit, screen-reader labels and `aria-pressed`, a revoked session cannot change it; on phones, opening a report scrolls the reader into view and **Back to list** returns without losing an unsaved note |
| `ui/test_readability.py` | One `h1` and real section headings, the report reader's `h2`/`h3` structure, named dialogs with headings, the glossary, "Larger text" (default off, switches at once, remembered and applied before the page renders), note errors on the field, new-tab links that say so |
| `ui/test_workspace.py` | NiceGUI simulation of analyst workflows, including revisions, unsaved-note preservation and the **Export IOCs** dialog (count preview, empty downloads refused, download URL and new tab recorded), plus the reader's per-report IOC link, the intel brief (empty state, demo left out, executive summary, links to reports, indicators and searches) and **Sync all sources** (progress, partial failure, busy lock) |
| `ui/test_render_smoke.py` | Fresh-process boot of the whole app |
| `e2e/test_browser.py` | Real Chromium: sign-in, headers and cookie flags, demo, ingest → review → note, search, sign-out revokes other tabs |
| `e2e/test_readability.py` | Real Chromium with **axe-core** (`axe-playwright-python`): **no violations of WCAG 2.0-2.2 A, AA and AAA rules or axe best practices** on every screen (sign-in, inbox, report, every dialog, every tab, sign-out), both themes, desktop and iPhone; painted-colour contrast inside dialogs; rendered typography (16 px minimum, line height 1.5, 80 characters per line at most, no capitals or centred paragraphs); a 3 px focus outline on every control; messages that stay until dismissed; dialog problems explained in the dialog and never covered; "Larger text"; reduced motion; the page language |
| `e2e/test_theme_and_mobile.py` | Real Chromium: System follows the device's light/dark setting; a choice applies at once, survives a reload, reaches the sign-out page and stays on that device; **contrast as rendered** in both themes; desktop tab labels visible; on an iPhone 13, a Pixel 7 and a 320 px screen: nothing wider than the screen (sign-in, every tab, dialogs), 16 px inputs, 40 px+ buttons, reader scrolled into view and **Back to list** |
| `live/test_sources_live.py` | Real publishers' contracts (nightly) |

## Full-length synthetic reports and the known-defects register

`tests/corpus/reports/` holds two realistic synthetic intrusion reports with hand-labelled ground truth. They
run through extraction, the service layer on both databases, the API, the NiceGUI dialog, the real browser
against the container, the extraction benchmark and the performance probes.

| Report | Edge cases |
| --- | --- |
| `notional-intrusion-report.md` (GLASS HARBOR) | Defanged indicators, IPv6, ports, CIDR, upper-case hashes, Cyrillic homoglyph domain, e-mail addresses, PowerShell, file names, versions, German text, astral emoji, embedded HTML, TLP:AMBER |
| `notional-salt-meridian.md` (SALT MERIDIAN) | IPv6 zone IDs and IPv4-mapped/bracketed forms, IPv6 CIDR, zero-padded octets, wrapped hash, SHA-512, zero-width space and NFD accent in domains, `_dmarc`, trailing-dot FQDN, punycode, credential URL, Turkish and Japanese text, TLP:RED |

**Known-defects register.** Defects that are found but not yet fixed are written as `xfail(strict=True)`
tests ([ADR 0010](adr/0010-known-defect-register.md)). Fixing a defect turns its test red until the marker
is removed, so the register cannot drift.

In 0.2.0 the register is **empty**. All eight defects the reports exposed (fabricated or truncated
indicators, defanged and international names, CIDR and version IPs, file-name domains, non-ASCII search on
SQLite, the permissive TLP default, unbounded entity pivots) are fixed and are now ordinary regression tests.
Deliberate limitations are tested as such (for example, an even 32 + 32 hex split stays two hashes).

## What the real-browser gate found

These defects were invisible to every in-process test, and all but the last were already present in 0.1.0:

- **No browser could sign in.** `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on form POSTs,
  which the Origin check rejected.
- **About 1 MB of JavaScript was re-downloaded on every page load**, because `no-store` was appended to immutable
  framework assets.
- **Unsaved note text was lost** whenever the pane re-rendered (a review click, or a sync finishing).
- A test-isolation flaw in my own first E2E draft: it relied on shared demo state.

## Running

Make equivalents: `make test`, `make test-fast`, `make test-cov`, `make test-postgres`, `make test-live`,
`make test-e2e` (against `make up`, started with `INSIGHT_MAX_TLP=RED`).

```sh
pytest                                   # everything offline
pytest tests/unit -q                     # fast inner loop (~15 s)
pytest -m "not ui and not slow"
INSIGHT_TEST_DATABASE_URL=postgresql+psycopg://postgres@localhost/postgres pytest -m "not slow"
HYPOTHESIS_PROFILE=nightly pytest tests/unit/test_extraction.py
INSIGHT_LIVE_TESTS=1 pytest tests/live -m live
INSIGHT_E2E_URL=http://127.0.0.1:8080 INSIGHT_E2E_PASSWORD=… pytest tests/e2e -m e2e
# an installed Chromium/Chrome instead of `playwright install chromium`:
INSIGHT_E2E_CHROMIUM=/usr/bin/chromium INSIGHT_E2E_URL=… INSIGHT_E2E_PASSWORD=… pytest tests/e2e -m e2e
```

## Writing tests

- Fixtures: `client`, `authed`, `make_document(**overrides)`, `login(client)`, `session_factory`/`db`,
  `database_url`, `empty_database_url`, `count_queries(engine)`.
- Fake a provider with `monkeypatch.setattr(connectors, 'download', fake)`. For the fetcher itself, pass
  `transport=httpx.MockTransport(...)` and patch `socket.getaddrinfo`.
- NiceGUI 3 runs `refresh()` in the background. Wait with `await user.should_see(...)` (which polls) before
  `user.find(...)`, and scope ambiguous finds with `with user.scope(marker='document-list')`.
- Browser tests must create their own data (e.g. a uniquely titled document). The server under test is
  long-lived.
- When you fix a bug, add a test that says `Regression:` and describes the old behaviour.
