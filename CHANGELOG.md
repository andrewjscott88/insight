# Changelog

## Unreleased

### Fixed: CI
- **Every GitHub Action is pinned to a commit SHA and the base image to a digest**; zizmor now enforces
  `hash-pin` and the release gate's pin check passes. `aquasecurity/trivy-action` moves from `0.28.0`, a tag that
  no longer exists (removed after the March 2026 trivy-action tag hijack, GHSA-69fq-xp46-6x23), to `v0.36.0`.
  This had broken the container job and the nightly image re-scan.
- **Mutation testing scored 0%:** a repository-hygiene test failed inside mutmut's `mutants/` copy (which git
  ignores), so mutmut aborted before testing any mutant. The test now skips when run from such a copy.
- **The newest-dependencies job failed on NiceGUI 3.19**, whose test simulator routes `ui.navigate.to` through
  `Client.open` and drops `new_tab`. The test helper now records the call on 3.18 and 3.19; the application was
  unaffected.

## 0.5.0 - 2026-11-19

### Added: readability for people with reading difficulties (ADR 0017)
An audit against WCAG 2.2, W3C COGA, the British Dyslexia Association style guide, APCA and plain-language
guidance found six WCAG A/AA failures and many readability gaps. The GUI now meets WCAG 2.2 AA plus the AAA
criteria written for reading, and a browser test (axe-core) checks every screen in both themes on desktop and phone.
- **Easier to read:** 16 px minimum text (was down to 10 px; 98% of desktop text was under 16 px), line spacing of at
  least 1.5, lines of about 70 characters (were up to 130), sentence case instead of capitals, left-aligned text, and
  report text in the page instead of a small scrolling box.
- **Stronger contrast:** every text colour at least 7:1 in both themes (WCAG AAA) and APCA Lc 75 or more; dark-mode
  grey text was APCA Lc 51. Light-theme field borders 4.2:1 or more (were 1.78:1).
- **Larger text** button (per device, remembered): a 19 px base with more space between letters, words and lines.
- **What the words mean:** a plain-language glossary of every abbreviation and specialist term (TLP, IOC, CVE,
  KEV...). Interface text rewritten in plainer words: Flesch-Kincaid grade 7.4 → 4.2; no sentence above grade 9.
- **Messages stay until you dismiss them** (they vanished after about 5 seconds, errors included); a new one replaces
  the last. They never cover a dialog or the control you are on.
- **Clear errors:** problems are explained on the field itself, in plain words that name the field as you see it
  (was `title: String should have at least 1 character`), and the cursor goes to the first one. Problems inside an
  open dialog are shown in the dialog.
- **Structure for assistive technology:** page language (`lang="en-US"`), real headings, named dialogs, links that say
  they open a new tab, invalid fields marked `aria-invalid`, a decorative loading bar hidden from screen readers.
- **Keyboard and motion:** a 3 px focus outline on every control (was a faint tint, 1.2–1.9:1); 44 px targets;
  animations off when the device asks for reduced motion.
- **You keep your place:** a page that loses its connection for up to 30 seconds (a phone losing signal or going to
  sleep) carries on where it was. After NiceGUI's default of 3 seconds it reloaded, losing the reading position and
  any unsaved note.

### Fixed: found by the readability audit
- Page language missing on the workspace (WCAG 3.1.1, Level A).
- No headings anywhere in the workspace (WCAG 1.3.1).
- The report text box could not be scrolled with the keyboard (WCAG 2.1.1).
- Light theme: field borders 1.78:1 (WCAG 1.4.11); selected report title 4.0:1 on hover (WCAG 1.4.3).
- Light theme: Quasar's "dark text" colour was remapped to the light panel colour (a defect from the theme work).
- Words were broken mid-word in narrow boxes ("docume-nts", especially with larger text): only hashes and URLs
  may break now, and the counters wrap to fewer columns instead.

### Added: light and dark themes, and a GUI that reads well on phones
- **Theme switch.** **Light / Dark / System** buttons at the top right of the workspace (icons only on a phone)
  switch at once. The browser remembers the choice for a year in the `insight_theme` cookie, per device, and the
  sign-in and sign-out pages use it too. **System is the default:** it follows the device's light/dark setting
  and changes with it. The workspace was dark only before. ADR 0016.
- **`INSIGHT_THEME=system|light|dark`** sets the default for browsers that have not picked a theme.
  `make theme THEME=dark` writes it to `.env` and restarts; `make up THEME=light` does the same while building.
  An invalid value stops start-up.
- **Phone layout:** larger text (16 px report text), 16 px inputs so iOS no longer zooms when a field is focused,
  touch targets of at least 40–44 px, short tab labels (Inbox, Entities, Watch, Sources) that fit without
  scrolling, the three counters in one row, tighter dialogs, and report text that no longer scrolls inside the
  scrolling page. Opening a report on a phone scrolls to it, and **← Back to list** returns to the list with that
  report in view.
- The mobile address bar follows the theme (`theme-color`).

### Fixed: readability defects found while adding the themes
- **Filled buttons were unreadable** (white on mint, 1.6:1) in the dark theme. Labels are now dark on mint
  (9.7:1). Every text colour is tested at WCAG AA (4.5:1) in both themes, from the palette and as rendered in
  Chromium.
- **The sign-in card ran off the right edge of a phone screen.**
- **Responsive labels that never showed:** the header tagline (`hidden sm:block` loses to Quasar's `!important`
  `.hidden`). Now visible on wider screens; an architecture test forbids the pattern.

### Changed: sign-in style sheet
- `static/app.css` now holds only the sign-in and sign-out pages' styles (about 150 unused rules from an earlier
  front end were removed); the sign-out page uses it instead of inline colours.

### Added: HTTP API for scripts and SIEMs
- **API key.** One key at a time, sent as `Authorization: Bearer insk_…` (no sign-in flow, cookie or CSRF token).
  Created, rotated, revoked and inspected only on the host: `make api-key-create|status|rotate|revoke` or
  `insight api-key create|status|rotate|revoke` (`--name`, `--access read|read-write`, `--expires-days`,
  `--max-tlp`). Read-only by default; expiry required (default 90 days, at most 365); shown once, stored as a
  SHA-256 hash only. Rotation and revocation apply on the next request, without a restart. Invalid, revoked
  and expired keys all get the same `401`. Audited as `api_key.create` / `api_key.revoke`; every write made
  with the key is logged with its key ID, never the key. ADR 0012.
- **TLP limit per key** (`--max-tlp GREEN`, `MAX_TLP=GREEN`): reports above it are invisible to the key on every
  route (indistinguishable from missing ones), its IOC exports are capped at the limit, and it cannot store
  reports above it. Limited keys cannot read the audit log or run CVE enrichment. `--max-tlp RED` removes the
  limit. ADR 0014.
- **Rate limits per caller** on every authenticated `/api` request: `read` 300/min, `write` 60/min,
  `ioc-export` 30/hour; the key and the browser session have separate budgets. Invalid keys are limited to 10
  per minute per client address without ever refusing the valid key. Responses carry `RateLimit-Policy` and
  `RateLimit` (IETF draft); `429` adds `Retry-After`.
- **Audit events record who acted**: `operator`, `api-key:<key ID>`, `cli`, `connector:<source>` or `system`
  (`GET /api/audit` returns `actor`).

### Added: publishing an instance
- **Reverse proxy support.** `INSIGHT_TRUSTED_PROXIES` (IPs or CIDR networks) makes Insight honour
  `X-Forwarded-For`/`X-Forwarded-Proto` from the proxy only. Before, sign-in and every other browser write
  behind an HTTPS proxy failed with `403` (Insight saw `http`, the browser's `Origin` said `https`), and every
  client appeared to come from the proxy. `*` and malformed entries stop start-up.
- **TLP:RED is refused by default.** `INSIGHT_MAX_TLP` (default `AMBER+STRICT`) is the most restrictive label
  the instance stores. A report labelled above it, or raised above it by a `TLP:` marking in its text, is
  refused on upload from the workspace and the API (`422`, with the reason) and nothing is stored; the workspace
  offers only permitted labels. Connectors and the demo are exempt. Start-up logs how many stored reports exceed
  the limit. ADR 0013.
- **Optional sign-in MFA, off by default.** `INSIGHT_MFA=on` requires an authenticator-app code (TOTP, RFC
  6238). `make mfa-enable` pairs the app if needed (nothing is saved until a code matches), sets `INSIGHT_MFA=on`
  in `.env` and restarts; `make mfa-disable` turns it off and keeps the pairing; `make mfa-status`,
  `make mfa-reset`; CLI `insight mfa setup|reset|status`. Each code works once; a wrong password never uses up a
  code; either mistake gets the same message. MFA on with no app paired locks sign-in (`503`) instead of
  falling back to the password. ADR 0015.
- `Strict-Transport-Security: max-age=31536000` on every response when `INSIGHT_SECURE_COOKIES=1`.
- `compose.yaml` passes `INSIGHT_ALLOWED_HOSTS`, `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_SECURE_COOKIES`,
  `INSIGHT_MAX_TLP` and `INSIGHT_MFA` through from `.env`, with safe defaults. Invalid values stop start-up.

### Added: Makefile
- `make help` lists 48 targets: first run (`env`: `.env` with generated credentials, never overwritten), running
  (`up`, `stop`, `restart`, `down`, `logs`, `ps`, `health`, `version`), data (`backup`, `restore` with a
  confirmation prompt, `export-iocs`, `migrate`, `db-shell`), the API key, MFA, checks against a running
  instance (`smoke`, `test-e2e`), development (`dev`, `serve`, `test*`, `lint`, `format`, `typecheck`), CI gates
  (`check`, `ci`, `package`, `benchmark`, `drill`) and maintenance (`locks`, `ioc-example`, `update-tlds`,
  `release-fixture`, `release-check`, `clean`). Backups and exports land in owner-only `backups/` and
  `exports/`, which git and Docker ignore; editing `.env` never loosens its permissions.
- `scripts/check_forbidden_files.py` also refuses files under `backups/` and `exports/`, and Insight API keys
  (`insk_…`) in any committed file.

### Licence
- Insight is released under the **MIT License** (`LICENSE`). The wheel and image carry `LICENSE` and `NOTICE`;
  the package metadata declares `License-Expression: MIT`.

### Documentation
- New [docs/API_GUIDE.md](docs/API_GUIDE.md): authentication (key and session), status codes, errors, rate
  limits, TLP and paging, a `curl` command for every route, recipes (SIEM pulls, ingesting files, paging,
  bulk review, back-off on `429`, Python) and troubleshooting. Its commands were executed against a running
  instance, and a test fails if a route has no `curl` example.
- RUNBOOK: reverse proxy setup, MFA, the API key, monitoring signals for the new log lines, Makefile
  equivalents. SECURITY: a checklist for publishing an instance. ARCHITECTURE: the API request pipeline and the
  deferred API work. ADRs 0012-0015. VALIDATION: what the unreleased work was verified against.

### Fixed before release
- Found while building the above, each with a regression test: a full-width or other non-ASCII digit in a
  sign-in code caused a server error; `--max-tlp RED` stored a RED limit instead of lifting it, locking the key
  out of the audit log for good; a clock stepping backwards could drain a rate-limit bucket and lock a caller
  out.

### Known issue
- A CVE-enrichment request for a well-formed CVE that no report mentions is refused (`422`) but still starts the
  6.5 s enrichment window (pre-existing; malformed requests do not).

### Added: cross-report IOC export
- **One JSON file with every indicator of compromise across your reports** (`format: insight-ioc-v1`). Each
  indicator appears once, with:
  - every report that mentions it (title, source, URL, TLP, triage status, ingestion time, extractor version,
    number of mentions and the first mention in context);
  - mention counts per review state, CISA KEV context for CVEs, and first/last ingestion times.
- **TLP is never lowered.** Each indicator carries the most restrictive label of its included reports, and the file
  carries the most restrictive label of every report it includes (`AMBER` when empty).
- **Filters:** indicator type, observation review state, highest TLP to include (`max_tlp`), chosen reports
  (`document_id`, `--document`), and the inbox search, status, TLP and superseded-revision filters. By default,
  mentions rejected during review are left out.
- **Sharing controls:**
  - defanging of values, report titles and evidence, including e-mail domains, CIDR ranges, file-like names
    (`update.zip`) and words cut at the edges of an excerpt. Source URLs stay as stored; each defanged value refangs
    to the original;
  - evidence can be left out (`--no-evidence`, `evidence=false`, **Include evidence excerpts**) so excerpts cannot
    carry context an analyst rejected.
- Available in four places:
  - the workspace (**Export IOCs**), with a live count preview that refuses empty or over-limit downloads;
  - the report reader (**Export this report's IOCs ↗**);
  - the API (`GET /api/iocs/export`, see docs/API.md);
  - the CLI: `insight export-iocs FILE`, which never overwrites, writes mode 0600, requires a current schema,
    lists every option's values and examples in `--help`, and reports problems as one-line messages.
- Error messages name the parameter or option as the caller wrote it (`kind 'IP': …`, `--kind 'ipv4': …`).
- Every export is audited as `ioc.export`. The audit event's object ID is the `export_id` inside the file.
- Not STIX. An export is not permission to redistribute.

### Fixed before release: found by exporting the synthetic reports
The two synthetic full-length reports (`tests/corpus/reports/`) were ingested through the API and exported through
the API, CLI and workspace. The exported indicators matched the hand-labelled ground truth exactly (apart from
the extractor's documented even-split hash). These export defects were found and fixed, each with a regression
test (`tests/api/test_ioc_export_reports.py` and `tests/unit/test_ioc_export.py`):
- defanged exports left **e-mail domains** (`billing@invoices.example.net`) and **CIDR ranges**
  (`203.0.113.0/24`, `2001:db8::/32`) live, because the extractor deliberately does not report them as indicators;
- defanged exports left **URLs and names cut at the edge of an excerpt** live (`…ttps://mail-relay.example.org/…`);
- **titles** were never defanged, although they often name indicators;
- a **rejected victim address** (`10.20.30.40`, "victim network") still reached recipients inside the excerpt of
  an accepted neighbour. Evidence can now be left out, and the guide recommends it for sharing;
- the CLI printed a **traceback** for an unwritable or read-only destination, and a raw `[Errno 17]` for an
  existing file;
- the dialog opened a tab with a **JSON error or an empty file** instead of explaining that nothing matched;
- a wrong `--kind` produced a confusing **second error** ("should have at least 1 item"), and messages used
  internal field names (`kinds.0`);
- summaries said "from **1 reports**".

### Documentation
- New guide [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md): quick start (workspace, CLI, Docker, curl, Python), recipes,
  how the filters combine, reading the file, TLP and sharing, defanging, `jq` recipes, STIX mapping notes,
  troubleshooting and format versioning.
- JSON Schema [docs/schemas/insight-ioc-v1.schema.json](docs/schemas/insight-ioc-v1.schema.json) and example file
  [docs/examples/insight-iocs-example.json](docs/examples/insight-iocs-example.json) (synthetic demo data),
  regenerated by `scripts/make_ioc_example.py`; tests keep both in step with the code.
- IOC export coverage in the README, API reference, RUNBOOK, security notes, CONTRIBUTING and test catalogue.

### Changed (internal; no behaviour change)
- `jsonschema` (already installed through `check-jsonschema`) is now a declared development dependency; the tests
  use it to validate exports. Lock file pins and hashes are unchanged.
- `starlette` is now a declared runtime dependency (`>=1.3.1,<2`). `main.py` imports it directly; it was only
  installed because FastAPI and NiceGUI require it. The lock files keep the same versions and hashes.
- `extraction.extract` is split into one pass per indicator family over a small collector (`_Mentions`). Output
  is identical: same mentions, offsets, evidence and limit error, checked against the previous implementation
  on the labelled corpus and 200,000 generated texts. `EXTRACTOR_VERSION` is unchanged.
- `main.create_app` only composes the application; routes are registered by one function per area, and the
  session check, auth dependency, session rotation and IOC query parsing are importable, separately tested
  functions. Routes, middleware order and responses are unchanged.
- Type annotations follow current typeshed (`Generator`/`AsyncGenerator` for context managers); the app's
  shutdown releases database connections even if shutdown fails. Two unused definitions were removed.

### Upgrade notes
- **TLP:RED uploads are refused by default.** To keep storing TLP:RED material deliberately, set
  `INSIGHT_MAX_TLP=RED` in `.env`. Existing RED reports are kept either way; start-up logs how many exceed the
  limit. The browser (e2e) tests need `INSIGHT_MAX_TLP=RED` on the server they run against.
- Schema migrations `0004` (`api_keys`) and `0005` (audit `actor`, the key's `max_tlp`, `operator_mfa`) run
  automatically at start-up; back up first, as always. No existing data changes. Audit events from before
  `0005` have an empty actor.
- MFA stays off unless you turn it on (`make mfa-enable`). The new settings (`INSIGHT_TRUSTED_PROXIES`,
  `INSIGHT_MAX_TLP`, `INSIGHT_MFA`) are validated strictly: a typo stops start-up with a message naming it.
- Browser API clients are rate limited too (far above interactive use). Scripts that scraped the sign-in form
  can switch to the API key (docs/API_GUIDE.md).
- The inbox search now builds its report filters with the same helper as the IOC export; results are
  unchanged.

## 0.2.0 - 2026-11-13

Schema migrations `0002` and `0003` run automatically on start-up. **Back up first** (`insight backup FILE`).
See "Upgrade notes" at the end of this section.

### Fixed: found by running two synthetic intrusion reports through the pipeline
Reports: `tests/corpus/reports/` (GLASS HARBOR and SALT MERIDIAN, with hand-labelled ground truth).
- **Fabricated or truncated indicators** (worse than missed ones) are no longer produced:
  - homoglyph domains (`exаmple-login.com` → `mple-login.com`) and zero-width characters (`exam\u200bple.com` →
    `ple.com`);
  - half-defanged names (`files.example[.]net` → `files.example`);
  - the IPv4-mapped `::ffff:203.0.113.9` truncated into the different address `::ffff:203`;
  - URL path segments (`logon.aspx`, `b.js`) reported as domains.
  The extractor is now `regex-v2` (see docs/EXTRACTION.md).
- **Defanged indicators are refanged** (`hxxp`, `hxxps`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`). Offsets
  and evidence still point at the defanged source text.
- **International domains** are extracted as punycode (`xn--…`), including NFD-accented and homoglyph names.
- **Domains must have a real TLD** (bundled ICANN list, plus special-use names such as `.example`, `.onion`,
  `.internal`), so `svchost.exe`, `update.bin` and `Net.WebClient` are no longer domains. Two-label names whose
  TLD is also a common file extension (`update.zip`, `setup.py`, `app.run`) count only as URL hosts.
- **IP addresses:**
  - CIDR ranges (`203.0.113.0/24`, `2001:db8::/32`) and version strings (`firmware 10.2.9.1`) are no longer
    single IPs;
  - IPv4-mapped IPv6 resolves to the IPv4 address;
  - fixed-width zero padding (`192.000.002.033`) is accepted, while ambiguous leading zeros are still rejected.
- **New extraction coverage:**
  - `sha512` kind;
  - hashes wrapped unevenly onto the next line are joined;
  - `_dmarc`-style labels, trailing-dot FQDNs and punycode TLDs are recognised;
  - credentials are stripped from URLs instead of the whole URL (and its domain) being dropped;
  - balanced parentheses are kept in URLs.
- **Search folds case, accents, width and Unicode normal form identically on SQLite and PostgreSQL**. Previously
  `überwachung` and `istanbul` found nothing on SQLite, and an NFC `café` never matched NFD text on either
  database. Watch terms use the same folding.
- **TLP handling:**
  - the API default is now `AMBER` (it was `CLEAR`, less restrictive than the UI);
  - a `TLP:` marking in the title or body raises the label and never lowers it;
  - the event is audited (`document.tlp_raised`), the API returns `tlp_raised_from`, and the UI warns.
- **CRLF and LF copies of a report now de-duplicate** (line endings are normalised at input).
- **Entity explorer:** pivot lists load lazily, 25 at a time. 100 reports sharing 43 indicators went from
  5,196 UI elements, a 1.7 MB page and 3.7 s to 933 elements, 174 KB and 0.56 s. `/api/entities/{id}` is
  paginated (`offset`, `limit`, `document_count`).
- **JavaScript consumers** get `start_offset_utf16`/`end_offset_utf16`. The code-point offsets are off by one
  after astral-plane characters such as emoji.
- **RSS items whose summary was cut** are flagged `truncated`, and the UI says the full report may contain more
  indicators.
- The connector user agent now reports the real version.

### Fixed: found while writing and verifying the runbook
- **Migrations and sign-ins were invisible in the logs.** Uvicorn configures only its own loggers, so
  `insight.*` INFO records were dropped. `serve` and `migrate` now log schema upgrades (`Database schema
  upgraded 0001 -> 0003`) and sign-ins with timestamps.
- **The TLD list would never have been committed.** The `.gitignore` rule `data/` (meant for the runtime data
  directory) also matched `src/insight/data/`. It is now anchored (`/data/`), and a test guarantees that no
  package file is ignored.
- The manual document-deletion procedure (RUNBOOK §9) was tested against a revision chain. The first draft
  violated the one-current-revision index; the published order is verified.
- Test isolation: CLI tests no longer leak logger configuration into later tests (found by mutation testing,
  which runs tests in a different order under pytest 8).

### Documentation
- New: `docs/RUNBOOK.md` (operations), `docs/API.md`, `docs/EXTRACTION.md`, `docs/README.md` (index),
  `docs/adr/` (11 decision records), `CONTRIBUTING.md`, root `SECURITY.md` (vulnerability reporting),
  `NOTICE` (third-party data), pull-request template.
- A documentation gate checks that relative links resolve, every API route is documented, every ADR is indexed,
  and the README states the current version.
- `scripts/update_tlds.py` regenerates the bundled TLD list from the Public Suffix List.

### Extraction quality (benchmark corpus, both reports included)
Overall precision **67.8% → 97.9%**, recall **78.4% → 98.9%**; domain precision **36% → 100%**. The only
remaining miss is a documented limitation: a hash split evenly into two valid lengths (32 + 32) cannot be told
apart from a one-hash-per-line list.

### Fixed: found by the new real-browser gate (all present since 0.1.0)
- **No browser could sign in.** `Referrer-Policy: no-referrer` makes Chromium and Firefox send `Origin: null`
  on same-origin form POSTs, and the Origin check rejected them (HTTP 403). The policy is now `same-origin`;
  the Origin check stays strict and `Origin: null` is still refused.
- `Cache-Control: no-store` was appended to NiceGUI's immutable framework assets, so browsers re-downloaded
  ~1 MB of JavaScript on every page load. Security headers no longer override or duplicate headers the
  application set. Reloads now transfer zero bytes of framework assets and took ~0.4 s in testing
  (previously every load behaved like a cold load: 2-4 s).
- Unsaved note text was discarded whenever the document pane re-rendered (a review click, or a source sync
  finishing in the background). Drafts are now kept per document until saved.

### Decision 1: schema migrations (Alembic)
- Migrations ship inside the package and run at start-up. `insight migrate` runs them explicitly.
- 0.1.0 databases are detected, stamped at the baseline (which reproduces the 0.1.0 schema exactly on SQLite
  and PostgreSQL) and upgraded. Every committed release database is upgraded in CI.
- Datetime-column conversion is deliberately deferred to the PostgreSQL milestone: SQLAlchemy's
  `DateTime(timezone=True)` silently drops UTC offsets on SQLite (verified).

### Decision 2: sign-in throttling
- The hard lockout after 10 failures/minute is replaced by serialised password checks with a 1 s delay per
  failure, a 30/minute backstop, and logging of failures (never the password).

### Decision 3: performance
- Document lists compute entity counts with one grouped query (was one query per row).
- Ingest loads and creates entities in batches (was two round trips per mention). PostgreSQL ingest is 2.4×
  faster, SQLite 1.6×; found by the new performance-budget gate.

### Decisions 4 and 5: UI split and one query layer
- `ui.py` (one ~600-line function) is now the `insight.ui` package, one module per panel, with typed state.
- All SQL lives in `services.py`; the API and UI share it, and an architecture test enforces this.
- Search is the same everywhere: literal, case-insensitive, over title, body **and source name** (the API
  previously ignored source names and was case-sensitive on PostgreSQL).

### Decision 6: revisions instead of duplicates
- Synced items carry `(source_key, external_id)`. A publisher edit creates a new revision that supersedes
  the old one (one current revision per item, enforced by a partial unique index); a revert reactivates the
  earlier revision. Bodies are never edited. Existing duplicates are linked during the migration.
- API: `include_superseded` on `/api/documents`; `is_current` in summaries; `source_key`, `external_id`,
  `supersedes_id`, `revisions` in document details; `observations_unreviewed` in `/api/stats`.
- UI: superseded banner with a link to the current revision, revision history, "Include superseded" switch.

### Decision 7: container and supply chain
- Multi-stage image, hash-pinned build backend, no build isolation, non-root user, read-only root filesystem
  (Compose `read_only: true`), NiceGUI storage on the data volume, resource limits.
- `insight backup FILE`: consistent online SQLite backup with integrity check.

### Upgrade notes
- API clients that relied on the old `tlp` default (`CLEAR`) must now send `tlp` explicitly. Resubmitting such
  a document without `tlp` creates a new AMBER document instead of de-duplicating.
- Documents ingested before 0.2.0 keep their `regex-v1` observations; only new documents use `regex-v2`.
  Re-ingesting changed feed items creates new revisions automatically.
- Migration `0003` folds the text of every stored document once. Allow a few seconds per 10,000 documents.

### Synthetic full-length report (pipeline dry run)
- Added `tests/corpus/reports/notional-intrusion-report.md` with ground truth, plus tests at every layer (unit on
  both databases, API, NiceGUI, real browser) and in the extraction benchmark. Defects it found are tracked as
  strict-xfail tests (see docs/TESTING.md, "known-defects register").
- Pipeline fixes found by the dry run: the extraction gate now fingerprints its corpus and reports "corpus
  changed" instead of false regressions; per-test `max_examples` made the nightly 5,000-example property run
  silently use 300 (removed, with a guard test); `pip-audit` exited 0 with nothing audited and wrote an empty SBOM
  when its service was unreachable (now `--strict`, plus a non-empty-SBOM check).

### CI/CD
- Five tiers (pre-commit, CI, nightly, milestone gate, release). See docs/CI_CD.md.
- New gates: lock/pyproject drift, workflow schema and zizmor, gitleaks, Trivy, licence policy, PostgreSQL
  suite, extraction-quality benchmark, performance budget, backup/restore drill, Playwright, OWASP ZAP,
  mutation testing, live contract tests, cosign signing, SBOM and provenance attestations.
- Mutation testing (86% of 1,305 mutants killed) found and closed seven test gaps.

## 0.1.0 – code-review revision

### Fixed: build and install
- `nicegui>=4.0,<5` could not be satisfied (NiceGUI 4 does not exist), so the package could not be
  installed. It is now `nicegui>=3.18,<4`.
- `requirements.lock` pinned five versions that do not exist on PyPI (`nicegui 4.0.0`,
  `fastapi 0.162.5`, `python-socketio 5.18.1`, `annotated-doc 0.0.6`, `certifi 2026.10.23`). This broke
  the Docker build, CI and the README quick start. The lock files are now generated by `uv pip compile`
  with hashes and split into runtime (`requirements.lock`) and dev (`requirements-dev.lock`).
- `insight serve` ignored `./.env` for non-editable installs: bare `load_dotenv()` searches from the
  module's own directory. It now loads `.env` from the working directory, as documented.

### Fixed: security
- Login/logout CSRF check: the literal token `missing` matched the fallback default when the session had
  no token. That allowed CSRF-less login with the correct password, and a wrong password crashed with
  `KeyError` (HTTP 500). The check now fails closed.
- Any request header containing a non-UTF-8 byte (valid HTTP `obs-text`) caused a 500 on every route.
  Headers are now decoded as latin-1, per ASGI.

### Fixed: correctness
- IPv4 addresses at the end of a sentence (`… 192.0.2.8.`) or with a port (`192.0.2.8:443`) were not
  extracted.
- The local part of e-mail addresses (`first.last@…`) was extracted as a domain.
- Extraction patterns are ASCII-only, so Unicode digits and look-alike letters no longer match.
- The 2,000-mention limit raised at exactly 2,000 (off-by-one relative to its "exceeds" message).
- `import_kev` raised `AttributeError`/`TypeError` instead of `ValueError` for malformed payloads.
- A non-JSON or oversized provider response was reported as HTTP 422 (client error); it is now 502.
- Invalid enrichment requests consumed the 6.5 s throttle window.
- The redirect-refusal message in `download()` was unreachable because `raise_for_status()` ran first.
- UI notes were audited as `note.create` while the API used `note.add`; both now use `note.add`.
- `insight init` crashed with a traceback when `.env` existed; it now prints a message and exits 1.
- `sqlite://` (in-memory) databases were empty in every thread but the first.

### Changed
- Source-sync and enrichment database work runs in a worker thread, so the NiceGUI event loop is not blocked.
- Document detail fetches KEV context with a single join (was one query per observation). Ingest caches
  entity lookups within a document.
- Full type hints (`mypy --strict` clean), expanded ruff ruleset, `ruff format`, single-sourced version,
  `py.typed`, `insight --version`.
- Docker image: Python 3.13, runtime-only dependencies, `--require-hashes`.
- CI: lint/format/type-check/audit job plus a test matrix on Python 3.11–3.14 with a coverage gate.
