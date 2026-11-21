# Insight

A single-operator threat-intelligence workbench, run locally or published behind a TLS reverse proxy. Application logic and the interactive GUI are authored in **Python**, using **NiceGUI + FastAPI + SQLAlchemy**. NiceGUI supplies the underlying browser assets; no separate React/Node build is required.

**Version 0.6.0: a single-operator pilot release, not a production multi-user TIP.** Nothing is deployed or connected automatically. Operating it: [docs/RUNBOOK.md](docs/RUNBOOK.md). Scripting against it: [docs/API_GUIDE.md](docs/API_GUIDE.md) (every call, with `curl`). All documentation: [docs/README.md](docs/README.md).

## What works

- **Built for readability, including for people with dyslexia or other reading difficulties** ([ADR 0017](docs/adr/0017-readability-standard.md)): WCAG 2.2 AA plus its reading-related AAA criteria (7:1 contrast, lines of about 70 characters, 1.5 line spacing, plain language), 16 px minimum text, no capitals, real headings, a strong focus outline, messages that stay until you dismiss them, a **Larger text** button and a **What the words mean** glossary. Checked in the test suite with axe-core on every screen.
- **Light and dark themes, readable on phones.** The workspace follows each device's light/dark setting by default; the **Light / Dark / System** buttons in the header override it for that browser. The instance default is `INSIGHT_THEME` (`make theme THEME=dark`). On a phone the layout uses larger text, no zoom-on-focus, big touch targets, and opening a report scrolls to it (with **← Back to list**). Text in both themes meets WCAG AA contrast (tested).
- Password-protected analyst inbox with split-pane report reader, search and TLP/status filters. Search ignores case, accents and Unicode normal form identically on SQLite and PostgreSQL.
- Paste reports with title, source, URL and handling label; preserve original text and its SHA-256 hash.
- Deterministic extraction of CVEs, IPv4/IPv6, URLs, domains and MD5/SHA1/SHA256/SHA512 mentions, including defanged (`hxxp`, `[.]`) and international (punycode) forms. It is precision-first: about 98% precision and recall on the labelled corpus ([docs/EXTRACTION.md](docs/EXTRACTION.md)).
- TLP defaults to AMBER, and a `TLP:` marking inside a report can only raise its label, never lower it.
- Exact character offsets and contextual evidence, canonical entities and cross-report pivots.
- Accept/reject/reset observations, triage reports and add analyst notes with audit events. Delete a report
  for legal or retention reasons with `make delete-report` (CLI only; audited, repairs revisions).
- **Verdicts and a safe blocklist.** Accept only says a value was copied correctly; a separate **verdict** (benign,
  suspicious, malicious, with a reason, its own TLP label and an optional end date) says what it means, from the
  reader or the entity explorer. **Warnings** mark values that must never be blocked (private, reserved and
  example addresses, reserved names, big vendor sites). `GET /api/iocs/blocklist` lists only unexpired malicious
  values with an accepted mention and no warning, for firewalls and SIEMs.
- **MITRE ATT&CK® techniques** ([ADR 0019](docs/adr/0019-attack-techniques.md)). Reports are tagged with the
  technique IDs written in them (`T1059.001`), checked against a bundled Enterprise ATT&CK catalog; analysts add
  and remove the rest in the reader, and new revisions keep those decisions. The **ATT&CK techniques** tab groups
  the techniques in your reports by tactic over a period you choose, opens the reports behind each one, and
  downloads a layer for ATT&CK Navigator. Never guessed from prose; no attribution. `make attack-backfill` tags
  reports stored before 0.7.0. API: `/api/attack/*` and `/api/documents/{id}/techniques`.
- Organization watch terms highlight literal product, vendor or topic matches. These are transparent keyword matches, not calibrated risk scores.
- **Threat-research sources, off until you switch them on** ([ADR 0021](docs/adr/0021-threat-research-sources.md)):
  Cisco Talos, Microsoft Threat Intelligence, The DFIR Report, ESET WeLiveSecurity, Kaspersky Securelist and
  The Record (news), for reporting on attacker groups, campaigns and malware. Insight keeps each item's title,
  short summary and link. Each publisher's reuse rule applies: only CISA's text leaves Insight in exports; for
  every other feed, exports carry titles, links, dates and indicators, not the publisher's words.
- Curated connectors: CISA KEV, CISA security advisories (CISA's machine-readable CSAF files), SANS ISC and UK
  NCSC feeds. **Sync now** per source, **Sync all sources** at the top of the workspace, and **opt-in
  schedules** (off by default; every hour, 6 hours or day, per source or for all, from a time of day you choose,
  in UTC) so the feeds and the brief stay fresh by themselves. An unchanged feed is not downloaded again (`ETag` / `Last-Modified`). See
  [ADR 0018](docs/adr/0018-opt-in-scheduled-syncs.md).
- **Threat landscape** opens the workspace ([ADR 0020](docs/adr/0020-threat-landscape.md)): a plain-English
  executive summary of the last 7 or 30 days, compared with the 4 weeks or months before. Which kinds of threat
  are **rising**, **new** or **quieter** (ransomware, phishing, data theft, supply chain, zero-days and 8 more,
  spotted by listed words and ATT&CK techniques), what each one is, **why it matters** and **what to check**,
  what attackers are doing by ATT&CK tactic, and every report behind it. Counted from your reports, not written
  by AI; marked with the most restrictive TLP it used; **Download as a briefing to share** (Markdown).
  `GET /api/landscape`, `GET /api/landscape/briefing`.
- **Intel brief** below it: what the period adds up to, built from your reports (no AI). An
  **executive summary** in a few plain sentences (what came in, what attackers are using now and the US federal
  fix-by date, the most serious new weakness, what matches your watch terms, a first step), then *Exploited now*
  (CISA KEV), *Most severe* (CVSS 9 or higher), *Your watch terms*, *Seen in several sources* and
  *Most-mentioned vendors*. Every line opens its report, indicator or a search. "New" means published in the
  last 7 days, so a first sync of old history does not flood it; the demo is left out. Also `GET /api/brief`.
- On-demand NVD and FIRST EPSS CVE lookups; no API key required for this small-scale prototype. Provider throttling/outages still apply.
- JSON report exports retain provenance and TLP; they are **not STIX** and do not authorize redistribution.
- **IOC export**: one JSON file listing every indicator across your reports once, with its source reports, evidence, KEV context and the most restrictive TLP of the reports it includes. Filter by type, review status, highest TLP or report; defang for e-mail and tickets, and leave evidence out when sharing. **Export IOCs** in the workspace (with a live count preview), **Export this report's IOCs** in the reader, `insight export-iocs FILE` or `GET /api/iocs/export`. Not STIX and not a blocklist by itself: see [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md).
- **HTTP API with an API key for scripts and SIEMs**: one key, created, rotated and revoked only on the host (`make api-key-create` / `insight api-key`), sent as `Authorization: Bearer`. Read-only unless you choose read-write; mandatory expiry; stored as a hash only; optionally limited to a TLP label (`MAX_TLP=GREEN`: more restrictive reports are invisible to it). Per-caller rate limits with `RateLimit` headers and `429` + `Retry-After`. Guide with every `curl` command: [docs/API_GUIDE.md](docs/API_GUIDE.md); field reference: [docs/API.md](docs/API.md).
- **TLP:RED is refused by default** (`INSIGHT_MAX_TLP=AMBER+STRICT`), including reports whose text carries a RED marking, so material meant for named recipients does not end up on a server. Set `INSIGHT_MAX_TLP=RED` to allow it.
- **Optional sign-in MFA** (authenticator-app codes), off by default: `make mfa-enable` / `make mfa-disable`.
- **Public deployment** behind a TLS reverse proxy: trusted proxy headers (`INSIGHT_TRUSTED_PROXIES`), secure cookies and HSTS. See [docs/RUNBOOK.md](docs/RUNBOOK.md) ("Reverse proxy").
- The audit log records who acted: the operator, the API key (by key ID), the CLI or a connector.
- A `Makefile` for every routine task: `make help`.
- Clearly labeled synthetic demo data. All examples use reserved test infrastructure, not live malicious endpoints.
- Persistent SQLite database in a Docker volume, with automatic schema migrations. PostgreSQL 16 is supported and tested in CI (`INSIGHT_DATABASE_URL=postgresql+psycopg://…`, `pip install '.[postgres]'`).
- Publisher edits to synced items (e.g. a changed KEV description) become **revisions** of one report, not duplicates. The inbox shows the current revision; older ones stay available as evidence.

### What does “free sources” mean?

The starting connectors access publicly available intelligence without paid subscriptions. This is **open-source intelligence (OSINT)**, not a claim that every publisher grants an open-source content license. Feed imports retain title, source link and up to 500 characters of feed summary; they never crawl full articles. Review each publisher’s terms before retention or redistribution. The registry is intentionally small and explicit, not “every free feed on the internet.”

## Quick start: Docker Desktop

1. Unzip this project and open a terminal **inside the `insight` folder**.
2. Create `.env` with a strong workspace password and random signing secret. With `make` (Linux, macOS, WSL):
   `make env`. Otherwise, if Python 3 is installed (Windows: replace `python` with `py` if necessary):

```sh
python -c "import pathlib,secrets; p=pathlib.Path('.env'); p.open('x').write('INSIGHT_PASSWORD='+secrets.token_urlsafe(18)+'\nINSIGHT_SESSION_SECRET='+secrets.token_urlsafe(48)+'\n')"
```

This refuses to overwrite an existing `.env`. Alternatively, create `.env` manually using `.env.example` and choose a password of at least 12 characters plus a random secret of at least 32 characters. Keep the file private.

3. Run `make up`, or:

```sh
docker compose up --build -d
```

4. Open **http://localhost:8080**. Sign in with `INSIGHT_PASSWORD` from `.env`.
5. Click **Load demo**, inspect a report, review its extracted observations and follow an entity to related reports.
6. In **Sources**, run only the sources you want. These buttons make outbound internet requests. NVD/EPSS lookups explicitly send the selected CVE identifier to that provider; source documents are not sent.

The container runs as an unprivileged user with a read-only root filesystem and no Linux capabilities. The Docker port is bound to **127.0.0.1 only**. Never expose port 8080 itself to your LAN or the internet: to publish Insight, put it behind a TLS reverse proxy as described in [docs/RUNBOOK.md](docs/RUNBOOK.md) ("Reverse proxy") and read [docs/SECURITY.md](docs/SECURITY.md) first. It has one operator password (plus optional MFA). Sign-in sessions are stored in the database for 8 hours and survive a restart: a restart does **not** sign anyone out. To end sessions, use **Sign out everywhere** on the sign-out page, or change the password or MFA setting. Rate limits are in memory, so use one process/worker.

```sh
docker compose logs -f insight
docker compose stop
docker compose start
```

### Makefile

`make help` lists every target. Each wraps a command documented in the RUNBOOK or CONTRIBUTING, so those stay
the reference. Common ones:

| Task | Command |
| --- | --- |
| First run | `make env` (creates `.env`, never overwrites) · `make up` |
| Run | `make up` · `make stop` · `make restart` · `make down` · `make logs` · `make ps` · `make health` |
| Back up / restore | `make backup` (into `backups/`) · `make restore BACKUP=backups/backup-....db` (asks first) |
| Delete a report (legal or retention reasons) | `make delete-report ID=... REASON='ticket 42'` (asks first; back up first) |
| Tag ATT&CK techniques in reports stored before 0.7.0 | `make attack-backfill` (once after upgrading; safe to rerun) |
| Export IOCs | `make export-iocs EXPORT_ARGS="--max-tlp GREEN --review-status accepted --defang --no-evidence"` (into `exports/`) |
| API key | `make api-key-create NAME=siem [ACCESS=read-write] [MAX_TLP=GREEN]` · `make api-key-status` · `make api-key-rotate` · `make api-key-revoke` |
| Sign-in MFA (off by default) | `make mfa-enable` · `make mfa-disable` · `make mfa-status` · `make mfa-reset` |
| Default colour theme (System) | `make theme THEME=system\|light\|dark` · or while building: `make up THEME=dark` |
| Check an instance | `make smoke` · `make version` |
| Develop | `make dev` · `make test` · `make test-fast` · `make format` · `make check` · `make ci` |

`backups/` and `exports/` hold copies of your intelligence: they are created owner-only, ignored by git and
Docker, and `scripts/check_forbidden_files.py` refuses to commit them.

Data survives container rebuilds in `insight_insight-data` (the exact Compose prefix follows your directory name). `docker compose down` preserves it; **`docker compose down -v` deletes it**.

## Upgrading

**Back up first** (see below). Then rebuild and start as usual (`docker compose up --build -d`). Insight applies database migrations automatically at start-up; `insight migrate` does the same explicitly and prints the before/after revision. Databases from 0.1.0 are recognised and upgraded in place. Reports that 0.1.0 duplicated because a publisher edited an item are linked as revisions, and nothing is deleted. Since 0.6.0 sessions are stored in the database, so a restart keeps you signed in. After upgrading to 0.7.0, run `make attack-backfill` once to tag ATT&CK techniques in older reports.

## Local Python development

Python 3.11, 3.12, 3.13 and 3.14 are tested (CI runs the full suite on each). The Docker image uses 3.13.

```sh
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell instead:
# .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-dev.lock
pip install --no-deps -e .
insight init       # creates .env if absent; refuses to overwrite an existing one
insight serve
```

Open http://127.0.0.1:8080. Default local data lives in `./data/insight.db`. Use `INSIGHT_DATA_DIR` (or `INSIGHT_DATABASE_URL`) to change it. The CLI loads `.env` from the current directory; variables already set in the environment take precedence.

| Command | Purpose |
| --- | --- |
| `insight init` | Create `.env` with generated credentials (never overwrites) |
| `insight serve` | Run the workspace (migrates the database first) |
| `insight migrate` | Apply database migrations explicitly |
| `insight backup FILE` | Consistent online SQLite backup, safe while running (never overwrites) |
| `insight export-iocs FILE` | Write a JSON IOC export (never overwrites; owner-only file). Options and recipes: [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md#2-quick-start) |
| `insight attack-backfill` | Tag ATT&CK technique IDs in reports stored before 0.7.0 (safe to rerun) |
| `insight mfa setup` | Pair an authenticator app for sign-in codes (shows a secret, then confirms one code). Also `status`, `reset`. MFA itself is **off by default** and switched with `INSIGHT_MFA=on`; with Docker, `make mfa-enable` / `make mfa-disable` do both steps |
| `insight api-key create --name NAME` | Create the API key for scripts/SIEM (read-only unless `--access read-write`; `--max-tlp GREEN` hides more restrictive reports from it; shown once). Also `status`, `rotate`, `revoke`. See [docs/API.md](docs/API.md#api-key-scripts-and-siem) |
| `insight --version` | Print the version |

Install the git hooks once: `pre-commit install --hook-type pre-commit --hook-type pre-push`.

### Quality checks

```sh
pytest                                # full offline suite (~630 tests, about two minutes)
pytest --cov                          # with branch coverage (CI requires 90%)
pytest tests/unit -q                  # fast inner loop
pytest -m "not ui and not slow"       # skip NiceGUI simulation and subprocess tests
INSIGHT_TEST_DATABASE_URL=postgresql+psycopg://postgres@localhost/postgres pytest   # against PostgreSQL
ruff check src tests scripts && ruff format --check src tests scripts
mypy                                  # strict, over src/, tests/ and scripts/
pre-commit run --all-files            # everything CI's quality job runs
```

Browser tests (Playwright) against a running instance:

```sh
pip install --require-hashes -r requirements-e2e.lock && python -m playwright install chromium
INSIGHT_E2E_URL=http://127.0.0.1:8080 INSIGHT_E2E_PASSWORD=... pytest tests/e2e -m e2e
```

Start that instance with `INSIGHT_MAX_TLP=RED`: one browser test ingests the synthetic TLP:RED report.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, [docs/TESTING.md](docs/TESTING.md) for the test-suite design, [docs/CI_CD.md](docs/CI_CD.md) for the pipeline and [docs/RELEASING.md](docs/RELEASING.md) for the release procedure. Scripting against Insight: [docs/API.md](docs/API.md).

### Dependencies

`pyproject.toml` declares ranges; four lock files pin exact, hash-verified versions:

| Lock | Contents | Used by |
| --- | --- | --- |
| `requirements.lock` | runtime | Docker image, releases |
| `requirements-dev.lock` | runtime + test, lint, type-check and CI tooling | development, CI |
| `requirements-e2e.lock` | dev + Playwright | browser tests |
| `requirements-build.lock` | build backend (setuptools) | wheel and image builds |

After changing dependencies in `pyproject.toml`, run `python scripts/lock.py` (requires [uv](https://docs.astral.sh/uv/)). CI fails if the locks and `pyproject.toml` disagree.

## Daily workflow

1. **Collect:** paste authorized text or explicitly sync a curated feed.
2. **Read:** search/filter the inbox and read evidence in context.
3. **Review:** accepting a mention means the extraction is useful/accurate, **not that the entity is malicious**.
4. **Correlate:** pivot to other documents that mention the same canonical entity.
5. **Prioritize:** watch terms identify possible organizational relevance; CISA KEV signals observed exploitation, NVD supplies vulnerability metadata, and EPSS estimates exploitation probability. None proves that your assets are exposed.
6. **Record:** write an analyst note explaining your judgment.
7. **Share:** export the indicators you reviewed (**Export IOCs**), filtered to the TLP you may share at. Check the file's label and evidence before it leaves your hands ([docs/IOC_EXPORT.md](docs/IOC_EXPORT.md)).

The data model separates documents, entities, observations, notes and external enrichments. It intentionally does not invent threat-actor attribution or causal relationships from co-occurrence.

## Handling sensitive intelligence

TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED are preserved as metadata. **This single-user release does not enforce organizational sharing groups or recipient-level TLP access.** Only import material you personally may access and retain. Local JSON exports preserve the label but cannot prevent later disclosure. An IOC export is labelled with the most restrictive TLP of the reports it includes; use `max_tlp` (or **Most restrictive TLP to include**) to keep restricted reports out of a file you intend to share. No external AI provider is called.

No automatically fetched article HTML is rendered. Source text is displayed as text; links are HTTP(S) only. Curated connector destinations are fixed and checked for public DNS resolution, redirects are disabled, and payload sizes are bounded. An egress firewall is still advisable: application DNS checks are not a complete DNS-rebinding defense.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Backup and restore

Take a consistent backup **while Insight is running**:

```sh
docker compose exec insight insight backup /data/backup-$(date +%Y%m%d).db
docker compose cp insight:/data/backup-$(date +%Y%m%d).db ./
```

`insight backup` uses SQLite's online backup API, runs an integrity check and never overwrites an existing file. (For PostgreSQL use `pg_dump`.) Protect backups like the source data. To restore, stop the app and copy the backup into the volume as `/data/insight.db`, preserving UID 10001 write access. Every milestone gate runs an automated backup-and-restore drill. Never commit `.env` or databases to Git; a pre-commit hook and CI enforce this.

## Scope and known limits

- No team accounts, SSO, RBAC or recipient-level dissemination rules. MFA is an optional single-operator authenticator-app code, off by default (`make mfa-enable`). One API key at a time.
- Rate limits live in server memory: one worker, and a restart resets them. Sessions are stored in the database and survive restarts. The API is unversioned (breaking changes are listed in the CHANGELOG's upgrade notes).
- No full-text relevance ranking engine, alert delivery, case management or graph visualization yet. Source syncs can run on opt-in schedules (off by default).
- No PDF/binary parsing, arbitrary URL fetching, arbitrary feed entry, STIX/TAXII/MISP synchronization or automatic full-article storage.
- No actor/malware attribution, ML or LLM inference. Extraction is deterministic and can still miss or mis-read unusual formats (see the known gaps in [docs/EXTRACTION.md](docs/EXTRACTION.md); the labelled benchmark `python scripts/benchmark_extraction.py` measures quality). Manual review is essential. URL extraction trims sentence punctuation and unbalanced closing brackets, so verify against the source evidence.
- Matching is literal; watch terms are not an asset inventory. Source-language dates are not authoritative ingestion dates.
- The inbox shows up to 200 rows; entity pivots load 25 documents at a time. The API paginates documents and entity pivots. Suitable for a pilot, not large-scale intelligence ingestion.
- KEV updates store all supplied records but add inbox documents for only the latest 100 entries. Old KEV rows are retained with import timestamps, not silently deleted; absence from a later import is not evidence of current KEV membership.
- Source failures are visible and non-destructive. Some sites may block automated requests. No success is fabricated when a provider rejects or changes its endpoint.
- Schema changes ship as Alembic migrations that are tested for reversibility and against databases written by every previous release. Timestamps are ISO-8601 UTC strings; see `docs/ARCHITECTURE.md`.
- Audit events are application records, not tamper-proof logs. Local administrators can modify the database.

Planned work is listed in [ROADMAP.md](ROADMAP.md).

## Extending it

Add adapters in `connectors.py` only after reviewing their destinations, size limits and source terms. Keep deterministic evidence and analyst review independent of enrichment. `docs/LLM_EXTENSION.md` defines the future LLM integration boundary without enabling it now.

## License

Insight is released under the [MIT License](LICENSE). Copyright (c) 2026 Andrew Scott and the Insight contributors.
Third-party data and dependencies keep their own licences; see [NOTICE](NOTICE). The MIT License covers this
software, not the intelligence you store in it: source reports keep their publishers' terms and TLP labels.
