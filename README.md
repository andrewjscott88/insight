# Insight

A local, single-operator threat-intelligence workbench. Application logic and the interactive GUI are authored in **Python**, using **NiceGUI + FastAPI + SQLAlchemy**. NiceGUI supplies the underlying browser assets; no separate React/Node build is required.

**Version 0.2.0: a single-operator pilot release, not a production multi-user TIP.** Nothing is deployed or connected automatically. Operating it: [docs/RUNBOOK.md](docs/RUNBOOK.md). All documentation: [docs/README.md](docs/README.md).

## What works

- Password-protected analyst inbox with split-pane report reader, search and TLP/status filters. Search ignores case, accents and Unicode normal form identically on SQLite and PostgreSQL.
- Paste reports with title, source, URL and handling label; preserve original text and its SHA-256 hash.
- Deterministic extraction of CVEs, IPv4/IPv6, URLs, domains and MD5/SHA1/SHA256/SHA512 mentions, including defanged (`hxxp`, `[.]`) and international (punycode) forms. It is precision-first: about 98% precision and recall on the labelled corpus ([docs/EXTRACTION.md](docs/EXTRACTION.md)).
- TLP defaults to AMBER, and a `TLP:` marking inside a report can only raise its label, never lower it.
- Exact character offsets and contextual evidence, canonical entities and cross-report pivots.
- Accept/reject/reset observations, triage reports and add analyst notes with audit events.
- Organization watch terms highlight literal product, vendor or topic matches. These are transparent keyword matches, not calibrated risk scores.
- Explicit, on-demand connectors: CISA KEV, CISA advisories, SANS ISC and UK NCSC feeds.
- On-demand NVD and FIRST EPSS CVE lookups; no API key required for this small-scale prototype. Provider throttling/outages still apply.
- JSON report exports retain provenance and TLP; they are **not STIX** and do not authorize redistribution.
- **IOC export**: one JSON file listing every indicator across your reports once, with its source reports, evidence, KEV context and the most restrictive TLP of the reports it includes. Filter by type, review status, highest TLP or report; defang for e-mail and tickets, and leave evidence out when sharing. **Export IOCs** in the workspace (with a live count preview), **Export this report's IOCs** in the reader, `insight export-iocs FILE` or `GET /api/iocs/export`. Not STIX and not a blocklist by itself: see [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md).
- Clearly labeled synthetic demo data. All examples use reserved test infrastructure, not live malicious endpoints.
- Persistent SQLite database in a Docker volume, with automatic schema migrations. PostgreSQL 16 is supported and tested in CI (`INSIGHT_DATABASE_URL=postgresql+psycopg://…`, `pip install '.[postgres]'`).
- Publisher edits to synced items (e.g. a changed KEV description) become **revisions** of one report, not duplicates. The inbox shows the current revision; older ones stay available as evidence.

### What does “free sources” mean?

The starting connectors access publicly available intelligence without paid subscriptions. This is **open-source intelligence (OSINT)**, not a claim that every publisher grants an open-source content license. Feed imports retain title, source link and up to 500 characters of feed summary; they never crawl full articles. Review each publisher’s terms before retention or redistribution. The registry is intentionally small and explicit, not “every free feed on the internet.”

## Quick start: Docker Desktop

1. Unzip this project and open a terminal **inside the `insight` folder**.
2. Create `.env` with a strong workspace password and random signing secret.

If Python 3 is installed (Windows: replace `python` with `py` if necessary):

```sh
python -c "import pathlib,secrets; p=pathlib.Path('.env'); p.open('x').write('INSIGHT_PASSWORD='+secrets.token_urlsafe(18)+'\nINSIGHT_SESSION_SECRET='+secrets.token_urlsafe(48)+'\n')"
```

This refuses to overwrite an existing `.env`. Alternatively, create `.env` manually using `.env.example` and choose a password of at least 12 characters plus a random secret of at least 32 characters. Keep the file private.

3. Run:

```sh
docker compose up --build -d
```

4. Open **http://localhost:8080**. Sign in with `INSIGHT_PASSWORD` from `.env`.
5. Click **Load demo**, inspect a report, review its extracted observations and follow an entity to related reports.
6. In **Sources**, run only the sources you want. These buttons make outbound internet requests. NVD/EPSS lookups explicitly send the selected CVE identifier to that provider; source documents are not sent.

The container runs as an unprivileged user with a read-only root filesystem and no Linux capabilities. The Docker port is bound to **127.0.0.1 only**. Do not expose this prototype directly to your LAN or the internet. It uses local HTTP, one shared operator password and in-memory session revocation. Restarting signs everyone out. Use one process/worker.

```sh
docker compose logs -f insight
docker compose stop
docker compose start
```

Data survives container rebuilds in `insight_insight-data` (the exact Compose prefix follows your directory name). `docker compose down` preserves it; **`docker compose down -v` deletes it**.

## Upgrading

**Back up first** (see below). Then rebuild and start as usual (`docker compose up --build -d`). Insight applies database migrations automatically at start-up; `insight migrate` does the same explicitly and prints the before/after revision. Databases from 0.1.0 are recognised and upgraded in place. Reports that 0.1.0 duplicated because a publisher edited an item are linked as revisions, and nothing is deleted. Existing browser sessions do not survive a restart.

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

- No team accounts, SSO, RBAC, MFA or recipient-level dissemination rules.
- No full-text relevance ranking engine, automated scheduling, alert delivery, case management or graph visualization yet.
- No PDF/binary parsing, arbitrary URL fetching, arbitrary feed entry, STIX/TAXII/MISP synchronization or automatic full-article storage.
- No actor/malware attribution, ML or LLM inference. Extraction is deterministic and can still miss or mis-read unusual formats (see the known gaps in [docs/EXTRACTION.md](docs/EXTRACTION.md); the labelled benchmark `python scripts/benchmark_extraction.py` measures quality). Manual review is essential. URL extraction trims sentence punctuation and unbalanced closing brackets, so verify against the source evidence.
- Matching is literal; watch terms are not an asset inventory. Source-language dates are not authoritative ingestion dates.
- The inbox shows up to 200 rows; entity pivots load 25 documents at a time. The API paginates documents and entity pivots. Suitable for a pilot, not large-scale intelligence ingestion.
- KEV updates store all supplied records but add inbox documents for only the latest 100 entries. Old KEV rows are retained with import timestamps, not silently deleted; absence from a later import is not evidence of current KEV membership.
- Source failures are visible and non-destructive. Some sites may block automated requests. No success is fabricated when a provider rejects or changes its endpoint.
- Schema changes ship as Alembic migrations that are tested for reversibility and against databases written by every previous release. Timestamps are ISO-8601 UTC strings; see `docs/ARCHITECTURE.md`.
- Audit events are application records, not tamper-proof logs. Local administrators can modify the database.
- This repository does not assign a distribution license on your behalf; choose one before publishing.

## Extending it

Add adapters in `connectors.py` only after reviewing their destinations, size limits and source terms. Keep deterministic evidence and analyst review independent of enrichment. `docs/LLM_EXTENSION.md` defines the future LLM integration boundary without enabling it now.
