# Insight operations runbook

For whoever installs, runs, upgrades, backs up or troubleshoots Insight. Commands assume the Docker Compose
deployment from the README, run from the directory that contains `compose.yaml`. Local-Python equivalents are
given where they differ.

> Insight is a **single-operator, loopback-only** workbench. Do not expose it to a network without the
> hardening listed in [SECURITY.md](SECURITY.md) ("Before internet/shared use").

## Quick reference

| Task | Command |
| --- | --- |
| Start / stop / restart | `docker compose up -d` · `docker compose stop` · `docker compose restart` |
| Status and health | `docker compose ps` · `curl -fsS http://127.0.0.1:8080/health` |
| Follow logs | `docker compose logs -f insight` |
| Backup (online, safe while running) | `docker compose exec insight insight backup /data/backup-$(date +%F).db` |
| Copy a backup off the volume | `docker compose cp insight:/data/backup-YYYY-MM-DD.db ./` |
| Export IOCs (e.g. shareable at GREEN) | `docker compose exec insight insight export-iocs /data/iocs-$(date +%F).json --max-tlp GREEN --review-status accepted --defang --no-evidence` |
| Copy an export off the volume, then remove it | `docker compose cp insight:/data/iocs-YYYY-MM-DD.json ./` · `docker compose exec insight rm /data/iocs-YYYY-MM-DD.json` |
| Apply migrations explicitly | `docker compose exec insight insight migrate` |
| Smoke-test a running instance | `python scripts/smoke.py http://127.0.0.1:8080 --password "$INSIGHT_PASSWORD"` |
| Version | `docker compose exec insight insight --version` · `curl -s http://127.0.0.1:8080/health` |

## 1. System overview

```
Browser ──HTTP (127.0.0.1:8080)──► uvicorn (1 worker)
                                    ├─ FastAPI: /login, /logout, /api/*, /health, /static
                                    └─ NiceGUI workspace (/) over a WebSocket
                                         │
                                  services.py (only SQL layer) ──► SQLite /data/insight.db
                                         │                          (or PostgreSQL)
                                  connectors.py ──HTTPS (on demand only)──► CISA, SANS ISC, UK NCSC, FIRST, NVD
```

| Item | Location / value |
| --- | --- |
| Container user | UID/GID 10001; root filesystem read-only; writable: `/data` (volume), `/tmp` (tmpfs) |
| Database | `/data/insight.db` (SQLite) or `INSIGHT_DATABASE_URL` |
| NiceGUI storage | `/data/.nicegui` |
| Volume | `<project>_insight-data` (`docker volume ls`) |
| Port | `127.0.0.1:8080` only |
| Sessions | In memory: a restart signs everyone out. Run exactly **one** worker. |
| Outbound network | Only when an operator presses **Sync now** or approves a CVE lookup |

## 2. Configuration

Set in `.env` (Compose reads it) or the process environment. Real environment variables override `.env`.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `INSIGHT_PASSWORD` | yes | - | At least 12 characters. `insight init` generates one. |
| `INSIGHT_SESSION_SECRET` | yes | - | At least 32 random characters. Changing it invalidates every session cookie. |
| `INSIGHT_DATA_DIR` | no | `data` (`/data` in the image) | SQLite file and NiceGUI storage location |
| `INSIGHT_DATABASE_URL` | no | `sqlite:///<data dir>/insight.db` | e.g. `postgresql+psycopg://user:pass@host/insight` |
| `INSIGHT_ALLOWED_HOSTS` | no | `localhost,127.0.0.1` | Host headers accepted. Anything else gets HTTP 400. |
| `INSIGHT_SECURE_COOKIES` | no | `0` | Set `1` only behind HTTPS |
| `NICEGUI_STORAGE_PATH` | no | `/data/.nicegui` in the image | Must be writable |

Never commit `.env`: a pre-commit hook and CI block it. Treat the file like the password it contains.

## 3. First start

1. `insight init` (or the one-liner in the README) creates `.env` with mode 0600. It refuses to overwrite an
   existing file.
2. `docker compose up --build -d`, then wait for `docker compose ps` to show `healthy` (within 30 s).
3. Open http://localhost:8080 and sign in with `INSIGHT_PASSWORD`.
4. Optional: **Load demo** to confirm the workspace renders. The demo is idempotent and uses only
   documentation addresses.

Local Python: `pip install --require-hashes -r requirements.lock && pip install --no-deps .`, then
`insight init`, then `insight serve`.

## 4. Routine operations

### Daily
- Confirm the container is `healthy`.
- Review **Sources → Recent sync activity** for `error` runs (see §8).
- Scan logs for `Failed sign-in attempt` and `Sign-in refused` (see §11).

### Weekly
- Take a backup and copy it off the host (§5).
- Check volume usage: `docker system df -v | grep insight-data`.
- If you track releases, compare `insight --version` with the latest GitHub Release (§6).

### Rotating credentials
Rotate at least every 90 days, when anyone who knew them leaves, and **immediately** if they may have leaked.
1. Generate new values: `python -c "import secrets; print(secrets.token_urlsafe(18)); print(secrets.token_urlsafe(48))"`.
2. Replace `INSIGHT_PASSWORD` and `INSIGHT_SESSION_SECRET` in `.env`.
3. `docker compose up -d` (recreates the container with the new environment).

Everyone is signed out, and cookies issued with the old secret stop working.

### Sign-in throttling (expected behaviour)
Each failed sign-in waits about 1 s, and sign-ins are checked one at a time. More than 30 failures in one
minute returns HTTP 429 for the rest of that minute. A legitimate operator can always sign in again after the
window; there is no lockout.

## 5. Backup and restore

### Back up (online, no downtime)
```sh
docker compose exec insight insight backup /data/backup-$(date +%F).db     # refuses to overwrite
docker compose cp insight:/data/backup-$(date +%F).db ./backups/
docker compose exec insight rm /data/backup-$(date +%F).db                  # optional: free volume space
```
`insight backup` uses SQLite's online backup API and runs `PRAGMA integrity_check` on the copy. It prints
`integrity ok` on success. Store backups with the same protection as the data (they contain TLP:RED material
if you do). For PostgreSQL, use `pg_dump --format=custom` instead.

Host cron example (daily at 02:30, keep 14):
```cron
30 2 * * * cd /opt/insight && docker compose exec -T insight insight backup /data/b-$(date +\%F).db && docker compose cp insight:/data/b-$(date +\%F).db /srv/backups/ && docker compose exec -T insight rm /data/b-$(date +\%F).db && find /srv/backups -name 'b-*.db' -mtime +14 -delete
```

### Restore
1. `docker compose stop`
2. Copy the backup into the volume as the live database, preserving ownership:
   ```sh
   docker compose run --rm --no-deps -v "$PWD/backups:/restore:ro" --entrypoint sh insight \
     -c 'cp /restore/backup-YYYY-MM-DD.db /data/insight.db'
   ```
3. `docker compose up -d`. Migrations run automatically if the backup is from an older version.
4. Sign in, and check **Source documents** and a known report.

Every milestone gate runs an automated backup and restore drill (`scripts/backup_restore_drill.py`). Run it
yourself after changing the backup procedure.

## 6. Upgrades

### Before
1. Read the new version's section of `CHANGELOG.md`, especially **Upgrade notes**.
2. Take a backup (§5) and copy it off the host.
3. Verify the published image's signature (releases are signed with cosign, keyless):
   ```sh
   cosign verify ghcr.io/<org>/insight@sha256:<digest> \
     --certificate-identity-regexp '^https://github.com/<org>/insight/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

### Upgrade
- From source: `git pull && docker compose up --build -d`.
- From a published image: set `image: ghcr.io/<org>/insight@sha256:<digest>` in `compose.yaml`, then
  `docker compose up -d`.

Migrations run at start-up. `docker compose logs insight` shows, for example:

```
WARNING  insight.migrations: Unversioned (0.1.0) database detected: stamping it at baseline 0001
WARNING  insight.migrations: Database schema upgraded 0001 -> 0003
INFO:     Application startup complete.
```

An up-to-date database logs `Database schema at revision 0003 (up to date)`. `insight migrate` is idempotent
and prints the before and after revision.

### After
- `curl -s http://127.0.0.1:8080/health` shows the new version.
- `python scripts/smoke.py http://127.0.0.1:8080 --password … --no-demo` passes.

### Roll back
Prefer **restore, not downgrade**:
1. Stop the container.
2. Switch back to the previous image digest or git tag.
3. Restore the pre-upgrade backup (§5).

Alembic downgrades exist and are tested, but a restore is simpler and loses nothing that the backup held.

## 7. Migrations in detail

| Situation | What happens |
| --- | --- |
| Empty database | All revisions are applied from `0001` |
| 0.1.0 database (no `alembic_version` table) | Stamped at `0001` (identical to the 0.1.0 schema), then upgraded |
| Migrated database | Only newer revisions are applied |

On SQLite, migrations temporarily disable foreign keys (SQLite's documented procedure for table rebuilds) and
run `PRAGMA foreign_key_check` before committing. On any error the transaction rolls back and the application
does not start.

**If start-up fails during a migration:**
1. Read the traceback in `docker compose logs insight`.
2. Do not edit the database by hand. Restore the pre-upgrade backup and start the previous version.
3. Open an issue with the log; a release fixture for your version will reproduce it.

## 8. Sources, enrichment and their failures

Nothing syncs automatically. **Sync now** contacts exactly one publisher and records a run (success or error)
under *Recent sync activity*. Enrichment (EPSS/NVD) sends only the CVE identifier, after explicit consent, at
most once every 6.5 s.

| Message (run history / API 502) | Meaning | Action |
| --- | --- | --- |
| `HTTPStatusError: … 403/404` | Publisher blocked or moved the feed | Check the URL in a browser; update `SOURCES` in `connectors.py` and ship a release |
| `HTTPStatusError: … 429/503` | Rate-limited or down | Retry later |
| `ValueError: Redirects are disabled…` | Feed moved | Review the new location, then update the registry |
| `ValueError: Source resolves to a non-public destination` | DNS returned a private or loopback address | Possible DNS tampering: check resolvers; do not work around it |
| `ValueError: Source exceeds the 8 MB payload limit` | Feed grew | Confirm it is legitimate; raise `MAX_BYTES` in a release |
| `ValueError: Invalid CVE in KEV input` / `Invalid KEV record field` | KEV format changed | Nothing was imported (all-or-nothing). Report it; the nightly live tests should also flag it. |
| `OSError` / `ConnectError` | No network or DNS | Check host egress (an egress firewall is recommended) |
| Enrichment `429` | Less than 6.5 s since the last lookup | Wait |
| Enrichment `502 … non-JSON` | Provider outage or HTML error page | Retry later |

Feed items keep at most 500 characters of summary. Such items show **Truncated by the connector**, because the
full report may contain more indicators. Open the original source and paste it if you are permitted to.

Publisher edits become **revisions**: the inbox shows the current one, and **Include superseded revisions**
shows history.

## 9. Data handling

**TLP policy** (enforced in the service layer for the UI, the API and connectors):
- The default label is AMBER.
- A `TLP:` marking in the title or body **raises** the label to the most restrictive marking. It is never
  lowered.
- Raises are audited (`document.tlp_raised`), the UI warns, and the API returns `tlp_raised_from`.
- Public feeds are CLEAR.
- Labels are metadata: there is no recipient-level enforcement (single user).

**Exports** keep provenance and TLP. They are not permission to share.
- A **report export** (`/api/documents/{id}/export`) contains one report with all its observations.
- An **IOC export** (**Export IOCs**, `insight export-iocs`, `/api/iocs/export`) lists indicators across reports.
  The file is labelled with the most restrictive TLP of the reports it includes. Filter with `max_tlp` when
  exporting for a given audience, rather than editing the file afterwards. Evidence excerpts are raw report text
  and can carry victim details an analyst rejected, so leave them out when sharing (`--no-evidence`, or untick
  **Include evidence excerpts**). See [IOC_EXPORT.md](IOC_EXPORT.md).
- Every export is audited (`document.export`, `ioc.export`). The `ioc.export` event's `object_id` equals the
  `export_id` inside the file, so a file found later can be traced to when and how it was produced.
- CLI exports are written owner-only (`0600`). Browser and API downloads follow your normal file permissions.
  Exports written into the Docker volume stay there until you remove them, so copy them out and delete them.

**Deleting a document** (legal or retention obligations). There is no delete function yet, so use this tested
procedure. It preserves the revision chain and audits the deletion.

1. Stop Insight and **take a backup** (§5).
2. Find the document ID (shown in the export file name, or `GET /api/documents?q=…`).
3. Run this in the data volume. Replace `DOC_ID` and the reason; `python -m sqlite3` ships with the image.
   ```sh
   docker compose run --rm --no-deps --entrypoint python insight -m sqlite3 /data/insight.db
   ```
   ```sql
   PRAGMA foreign_keys = ON;
   BEGIN IMMEDIATE;
   CREATE TEMP TABLE target AS SELECT id, supersedes_id, is_current FROM documents WHERE id = 'DOC_ID';
   UPDATE documents SET supersedes_id = (SELECT supersedes_id FROM target) WHERE supersedes_id = 'DOC_ID';
   DELETE FROM observations WHERE document_id = 'DOC_ID';
   DELETE FROM notes WHERE document_id = 'DOC_ID';
   DELETE FROM documents WHERE id = 'DOC_ID';
   UPDATE documents SET is_current = 1 WHERE id = (SELECT supersedes_id FROM target WHERE is_current = 1);
   DELETE FROM entities WHERE id NOT IN (SELECT DISTINCT entity_id FROM observations);
   INSERT INTO audit_events (id, action, object_id, detail, created_at)
   VALUES (lower(hex(randomblob(16))), 'document.delete', 'DOC_ID', 'manual deletion: <reason / ticket>',
           strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now'));
   DROP TABLE target;
   COMMIT;
   PRAGMA foreign_key_check;
   PRAGMA integrity_check;
   ```
4. Start Insight. Backups taken before the deletion still contain the document, so apply your retention policy
   to them too.

The order matters: the predecessor is re-activated only after the target is gone, because of the "one
current revision per item" index. This procedure was tested for current, superseded and manual documents.

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Browser shows `Forbidden` on sign-in | Request `Origin` does not match `Host` (reverse proxy, different host name) | Use http://localhost:8080 or http://127.0.0.1:8080 exactly. Behind a proxy, keep the `Host` header and terminate TLS consistently. |
| `Invalid host header` (400) | Host not in `INSIGHT_ALLOWED_HOSTS` | Add it, and understand the exposure first |
| `Too many login attempts` (429) | More than 30 failed sign-ins in a minute | Wait 60 s. Check logs for unknown sources (§11). |
| Signed out unexpectedly | Restart, 8-hour session expiry, sign-out in another tab, or rotated secret | Sign in again (expected) |
| Container `unhealthy` | Start-up failure (often a migration, or bad credentials) | `docker compose logs insight`. A `RuntimeError: Set INSIGHT_PASSWORD…` means `.env` is missing or values are too short. |
| `Read-only file system` in logs | Something writes outside `/data` or `/tmp` | Check `NICEGUI_STORAGE_PATH` and `INSIGHT_DATA_DIR` point into `/data` |
| `database is locked` | Another process holds a write lock (manual `sqlite3` session, backup script) | Close it. Insight waits 5 s (`busy_timeout`). |
| Search misses a report | Search is a literal substring of title, source and body (folded for case, accents and width) | Use a shorter distinctive substring. Superseded revisions need **Include superseded revisions**. |
| TLP changed after ingest | The text contains a more restrictive `TLP:` marking | Expected (§9). See the `document.tlp_raised` audit event. |
| An indicator is wrong or missing | Extraction limits (see docs/EXTRACTION.md) | Review the evidence. Add the case to `tests/corpus/` and run `scripts/benchmark_extraction.py`. |
| Workspace slow with many reports | Inbox shows up to 200 reports; entity pivots load lazily | Filter by status or TLP. Report sizes and counts in an issue. |
| Sync button greyed out | Another sync is running (one at a time) | Wait |
| IOC export: `More than 100,000 indicator mentions match` | The per-export cap | Export in parts (by type, TLP or search). See [IOC_EXPORT.md](IOC_EXPORT.md#9-limits-and-troubleshooting) |
| IOC export in Docker: `cannot create …: Read-only file system` | The file was written outside `/data` | Write to `/data/...`, then `docker compose cp` |
| IOC export: `max_tlp` rejected although it says `AMBER+STRICT` | `+` in a URL means a space | Use `AMBER%2BSTRICT`, or let the client encode parameters |
| IOC export: `The database schema is not current` | CLI run against a database from an older release | Back up, then `insight migrate` |
| IOC export is empty (`Nothing matched the filters`, `tlp: AMBER`) or misses an indicator | Filters exclude it: rejected mentions and superseded revisions are left out by default, as are reports above `max_tlp` | Loosen the filters; check the mention's review state. The workspace preview shows the count before downloading |

Logs go to stdout/stderr (`docker compose logs`). Insight's own records have the form
`2026-11-13 00:39:58,372 INFO     insight.auth: Operator signed in`. The loggers are:
- `insight.auth`: sign-ins, failures and refusals, never passwords;
- `insight.migrations`: schema changes at start-up.

Uvicorn logs every request line.

## 11. Monitoring and alerting

| Signal | How | Alert when |
| --- | --- | --- |
| Liveness | Docker `HEALTHCHECK` → `/health` every 30 s | Not `healthy` for more than 2 minutes |
| Brute-force attempts | Log lines `Failed sign-in attempt` / `Sign-in refused` | More than 10 in 10 minutes |
| Source health | Run history / `GET /api/sources` (`runs[0].status`) | Same source `error` 3 times in a row |
| Disk | Volume usage | Above 80% |
| Upstream changes | Nightly pipeline issue "Nightly pipeline failure" | Any new comment |
| Vulnerabilities | CI `pip-audit`, Trivy, nightly image re-scan | Any HIGH/CRITICAL |

## 12. Security incidents

| Incident | Immediate actions |
| --- | --- |
| Password or secret may be exposed | Rotate both (§4), then review logs for sign-ins you did not make. `.env` is plaintext: check who can read it. |
| Unknown sign-ins or brute force | Confirm the port is bound to 127.0.0.1 (`docker compose port insight 8080`); rotate credentials; find the local process responsible |
| Secret committed to git | Rotate it, then purge the history (`git filter-repo`). gitleaks in CI should have flagged it. |
| Vulnerable dependency (CI, Trivy, Dependabot) | Wait for (or trigger) `lock-refresh`, then release through the normal gates. Do not hot-patch the container. |
| Host compromise | Assume all stored intelligence and credentials are exposed: notify per your TLP obligations; rebuild the host; restore a known-good backup; rotate everything |
| Malicious content in a report | Reports are stored and rendered as text only (tested against embedded `<script>`). No action needed beyond normal review. |

Report suspected vulnerabilities in Insight itself as described in [SECURITY.md](../SECURITY.md).

## 13. Releases (the "CD" part)

Insight is published, not deployed: signed images in GHCR plus GitHub Releases. Procedure:
[RELEASING.md](RELEASING.md). Pipeline: [CI_CD.md](CI_CD.md). In production, pin the image **by digest** and
verify the signature (§6).

## 14. Known limitations (0.2.0)

- Single operator; no SSO, RBAC or recipient-level TLP enforcement; in-memory sessions (one worker).
- No delete function (use §9); audit events are not tamper-proof.
- Extraction is deterministic regex plus validation (about 98% precision and recall on the labelled corpus).
  Known gaps:
  - a hash split evenly into two valid lengths stays two hashes;
  - e-mail addresses, CIDR ranges and ATT&CK technique IDs are not extracted;
  - IPv6 zone IDs are dropped.
  See [EXTRACTION.md](EXTRACTION.md).
- Documents ingested before 0.2.0 keep their `regex-v1` observations.
- Feed summaries are capped at 500 characters (flagged as truncated).
- IOC export:
  - at most 100,000 mentions per export (export in parts);
  - defanging leaves source URLs, IP-shaped version numbers and names without a real TLD as written;
  - evidence excerpts can contain context an analyst rejected unless evidence is left out;
  - an expired session shows `{"detail":"Sign in required"}` in the download tab.
  See [IOC_EXPORT.md](IOC_EXPORT.md).
- The application checks DNS answers but does not pin connections, so use an egress firewall against DNS
  rebinding.

## 15. Reference

| Document | Contents |
| --- | --- |
| [README](../README.md) | Quick start, daily workflow, commands |
| [ARCHITECTURE](ARCHITECTURE.md) | Design, data model, migrations, revisions |
| [API](API.md) | HTTP endpoints |
| [EXTRACTION](EXTRACTION.md) | Indicator extraction rules and limits |
| [SECURITY](SECURITY.md) | Security posture and hardening requirements |
| [TESTING](TESTING.md) · [CI_CD](CI_CD.md) · [RELEASING](RELEASING.md) | Quality gates and release process |
| [VALIDATION](VALIDATION.md) | What each release was validated against |
| [adr/](adr/) | Architecture decision records |
