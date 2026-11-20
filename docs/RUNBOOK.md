# Insight operations runbook

For whoever installs, runs, upgrades, backs up or troubleshoots Insight. Commands assume the Docker Compose
deployment from the README, run from the directory that contains `compose.yaml`. Local-Python equivalents are
given where they differ.

> Insight is a **single-operator** workbench, bound to loopback by default. To publish it, use a TLS reverse
> proxy ("Reverse proxy" in §2) and work through the checklist in [SECURITY.md](SECURITY.md) ("Publishing an
> instance"). Never expose port 8080 itself. `make help` lists a shortcut for most commands below.

## Quick reference

The Makefile wraps these (`make help`); the commands it runs are the ones in the right-hand column.

| Task | Make | Command |
| --- | --- | --- |
| Start / stop / restart | `make up` · `make stop` · `make restart` | `docker compose up -d` · `docker compose stop` · `docker compose restart` |
| Status and health | `make ps` · `make health` | `docker compose ps` · `curl -fsS http://127.0.0.1:8080/health` |
| Follow logs | `make logs` | `docker compose logs -f insight` |
| Backup (online, safe while running) and copy it off the volume | `make backup` (into `backups/`, owner-only) | `docker compose exec insight insight backup /data/backup-$(date +%F).db` · `docker compose cp insight:/data/backup-YYYY-MM-DD.db ./` |
| Restore | `make restore BACKUP=backups/…` (asks first) | §5 |
| Export IOCs (e.g. shareable at GREEN), copy it off the volume, remove it | `make export-iocs EXPORT_ARGS="--max-tlp GREEN --review-status accepted --defang --no-evidence"` | `docker compose exec insight insight export-iocs /data/iocs-$(date +%F).json …` · `docker compose cp insight:/data/iocs-YYYY-MM-DD.json ./` · `docker compose exec insight rm /data/iocs-YYYY-MM-DD.json` |
| Apply migrations explicitly | `make migrate` | `docker compose exec insight insight migrate` |
| Smoke-test a running instance | `make smoke` (password from `.env`, no demo data) | `python scripts/smoke.py http://127.0.0.1:8080 --password "$INSIGHT_PASSWORD"` |
| Version | `make version` · `make health` | `docker compose exec insight insight --version` · `curl -s http://127.0.0.1:8080/health` |
| API key | `make api-key-create NAME=siem` · `make api-key-status` · `-rotate` · `-revoke` | `docker compose exec insight insight api-key …` |
| Sign-in MFA (off by default) | `make mfa-enable` · `make mfa-disable` · `make mfa-status` · `make mfa-reset` | §4, "Sign-in second factor" |
| Default colour theme (System by default) | `make theme THEME=dark` · `make up THEME=light` | Set `INSIGHT_THEME` in `.env`, then `docker compose up -d` (§4, "Colour theme") |

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
| `INSIGHT_TRUSTED_PROXIES` | no | none | Reverse proxy address(es), IPs or CIDRs (`172.18.0.1`, `10.0.0.0/24`). See "Reverse proxy" below. `*` and malformed entries stop start-up. |
| `INSIGHT_MFA` | no | `off` | `on` requires an authenticator-app code at sign-in (`make mfa-enable` pairs the app and sets it). Anything other than on/off stops start-up. |
| `INSIGHT_MAX_TLP` | no | `AMBER+STRICT` | Most restrictive label stored. Reports at or raised to a higher label (i.e. TLP:RED) are refused on upload. `RED` allows everything. |
| `INSIGHT_THEME` | no | `system` | Colour theme for browsers that have not picked one: `system` (follow each device's light/dark setting), `light` or `dark`. Each browser can override it with the Light/Dark/System buttons in the workspace header (`make theme THEME=dark` sets it). Anything else stops start-up. |
| `NICEGUI_STORAGE_PATH` | no | `/data/.nicegui` in the image | Must be writable |

Never commit `.env`: a pre-commit hook and CI block it. Treat the file like the password it contains.

Invalid values for `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_MAX_TLP`, `INSIGHT_MFA` or `INSIGHT_THEME` stop start-up with a message naming the
variable, rather than running with a setting that silently does nothing.

### Reverse proxy (public deployment)
Put Insight behind a TLS-terminating reverse proxy (Caddy, nginx, Traefik); never expose port 8080 itself. The
Compose port stays bound to 127.0.0.1, so only the proxy on the same host can reach it.

1. In `.env`: `INSIGHT_ALLOWED_HOSTS=insight.example.org`, `INSIGHT_SECURE_COOKIES=1` and
   `INSIGHT_TRUSTED_PROXIES=<address the proxy connects from>`.
2. Find that address: before setting it, make one request through the proxy and read the client address in
   `docker compose logs insight` (uvicorn's access line, e.g. `172.18.0.1:53422 - "GET /login"`). With the
   proxy on the host, this is the Compose network's gateway:
   `docker network inspect insight_default -f '{{(index .IPAM.Config 0).Gateway}}'` (the network name follows
   your directory name).
3. The proxy must pass the original `Host` header, set `X-Forwarded-For` and `X-Forwarded-Proto`, and forward
   WebSocket upgrades (the workspace uses them). Caddy does all of this by default:
   `insight.example.org { reverse_proxy 127.0.0.1:8080 }`. For nginx:

   ```nginx
   location / {
       proxy_pass http://127.0.0.1:8080;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
   }
   ```
4. `docker compose up -d`. The log shows `Trusting X-Forwarded-For/-Proto from: …`. Sign in through the
   public URL to confirm.

Without step 1, sign-in through an HTTPS proxy fails with `403` (Insight sees `http`, the browser's `Origin`
says `https`), and every client appears to come from the proxy's address. Forwarded headers from any other
address are ignored, so clients cannot forge their address or scheme.

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

### The API key
`insight api-key status` shows the key ID, access, expiry and last use (in Docker: `docker compose exec insight
insight api-key status`). Rotate before the expiry date with `insight api-key rotate`, then paste the new key
into the SIEM or script: the old key stops working immediately. Rotating `INSIGHT_SESSION_SECRET` does not
affect the key. `429` responses with `Retry-After` mean a client exceeded its rate limit (docs/API.md).

### Sign-in second factor (MFA)
MFA is **off by default**: sign-in asks for the password only. Turning it on adds a code from an authenticator
app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis, Bitwarden, ...). Two separate things are
involved: **pairing** the app (stored in the database) and the **switch** `INSIGHT_MFA=on|off` (in `.env`).

| With Docker (Makefile) | What it does |
| --- | --- |
| `make mfa-enable` | Pairs an app if none is paired (shows a secret, then asks for one code; nothing is saved until a code matches), sets `INSIGHT_MFA=on` in `.env`, restarts Insight |
| `make mfa-disable` | Sets `INSIGHT_MFA=off` and restarts. The app stays paired, so `make mfa-enable` later needs no new pairing |
| `make mfa-status` | Whether MFA is on and whether an app is paired |
| `make mfa-reset` | Forgets the paired app (lost or replaced phone) |

Without make: `docker compose run --rm insight insight mfa setup`, then set `INSIGHT_MFA=on` in `.env` and run
`docker compose up -d`. Local Python: `insight mfa setup`, set `INSIGHT_MFA=on`, restart `insight serve`.

Pairing prints a secret and an `otpauth://` URI: enter the secret in the app manually as a time-based account,
or turn the URI into a QR code on your own machine. With MFA on, each code works once. If `INSIGHT_MFA=on` but no
app is paired, sign-in is **locked** (the sign-in page says so) rather than falling back to the password alone;
start-up logs an error. **Lost phone:** `make mfa-disable` (sign in with the password), then `make mfa-reset`
and `make mfa-enable` with the new phone. Codes depend on the clock: if they are always refused, check the time
on the phone and the server (NTP). The pairing secret is stored in the database: protect backups like the
password.

### Colour theme and text size
The workspace and the sign-in pages come in a light and a dark theme. **System** (the default) follows each
device's light/dark setting and changes with it, e.g. when a phone switches to dark mode in the evening.

- **In the browser:** the **Light / Dark / System** buttons at the top right of the workspace (icons only on a
  phone) switch at once. The choice is remembered by that browser in the `insight_theme` cookie for a year, so
  a phone and a desktop can differ. It is a display preference, not a credential.
- **Instance default** (browsers that have not picked one): `INSIGHT_THEME=system|light|dark` in `.env`.

| With Docker (Makefile) | What it does |
| --- | --- |
| `make theme THEME=dark` | Sets `INSIGHT_THEME=dark` in `.env` (the file stays private) and restarts Insight |
| `make up THEME=light` | The same while building and starting; without `THEME`, `make up` leaves `.env` alone |
| `make theme` | Shows the usage and the current value |

Without make: set `INSIGHT_THEME` in `.env` and run `docker compose up -d` (local Python: restart `insight serve`).
A browser that has already picked a theme keeps it; choosing **System** there hands it back to the device.

**Larger text** (next to the theme buttons) gives that browser a 19 px base size with more space between
letters, words and lines, for anyone who finds dense text hard to read. It is remembered per device in the
`insight_text` cookie and also applies to the sign-in page. **What the words mean** explains every abbreviation and
specialist term in plain language. Messages stay on screen until you press **Dismiss**. The readability standard
the GUI meets is [ADR 0017](adr/0017-readability-standard.md).

### Who did what
`GET /api/audit` (and the `audit_events` table) records an `actor` per event: `operator`, `api-key:<key ID>`,
`cli`, `connector:<source>` or `system`. Events from before schema revision `0005` have an empty actor.

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
`make restore BACKUP=backups/backup-YYYY-MM-DD-HHMMSS.db` performs these steps after asking for confirmation
(`CONFIRM=yes` skips the question). By hand:

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
under *Recent sync activity*. **Sync all sources** (top of the workspace, or `POST /api/sources/sync-all`) does
the same for every source in turn; a failing source does not stop the others, and the message names it. Enrichment (EPSS/NVD) sends only the CVE identifier, after explicit consent, at
most once every 6.5 s.

| Message (run history / API 502) | Meaning | Action |
| --- | --- | --- |
| `HTTPStatusError: … 403/404` | Publisher blocked or moved the feed | Check the URL in a browser; update `SOURCES` in `connectors.py` and ship a release |
| `HTTPStatusError: … 429/503` | Rate-limited or down | Retry later |
| `ValueError: Redirects are disabled…` | Feed moved | Review the new location, then update the registry |
| `ValueError: Source resolves to a non-public destination` | DNS returned a private or loopback address | Possible DNS tampering: check resolvers; do not work around it |
| `ValueError: Source exceeds the 8 MB payload limit` | Feed grew | Confirm it is legitimate; raise `MAX_BYTES` in a release |
| `ValueError: Invalid CVE in KEV input` / `Invalid KEV record field` | KEV format changed | Nothing was imported (all-or-nothing). Report it; the nightly live tests should also flag it. |
| `Read N advisories; … X could not be read.` (success) | Some CISA advisory files failed to download or are not valid CSAF | The others were imported; the next sync tries again. Report it if it persists. |
| `ValueError: The CSAF index lists no advisories` / `None of the N newest CSAF advisories could be read` | CISA moved or changed its CSAF repository | Nothing was imported. Report it; the nightly live tests should also flag it. |
| `OSError` / `ConnectError` | No network or DNS | Check host egress (an egress firewall is recommended) |
| Enrichment `429` | Less than 6.5 s since the last lookup | Wait |
| Enrichment `502 … non-JSON` | Provider outage or HTML error page | Retry later |

**CISA Security Advisories** (`cisa-csaf`) reads CISA's machine-readable CSAF 2.0 files from its GitHub
repository (`raw.githubusercontent.com/cisagov/CSAF`): the `changes.csv` index of the OT (industrial control
systems) and IT folders, then the 25 newest advisories, so one sync makes about 27 requests. Newest means by
publication date, which is part of each file name (`icsa-26-323-03`: 2026, day 323), not by when CISA last
saved the file: CISA sometimes re-saves years-old advisories in bulk. Advisories already stored are read again
while they are among the newest, so an update becomes a new revision of its report. Each report keeps the
advisory's summary, vendors, sectors and every CVE with its CVSS score (up to 100), and links to CISA's web page
for the advisory. CISA does not publish its threat-actor advisories (AA-series, #StopRansomware) as CSAF, so they
are not included. It replaced the CISA advisories RSS feed, which cisa.gov refuses to automated clients (`403`).

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
- **TLP limit** (`INSIGHT_MAX_TLP`, default `AMBER+STRICT`): a report labelled, or raised by a marking in its
  text, above the limit is refused on upload from the workspace and the API (`422`), and nothing is stored.
  So by default TLP:RED never reaches the server. A text that only *mentions* "TLP:RED" is refused too: reword
  the marking if it is not the report's own handling label. Connector items (public feeds) and the synthetic
  demo are not limited. Reports stored before the limit are kept and stay readable; at start-up Insight logs
  how many exceed it. Review them and delete any that must not stay (procedure below) before exposing the
  instance.

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
   docker compose run --rm --no-deps --entrypoint python insight -m sqlite3 /data/insight.db   # or: make db-shell
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
| Brute-force attempts | Log lines `Failed sign-in attempt` (says whether the password or the code was wrong) / `Sign-in refused` | More than 10 in 10 minutes |
| API key probing | Log lines `Rejected API key <key ID> from <address>: <reason>` (reason `revoked`/`expired`: an old key is still in use somewhere) | More than 10 in 10 minutes, or any `revoked` |
| Unexpected API writes | Log lines `API key <key ID>: POST /api/...`; `GET /api/audit` (`actor`) | Writes you did not schedule |
| Rate limiting | Log lines `Rate limit '<policy>' exceeded by <caller>` | Repeated for your own integration (raise its schedule interval) |
| Refused uploads | Log lines `Refused a TLP:RED report` (never the content) | Any, if nobody expected to upload RED |
| MFA misconfiguration | Log line `INSIGHT_MFA=on but no authenticator app is paired` (sign-in locked) | Any |
| Source health | Run history / `GET /api/sources` (`runs[0].status`) | Same source `error` 3 times in a row |
| Disk | Volume usage | Above 80% |
| Upstream changes | Nightly pipeline issue "Nightly pipeline failure" | Any new comment |
| Vulnerabilities | CI `pip-audit`, Trivy, nightly image re-scan | Any HIGH/CRITICAL |

## 12. Security incidents

| Incident | Immediate actions |
| --- | --- |
| Password or secret may be exposed | Rotate both (§4), then review logs for sign-ins you did not make. `.env` is plaintext: check who can read it. |
| Phone with the authenticator app lost | `make mfa-disable`, sign in with the password, `make mfa-reset`, then `make mfa-enable` with the new phone. If the phone may be in someone else's hands, also rotate `INSIGHT_PASSWORD`. |
| API key may be exposed | `insight api-key revoke` (immediate), then `insight api-key create` and update the client. Check `insight.auth` logs for `API key <key ID>` writes and `Rejected API key` lines, and the audit log for unexpected changes. |
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

- Single operator; no SSO, RBAC or recipient-level TLP enforcement; in-memory sessions and rate limits (one
  worker; a restart signs everyone out and resets the limits).
- One API key at a time; rotation takes effect immediately (no overlap), so update the client right after
  `make api-key-rotate`.
- `make smoke` and `scripts/smoke.py` sign in with the password only, so they need MFA off.
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
| [API_GUIDE](API_GUIDE.md) | Every API call with `curl`, authentication, limits, recipes, troubleshooting |
| [API](API.md) | HTTP endpoint and field reference |
| [Makefile](../Makefile) | `make help`: shortcuts for running, backing up, keys, MFA, tests and CI gates |
| [EXTRACTION](EXTRACTION.md) | Indicator extraction rules and limits |
| [SECURITY](SECURITY.md) | Security posture and hardening requirements |
| [TESTING](TESTING.md) · [CI_CD](CI_CD.md) · [RELEASING](RELEASING.md) | Quality gates and release process |
| [VALIDATION](VALIDATION.md) | What each release was validated against |
| [adr/](adr/) | Architecture decision records |
