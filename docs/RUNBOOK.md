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
| Exchange MISP events | [MISP guide](MISP.md) | `insight misp-export FILE --max-tlp GREEN` · `insight misp-import FILE` |
| Apply migrations explicitly | `make migrate` | `docker compose exec insight insight migrate` |
| Smoke-test a running instance | `make smoke` (password from `.env`, no demo data) | `python scripts/smoke.py http://127.0.0.1:8080 --password "$INSIGHT_PASSWORD"` |
| Version | `make version` | `docker compose exec insight insight --version` |
| API key | `make api-key-create NAME=siem` · `make api-key-status` · `-rotate` · `-revoke` | `docker compose exec insight insight api-key …` |
| Sign-in MFA (off by default) | `make mfa-enable` · `make mfa-disable` · `make mfa-status` · `make mfa-reset` | §4, "Sign-in second factor" |
| Alert destinations | Watch terms tab: *Alerts* | `insight notify list`, `add`, `enable`, `disable` or `remove` ([alerts guide](ALERTS.md#manage-destinations-on-the-host)) |
| Scheduled syncs (off by default) | Sources tab: *Start at* and *Sync by itself* | `docker compose exec insight insight schedule all --every 24h --at 00:00` · `insight schedule` lists them (§8) |
| Default colour theme (System by default) | `make theme THEME=dark` · `make up THEME=light` | Set `INSIGHT_THEME` in `.env`, then `docker compose up -d` (§4, "Colour theme") |
| Full threat-group library (optional, on request) | `make threat-library-sync`, then `make restart` | `docker compose run --rm insight insight threat-library-sync` (§8, "Threat library") |


## 1. System overview

```
Browser ──HTTP (127.0.0.1:8080)──► uvicorn (1 worker)
                                    ├─ FastAPI: /login, /logout, /api/*, /health, /static
                                    └─ NiceGUI workspace (/) over a WebSocket
                                         │
                                  services/ (only SQL layer) ────► SQLite /data/insight.db
                                         │                          (or PostgreSQL)
                                  connectors.py ──HTTPS (on demand or on a schedule you set)──► CISA, GitHub (CISA CSAF), SANS ISC, UK NCSC, FIRST, NVD
```

| Item | Location / value |
| --- | --- |
| Container user | UID/GID 10001; root filesystem read-only; writable: `/data` (volume), `/tmp` (tmpfs) |
| Database | `/data/insight.db` (SQLite) or `INSIGHT_DATABASE_URL` |
| NiceGUI storage | `/data/.nicegui` |
| Volume | `<project>_insight-data` (`docker volume ls`) |
| Port | `127.0.0.1:8080` only |
| Sessions | In the database (8 hours): a restart or upgrade keeps you signed in; a new password, MFA setting or temporary-access mode invalidates existing sessions. **Sign out everywhere** on the sign-out page ends every session. Rate limits stay in memory, so run exactly **one** worker. |
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
| `INSIGHT_DEV_NO_AUTH` | no | `off` | Temporary password-free operator access. Only `on` enables it; blank or `off` disables it. Invalid values or enabling it with MFA stop start-up. Anyone who can reach the site can enter and use its operator tools. See "Temporary password-free access" in §4. |
| `INSIGHT_MAX_TLP` | no | `AMBER+STRICT` | Most restrictive label stored. Reports at or raised to a higher label (i.e. TLP:RED) are refused on upload. `RED` allows everything. |
| `INSIGHT_RUN_JOBS` | no | `on` | Run scheduled syncs in this process ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)). Nothing is scheduled until you choose a schedule (§8). Set `off` in every process but one if you run several. Anything other than on/off stops start-up. |
| `INSIGHT_THEME` | no | `system` | Colour theme for browsers that have not picked one: `system` (follow each device's light/dark setting), `light` or `dark`. Each browser can override it with the Light/Dark/System buttons in the workspace header (`make theme THEME=dark` sets it). Anything else stops start-up. |
| `INSIGHT_PUBLIC_URL` | no | (none) | The address people open Insight at; alerts link to `/?report=<id>` ([docs/ALERTS.md](ALERTS.md)) |
| `INSIGHT_SMTP_HOST`, `INSIGHT_SMTP_PORT`, `INSIGHT_SMTP_SECURITY`, `INSIGHT_SMTP_USERNAME`, `INSIGHT_SMTP_PASSWORD`, `INSIGHT_SMTP_FROM` | for e-mail alerts | port 587, `starttls` | The mail server for e-mail alerts. `SECURITY` is `starttls`, `tls` (port 465) or `none` (only for a relay on this host). Treat the password like `INSIGHT_PASSWORD` |
| `INSIGHT_ALERT_PRIVATE_TARGETS` | no | `off` | `on` lets webhooks reach private networks (a chat or automation server on your LAN); link-local addresses stay blocked ([ADR 0022](adr/0022-alerts.md)) |
| `INSIGHT_ABUSECH_AUTH_KEY` | no | (none) | Account key for the optional URLhaus, ThreatFox and MalwareBazaar Community APIs. Sent in the `Auth-Key` header to the enabled publisher API. |
| `INSIGHT_NVD_API_KEY` | no | (none) | A free NIST NVD API key: CVE lookups at NVD every 0.7 s instead of every 6.5 s ([ADR 0023](adr/0023-automatic-cve-lookups.md)). Sent only in NVD's `apiKey` header, never logged |
| `INSIGHT_MISP_URL` and `INSIGHT_MISP_KEY` | no | (none) | The trusted public HTTPS instance and its API key, read by host CLI MISP transfers. File exchange also works offline. |
| `NICEGUI_STORAGE_PATH` | no | `/data/.nicegui` in the image | Must be writable |
| `INSIGHT_OTX_API_KEY` | no | (none) | The operator's OTX subscription key. Set it on the host and switch on the AlienVault OTX source. |

Never commit `.env`: a pre-commit hook and CI block it. Treat the file like the password it contains.

Invalid values for `INSIGHT_TRUSTED_PROXIES`, `INSIGHT_MAX_TLP`, `INSIGHT_MFA`, `INSIGHT_DEV_NO_AUTH`, `INSIGHT_RUN_JOBS`, `INSIGHT_THEME` or the alert settings stop start-up with a message naming the
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

### Temporary password-free access

`INSIGHT_DEV_NO_AUTH=on` deliberately lets anyone who can reach the site obtain the full browser operator
session without a password. On a public domain, that means public access to stored reports, exports and
editing tools. It is not a read-only public feed or a per-user account system. The setting is **off by
default** and the workspace displays a notice while it is enabled.

To enable it temporarily:

1. Keep the existing `INSIGHT_PASSWORD` and `INSIGHT_SESSION_SECRET`; both remain required and must still
   meet their length requirements. Do not remove them from the environment.
2. Set `INSIGHT_DEV_NO_AUTH=on` in the deployment's environment. `INSIGHT_MFA` must be `off`: combining MFA
   and password-free access is rejected at start-up. Record any previous MFA setting for restoration.
3. Recreate the container with the changed environment: `docker compose up -d --no-deps insight`. A plain
   `docker compose restart` does not apply changed Compose environment values. For local Python, restart
   `insight serve` with the new environment.
4. From a fresh browser, open the site and confirm it enters the workspace without a password. A visit to
   `/login` creates a normal expiring session and redirects to `/`; it no longer returns a password form.

The cookie, CSRF checks, same-origin checks, API-key rules and HTTPS/proxy settings remain in effect.
An API request without a valid session or key still returns `401`, but anyone can obtain a session through
`/login` while this mode is on. API-key TLP limits do not restrict the full operator session. Signing out,
including **Sign out everywhere**, ends existing sessions but cannot keep visitors out while the mode is
enabled: they can visit `/login` again. Password-form smoke scripts are for the normal protected mode;
verify the open mode's redirect, session, CSRF and report access explicitly.

To restore password protection:

1. Set `INSIGHT_DEV_NO_AUTH=off` (or remove it) and restore the previous MFA setting, if any. Keep the
   configured password and signing secret.
2. Run `docker compose up -d --no-deps insight` again, or restart the local Python process with the changed
   environment. The authentication-mode change invalidates sessions issued by the password-free mode.
3. Confirm a fresh browser sees the password form, an old password-free session cannot read `/api/stats`,
   and a request without any session or key returns `401`. Sign in with the retained password and, when
   enabled, the authenticator code; then run the normal smoke check.

Restoring sign-in stops future unauthenticated entry. It does not undo report changes or recall information
that visitors viewed or exported during the open period. The [security record](SECURITY.md#temporary-public-operator-access)
describes this tradeoff and the controls that remain.

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
Each failed sign-in waits about 1 s before it is answered. After 30 failures in one minute, wrong passwords
get HTTP 429 for the rest of that minute (still after the delay), and the log says `Sign-in refused`. The right
password always signs in, even during a flood of bad guesses ([ADR 0002](adr/0002-login-delay-not-lockout.md)):
there is no lockout.

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
3. Verify the published image's signature with cosign v3 or later (releases are signed with cosign, keyless):
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
- `curl -fsS http://127.0.0.1:8080/health` returns `{"status":"ok"}`.
- `docker compose exec insight insight --version` shows the new version. A signed-in browser session can also read the `version` field from `GET /api/session`.
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

Nothing syncs automatically unless you turn on a schedule. **Sync now** contacts exactly one publisher and
records a run (success or error) under *Recent sync activity*. **Sync all sources** (top of the workspace, or
`POST /api/sources/sync-all`) does the same for every source in turn; a failing source does not stop the
others, and the message names it.

**Schedules** ([ADR 0018](adr/0018-opt-in-scheduled-syncs.md)) make a source sync by itself: *Off* (default),
*Every hour*, *Every 6 hours* or *Every day*, per source or for all at once, in the Sources tab (which also
shows the next sync), or on the host with `insight schedule SOURCE|all --every off|1h|6h|24h` (`insight
schedule` alone lists them). API keys may read schedules (`GET /api/schedules`) but not change them. A schedule
you turn on syncs within a minute, then every interval, unless you choose a start time: **Start at** in the
Sources tab, or `--at HH:MM` (for example `insight schedule all --every 24h --at 00:00` syncs everything daily
at midnight UTC, which is 7 pm in New York in winter). Times are UTC, and every next sync keeps the slot, so a
daily sync stays on its hour. Changing **Start at** moves the schedules that are on. Scheduled syncs run inside `insight serve` while
`INSIGHT_RUN_JOBS` is on (the default); the start-up log names every enabled schedule. A failed scheduled sync
is tried again after 5, then 10 minutes, and each attempt appears in *Recent sync activity*. `GET /api/jobs`
lists recent jobs.

Public GET feeds use the publisher's cache validators (`If-None-Match`, `If-Modified-Since`). These feeds and the abuse.ch feeds compare the
response bytes with the last successful import. An unchanged feed records `Unchanged since the last
sync.` and nothing else. After an upgrade, every source is read once in full.

**abuse.ch indicator feeds.** Get an abuse.ch Auth-Key from [the account portal](https://auth.abuse.ch/),
set `INSIGHT_ABUSECH_AUTH_KEY` in the server environment and recreate the container. In **Sources → Indicator
feeds**, switch on the feeds you use and choose **Sync now**. Each sync makes one request for recent metadata.
URLhaus asks for 100 recent URL records, ThreatFox asks for the last day of indicators, and MalwareBazaar
asks for the last hour of file metadata. Insight reads up to 100 entries per sync. Short feed windows can
leave gaps when an instance is offline. The source record ID or SHA-256 connects subsequent revisions.
Reported network indicators are stored in defanged form. Publisher record links are for manual reference.

Each feed starts off. The imported public indicator records are marked TLP:CLEAR, with publisher text and
evidence withheld from exports. Check your abuse.ch access and sharing terms before enabling a schedule or
redistributing data. Community access has fair-use limits, and commercial use may require a subscription.
[URLhaus API](https://urlhaus-api.abuse.ch/) · [ThreatFox API](https://threatfox.abuse.ch/api/) ·
[MalwareBazaar API](https://bazaar.abuse.ch/api/) · [abuse.ch terms](https://abuse.ch/terms-of-use/)

**AlienVault Open Threat Exchange (OTX).** Set `INSIGHT_OTX_API_KEY` in the host environment (or Compose
`.env`), restart Insight, then turn on **AlienVault Open Threat Exchange (OTX)** in Sources. **Sync now**
requests the first 25 subscribed pulses. Insight imports only explicitly public pulses marked TLP:CLEAR
or its former name, WHITE. Recent sync activity gives the numbers imported and skipped. A missing key,
refused request or malformed response records an error. A valid empty page is a successful sync.

Insight keeps each eligible pulse's ID, title, source link and supported indicator values from its first
100 indicator entries. It leaves descriptions and reference articles at OTX. A pulse keeps the same ID
across syncs, and changes to its imported content create a report revision. Unsubscribing or a subsequent
change to private visibility leaves the previously imported public snapshot in the workspace. Source reuse
is metadata-only. Review the terms for your intended use, including the non-commercial use condition for
free access. [OTX DirectConnect and keys](https://otx.alienvault.com/api) ·
[OTX end-user agreement](https://www.levelblue.com/legal/otx-eula-terms)

**CVE lookups** (FIRST EPSS and NIST NVD) send only the CVE number. People start one with *Look up this CVE*
after agreeing to the request. **Automatic lookups** ([ADR 0023](adr/0023-automatic-cve-lookups.md)) are off
until you switch a provider on under *Automatic CVE lookups* in the Sources tab (audited as `lookup.on` and
`lookup.off`). Then the job runner looks up each CVE that a current TLP:CLEAR or GREEN report mentions and that
has no recent answer (EPSS after 7 days, NVD after 30), newest reports first, as `lookup` jobs (in
`GET /api/jobs` and the start-up log). CVEs seen only in AMBER or RED reports are never looked up by
themselves. The Sources tab shows how many CVEs are waiting. One throttle per provider is shared by people,
the API and the job runner: NVD gets one request every 6.5 s, EPSS one a second. Without a key NVD gets
through about 550 CVEs an hour, so a first backlog of thousands takes a day; set `INSIGHT_NVD_API_KEY` (free,
from NVD) for one request every 0.7 s, and restart. The key goes only in NVD's `apiKey` header and is never
logged. A failed lookup job is tried again after 5, 10 and 20 minutes; after the last failure that provider
pauses for an hour, then tries again by itself.

| Message (run history / API 502) | Meaning | Action |
| --- | --- | --- |
| `HTTPStatusError: … 403/404` | Publisher blocked or moved the feed | Check the URL in a browser; update `SOURCES` in `connectors.py` and ship a release |
| `HTTPStatusError: … 429/503` | Rate-limited or down | Retry later |
| `ValueError: Redirects are disabled…` | Feed moved | Review the new location, then update the registry |
| `ValueError: Source resolves to a non-public destination` | DNS returned a private or loopback address | Possible DNS tampering: check resolvers; do not work around it |
| `ValueError: Source exceeds the 8 MB payload limit` | Feed grew | Confirm it is legitimate; raise `MAX_BYTES` in a release |
| `ValueError: Invalid CVE in KEV input` / `Invalid KEV record field` | KEV format changed | Nothing was imported (all-or-nothing). Report it; the nightly live tests should also flag it. |
| `Read N advisories; … X could not be read.` (success) | Some CISA advisory files failed to download or are not valid CSAF | The others were imported; the next sync tries again. Report it if it persists. |
| `Unchanged since the last sync.` (success) | The publisher's feed has not changed since the last successful sync | Nothing to do; nothing was re-imported. |
| `ValueError: The CSAF index lists no advisories` / `None of the N newest CSAF advisories could be read` | CISA moved or changed its CSAF repository | Nothing was imported. Report it; the nightly live tests should also flag it. |
| `OSError` / `ConnectError` | No network or DNS | Check host egress (an egress firewall is recommended) |
| `TimeoutError: The download took longer than 120 seconds` | The publisher answered too slowly (every download has an overall limit, review L6) | Retry later; nothing was imported |
| Lookup `429` / *Wait N more second(s)* | The provider's window is taken, possibly by Insight's own automatic lookups | Wait the seconds shown |
| Lookup `502 … non-JSON` | Provider outage or HTML error page | Retry later |
| Lookup job `NVD answered HTTP 403/404 (check INSIGHT_NVD_API_KEY)` | NVD refused the key (mistyped, revoked or expired) | Fix or remove `INSIGHT_NVD_API_KEY` and restart; jobs resume within an hour |
| Lookup job `NVD answered HTTP 403` (no key hint) | NVD's rate limit without a key, often another tool on the same address | It retries by itself; a key avoids it |
| Lookup job `… request failed: ConnectError` | No network or DNS | Check host egress; allow `services.nvd.nist.gov` and `api.first.org` |
| Lookup job `Looked up N CVEs …; M could not be answered` / Sources tab *could not answer for M CVE(s)* | NVD refused those CVEs (for example a CVE number a report got wrong) | Nothing to do: each is tried again after 1 hour, then 2, 4 … up to 7 days, without holding up the rest |

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

### Threat library

Industry threats and threat guides ([THREAT_GUIDES.md](THREAT_GUIDES.md)) read a threat-group library. Insight
ships a small edition (`src/insight/data/actors.json`), so they work offline from the first start. The full
edition adds whole group descriptions, ATT&CK procedure examples, analytics and every reference:

```sh
make threat-library-sync      # Docker: docker compose run --rm insight insight threat-library-sync
make restart                  # load it (the running process keeps the edition it loaded)
```

The sync downloads two files whose versions and SHA-256 are pinned in the code (MITRE ATT&CK Enterprise 20.1,
about 55 MB, and the MISP galaxy threat-actor cluster, version 359, about 1.5 MB) from `raw.githubusercontent.com`
over HTTPS, refuses anything larger than 80 MB or 8 MB, checks both hashes before parsing, and writes
`/data/threat-library.json` (`<INSIGHT_DATA_DIR>/threat-library.json`) atomically. It contacts nothing else
and never runs by itself. Allow `raw.githubusercontent.com` in the egress firewall for it (the CISA CSAF source
uses the same host).

| Message | Meaning | Action |
| --- | --- | --- |
| `… SHA-256 … does not match the pinned release; nothing was changed` | The file served is not the pinned one | Nothing was written. Do not override; report it (a moved or altered upstream file) |
| `Source exceeds the 80 MB payload limit` (or 8 MB) | The download exceeded its limit | Nothing was written. Report it |
| `OSError` / `ConnectError` | No network, DNS or egress | Check host egress; the bundled edition keeps working |
| Industry threats still says `bundled copy` after a sync | The process was not restarted, or the file is invalid (logged as `insight.threat_library` warning) | `make restart`; if it persists, delete `/data/threat-library.json` and sync again |

To go back to the bundled edition, delete `/data/threat-library.json` and restart. Moving to a newer ATT&CK or
MISP release is a code change in an Insight release (`scripts/update_actors.py`, ADR 0025), never a setting.

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
  how many exceed it. Review them and delete any that must not stay (`make delete-report`, below) before exposing the
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

**Deleting a report** (legal or retention obligations). Reports can carry victims' names, addresses and hosts,
so the law may require you to delete one. Deletion has no undo and needs shell access, like API keys and MFA
(no API route or button).

1. **Take a backup** (§5).
2. Find the report ID (in the export file name, `GET /api/documents?q=…`, or the reader's URL).
3. Run, with a reason your records can trace (a ticket, the retention rule):
   ```sh
   make delete-report ID=<report id> REASON='ticket 1234: retention period ended'
   # without Docker: insight delete-report <report id> --reason '...'   (add --yes for scripts)
   ```
   It shows the report and what goes with it, and deletes only after you type `delete`.

In one transaction it deletes the report, its observations and notes, and every indicator that no other report
mentions, with any verdict on it. It repairs the revision chain: later revisions point past the deleted one, and
when it was the current revision of a synced item, the newest remaining revision becomes current. One
`document.delete` audit event (actor `cli`) keeps the reason, the content hash and the counts, never the title or
the text. Insight can stay running.

Two things it cannot reach: **backups** taken before the deletion still contain the report, so apply your
retention policy to them; and a report **synced from a public source** comes back if the publisher still lists
the item and the feed changes, so remove it at the source too or turn that source's schedule off.

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Browser shows `Forbidden` on sign-in | Request `Origin` does not match `Host` (reverse proxy, different host name) | Use http://localhost:8080 or http://127.0.0.1:8080 exactly. Behind a proxy, keep the `Host` header and terminate TLS consistently. |
| `Invalid host header` (400) | Host not in `INSIGHT_ALLOWED_HOSTS` | Add it, and understand the exposure first |
| `Too many login attempts` (429) | More than 30 failed sign-ins in a minute | Wait 60 s. Check logs for unknown sources (§11). |
| Signed out unexpectedly | 8-hour session expiry, sign-out in another tab, **Sign out everywhere**, or a new password, MFA setting or session secret | Sign in again (expected) |
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
| Alert delivery | **Watch terms → Alerts → Recent alerts** (status `Failed` with the reason); job messages `Sent N alert(s); M failed.` | Any `Failed`: a destination moved, or its secret or mail password changed |
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

## 14. Known limitations

- Single operator; no SSO, RBAC or recipient-level TLP enforcement; rate limits and the sign-in throttle live
  in memory (one worker; a restart resets them). Sessions are stored in the database and survive restarts.
- One API key at a time; rotation takes effect immediately (no overlap), so update the client right after
  `make api-key-rotate`.
- `make smoke` and `scripts/smoke.py` sign in with the password only, so they need MFA off.
- Deleting a report is CLI-only (`make delete-report`, §9); audit events are not tamper-proof.
- Extraction is deterministic regex plus validation (about 98% precision and recall on the labelled corpus).
  Known gaps:
  - a hash split evenly into two valid lengths stays two hashes;
  - CIDR ranges must start at a network boundary;
  - IPv6 zone IDs are dropped.
  See [EXTRACTION.md](EXTRACTION.md).
- Stored reports keep their original observations. New reports and revisions use `regex-v5`, which also recognizes bracketed web schemes and word-form e-mail separators.
  Look for the personal-data warning when reviewing an address or choosing indicators to share.
- Feed summaries are capped at 500 characters (flagged as truncated).
- IOC export:
  - at most 100,000 mentions per export (export in parts);
  - defanging leaves source URLs, IP-shaped version numbers and names without a real TLD as written;
  - evidence excerpts can contain context an analyst rejected unless evidence is left out;
  - an expired session shows `{"detail":"Sign in required"}` in the download tab.
  See [IOC_EXPORT.md](IOC_EXPORT.md).
- Industry threats and threat guides: industry claims come only from MITRE ATT&CK prose and MISP galaxy labels
  (plus your own), so coverage follows those sources; "reports naming a group" is a count of names, not
  attribution; hunt hypotheses are generic starting points; rules are stored, never run. See
  [THREAT_GUIDES.md](THREAT_GUIDES.md#limits).
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
