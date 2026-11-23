# Toward a premium TIP: the detailed plan

**Audience:** the maintainer (solo developer, SOC / blue team).
**Baseline:** Insight 0.6.0, public repo [andrewjscott88/insight](https://github.com/andrewjscott88/insight), reviewed 21 November 2026. Line references are as of 0.6.0; re-check them before treating any as a patch.
**Release order:** [ROADMAP.md](../ROADMAP.md) puts these items into releases, together with the remaining items of the 0.5.0 review.
**Scope:** Make Insight as effective as possible for a self-hosted, single-operator (and later small-team) workbench, and *comparable in workflow and interop* to premium TIPs. This does **not** mean reproducing CrowdStrike, Mandiant, or Recorded Future collection. Those products sell sensor telemetry, incident-response caseloads, and human/dark-web reporting that a solo developer cannot and should not try to clone.

Existing project issues are cited where they already exist (`ROADMAP.md`). Scheduled source syncs (`ROADMAP.md` #10) are **already implemented** in 0.6.0 (`src/insight/jobs.py`, ADR 0018); do not rebuild them. Sessions are already stored in the database (0.6.0, migration `0008`). No vendor list prices are included; premium TIPs are quote-based.

---

## 1. Current state versus premium TIPs

Insight is a MIT-licensed, self-hosted workbench: NiceGUI + FastAPI + SQLAlchemy, SQLite (or PostgreSQL), four curated public connectors, deterministic indicator extraction, TLP policy, analyst verdicts, watch terms, a 7-day fact-based brief, an IOC export (`insight-ioc-v1`, **not STIX**), a blocklist API, one operator password (optional TOTP), one hashed API key, and opt-in scheduled syncs.

| Area | Insight 0.6.0 today | What premium TIPs (CrowdStrike Falcon Adversary Intelligence, Google Threat Intelligence, Recorded Future, Microsoft Defender TI) add | Realistic open-source peers (MISP, OpenCTI) |
| --- | --- | --- | --- |
| Collection | CISA KEV, CISA CSAF (25 newest), SANS ISC RSS, UK NCSC RSS; pasted reports | Proprietary telemetry, IR, dark web, human intel, malware corpora | You bring the feeds; large connector/sharing ecosystems |
| Actors / campaigns | None by design (no attribution from co-occurrence) | Actor, campaign, malware, and infrastructure profiles | Galaxies / native STIX intrusion sets and campaigns |
| ATT&CK | None | Technique mapping in product UIs and APIs | MISP galaxies; OpenCTI native attack patterns |
| IOC enrichment | Local extraction + verdicts; on-demand NVD/EPSS only | Reputation, prevalence, sandbox, risk scores | Correlation, warning lists, enrichment modules |
| Vulnerability intel | Full KEV table but incomplete fields; inbox only latest 100 KEV additions; brief "most severe" is CSAF CVSS 9+ only | KEV/EPSS/exploit context tied to actors and org exposure | You wire KEV/NVD/EPSS in; OpenCTI links vulns to adversaries |
| Sharing | Custom JSON + TLP; no STIX/TAXII/MISP | STIX APIs and/or TAXII (Google, Recorded Future, Microsoft verified) | MISP JSON + STIX 1/2; OpenCTI native STIX 2.1 + TAXII |
| Integrations | One HTTP API and `/api/iocs/blocklist` | SIEM/SOAR/EDR packs, playbooks | PyMISP, ZMQ/Kafka, 400+ OpenCTI connectors |
| Detection content | None | YARA / hunting packages / KQL (varies by vendor) | Suricata, Snort, Zeek, OpenIOC export (MISP) |
| Alerting | Watch terms highlight text only | PIR/brand monitoring, email/intel notifications | Notifications, sightings, EE PIRs |
| Search / graph | Folded literal search; entity pivots; no graph | Intel explorers and knowledge graphs | Event graphs (MISP); STIX hypergraph (OpenCTI) |
| Identity | Single operator; audit events, not tamper-evident | Enterprise IdP and roles | RBAC (MISP; OpenCTI advanced RBAC is Enterprise Edition) |
| AI | None; brief is deterministic | Gemini, Copilot, Autonomous Threat Operations, etc. | OpenCTI AI is Enterprise Edition |
| Cost / audience | Free, self-hosted, one analyst | Quote-based commercial products | Free self-hosted cores; optional paid EE/SaaS |

**Insight is already strong at:** local control, no license fee, transparent connectors, evidence-preserving extraction, raise-only TLP with instance and per-key limits, container/API hardening, and a brief that does not hallucinate.

**The gap to close first** is operational completeness (vuln fields, auto-enrichment, alerts, more free IOC feeds) and then interop (STIX, ATT&CK, MISP). Do not spend Phase 2–3 time on fake "global threat graphs."

---

## 2. Security and reliability findings (fix these first)

These were found by reading the 0.6.0 tree. They are not a pentest of the live site. File paths are under `/workspace/insight`.

### 2.1 Verify any public deployment against the repository

Nothing in this repository enables anonymous workspace access, and there is no configuration flag for it.

Designed access:

- `/` redirects unauthenticated browsers to `/login` (`src/insight/ui/page.py:47-50`).
- UI callbacks recheck `Workspace.authorized()` (`src/insight/ui/workspace.py:62-67`).
- `/api/*` requires a valid session plus CSRF on writes, or a CLI-minted Bearer key (`src/insight/web/auth.py:137-196`).
- Settings require `INSIGHT_PASSWORD` (12+ characters) and `INSIGHT_SESSION_SECRET` (32+ characters) (`src/insight/config.py:15-16, 125-131`).

A visitor still receives an `insight_session` cookie from Starlette's `SessionMiddleware` (`src/insight/web/app.py:72-79`), and `/login` stores a CSRF token in that cookie (`src/insight/web/routes/pages.py:33`). That cookie alone is **not** a sign-in: `session_checker` requires `authenticated=True` and a stored, unexpired session ID (`src/insight/web/auth.py:93-107`; `src/insight/services/access.py:238-243`).

If a public instance ever shows the workspace, the brief or any banner about open access without a sign-in form, that behaviour is **not in this code**: treat it as a deployment incident (a different build, or another service in front of Insight), not as a feature.

**What to do:** From an incognito window, `GET https://<public-host>/` must 303 to `/login`. Confirm the running image is the released version, and that `.env` sets `INSIGHT_ALLOWED_HOSTS=<public-host>`, `INSIGHT_SECURE_COOKIES=1`, `INSIGHT_TRUSTED_PROXIES=<proxy address>`, and preferably `INSIGHT_MFA=on` (`docs/RUNBOOK.md:77-108`). Confirm no second process is serving a different app in front of, or instead of, Insight.

### 2.2 README session documentation bug (Medium) — fixed with this plan

`README.md:74` still says Insight "has one operator password (plus optional MFA), **in-memory sessions** and rate limits: **restarting signs everyone out**."

That is wrong for sessions as of 0.6.0. Sessions live in `operator_sessions` for eight hours and **survive a restart**. Changing the password, session secret, or MFA setting ends them; "Sign out everywhere" ends them. See `src/insight/web/auth.py:96-97`, `src/insight/services/access.py:203-211, 238-243`, migration `0008_operator_sessions.py`, and the already-correct `docs/RUNBOOK.md:50` and `docs/SECURITY.md:5`.

Rate limits **are** still in-process (`src/insight/ratelimit.py`, `docs/SECURITY.md:9`), so that part of the README sentence remains true. An operator who restarts the container thinking they have revoked every session would be mistaken.

`README.md:212` is also stale: it lists "no … automated scheduling," but opt-in schedules shipped in 0.6.0 (`src/insight/jobs.py`, ADR 0018). `docs/ARCHITECTURE.md:130-132` still says sources must be run manually and that there is no durable scheduler.

### 2.3 MFA and secure-cookie defaults (Medium, for any internet-facing host)

Defaults are password-only and cookies not marked Secure:

- `INSIGHT_SECURE_COOKIES` defaults to `0` (`compose.yaml:14`, `src/insight/config.py:99, 140`).
- `INSIGHT_MFA` defaults to off (`compose.yaml:18`, `src/insight/config.py:107-109, 144`).
- The operator password is stored in plaintext in `.env` (`docs/SECURITY.md:7`).

This is acceptable for loopback use. It is not acceptable for a public hostname unless the runbook checklist is followed. `src/insight/web/app.py:99-102` already logs a reminder that MFA is off when trusted proxies are set; extend that pattern (see Phase 0.3).

### 2.4 DNS rebinding residual on connectors (Medium)

`download()` first checks that DNS answers for a curated hostname are globally routable (`src/insight/connectors.py:147-150`), then `httpx` resolves the name again (`src/insight/connectors.py:197-206`). A resolver that changes its answer in between can send the request to a non-public address. The code and docs already admit this: `connectors.py:203` and `docs/SECURITY.md:25, 45`. Redirects are disabled and `trust_env=False`, which is good, but the TOCTOU remains.

### 2.5 Unauthenticated `/health` disclosed the version (Low, resolved)

At the time of the review, the public health check included the Insight version. Phase 0.5 moved it to the signed-in session response. Docker still checks `/health` for liveness.

### 2.6 TOTP secret stored in recoverable form (Low, documented)

The review found that a database copy contained the plaintext authenticator seed. Phase 0.6 addresses this
in revision `0017`. Anyone holding both the encrypted database and the matching host secret can still
recover the seed. [Security posture](SECURITY.md)

---

## 3. How to use this roadmap

- **Phase 0** is mandatory before adding features to a public instance.
- **Phase 1** makes today's vuln-centric workflow actually complete.
- **Phase 2** is the core TIP feature set (STIX, ATT&CK, MISP, actors, detection artifacts).
- **Phase 3** is advanced (TAXII, graph, identity, LLM, optional paid enrichment APIs).

Effort: **S** (hours to a couple of days), **M** (several days to a week), **L** (more than a week, often more than one migration and UI surface). Each item lists the existing modules to touch, not a greenfield rewrite. Follow current architecture: `services/` is the only SQL layer; connectors stay on an HTTPS allowlist with size limits; do not invent actor attribution from co-occurrence (`README.md:187, 214`).

Next Alembic revision after `0008_operator_sessions.py` should be `0009_…`, generated the way `docs/ARCHITECTURE.md` and `CONTRIBUTING.md` describe, with `test_models_match_migrations` kept green.

---

## Phase 0 — Fixes (do these first)

### 0.1 Verify and lock down every public deployment

- **What to build:** Not a code feature. A short operational checklist and, if anything in front of Insight is bypassing auth, a deployment fix. Optionally add a smoke assertion that anonymous `GET /` is 303 `/login` on the public URL (`scripts/smoke.py` already checks anonymous workspace access locally).
- **Why / which TIP capability:** Basic access control. Premium TIPs assume authenticated enterprise tenants. A publicly writable inbox would undermine every later feature.
- **Implementation notes:** Walk `docs/RUNBOOK.md:77-108` and `docs/SECURITY.md:31-45`. Confirm Compose still binds `127.0.0.1:8080` (`compose.yaml:6`) and that Caddy (or nginx) is only a TLS reverse proxy, as in the runbook one-liner. Compare the running version from an authenticated session to `__version__ == '0.6.0'` (`src/insight/__init__.py:3`).
- **New tables or endpoints:** None required. Optional: keep `/health` unauthenticated but versionless (0.5).
- **Sources / libraries:** Existing `scripts/smoke.py`.
- **Effort:** S
- **Acceptance criteria:** Incognito `GET https://<public-host>/` returns 303 to `/login`. `GET /api/brief` and `POST /api/documents` without a session return 401. After sign-in, the workspace loads. `.env` has `INSIGHT_SECURE_COOKIES=1`, `INSIGHT_ALLOWED_HOSTS`, and `INSIGHT_TRUSTED_PROXIES` set correctly.

### 0.2 Fix stale session and scheduling documentation — done

Done in the change that added this plan: README and `docs/ARCHITECTURE.md` now describe stored sessions,
opt-in schedules and the job runner, and `ROADMAP.md` marks #10 done.


- **What to build:** Doc-only corrections.
- **Why:** Operators will make wrong security decisions (restart to "kick sessions," or assume schedules do not exist).
- **Implementation notes:** Rewrite `README.md:74` to match `docs/RUNBOOK.md:50`: sessions are in the database (8 hours), restarts keep the operator signed in, a new password or MFA setting signs everyone out, rate limits stay in memory, use one worker. Remove "automated scheduling" from the "not yet" list at `README.md:212`, or narrow it to "alert delivery." Update `docs/ARCHITECTURE.md:130-132` to describe opt-in schedules and the job runner. Mark `ROADMAP.md` #10 as done, with a pointer to ADR 0018.
- **New tables or endpoints:** None.
- **Sources / libraries:** None.
- **Effort:** S
- **Acceptance criteria:** A grep for "in-memory sessions" and "restarting signs everyone out" returns no current claims. `tests/unit/test_docs.py` (if it asserts README facts) is updated and green.

### 0.3 Safer public-deploy defaults and startup warnings

- **What to build:** Stronger start-up warnings (and optionally a fail-closed mode) when Insight is clearly internet-facing.
- **Why:** MFA off and non-Secure cookies are the default (`compose.yaml:14, 18`; `src/insight/config.py:99, 107-109, 140, 144`). Microsoft and other enterprise TIPs assume org identity and TLS.
- **Implementation notes:** Extend `_log_deployment_warnings` in `src/insight/web/app.py:85-109`. If `trusted_proxies` is set or `allowed_hosts` is not only loopback: warn when `secure_cookies` is false (already partially done at lines 89-90) and when `mfa` is false (already logged at 99-102). Consider refusing to start when `INSIGHT_REQUIRE_HARDENED=1` (new, default off) unless `secure_cookies` and `mfa` are on, so local `make dev` does not break. Document the flag in `.env.example` and `docs/RUNBOOK.md` section 2. Do not silently turn MFA on; pairing still requires `insight mfa setup`.
- **New tables or endpoints:** None. Optional env var `INSIGHT_REQUIRE_HARDENED`.
- **Sources / libraries:** None.
- **Effort:** S
- **Acceptance criteria:** Tests in `tests/unit/test_config.py` / `tests/api/test_app_factory.py` cover the warning and the optional fail-closed flag. Runbook "Reverse proxy" section names the flag. Loopback defaults unchanged.

### 0.4 Pin outbound connector connections to the checked DNS addresses

- **What to build:** Close the DNS-rebinding TOCTOU in `download()`.
- **Why:** Matches the residual risk already documented in `docs/SECURITY.md:25`. Premium vendors are not the point here; this is baseline connector hygiene before adding more feeds in Phase 1.
- **Implementation notes:** In `src/insight/connectors.py`, keep `_assert_public` (`147-150`) but use the resolved addresses for the actual connection (custom `httpx` transport or a connection hook): connect to the verified public IP, set TLS SNI / certificate hostname to the original name, and send the original `Host` header. Re-run the public-IP check if a fallback address is used. Keep `follow_redirects=False`, `trust_env=False`, HTTPS-only, allowlisted hosts, and the 8 MB cap (`MAX_BYTES`, `ALLOWED_HOSTS`). Update the comment at line 203 and `docs/SECURITY.md:25` to describe what is now pinned and what still needs an egress firewall (you cannot defeat a malicious public host that you intentionally allowlisted).
- **New tables or endpoints:** None.
- **Sources / libraries:** Existing `httpx`.
- **Effort:** M
- **Acceptance criteria:** Unit tests in `tests/unit/test_download.py` (or equivalent) show that a hostname whose first resolution is public and whose second is private is not contacted on the private address. Existing connector tests stay green. Live tests (`tests/live/test_sources_live.py`) still pass when enabled.

### 0.5 Stop advertising the version on unauthenticated `/health`

- **What to build:** Split liveness from version disclosure.
- **Why:** Low-severity information disclosure (`src/insight/web/routes/pages.py:25-27`).
- **Implementation:** `GET /health` returns only `{"status": "ok"}`. After sign-in, `GET /api/session` returns the running Insight version alongside the CSRF token. Docker continues to check `/health`.
- **Sources / libraries:** None.
- **Effort:** S
- **Acceptance criteria:** Unauthenticated `/health` has no version string. Authenticated clients can still read `0.6.0` (or later). Container healthcheck stays green. `tests/api` updated.

### 0.6 Encrypt the TOTP secret at rest

Revision `0017` encrypts existing authenticator seeds with AES-256-GCM. Insight derives the encryption key
from `INSIGHT_SESSION_SECRET` using HKDF-SHA256, and the host CLI encrypts new pairings the same way.
Migrated pairings retain their last accepted time step. The host CLI supports replacing a pairing when the
session secret is deliberately changed. [Upgrade, backup and recovery](RUNBOOK.md#sign-in-second-factor-mfa)

---

## Phase 1 — Quick wins (complete the current product)

### 1.1 Complete KEV catalog fields and inbox policy

- **What to build:** Persist the KEV fields Insight currently drops, and make the inbox policy explicit so historical KEV CVEs are usable.
- **Why / which TIP capability:** Vulnerability intelligence. Recorded Future uses KEV membership in risk rules and adds exploit context; Insight already upserts the catalog into `kev_records` but ignores `knownRansomwareCampaignUse`, `vulnerabilityName`, `notes`, and `cwes` (`src/insight/connectors.py:59-66, 504-532`; `src/insight/models.py:146-154`). Inbox documents are only the latest 100 by `dateAdded` (`KEV_INBOX_LIMIT`, lines 36 and 534). The brief and IOC KEV view therefore cannot say "used in ransomware campaigns."
- **Implementation notes:** Extend `KEV_STRING_FIELDS` and `KEVRecord` with `vulnerability_name`, `known_ransomware`, `notes`, and a bounded `cwes` text or JSON column. Migration `0010_kev_fields.py`. Update `import_kev()` body text and `services/search.py` `_kev_view` (`111-121`) so the reader and exports show the new fields. Keep a cap, but either (a) raise it with a documented default, (b) also create inbox documents for entries added in the brief window, or (c) create a document the first time a CVE is newly added and leave older ones as catalog-only with a UI badge. Do not delete catalog rows when they fall out of the top 100 (already the rule at `README.md:217`).
- **New tables or endpoints:** Columns on `kev_records`. No new route required; existing document and brief APIs should expose the fields.
- **Sources / libraries:** Existing feed [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). Catalog page: [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Effort:** S
- **Acceptance criteria:** After a fixture or recorded KEV payload with `knownRansomwareCampaignUse=Known` is imported, `kev_records` and `_kev_view` include that flag and the vulnerability name. Tests in `tests/unit/test_kev.py` cover field validation, length bounds, and inbox policy. A first sync still cannot explode the inbox without a documented cap.

### 1.2 Automatic NVD and EPSS enrichment for extracted CVEs

- **What to build:** After ingest or a source sync, enqueue background NVD and EPSS lookups for newly seen CVEs, instead of only the consent dialog / `POST /api/enrichment/{provider}/{cve}`.
- **Why / which TIP capability:** IOC and vulnerability enrichment. Google TI and Recorded Future attach scores automatically. Insight already has `enrich_cve()`, `PROVIDERS` for NVD and EPSS (`src/insight/connectors.py:68-72, 725-777`), the `enrichments` table, UI consent in `src/insight/ui/enrichment.py`, and a 6.5 s throttle (`src/insight/web/routes/sources.py:139-141`). The brief does not read those caches.
- **Implementation notes:** Add a job kind next to `SOURCE_SYNC` in `src/insight/jobs.py` (`HANDLERS`) and `src/insight/services/jobs.py`. Enqueue from `services.ingest` or from `_store_source` / `_ingest_items` when a new or revised document introduces a CVE entity. Respect `ENRICHMENT_INTERVAL_SECONDS`, `INSIGHT_RUN_JOBS`, and provider outages (`ProviderError`). Keep the manual dialog for force-refresh. Do not send report bodies to NVD or FIRST — only the CVE ID, as today. Cache remains `Enrichment.payload` JSON.
- **New tables or endpoints:** Reuse `jobs` and `enrichments`. Optional `GET /api/enrichment/{cve}` to read the cache without triggering a fetch. Optional operator toggle "auto-enrich CVEs" stored as a setting or schedule-like row so the operator stays in control (Insight's model is opt-in outbound).
- **Sources / libraries:** [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (`https://services.nvd.nist.gov/rest/json/cves/2.0`, already in `PROVIDERS`). [FIRST EPSS](https://www.first.org/epss/) (`https://api.first.org/data/v1/epss`, already in `PROVIDERS`). For bulk backfill, FIRST also publishes a daily CSV on that site; prefer the existing JSON API unless a documented rate limit forces a CSV import.
- **Effort:** M
- **Acceptance criteria:** Syncing a report that mentions a new CVE eventually produces `enrichments` rows for `nvd` and `epss` without a UI click, within the throttle. Failures are `SourceRun` or job error records, not silent. Auto-enrich can be turned off. Tests do not hit the network (reuse connector transport fakes in `tests/unit/test_sync_and_enrichment.py`).

### 1.3 Upgrade the 7-day brief with KEV ransomware, NVD CVSS, and EPSS

- **What to build:** Teach `brief_data` / `compose` to use the richer vuln data from 1.1 and 1.2.
- **Why / which TIP capability:** Vulnerability prioritization. Today "Most severe" is only CSAF body regex `SCORE_LINE` (`src/insight/brief.py:26-29, 163-166, 287-290`). EPSS and NVD are invisible to the landing page.
- **Implementation notes:** Extend `BriefKev` and `BriefData` in `src/insight/services/brief.py` with ransomware flag, NVD base score, and EPSS probability when cached. Update `src/insight/brief.py` sections: keep "Exploited now"; add ransomware-used KEV lines; let "Most severe" consider NVD CVSS as well as CSAF; optionally mention high-EPSS CVEs with a plain-language caveat that EPSS is a probability estimate, not exposure. Wire `src/insight/ui/brief.py` and `GET /api/brief` (`src/insight/web/routes/workspace.py`). Leave demo reports out, same as today.
- **New tables or endpoints:** No new tables. `GET /api/brief` JSON grows fields; document in `docs/API.md`.
- **Sources / libraries:** Same as 1.1–1.2. No AI.
- **Effort:** M
- **Acceptance criteria:** Unit tests in `tests/unit/test_brief.py` cover: KEV ransomware line present/absent; NVD score 9.8 beats or joins CSAF; missing caches do not crash; wording still only states stored facts. UI smoke still passes.

### 1.4 Notifications for watch-term hits and new KEV entries

- **What to build:** Email and/or signed HTTPS webhooks when a new current report matches a watch term, or when KEV gains an entry (already `ROADMAP.md` #15).
- **Why / which TIP capability:** Alerting / watchlists. Microsoft documents email notifications for updated intel; CrowdStrike Elite uses PIR notifications. Insight watch terms are literal highlights only (`README.md:23, 215`).
- **Implementation notes:** New service `src/insight/services/notifications.py`. After a successful `sync_source` / `ingest` of a *new* current document, evaluate watch terms with the existing folded `search_text` / `like_pattern` path (`src/insight/services/brief.py:134-139`, `src/insight/services/triage.py`). For KEV, fire on new `date_added` in the import, not on every catalog upsert. Deliver in `jobs.py` (new handler), never inline on the request path. Store destinations only via CLI (`insight notify …`) or the workspace, **not** the API key (same rule as schedules, `src/insight/web/auth.py:183-185`). Sign webhooks (HMAC header) and include TLP, document id, and a link, not necessarily full bodies of AMBER+ reports. Respect `INSIGHT_MAX_TLP` and do not put RED/AMBER+STRICT evidence in email by default.
- **New tables or endpoints:** `notification_targets` (id, kind=`webhook|smtp`, url or address, secret hash, created_at, last_status). `notification_events` (id, trigger, object_id, sent_at, status) for audit. CLI in `src/insight/cli.py`. Optional `GET /api/notifications` (session only) to list deliveries. UI: a short panel on the Sources or Watch tab (`src/insight/ui/watch_terms.py` or `src/insight/ui/schedules.py`).
- **Sources / libraries:** Standard library `smtplib` / `httpx` (already used). Keep destinations on an allowlist (HTTPS only for webhooks).
- **Effort:** M
- **Acceptance criteria:** Tests against a fake SMTP/webhook sink (the approach already sketched in `docs/CI_CD.md` for M4). A new matching report produces one notification; a revision of the same item does not flood. Disabling the target stops delivery. API keys cannot register targets.

### 1.5 Add abuse.ch IOC connectors (URLhaus, ThreatFox, MalwareBazaar)

- **What to build:** Three new curated `SOURCES` entries that ingest recent malware URLs, network IOCs, and file hashes as TLP:CLEAR (or the source's stated label), using the existing allowlisted HTTPS connector pattern.
- **Why / which TIP capability:** Collection and IOC enrichment. This is the largest *open* collection gap: Insight has almost no malware IOC diet, while premium tools and MISP communities are full of them.
- **Implementation notes:** Extend `Source.kind` if JSON/API feeds do not fit `kev|rss|csaf` (`src/insight/connectors.py:87-140`). Add each host to `ALLOWED_HOSTS` only after `_assert_public` still applies. Reuse `fetch_if_changed`, `MAX_BYTES`, `MAX_FEED_ITEMS`, `ingest(..., ref=SourceRef(...))`, and TLP:CLEAR for public feeds. Auth keys (ThreatFox documents an auth-key) must come from env (for example `INSIGHT_ABUSECH_AUTH_KEY`), never committed, and must not be logged. Honour each API's terms and rate limits; store `external_id` stably (IOC id or hash). Wire `src/insight/ui/sources.py`, `src/insight/web/routes/sources.py`, and schedules automatically via `SOURCES`.
- **New tables or endpoints:** No new core tables if documents/entities suffice. Reuse `fetch_state` and `source_runs`. Env vars for API keys in `.env.example` and the runbook.
- **Sources / libraries:** [URLhaus API](https://urlhaus.abuse.ch/api/), [ThreatFox](https://threatfox.abuse.ch/), [MalwareBazaar API](https://bazaar.abuse.ch/api/). Review each page's authentication and redistribution terms before enabling a default schedule. Do not download malware payloads into the inbox; hashes and metadata only for MalwareBazaar.
- **Effort:** M
- **Acceptance criteria:** Offline tests with recorded fixtures (follow `tests/fixtures` and `tests/unit/test_feeds.py` / `test_kev.py` style). Each source can sync, is idempotent, creates entities (url/domain/ip/hash), and shows up in Sources + Sync all. Live tests stay behind `INSIGHT_LIVE_TESTS=1`. No sample binaries stored.

### 1.6 Add an AlienVault OTX pulse connector (implemented)

- **What to build:** Optional curated connector for OTX pulses the operator subscribes to (API key required).
- **Why / which TIP capability:** Community IOC sharing, closer to MISP-style pulses than to Mandiant IR reporting.
- **Implementation notes:** Same pattern as 1.5. Key in `INSIGHT_OTX_API_KEY`. Map pulse indicators to entities; keep pulse id as `external_id`; cap items; do not crawl full referenced articles (Insight policy at `README.md:50, 213`).
- **New tables or endpoints:** None beyond `SOURCES` + `fetch_state`.
- **Sources / libraries:** [AlienVault OTX](https://otx.alienvault.com/) (API documentation is linked from that site; require an operator key, never a built-in one).
- **Effort:** M
- **Acceptance criteria:** Without a key, the source is visible but sync fails with a clear, non-secret error. With a fixture pulse, indicators ingest once and revisions follow pulse updates. Tests never require a real key in CI.

### 1.7 Continue extraction-quality work (existing M1)

- **What to build:** Close known extractor gaps and grow the labelled corpus (`ROADMAP.md` #9).
- **Why / which TIP capability:** IOC quality. Premium tools invest heavily in validation; Insight's promise is precision-first extraction (`docs/EXTRACTION.md`). More feeds in 1.5–1.6 will otherwise inject noise.
- **Implementation notes:** `src/insight/extraction.py`, `tests/corpus/extraction.json`, `scripts/benchmark_extraction.py`, `docs/EXTRACTION.md`. Ratchet the baseline. Especially defanged indicators, as the roadmap already says.
- **New tables or endpoints:** None.
- **Sources / libraries:** Existing corpus only, plus newly permitted real reports (no leaked secrets).
- **Effort:** M (ongoing)
- **Acceptance criteria:** Benchmark does not regress. Documented gaps shrink. CI still enforces the baseline.

---

## Phase 2 — Core TIP features (interop and context)

### 2.1 STIX 2.1 export

- **What to build:** Export reports and indicators as STIX 2.1 bundles, validated on every export (`ROADMAP.md` #12).
- **Why / which TIP capability:** Sharing. Recorded Future and Microsoft document TAXII/STIX; Google TI can return STIX bundles; MISP and OpenCTI speak STIX. Insight's own README says the current export is not STIX (`README.md:36-37`).
- **Implementation notes:** New pure module `src/insight/stix_export.py` next to `src/insight/ioc_export.py`. Map: `indicator` (with pattern for IPv4/IPv6/domain/url/file hashes), `vulnerability` (CVE), `report` or `note` for document metadata, `marking-definition` for TLP, `relationship` (`indicates`, `related-to`). Include KEV context as a custom property or a `note`, not a fake intrusion set. Reuse `services.export_iocs` selection rules (`max_tlp`, review status, evidence flag). Call `stix2-validator` in tests and optionally at export time. CLI `insight export-stix FILE`, API `GET /api/iocs/stix` or `GET /api/export/stix`, UI next to Export IOCs (`src/insight/ui/ioc_export.py`, `src/insight/web/routes/exports.py`).
- **New tables or endpoints:** No new tables required. `GET /api/iocs/stix` (auth, rate-limit like IOC export). Audit event `stix.export`.
- **Sources / libraries:** [STIX 2.1 spec](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2), [stix2-validator](https://github.com/oasis-open/cti-stix-validator) (already named in `ROADMAP.md`). Pin and hash-lock via `scripts/lock.py`.
- **Effort:** M
- **Acceptance criteria:** Validator passes on fixture exports. Round-trip test: export then import (2.2) preserves indicator values, TLP, and document ids. Empty/over-limit behaviour matches IOC export. No actor objects are emitted unless the operator created them (2.5).

### 2.2 STIX 2.1 import

- **What to build:** Ingest a STIX 2.1 bundle as documents/entities (and later ATT&CK/actor objects) with TLP raising and instance `INSIGHT_MAX_TLP` enforcement.
- **Why / which TIP capability:** Same sharing story; Microsoft and MISP both ingest STIX. Required for OpenCTI/MISP interop.
- **Implementation notes:** `src/insight/stix_import.py` + `services.ingest`. Map `indicator` patterns back to entity kinds already supported by `extraction.py` / `schemas.py`. Reject or quarantine unknown pattern types. Store the bundle hash and source identity for revisions. CLI `insight import-stix FILE`, API `POST /api/import/stix` (read-write key or session + CSRF), UI in the ingest dialog (`src/insight/ui/ingest.py`, `src/insight/web/routes/documents.py` or a new `routes/imports.py`).
- **New tables or endpoints:** Optional `import_batches` (id, filename, hash, created_at, counts). `POST /api/import/stix`.
- **Sources / libraries:** Same STIX libraries as 2.1. Test with bundles produced by 2.1 and a small public ATT&CK or CISA STIX example, checking licences before committing fixtures.
- **Effort:** M
- **Acceptance criteria:** Import of Insight's own export is lossless for supported objects. A bundle labelled above `INSIGHT_MAX_TLP` is refused. Malformed bundles return 400 and write no partial documents (or a documented transaction rollback). Tests do not require network.

### 2.3 ATT&CK mapping

- **What to build:** Store MITRE ATT&CK technique (and tactic) IDs on reports or as first-class entities, with manual tagging plus conservative auto-suggest from explicit technique IDs in text.
- **Why / which TIP capability:** ATT&CK mapping, present in Google TI, Microsoft Threat analytics, MISP galaxies, and OpenCTI. Do **not** auto-assign a threat actor.
- **Implementation notes:** Load the official ATT&CK STIX dataset at build or via an opt-in "sync ATT&CK catalog" source (version-pin the dataset). New tables `attack_patterns` (id `T1059`, name, tactics, stix_id, domain) and `document_attack_patterns` (document_id, technique_id, method=`manual|extracted`, evidence offsets). Service module `src/insight/services/attack.py`. Extractor: only `T####` / `T####.###` tokens already in the report body (precision-first). UI: tag picker in the reader (`src/insight/ui/reader.py`), filters in the inbox, brief section "Techniques seen." Export in STIX as `attack-pattern` + `uses`/`indicates` relationships. CLI `insight attack-sync` to refresh the catalog.
- **New tables or endpoints:** `attack_patterns`, `document_attack_patterns`. `GET/POST /api/documents/{id}/attack-patterns`, `GET /api/attack-patterns`.
- **Sources / libraries:** [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data), [mitreattack-python](https://github.com/mitre-attack/mitreattack-python), ATT&CK site [https://attack.mitre.org/](https://attack.mitre.org/).
- **Effort:** M
- **Acceptance criteria:** Catalog sync is offline-testable from a fixture subset. Manual tags persist and survive document revisions (decide whether tags are per-revision). Auto-suggest never creates a tag from a CVE or product name alone. STIX export includes only tagged techniques.

### 2.4 MISP export and import

- **What to build:** Export a TLP-filtered, reviewed event to a MISP instance or a MISP JSON file; optionally ingest a trusted MISP feed or event.
- **Why / which TIP capability:** The practical CERT/ISAC sharing network (`https://www.misp.software/features/`). Recorded Future lists MISP as an integration. Better first sharing target than running a TAXII server.
- **Implementation notes:** After 2.1, prefer `misp-stix` or PyMISP event objects. New `src/insight/misp_export.py` / `misp_import.py`. Config: `INSIGHT_MISP_URL`, `INSIGHT_MISP_KEY` on the host only. Default export: accepted (or unreviewed-but-operator-approved) indicators, `distribution` aligned to TLP, no evidence excerpts unless asked. CLI `insight misp-export` / `insight misp-import`. Keep API keys from changing MISP destinations if you add HTTP routes (session/CLI only).
- **New tables or endpoints:** Optional `misp_push_log` (event uuid, sent_at, status). CLI-first is enough for v1.
- **Sources / libraries:** [MISP features / STIX interop](https://www.misp.software/features/), [PyMISP](https://github.com/MISP/PyMISP), [misp-stix](https://github.com/MISP/misp-stix). Pin and hash-lock.
- **Effort:** M to L
- **Acceptance criteria:** A fixture export opens as a valid MISP event (or documented MISP JSON). TLP:RED is omitted unless `INSIGHT_MAX_TLP=RED` and the operator passes an explicit flag. Import is idempotent on event UUID. CI uses fixtures, not a live MISP.

### 2.5 Actor and campaign entities (manual first)

- **What to build:** First-class `actor` and `campaign` entities the operator can create and link to reports, indicators, and ATT&CK techniques. Optional import of MITRE ATT&CK *group* catalog as **suggestions**, never as automatic attribution.
- **Why / which TIP capability:** Adversary and campaign tracking, the most visible premium gap. MISP galaxies and OpenCTI STIX objects are the honest models to copy. Insight's README forbids inferring attribution from co-occurrence (`README.md:187, 214`); keep that rule.
- **Implementation notes:** New tables `threat_actors` / `campaigns` (id, name, aliases, description, tlp, stix_id, source, created_at) and link tables to documents and entities. Services `src/insight/services/actors.py`. UI tab or reader sidebar (`src/insight/ui/entities.py`, `src/insight/ui/reader.py`). API `GET/POST /api/actors`, `/api/campaigns`, and link endpoints. STIX export emits `threat-actor` / `campaign` only for these rows. Seed ATT&CK groups from the same dataset as 2.3, clearly labelled "catalog, not a claim that they are in your reports."
- **New tables or endpoints:** As above. Audit events `actor.create`, `actor.link`, etc.
- **Sources / libraries:** ATT&CK groups in [attack-stix-data](https://github.com/mitre-attack/attack-stix-data). Later, optional pull from a local MISP galaxy or OpenCTI instance.
- **Effort:** L
- **Acceptance criteria:** An operator can create "Example Actor," link two reports, see the join in the UI, and export STIX containing that actor and relationships. No automatic actor is created when two reports share an IP. Tests cover TLP limits on actor records.

### 2.6 Optional GreyNoise community enrichment for IPs

- **What to build:** Opt-in enrichment provider `greynoise` for IP entities (benign scanner vs. suspicious vs. unknown).
- **Why / which TIP capability:** IOC enrichment / noise reduction, adjacent to what reputation services give premium tools. Helps verdicts stay honest.
- **Implementation notes:** Extend `PROVIDERS` / `enrich_cve`-style `enrich_observable()` in `connectors.py`. Add `GreyNoise` only if the operator sets `INSIGHT_GREYNOISE_KEY` (community API). Same throttle, cache table (generalize `Enrichments` beyond CVE or add `observable_enrichments`). UI next to the existing enrichment dialog (`src/insight/ui/enrichment.py`, `src/insight/ui/verdicts.py`). Never treat a GreyNoise classification as an Insight verdict automatically.
- **New tables or endpoints:** Generalize `enrichments` (provider, subject_kind, subject_value) or a new table. `POST /api/enrichment/greynoise/{ip}`.
- **Sources / libraries:** [GreyNoise docs](https://docs.greynoise.io/). Community vs paid tiers are defined there; implement only what the operator's key allows, and document it.
- **Effort:** M
- **Acceptance criteria:** No key means the action is hidden or fails closed with a clear error. Fixtures cover classify / not-found. Cached results have `fetched_at`. No auto-block from this data.

### 2.7 Link YARA and Sigma as artifacts

- **Status (unreleased):** Built, including individual rule downloads with a handling manifest. [Using rule files](THREAT_GUIDES.md#rules)

- **What to build:** Attach rule text (YARA or Sigma) to a report, CVE, actor, or malware-family label. Do **not** build a detection engine.
- **Why / which TIP capability:** Detection content. CrowdStrike documents YARA rule download; MISP exports Suricata/Snort/Zeek; Google TI describes YARA hunting. Insight should *carry* rules, not execute them.
- **Implementation notes:** Table `detection_rules` (id, kind=`yara|sigma`, name, body, source_url, content_hash, tlp, created_at) and `detection_rule_links`. Service + UI in the reader. Optional import from a local file. Hash and display; syntax-check if a library is already acceptable to pin. Include rules in STIX as `file` + `note` or a documented custom object, or export sidecar files. CLI `insight rule-add`.
- **New tables or endpoints:** As above. `GET/POST /api/rules`, `POST /api/rules/{id}/link`.
- **Sources / libraries:** [SigmaHQ](https://github.com/SigmaHQ/sigma) as a *reference* the operator may point at, not something to vendor into the image by default. Public YARA collections only when licences allow. Optional later: `plyara` or `sigma-cli` for validation, hash-pinned if added.
- **Effort:** M
- **Acceptance criteria:** A rule can be attached, listed, exported, and deleted (audited). Bodies are shown as text, never executed in the browser. TLP of the rule is at least as restrictive as requested.

### 2.8 PDF report ingestion (existing M2/M5-adjacent item)

- **What to build:** Extract text from an uploaded PDF advisory, store the original file hash as evidence (`ROADMAP.md` #13).
- **Why / which TIP capability:** Collection / ingest. Many advisories still ship as PDF; premium workbenches and OpenCTI handle this. Insight currently has no PDF/binary parsing (`README.md:213`).
- **Implementation notes:** Bounded upload (existing 2 MB body limit in `src/insight/web/boundary.py` may need a documented higher cap for PDFs, still hard-capped). Extract with a pinned library; store raw bytes outside the SQLite row if large (or hash + text only, with the file in `/data/attachments`). Ingest the text through `services.ingest` as today. No JS rendering of PDF. Virus/malware PDFs: treat as untrusted; do not follow embedded links.
- **New tables or endpoints:** `attachments` (id, document_id, sha256, media_type, size, path). `POST /api/documents` multipart or `POST /api/documents/pdf`.
- **Sources / libraries:** Prefer a well-known, pinable extractor such as `pypdf` (evaluate and lock; do not invent a choice if you later reject it for security). Keep extraction deterministic.
- **Effort:** M
- **Acceptance criteria:** A fixture PDF becomes a document with correct SHA-256, extracted text, and observations. A non-PDF or oversize file is refused. Tests do not require network.

### 2.9 Network-indicator export for Suricata or Snort

- **What to build:** Generate a simple rule or IP/domain list for accepted, unexpired, non-warning malicious network indicators (the same population as `/api/iocs/blocklist`).
- **Why / which TIP capability:** Detection content, matching MISP's Suricata/Snort/Zeek export at a smaller scale (`https://www.misp.software/features/`).
- **Implementation notes:** Extend `src/insight/ioc_export.py` and `src/insight/web/routes/exports.py` / `src/insight/cli.py`. Start with a documented `alert ip` / DNS list format and a clear header that this is not a substitute for review (`docs/IOC_EXPORT.md` already warns about blocklists). Reuse verdict + warning logic in `src/insight/flags.py` and `src/insight/services/exports.py`.
- **New tables or endpoints:** `GET /api/iocs/suricata` or `?format=suricata` on the blocklist route.
- **Sources / libraries:** Suricata/Snort rule syntax docs as the output contract; no need to bundle the engines.
- **Effort:** S to M
- **Acceptance criteria:** Only accepted, unexpired, non-warning malicious IPs/domains appear. Defanging is off in rule output (and documented as dangerous). Empty exports are refused. Tests cover warning-list exclusions.

---

## Phase 3 — Advanced

### 3.1 TAXII 2.1 server (read-only collections)

- **What to build:** A small TAXII 2.1 API root that serves the STIX bundles from 2.1 (recent KEV, accepted IOCs, optional ATT&CK-tagged reports).
- **Why / which TIP capability:** Sharing. Recorded Future documents TAXII 2.1 at `https://docs.recordedfuture.com/reference/stix-taxii-overview`; Microsoft Sentinel imports TAXII 2.0/2.1 and can export 2.1. This lets a SIEM pull from Insight without a custom client.
- **Implementation notes:** Implement only what you need (discovery, collections, objects, pagination), authenticated with the existing API key or a dedicated TAXII user. Session-cookie browsers should not be the TAXII client. Reuse TLP filters. Put routes under `/taxii2/` in `src/insight/web/`. Do not allow API-key writes to mint collections.
- **New tables or endpoints:** TAXII 2.1 discovery, `collections`, `objects`. Maybe `taxii_collections` config rows.
- **Sources / libraries:** [TAXII 2.1 spec](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html). Evaluate OASIS [medallion](https://github.com/oasis-open/cti-taxii-server) versus a thin FastAPI implementation; only add a dependency if it can be hash-pinned and trimmed to read-only. Test with a public TAXII client library such as [taxii2-client](https://github.com/oasis-open/cti-taxii-client).
- **Effort:** L
- **Acceptance criteria:** A TAXII 2.1 client with a valid key can list collections and pull objects that match a STIX export of the same filter. An unauthenticated client is denied. Pagination works. CI uses the client against the test app.

### 3.2 Ranked search and a graph view

- **What to build:** Full-text relevance ranking and a graph of reports, indicators, CVEs, techniques, and (if present) actors (`ROADMAP.md` #17).
- **Why / which TIP capability:** Search and graphing. OpenCTI's knowledge graph and Google's workbench graphs are the UX to aim at, at pilot scale.
- **Implementation notes:** Search: improve `src/insight/services/search.py` (SQLite FTS5 and PostgreSQL `tsvector` behind the same service API; keep folded matching). Graph: API `GET /api/graph?seed=…` returning nodes/edges from existing links (observations, KEV, ATT&CK, actor links). UI: a new panel, lazy-loaded, capped (Insight is still a pilot; `README.md:216`).
- **New tables or endpoints:** Possible FTS shadow tables. `GET /api/graph`.
- **Sources / libraries:** SQLAlchemy + native FTS. For UI, a small graph component that can be vendored or pinned; keep accessibility in mind (ADR 0017).
- **Effort:** L
- **Acceptance criteria:** Ranked search has tests on both SQLite and PostgreSQL. Graph of a fixture report set is deterministic and capped. Keyboard and contrast rules still pass.

### 3.3 Exploit-availability context

- **What to build:** Optional flags on a CVE: public PoC mentioned, Metasploit module mentioned, or membership in an *additional* KEV-like catalog, without storing exploit payloads.
- **Why / which TIP capability:** Vulnerability prioritization beyond CVSS and EPSS. Recorded Future's vuln cards include exploitation evidence and EPSS; Insight should stay metadata-only.
- **Implementation notes:** New columns or an `exploit_signals` table (cve, source, signal, url, fetched_at). Connectors must be allowlisted and terms-reviewed. Prefer metadata APIs over scraping GitHub. Never ingest exploit code into `documents.body` by default.
- **New tables or endpoints:** `exploit_signals`. Fields on `GET /api/entities` for CVE kind. Brief line when a *new* KEV also has a public-PoC signal.
- **Sources / libraries:** [VulnCheck KEV](https://www.vulncheck.com/kev) only if the published terms allow your use and any required key is operator-supplied. FIRST EPSS and CISA KEV remain the default, already-wired sources. Exploit-DB or GitHub code search only after a written ToS/redistribution review; skip them if unclear.
- **Effort:** M to L
- **Acceptance criteria:** Signals are cached with source and time. No payload bytes in the database. Missing sources degrade cleanly. Legal/ToS notes live in `docs/SECURITY.md` or the runbook.

### 3.4 OIDC sign-in and RBAC

- **What to build:** Identity-provider login, roles, and an authorisation matrix (`ROADMAP.md` #14).
- **Why / which TIP capability:** Multi-user, RBAC, and audit. MISP already has this; OpenCTI advanced RBAC/SSO is Enterprise Edition. Required before Insight is a shared SOC tool. Keep the current single-operator mode as the default.
- **Implementation notes:** New identity tables (`users`, `roles`, `user_roles`) and map sessions to a user id. OIDC against the operator's IdP. Roles such as `viewer`, `analyst`, `admin`. `services.set_actor` already records a string actor (`docs/SECURITY.md:17`); switch it to `user:<id>` / `role`. TLP recipient groups can come later; do not claim them in v1. Authenticated ZAP active scan, as the official roadmap says. CLI remains a host-admin break-glass.
- **New tables or endpoints:** `users`, `roles`, OIDC callback routes. `/login` grows an "Sign in with SSO" path without removing the existing password path until SSO is required.
- **Sources / libraries:** A pinable OIDC client compatible with FastAPI (evaluate before adding; hash-pin). Follow `docs/adr/0012` and `0015` so API keys stay CLI-minted.
- **Effort:** L
- **Acceptance criteria:** A second user can be a viewer and cannot ingest, sync, or change schedules. Analyst can triage but not mint keys or notification destinations (admin only). Architecture tests prevent routes from dropping `require_auth`. Existing single-operator deployments upgrade with a single admin user and keep working.

### 3.5 Multi-worker sessions and rate limits

- **What to build:** Move rate-limit state (and any remaining process-local locks that must be shared) out of one process (`ROADMAP.md` #16). Sessions are already in the database.
- **Why / which TIP capability:** Reliability when you scale past `uvicorn` `workers=1` (`src/insight/cli.py:606-607`). Premium products are multi-tenant; this is just so Insight does not break if you add workers.
- **Implementation notes:** Keep `RateLimiter.hit` as the interface (`src/insight/ratelimit.py`, ADR 0012). Back it with Redis or PostgreSQL. Job runner must still run in **one** process (`INSIGHT_RUN_JOBS`). Document the topology in the runbook.
- **New tables or endpoints:** Possibly `rate_limit_buckets` if you avoid Redis.
- **Sources / libraries:** Redis only if you are willing to operate it; otherwise a Postgres-backed limiter. Do not add a dependency lightly.
- **Effort:** L
- **Acceptance criteria:** Two app workers share rate limits and do not issue duplicate scheduled syncs. Tests simulate two processes. Single-worker SQLite installs remain the default.

### 3.6 Opt-in LLM assistant (existing design contract)

- **What to build:** Optional, off-by-default proposals for summaries or ATT&CK *suggestions*, stored as reviewable claims, never as facts (`docs/LLM_EXTENSION.md`).
- **Why / which TIP capability:** AI features (Gemini, Copilot, OpenCTI EE). Insight's brief should remain the authoritative deterministic summary. Use the model only as an assistant.
- **Implementation notes:** Implement the `AnalystAssistant` protocol already written in `docs/LLM_EXTENSION.md`. Store provider, model, version, timestamp, document hash, spans, and review state. Default to a local endpoint. No silent send of AMBER+ or RED text off-box. No tool execution. Gate with the evaluations the doc lists. UI must label output as "proposal."
- **New tables or endpoints:** `model_proposals`. `POST /api/documents/{id}/propose` (session only).
- **Sources / libraries:** Operator-chosen local or remote API. No vendor is baked in.
- **Effort:** L
- **Acceptance criteria:** Default installs make zero model calls (tested). A proposal cannot change verdicts or ingest without an analyst click. TLP policy is enforced before any outbound prompt. Evaluation notes are checked in or linked.

### 3.7 Optional Shodan or Censys enrichment (operator-supplied keys)

- **What to build:** Optional exposure context for IPs/domains, clearly labelled as a paid/optional API.
- **Why / which TIP capability:** Attack-surface context. Recorded Future sells this as a separate capability; Insight should only offer it if the operator already has a key.
- **Implementation notes:** Same enrichment framework as 2.6. Keys in env. Allowlist hosts. No default schedule that would exhaust credits. Document that pricing is set by those vendors (quote or their published plans — do not copy prices here).
- **New tables or endpoints:** Reuse observable enrichments. `POST /api/enrichment/shodan/{ip}` (or censys), disabled without a key.
- **Sources / libraries:** Official Shodan and Censys API docs, added only after a terms review. Not required for MVP parity with MISP.
- **Effort:** M
- **Acceptance criteria:** No key, no calls. Fixtures for the parser. Credits/quota errors are visible in the UI.

### 3.8 Lightweight case management

- **What to build:** A case object that groups reports, indicators, notes, and (later) actors into one investigation the operator can close.
- **Why / which TIP capability:** OpenCTI advertises centralized case management; premium SOCs live in cases, not inboxes. Insight lists "no … case management" at `README.md:212`.
- **Implementation notes:** Tables `cases` and `case_items`. Services + a Cases tab. Link from the inbox and reader. Optional webhook when a case is opened (reuses 1.4). Do not build a SOAR.
- **New tables or endpoints:** `cases`, `case_items`. `/api/cases` CRUD.
- **Sources / libraries:** None required.
- **Effort:** L
- **Acceptance criteria:** A case can collect two reports and one entity, show a timeline of audit events, and close with a note. TLP of the case is the max of its items. Tests cover delete/unlink.

### 2.10 Industry threat profiles and actor threat guides (requested 2026-11-21)

- **What to build:** The analyst picks an industry (for example healthcare, energy or finance). Insight lists the
  **top ten threat groups known to target it**, each with the evidence for listing it. The analyst opens one group
  and **exports a threat guide**: its names and aliases, the industries and regions it targets, how it operates
  (ATT&CK techniques by tactic, with a Navigator layer), its tools and malware, its activity in the analyst's own
  reports, what to check and defend first (ATT&CK mitigations and detections), and the sources for every claim.
- **Threat hunt section (requested 2026-11-21):** the guide must be usable to **start a hunt**, not only to read:
  - **Hunt hypotheses** per technique the group uses, worded as "If GROUP is active here, expect TECHNIQUE: look
    in DATA SOURCE for BEHAVIOUR", built from ATT&CK's data sources, detection notes and data components, highest
    priority first (techniques also trending in the analyst's reports, then the group's most-used ones).
  - **Where to look:** the log and telemetry sources each hypothesis needs (process creation, authentication,
    DNS, proxy, e-mail, cloud audit), so the hunter can check coverage before starting.
  - **Indicator sweep list:** the group's indicators from the analyst's own reports (accepted, not expired, not on
    a warning list, within the export's TLP limit), downloadable in the IOC export formats (CSV, JSON) for a
    retro-hunt in the SIEM or EDR, each with its first and last seen dates and source report.
  - **Detection content:** Sigma and YARA rules the analyst linked to the group or its techniques (TIP 2.7), and
    references to public rule sets, carried as text and never run by Insight.
  - **A hunt record:** a checklist per hypothesis (data checked, time range, result: nothing found, suspicious,
    confirmed) that the analyst can fill in and keep with the guide, so hunts are repeatable and their outcome
    feeds back as notes or verdicts.
  - Hunt text follows the same rules: facts from cited catalogs and the analyst's data, no AI-written queries;
    ready-made SIEM queries only from sources whose licences allow it.
- **Why / which TIP capability:** Threat profiling for priority intelligence requirements. Premium platforms lead
  with "who targets my sector"; analysts use it to brief leadership and to choose which defences to test first.
- **It needs a threat library:** a bundled, regenerable catalog of threat groups, like the ATT&CK catalog
  (TIP 2.3), with a source for every claim:
  - **MITRE ATT&CK groups** (intrusion sets) from the bundle Insight already reads: names, aliases, descriptions,
    techniques and software used, references. ATT&CK has no structured industry field; sectors appear only in
    its prose.
  - **Structured targeting data** for industries and regions, such as the MISP galaxy threat-actor cluster
    (target categories, suspected victims). Check each source's licence before bundling it, keep provenance per
    field, and avoid non-commercial licences (Insight is redistributable).
  - **Insight's own reports:** literal matches of a group's names and aliases (like watch terms) give "named in N
    of your reports, last on DATE"; analyst-created actors and links come from TIP 2.5.
- **Ranking, never a hidden score:** a group is listed only if a cited catalog entry names the industry; the order
  is by mentions in the analyst's reports in the last 90 days, then the most recent publicly reported activity,
  then ATT&CK coverage. Each line shows why it is there. A listed group is not a claim that it targeted the
  analyst's organisation, and Insight still never infers attribution from shared indicators.
- **Implementation notes:** `scripts/update_actors.py` (like `update_attack.py`) builds
  `src/insight/data/actors.json`: groups, aliases, industries and regions with their source, techniques, software,
  references. A small fixed industry list maps the catalogs' labels. The guide export follows the landscape
  briefing (ADR 0020): Markdown and print, TLP-marked from the reports it cites (CLEAR when it uses only public
  catalogs), plain language (ADR 0017), catalog text quoted with attribution under its terms, no AI-written text.
- **New tables or endpoints:** none for the bundled catalog; TIP 2.5's `threat_actors` holds the analyst's own
  groups and corrections. `GET /api/industries`, `GET /api/industries/{key}/actors`, `GET /api/actors/{id}/guide`
  (Markdown, audited). UI: an **Industry threats** view (industry picker, top-ten list with evidence) and a group
  page with **Export threat guide**.
- **Sources / libraries:** [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) (already used;
  terms in `NOTICE`); [MISP galaxy](https://github.com/MISP/misp-galaxy) (licence to confirm before bundling).
- **Effort:** L (catalog and industry mapping M; ranking and views M; guide export S to M).
- **Status (unreleased):** built. See [ADR 0025](adr/0025-threat-guides.md) and [THREAT_GUIDES.md](THREAT_GUIDES.md).
  Differences from this plan: TIP 2.5 and 2.7 were built at their minimum (`threat_actors`, `actor_documents`,
  `industry_claims`, `detection_rules`, `rule_links`, `hunts`, `hunt_checks`; migration `0014`), the guide is also
  exported as JSON, a Navigator layer and a sweep list, and `insight threat-library-sync` fetches a fuller copy of
  the same pinned releases. No print layout yet; the Markdown export prints.
- **Acceptance criteria:** Choosing an industry lists at most ten groups, each with the catalog source naming the
  industry and its count in the analyst's reports; a group not named for that industry is never listed; a guide
  exports with aliases, industries, techniques by tactic and a Navigator layer, tools, mitigations, the analyst's
  reports that name the group, sources, and a TLP marking; TLP limits apply to the report counts and titles in it;
  wording passes the plain-language checks; the hunt section lists hypotheses with their data sources for every
  technique in the guide, an indicator sweep list that honours TLP and warning lists, linked rules, and a hunt
  record the analyst can save.

---

## Phase 4 — An intelligence program (planned 22 November 2026)

By 0.9.0 Insight covers the basics a premium TIP offers. What it still lacks against the 2026 market leaders
is the intelligence craft around them: requirements, confidence, analytic products and infrastructure pivots.
Proprietary collection (dark web, telemetry, human sources) stays out of scope.

**Boundary with hunting and response.** Insight owns the intelligence cycle: requirements, collection,
analysis, finished products and dissemination. Hunting against an organisation's own telemetry, detections,
incidents and response belong to a separate tool (the maintainer's is Shift). Insight feeds such tools over
open standards (TAXII 2.1 and STIX 2.1), so it stays a standalone TIP that any SIEM or hunt tool can use.
What comes back is intelligence, not response: **sightings** ("seen in our environment, at this time") and
**requests for information**. Insight never records what was done about an indicator. Its hunt records
(TIP 2.10) and cases (TIP 3.8) get no new response features: 4.3 replaces hunt tracking with hunt packages,
and 4.4 turns cases into intelligence products.

### 4.1 Intelligence requirements and requests for information

Priority intelligence requirements (PIRs), the narrower intelligence requirements (IRs) under them, and
requests for information (RFIs), each a question with a stakeholder, a priority and a TLP. A requirement
lists what makes a report relevant (terms, CVEs, ATT&CK techniques, actors, campaigns); Insight shows which
requirements each report addresses, which have gone quiet, and the evidence behind each answer. RFIs can be
posted by an API key with the new `rfi` scope, so a hunt tool can ask a question without reading anything.
Peers: ThreatConnect, Flashpoint Ignite, Anomali ThreatStream, Silobreaker, OpenCTI Enterprise Edition.

### 4.2 Confidence, source reliability and sightings

Admiralty grades per source (reliability A–F) and per assessment (credibility 1–6), an indicator confidence
built from which sources agree and how recently, ageing per source and indicator type, source statistics
(what a feed added that nothing else did, how often its indicators were rejected), and a sightings API
(STIX `sighting`) whose sightings are the strongest confidence signal. Peers: ThreatQ, ThreatConnect, Cyware,
Google Threat Intelligence, MISP decaying models.

### 4.3 Hunt packages over TAXII

A hunt package is a hypothesis, its ATT&CK techniques, indicators, the linked Sigma, YARA, Suricata or Snort
rules (STIX indicators with those `pattern_type`s) and the intelligence context, served in a *Hunt packages*
TAXII collection. Running hunts and recording their results belongs to the hunt tool; Insight's hunt record
stops growing.

### 4.4 Finished intelligence products

Cases become analytic products: bottom line up front, key judgements with standard estimative language and
confidence, intelligence gaps, linked evidence, a TLP never below the strictest source cited, and export to
PDF, Markdown and STIX `report`. Peers: EclecticIQ, OpenCTI.

### 4.5 Operator-defined sources

RSS or Atom feeds and TAXII collections added in Settings, switched off by default, each with its own TLP and
redistribution rule (review J3).

### 4.6 Infrastructure pivots

Part 1 implements RDAP and RIPEstat lookups, shared consent/cache policy, Settings switches and graph views.
Certificate transparency and passive DNS remain separate planned parts.
See [ADR 0037](adr/0037-infrastructure-pivots.md). This item stays unchecked until all parts pass their gates.

Manual, approved-per-lookup, metadata-only pivots that land in the link map: RDAP, certificate transparency
(crt.sh), IP-to-ASN, and passive DNS where the operator has access (for example CIRCL for vetted users).

### 4.7 Adversary library imports

**Done (unreleased).** Both pinned library editions cover current ATT&CK malware and tools, their techniques,
and the groups that use them. Aliases retain their MISP or ATT&CK provenance. Format 1 editions still load.
Analysts can link reports, actors and campaigns to software and share those decisions through STIX and TAXII.
Actor guides include a dated, TLP-filtered timeline. Software Navigator layers show catalog techniques;
software-only techniques in actor layers have score zero. [ADR 0038](adr/0038-adversary-library.md) and
[threat guides](THREAT_GUIDES.md).

### 4.8 Read-only MCP endpoint

Model Context Protocol access for AI agents, using API keys and their TLP ceilings. Insight itself still
writes nothing with a model ([LLM_EXTENSION.md](LLM_EXTENSION.md); 3.6 stays separate and opt-in).
Eight read tools share a stateless `POST /mcp` endpoint for protocols 2026-07-28 and 2025-11-25.
The per-key sharing ceiling applies to each result. [MCP guide](MCP.md), [ADR 0039](adr/0039-read-only-mcp.md).

---

## 4. Implementation order

[ROADMAP.md](../ROADMAP.md) assigns these items to releases. Within and across phases:

- Phase 0 first (0.1 can run in parallel with the others).
- Phase 1: 1.1 → 1.2 → 1.3 (the vulnerability vertical), then 1.4 (alerts), then 1.5 / 1.6 (feeds); 1.7 is ongoing.
- Phase 2: 2.1 before 2.2, 2.4 and 3.1; 2.3 before 2.5's ATT&CK seeding; 2.6 and 2.8 can proceed in parallel;
  2.7 and 2.9 after the export patterns exist; 2.10 after 2.3 (done) and with or after 2.5.
- Phase 3: 3.1 after 2.1; 3.4 before treating Insight as multi-user; 3.6 only after evaluation hooks exist;
  3.7 last and optional.
- Phase 4 is required for 1.0 (Andrew, 22 November 2026): 4.1 → 4.2 → 4.3 → 4.4 (the intelligence cycle and
  the hunt-tool contract), then 4.5–4.8 in any order. 4.2's sightings and 4.3's collection extend the TAXII and API contract that 4.1's RFI intake starts.

Three items from the 0.5.0 review are prerequisites that this plan does not list:

- **B2, throttles and locks into services**, before 1.2: automatic enrichment must use the same throttle as the
  manual lookup, not a third copy of it.
- **J3, per-source redistribution rules** (allow, or metadata only), before 1.5 / 1.6 add feeds with their own
  terms and before 2.1 / 2.4 / 3.1 send publishers' text to other tools.
- **D2, e-mail and CIDR indicator kinds** (implemented for 0.8.0), before 2.1: STIX patterns and MISP
  attributes use these kinds. E-mail indicators carry the personal-data warning flag (review J1).

## 5. Checklist

### Phase 0 — Fixes (6)

- [ ] **0.1** Live deployment: anonymous `/` is 303 `/login`; public `.env` uses secure cookies, allowed hosts, trusted proxies, preferably MFA
- [x] **0.2** Fix `README.md:74` and `:212`, `docs/ARCHITECTURE.md:130-132`, and mark roadmap #10 done
- [ ] **0.3** Stronger startup warnings / optional `INSIGHT_REQUIRE_HARDENED` for internet-facing installs
- [x] **0.4** Pin connector connections to DNS addresses already checked as public (code review L1)
- [x] **0.5** `/health` reports liveness. `/api/session` returns the version after sign-in.
- [x] **0.6** Encrypt TOTP secrets at rest and migrate existing pairings

### Phase 1 — Quick wins (7)

- [ ] **1.1** Persist KEV ransomware / vulnerability name / notes / CWEs (done, ADR 0024); document inbox policy (open)
- [x] **1.2** Auto-enqueue NVD and EPSS lookups for new CVEs (opt-in, throttled): done, ADR 0023, with review B2 and C2
- [x] **1.3** Brief uses ransomware flag, NVD CVSS, and EPSS (fact-only wording): done, ADR 0024, with a prioritised CVE view
- [x] **1.4** Webhook/email notifications for watch-term hits and new KEV (`ROADMAP` #15)
- [x] **1.5** abuse.ch URLhaus, ThreatFox, and MalwareBazaar connectors (metadata/IOCs only)
- [x] **1.6** AlienVault OTX subscriptions with an operator API key, bounded to explicitly public CLEAR/WHITE pulses
- [x] **1.7** 0.8.0 extraction-quality corpus expansion and benchmark ratchet (`ROADMAP` #9, ongoing)

### Phase 2 — Core TIP features (10)

- [x] **2.1** STIX 2.1 export, validated (`ROADMAP` #12)
- [x] **2.2** STIX 2.1 import with TLP enforcement
- [x] **2.3** ATT&CK catalog, report and analyst tags, and TLP-marked technique references in STIX Reports
- [x] **2.4** MISP export/import (host CLI). [Event files and trusted instance exchange](MISP.md)
- [x] **2.5** Manual actors and campaigns with TLP-marked report, indicator and technique links in STIX exports
- [x] **2.6** Optional GreyNoise community IP enrichment
- [x] **2.7** YARA and Sigma rules with report, actor, technique, CVE and malware-family links and a downloadable rule file and manifest
- [x] **2.8** PDF advisory ingest with file hash (`ROADMAP` #13)
- [x] **2.9** Suricata and Snort 3 alert rules for the IP and domain blocklists
- [x] **2.10** Industry threat profiles (top ten groups per industry, with evidence) and exportable actor threat guides with a threat hunt section (hypotheses, data sources, indicator sweep list, linked rules, hunt record); needs a bundled threat-group library: done, ADR 0025, [THREAT_GUIDES.md](THREAT_GUIDES.md)

### Phase 3 — Advanced (8)

- [x] **3.1** Read-only TAXII 2.1 server over STIX collections: done, ADR 0026, [TAXII.md](TAXII.md)
- [x] **3.2** Ranked search and graph view (`ROADMAP` #17): done, ADR 0027
- [x] **3.3** Exploit-availability signals (metadata only, terms-reviewed sources): done, ADR 0028 (report signals and VulnCheck KEV; Exploit-DB and GitHub not contacted)
- [ ] **3.4** OIDC and RBAC (`ROADMAP` #14)
- [ ] **3.5** Shared rate limits for multi-worker deploys (`ROADMAP` #16)
- [ ] **3.6** Opt-in LLM proposals per `docs/LLM_EXTENSION.md`
- [x] **3.7** Optional Shodan/Censys enrichment (operator keys; vendor-priced): Shodan done, ADR 0031; Censys deferred
- [x] **3.8** Lightweight case management: done, ADR 0029 (no webhook on open)

### Phase 4 — An intelligence program (8)

- [x] **4.1** Intelligence requirements (PIR, IR) and requests for information, with RFI intake for API keys:
  done, ADR 0032
- [x] **4.2** Admiralty grades, indicator confidence and ageing, source statistics (ADR 0033); sightings API (ADR 0035)
- [x] **4.3** Hunt packages (Sigma, YARA, Suricata, Snort as STIX indicators) in a TAXII collection (ADR 0034)
- [x] **4.4** Finished intelligence products (key judgements, estimative language, PDF/Markdown/STIX):
  ADR 0036
- [ ] **4.5** Operator-defined RSS/Atom and TAXII sources
- [ ] **4.6** Infrastructure pivots: RDAP, certificate transparency, ASN, passive DNS
- [x] **4.7** Adversary library imports: sourced group aliases, software links and sharing, actor timelines and Navigator layers (ADR 0038)
- [x] **4.8** Read-only MCP endpoint for AI agents, with eight tools and per-key sharing ceilings (ADR 0039)

**Total: 39 items.** Out of scope on purpose: cloning CrowdStrike/Mandiant/Recorded Future collection, building a malware sandbox, automated adversary attribution, and any always-on cloud AI.

---

## 6. Document history

Written 21 November 2026 from the Insight 0.6.0 source and official vendor documentation, then adapted for the
repository: the release order lives in `ROADMAP.md`, deployment-specific notes are kept out of this public file,
and item 0.2 is done. Phase 4 added 22 November 2026 after comparing 0.9.0 with the 2026 TIP market and
setting the boundary with hunting and response tools.
