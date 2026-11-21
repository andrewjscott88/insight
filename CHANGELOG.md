# Changelog

## Unreleased

### STIX 2.1 export

- Export indicators, CVEs and report provenance with TLP 2.0 markings from the workspace, the CLI
  (`insight export-stix FILE`) or `GET /api/iocs/stix`. Every bundle is validated locally before download.
  The existing report, review and publisher sharing rules apply. [Export guide](docs/IOC_EXPORT.md#stix-21-export)

### Optional indicator feeds

- The Sources tab can now sync URLhaus, ThreatFox and MalwareBazaar using an operator's abuse.ch key.
  The feeds start switched off. They ingest recent indicator metadata and keep source evidence in Insight.
- Added optional AlienVault OTX subscription sync. With your own key, Insight imports public CLEAR/WHITE
  pulses as reports and links revisions to their OTX pulse ID. [Runbook](docs/RUNBOOK.md#8-sources-enrichment-and-their-failures).

**Upgrading from 0.6.0:** migrations `0009` (ATT&CK technique tags), `0010` (source switches), `0011`
(alerts), `0012` (CVE lookup failures) and `0013` (more KEV fields; the next KEV sync fills them) run at start-up, or with `make migrate`. Reports stored before the upgrade get their technique tags when you run
`make attack-backfill` once (safe to run again). The new threat-research sources start switched off: Insight
contacts no new host until you switch one on. **Exports change for SANS ISC and NCSC reports:** their text and
evidence are no longer included (their publishers allow metadata only). Every 0.6.0 API field is unchanged; new
fields are additive. TLP-limited API keys may now read cached CVE scores (`GET /api/cves/{cve}/scores`) for
CVEs in reports they can see; starting a lookup stays refused to them. The new password-free access
(`INSIGHT_DEV_NO_AUTH`) is off unless you set it to `on`.

### More defanged indicators in reports

- The extractor now recognizes web links beginning with `[http]://` or `[https]://`, plus e-mail addresses
  written with `[at]` or `(at)`. The highlighted text keeps the spelling from the source report.
- New reports and revisions record extractor version `regex-v5`. The benchmark includes three attributed
  U.S. government advisory excerpts and four new synthetic cases.

### E-mail addresses in reports

- Insight can highlight an e-mail address in its source report and show other reports that mention the same
  mailbox. Each address carries a personal-data warning. IOC exports can filter out entries with that flag.
- E-mail support was introduced with `regex-v4`. Earlier reports keep their original observations and review decisions.

### Network ranges in reports

- Insight now recognizes IPv4 and IPv6 network ranges (CIDR). Analysts can review a whole range,
  find other reports that mention it, and include it in indicator exports. The original spelling stays in
  the evidence. CIDR support was introduced with `regex-v3`. Insight skips the universal networks
  `0.0.0.0/0` and `::/0`, which occur in firewall and cloud rules.
- **IOC exports:** the default now includes `cidr` entries. Select the previous kinds with `--kind` or the API's
  `kinds` field. Consumers that validate indicator kinds need the updated schema.

### Manage alert destinations on the host

- `insight notify` lists, adds, enables, disables and removes destinations. It reads new addresses from
  a hidden prompt or standard input and saves JSON signing keys to a new owner-only file. The list shows the name, ID, style, state and TLP limit.

### Added: a prioritised CVE view, and a brief that uses ransomware use, NVD and EPSS (TIP 1.3)
- **Prioritised CVEs** tab and `GET /api/cves` ([ADR 0024](docs/adr/0024-prioritised-cves.md)): the CVEs in your
  reports, most urgent first by stated rules: used in ransomware (CISA KEV), known exploited, likely to be
  attacked soon (EPSS 10% or more), critical (CVSS 9 or more), high (CVSS 7 or more). Each row says why it is
  there, lists the facts behind it and opens its newest report. Follows the TLP limit; the demo is left out.
- **The brief:** *Exploited now* lists ransomware-linked entries first; the summary says how many; new findings
  **Used in ransomware attacks** (first) and **Likely to be attacked soon** (with the EPSS caveat). *Most
  severe* now also uses NIST NVD's score for any CVE a new report mentions, says where each score comes from,
  and shows NVD's beside a CISA advisory's when they differ.
- **More of CISA KEV (TIP 1.1):** the weakness name, known ransomware use, notes and CWEs are kept (migration
  `0013`), and the reader shows ransomware use and the name beside a CVE. KEV report text is unchanged.

### Fixed: field labels no longer overlap their examples
- An empty field showed its label and its example on top of each other (for example "Watch term" over
  "e.g. Palo Alto, VPN, identity"). The example now appears only once the label has moved up, as the
  framework intends; the readable colour of examples is unchanged.

### Security: fixes from the 2026-11-21 code review
- **M1, sign-in lockout:** 30 wrong passwords a minute from anyone used to refuse every sign-in, the right
  password included, and the operator's attempt waited behind every pending bad guess. The backstop now
  refuses only wrong passwords (still after the 1 s delay), and the delay no longer holds the check lock
  ([ADR 0002](docs/adr/0002-login-delay-not-lockout.md)).
- **M2, one bad CVE could stop NVD scoring:** a CVE NVD cannot answer for is now set aside with a growing wait
  (1 hour, doubling up to 7 days) while the rest of the batch goes on; the job fails only when every CVE in it
  failed or the provider itself is unavailable. Migration `0012` adds `lookup_failures`
  ([ADR 0023](docs/adr/0023-automatic-cve-lookups.md)).
- **M3, the image's Python was not fully tested:** the container ships Python 3.15 (a Dependabot bump), but
  pull requests ran the full suite on 3.11 and 3.14 only. 3.15 is now in the test matrix and the package
  classifiers. Add `Tests (Python 3.15, SQLite)` to the required checks on `main` (docs/CI_CD.md).
- **L1, DNS rebinding (TIP 0.4):** source syncs, CVE lookups and alert webhooks resolved a host to check it and
  again to connect, so a changing DNS answer could reach loopback, a private network or cloud metadata. They
  now connect to the checked address, keeping the host name for TLS and the `Host` header, and judge
  IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) by the address they reach.
- **L2, plain-text TOTP seed (not fixed yet):** encrypting the authenticator seed at rest needs the
  `cryptography` package, which has to be added through the lock workflow first. Tracked by a strict
  expected-failure test and documented in docs/SECURITY.md; protect backups like `.env` meanwhile.
- **L3, watch terms for TLP-limited keys:** `GET /api/watch-terms` is now refused (`403`) to TLP-limited API
  keys, like the audit log: terms often name clients, internal hosts or sensitive projects.
- **L4, the demo through an API key:** `POST /api/demo` is now for browser sessions only (keys get `403`), and
  the demo leaves out reports above `INSIGHT_MAX_TLP` instead of storing its AMBER+STRICT report past the limit.
- **L5, one lock for every background job:** source syncs, CVE lookups and alert deliveries shared the sync
  lock, so a lookup batch made *Sync all* answer `409` and alerts waited behind long syncs. They now run in
  separate lanes, side by side, each with its own lock; only syncs share the lock of *Sync now*
  ([ADR 0018](docs/adr/0018-opt-in-scheduled-syncs.md)).
- **L6, downloads without an overall time limit:** the 25 s timeout applied to each read, so a server sending a
  little data every 24 s could stretch one sync out for hours. Every download now stops after 120 seconds and is
  recorded as a failed fetch.
- **L7, CI images pinned by tag:** gitleaks (with the repository mounted), ZAP (on the host network) and the
  rehearsal's registry now run from digests, and `scripts/check_pins.py` fails on any third-party `docker run`
  image that is not pinned by digest. Dependabot does not update these; docs/CI_CD.md says how to.
- **N1, spreadsheet formulas in the blocklist CSV:** a cell starting with `=`, `+`, `-`, `@`, a tab or a carriage
  return now gets a leading `'`, so a spreadsheet shows it as text.
- **N2, the CVE due list:** the 15-second check for CVEs to look up now filters in the database (`NOT EXISTS`,
  `LIMIT`) instead of loading every CVE and cache row.
- **N3, a stale gitleaks exemption:** the test's fake API key carries an inline `gitleaks:allow`, so scans of
  the working tree stay clean wherever the line moves; the history fingerprint stays for `gitleaks detect`.
- **N4, the password's length:** sign-in pads the supplied and stored password to one fixed width before the
  constant-time comparison (no hashing), so response times no longer hint at its length. (The first version
  compared SHA-256 digests, which CodeQL flags as weak password hashing.)
- **N5, formatting:** the Python examples in docs/ALERTS.md, docs/API.md and docs/LLM_EXTENSION.md are
  formatted, so `ruff format --check .` passes on the whole repository.

### Changed: a clearer executive brief (from #39)
- Keep the **Insight** name and symbol; use **Cyber Threat Intelligence Feed** as the tagline and remove
  **Collect. Connect. Understand.** The threat landscape now leads the page, above the report tools.
- The threat landscape adds **What needs attention**: plain findings (known exploitation, a recurring topic or
  vendor, the highest severity, your watch terms, the last 24 hours), each with a conditional next step and
  links to its evidence; a **Last 24 hours** count beside the executive summary; and **About this brief**, the
  limits of the data and how fresh each source in use is.
  **Exploited now** and **Most severe** remain separate: known exploitation and technical severity are
  different signals. Repeated reporting is described as attention in collected sources, never as proof that
  attacks are increasing or that the operator's systems are affected.
- `GET /api/brief` retains `days`, `since`, `summary` and `sections`, and adds `as_of`, `recent_reports`,
  `report_count`, `source_count`, `highlights` and `coverage`. The brief uses stored reports and public KEV
  context; it makes no external AI call or new source request. Counts and evidence respect the caller's TLP
  limit. No database migration is needed. Field reference: [API](docs/API.md#executive-brief).
- Design, evidence rules and limits: [Executive brief](docs/EXECUTIVE_BRIEF.md).
- Phone header controls wrap at narrow widths, including temporary open access with larger text at 320 px.
  Long feed titles, URLs and source names wrap within their cards and opened reports instead of being cut off.
  Report review controls and extracted values also stay within a narrow reader.

### Added: temporary password-free operator access
- `INSIGHT_DEV_NO_AUTH=on` lets a visitor enter through `/login` without a password. It is **off by default**,
  rejects invalid values and cannot be combined with MFA. Password and signing-secret configuration remain
  required. On a public domain, enabling it deliberately gives anyone access to reports and operator tools.
- This mode uses normal expiring sessions, CSRF and same-origin checks; direct API calls still need a
  session or key. Turning it off and restarting with the changed environment invalidates open-mode sessions
  and restores the retained password. A workspace notice identifies the active mode.
- Configuration, consequences and restoration checks: [Runbook](docs/RUNBOOK.md#temporary-password-free-access)
  and [security record](docs/SECURITY.md#temporary-public-operator-access). The switch has no automatic expiry.

### Added: automatic CVE lookups at NIST NVD and FIRST EPSS (TIP 1.2)
- **Severity and attack likelihood beside every CVE** ([ADR 0023](docs/adr/0023-automatic-cve-lookups.md)): the
  reader shows a line such as "CVSS 9.8 (Critical), NIST NVD · EPSS 4.2% chance of exploitation attempts within
  30 days, higher than 91% of CVEs (FIRST)", and the lookup dialog shows the parsed scores, NVD's description and
  weakness types, with the provider's raw answer one click away (review C2).
- **Automatic lookups**, off until switched on per provider in the **Sources** tab (audited): the job runner looks
  up CVEs from current TLP:CLEAR and GREEN reports, newest first, and refreshes EPSS weekly and NVD monthly. CVEs
  seen only in AMBER or RED reports are never looked up by themselves; only CVE numbers are sent.
- **One throttle per provider** shared by people, the API and the job runner (review B2): NVD every 6.5 s, or
  every 0.7 s with the new optional `INSIGHT_NVD_API_KEY`; EPSS every second. EPSS and NVD no longer share one
  window, so a lookup at one never makes the other wait.
- `GET /api/cves/{cve}/scores` reads the cached scores without contacting anyone, following the caller's TLP
  limit.
- Insight shows NVD's notice where NVD data appears: "This product uses the NVD API but is not endorsed or
  certified by the NVD."

### Added: alerts (#15)
- **Alerts when a new report mentions a watch term, or CISA adds a KEV entry** ([ADR 0022](docs/adr/0022-alerts.md),
  [docs/ALERTS.md](docs/ALERTS.md)), to a chat webhook (Slack, Mattermost, Google Chat), a signed JSON webhook
  (`insight-alert-v1`, HMAC-SHA256) or e-mail. Set up on the **Watch terms** tab, with **Send a test alert** and
  **Recent alerts**; workspace only, never with an API key; audited.
- Each alert fires once per destination: revisions and re-imports add nothing, the first KEV import is not news,
  and the demo is quiet. Sent by the job runner within about 15 seconds; a failure is retried twice.
- **TLP:** each destination has a limit (default AMBER). Above it, and for every TLP:RED report, an alert carries
  only the label, the watch term and a link. Report text and evidence never leave.
- Webhooks must be HTTPS to public addresses (`INSIGHT_ALERT_PRIVATE_TARGETS=on` for your own network; never
  link-local), without redirects. New settings: `INSIGHT_PUBLIC_URL` (links to `/?report=<id>`, which now opens
  that report) and `INSIGHT_SMTP_*`; a wrong value stops start-up.

### Added: threat-research sources, and each publisher's reuse rule
- **Six optional sources** for reporting on attacker groups, campaigns and malware: Cisco Talos, Microsoft Threat
  Intelligence, The DFIR Report, ESET WeLiveSecurity, Kaspersky Securelist, and The Record (security news)
  ([ADR 0021](docs/adr/0021-threat-research-sources.md)). They feed the threat landscape and the inbox like
  any source. Insight keeps each item's title, the publisher's short summary and the link, never the article.
- **Switch any source on or off** in the Sources tab (audited as `source.on` / `source.off`). A source that is
  off is never contacted: *Sync now* refuses it, *Sync all sources* and "schedule every source" skip it, and
  switching it off also turns its schedule off. `insight schedule` follows the same rule.
- **Per-source reuse rules (review J3).** Only CISA's KEV list and CSAF advisories are exported with their text.
  For every other feed, the report export leaves out the text and evidence, and the IOC export's `evidence` is
  `null` for its mentions; titles, links, dates and indicators are still exported.
- `GET /api/sources` gains `category`, `optional`, `reuse` and `in_use`; syncing or scheduling a source that is
  off answers `409`.

### Added: a threat landscape that opens the workspace
- **An executive summary of what is trending and why it matters**, in plain English, for the last 7 or 30 days,
  compared with the 4 weeks or months before ([ADR 0020](docs/adr/0020-threat-landscape.md)). It says how busy
  the period was, which kinds of threat are **rising**, **new** or **quieter**, what attackers are doing by ATT&CK
  tactic ("getting in (Initial Access)"), then the brief's lines: weaknesses CISA says attackers use (now with
  "more than usual"), deadlines, the most severe weakness, your watch terms and a first step.
- **Trending threats**: 13 kinds of threat (ransomware, phishing, data theft and extortion, password and account
  theft, supply-chain attacks, zero-days, state-backed spying, wipers, DDoS, botnets, hacktivism, cryptomining,
  insider threats), each with what it is, why it matters, what to check, its newest reports and **How Insight
  spots this** (the words and ATT&CK techniques it counts).
- A rise must show in the **share** of reports as well as the count, so a new or busy source does not make
  everything look like it is rising. Without earlier reports, the landscape says it cannot show trends yet.
- The landscape carries the **most restrictive TLP** of the reports it counted. **Download as a briefing to
  share** gives the same as Markdown, TLP-marked; downloads are audited (`landscape.briefing`).
- API: `GET /api/landscape` and `GET /api/landscape/briefing` (`days` 1-30), limited to the reports the key may
  see. `GET /api/brief` is unchanged.

### Added: MITRE ATT&CK® techniques on reports

- STIX exports now link each included report to its tagged ATT&CK techniques. Each technique includes a
  MITRE reference and keeps the report's TLP label. Removed tags and tags outside the current catalog are
  omitted.
- **Tags from the report text.** A report is tagged with every Enterprise ATT&CK technique ID written in it
  (`T1059`, `T1059.001`), with the words around it as evidence. Insight never guesses a technique from prose and
  never infers an actor ([ADR 0019](docs/adr/0019-attack-techniques.md)).
- **Analysts decide the rest.** The reader's new **ATT&CK techniques** section adds a technique by ID or name and
  removes a wrong one. A new revision of a synced report keeps those decisions. Audited as `technique.tag` and
  `technique.untag`.
- **The ATT&CK techniques tab** groups the techniques in current reports by tactic, in matrix order, over the last
  7, 30 or 90 days, 12 months or all time, with the number of reports for each; opening a technique lists its
  reports. **Download a layer for ATT&CK Navigator** exports the same view as a Navigator layer (format 4.5),
  scored by report count.
- **API:** `GET /api/attack/techniques`, `/api/attack/summary`, `/api/attack/techniques/{id}/documents`,
  `/api/attack/navigator` and `GET`/`POST`/`DELETE /api/documents/{id}/techniques`. Every read takes the API
  key's TLP limit: a technique written only in an AMBER report does not exist for a GREEN-limited key.
- **The catalog ships with Insight** (Enterprise ATT&CK 20.1, about 700 techniques and sub-techniques, revoked and
  deprecated ones left out), so tagging works offline. `scripts/update_attack.py` regenerates it from MITRE's
  `attack-stix-data`. Reproduced under MITRE's terms of use; see `NOTICE`.
- `insight attack-backfill` / `make attack-backfill` tags reports stored before this release.
- Workspace tabs that do not fit now wrap onto a second line instead of scrolling sideways, which keyboard
  users could not reach.

### Documentation: a roadmap toward a premium TIP; corrected session and schedule notes
- `ROADMAP.md` now plans releases 0.7.0 to 1.0 and later from a detailed gap analysis against premium threat
  intelligence platforms, kept in `docs/ROADMAP-TIP.md`: security fixes first, then complete vulnerability
  intelligence, alerts and more feeds, STIX/ATT&CK/MISP, and analyst-created context.
- The README no longer says sessions are in memory and that a restart signs everyone out (stored sessions survive
  restarts since 0.6.0; use **Sign out everywhere**), nor that there is no scheduling. `docs/ARCHITECTURE.md`
  describes the job runner and opt-in schedules.

## 0.6.0 - 2026-11-20

**Upgrading from 0.5.0:** migrations `0006` (jobs, schedules, remembered feed downloads), `0007` (verdicts) and
`0008` (sessions) run at start-up, or with `make migrate`; nothing to do by hand. Take a backup first, as always.
The upgrade's restart signs you out once; after that, restarts keep you signed in. Schedules start **off**:
nothing syncs by itself until you choose a schedule. Every 0.5.0 API field and the `insight-ioc-v1` export
format are unchanged; new fields are additive.

### Changed: the container image runs Python 3.15
- The Docker image's base moves from `python:3.13-slim` to `python:3.15-slim` (pinned by digest; Dependabot #1).
  The container build, vulnerability scan, read-only smoke test and the release gate's browser and ZAP tests
  run against it. The Python package itself still supports 3.11 and later and is tested on 3.11 to 3.14.

### Changed: a restart no longer signs you out; **Sign out everywhere**
- **Sessions are stored in the database** (migration `0008`, review B4), so restarting or upgrading Insight
  keeps the operator signed in. Only a hash of each session ID is stored, keyed to the password and MFA setting:
  a copy of the database cannot sign anyone in, and **changing the password or turning MFA on or off still
  signs everyone out**, as the restart it needs always did. Sessions still last 8 hours.
- **Sign out everywhere** on the sign-out page ends every session on every browser and device (audited as
  `session.end_all`), for example after using a shared computer.
- Rate limits and the sign-in throttle stay in memory, so still run one worker.

### Added: scheduled syncs (off by default)
- **Sources can sync by themselves**: *Off* (default), *Every hour*, *Every 6 hours* or *Every day*, per source
  or for all sources at once, in the Sources tab, which also shows the next sync. **Start at** picks the time of
  day (UTC) the syncs run from, and every next sync keeps that slot, so a daily sync stays at, say, 00:00 UTC.
  On the host: `insight schedule SOURCE|all --every off|1h|6h|24h [--at HH:MM]` (`insight schedule` lists
  them). Over the API:
  `GET /api/schedules` for anyone signed in; `PUT /api/schedules/{key}` (with an optional `at`) from a browser
  session only, never an API key. Changes are audited (`schedule.update`). [ADR 0018](docs/adr/0018-opt-in-scheduled-syncs.md).
- **A job runner inside `insight serve`** runs them (`INSIGHT_RUN_JOBS`, default `on`; set `off` in every
  process but one if you run several). Jobs are stored (migration `0006`), one at a time per source, and never
  overlap a sync someone started. A failed scheduled sync is tried again after 5, then 10 minutes; every attempt
  appears in *Recent sync activity*, and `GET /api/jobs` lists recent jobs. Jobs a stopped server left running
  run again at the next start; finished jobs are kept 30 days.

### Changed: an unchanged feed is not downloaded again
- Every sync sends the feed's last `ETag` / `Last-Modified` and compares the bytes with last time. An unchanged
  feed records `Unchanged since the last sync.` and nothing else, so KEV's 1.3 MB catalogue is no longer
  re-read and rewritten when nothing changed. After an upgrade, each source is read once in full.

### Added: deleting a report (`insight delete-report`)
- **`make delete-report ID=... REASON='...'`** (or `insight delete-report ID --reason TEXT [--yes]`) deletes one
  report for legal or retention reasons (review finding C4): its observations and notes, and indicators no
  other report mentions, with their verdicts. It shows what will go and asks you to type `delete` first.
- The revision chain is repaired, and a synced item always keeps a current revision. The runbook's manual
  SQL procedure left an item with none when its first revision had been made current again, and it now
  failed on indicators with a verdict. The command replaces it.
- Audited as `document.delete` (actor `cli`) with the reason, content hash and counts, never the title or
  text. CLI only, like API keys and MFA.
### Changed: a lighter pipeline, the same guarantees (review G1, first part)
- Pull requests and pushes test Python 3.11 and 3.14; 3.12 and 3.13 run every night and in the milestone gate,
  which still tests all four.
- Mutation testing and the newest-dependency check run weekly (Sunday); live contracts, deep property tests and
  the image re-scan stay daily. A manual *Nightly* run does everything.
- Dependabot batches action and base-image updates into one pull request each per month.
- The nightly image re-scan and mutation testing, which had failed since 17 November because of the pipeline
  itself (an image tag with a stray `v`, and test settings mutmut lost), run again.
- **One tag per release.** The release workflow now runs the whole milestone gate on the final tag, then waits
  for approval before publishing; a release-candidate tag is no longer required (it remains an optional dry
  run, as does running the gate by hand). See `docs/RELEASING.md`.

### Added: verdicts, warning flags and a blocklist
- **Verdicts.** An analyst can now say what an indicator *means*: `benign`, `suspicious` or `malicious`
  (`POST /api/entities/{id}/assessment`), with a reason, an optional expiry date and the reason's own TLP label
  (default AMBER, since it may quote a restricted report). Review still says only that a value was copied
  correctly. Audited as `entity.assess`. A TLP-limited key sees a verdict only within its limit, and can neither
  set nor replace one above it. Stored in the new `entity_assessments` table (migration 0007).
- **Warning flags**, computed from each value and never stored: `non-routable` (private, loopback, shared,
  multicast or reserved addresses), `documentation` (the RFC 5737, 3849 and 9637 example ranges),
  `reserved-name` (`.local`, `.test`, `example.com` and other special-use names) and `common-benign` (a short
  list of vendor domains that reports cite constantly).
- **`GET /api/iocs/blocklist?kind=ip|domain|url|md5|sha1|sha256|sha512`**: values safe to load into a firewall
  or SIEM, as text or CSV. Only `malicious` verdicts that have not expired (their own date, or 30 days for IP
  addresses and 90 for domains and URLs; hashes do not expire), with an accepted mention and no warning flag,
  within the caller's TLP limit. Audited as `ioc.blocklist`; shares the IOC-export budget.
- **IOC export (`insight-ioc-v1`, additive):** each IOC gains `verdict`, `verdict_valid_until` and `flags`;
  new filters `verdict` and `exclude_flag`. The JSON Schema and the example are updated.
- `GET /api/entities/{id}` gains `flags`, `assessment`, `first_seen_at` and `last_seen_at`. First and last seen
  are computed from the reports the caller can see, so a TLP-limited key learns nothing from restricted ones.
- The SIEM recipe in the API guide now pulls the blocklist instead of the raw export (review finding C1).
- **In the workspace:** each observation in the reader, and each entity in the entity explorer, shows its
  warnings as badges and its verdict, with **Set verdict** / **Change verdict** (a reason, its TLP label and an
  optional end date). The reason's label defaults to AMBER, or to the report's own label when that is stricter.
  The explorer also shows when the value was first and last seen. New glossary entries explain verdicts, each
  warning and the blocklist; the verdict dialog is in the accessibility (axe) walk.

### Changed: the service layer is a package (internal)
- `services.py` (1,300 lines) is now `insight/services/`, one module per domain: `tlp`, `audit`, `common`,
  `documents`, `search`, `entities`, `triage`, `brief`, `exports`, `sources`, `jobs` and `access`. Every public
  name is re-exported, so `services.ingest(...)` and every other call site work unchanged. New architecture
  tests keep the modules small, keep `services.tlp` free of other domains' logic, and fail if a public name is
  not re-exported (review finding B3). No behaviour changes.
- The same for `main.py` (990 lines): the API now lives in `insight/web/`: `app` (the factory), `boundary` (the
  ASGI boundary and security headers), `auth` (callers, sessions, sign-in) and `routes/`, one module per area.
  `main.py` remains as a compatibility module, so `insight.main:create_app` and existing imports keep working.
  The TLP-limit architecture test now checks every route module.

### Changed: CI actions updated
- `actions/checkout` v5 → v7.0.1, `actions/setup-python` v6 → v7.1.0 and the CodeQL Action v3 → v4.39.3, in
  every workflow (from Dependabot's #19). None of the workflows uses `pull_request_target`, `workflow_run` or
  setup-python's removed `pip-install` input, the two breaking changes in these majors.
- The release-only actions, also from #19: `docker/setup-buildx-action` v4.4.1, `docker/login-action` v4.8.0,
  `docker/metadata-action` v6.2.0, `docker/build-push-action` v7.4.0, `sigstore/cosign-installer` v4.1.3 and
  `actions/attest-build-provenance` v4.2.2. Releases are now signed with cosign v3; verify them with cosign v3
  or later.
- **A release rehearsal** (`release-rehearsal.yml`) runs on every pull request that touches `release.yml`, the
  `Dockerfile` or its own files, because CI never runs the release workflow. It builds the image with its SBOM
  and provenance, pushes it to a throwaway local registry, signs and verifies it with cosign, checks that this
  cosign still verifies the last published release, then pulls by digest and smoke-tests the container, all
  with the release's action versions and without publishing anything. `scripts/check_release_actions.py`
  reads each pinned action's `action.yml` and fails if `release.yml` passes an input it no longer accepts.

### Fixed: documentation drift
- The API reference and guide said a refused enrichment request for an unknown CVE starts the 6.5 s window;
  since 0.5.0 it does not. The SIEM recipe implied that *accepted* means *malicious*; it now says accepted
  means copied correctly, and warns against using the export as a blocklist without review. The runbook's
  "Known limitations" heading no longer says 0.2.0.

### Added: Sync all sources and an intel brief on the landing page
- **Sync all sources**, next to *Export IOCs*, syncs every source in turn and shows how far it has got
  (`Syncing 2 of 4: …`). A failing source does not stop the others; the message names it and the *Sources* tab
  shows why. Same as `POST /api/sources/sync-all`. Nothing syncs by itself, as before.
- **Intel brief**, under the counters: what the last 7 days add up to, built from the data rather than written by
  AI, so it never says anything the reports do not.
  - An **executive summary** at the top, in a few plain sentences, most urgent first: what came in; how many
    more weaknesses CISA says attackers are using, in whose products, and the next US federal fix-by date (or
    that it has passed); exploited weaknesses that other sources also report; the most serious new weakness;
    what matches your watch terms (or a nudge to add some); and a first step when something is urgent.
  - Five short sections: *Exploited now*, *Most severe* (CVSS 9 or higher in new CISA advisories), *Your watch
    terms*, *Seen in several sources* and *Most-mentioned vendors*. Each line opens its report, the indicator in
    the entity explorer, or the inbox searching for that vendor or term.
  - "New" means published in the window: KEV entries by the day CISA added them, CISA advisories by their first
    release, other reports by the day Insight received them. A first sync of years of KEV history, or CISA
    updating old advisories, does not flood it. The synthetic demo is left out, and vendor names that differ
    only in capital letters count as one.
  - Also `GET /api/brief?days=7`, which honours the key's TLP limit.

### Changed: CISA advisories now come from CISA's CSAF files
- **CISA Security Advisories** (`cisa-csaf`) replaces **CISA Cybersecurity Advisories** (`cisa-advisories`).
  cisa.gov answers `403 Access Denied` to automated clients for its advisories RSS feed, whatever their request
  headers, so the old source never worked. The new one reads CISA's machine-readable CSAF 2.0 advisories from
  its GitHub repository: per sync, the 25 newest industrial control system and other vulnerability advisories,
  by the publication date in their file names (not by when CISA last re-saved a file, which it sometimes does
  for years-old advisories in bulk).
  Each report keeps the advisory's summary, vendors, sectors and every CVE with its CVSS score, is TLP:CLEAR,
  and links to CISA's web page for the advisory. An updated advisory becomes a revision of its report. CISA does
  not publish threat-actor advisories as CSAF, so they are not included.
- **API:** the source key `cisa-advisories` is gone; use `cisa-csaf`. Reports already imported keep their source.
- **Outbound traffic:** syncing this source contacts `raw.githubusercontent.com`. If you run an egress allow-list,
  add that host.

## 0.5.0 - 2026-11-19

### Fixed before release: CVE enrichment throttle
- **CVE enrichment:** a request for a well-formed CVE that no report mentions is still refused (`422`) but no
  longer starts the 6.5 s enrichment window, so the next valid lookup is not throttled (#8).

### Fixed before release: CI and container image
- **Every GitHub Action is pinned to a commit SHA and the base image to a digest**; zizmor now enforces
  `hash-pin` and the release gate's pin check passes. `aquasecurity/trivy-action` moves from `0.28.0`, a tag that
  no longer exists (removed after the March 2026 trivy-action tag hijack, GHSA-69fq-xp46-6x23), to `v0.36.0`.
  This had broken the container job and the nightly image re-scan.
- **Mutation testing scored 0%:** a repository-hygiene test failed inside mutmut's `mutants/` copy (which git
  ignores), so mutmut aborted before testing any mutant. The test now skips when run from such a copy.
- **The newest-dependencies job failed on NiceGUI 3.19**, whose test simulator routes `ui.navigate.to` through
  `Client.open` and drops `new_tab`. The test helper now records the call on 3.18 and 3.19; the application was
  unaffected.
- **Container image: six HIGH findings from Trivy removed.** The runtime stage now applies pending Debian
  security updates (zlib, CVE-2026-85091) and uninstalls `pip` after installing Insight, which removes the
  `msgpack`, `urllib3` and `setuptools` copies that pip vendors. Nothing in the running container uses pip.
- **Secret scan:** `.gitleaksignore` lists the fake `insk_` key that `tests/unit/test_scripts.py` builds to test
  the forbidden-files check (a false positive in gitleaks' generic rule).
- `docs/examples/insight-iocs-example.json` regenerated for 0.5.0 (generator version).
- **Release fixture:** `tests/fixtures/releases/insight-0.5.0.sqlite3` committed, created by the new manual
  **Release fixture** workflow (`.github/workflows/release-fixture.yml`) for releases prepared without a local
  environment.

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
