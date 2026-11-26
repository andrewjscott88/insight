# Insight

TIP 4.6 adds optional RDAP, RIPEstat, certificate transparency and passive DNS context in the indicator explorer and link map.
Enable a provider in Settings, then approve each uncached lookup of a reviewed TLP:CLEAR indicator. Contact
details are dropped and results never become indicators by themselves. See
[ADR 0037](docs/adr/0037-infrastructure-pivots.md).

A single-operator threat-intelligence workbench, run locally or published behind a TLS reverse proxy. Application logic and the interactive GUI are authored in **Python**, using **NiceGUI + FastAPI + SQLAlchemy**. NiceGUI supplies the underlying browser assets; no separate React/Node build is required.

**Version 1.0.0 supports a single operator.** You choose where to deploy it and which sources to connect.
For setup, backups and upgrades, see the [operator runbook](docs/RUNBOOK.md). For scripts, see the
[API guide with `curl` examples](docs/API_GUIDE.md). Browse the [documentation index](docs/README.md).

## What works

- **Focused intelligence briefs:** search the top of **Intel Brief** by **Sector / Industry** or any of
  the other Threat Hunt types, select a match and choose **Show brief**. The landing page starts with
  **Last 30 days**; **Last 7 days** remains available. Read concise takeaways and open supporting reports.
  Sector briefs separate sourced group background, reports mentioning the sector and reports linked to
  those groups. The period controls keep the chosen focus; **All intelligence** returns to the overview.
  No AI or source fetch is involved. [Brief behavior](docs/EXECUTIVE_BRIEF.md)

- **Guided threat hunting:** choose a sector/industry, threat type, actor, flaw, report, exploit activity,
  malware/tool, indicator or campaign in **Threat Hunt**, then download a plan as Markdown or PDF, or choose
  **Save as hunt package** to keep an editable draft. It uses saved metadata and fixed guidance, with source
  references and TLP limits. Saving is audited; publication is separate. It never runs a hunt or calls
  an AI service. **Saved hunt packages** and **Advanced: intelligence reports** hold the existing workflows.
  [Workflow and limits](docs/THREAT_HUNT.md)

- **Read-only MCP for agents:** Search reports and indicators, read report summaries, check indicator verdicts
  and confidence, and retrieve open requirements, hunt packages, group profiles and the threat landscape.
  Uses bearer API keys, TLP ceilings, publisher reuse rules and audited reads. Supports protocols
  2026-07-28 and 2025-11-25.
  Insight calls no model; OAuth is out of scope. [MCP guide](docs/MCP.md)

- **Built for readability, including for people with dyslexia or other reading difficulties** ([ADR 0017](docs/adr/0017-readability-standard.md)): WCAG 2.2 AA plus its reading-related AAA criteria (7:1 contrast, lines of about 70 characters, 1.5 line spacing, plain language), 16 px minimum text, no capitals, real headings, a strong focus outline, messages that stay until you dismiss them, a **Larger text** button and a **What the words mean** glossary. Checked in the test suite with axe-core on every screen.
- **Light and dark themes, readable on phones.** The workspace follows each device's light/dark setting by default; the **Light / Dark / System** buttons in the header override it for that browser. The instance default is `INSIGHT_THEME` (`make theme THEME=dark`). On a phone the layout uses larger text, no zoom-on-focus, big touch targets, and opening a report scrolls to it (with **← Back to list**). Text in both themes meets WCAG AA contrast (tested).
- **Intelligence requirements:** priority intelligence requirements (PIRs), narrower requirements and requests for information (RFIs), each with criteria (terms, CVEs, ATT&CK techniques, groups, campaigns). Every report shows the requirements it addresses; every requirement shows its matching reports, cited evidence and answer, and flags itself as quiet when nothing has matched for 30 days. A `read-feedback` API key lets a hunt tool file questions and report sightings, and nothing else ([ADR 0032](docs/adr/0032-intelligence-requirements.md)).
- **Finished intelligence products:** a bottom line up front, key judgements in ICD 203's estimative language with the analyst's confidence and their evidence, the analysis and intelligence gaps (one click to ask a gap as an RFI). Publishing keeps each version exactly as it went out; download it as a PDF with the TLP label on every page, as Markdown or as a STIX 2.1 report ([ADR 0036](docs/adr/0036-intelligence-products.md)).
- **Hunt packages over TAXII:** one hypothesis for a hunt tool, with its ATT&CK techniques, indicators and detection rules (Sigma, YARA, Suricata, Snort) and the reports behind it. Published packages are served in a *Hunt packages* TAXII collection as STIX 2.1; retired ones come back as revoked ([ADR 0034](docs/adr/0034-hunt-packages.md)).
- **Confidence and source reliability:** Admiralty grades for sources (A–F) and reports (1–6), and a 0–100 confidence for every indicator from how many independent sources agree, how far each is trusted and how old the reports are (IP addresses age in 30 days, hashes never). Sightings that hunt tools report back are the strongest signal ([ADR 0035](docs/adr/0035-sightings.md)). Source statistics show what each feed adds that nothing else does and how often its indicators are rejected ([ADR 0033](docs/adr/0033-confidence-and-source-reliability.md)).
- Password-protected analyst inbox with split-pane report reader, search and TLP/status filters. Search ignores case, accents and Unicode normal form identically on SQLite and PostgreSQL. A query lists reports **best match first** (every word must match; quotes keep a phrase together), with a snippet around the match.
- **Link map:** **Show links** on a report or indicator lists what it links to (indicators, reports, ATT&CK techniques and groups, your actors and campaigns) and what is two steps away; any entry can be put in the centre. `GET /api/graph` returns the same nodes and edges. [ADR 0027](docs/adr/0027-ranked-search-and-link-graph.md)
- Paste reports with title, source, URL and handling label; preserve original text and its SHA-256 hash.
- Deterministic extraction of CVEs, IPv4/IPv6 addresses and network ranges (CIDR), URLs, domains, e-mail addresses and MD5/SHA1/SHA256/SHA512 mentions, including defanged (`hxxp`, `[.]`) and international (punycode) forms. It is precision-first: about 98% precision and recall on the labelled corpus ([docs/EXTRACTION.md](docs/EXTRACTION.md)).
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
  technique IDs written in them (`T1059.001`), checked against bundled Enterprise, Mobile and industrial
  control systems (ICS) ATT&CK catalogs; analysts add
  and remove the rest in the reader, and new revisions keep those decisions. **Investigate › ATT&CK techniques** groups
  the techniques in your reports by tactic over a period you choose, opens the reports behind each one, and
  downloads a layer for ATT&CK Navigator. Never guessed from prose; no attribution. `make attack-backfill` tags
  reports stored before 0.7.0. STIX exports link each included report to its current catalog-backed tags,
  with the report's sharing label and a link to the technique on MITRE's site.
  API: `/api/attack/*` and `/api/documents/{id}/techniques`.
  Select a domain to browse its offline catalog or export a matching Navigator layer. Existing API calls
  default to Enterprise. [Domain catalogs](docs/adr/0042-mobile-and-ics-attack-catalogs.md)
- **Industry threats and threat guides** ([docs/THREAT_GUIDES.md](docs/THREAT_GUIDES.md),
  [ADR 0025](docs/adr/0025-threat-guides.md)): pick an industry and see up to ten threat groups that a cited
  source (MITRE ATT&CK or the MISP galaxy) says target it, each with the quoted evidence. Open one for a threat
  guide: aliases, targets, ATT&CK techniques and a Navigator layer, tools, mitigations, your reports that name it,
  sources and the TLP label, plus a hunt plan (starting hypotheses with log sources), an indicator sweep list,
  linked YARA, Sigma, Suricata and Snort rules (never run) and hunt records. Works offline from a bundled, pinned library;
  `make threat-library-sync` fetches a fuller copy. A group is never inferred from indicators or co-occurrence.
- **Adversary library imports** ([ADR 0038](docs/adr/0038-adversary-library.md)): the pinned catalog
  covers every current ATT&CK malware and tool, plus uniquely matched MISP group aliases with their sources.
  Aliases improve group searches and report name matches; they never create links. In **Investigate > Threat groups**, link software to a report or record its use by an
  actor or campaign. These labelled decisions appear in STIX and TAXII. [Software guide](docs/THREAT_GUIDES.md#software-and-report-links).
  Actor guides also include a bounded, reader-filtered [activity timeline](docs/THREAT_GUIDES.md#activity-timeline-and-software-layers-tip-47-part-3),
  with explicit campaign associations and distinct source/collection/action dates. Software Navigator layers
  show catalog techniques; software-only actor context never changes existing scores or hunt hypotheses.
- **Alerts** ([docs/ALERTS.md](docs/ALERTS.md)): when a new report mentions a watch term, or CISA adds a KEV
  entry, Insight tells a chat channel (Slack, Mattermost, Google Chat), your own tool (signed JSON webhook) or
  an e-mail address, within about 15 seconds of the sync. Each alert fires once; report titles go only up to
  each destination's TLP limit, and report text never leaves. Set up in Settings › Watch terms.
- Organization watch terms highlight literal product, vendor or topic matches. These are transparent keyword matches, not calibrated risk scores.
- **Threat-research sources, off until you switch them on** ([ADR 0021](docs/adr/0021-threat-research-sources.md)):
  Cisco Talos, Microsoft Threat Intelligence, The DFIR Report, ESET WeLiveSecurity, Kaspersky Securelist and
  The Record (news), for reporting on attacker groups, campaigns and malware. Insight keeps each item's title,
  short summary and link. Each publisher's reuse rule applies: only CISA's text leaves Insight in exports; for
  every other feed, exports carry titles, links, dates and indicators, not the publisher's words.
- **GreyNoise Community IP context.** With a host key, analysts can approve a passive lookup of a reviewed public IPv4 address from a current TLP:CLEAR report in Entity explorer. [Runbook](docs/RUNBOOK.md#greynoise-community-ip-context)
- **Certificate transparency (TIP 4.6 part 2).** Optional, approved crt.sh domain lookups show certificate names, issuer and dates in the workspace and link map. [Guide](docs/INFRASTRUCTURE_PIVOTS.md)
- **Passive DNS (TIP 4.6 part 3).** With approved CIRCL access and your own credentials, manually approved pivots show bounded DNS history and provider/date links. [Guide](docs/INFRASTRUCTURE_PIVOTS.md)
- **Shodan exposure context (optional, paid).** With your own Shodan key, the same reviewed address can be looked up at Shodan for open ports and exposure. [Runbook](docs/RUNBOOK.md#shodan-exposure-context)
- **Censys Platform context (optional).** Approve a lookup of one reviewed public IPv4 or IPv6 address to
  see observed services, host names and network details. Configure `INSIGHT_CENSYS_PAT` on the host and,
  when needed, `INSIGHT_CENSYS_ORG_ID`. Censys requires private sign-in and is unavailable during temporary
  open access. Results stay out of exports and follow your account terms; fresh lookups may use credits.
  [Censys setup](docs/CENSYS.md)
- **Optional abuse.ch indicator feeds.** Import recent URLs from URLhaus, network indicators and hashes from
  ThreatFox, and file hashes from MalwareBazaar. Set `INSIGHT_ABUSECH_AUTH_KEY` and enable the feeds you use.
  Each entry links to its record at the publisher. The connector reads only the provider's metadata API.
- Curated connectors: CISA KEV, CISA security advisories (CISA's machine-readable CSAF files), SANS ISC and UK
  NCSC feeds. **Sync now** per source, **Sync all sources** beside Intel Brief, and **opt-in
  schedules** (off by default; every hour, 6 hours or day, per source or for all, from a time of day you choose,
  in UTC) so the feeds and the brief stay fresh by themselves. An unchanged feed is not downloaded again (`ETag` / `Last-Modified`). See
  [ADR 0018](docs/adr/0018-opt-in-scheduled-syncs.md).
- **OTX subscriptions** import public CLEAR/WHITE pulses as reports with their indicators and source links.
  Set your own `INSIGHT_OTX_API_KEY` and turn on the source in the workspace. [Runbook](docs/RUNBOOK.md#8-sources-enrichment-and-their-failures)
- **Intel Brief** opens the workspace ([ADR 0020](docs/adr/0020-threat-landscape.md),
  [ADR 0041](docs/adr/0041-guided-threat-hunt-workspace.md)): a plain-English
  executive summary of the last 7 or 30 days, compared with the 4 weeks or months before. Which kinds of threat
  are **rising**, **new** or **quieter** (ransomware, phishing, data theft, supply chain, zero-days and 8 more,
  spotted by listed words and ATT&CK techniques), what each one is, **why it matters** and **what to check**,
  what attackers are doing by ATT&CK tactic, and every report behind it. Counted from your reports, not written
  by AI. Known exploited products or reported threat themes lead, with meaning and next steps before
  report-volume context. The most restrictive contributing TLP stays attached; **Download as a briefing
  to share** saves Markdown.
  `GET /api/landscape`, `GET /api/landscape/briefing`.
- **Evidence behind the brief** ([docs/EXECUTIVE_BRIEF.md](docs/EXECUTIVE_BRIEF.md)): what the period adds up to,
  built from your reports (no AI). **What needs attention** gives plain findings (known exploitation, a recurring
  topic, the highest severity and your watch terms), each with a conditional **next step** and
  its evidence. **About this brief** says what the data covers and how fresh each source is. There is no
  separate last-24-hour receipt card or attention highlight; the existing `recent_reports` API field remains.
  Then *Exploited now* (CISA KEV), *Most
  severe* (CVSS 9 or higher), *Your watch terms*, *Seen in several sources* and *Most-mentioned vendors*. Every
  line opens its report, indicator or a search. "New" means published in the period, so a first sync of old
  history does not flood it; the demo is left out. Also `GET /api/brief`.
- **Temporary password-free access** for development and demos (`INSIGHT_DEV_NO_AUTH=on`; **off by default**,
  refused together with MFA, announced on every page). While on, anyone who can reach the site can read and
  change everything; see the [runbook](docs/RUNBOOK.md#temporary-password-free-access) before using it.
- **Prioritised CVEs** ([ADR 0024](docs/adr/0024-prioritised-cves.md)): the CVEs in your reports, most urgent
  first by stated rules (used in ransomware, known exploited, reported exploited, public exploit, likely to be
  attacked soon, critical, high), each saying why. Public exploits come from your reports (a proof of concept,
  Metasploit module or Exploit-DB entry mentioned near the CVE) and, with your own free token, from VulnCheck KEV
  ([ADR 0028](docs/adr/0028-exploit-availability.md)); Insight never stores exploit code. The brief names ransomware-linked and likely-to-be-attacked weaknesses too. `GET /api/cves`.
- **CVE severity and attack likelihood** ([ADR 0023](docs/adr/0023-automatic-cve-lookups.md)): NIST NVD (CVSS)
  and FIRST EPSS scores shown in plain words beside each CVE, looked up on request or, once switched on in
  **Sources**, automatically for CVEs in TLP:CLEAR and GREEN reports. Only CVE numbers are sent. No key is
  needed; an optional free NVD key (`INSIGHT_NVD_API_KEY`) makes NVD lookups about ten times faster. This
  product uses the NVD API but is not endorsed or certified by the NVD.
- JSON report exports retain provenance and TLP; they are **not STIX** and do not authorize redistribution.
- **IOC export**: one JSON file listing every indicator across your reports once, with its source reports, evidence, KEV context and the most restrictive TLP of the reports it includes. Filter by type, review status, highest TLP or report; defang for e-mail and tickets, and leave evidence out when sharing. **Export IOCs** in the workspace (with a live count preview), **Export this report's IOCs** in the reader, `insight export-iocs FILE` or `GET /api/iocs/export`. Not STIX and not a blocklist by itself: see [docs/IOC_EXPORT.md](docs/IOC_EXPORT.md).
- Import a local PDF advisory from the ingest dialog or with `insight import-pdf FILE`. The report reader shows
  the original file’s SHA-256 alongside its searchable text and indicators. [PDF import](docs/API.md#post-apidocumentspdf)
- **STIX 2.1 import** brings a local bundle into the inbox as source-linked reports. Use the ingest dialog,
  `insight import-stix FILE` or the authenticated API. [Import guide](docs/API.md#post-apiimportstix)
- **STIX 2.1 export** shares filtered indicators, CVEs and source reports with TLP 2.0 markings. Select STIX in **Export IOCs**, run `insight export-stix FILE`, or use `GET /api/iocs/stix`. Each bundle is validated offline. [STIX export guide](docs/IOC_EXPORT.md#stix-21-export)
- **TAXII 2.1 server** (read-only): a SIEM or TIP polls `/taxii2/` with the API key and gets the indicators you accepted, within the key's TLP limit, with stable IDs and `added_after` for changes only. [TAXII guide](docs/TAXII.md)
- **HTTP API with an API key for scripts and SIEMs**: one key, created, rotated and revoked only on the host (`make api-key-create` / `insight api-key`), sent as `Authorization: Bearer`. Read-only unless you choose read-write; mandatory expiry; stored as a hash only; optionally limited to a TLP label (`MAX_TLP=GREEN`: more restrictive reports are invisible to it). Per-caller rate limits with `RateLimit` headers and `429` + `Retry-After`. Guide with every `curl` command: [docs/API_GUIDE.md](docs/API_GUIDE.md); field reference: [docs/API.md](docs/API.md).
- **TLP:RED is refused by default** (`INSIGHT_MAX_TLP=AMBER+STRICT`), including reports whose text carries a RED marking, so material meant for named recipients does not end up on a server. Set `INSIGHT_MAX_TLP=RED` to allow it.
- **Optional sign-in MFA** uses authenticator-app codes and starts switched off. Use `make mfa-enable` or
  `make mfa-disable`. The stored pairing is encrypted with a key derived from `INSIGHT_SESSION_SECRET`. [Setup and recovery](docs/RUNBOOK.md#sign-in-second-factor-mfa)
- **Public deployment** behind a TLS reverse proxy: trusted proxy headers (`INSIGHT_TRUSTED_PROXIES`), secure cookies and HSTS. See [docs/RUNBOOK.md](docs/RUNBOOK.md) ("Reverse proxy").
- The audit log records who acted: the operator, the API key (by key ID), the CLI or a connector.
- A `Makefile` for every routine task: `make help`.
- Clearly labeled synthetic demo data. All examples use reserved test infrastructure, not live malicious endpoints.
- Persistent SQLite database in a Docker volume, with automatic schema migrations. PostgreSQL 16 is supported and tested in CI (`INSIGHT_DATABASE_URL=postgresql+psycopg://…`, `pip install '.[postgres]'`).
- Publisher edits to synced items (e.g. a changed KEV description) become **revisions** of one report, not duplicates. The inbox shows the current revision; older ones stay available as evidence.

### What does “free sources” mean?

The starting connectors access publicly available intelligence without paid subscriptions. This is **open-source intelligence (OSINT)**, not a claim that every publisher grants an open-source content license. Feed imports retain title, source link and up to 500 characters of feed summary; they never crawl full articles. Review each publisher’s terms before retention or redistribution. The registry is intentionally small and explicit, not “every free feed on the internet.”

### Add your own feeds

Open **Settings › Sources › Your sources** to add an RSS feed, an Atom feed or a TAXII 2.1 collection.
For TAXII, enter the HTTPS API root and the collection ID. If the publisher requires a login, enter the
name of the host environment variable holding it. Choose the lowest TLP label the reports should carry. A new feed starts off. Switch it on to sync it
once, or choose a schedule to fetch updates. Adding a feed alone never contacts the publisher.

Insight shares only metadata by default. Choose public reuse only if the publisher allows its text to be
shared. TAXII imports also retain the publisher's own restrictions. Removing a source keeps its reports
and their labels, and limits future exports to metadata.
[Source settings and schedules](docs/RUNBOOK.md#8-sources-enrichment-and-their-failures)

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
6. In **Settings › Sources**, run only the sources you want. These buttons make outbound internet requests. NVD/EPSS lookups explicitly send the selected CVE identifier to that provider; source documents are not sent.

The container runs as an unprivileged user with a read-only root filesystem and no Linux capabilities. The Docker port is bound to **127.0.0.1 only**. Never expose port 8080 itself to your LAN or the internet: to publish Insight, put it behind a TLS reverse proxy as described in [docs/RUNBOOK.md](docs/RUNBOOK.md) ("Reverse proxy") and read [docs/SECURITY.md](docs/SECURITY.md) first. It has one operator password (plus optional MFA), and people can also sign in through your organisation's identity provider ([set-up](docs/RUNBOOK.md#identity-provider-sign-in)). Sign-in sessions are stored in the database for 8 hours and survive a restart: a restart does **not** sign anyone out. To end sessions, use **Sign out everywhere** on the sign-out page, or change the password or MFA setting. Rate limits are in memory, so use one process/worker.

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
| Note public-exploit mentions in reports stored before 0.9.0 | `make exploit-backfill` (once after upgrading; safe to rerun) |
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

**Back up first** (see below). Then rebuild and start as usual (`docker compose up --build -d`). Insight applies database migrations automatically at start-up; `insight migrate` does the same explicitly and prints the before/after revision. Databases from 0.1.0 are recognised and upgraded in place. Reports that 0.1.0 duplicated because a publisher edited an item are linked as revisions, and nothing is deleted. Since 0.6.0 sessions are stored in the database, so a restart keeps you signed in. After upgrading to 0.7.0, run `make attack-backfill` once to tag ATT&CK techniques in older reports. From 0.8.0, keep `INSIGHT_SESSION_SECRET` unchanged across upgrades: it also encrypts the authenticator pairing. After upgrading to 0.9.0, run `make exploit-backfill` once to note public-exploit mentions in older reports. On PostgreSQL, the 0.9.0 upgrade rewrites the timestamp columns once, so take the backup with `pg_dump --format=custom` before it.

## Local Python development

Python 3.11, 3.12, 3.13, 3.14 and 3.15 are tested (CI runs the full suite on each). The Docker image uses 3.15, which every
pull request tests.

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
| `insight misp-export FILE` / `insight misp-import FILE` | Exchange a single MISP event as JSON or with a configured MISP instance. [MISP guide](docs/MISP.md) |
| `insight attack-backfill` | Tag ATT&CK technique IDs in reports stored before 0.7.0 (safe to rerun) |
| `insight exploit-backfill` | Note public-exploit mentions near CVEs in reports stored before 0.9.0 (safe to rerun) |
| `insight industries` · `insight threat-profile INDUSTRY` | The industries, and the top ten groups for one with their evidence ([docs/THREAT_GUIDES.md](docs/THREAT_GUIDES.md#command-line)) |
| `insight threat-guide REF FILE` | Write a group's threat guide (`--format md\|json\|navigator\|sweep-csv\|sweep-json`, `--max-tlp`, `--include-named` to sweep reports that only name the group; never overwrites; owner-only file) |
| `insight rule-add FILE --kind sigma --link G0016` | Store a YARA, Sigma, Suricata or Snort rule (text only, never run) and link it to groups or techniques |
| `insight threat-library-sync` | Fetch the full pinned threat-group library (MITRE ATT&CK and MISP galaxy; checked by SHA-256) |
| `insight mfa setup` | Pair an authenticator app for sign-in codes (shows a secret, then confirms one code). Also `status`, `reset`. MFA itself is **off by default** and switched with `INSIGHT_MFA=on`; with Docker, `make mfa-enable` / `make mfa-disable` do both steps |
| `insight api-key create --name NAME` | Create the API key for scripts/SIEM (read-only unless `--access read-write`; `--max-tlp GREEN` hides more restrictive reports from it; shown once). Also `status`, `rotate`, `revoke`. See [docs/API.md](docs/API.md#api-key-scripts-and-siem) |
| `insight users list` | People who signed in through the identity provider. Also `role USER viewer\|analyst\|admin\|none`, `disable`, `enable`, `sign-out`, `remove`; each change ends the person's sessions. The password sign-in is the built-in operator, always an admin ([roles](docs/API.md#roles)) |
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

The side menu starts with **Intel Brief**, then **Triage** (reports and review), **Investigate** (indicators,
CVEs, techniques and threat groups), **Threat Hunt** (guide builder, saved hunt packages and advanced
intelligence reports), **Share** (IOC export, TAXII, API access and MISP), and **Settings**. Requirements and
requests for information remain in **Settings → Intelligence questions (advanced)**. Sources, lookups,
watch terms and alerts remain in Settings too. On a phone the menu sits above the content.

1. **Collect:** paste authorized text or explicitly sync a curated feed.
2. **Read:** search/filter the inbox and read evidence in context.
3. **Review:** accepting a mention means the extraction is useful/accurate, **not that the entity is malicious**.
4. **Correlate:** pivot to other documents that mention the same canonical entity.
5. **Prioritize:** watch terms identify possible organizational relevance; CISA KEV signals observed exploitation, NVD supplies vulnerability metadata, and EPSS estimates exploitation probability. None proves that your assets are exposed.
6. **Record:** write an analyst note explaining your judgment.
7. **Plan:** build a guide in **Threat Hunt**, then download it or **Save as hunt package** to create a draft.
   Review and edit the draft before explicitly publishing it. Run the hunt in your own tool
   ([docs/THREAT_HUNT.md](docs/THREAT_HUNT.md)).
8. **Share:** export the indicators you reviewed (**Export IOCs**), filtered to the TLP you may share at. Check the file's label and evidence before it leaves your hands ([docs/IOC_EXPORT.md](docs/IOC_EXPORT.md)).

The data model separates documents, entities, observations, notes and external enrichments. It intentionally does not invent threat-actor attribution or causal relationships from co-occurrence.

## Handling sensitive intelligence

TLP:CLEAR/GREEN/AMBER/AMBER+STRICT/RED are preserved as metadata. **This single-user release does not enforce organizational sharing groups or recipient-level TLP access.** Only import material you personally may access and retain. Local JSON exports preserve the label but cannot prevent later disclosure. An IOC export is labelled with the most restrictive TLP of the reports it includes; use `max_tlp` (or **Most restrictive TLP to include**) to keep restricted reports out of a file you intend to share. No external AI provider is called.

Badges explain the intended audience while retaining the standard token, such as **Public · TLP:CLEAR**
or **Your organization only · TLP:AMBER+STRICT**. Public disclosure under TLP does not waive copyright or
publisher reuse terms. The presentation does not lower stored labels or access limits.

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

- No recipient-level dissemination rules yet. Roles (viewer, analyst, admin) and their permission matrix are in place (TIP 3.4a), and people can sign in through an OpenID Connect provider such as Keycloak or Authentik (TIP 3.4b, [set-up](docs/RUNBOOK.md#identity-provider-sign-in)); admins approve them in Settings → People (or with `insight users` on the host). A read-only public view for TLP:CLEAR instances is available (`INSIGHT_PUBLIC_VIEW=on`, [runbook](docs/RUNBOOK.md#public-view)). MFA is an optional single-operator authenticator-app code, off by default (`make mfa-enable`). One API key at a time.
- Rate limits live in server memory: one worker, and a restart resets them. Sessions are stored in the database and survive restarts. The API is unversioned (breaking changes are listed in the CHANGELOG's upgrade notes).
- No full-text relevance ranking engine or drawn graph visualization yet. Source syncs can run on opt-in schedules (off by default).
- Local PDF import extracts text in a bounded Linux worker. Arbitrary URL fetching, arbitrary feed entry, STIX/TAXII/MISP synchronization and automatic full-article storage remain outside the collection workflow.
- No actor/malware attribution, ML or LLM inference (threat guides show what cited catalogs say about a group and which of your reports name it or you linked, never an inferred attribution). Extraction is deterministic and can still miss or mis-read unusual formats (see the known gaps in [docs/EXTRACTION.md](docs/EXTRACTION.md); the labelled benchmark `python scripts/benchmark_extraction.py` measures quality). Manual review is essential. URL extraction trims sentence punctuation and unbalanced closing brackets, so verify against the source evidence.
- Matching is literal; watch terms are not an asset inventory. Source-language dates are not authoritative ingestion dates.
- The inbox shows up to 200 rows; entity pivots load 25 documents at a time. The API paginates documents and entity pivots. Suitable for a pilot, not large-scale intelligence ingestion.
- KEV updates store all supplied records. Inbox reports follow the KEV inbox policy (RUNBOOK section 8): the newest 100 entries, plus every CVE added since the last sync (up to 500 per sync); older entries stay catalog-only. Old KEV rows are retained with import timestamps, not silently deleted; absence from a later import is not evidence of current KEV membership.
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
