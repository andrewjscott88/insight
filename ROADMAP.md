# Roadmap

Planned work for Insight, release by release. The goal: a self-hosted workbench that matches premium threat
intelligence platforms (TIPs) in **workflow and interoperability**, without cloning the telemetry, incident
response and dark-web collection they sell.

- **TIP n.n** refers to a section of [docs/ROADMAP-TIP.md](docs/ROADMAP-TIP.md), the detailed plan: what to
  build, why, which modules to touch, new tables and routes, sources, effort and acceptance criteria.
- **Review Xn** refers to the 0.5.0 architecture review (B2 policy in services, C2 CVE scores, D2 indicator kinds,
  J3 redistribution rules).
- **#n** links the GitHub issue where one exists.

Background: [docs/CI_CD.md](docs/CI_CD.md) (pipeline), [docs/VALIDATION.md](docs/VALIDATION.md) (what is not yet
verified) and the README's "Scope and known limits".

## 0.7.0: hardened, with complete vulnerability intelligence

Close the security findings first, then make the vulnerability workflow complete. Intelligence work comes first
where the operator asked for it: ATT&CK techniques were brought forward from 0.9.0.

- [x] **TIP 2.3 ATT&CK techniques** ([ADR 0019](docs/adr/0019-attack-techniques.md)): the bundled Enterprise
      catalog, tags from technique IDs written in reports, analyst tags and removals kept across revisions, the
      **ATT&CK techniques** tab with report pivots, a Navigator layer export and the API. Still to do: Mobile and
      ICS catalogs.
- [x] **Threat landscape** ([ADR 0020](docs/adr/0020-threat-landscape.md)), at the operator's request: a
      plain-English executive summary of what is trending against the weeks before, why it matters and what to
      check, attacker behaviour by tactic, TLP-marked and downloadable as a briefing. Next: analyst-defined
      themes, and KEV ransomware use (TIP 1.1) and EPSS (TIP 1.2) in it.
- [x] **TIP 1.4 Alerts** (#15, [ADR 0022](docs/adr/0022-alerts.md)), brought forward from 0.8.0: watch-term
      matches and new KEV entries to chat webhooks, signed JSON webhooks or e-mail, once each, within each
      destination's TLP limit. CLI management is available with `insight notify`. Next: a daily landscape digest.
- [x] **Threat-research sources** ([ADR 0021](docs/adr/0021-threat-research-sources.md)): Cisco Talos,
      Microsoft Threat Intelligence, The DFIR Report, ESET, Kaspersky Securelist and The Record, off until
      switched on, with per-source reuse rules (review J3, brought forward from 0.8.0).
- [ ] **TIP 0.1 Verify every public deployment.** Anonymous `GET /` answers 303 to `/login`; `.env` sets secure
      cookies, allowed hosts and trusted proxies, preferably MFA. A smoke check for the public URL.
- [x] **TIP 0.2 Fix stale session and scheduling documentation.** README and ARCHITECTURE now describe stored
      sessions, opt-in schedules and the job runner.
- [x] **TIP 0.3 Safer public-deploy defaults.** Stronger start-up warnings when Insight is internet-facing, and an
      optional `INSIGHT_REQUIRE_HARDENED=1` that refuses to start without secure cookies and MFA.
- [x] **TIP 0.4 Pin connector connections to the checked DNS addresses,** closing the DNS-rebinding gap (code
      review L1): source syncs, CVE lookups and alert webhooks connect to the address they checked.
- [x] **TIP 0.5** `/health` reports liveness. Signed-in users can read the version from `/api/session`.
- [x] **TIP 0.6 Encrypt the TOTP secret at rest.** Revision `0017` migrates existing pairings. [Upgrade and recovery](docs/RUNBOOK.md#sign-in-second-factor-mfa)
- [x] **Review B2 Throttles into one place** ([ADR 0023](docs/adr/0023-automatic-cve-lookups.md)): one throttle
      per provider in `insight.lookups`, shared by the API, the workspace and the automatic lookups. (The sync
      lock already lived in one place.)
- [x] **TIP 1.1 Complete KEV fields:** known ransomware use, vulnerability name, notes and CWEs (with TIP
      1.3, [ADR 0024](docs/adr/0024-prioritised-cves.md)), and a documented inbox policy for older entries
      ([RUNBOOK section 8](docs/RUNBOOK.md#8-sources-enrichment-and-their-failures)).
- [x] **TIP 1.2 Automatic NVD and EPSS lookups** ([ADR 0023](docs/adr/0023-automatic-cve-lookups.md)): off until
      switched on per provider; CVEs from TLP:CLEAR and GREEN reports, newest first, through the job queue;
      optional `INSIGHT_NVD_API_KEY`. With review C2: a parsed score per CVE in the reader, the dialog and
      `GET /api/cves/{cve}/scores`.
- [x] **TIP 1.3 The brief and a prioritised CVE view use them** ([ADR 0024](docs/adr/0024-prioritised-cves.md)):
      ransomware-used KEV entries first, NVD CVSS next to CSAF scores, EPSS with a plain-language caveat; the
      *Prioritised CVEs* tab and `GET /api/cves` rank by stated rules and say why.

## 0.8.0: alerts and more feeds

- [x] [#15](https://github.com/andrewjscott88/insight/issues/15) **TIP 1.4 Notifications (M4):** done in 0.7.0
      (above). Destinations are managed in the workspace or with `insight notify`.
- [x] **Review J3 Per-source redistribution rules** (public, or metadata only), applied by the report and IOC
      exports ([ADR 0021](docs/adr/0021-threat-research-sources.md)); STIX and MISP must apply them too.
- [x] **TIP 1.5 abuse.ch connectors:** URLhaus, ThreatFox and MalwareBazaar (indicators and metadata only, never
      samples; keys from the environment).
- [x] **TIP 1.6 AlienVault OTX pulses** with the operator's own key. Imports subscribed public CLEAR/WHITE
      pulses and their supported indicators. [Operator guide](docs/RUNBOOK.md#8-sources-enrichment-and-their-failures).
- [x] **Review D2 CIDR indicator kind:** IPv4 and IPv6 network ranges in report review, search and IOC export.
- [x] **Review D2 E-mail indicator kind:** review and find full addresses across reports, with a personal-data warning on each address.
- [x] [#9](https://github.com/andrewjscott88/insight/issues/9) **TIP 1.7 Extraction quality (M1), 0.8.0:**
      three attributed government advisory excerpts, four labelled syntax cases, bracketed HTTP(S) schemes,
      word-form e-mail separators, and an updated [benchmark](docs/EXTRACTION.md#measuring-quality).
      Corpus expansion is ongoing.

## 0.9.0: speaks STIX, ATT&CK and MISP

- [x] [#12](https://github.com/andrewjscott88/insight/issues/12) **TIP 2.1 STIX 2.1 export (M5),** validated on
      every export with publisher and retention checks. The offline round-trip test covers report IDs, values, handling and technique links.
- [x] **TIP 2.2 STIX 2.1 import** from a local file, CLI or API, with atomic imports, publisher restrictions,
      TLP raising and instance/key limits. [Import guide](docs/API.md#post-apiimportstix)
- [x] **TIP 2.3 ATT&CK techniques.** STIX Reports link to the catalog techniques tagged on each included
      report revision. Each exported `attack-pattern` carries that report's sharing label and MITRE technique ID.
- [x] **TIP 2.9 Network sensor export:** download Suricata or Snort 3 alert rules for the reviewed
      IP or domain blocklist. [Sensor rule formats](docs/IOC_EXPORT.md#network-sensor-rules).
- [x] **TIP 2.4 MISP export and import,** host CLI for event files and trusted MISP instances. [Guide](docs/MISP.md)

## 1.0: context around the indicators

- [x] **TIP 2.5 Actors and campaigns.** Analysts create records and explicitly link them to reports,
      indicators and ATT&CK techniques. STIX exports include the selected, visible links.
- [x] **TIP 2.10 Industry threat profiles and actor threat guides** (requested by Andrew, 2026-11-21): pick an
      industry and see the top ten threat groups known to target it, each with its evidence; open one and export
      a threat guide (aliases, targets, ATT&CK techniques and Navigator layer, tools, mitigations, your reports
      that name it, sources, TLP). The guide includes **threat hunt information** so analysts can start a hunt
      from it: hypotheses per technique with the data sources to search, an indicator sweep list from your
      reports, linked Sigma/YARA rules, and a hunt record. Needs a bundled threat-group library (ATT&CK groups
      plus sourced industry data); builds on TIP 2.3, 2.5 and 2.7.
      *Done (unreleased):* [docs/THREAT_GUIDES.md](docs/THREAT_GUIDES.md), [ADR 0025](docs/adr/0025-threat-guides.md).
- [x] **TIP 2.7 YARA and Sigma rules as linked artifacts** (carried and exported, never executed).
      *Done (unreleased):* attach rules to reports, actors, techniques, CVEs and malware families. Download
      the rule and its handling manifest together. [Rule files](docs/THREAT_GUIDES.md#rules)
- [x] **TIP 2.6 Optional GreyNoise enrichment** for IP addresses (operator key; never a verdict by itself).
- [x] [#13](https://github.com/andrewjscott88/insight/issues/13) **TIP 2.8 PDF report ingestion,** keeping the
      file's hash as evidence.

## Later

- [x] **TIP 3.1 Read-only TAXII 2.1 server** over the STIX export: one *Reviewed indicators* collection for
      API keys, stable IDs, `added_after` polling ([ADR 0026](docs/adr/0026-taxii-server.md), [guide](docs/TAXII.md)).
- [x] [#17](https://github.com/andrewjscott88/insight/issues/17) **TIP 3.2 Ranked search and a graph view.** BM25-style ranking
      identical on SQLite and PostgreSQL, `GET /api/graph`, and a keyboard-friendly link map
      ([ADR 0027](docs/adr/0027-ranked-search-and-link-graph.md)).
- [x] **TIP 3.3 Exploit-availability signals,** metadata only: report signals and optional VulnCheck KEV
      ([ADR 0028](docs/adr/0028-exploit-availability.md)).
- [ ] [#14](https://github.com/andrewjscott88/insight/issues/14) **TIP 3.4 OIDC sign-in and roles (M3),** with an
      authenticated ZAP active scan.
- [ ] [#16](https://github.com/andrewjscott88/insight/issues/16) **TIP 3.5 Multi-worker deployments:** shared rate
      limits (sessions are already in the database).
- [x] [#11](https://github.com/andrewjscott88/insight/issues/11) **PostgreSQL datetime columns and feed cursors
      (M2):** `timestamptz` on PostgreSQL, resumable OTX syncs, a tighter PostgreSQL budget
      ([ADR 0030](docs/adr/0030-postgres-timestamps-and-feed-cursors.md)).
- [x] **TIP 3.8 Lightweight case management** ([ADR 0029](docs/adr/0029-cases.md)).
- [ ] **TIP 3.6 Opt-in LLM proposals** under the contract in [docs/LLM_EXTENSION.md](docs/LLM_EXTENSION.md).
- [x] **TIP 3.7 Optional Shodan enrichment** with the operator's own key ([ADR 0031](docs/adr/0031-shodan.md));
      Censys waits for its Platform API transition.

**Out of scope on purpose:** cloning CrowdStrike, Mandiant or Recorded Future collection, a malware sandbox,
automated adversary attribution, and any always-on cloud AI.

## Done

### 0.6.0 (20 November 2026)

- [x] [#10](https://github.com/andrewjscott88/insight/issues/10) **Scheduled source syncs,** opt-in
      ([ADR 0018](docs/adr/0018-opt-in-scheduled-syncs.md)).
- [x] Verdicts, warning flags and a safe blocklist; report deletion; sign-in sessions stored in the database with
      **Sign out everywhere**; CISA CSAF advisories; the intel brief; a lighter pipeline with one tag per release.
      Details in the [CHANGELOG](CHANGELOG.md).

### 0.5.0

- [x] [#4](https://github.com/andrewjscott88/insight/issues/4) **Pin GitHub Actions to commit SHAs and the base
      image to a digest.**
- [x] [#5](https://github.com/andrewjscott88/insight/issues/5) **Get the `v0.5.0-rc.1` milestone gate green.**
- [x] [#6](https://github.com/andrewjscott88/insight/issues/6) **Commit the 0.5.0 upgrade fixture,** update
      `docs/VALIDATION.md` and tag `v0.5.0`.
- [x] [#7](https://github.com/andrewjscott88/insight/issues/7) **Repository settings:** branch protection, a
      `release` environment with a required reviewer, GHCR image visibility.
- [x] [#8](https://github.com/andrewjscott88/insight/issues/8) **Fix:** a refused CVE-enrichment request no longer
      starts the enrichment window.
