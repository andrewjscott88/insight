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
- [ ] **TIP 0.1 Verify every public deployment.** Anonymous `GET /` answers 303 to `/login`; `.env` sets secure
      cookies, allowed hosts and trusted proxies, preferably MFA. A smoke check for the public URL.
- [x] **TIP 0.2 Fix stale session and scheduling documentation.** README and ARCHITECTURE now describe stored
      sessions, opt-in schedules and the job runner.
- [ ] **TIP 0.3 Safer public-deploy defaults.** Stronger start-up warnings when Insight is internet-facing, and an
      optional `INSIGHT_REQUIRE_HARDENED=1` that refuses to start without secure cookies and MFA.
- [ ] **TIP 0.4 Pin connector connections to the checked DNS addresses,** closing the DNS-rebinding gap.
- [ ] **TIP 0.5 `/health` without the version;** the version moves behind sign-in.
- [ ] **TIP 0.6 Encrypt the TOTP secret at rest,** migrating existing rows.
- [ ] **Review B2 Throttles and locks into services,** so the API, the workspace and the automatic enrichment
      below share one implementation.
- [ ] **TIP 1.1 Complete KEV fields:** known ransomware use, vulnerability name, notes and CWEs; a documented inbox
      policy for older KEV entries.
- [ ] **TIP 1.2 Automatic NVD and EPSS enrichment** for newly seen CVEs: opt-in, throttled, through the job queue
      (with review C2, a cached score per CVE).
- [ ] **TIP 1.3 The brief and a prioritised CVE view use them:** ransomware-used KEV entries, NVD CVSS next to
      CSAF scores, EPSS with a plain-language caveat (review C2).

## 0.8.0: alerts and more feeds

- [ ] [#15](https://github.com/andrewjscott88/insight/issues/15) **TIP 1.4 Notifications (M4).** Signed webhooks
      and e-mail when a new report matches a watch term or KEV gains an entry; destinations set from the CLI or the
      workspace, never with an API key.
- [ ] **Review J3 Per-source redistribution rules** (allow, or metadata only), applied by every export, before the
      new feeds and before STIX and MISP.
- [ ] **TIP 1.5 abuse.ch connectors:** URLhaus, ThreatFox and MalwareBazaar (indicators and metadata only, never
      samples; keys from the environment).
- [ ] **TIP 1.6 AlienVault OTX pulses** with the operator's own key.
- [ ] **Review D2 E-mail and CIDR indicator kinds,** with e-mail addresses flagged as personal data.
- [ ] [#9](https://github.com/andrewjscott88/insight/issues/9) **TIP 1.7 Extraction quality (M1),** ongoing: a
      larger labelled corpus, the defanged-indicator gaps in [docs/EXTRACTION.md](docs/EXTRACTION.md), a
      ratcheted benchmark.

## 0.9.0: speaks STIX, ATT&CK and MISP

- [ ] [#12](https://github.com/andrewjscott88/insight/issues/12) **TIP 2.1 STIX 2.1 export (M5),** validated on
      every export, with a round-trip test.
- [ ] **TIP 2.2 STIX 2.1 import** with TLP raising and the instance TLP limit.
- [x] **TIP 2.3 ATT&CK techniques:** done in 0.7.0 (above); STIX export carries them as `attack-pattern` objects.
- [ ] **TIP 2.9 Suricata/Snort-oriented export** of the blocklist population.
- [ ] **TIP 2.4 MISP export and import,** CLI first.

## 1.0: context around the indicators

- [ ] **TIP 2.5 Actors and campaigns, created by the analyst.** ATT&CK groups only as a labelled catalog; never
      attribution from shared indicators.
- [ ] **TIP 2.7 YARA and Sigma rules as linked artifacts** (carried and exported, never executed).
- [ ] **TIP 2.6 Optional GreyNoise enrichment** for IP addresses (operator key; never a verdict by itself).
- [ ] [#13](https://github.com/andrewjscott88/insight/issues/13) **TIP 2.8 PDF report ingestion,** keeping the
      file's hash as evidence.

## Later

- [ ] **TIP 3.1 Read-only TAXII 2.1 server** over the STIX collections.
- [ ] [#17](https://github.com/andrewjscott88/insight/issues/17) **TIP 3.2 Ranked search and a graph view.**
- [ ] **TIP 3.3 Exploit-availability signals,** metadata only, from terms-reviewed sources.
- [ ] [#14](https://github.com/andrewjscott88/insight/issues/14) **TIP 3.4 OIDC sign-in and roles (M3),** with an
      authenticated ZAP active scan.
- [ ] [#16](https://github.com/andrewjscott88/insight/issues/16) **TIP 3.5 Multi-worker deployments:** shared rate
      limits (sessions are already in the database).
- [ ] [#11](https://github.com/andrewjscott88/insight/issues/11) **PostgreSQL datetime columns and feed cursors
      (M2).**
- [ ] **TIP 3.8 Lightweight case management.**
- [ ] **TIP 3.6 Opt-in LLM proposals** under the contract in [docs/LLM_EXTENSION.md](docs/LLM_EXTENSION.md).
- [ ] **TIP 3.7 Optional Shodan or Censys enrichment** with the operator's own keys.

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
