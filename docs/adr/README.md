# Architecture decision records

Short records of significant decisions: context, decision, consequences. New decisions get the next number;
superseded ones are marked, never deleted.

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-alembic-migrations.md) | Alembic owns the schema; datetime columns deferred | Accepted |
| [0002](0002-login-delay-not-lockout.md) | Sign-in throttling by delay, not lockout | Accepted |
| [0003](0003-single-query-layer-and-ui-panels.md) | One query layer; UI split into panel modules | Accepted |
| [0004](0004-revisions-for-synced-items.md) | Publisher edits become revisions, never edits or duplicates | Accepted |
| [0005](0005-container-and-supply-chain.md) | Hardened container and hash-pinned supply chain | Accepted |
| [0006](0006-five-tier-pipeline.md) | Five-tier CI/CD; CD means publishing | Accepted |
| [0007](0007-extraction-precision-first.md) | Extraction: a wrong indicator is worse than a missed one | Accepted |
| [0008](0008-folded-search-text.md) | Search on a folded copy of the text | Accepted |
| [0009](0009-tlp-policy.md) | TLP: default AMBER; markings can only raise the label | Accepted |
| [0010](0010-known-defect-register.md) | Known defects as strict expected-failure tests | Accepted |
| [0011](0011-offsets-code-points-and-utf16.md) | Evidence offsets: code points, plus UTF-16 for JavaScript | Accepted |
| [0012](0012-single-api-key-and-rate-limits.md) | One API key, managed from the CLI; per-caller rate limits | Accepted |
| [0013](0013-instance-tlp-limit.md) | An instance TLP limit; TLP:RED refused by default | Accepted |
| [0014](0014-per-key-tlp-limit.md) | A TLP limit per API key, enforced in the service layer | Accepted |
| [0015](0015-totp-second-factor.md) | TOTP second factor for the operator, managed from the CLI | Accepted |
| [0016](0016-colour-themes-and-per-device-choice.md) | Light and dark themes from one set of tokens; per-device choice | Accepted |
| [0017](0017-readability-standard.md) | Readability: WCAG 2.2 AA, its reading-related AAA criteria and dyslexia guidance | Accepted |
| [0018](0018-opt-in-scheduled-syncs.md) | Opt-in scheduled syncs with an in-process job runner | Accepted |
| [0019](0019-attack-techniques.md) | MITRE ATT&CK techniques on reports, from the text and from analysts | Accepted |
| [0020](0020-threat-landscape.md) | A threat landscape counted from the reports, compared with the weeks before | Accepted |
| [0021](0021-threat-research-sources.md) | Threat-research sources, switched on by the operator, with per-publisher reuse rules | Accepted |
| [0022](0022-alerts.md) | Alerts on watch-term matches and new KEV entries, sent by the job runner | Accepted |
| [0023](0023-automatic-cve-lookups.md) | Automatic NVD and EPSS lookups, with one throttle per provider | Accepted |
| [0024](0024-prioritised-cves.md) | A prioritised CVE view, and a brief that uses KEV ransomware use, NVD CVSS and EPSS | Accepted |
| [0025](0025-threat-guides.md) | Industry threat profiles and actor threat guides from a sourced, pinned threat-group library | Accepted |
| [0026](0026-taxii-server.md) | A read-only TAXII 2.1 server over the STIX export, with stable objects | Accepted |
| [0027](0027-ranked-search-and-link-graph.md) | Ranked search and a link graph from what Insight already records | Accepted |
| [0028](0028-exploit-availability.md) | Exploit-availability context from reports and VulnCheck KEV, metadata only | Accepted |
| [0029](0029-cases.md) | Lightweight case management | Accepted |
| [0030](0030-postgres-timestamps-and-feed-cursors.md) | Native PostgreSQL timestamps and resumable OTX syncs | Accepted |
| [0031](0031-shodan.md) | Optional Shodan exposure context for reviewed IPs | Accepted |
| [0032](0032-intelligence-requirements.md) | Intelligence requirements and requests for information | Accepted |
| [0033](0033-confidence-and-source-reliability.md) | Confidence, source reliability and report credibility | Accepted |
| [0034](0034-hunt-packages.md) | Hunt packages over TAXII | Accepted |
| [0035](0035-sightings.md) | Sightings from hunt tools | Accepted |
| [0036](0036-intelligence-products.md) | Finished intelligence products | Accepted |
| [0038](0038-adversary-library.md) | Adversary library imports | Accepted |
| [0039](0039-read-only-mcp.md) | Read-only MCP with API keys and per-key TLP ceilings | Accepted |
