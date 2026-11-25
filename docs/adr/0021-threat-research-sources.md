# ADR 0021: Threat-research sources, switched on by the operator, with per-publisher reuse rules

Status: Accepted

## Context
Insight's four sources (CISA KEV, CISA's CSAF advisories, SANS ISC, UK NCSC) are mostly about weaknesses. The
threat landscape (ADR 0020) and ATT&CK mapping (ADR 0019) need reporting on threat activity: crime groups,
state-backed spying, campaigns, malware. The 0.5.0 review (J3) required per-source redistribution rules before
Insight adds feeds with their own terms, and before any export carries publishers' words to other tools.

## Decision
1. **Six optional sources, all RSS.** Cisco Talos, Microsoft Threat Intelligence, The DFIR Report, ESET
   WeLiveSecurity and Kaspersky Securelist (threat research), and The Record by Recorded Future News (news).
   Each feed address was checked against public feed directories; a publisher that moves its feed shows up as a
   failed sync in the Sources tab, never as silent data loss. CISA's cybersecurity-advisory RSS feed is not
   included: CISA refuses automated clients (the reason Insight reads CISA's CSAF files instead).
2. **Off until switched on.** Optional sources start switched off, so an upgrade never makes Insight contact a
   new host. The operator switches any source on or off in the Sources tab (audited as `source.on` and
   `source.off`, stored in `source_switches`, migration 0010). A switched-off source is never contacted:
   *Sync now* refuses it (API: `409`), *Sync all sources* and "schedule every source" skip it, and switching
   off also turns its schedule off. API keys cannot switch sources, as they cannot change schedules.
3. **Only what a feed reader shows.** As for the existing feeds, Insight keeps the title, the publisher's own
   summary (at most 500 characters) and the link; it never fetches the article and never reads
   `content:encoded`.
4. **Reuse rules per source** (`insight/source_registry.py`, dependency-free so services can apply them):
   `public` for US government works (CISA KEV and CSAF), `metadata` for every other publisher, including the
   existing SANS ISC and NCSC feeds whose notes always said "feed metadata only". For `metadata` sources the
   report export leaves out the text and each indicator's evidence, and the IOC export sets `evidence` to `null`
   for their mentions. Titles, links, dates, indicator values and counts still leave Insight. Reports the
   analyst pasted are theirs: no rule applies.

## Consequences
- The landscape's themes see far more threat reporting once sources are switched on; the share test in ADR 0020
  keeps a busy news feed from making everything look like it is rising.
- RSS summaries rarely name ATT&CK technique IDs, so most technique tags still come from analysts and from
  reports pasted in full.
- An export from Insight 0.7.0 differs from 0.6.0 for SANS ISC and NCSC reports: their summaries and evidence
  are no longer included. This is the documented behaviour change of J3.
- STIX, MISP and TAXII exports (TIP 2.1, 2.4, 3.1) must apply the same rule.
