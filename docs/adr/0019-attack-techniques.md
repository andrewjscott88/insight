# ADR 0019: MITRE ATT&CK® techniques on reports, from the text and from analysts

Status: accepted (unreleased)

## Context
Threat intelligence analysts describe adversary behaviour in MITRE ATT&CK terms: which techniques a campaign
used, which ones are trending in their intake, which reports describe the same behaviour. Insight 0.6.0 stored
indicators and verdicts but no behaviour, so none of those questions could be answered. Every premium threat
intelligence platform and both open-source peers (MISP, OpenCTI) map reports to ATT&CK; the premium-TIP plan
(`docs/ROADMAP-TIP.md`, item 2.3) makes it the base for actors, campaigns and STIX export.

Three constraints shape the answer:

- **No guessing.** Insight's extraction is precision-first (ADR 0007), and it never infers attribution
  (README, "Scope and known limits"). A technique guessed from prose would be the same kind of claim.
- **No surprise traffic.** Insight goes online only when someone asks it to (ADR 0018).
- **Revisions.** Synced items get new revisions (ADR 0004). An analyst who corrected a mapping should not have
  to correct it again when the publisher edits a sentence.

## Decision
1. **A bundled, regenerated catalog.** `src/insight/data/attack-enterprise.json` holds every current Enterprise
   technique and sub-technique (ID, name, tactics) and the tactics in matrix order, about 65 KB.
   `scripts/update_attack.py` regenerates it from MITRE's `attack-stix-data` bundle; revoked and deprecated
   techniques are left out. It ships with Insight, so tagging works offline, and it is reproduced under MITRE's
   terms of use with MITRE's copyright notice (`NOTICE`). Mobile and ICS can follow the same way.
2. **Only IDs written in the report.** At ingest, `insight.attack.find_techniques` tags a report with every
   technique ID written in its text that is in the catalog (`source: report`): the author mapped it. The ID must
   stand alone (not `XT1059`, `T1059.0012` or `T1059-2`) and be uppercase. Nothing is inferred from prose,
   product names, CVEs or indicators, and no actor is ever inferred from techniques.
3. **Analysts decide the rest.** An analyst adds techniques (`source: analyst`) and removes wrong ones. A removal
   is kept as a row with `status: removed`.
4. **Per revision, with decisions carried forward.** Tags belong to one report revision (like observations, whose
   offsets index that revision's text). A new revision gets the IDs written in its own text plus every decision
   made on the revision it replaces: added techniques stay added, removed ones stay removed. A publisher reverting
   to an earlier revision brings the later decisions to it too.
5. **TLP like everything else.** Every read takes the caller's TLP limit. Summaries and pivots count current
   revisions the caller can see; a technique written only in an AMBER report does not exist for a GREEN key.
6. **ATT&CK Navigator, not a new visualisation.** `GET /api/attack/navigator` exports the summary as a Navigator
   layer (format 4.5), scored by report count, so analysts use the tool they already know.
7. **Backfill on request.** Reports stored before 0.7.0 get their tags from `insight attack-backfill`
   (`make attack-backfill`); a migration never imports application code.
8. **STIX report tags.** After the export filters select reports, each STIX Report links to its active,
   catalog-backed techniques through `object_refs`. This link means the report was tagged with that
   technique. A tag alone gives no basis for an actor attribution or an indicator-to-technique relationship.
   Each `attack-pattern` carries the catalog name, tactics, MITRE technique ID and URL, catalog version,
   copyright notice and terms. Tag evidence and analyst names stay in Insight. An export supports up to
   100,000 active report tags.
   Reports with the same sharing label reuse one object per technique in a bundle. A technique mentioned
   at two sharing levels gets two objects, each with the corresponding report marking. Match a technique
   across exports by its `mitre-attack` external ID. Each Insight catalog projection has a fresh STIX UUID.

## Consequences
- Analysts can see which techniques their intake describes, over any period, pivot from a technique to its
  reports, correct the mapping, and open the result in ATT&CK Navigator.
- Most reports name no technique IDs, so most mapping is the analyst's. Suggesting techniques from prose would
  need a reviewed model (the opt-in LLM contract in `docs/LLM_EXTENSION.md`) and is not part of this decision.
- The catalog ages: a new ATT&CK release needs `scripts/update_attack.py` and an Insight release. Tags on a
  technique that leaves the catalog stay, marked `in_catalog: false`.
