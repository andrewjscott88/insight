# ADR 0035: Sightings from hunt tools

Status: Accepted

## Context
TIP Phase 4 lets intelligence flow back from hunt tools (the maintainer's is Shift), but only as intelligence:
requests for information (ADR 0032) and **sightings**, "seen in our environment, at this time". A sighting is
the strongest evidence that an indicator is real and current, so it should feed the confidence score (ADR
0033). Insight must never record what was done about an indicator. TIP 4.2 is required for 1.0.

Constraints: TLP per reader everywhere (ADR 0013, 0014); one audit log; the narrowest key access a hunt tool
needs; one active API key at a time (ADR 0012), so one key must cover everything a hunt tool sends.

## Decision
1. **Sightings** (migration 0027). Each row names a known indicator, the first and last time it was seen, how
   often, where (in the reporter's words), what saw it, a note, the reporter's own reference, an optional hunt
   package (ADR 0034) and a TLP label. Deleting the indicator deletes its sightings; deleting the package
   keeps them.
2. **Known indicators only.** `POST /api/sightings` takes the value as Insight serves it (and the kind, if a
   value could be more than one) and refuses an indicator Insight does not know, or that no report within the
   caller's limit mentions (`404`). Insight's indicators come from reports; a hunt tool cannot create one.
3. **Labels.** A sighting's label defaults to AMBER (it describes your own network) and is raised by TLP
   markings in its text and by its hunt package's label. A reader sees a sighting only within its limit, and
   only for an indicator a report within its limit mentions.
4. **Confidence.** Each place an indicator was seen counts as one completely reliable source (reliability A),
   weighing 0.9 when fresh and ageing from when it was last seen, with the indicator kind's half-life (ADR
   0033). Several sightings at one place count once. A reader's score uses only the sightings it may see.
5. **One key level for hunt tools.** The unreleased `read-rfi` access level becomes `read-feedback`: GET
   requests, plus `POST /api/rfis` and `POST /api/sightings`, and nothing else. Migration 0027 renames
   existing `read-rfi` keys. An unknown access level is still treated as read-only.
6. **Interfaces.** `POST`/`GET /api/sightings` and `DELETE /api/sightings/{id}` (for one reported by
   mistake); sightings in the confidence of `GET /api/entities/{id}`; in the indicator explorer, "Seen in your
   own data" and each place in the confidence breakdown. Audited as `sighting.add` and `sighting.delete` on
   the indicator.
7. **Not built yet.** STIX `sighting` objects (in TAXII or an import), sightings of indicators Insight does
   not know, and alerts on new sightings.

## Consequences
- An indicator seen in your own data recently scores high whatever the reports say; one seen long ago fades
  like an old report.
- A hunt tool needs one key, with the narrowest access that lets it ask questions and report what it saw.
- `where` and `observer` are free text: they are shown as given and may describe your network, which is why
  the default label is AMBER.
