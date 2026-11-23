# ADR 0026: A read-only TAXII 2.1 server over the STIX export, with stable objects

Status: accepted (unreleased)

## Context
SIEMs and threat-intelligence platforms (Microsoft Sentinel, OpenCTI, MISP and others) pull STIX from TAXII 2.1
servers on a schedule. Insight already exports validated STIX 2.1 (`GET /api/iocs/stix`, TIP 2.1), but a
polling client cannot use those exports directly:

- **Random IDs.** Each export gives every indicator a new random STIX ID, so a client polling twice stores
  every indicator twice.
- **No change times.** Every object's `modified` is the export time, so `added_after` (the TAXII way to ask
  "what changed since my last poll?") would return everything, every time.
- **No acceptance time.** An analyst often accepts an indicator days after its report arrived. Nothing
  recorded when, so a poll could never tell that the indicator just became shareable.

Constraints: the same sharing rules as every export (TLP per API key, review status, publisher reuse rules,
ADR 0013, 0014, 0021); nothing written through TAXII; no API key may create a collection; offline, single
worker; no new dependency unless it can be hash-pinned and trimmed (TIP 3.1).

## Decision
1. **A thin FastAPI implementation, read-only.** `/taxii2/` (discovery), one API root `/taxii2/insight/`, its
   collections, and for each collection `objects/` (with `added_after`, `limit`, `next`, `match[id]`,
   `match[type]`, `match[version]`, `match[spec_version]`), `manifest/`, `objects/{id}/` and
   `objects/{id}/versions/`. No `POST`, no status resource. OASIS medallion was not used: it brings its own
   storage backends and write paths that would all need removing.
2. **API keys only.** A signed-in browser gets `403` (the workspace has its own STIX download); no key gets
   `401`. Read-only and TLP-limited keys work; each sees only what its TLP limit allows.
3. **Fixed collections, defined in code.** v1 has one: *Reviewed indicators* (`insight.taxii.COLLECTIONS`).
   Nothing (setting, key or table) can create another.
4. **The STIX export's own selection.** A collection read runs the export pipeline with
   `review_statuses=('accepted',)` and the key's TLP limit, so superseded revisions, verdict meanings and
   publisher reuse rules apply unchanged, and the bundle is validated with the OASIS validator before any
   page is served. Each read is audited (`taxii.read`).
5. **Stable objects.** In TAXII mode the builder gives each indicator and CVE a UUIDv5 from its kind and
   value (`insight.stix_export.stable_id`, fixed namespace), so the same indicator has the same ID in every
   poll and for every key. Reports already use `report--<report id>`.
6. **Real change times.** Migration 0018 adds `observations.reviewed_at`, set whenever a review changes a
   mention's status. An indicator's or report's `modified`, and its `date_added`, is the latest arrival or
   review time of its visible accepted mentions. A TLP marking definition takes the `date_added` of the
   newest object it marks, so an incremental poll always brings the markings it needs. Pagination is keyset on
   `(date_added, id)`, so pages stay consistent while new objects arrive.
7. **One version per object.** Insight serves the current version only; `versions/` lists it, and
   `match[version]=first|last|all` all select it.
8. **Its own rate budget.** Each page is built from a full snapshot, so pages hold up to 1,000 objects and
   reads draw on a `taxii` budget of 240 per hour per key (the export budget of 30 per hour would stop a
   client paging through its first sync).

## Consequences
- A SIEM can poll Insight with a standard TAXII 2.1 client and a Bearer key, and `added_after` returns only
  what changed, including indicators accepted long after their report arrived.
- Indicator IDs are stable across polls and keys, so a client never stores duplicates.
- **Not in v1:** revocation: an indicator that stops being shareable (rejected, or its report deleted) simply
  stops appearing; clients that need removals should re-pull the collection.
- **Added in 0.9.0:** the indicators collection also serves the ATT&CK techniques, actors, campaigns and
  relationships of the STIX export, with IDs derived from their content (a technique from the ATT&CK version,
  technique and markings; a restricted projection of an actor or campaign from its ID and label; a link from
  the link, its target and label). An actor or campaign is dated no earlier than its first visible
  relationship, so a newly linked old actor still reaches a polling client. A second fixed collection serves
  the CISA KEV catalog (TLP:CLEAR) with a real change time per entry (`kev_records.changed_at`, migration
  0020): a sync that changes nothing changes no version.
- Mentions reviewed before 0018 have no review time; their report's arrival time stands in. This only matters
  for a client that polled before the upgrade, and none could.
- Every page rebuilds and validates the snapshot. That is fine for one operator's collection (the export caps
  at 100,000 mentions; past that a read answers `413`), but not for a shared, high-volume feed.
- CI runs the hash-pinned OASIS Python client against a loopback Insight server. It checks discovery,
  unauthenticated access, paging, and agreement with the STIX export for a GREEN-limited key. The development and
  browser-test lock files pin the client.
