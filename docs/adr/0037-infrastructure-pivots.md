# 0037: Approved infrastructure pivots

Status: Proposed (TIP 4.6, part 1; checks and maintainer review pending)

## Decision

Reuse `Enrichment(provider, subject)` for bounded metadata and `SourceSwitch` with `pivot:` keys for
audited provider switches. No migration or dependency is required. Providers start off. An uncached lookup
requires explicit consent, a reviewed observation in a current TLP:CLEAR report, and either the operator
session or an unlimited read-write API key. Cached reads also recheck eligibility and expire after 24 hours.
The services accept the caller's TLP ceiling; hidden and missing subjects have the same response.

Use pinned, SHA-256-checked copies of IANA's DNS, IPv4 and IPv6 RDAP bootstrap files. The manual refresh script
uses the existing guarded downloader. Review all changed hosts before updating the pins. Select the longest
matching prefix or domain suffix. Use only HTTPS URLs explicitly present in the bootstrap: HTTP-only
registries are unavailable, not silently upgraded. Never follow referrals, redirects or returned links.

Keep registration dates, status, name servers, network name, handle, range and country. For a registrar,
retain only its public IANA identifier. This is the conservative interpretation of the no-contact-data rule:
do not retain any entity or vCard fields, even a registrar's display name. No registrant, abuse or technical
contact details, notices, raw responses or remarks enter the cache or UI.

RIPEstat supplies the containing announced prefix and origin network numbers, then the holders of those
same origins. This is one approved operation with at most two requests to the same provider; the second
request sends only the already returned prefix. Validate that the prefix contains the requested address and
that the second response names the exact prefix and origin set. A mismatch fails closed. No DNS lookup
service or automatic recursive expansion is used. Unannounced addresses have an explicit empty result.

Use one lock and throttle per provider across API and UI. Each outbound request has a 30-second total
deadline, the downloader's connection timeout and a two-megabyte cap. Both providers wait at least two
seconds between requests and honor a rate-limit response. Errors are written locally and never echo provider
response text, a query URL or credentials. Audit approved attempts and successful cache writes. Retention
removes pivot cache rows with orphan indicators; cache writes use the existing entity-lock pattern.

Graph nodes are views of eligible cached metadata, with provider and fetch date on each edge. A matching
known indicator is linked only when visible to the caller. Otherwise the result remains provider context.
No pivot creates an indicator, observation, verdict or attribution. Stale or newly ineligible graph roots
are missing. The graph keeps its existing node and depth caps.

Certificate transparency and passive DNS are subsequent parts of this ADR and remain unimplemented here.
They must keep the same switches, disclosure rules, TTL, tests and transport boundary.

## Provider terms

- [IANA RDAP bootstrap registries](https://www.iana.org/assignments/rdap-dns): bootstrap routing does not
  replace the individual registry's RDAP terms. The operator must be allowed to query that registry.
- [RIPEstat usage](https://stat.ripe.net/docs/getting-started/what-is-ripestat): the public API permits
  non-commercial applications; contact RIPE NCC for commercial use. Do not imply blanket commercial rights.
- [Network info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) and
  [prefix overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview) define the projection.

## Validation

Offline parser fixtures include contacts to discard, invalid data, oversized responses and wrong subjects.
Service/API tests cover consent, switches, cache revalidation, expiry, key access and graph labels. The
GREEN-key sweep plants a hidden pivot cache. The NiceGUI test checks consent before disclosure. Opt-in live
checks require `INSIGHT_LIVE_PIVOTS=1` and use public test subjects only. Full SQLite/PostgreSQL, strict typing,
milestone and CodeQL checks are required before readiness is claimed.
