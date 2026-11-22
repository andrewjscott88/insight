# 0037 — Manual infrastructure pivots

Status: Proposed

## Context

Analysts need bounded infrastructure context without silently disclosing their report contents or interests.
ADR 0031 already defines the reviewed/current/CLEAR, consent, cache, audit and shared-throttle boundary.

## Part 2: certificate transparency

Reuse that boundary in generic pivot services and routes. The provider registry in this part contains only
`crtsh`; domains are eligible, IP addresses are not. Read-only and limited keys can read eligible cached
context; only a session or unlimited read-write key can request a lookup. Hidden and missing values both
return 404. Switching off stops new requests; eligible cached context expires after 24 hours.

The adapter keeps only bounded, validated metadata and checks every certificate against the requested
domain. It deduplicates names and keeps the newest validity record per name. Other names on the same
certificate are context, not inferred ownership. The graph adds no indicators and links only known values
visible to the reader. Limit graph rows before resolving known indicators to bound database work.

Use one fixed HTTPS host through the guarded downloader, no redirects, 2 MB / 30 seconds and a conservative
60-second shared throttle. Treat malformed, oversized and unrelated answers as failures; never cache them.
No new dependencies or migration. Provider terms, limitations and the exact metadata fields are in
[Infrastructure pivots](../INFRASTRUCTURE_PIVOTS.md).

## Scope and integration

This main-based PR includes shared support so it can pass independently. Only certificate transparency is
implemented here. RDAP/ASN and credential-gated passive DNS are separate parts, not claimed complete by
this decision. Shared support must be reconciled when those independently reviewed branches are combined.
The overall TIP 4.6 milestone remains open until every part is reviewed and integrated.
