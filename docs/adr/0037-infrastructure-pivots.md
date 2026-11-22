# 0037 — Manual infrastructure pivots

Status: Proposed

## Context

Analysts need bounded infrastructure context while preserving the manual disclosure controls in ADR 0031:
reviewed/current/CLEAR evidence, explicit uncached approval, audit, cache eligibility and shared throttles.

## Part 3: passive DNS

Register only `circl` in this independent part. Credentials are host settings, never database rows or API
inputs. A switch cannot be enabled without them, and removing credentials makes an existing switch
ineffective. Credentials are checked again before the request. The fixed CIRCL HTTPS endpoint gets a
Basic Authorization header through the guarded downloader; no redirects, other hosts or URL credentials.
Always disable the provider's default active resolver with `dribble-disable-active-query`.

Use a five-second shared throttle, one in-flight request, 30 seconds and 2 MB; request 501 rows, retain at
most 500, never follow cursors. Every bounded NDJSON record must have a query-matching endpoint. Preserve
provider name/answer direction instead of inferring ownership, and drop unknown fields. Duplicates combine
the widest observation interval and maximum reported count, never a sum. Missing counts stay unknown.

The graph resolves at most 26 candidate neighbours for its 25-row display cap. It adds no indicators and
links only reader-visible known values. Cache reads require current accepted CLEAR evidence even when no
network request occurs. Switching off blocks outbound calls but does not erase eligible cached data.
No migration or dependency. [Operator and provider conditions](../INFRASTRUCTURE_PIVOTS.md).

## Scope and integration

This main-based PR carries shared support so it can pass independently. RDAP/ASN and certificate
transparency remain separate companion parts; shared registry, route, UI and graph changes need additive
reconciliation when combined. TIP 4.6 remains open until every part is reviewed and integrated.
