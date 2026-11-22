# Brief: TIP 4.6 Infrastructure pivots

Required for 1.0. ADR number reserved: **0037**. Read [AGENTS.md](../../AGENTS.md) first.

## Goal

From a reviewed indicator, let the analyst pivot to the infrastructure around it, one approved lookup at a
time, and see the results in the link map: who registered a domain or address (RDAP), which names appear on
its certificates (certificate transparency through crt.sh), which network announces an address (IP to ASN),
and what it resolved to (passive DNS, where the operator has access, for example CIRCL for vetted users).

## What already exists (copy this pattern)

- **Two manual lookups with the exact rules to follow:** GreyNoise Community (`greynoise.py`) and Shodan
  (`shodan.py`), with `services/ip_enrichment.py`, throttles in `lookups.py` and the `Enrichment` table as the
  cache. Read [ADR 0031](../adr/0031-shodan.md): only a reviewed indicator in a current TLP:CLEAR report;
  the operator approves each uncached lookup; never scheduled; one throttle per provider shared by every
  caller; answers cached (24 hours) and eligibility rechecked on every read; every lookup audited; metadata
  only; an answer about another value refused; errors written by Insight, never echoing a URL or credential.
- **Outbound connections:** `connectors.download` and `egress.py` (HTTPS, allowlisted hosts, addresses checked
  before connecting, size caps).
- **The link map:** `services/graph.py` and `GET /api/graph` ([ADR 0027](../adr/0027-ranked-search-and-link-graph.md)),
  shown in the workspace with **Show links**.
- **The indicator explorer** (`ui/entities.py`) already offers the GreyNoise and Shodan buttons.

## Build

1. **RDAP** for domains and IP addresses. Use pinned copies of the IANA RDAP bootstrap files (with a script
   to refresh them), so the allowlist is exactly the RDAP servers they name. Keep registrar, status, creation,
   change and expiry dates, name servers, and for addresses the network name, handle, range and country.
   **Never store or show contact details** of registrants or other entities: they are personal data.
2. **Certificate transparency** through crt.sh's JSON output for a domain: names on certificates, issuer,
   validity dates; de-duplicated and capped (for example 500 names). crt.sh is fragile: a slow throttle and
   clear errors.
3. **IP to ASN** for addresses, from an HTTPS JSON source with published terms (RIPEstat, for example): the
   announcing AS number, its holder and the announced prefix. No DNS-based services: Insight's egress is
   HTTPS only.
4. **Passive DNS**, off unless the operator configures credentials (CIRCL pDNS uses HTTP basic
   authentication; read them from settings such as `INSIGHT_CIRCL_PDNS_USER` and `INSIGHT_CIRCL_PDNS_PASSWORD`).
   Keep name, type, answer, first and last seen, and count; cap the rows.
5. **Switches.** Each provider is off by default and switched on in Settings (audited, like source switches),
   in addition to the per-lookup approval.
6. **API and workspace.** `POST /api/pivots/{provider}` with the value (a session or an unlimited read-write
   key, as for Shodan) and `GET /api/pivots?value=...` for cached results; a **Pivot** choice in the indicator
   explorer with one button per enabled provider, and a confirmation that names the provider and says the
   value leaves Insight.
7. **Link map.** Pivot results become nodes (domain, address, AS, certificate name, name server) with edges
   labelled by provider and date. A result that matches a known indicator links to it. Results never become
   indicators or observations by themselves.

## Not in scope

Scheduled or bulk pivots; paid providers other than passive DNS the operator already has; storing contact
details.

## Constraints

- Every host on the allowlist, HTTPS only, size caps and timeouts, offline parser fixtures for each provider
  (including malformed and oversized answers), and a `tests/live` case for each.
- The `Enrichment` table (provider and subject) should hold the cache without a migration; check before
  adding one.
- Add the providers and their terms to SECURITY.md and the outbound-connections documentation.

## Suggested parts

1. RDAP and IP to ASN, with the link map changes.
2. Certificate transparency.
3. Passive DNS.

## Done when

Every item in the AGENTS.md checklist is met for each part, the docs above and API.md, API_GUIDE.md,
CHANGELOG.md, README.md, ROADMAP.md and ROADMAP-TIP.md are updated, and ADR 0037 records the decisions.
