# ADR 0043: private Censys Platform host context

- Status: Accepted (1.0.0)
- Date: 2026-11-23

## Decision

Use the Censys Platform v3 single-host endpoint, not the retired Legacy Search API. This extends the manual
exposure-context workflow in [ADR 0031](0031-shodan.md) to reviewed public IPv4 and IPv6 addresses. It does
not add search, bulk lookup, live scans, schedules, automatic attribution, or new indicators.

The operator configures `INSIGHT_CENSYS_PAT` on the host. `INSIGHT_CENSYS_ORG_ID` is optional and must be a
UUID if supplied. A missing or malformed setting makes no request. Tokens are sent only in the bearer
header to `api.platform.censys.io`; the optional organization ID is a query parameter. No credential is
accepted through the workspace or stored in the database. The connector uses the v3 host-v1 Accept header.

Only an accepted observation in a current TLP:CLEAR report makes an address eligible. Every cache read
rechecks this rule and takes the caller's `max_tlp`. A POST requires explicit `approved: true`; callers are
a signed-in session with CSRF or an unlimited read-write key. Other keys may read eligible cached context.
The browser checkbox names Censys, the address disclosed and the account terms. Nothing runs on page load.

One shared in-flight lock and a two-second provider throttle cover all manual callers. Provider `429` and
`503` responses defer later calls according to bounded Retry-After, or 60 seconds when absent. Answers,
including inaccessible/missing records, are reused for 24 hours. Errors do not replace earlier cached
answers. Each actual outbound attempt is audited before the request, successful cache writes are audited,
and POST cache reuse is audited, with the session or API-key actor. Retention removes the cache with its
indicator. The existing `Enrichment` table is sufficient; no migration or dependency is added.

## Data and connection limits

`connectors.download` pins connections to the public addresses checked by `egress.py`, requires HTTPS,
allows only the fixed API host, refuses redirects, applies its connection/read timeouts and total deadline, and caps the response at
1,000,000 bytes. Field projection asks only for the subject IP, host names, announcing network, country
code and service port/protocol/transport/observation times. The parser checks the returned subject and
network prefix and keeps at most 100 distinct service rows and 20 host names. Unexpected or oversized
answers have Insight-written errors. Provider error bodies, URLs and credentials are never echoed.

Contact details, WHOIS contacts, precise location, certificates, banners, HTTP headers, response bodies
and other raw protocol fields are discarded. Observations remain provider context, never a verdict.
The user sees Censys attribution and a link; a missing record means no accessible result, not a safe host.

## Account terms and private use

The operator must use an account whose terms permit their purpose. As reviewed on the date above,
[general terms](https://censys.com/terms-of-service/) section 3.1 limits Free/Researcher commercial use and
third-party incorporation; section 3.2 requires attribution for free use. The
[Starter terms](https://censys.com/self-service-subscription-terms-of-service/) section 2.1 limits use to the
customer's internal purposes and excludes third-party product/service enrichment; section 2.3 covers
registered users and credential sharing. An operator's applicable agreement governs their access.

Our conservative implementation refuses both Censys lookup and cached-read routes while temporary open
access is enabled. The rest of Insight's access mode is unchanged. The workspace still shows setup
guidance, so the feature does not vanish when no token is configured. Censys cache data is not included
in report exports, STIX, TAXII, MCP, hunt packages, focused briefs or the link map. This private-cache
boundary avoids treating the source indicator's CLEAR label as a licence to redistribute provider data.

## References and validation

- [Single-host API](https://docs.censys.com/reference/v3-globaldata-asset-host)
- [Authentication, organization IDs, credits and rate limits](https://docs.censys.com/reference/get-started)
- [Platform transition guide](https://docs.censys.com/docs/platform-api-transition-guide)

Offline fixtures mirror the documented `result.resource` envelope, with synthetic values. Focused tests
cover projection, wrong subjects, malformed/oversized data, credential handling, IPv6, disclosure approval,
cache expiry/revocation, audit, retention, middleware authorization, GREEN-key filtering and the workspace.
`tests/live/test_censys.py` is separately opt-in with `INSIGHT_LIVE_CENSYS=1`; it is not run during ordinary
tests because it sends a public test address and can consume account credits. No live provider validation
is claimed by the offline tests.
