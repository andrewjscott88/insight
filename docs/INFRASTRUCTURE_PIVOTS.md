# Infrastructure pivots

RDAP returns registry metadata and RIPEstat returns the network announcing a public address. To enable these providers and query a reviewed indicator, see the [API guide](API_GUIDE.md) and [ADR 0037](adr/0037-infrastructure-pivots.md).

## Certificate transparency (TIP 4.6 part 2)

In **Settings › Sources › Infrastructure lookups**, turn on **Use crt.sh** (off by default).
In **Investigate › Indicators**, open **Pivot** for a reviewed domain in a current TLP:CLEAR report.
Approve sending that domain to crt.sh. The lookup sends a wildcard domain query, never report text.
No scheduled or bulk queries run. Switch changes, outbound requests and saved answers are audited.

Answers, including no matches, are reused for 24 hours. Every cache read checks that the domain still
has accepted evidence in a current CLEAR report. The link map shows certificate names with provider and
fetch date; a known visible indicator is linked when its value matches. This context never creates an
indicator or observation and is not evidence of ownership or malicious activity.

Only names, issuer and validity dates are kept. Names are de-duplicated; for renewals the newest validity
start wins, with validity end and issuer as deterministic tie breakers. At most 500 names are returned.
Each result certificate must contain the requested domain or a subdomain; its other names remain useful
certificate context. An unrelated or malformed row rejects the entire answer, even after the output cap.
Certificates, serial numbers, raw subjects and contact details are not retained. A limited result is marked
`truncated`; crt.sh may also limit its search, so the result is not a complete history.

The only destination is `https://crt.sh/`, using its JSON search interface. Insight allows one request per
60 seconds across all callers, one in flight, with a 30-second overall timeout and a 2 MB response cap.
These are Insight limits, not a provider service guarantee. HTTP 429 adds the provider's bounded wait.
crt.sh can be slow or unavailable; errors are written by Insight without response bodies or request URLs,
and failures are not cached. HTTPS host allowlisting, checked public DNS addresses and no redirects apply.

Review the provider's current access and reuse conditions before enabling it. A public search interface is
not a blanket redistribution licence. Interface references, reviewed 22 November 2026:
[crt.sh JSON query support](https://github.com/crtsh/certwatch_db/issues/56) and
[crt.sh interface source](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc).
No provider source code is copied and no dependency is added.

## Passive DNS (TIP 4.6 part 3)

CIRCL passive DNS is optional and restricted to approved partners. Obtain your own access under
[CIRCL's access conditions](https://www.circl.lu/services/passive-dns/). Insight neither supplies access nor
grants redistribution rights. Follow the conditions agreed with the provider when retaining or sharing data.

Set `INSIGHT_CIRCL_PDNS_USER` and `INSIGHT_CIRCL_PDNS_PASSWORD` in the server environment. Restart a directly
run process. For Docker Compose, edit the host `.env` and recreate the Insight container with
`docker compose up -d --force-recreate insight`; a plain restart keeps the old environment. Credentials
must be nonempty printable ASCII, at most 1,024 characters each; a username cannot contain a colon. Never put
real credentials in a report, API body or repository. Settings shows only whether they are configured.
Without valid settings the provider is unavailable, even if an earlier switch setting was on.

In **Settings › Sources › Infrastructure lookups**, turn on **Use CIRCL passive DNS** (off by default).
In **Investigate › Indicators**, open **Pivot** for a reviewed domain or public IP in a current TLP:CLEAR
report. Approve sending that value to CIRCL for each uncached lookup. It receives only that value, never
report text. Nothing is scheduled or fetched in bulk. Switches, requests and saved answers are audited.

Insight always sends `dribble-disable-active-query` because CIRCL enables active resolution by default.
This header requests stored passive records only. Basic authentication goes only in the Authorization
header to `https://www.circl.lu/pdns/query/<value>` through the guarded HTTPS downloader. Redirects, private
destinations and other hosts are refused. Credentials never enter URLs, cache payloads or audit records.
Failures use Insight-written errors without request URLs, response bodies or credentials.

The shared provider throttle allows one request per five seconds across all callers and one in flight;
HTTP 429 adds a bounded provider wait. Insight imposes 2 MB and 30-second response limits. These are local
limits, not a provider quota guarantee. Requests ask for at most 501 records to detect the 500-row display
cap; Insight never follows pagination cursors or retries automatically. A result may still be incomplete
because the provider controls its source coverage and search limits.

Only `name`, `type`, `answer`, UTC `first_seen` / `last_seen` and `count` are retained. Missing counts remain
null. The provider's `rrname` / `rdata` direction is preserved: its version 2 examples sometimes put an IP
in the name and the queried domain in the answer. Each record must contain an exact canonical query match
on one endpoint; malformed or unrelated records reject the whole response, including beyond the output cap.
Duplicate name/type/answer rows combine the earliest first seen, latest last seen and maximum reported count
(not their sum). At most 500 rows and 500 graph nodes survive. Structured answers remain bounded text and
only valid standalone names or addresses become graph nodes. Raw sensor fields and contact fields are dropped.

Answers, including no matches, are cached for 24 hours in the existing Enrichment table. Every read and save
rechecks accepted evidence in a current CLEAR report and the reader's TLP limit. Disabling the provider or
removing credentials stops new requests; eligible cached data remains readable until expiry. The link map
shows provider and fetch date, links known visible values, and creates no indicators or observations.
Past DNS history does not prove ownership or malicious activity.

Interface and authentication references reviewed 22 November 2026:
[CIRCL service and headers](https://www.circl.lu/services/passive-dns/) and
[official PyPDNS client interface](https://github.com/CIRCL/PyPDNS).
No client code is copied and no dependency is added. No migration is required.

The tracked phone browser test checks the off state on a normal unconfigured test server. For its consent
layout branch, start an isolated test server with synthetic `INSIGHT_CIRCL_PDNS_USER=synthetic-user` and
`INSIGHT_CIRCL_PDNS_PASSWORD=synthetic-password`. It enables the switch and measures the confirmation,
but never clicks the lookup button or contacts CIRCL. Never use production credentials for browser fixtures.
