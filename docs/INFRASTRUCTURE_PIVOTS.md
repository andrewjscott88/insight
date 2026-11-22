# Infrastructure pivots

## Passive DNS (TIP 4.6 part 3)

CIRCL passive DNS is optional and restricted to approved partners. Obtain your own access under
[CIRCL's access conditions](https://www.circl.lu/services/passive-dns/). Insight neither supplies access nor
grants redistribution rights. Follow the conditions agreed with the provider when retaining or sharing data.

Set `INSIGHT_CIRCL_PDNS_USER` and `INSIGHT_CIRCL_PDNS_PASSWORD` on the server, then restart Insight. Credentials
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

This main-based part includes shared infrastructure support and registers only `circl`. RDAP/ASN and
certificate transparency are separate parts. Combining the branches must reconcile the shared files;
this part does not claim the entire TIP 4.6 milestone complete.

The tracked phone browser test checks the off state on a normal unconfigured test server. For its consent
layout branch, start an isolated test server with synthetic `INSIGHT_CIRCL_PDNS_USER=synthetic-user` and
`INSIGHT_CIRCL_PDNS_PASSWORD=synthetic-password`. It enables the switch and measures the confirmation,
but never clicks the lookup button or contacts CIRCL. Never use production credentials for browser fixtures.
